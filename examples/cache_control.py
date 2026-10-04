#!/usr/bin/env python3
"""Observe ET cache CSR commands, mode changes and error feedback in SysEmu."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import struct
import subprocess
import sys
import uuid

from gemm import LINKER, ROOT, command, runtime, symbols, trace_data
from add import event_at, require, run_logged


OUT = ROOT / "out" / "cache-control"
DONE = 0x4B4F5445
AREA_SIZE = 1024
LINE = 64
FEATURE_ADDRESS = 0x01C0340000
FEATURE_CLEAR = 0x2E  # enable ML, user cache/scratchpad and lock/unlock; preserve T1 disable
CSRS = {"cache_invalidate": 0x7D0, "mcache_control": 0x7E0,
        "evict_sw": 0x7F9, "flush_sw": 0x7FB, "lock_sw": 0x7FD, "unlock_sw": 0x7FF,
        "ucache_control": 0x810, "prefetch_va": 0x81F, "evict_va": 0x89F,
        "flush_va": 0x8BF, "lock_va": 0x8DF, "unlock_va": 0x8FF, "dcache_debug": 0xFC0}


def cases(case: str) -> list[dict[str, object]]:
    if case not in ("primary", "exact"):
        raise ValueError(f"unknown case: {case}")
    mask, stride, way = (15, 64, 1) if case == "primary" else (5, 128, 2)
    ops = []
    def site(name, csr, kind="control", value=0, **extra):
        ops.append(dict(name=name, csr=CSRS[csr], csr_name=csr, kind=kind,
                        value=value, mask=mask, stride=stride, way=way, error=0, **extra))

    # Writes use the actual machine/user legalization rules in zicsr.cpp.
    # The expected readbacks are explicit, rather than inferred from write logs.
    site("invalidate", "cache_invalidate", value=3)
    site("shared_to_scratch_rejected", "mcache_control", value=3)
    site("split", "mcache_control", value=1)
    site("mode_two_rejected", "mcache_control", value=2)
    site("user_scratch", "ucache_control", value=0x7FF)
    site("user_scratch_off", "ucache_control", value=0)
    site("machine_scratch", "mcache_control", value=3)
    site("split_return", "mcache_control", value=1)
    site("shared", "mcache_control", value=0)
    # Four entries cross the last set and way. TM selects entries, not FP lanes.
    site("evict_wrap", "evict_sw", "sw", dest=1 if case == "primary" else 2, first_set=14, count=4)
    site("flush_wrap", "flush_sw", "sw", dest=3 if case == "primary" else 1, first_set=15, count=4)
    site("evict_sw_dest_zero", "evict_sw", "sw", dest=0, first_set=14, count=4)
    site("flush_sw_dest_zero", "flush_sw", "sw", dest=0, first_set=15, count=4)
    site("prefetch", "prefetch_va", "va", dest=0 if case == "primary" else 2, count=4)
    site("prefetch_dest_three", "prefetch_va", "va", dest=3, count=4)
    site("evict_va", "evict_va", "va", dest=1 if case == "primary" else 3, count=4)
    site("flush_va", "flush_va", "va", dest=2 if case == "primary" else 1, count=4)
    site("evict_va_dest_zero", "evict_va", "va", dest=0, count=4)
    site("flush_va_dest_zero", "flush_va", "va", dest=0, count=4)
    site("lock_va", "lock_va", "va", dest=0, count=4)
    site("unlock_va", "unlock_va", "va", dest=0, count=4)
    site("lock_first", "lock_sw", "hard")
    site("lock_same_way", "lock_sw", "hard", refill=True)
    ops[-1]["error"] = 0x20
    site("lock_same_address", "lock_sw", "hard", other_way=True)
    ops[-1]["error"] = 0x20
    site("evict_locked", "evict_sw", "hard_sw", dest=1, count=1)
    site("flush_locked", "flush_sw", "hard_sw", dest=1, count=1)
    site("unlock_hard", "unlock_sw", "unlock")
    site("lock_after_unlock", "lock_sw", "hard")
    site("split_clears_locks", "mcache_control", value=1)
    site("lock_after_mode_change", "lock_sw", "hard", refill=True)
    site("shared_return", "mcache_control", value=0)
    site("debug_read", "dcache_debug", "read")
    # These command engines catch access exceptions and report bit 7 themselves.
    # The test does not suppress simulator faults or modify their semantics.
    for csr in ("prefetch_va", "evict_va", "flush_va", "lock_va", "unlock_va"):
        site(csr + "_access_error", csr, "fault", dest=1, count=1)
        ops[-1]["error"] = 0x80
    return ops


def initial_memory(case: str) -> bytes:
    base, step = (129, 37) if case == "primary" else (17, 53)
    return bytes((base + step * i) % 256 for i in range(AREA_SIZE))


def kernel(case: str, ops: list[dict[str, object]]) -> str:
    lines = ["# SPDX-License-Identifier: Apache-2.0",
             "# Startup provenance: Copyright (c) 2025 Ainekko, Co.; ET Platform boot.S.",
             ".option push", ".option norelax", ".option norvc", '.section .text.entry,"ax",@progbits',
             ".globl _start", "_start:", "    csrwi satp, 0", "    csrwi mip, 0",
             "    la sp, __stack_top", "    la t0, trap_handler", "    csrw mtvec, t0",
             f"    li t1, 0x{FEATURE_ADDRESS:x}", "    la t3, feature_state",
             ".globl feature_before", "feature_before:", "    ld t0, 0(t1)", "    sd t0, 0(t3)",
             f"    li t2, {-1 ^ FEATURE_CLEAR}", "    and t0, t0, t2", "    sd t0, 0(t1)",
             ".globl feature_after", "feature_after:", "    ld t0, 0(t1)", "    sd t0, 8(t3)",
             # Normalize modes through a legal transition from every supported mode.
             "    csrwi mcache_control, 1", "    csrwi mcache_control, 0", "    csrwi ucache_control, 0"]
    for op in ops:
        name, kind = str(op["name"]), op["kind"]
        if op.get("refill"):
            lines.extend(("    la t3, hard_area", "    addi t3, t3, 128", "    li t0, 0x5a5a5a5a5a5a5a5a"))
            lines.extend(f"    sd t0, {i * 8}(t3)" for i in range(8))
        lines.extend(("    csrwi tensor_error, 0", f"    li t0, {op['mask']}", "    csrw tensor_mask, t0",
                      f"    li x31, {int(op['stride']) | 0x17}"))
        if kind in ("va", "fault"):
            lines.extend(("    la t1, va_area", "    addi t1, t1, 128") if kind == "va" else
                         ("    li t1, 0x0200000000 # reserved PA region",))
            control = (1 << 63) | (int(op["dest"]) << 58) | (int(op["count"]) - 1)
            lines.extend((f"    li t2, 0x{control:x}", "    or t1, t1, t2"))
        elif kind == "sw":
            control = (1 << 63) | (int(op["dest"]) << 58) | (int(op["first_set"]) << 14) | (3 << 6) | (int(op["count"]) - 1)
            lines.append(f"    li t1, 0x{control:x}")
        elif kind in ("hard", "hard_sw", "unlock"):
            lines.extend(("    la t1, hard_area", "    addi t1, t1, 128"))
            way = int(op["way"]) ^ int(bool(op.get("other_way")))
            if kind != "hard":
                # These two operations happen in shared mode: index=(PA/64)%16.
                lines.extend(("    srli t1, t1, 6", "    andi t1, t1, 15",
                              f"    slli t1, t1, {14 if kind == 'hard_sw' else 6}"))
            control = (way << 6) | (int(op["dest"]) << 58) if kind == "hard_sw" else way << 55
            lines.extend((f"    li t2, 0x{control:x}", "    or t1, t1, t2"))
        else:
            lines.append(f"    li t1, 0x{op['value']:x}")
        lines.extend((f".globl op_{name}", f"op_{name}:"))
        lines.append(f"    csrr s8, 0x{op['csr']:x}" if kind == "read" else f"    csrw 0x{op['csr']:x}, t1")
        lines.append(f"    la t3, record_{name}")
        for offset, label, csr, rd in ((0, "error", 0x808, "s4"), (8, "machine", 0x7E0, "s5"),
                                       (16, "user", 0x810, "s6"), (24, "mask", 0x805, "s7"),
                                       (32, "command", op["csr"], "s8")):
            lines.extend((f".globl read_{label}_{name}", f"read_{label}_{name}:",
                          f"    csrr {rd}, 0x{csr:x}", f"    sd {rd}, {offset}(t3)"))
        lines.extend(("    la t4, hard_area", "    addi t4, t4, 128"))
        for i in range(8):
            lines.extend((f".globl copy_{name}_{i}", f"copy_{name}_{i}:",
                          f"    ld t0, {i * 8}(t4)", f"    sd t0, {40 + i * 8}(t3)"))
    lines.extend(("    li t0, 0x4b4f5445", "    la t1, completion", "    sw t0, 0(t1)",
                  ".globl park", "park:", "    wfi", "    j park", ".balign 4096", "trap_handler:",
                  "    csrr t0, mcause", "    la t1, trap_cause", "    sd t0, 0(t1)",
                  "    li t0, 1", "    la t1, trap_marker", "    sw t0, 0(t1)", "    j park", ".option pop",
                  '.section .data,"aw",@progbits', ".balign 64", ".globl __monitor_start", "__monitor_start:",
                  ".globl feature_state", "feature_state:", "    .fill 64,1,0xa5"))
    for area in ("va_area", "hard_area"):
        lines.extend((".balign 64", f".globl {area}", f"{area}:",
                      "    .byte " + ", ".join(str(x) for x in initial_memory(case))))
    for op in ops:
        lines.extend((f".globl record_{op['name']}", f"record_{op['name']}:", "    .fill 128,1,0xa5"))
    lines.extend((".globl completion", "completion:", "    .word 0", ".globl trap_marker", "trap_marker:", "    .word 0",
                  ".globl trap_cause", "trap_cause:", "    .dword 0", ".globl __monitor_end", "__monitor_end:"))
    return "\n".join(lines) + "\n"


def cache_events(trace: str) -> dict[int, dict[str, object]]:
    """Normalize actual 512-bit memory and cache action logs, retaining raw lines."""
    rows, pc = {}, None
    for line in trace.splitlines():
        inst = re.search(r"\[(H\d+ S\d+:N\d+:C\d+:T\d+)\] I\(M\): 0x([0-9a-f]+)", line)
        if inst:
            pc = int(inst.group(2), 16)
            rows[pc] = {"hart": inst.group(1), "accesses": [], "actions": [], "csrs": [], "raw": []}
        if pc is None:
            continue
        csr = re.search(r"\t([a-z][a-z0-9_]*) ([=:]) 0x([0-9a-f]+)", line)
        if csr and csr.group(1) in {*CSRS, "tensor_error", "tensor_mask"}:
            rows[pc]["csrs"].append({"name": csr.group(1), "direction": csr.group(2),
                                      "value": f"0x{int(csr.group(3), 16):x}"})
        access = re.search(r"MEM512\[0x([0-9a-f]+)\] ([=:]) \{([^}]+)\}", line)
        if access:
            words = re.findall(r"(\d+):0x([0-9a-f]{8})", access.group(3))
            if [int(i) for i, _ in words] != list(range(16)):
                raise RuntimeError("incomplete 512-bit memory event")
            raw = struct.pack("<16I", *(int(word, 16) for _, word in words))
            rows[pc]["accesses"].append({"bits": 512, "address": f"0x{int(access.group(1), 16):x}",
                "direction": "write" if access.group(2) == "=" else "read", "bytes": raw.hex(" ")})
        sw = re.search(r"Doing (EvictSW|FlushSW): Set: (\d+), Way: (\d+), DestLevel: (\d+)", line)
        va = re.search(r"(Doing|Skipping) (EvictVA|FlushVA|LockVA|UnlockVA): 0x([0-9a-f]+)(?: \(0x([0-9a-f]+)\))?", line)
        hard = re.search(r"Doing LockSW: \(0x([0-9a-f]+)\), Way: (\d+), Set: (\d+)", line)
        if sw:
            rows[pc]["actions"].append(dict(action=sw.group(1), set=int(sw.group(2)), way=int(sw.group(3)), dest=int(sw.group(4))))
        elif va:
            rows[pc]["actions"].append(dict(action=va.group(2), selected=va.group(1) == "Doing",
                address=f"0x{int(va.group(3), 16):x}", physical_address=f"0x{int(va.group(4), 16):x}" if va.group(4) else None))
            if va.group(2) in ("EvictVA", "FlushVA"):
                destination = re.search(r"DestLevel: (\d+)", line)
                if not destination:
                    raise RuntimeError("missing cache destination level in VA action trace")
                rows[pc]["actions"][-1]["dest"] = int(destination.group(1))
        elif hard:
            rows[pc]["actions"].append(dict(action="LockSW", address=f"0x{int(hard.group(1), 16):x}",
                                           way=int(hard.group(2)), set=int(hard.group(3))))
        if access or sw or va or hard or re.search(r"double-locking|access fault|suppressed|exception", line, re.I):
            rows[pc]["raw"].append(line)
    return rows


def execute(case: str, env: dict[str, str]) -> None:
    out = OUT if case == "primary" else OUT / case
    out.mkdir(parents=True, exist_ok=True)
    log = out / "commands.log"
    log.write_text("")
    ops = cases(case)
    (out / "kernel.S").write_text(kernel(case, ops))
    (out / "link.ld").write_text(LINKER)
    for name in ("result.json", "registers.json", "output.bin", "prestart.bin", "trace.log"):
        (out / name).unlink(missing_ok=True)
    stage = f"/tmp/etsoc1-cache-control-{uuid.uuid4().hex[:10]}"
    container, podman = env["kind"] == "podman", shutil.which("podman") or "podman"
    def checked(argv):
        result = run_logged(log, argv)
        require(result, "cache-control command")
        return result
    if container:
        checked([podman, "exec", env["container"], "mkdir", "-p", stage])
        for name in ("kernel.S", "link.ld"):
            checked([podman, "cp", str(out / name), f"{env['container']}:{stage}/{name}"])
        work, shell = stage, command(env, ["bash", "-lc"])
    else:
        work, shell = str(out), ["bash", "-lc"]
    tp, qwork = shlex.quote(env["tool_prefix"]), shlex.quote(work)
    build = (f"set -euo pipefail; cd {qwork}; "
             f"{tp}as --march=rv64imfc -mabi=lp64f -o kernel.o kernel.S; "
             f"{tp}ld --no-relax --build-id=none -T link.ld -o kernel.elf kernel.o; "
             f"{tp}objdump -d -M numeric kernel.elf > kernel.asm; "
             f"{tp}readelf -h -l -S kernel.elf > elf-inspection.txt; "
             f"{tp}objdump -h kernel.elf > sections.txt; "
             f"{tp}nm -n --defined-only kernel.elf > symbols.txt; "
             f"{tp}objcopy -O binary --only-section=.text kernel.elf text.bin")
    built = run_logged(log, [*shell, build])
    if container:
        checked([podman, "cp", f"{env['container']}:{stage}/.", str(out)])
    require(built, "assemble cache-control ELF")
    syms, inspection = symbols((out / "symbols.txt").read_text()), (out / "elf-inspection.txt").read_text()
    entry_match = re.search(r"Entry point address:\s+0x([0-9a-fA-F]+)", inspection)
    text_match = re.search(r"^\s*\[\s*\d+\]\s+\.text\s+\S+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)", inspection, re.MULTILINE)
    if not entry_match or not text_match:
        raise RuntimeError("missing ELF entry/section mapping")
    entry = int(entry_match.group(1), 16)
    text_vma, text_offset, text_size = (int(text_match.group(i), 16) for i in (1, 2, 3))
    text, disassembly = (out / "text.bin").read_bytes(), (out / "kernel.asm").read_text()
    instructions = []
    for op in ops:
        pc = syms[f"op_{op['name']}"]
        raw = text[pc - text_vma:pc - text_vma + 4]
        decoded = [line.strip() for line in disassembly.splitlines() if re.search(rf"\b{pc:x}:\s", line)]
        word = int.from_bytes(raw, "little")
        # Base RISC-V SYSTEM opcode and CSR address, unlike custom packed opcodes.
        expected_fields = (0x73, op["csr"], 2 if op["kind"] == "read" else 1, 24 if op["kind"] == "read" else 0,
                           0 if op["kind"] == "read" else 6)
        if len(raw) != 4 or len(decoded) != 1 or (word & 0x7F, word >> 20, word >> 12 & 7, word >> 7 & 31, word >> 15 & 31) != expected_fields:
            raise RuntimeError(f"wrong assembled cache CSR instruction: {op['name']}: {decoded}")
        instructions.append({"name": op["name"], "csr": f"0x{op['csr']:03x}", "csr_name": op["csr_name"],
            "mnemonic": "csrrs" if op["kind"] == "read" else "csrrw", "pc": f"0x{pc:x}",
            "file_offset": f"0x{text_offset + pc - text_vma:x}", "word": f"0x{word:08x}",
            "bytes_memory_order": raw.hex(" "), "decoded": decoded[0]})
    (out / "operations.json").write_text(json.dumps(instructions, indent=2) + "\n")
    (out / "operations.bin").write_bytes(b"".join(bytes.fromhex(row["bytes_memory_order"]) for row in instructions))
    (out / "op.bin").write_bytes(bytes.fromhex(instructions[0]["bytes_memory_order"]))
    dump_addr, dump_size = syms["__monitor_start"], syms["__monitor_end"] - syms["__monitor_start"]
    (out / "elf-layout.json").write_text(json.dumps({
        "entry": f"0x{entry:x}", "selected_hart": "H0 S0:N0:C0:T0", "executable_sections": [".text"],
        "text_vma": f"0x{text_vma:x}", "text_file_offset": f"0x{text_offset:x}", "text_size": text_size,
        "monitor_address": f"0x{dump_addr:x}", "monitor_size": dump_size, "operations": instructions,
        "symbols": {name: f"0x{addr:x}" for name, addr in syms.items()},
    }, indent=2) + "\n")
    sim = [env["simulator"], "-l", "-lm", "0", "-lt", "0", "-sp_dis", "-Werror=memory",
           "-reset_pc", hex(entry), "-single_thread", "-minions", "0x1", "-shires", "0x1",
           "-max_cycles", "10000", "-elf_load", f"{work}/kernel.elf",
           "-dump_at_pc_pc", hex(entry), "-dump_at_pc_addr", hex(dump_addr), "-dump_at_pc_size", hex(dump_size),
           "-dump_at_pc_file", f"{work}/prestart.bin", "-dump_addr", hex(dump_addr),
           "-dump_size", str(dump_size), "-dump_file", f"{work}/output.bin"]
    run = run_logged(log, command(env, ["timeout", "--signal=TERM", "--kill-after=5s", "90s", *sim]))
    (out / "trace.log").write_text(run.stdout or "")
    if container:
        checked([podman, "cp", f"{env['container']}:{stage}/.", str(out)])
        checked([podman, "exec", env["container"], "rm", "-rf", stage])
    require(run, "execute cache-control ELF")
    validate(case, ops, instructions, out, syms, dump_addr, dump_size)


def validate(case, ops, instructions, out, syms, dump_addr, dump_size):
    trace = (out / "trace.log").read_text()
    if "Finishing emulation" not in trace or "Error, max cycles reached" in trace or re.search(r"\bTrapping\b", trace):
        raise RuntimeError("cache-control execution did not complete normally")
    events, regs = trace_data(trace)
    raw_events = cache_events(trace)
    event_at(events, syms["park"], "wfi")
    pre, memory = (out / "prestart.bin").read_bytes(), (out / "output.bin").read_bytes()
    if len(pre) != dump_size or len(memory) != dump_size:
        raise RuntimeError("incomplete simulator memory dumps")
    offset = lambda name: syms[name] - dump_addr
    before, after = struct.unpack_from("<2Q", memory, offset("feature_state"))
    for label, value in (("feature_before", before), ("feature_after", after)):
        event_at(events, syms[label], "ld")
        if regs[(syms[label], "x5", "=")] != value:
            raise RuntimeError("feature ESR trace and memory disagree")
    if after != before & ~FEATURE_CLEAR:
        raise RuntimeError("feature write changed unrelated ESR bits")
    expected_memory = bytearray(pre)
    if pre[offset("feature_state"):offset("feature_state") + 64] != bytes([0xA5]) * 64:
        raise RuntimeError("feature snapshot was not seeded")
    expected_memory[offset("feature_state"):offset("feature_state") + 16] = struct.pack("<2Q", before, after)
    for area in ("va_area", "hard_area"):
        if pre[offset(area):offset(area) + AREA_SIZE] != initial_memory(case):
            raise RuntimeError("incorrect input memory")
    machine, user, results, register_rows = 0, 0, [], []
    hard_address, va_address = syms["hard_area"] + 128, syms["va_area"] + 128
    fault_pcs = {int(inst["pc"], 16) for op, inst in zip(ops, instructions) if op["kind"] == "fault"}
    for pc, row in raw_events.items():
        if pc not in fault_pcs and re.search(r"exception|suppressed|access fault", "\n".join(row["raw"]), re.I):
            raise RuntimeError(f"unexpected cache access exception at PC {pc:#x}")
    for op, inst in zip(ops, instructions):
        name, kind, pc = op["name"], op["kind"], int(inst["pc"], 16)
        event = event_at(events, pc, inst["mnemonic"])
        observed = raw_events[pc]
        if event["word"] != int(inst["word"], 16) or observed["hart"] != event["hart"]:
            raise RuntimeError(f"wrong executed instruction at {name}")
        if op.get("refill"):
            expected_memory[hard_address - dump_addr:hard_address - dump_addr + LINE] = bytes([0x5A]) * LINE
        expected_accesses, expected_actions = [], []
        value = op["value"]
        if kind == "control":
            if op["csr_name"] == "mcache_control":
                accepted = (value & 3) == 1 if machine == 0 else (value & 3) != 2
                if accepted:
                    machine = value & 3
                    user = (user & ~3) | machine
            elif op["csr_name"] == "ucache_control":
                user = (machine & 1) | (value & ~1 & 0x7DF)
                machine = user & 3
        if kind == "sw":
            value = (1 << 63) | (op["dest"] << 58) | (op["first_set"] << 14) | (3 << 6) | (op["count"] - 1)
            if op["dest"]:
                for i in range(op["count"]):
                    if op["mask"] >> i & 1:
                        absolute = op["first_set"] + i
                        expected_actions.append(dict(action="EvictSW" if op["csr_name"] == "evict_sw" else "FlushSW",
                            set=absolute % 16, way=(3 + absolute // 16) % 4, dest=op["dest"]))
        elif kind in ("va", "fault"):
            address = va_address if kind == "va" else 0x0200000000
            value = (1 << 63) | (op["dest"] << 58) | (op["count"] - 1) | address
            active = op["csr_name"] not in ("evict_va", "flush_va") or op["dest"] != 0
            active &= op["csr_name"] != "prefetch_va" or op["dest"] != 3
            if active and kind == "va":
                for i in range(op["count"]):
                    selected, address = bool(op["mask"] >> i & 1), va_address + i * op["stride"]
                    if op["csr_name"] != "prefetch_va":
                        expected_actions.append(dict(action={"evict_va": "EvictVA", "flush_va": "FlushVA",
                            "lock_va": "LockVA", "unlock_va": "UnlockVA"}[op["csr_name"]], selected=selected,
                            address=f"0x{address:x}", physical_address=f"0x{address:x}" if selected else None))
                        if op["csr_name"] in ("evict_va", "flush_va"):
                            expected_actions[-1]["dest"] = op["dest"]
                    if selected and op["csr_name"] in ("prefetch_va", "lock_va"):
                        data = bytes(LINE) if op["csr_name"] == "lock_va" else bytes(expected_memory[address - dump_addr:address - dump_addr + LINE])
                        expected_accesses.append(dict(bits=512, address=f"0x{address:x}",
                            direction="write" if op["csr_name"] == "lock_va" else "read", bytes=data.hex(" ")))
                        if op["csr_name"] == "lock_va":
                            expected_memory[address - dump_addr:address - dump_addr + LINE] = data
        elif kind in ("hard", "hard_sw", "unlock"):
            way = op["way"] ^ int(bool(op.get("other_way")))
            cache_set = (hard_address // LINE) % (16 if machine == 0 else 8)
            if kind == "hard":
                value = hard_address | (way << 55)
                if not op["error"]:
                    expected_accesses.append(dict(bits=512, address=f"0x{hard_address:x}", direction="write", bytes=bytes(LINE).hex(" ")))
                    expected_memory[hard_address - dump_addr:hard_address - dump_addr + LINE] = bytes(LINE)
                    expected_actions.append(dict(action="LockSW", address=f"0x{hard_address:x}", way=way, set=cache_set))
                elif "double-locking" not in "\n".join(observed["raw"]):
                    raise RuntimeError("missing duplicate-lock diagnostic")
            elif kind == "hard_sw":
                value = (cache_set << 14) | (way << 6) | (op["dest"] << 58)
                if op["csr_name"] == "flush_sw":
                    expected_actions.append(dict(action="FlushSW", set=cache_set, way=way, dest=op["dest"]))
            else:
                value = (cache_set << 6) | (way << 55)
        if kind != "read" and regs[(pc, "x6", ":")] != value:
            raise RuntimeError(f"wrong actual command operand at {name}")
        if kind in ("va", "fault") and regs[(pc, "x31", ":")] != op["stride"] | 0x17:
            raise RuntimeError("incorrect stride register")
        if kind in ("va", "fault", "sw") and {"name": "tensor_mask", "direction": ":", "value": f"0x{op['mask']:x}"} not in observed["csrs"]:
            raise RuntimeError("active tensor mask was not read at the command PC")
        actual_reads = []
        for label, rd, csr in (("error", 20, 0x808), ("machine", 21, 0x7E0), ("user", 22, 0x810),
                              ("mask", 23, 0x805), ("command", 24, op["csr"])):
            read_pc = syms[f"read_{label}_{name}"]
            read = event_at(events, read_pc, "csrrs")
            if read["word"] != (csr << 20) | (2 << 12) | (rd << 7) | 0x73:
                raise RuntimeError("wrong CSR readback instruction")
            actual_reads.append(regs[(read_pc, f"x{rd}", "=")])
        expected_reads = [op["error"], machine, user, op["mask"], machine if op["csr_name"] == "mcache_control" else
                          user if op["csr_name"] == "ucache_control" else 0]
        if kind == "read" and regs[(pc, "x24", "=")] != 0:
            raise RuntimeError("unexpected dcache_debug state")
        record = offset(f"record_{name}")
        if pre[record:record + 128] != bytes([0xA5]) * 128:
            raise RuntimeError("command record was not seeded")
        actual_record = struct.unpack_from("<5Q", memory, record)
        if tuple(actual_reads) != actual_record:
            raise RuntimeError(f"CSR register trace and device snapshot disagree at {name}")
        copied = []
        for i in range(8):
            copy_pc = syms[f"copy_{name}_{i}"]
            event_at(events, copy_pc, "ld")
            copied.append(regs[(copy_pc, "x5", "=")])
        hard_snapshot = memory[record + 40:record + 104]
        if struct.pack("<8Q", *copied) != hard_snapshot:
            raise RuntimeError("hard-lock memory snapshot and actual load trace disagree")
        expected_memory[record:record + 40] = struct.pack("<5Q", *expected_reads)
        expected_memory[record + 40:record + 104] = expected_memory[hard_address - dump_addr:hard_address - dump_addr + LINE]
        passed = (actual_reads == expected_reads and observed["actions"] == expected_actions and
                  observed["accesses"] == expected_accesses and memory[record:record + 128] == expected_memory[record:record + 128])
        results.append({**inst, "pass": passed, "expected_error": f"0x{op['error']:x}",
                        "actual_readbacks": [f"0x{x:x}" for x in actual_reads],
                        "expected_readbacks": [f"0x{x:x}" for x in expected_reads],
                        "actions": observed["actions"], "actions_expected": expected_actions,
                        "accesses": observed["accesses"], "accesses_expected": expected_accesses})
        register_rows.append({**inst, "hart": event["hart"], "cycle": event["cycle"],
            "operand": f"0x{regs[(pc, 'x6', ':')]:x}" if kind != "read" else None,
            "x31": f"0x{regs[(pc, 'x31', ':')]:x}" if (pc, "x31", ":") in regs else None,
            "readback_names": ["tensor_error", "mcache_control", "ucache_control", "tensor_mask", op["csr_name"]],
            "readback_pcs": {label: f"0x{syms[f'read_{label}_{name}']:x}" for label in ("error", "machine", "user", "mask", "command")},
            "actual_readbacks": [f"0x{x:x}" for x in actual_reads], "raw_cache_events": observed["raw"]})
        register_rows[-1].update(active_tensor_mask=next((row["value"] for row in observed["csrs"]
                                    if row["name"] == "tensor_mask" and row["direction"] == ":"), None),
                                hard_snapshot_address=f"0x{hard_address:x}", hard_snapshot_bytes=hard_snapshot.hex(" "))
        print(f"  {name:<30} CSR={inst['csr']} PC={inst['pc']} error={actual_reads[0]:#04x} {'PASS' if passed else 'FAIL'}")
    completion, trap_marker, trap_cause = struct.unpack_from("<IIQ", memory, offset("completion"))
    if pre[offset("completion"):offset("completion") + 16] != bytes(16):
        raise RuntimeError("completion/trap memory was not initialized")
    expected_memory[offset("completion"):offset("completion") + 4] = struct.pack("<I", DONE)
    passed = all(row["pass"] for row in results) and memory == expected_memory and completion == DONE and not trap_marker and not trap_cause
    (out / "registers.json").write_text(json.dumps({"source": "actual SysEmu register events and device CSR/memory snapshots",
        "feature_before": f"0x{before:x}", "feature_after": f"0x{after:x}", "operations": register_rows}, indent=2) + "\n")
    (out / "result.json").write_text(json.dumps({"case": case, "operation_count": len(ops),
        "csr_count": len({op["csr"] for op in ops}), "operations": results,
        "whole_monitor_matches": memory == expected_memory, "completion_word": f"0x{completion:08x}",
        "trap_marker": trap_marker, "trap_cause": trap_cause, "pass": passed}, indent=2) + "\n")
    if not passed:
        raise RuntimeError(f"cache-control state/access/reference checks failed; inspect {out}/result.json")
    print(f"Cache control {case}: {len(ops)} sites, {len(CSRS)} CSRs, completion={completion:#x}, PASS; {out}")


def main() -> int:
    selected = sys.argv[1:] or ["primary", "exact"]
    if any(case not in ("primary", "exact") for case in selected):
        raise SystemExit("usage: python3 examples/cache_control.py [primary|exact ...]")
    env = runtime()
    for case in selected:
        print(f"\nCache control {case}: H0 S0:N0:C0:T0")
        execute(case, env)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print(f"cache_control.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
