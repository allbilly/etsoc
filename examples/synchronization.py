#!/usr/bin/env python3
"""Execute minion FLB/FCC/STALL CSRs and observe their real state transitions."""

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
from add import event_at, run_logged
from packed_memory import memory_events


OUT = ROOT / "out" / "synchronization"
DONE = 0x4B4F5445
SEED = 0x5AA55AA55AA55AA5
FEATURE = 0x01C0340000
FLB_BASE = 0x0100340100
FCC_BASE = 0x01003400C0
IPI_SET, IPI_CLEAR = 0x01C0340090, 0x01C0340098
MTIME_TARGET = 0x01C0340218
# IO_SHIRE_ID=254 and ESR_REGION_SHIRE_SHIFT=22 in the pinned ET-SOC1 source.
MTIME = 0x01C0000000 | (254 << 22)
MTIMECMP = MTIME + 8
CSRS = {"excl_mode": 0x7D3, "flb": 0x820, "fcc": 0x821, "stall": 0x822, "fccnb": 0xCC0}


def inputs(case: str) -> tuple[int, int, int, int, int]:
    if case == "primary":
        return 3, 2, 2, 3, 8  # barrier, limit, FCC0/FCC1 credits, timer delay
    if case == "exact":
        return 31, 3, 3, 2, 12
    raise ValueError(f"unknown case: {case}")


def operations(case: str) -> list[dict[str, object]]:
    barrier, limit, credits0, credits1, delay = inputs(case)
    ops = []
    # The host computes validation references only; all counter changes are
    # produced by the device's CSR instructions or ESR stores in upstream SysEmu.
    old = 0
    for i in range(limit + 2):
        new = 0 if old == limit else old + 1
        ops.append(dict(name=f"flb_{i}", kind="flb", csr="flb", value=(1 << 47) | (1 << 13) | (limit << 5) | barrier,
                        before=old, after=new, returned=int(new == 0), exclusive=0))
        old = new
    for name, lim, returned in (("flb_limit_255", 255, 1), ("flb_counter_wrap", 0, 0)):
        ops.append(dict(name=name, kind="flb", csr="flb", value=(lim << 5) | barrier,
                        reset=255, before=255, after=0, returned=returned, exclusive=0))
    ops.append(dict(name="credits_initial", kind="credit_read", csr="fccnb", value=0,
                    before=0, after=0, returned=0, exclusive=0))
    credits = [0, 0]
    for counter, count in enumerate((credits0, credits1)):
        for i in range(count):
            before = credits[0] | credits[1] << 16
            credits[counter] += 1
            ops.append(dict(name=f"credit{counter}_{i}", kind="credit_store", csr=None,
                            address=FCC_BASE + counter * 8, value=1 | ((1 << 63) if case == "exact" else 0),
                            before=before, after=credits[0] | credits[1] << 16, returned=SEED, exclusive=0))
    order = (0, 1, 0, 1, 1) if case == "primary" else (1, 0, 1, 0, 0)
    for i, counter in enumerate(order):
        before = credits[0] | credits[1] << 16
        credits[counter] -= 1
        ops.append(dict(name=f"consume_{i}", kind="credit_consume", csr="fcc", value=counter | (0x100 if case == "exact" else 0),
                        before=before, after=credits[0] | credits[1] << 16, returned=0, exclusive=0))
    ops.append(dict(name="credits_empty", kind="credit_read", csr="fccnb", value=0,
                    before=0, after=0, returned=0, exclusive=0))
    ops.extend((dict(name="exclusive_enter", kind="mode", csr="excl_mode", value=1,
                     before=0, after=1, returned=0, exclusive=1),
                dict(name="stall_exclusive", kind="stall", csr="stall", value=0x1234,
                     before=0, after=0, returned=0, exclusive=1),
                dict(name="exclusive_exit", kind="mode", csr="excl_mode", value=0,
                     before=1, after=0, returned=1, exclusive=0),
                dict(name="stall_pending", kind="pending", csr="stall", value=0x5678,
                     before=8, after=8, returned=0, exclusive=0),
                dict(name="stall_timer", kind="timer", csr="stall", value=0x9ABC,
                     before=0, after=0x80, returned=0, exclusive=0)))
    return ops


def kernel(case: str, ops: list[dict[str, object]]) -> str:
    barrier, limit, credits0, credits1, delay = inputs(case)
    barrier_address, guard_address = FLB_BASE + barrier * 8, FLB_BASE + ((barrier + 1) % 32) * 8
    lines = ["# SPDX-License-Identifier: Apache-2.0",
             "# Startup provenance: Copyright (c) 2025 Ainekko, Co.; ET Platform boot.S.",
             ".option push", ".option norelax", ".option norvc", '.section .text.entry,"ax",@progbits',
             ".globl _start", "_start:", "    csrwi satp, 0", "    csrwi mie, 0", "    csrwi mip, 0",
             "    csrwi excl_mode, 0", "    csrwi tensor_error, 0", "    csrci mstatus, 8",
             "    la sp, __stack_top", "    la t0, trap_handler", "    csrw mtvec, t0",
             "    la t3, feature_state", f"    li t1, 0x{FEATURE:x}",
             ".globl feature_before", "feature_before:", "    ld t0, 0(t1)", "    sd t0, 0(t3)",
             "    andi t0, t0, -3 # clear only ML-disable bit 1", "    sd t0, 0(t1)",
             ".globl feature_after", "feature_after:", "    ld t0, 0(t1)", "    sd t0, 8(t3)",
             ".globl status_initial", "status_initial:", "    csrr t0, mstatus", "    sd t0, 16(t3)",
             f"    li t2, 0x{barrier_address:x}", "    sd zero, 0(t2)",
             f"    li t2, 0x{guard_address:x}", "    li t0, 0x5a", "    sd t0, 0(t2)"]
    for op in ops:
        name, kind = op["name"], op["kind"]
        if kind == "flb":
            lines.append(f"    li t2, 0x{barrier_address:x}")
            if "reset" in op:
                lines.extend((f"    li t0, {op['reset']}", "    sd t0, 0(t2)"))
            before, after = "ld s5, 0(t2)", "ld s6, 0(t2)"
        elif kind.startswith("credit"):
            if kind == "credit_store":
                lines.append(f"    li t2, 0x{op['address']:x}")
            before, after = "csrr s5, fccnb", "csrr s6, fccnb"
        elif kind == "mode":
            before, after = "csrr s5, excl_mode", "csrr s6, excl_mode"
        else:
            before, after = "csrr s5, mip", "csrr s6, mip"
            if kind == "pending":
                lines.extend(("    csrwi mie, 8", f"    li t2, 0x{IPI_SET:x}", "    li t0, 1", "    sd t0, 0(t2)"))
            elif kind == "timer":
                lines.extend((f"    li t2, 0x{MTIMECMP:x}", "    li t0, -1", "    sd t0, 0(t2)",
                              f"    li t2, 0x{MTIME_TARGET:x}", "    li t0, 1", "    sd t0, 0(t2)",
                              f"    li t2, 0x{MTIME:x}", "    sd zero, 0(t2)",
                              ".globl timer_now", "timer_now:", "    ld s1, 0(t2)", f"    addi s2, s1, {delay}",
                              f"    li t0, 0x{MTIMECMP:x}", ".globl timer_arm", "timer_arm:",
                              "    sd s2, 0(t0)", "    li t0, 128", "    csrw mie, t0"))
        lines.extend((f".globl before_{name}", f"before_{name}:", f"    {before}",
                      f"    li t1, 0x{op['value']:x}", f"    li s4, 0x{SEED:x}",
                      f".globl seed_{name}", f"seed_{name}:", "    addi t0, s4, 0",
                      f".globl op_{name}", f"op_{name}:"))
        if kind == "credit_store":
            lines.append("    sd t1, 0(t2) # device ESR write supplies credits to minion 0/thread 0")
        elif kind == "credit_read":
            lines.append("    csrr s4, fccnb")
        else:
            lines.append(f"    csrrw s4, {op['csr']}, t1")
        lines.extend((f".globl resume_{name}", f"resume_{name}:", f"    {after}"))
        if kind == "timer":
            lines.extend((".globl timer_after", "timer_after:", "    ld s3, 0(t2)",
                          "    la t3, timer_record", "    sd s1, 0(t3)", "    sd s2, 8(t3)", "    sd s3, 16(t3)"))
        lines.append(f"    la t3, record_{name}")
        for offset, reg in ((0, "s5"), (8, "s6"), (16, "s4")):
            lines.extend((f".globl capture_{reg}_{name}", f"capture_{reg}_{name}:", f"    sd {reg}, {offset}(t3)"))
        for offset, label, csr, reg in ((24, "error", "tensor_error", "s7"), (32, "exclusive", "excl_mode", "s8"),
                                       (40, "enabled", "mie", "s9"), (48, "pending", "mip", "s10"),
                                       (56, "status", "mstatus", "s11")):
            lines.extend((f".globl read_{label}_{name}", f"read_{label}_{name}:",
                          f"    csrr {reg}, {csr}", f"    sd {reg}, {offset}(t3)"))
        if kind == "pending":
            lines.extend((f"    li t2, 0x{IPI_CLEAR:x}", "    li t0, 1", "    sd t0, 0(t2)", "    csrwi mie, 0"))
        elif kind == "timer":
            lines.extend((f"    li t2, 0x{MTIMECMP:x}", "    li t0, -1", ".globl timer_disarm", "timer_disarm:", "    sd t0, 0(t2)",
                          "    csrwi mie, 0", f"    li t2, 0x{MTIME_TARGET:x}", "    sd zero, 0(t2)"))
    lines.extend((f"    li t2, 0x{guard_address:x}", ".globl guard_read", "guard_read:", "    ld t0, 0(t2)",
                  "    la t3, feature_state", "    sd t0, 24(t3)", "    li t0, 0x4b4f5445", "    la t1, completion", "    sw t0, 0(t1)",
                  ".globl park", "park:", "    wfi", "    j park", ".balign 4096", "trap_handler:",
                  "    csrr t0, mcause", "    la t1, trap_cause", "    sd t0, 0(t1)",
                  "    li t0, 1", "    la t1, trap_marker", "    sw t0, 0(t1)", "    j park", ".option pop",
                  '.section .data,"aw",@progbits', ".balign 64", ".globl __monitor_start", "__monitor_start:",
                  ".globl input_controls", "input_controls:", "    .dword " + ", ".join(str(x) for x in inputs(case)), "    .fill 24,1,0xa5",
                  ".globl feature_state", "feature_state:", "    .fill 64,1,0xa5",
                  ".globl timer_record", "timer_record:", "    .fill 64,1,0xa5"))
    for op in ops:
        lines.extend((f".globl record_{op['name']}", f"record_{op['name']}:", "    .fill 128,1,0xa5"))
    lines.extend((".globl completion", "completion:", "    .word 0", ".globl trap_marker", "trap_marker:", "    .word 0",
                  ".globl trap_cause", "trap_cause:", "    .dword 0", ".globl __monitor_end", "__monitor_end:"))
    return "\n".join(lines) + "\n"


def execute(case: str, env: dict[str, str]) -> None:
    out = OUT if case == "primary" else OUT / case
    out.mkdir(parents=True, exist_ok=True)
    log = out / "commands.log"
    log.write_text("")
    ops = operations(case)
    (out / "kernel.S").write_text(kernel(case, ops))
    (out / "link.ld").write_text(LINKER)
    for name in ("result.json", "registers.json", "output.bin", "prestart.bin", "trace.log"):
        (out / name).unlink(missing_ok=True)
    stage = f"/tmp/etsoc1-synchronization-{uuid.uuid4().hex[:10]}"
    container, podman = env["kind"] == "podman", shutil.which("podman") or "podman"
    def checked(argv):
        result = run_logged(log, argv)
        if result.returncode:
            raise RuntimeError(f"synchronization command failed ({result.returncode}); inspect {log}")
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
    if built.returncode:
        raise RuntimeError(f"assemble synchronization ELF failed ({built.returncode}); inspect {log}")
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
        if op['kind'] == 'credit_store':
            correct = word & 0x7F == 0x23 and word >> 12 & 7 == 3 and word >> 15 & 31 == 7 and word >> 20 & 31 == 6
            mnemonic, csr = 'sd', None
        else:
            csr = CSRS[op['csr']]
            read = op['kind'] == 'credit_read'
            correct = (word & 0x7F, word >> 20, word >> 12 & 7, word >> 7 & 31, word >> 15 & 31) == (0x73, csr, 2 if read else 1, 20, 0 if read else 6)
            mnemonic = 'csrrs' if read else 'csrrw'
        if len(raw) != 4 or len(decoded) != 1 or not correct:
            raise RuntimeError(f"wrong assembled synchronization instruction: {op['name']}: {decoded}")
        instructions.append({'name': op['name'], 'csr': f'0x{csr:03x}' if csr is not None else None,
            'csr_name': op['csr'], 'mnemonic': mnemonic, 'pc': f'0x{pc:x}',
            'file_offset': f'0x{text_offset + pc - text_vma:x}', 'word': f'0x{word:08x}',
            'bytes_memory_order': raw.hex(' '), 'decoded': decoded[0]})
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
    if run.returncode:
        raise RuntimeError(f"execute synchronization ELF failed ({run.returncode}); inspect {log} and {out / 'trace.log'}")
    validate(case, ops, instructions, out, syms, dump_addr, dump_size)


def validate(case, ops, instructions, out, syms, dump_addr, dump_size):
    trace = (out / "trace.log").read_text()
    if "Finishing emulation" not in trace or "Error, max cycles reached" in trace or re.search(r"\b(?:Trapping|exception)\b", trace, re.I):
        raise RuntimeError("synchronization program did not complete normally")
    events, regs = trace_data(trace)
    accesses = memory_events(trace)
    blocks, current = {}, None
    for line in trace.splitlines():
        match = re.search(r"I\(M\): 0x([0-9a-f]+)", line)
        if match:
            current = int(match.group(1), 16)
            blocks[current] = []
        if current is not None:
            blocks[current].append(line)
    event_at(events, syms["park"], "wfi")
    pre, memory = (out / "prestart.bin").read_bytes(), (out / "output.bin").read_bytes()
    if len(pre) != dump_size or len(memory) != dump_size:
        raise RuntimeError("incomplete simulated memory dumps")
    offset = lambda name: syms[name] - dump_addr
    expected = bytearray(pre)
    if struct.unpack_from("<5Q", pre, offset("input_controls")) != inputs(case):
        raise RuntimeError("incorrect deterministic input controls")
    feature_before, feature_after, status, guard = struct.unpack_from("<4Q", memory, offset("feature_state"))
    for label, value in (("feature_before", feature_before), ("feature_after", feature_after), ("status_initial", status), ("guard_read", guard)):
        event_at(events, syms[label])
        if regs[(syms[label], "x5", "=")] != value:
            raise RuntimeError("setup ESR/CSR snapshot disagrees with real scalar register write")
    if feature_after != feature_before & ~2 or status & 8 or guard != 0x5A:
        raise RuntimeError("incorrect feature/global interrupt/barrier guard state")
    if pre[offset("feature_state"):offset("feature_state") + 64] != bytes([0xA5]) * 64:
        raise RuntimeError("setup snapshots were not seeded")
    expected[offset("feature_state"):offset("feature_state") + 32] = struct.pack("<4Q", feature_before, feature_after, status, guard)
    results, register_rows = [], []
    for op, inst in zip(ops, instructions):
        name, pc = op["name"], int(inst["pc"], 16)
        event, resume = event_at(events, pc, inst["mnemonic"]), event_at(events, syms[f"resume_{name}"])
        if event["word"] != int(inst["word"], 16):
            raise RuntimeError("executed operation differs from ELF")
        seed = syms[f"seed_{name}"]
        event_at(events, seed, "addi")
        if regs[(seed, "x20", ":")] != SEED:
            raise RuntimeError("missing scalar destination sentinel")
        actual_before = regs[(syms[f"before_{name}"], "x21", "=")]
        actual_after = regs[(syms[f"resume_{name}"], "x22", "=")]
        event_at(events, syms[f"before_{name}"])
        capture = syms[f"capture_s4_{name}"]
        event_at(events, capture, "sd")
        returned = regs[(capture, "x20", ":")]
        if op["kind"] != "credit_store" and regs[(pc, "x20", "=")] != returned:
            raise RuntimeError("actual operation register write and destination snapshot disagree")
        if op["kind"] != "credit_read" and regs[(pc, "x6", ":")] != op["value"]:
            raise RuntimeError("wrong actual operation operand")
        observed_state = []
        for label, rd, csr in (("error", 23, 0x808), ("exclusive", 24, 0x7D3), ("enabled", 25, 0x304),
                              ("pending", 26, 0x344), ("status", 27, 0x300)):
            read_pc = syms[f"read_{label}_{name}"]
            read = event_at(events, read_pc, "csrrs")
            if read["word"] != (csr << 20) | (2 << 12) | (rd << 7) | 0x73:
                raise RuntimeError("wrong CSR state readback instruction")
            observed_state.append(regs[(read_pc, f"x{rd}", "=")])
        actual = [actual_before, actual_after, returned, *observed_state]
        record = offset(f"record_{name}")
        if pre[record:record + 128] != bytes([0xA5]) * 128 or tuple(actual) != struct.unpack_from("<8Q", memory, record):
            raise RuntimeError("state snapshots disagree with actual register events or were not seeded")
        enabled, pending = (8, 8) if op["kind"] == "pending" else (128, 128) if op["kind"] == "timer" else (0, 0)
        reference = [op["before"], op["after"], op["returned"], 0, op["exclusive"], enabled, pending, status]
        expected[record:record + 64] = struct.pack("<8Q", *reference)
        if op["kind"] == "credit_store":
            if regs[(pc, "x7", ":")] != op["address"] or accesses.get(pc) != [dict(bits=64, address=f"0x{op['address']:x}", direction="write", value=f"0x{op['value']:x}")]:
                raise RuntimeError("credit was not supplied by the actual device ESR store")
            received = re.findall(r"Receiving credits: fcc0 = 0x([0-9a-f]+), fcc1 = 0x([0-9a-f]+)", "\n".join(blocks[pc]))
            if received != [(f"{actual_after & 0xFFFF:x}", f"{actual_after >> 16:x}")]:
                raise RuntimeError("credit receiver trace disagrees with the FCCNB readback")
        elif op["kind"] == "flb":
            barrier = inputs(case)[0]
            for address_pc, value in ((syms[f"before_{name}"], actual_before), (syms[f"resume_{name}"], actual_after)):
                if accesses.get(address_pc) != [dict(bits=64, address=f"0x{FLB_BASE + barrier * 8:x}", direction="read", value=f"0x{value:x}")]:
                    raise RuntimeError("FLB before/after state did not come from the actual barrier ESR")
            old = re.findall(r"S0:fast_local_barrier(\d+) : (\d+) \(limit : (\d+)\)", "\n".join(blocks[pc]))
            new = re.findall(r"S0:fast_local_barrier(\d+) = (\d+)$", "\n".join(blocks[pc]), re.MULTILINE)
            limit = op["value"] >> 5 & 255
            internal_new = 0 if actual_before == limit else actual_before + 1
            if old != [(str(barrier), str(actual_before), str(limit))] or new != [(str(barrier), str(internal_new))]:
                raise RuntimeError("FLB helper trace disagrees with the actual input/counter transition")
            if actual_after != internal_new & 255 or returned != int(internal_new == 0):
                raise RuntimeError("FLB counter truncation/completion result disagrees")
        elif op["kind"] == "credit_consume":
            counter = op["value"] & 1
            transition = re.findall(r"\tfcc([01]) ([=:]) (\d+)$", "\n".join(blocks[pc]), re.MULTILINE)
            if transition != [(str(counter), ":", str(actual_before >> (16 * counter) & 0xFFFF)),
                              (str(counter), "=", str(actual_after >> (16 * counter) & 0xFFFF))]:
                raise RuntimeError("FCC decrement trace disagrees with actual FCCNB readbacks")
        passed = actual == reference and memory[record:record + 128] == expected[record:record + 128]
        results.append({**inst, "pass": passed, "actual": [f"0x{x:x}" for x in actual], "expected": [f"0x{x:x}" for x in reference],
                        "resume_cycle_gap": resume["cycle"] - event["cycle"]})
        register_rows.append({**inst, "hart": event["hart"], "cycle": event["cycle"], "resume_pc": f"0x{resume['pc']:x}",
            "resume_cycle": resume["cycle"], "destination_before": f"0x{regs[(seed, 'x20', ':')]:x}",
            "destination_after": f"0x{returned:x}", "state_names": ["before", "after", "returned", "tensor_error", "excl_mode", "mie", "mip", "mstatus"],
            "actual": [f"0x{x:x}" for x in actual], "accesses": accesses.get(pc, []), "raw_operation_events": blocks[pc],
            "operand": f"0x{regs[(pc, 'x6', ':')]:x}" if op["kind"] != "credit_read" else None,
            "esr_address": f"0x{regs[(pc, 'x7', ':')]:x}" if op["kind"] == "credit_store" else None,
            "before_pc": f"0x{syms[f'before_{name}']:x}",
            "state_read_pcs": {label: f"0x{syms[f'read_{label}_{name}']:x}" for label in ("error", "exclusive", "enabled", "pending", "status")}})
        print(f"  {name:<23} PC={inst['pc']} word={inst['word']} before={actual_before:#x} after={actual_after:#x} returned={returned:#x} {'PASS' if passed else 'FAIL'}")
    timer_now, scheduled, timer_after = struct.unpack_from("<3Q", memory, offset("timer_record"))
    if regs[(syms["timer_now"], "x9", "=")] != timer_now or regs[(syms["timer_after"], "x19", "=")] != timer_after:
        raise RuntimeError("timer memory snapshot differs from actual ESR load register writes")
    _, _, _, _, delay = inputs(case)
    if scheduled != timer_now + delay or timer_after < scheduled:
        raise RuntimeError("timer did not reach its device-programmed target")
    if accesses.get(syms["timer_now"]) != [dict(bits=64, address=f"0x{MTIME:x}", direction="read", value=f"0x{timer_now:x}")] or accesses.get(syms["timer_after"]) != [dict(bits=64, address=f"0x{MTIME:x}", direction="read", value=f"0x{timer_after:x}")]:
        raise RuntimeError("timer snapshots did not come from the actual IO-shire timer ESR")
    event_at(events, syms["timer_arm"], "sd")
    event_at(events, syms["timer_disarm"], "sd")
    if regs[(syms["timer_arm"], "x18", ":")] != scheduled or accesses.get(syms["timer_arm"]) != [dict(bits=64, address=f"0x{MTIMECMP:x}", direction="write", value=f"0x{scheduled:x}")]:
        raise RuntimeError("timer target did not come from the actual device timer-arm store")
    if accesses.get(syms["timer_disarm"]) != [dict(bits=64, address=f"0x{MTIMECMP:x}", direction="write", value="0xffffffffffffffff")]:
        raise RuntimeError("timer was not disabled by the actual device store")
    expected[offset("timer_record"):offset("timer_record") + 24] = struct.pack("<3Q", timer_now, scheduled, timer_after)
    timer_event = event_at(events, syms["op_stall_timer"], "csrrw")
    resumed = event_at(events, syms["resume_stall_timer"])
    waiting = re.findall(r"^(\d+): DEBUG EMU: \[(H\d+ S\d+:N\d+:C\d+:T\d+)\]\s+(Start|Stop) waiting for interrupt$", trace, re.MULTILINE)
    timed_waits = [(int(cycle), hart, action) for cycle, hart, action in waiting if timer_event["cycle"] <= int(cycle) <= resumed["cycle"]]
    if ([row[2] for row in timed_waits] != ["Start", "Stop"] or any(row[1] != "H0 S0:N0:C0:T0" for row in timed_waits)
            or resumed["cycle"] <= timer_event["cycle"] + 1):
        raise RuntimeError("missing actual STALL wait/wake execution evidence")
    for name in ("stall_exclusive", "stall_pending"):
        operation, after = event_at(events, syms[f"op_{name}"]), event_at(events, syms[f"resume_{name}"])
        if after["cycle"] != operation["cycle"] + 1:
            raise RuntimeError("nonwaiting STALL case unexpectedly waited")
        if any(operation["cycle"] <= int(cycle) <= after["cycle"] for cycle, _, _ in waiting):
            raise RuntimeError("nonwaiting STALL case logged a wait transition")
    completion, trap_marker, trap_cause = struct.unpack_from("<IIQ", memory, offset("completion"))
    expected[offset("completion"):offset("completion") + 4] = struct.pack("<I", DONE)
    passed = all(row["pass"] for row in results) and memory == expected and (completion, trap_marker, trap_cause) == (DONE, 0, 0)
    (out / "registers.json").write_text(json.dumps({"source": "actual SysEmu scalar register events plus device ESR/CSR snapshots",
        "feature_before": f"0x{feature_before:x}", "feature_after": f"0x{feature_after:x}", "operations": register_rows,
        "timer_now": timer_now, "timer_target": scheduled, "timer_after": timer_after, "timer_wait_events": timed_waits}, indent=2) + "\n")
    (out / "result.json").write_text(json.dumps({"case": case, "operation_count": len(ops), "csr_count": len(CSRS), "operations": results,
        "whole_monitor_matches": memory == expected, "timer_wait_cycles": resumed["cycle"] - timer_event["cycle"],
        "completion_word": f"0x{completion:08x}", "trap_marker": trap_marker, "trap_cause": trap_cause, "pass": passed}, indent=2) + "\n")
    if not passed:
        raise RuntimeError(f"synchronization state/reference checks failed; inspect {out}/result.json")
    print(f"Synchronization {case}: {len(ops)} sites, timed STALL gap={resumed['cycle'] - timer_event['cycle']} cycles, PASS; {out}")


def main() -> int:
    selected = sys.argv[1:] or ["primary", "exact"]
    if any(case not in ("primary", "exact") for case in selected):
        raise SystemExit("usage: python3 examples/synchronization.py [primary|exact ...]")
    env = runtime()
    for case in selected:
        print(f"\nSynchronization {case}: H0 S0:N0:C0:T0")
        execute(case, env)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print(f"synchronization.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
