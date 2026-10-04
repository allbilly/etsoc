#!/usr/bin/env python3
"""Execute ET message-port CSRs, device ESR sends, and a two-minion wakeup."""

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
from add import run_logged
from packed_memory import memory_events
from cache_control import cache_events


OUT = ROOT / "out" / "message-ports"
DONE, SEED, MASK64 = 0x4B4F5445, 0x5AA55AA55AA55AA5, (1 << 64) - 1
FEATURE, PORT_ESR = 0x01C0340000, 0x0100000800
FEATURE_CLEAR = 0x2E  # enable ML and cache/lock commands, preserve unrelated bits
CSRS = {f"port{kind}{p}": base + p for kind, base in
        (("ctrl", 0x9CC), ("head", 0xCC8), ("headnb", 0xCCC)) for p in range(4)}
CASES = ("primary", "exact", "blocking-primary", "blocking-exact", "overflow-primary", "overflow-exact")


def parameters(case):
    if case not in CASES:
        raise ValueError(f"unknown case: {case}")
    return (4, 2 if case.startswith("overflow") else 4, 1, 0) if case.endswith("primary") else (8, 2, 2, 0x12)


def payloads(case):
    if case.startswith("blocking"):
        return [0x0123456789ABCDEF if case.endswith("primary") else 0xFEDCBA9876543210]
    return [((0xAABBCCDD << 32) | ((0x81020304 + p * 0x01010101 + i * 0x11111111) & 0xFFFFFFFF))
            if case.endswith("primary") else (0xFEDCBA9876543210 ^ (p * 0x1111111111111111) ^ (i * 0x102030405060708))
            for p in range(4) for i in range(7)]


def operations(case):
    if case.startswith("blocking"):
        return [dict(name="receiver_config", port=0, kind="config", csr="portctrl0", hart=0),
                dict(name="receiver_head", port=0, kind="head", csr="porthead0", hart=0),
                dict(name="sender_send", port=0, kind="send", csr=None, hart=2)]
    ops = []
    for port in range(4):
        sequence = [("clamp", "config", None), ("enable", "config", None), ("empty_before", "empty", None),
                    ("send0", "send", 0), ("send1", "send", 1), ("head0", "head", 0), ("head1", "headnb", 1),
                    ("send2", "send", 2), ("send3", "send", 3), ("head2", "head", 2), ("head3", "headnb", 3),
                    ("send4", "send", 4), ("head4", "head", 4), ("empty_after", "empty", None),
                    ("send_discard", "send", 5), ("reset", "config", None), ("empty_reset", "empty", None),
                    ("disable", "config", None), ("send_disabled", "send", 6), ("control_read", "control", None)]
        if case.startswith("overflow"):
            sequence = [("enable", "config", None), ("send0", "send", 0), ("send1", "send", 1), ("send2", "send", 2),
                        ("head0", "head", 2), ("head1", "headnb", 1), ("head2", "headnb", 2), ("empty_after", "empty", None),
                        ("reset", "config", None), ("bulk_send", "send", 3), ("probe255", "headnb", 3),
                        ("restore255", "send", 4), ("wrap256", "send", 5), ("empty_wrap", "empty", None), ("control_read", "control", None)]
        for suffix, kind, index in sequence:
            family = "ctrl" if kind in ("config", "control") else "head" if kind == "head" else "headnb"
            op = dict(name=f"p{port}_{suffix}", port=port, kind=kind, suffix=suffix, index=index,
                      csr=None if kind == "send" else f"port{family}{port}", hart=0, repeat=255 if suffix == "bulk_send" else 1)
            if case.startswith("overflow") and kind in ("head", "headnb"):
                op["return_slot"] = 1 if suffix == "head1" else 0
            ops.append(op)
    return ops


def label(name):
    return [f".globl {name}", f"{name}:"]


def startup():
    # Bare translation, explicit interrupt state and trap target follow boot.S.
    # No FP arithmetic is used here. A hard-locked cache line supplies each port's
    # backing address; in this simulator LOCK_SW also zeroes that real 64B line.
    return ["# SPDX-License-Identifier: Apache-2.0",
            "# Startup provenance: Copyright (c) 2025 Ainekko, Co.; ET Platform boot.S.",
            ".option push", ".option norelax", ".option norvc", '.section .text.entry,"ax",@progbits',
            *label("_start"), "    csrwi satp, 0", "    csrwi mie, 0", "    csrwi mip, 0",
            "    csrci mstatus, 8", "    la sp, __stack_top", "    la t0, trap_handler", "    csrw mtvec, t0"]


def receiver_setup(ports, way):
    lines = ["    la t3, feature_state", f"    li t1, 0x{FEATURE:x}", *label("feature_before"),
             "    ld t0, 0(t1)", "    sd t0, 0(t3)", f"    li t2, {-1 ^ FEATURE_CLEAR}",
             "    and t0, t0, t2", "    sd t0, 0(t1)", *label("feature_after"),
             "    ld t0, 0(t1)", "    sd t0, 8(t3)", *label("status_initial"),
             "    csrr t0, mstatus", "    sd t0, 16(t3)", "    csrwi tensor_error, 0",
             "    csrwi mcache_control, 1", "    csrwi mcache_control, 0", "    csrwi ucache_control, 0"]
    for p in ports:
        lines.extend((f"    csrwi portctrl{p}, 0", f"    la t1, target_{p}", "    addi t1, t1, 64",
                      f"    li t2, 0x{way << 55:x}", "    or t1, t1, t2", *label(f"lock_{p}"),
                      "    csrw lock_sw, t1"))
    return lines


def config_operand(p, width, capacity, way, flags, enabled=True):
    # The actual linker address determines the shared-cache set. It is not a
    # host-side guessed physical address. Port control stores the set and way.
    bits = (way << 24) | ((capacity - 1) << 8) | ((width.bit_length() - 1) << 5) | flags | int(enabled)
    return [f"    la t1, target_{p}", "    addi t1, t1, 64", "    srli t1, t1, 6",
            "    andi t1, t1, 15", "    slli t1, t1, 16", f"    li t2, 0x{bits:x}", "    or t1, t1, t2"]


def finish_data(case, ops, ports):
    lines = [".balign 4096", "trap_handler:", "    csrr t0, mcause", "    la t1, trap_cause", "    sd t0, 0(t1)",
             "    li t0, 1", "    la t1, trap_marker", "    sw t0, 0(t1)", "    j park", ".option pop",
             '.section .data,"aw",@progbits', ".balign 64", *label("__monitor_start"), *label("input_payloads"),
             "    .dword " + ", ".join(f"0x{x:x}" for x in payloads(case)), ".balign 64,0xa5",
             *label("feature_state"), "    .fill 64,1,0xa5"]
    if case.startswith("overflow"):
        lines.extend((*label("input_count"), "    .dword 255", "    .fill 56,1,0xa5"))
    for p in ports:
        lines.extend((*label(f"target_{p}"), "    .fill 192,1,0xa5"))
    if case.startswith("blocking"):
        lines.extend((*label("handshake"), "    .dword 0,0", "    .fill 48,1,0xa5",
                      *label("blocking_record"), "    .fill 128,1,0xa5"))
    else:
        for op in ops:
            lines.extend((*label(f"record_{op['name']}"), "    .fill 128,1,0xa5"))
    lines.extend((*label("completion"), "    .word 0", *label("trap_marker"), "    .word 0",
                  *label("trap_cause"), "    .dword 0", *label("__monitor_end")))
    return lines


def kernel(case, ops):
    width, capacity, way, flags = parameters(case)
    if case.startswith("blocking"):
        return blocking_kernel(case, ops, way)
    lines = [*startup(), *receiver_setup(range(4), way)]
    for op in ops:
        p, name, kind, suffix = op["port"], op["name"], op["kind"], op["suffix"]
        lines.extend(("    csrwi tensor_error, 0", *label(f"before_{name}"), f"    csrr s5, portctrl{p}"))
        if kind == "config":
            if suffix == "clamp":
                clamp = (0xDEADBEEF << 32) | (0xFF << 24) | (0xF1 << 16) | (0xFFF if case == "exact" else 0xF1F)
                # Explicitly disable it, allowing 32B config testing without a wide send.
                lines.append(f"    li t1, 0x{clamp & ~1:x}")
            else:
                lines.extend(config_operand(p, width, capacity, way, flags, suffix != "disable"))
        elif kind == "send":
            lines.extend(("    la t1, input_payloads", *label(f"input_{name}"),
                          f"    ld t1, {(p * 7 + op['index']) * 8}(t1)", f"    li t2, 0x{PORT_ESR + p * 64:x}"))
            if op["repeat"] != 1:
                lines.extend(("    la t4, input_count", *label(f"count_{name}"), "    ld t4, 0(t4)"))
        lines.extend((f"    li s4, 0x{SEED:x}", f"    li s1, 0x{SEED:x}", f"    li s9, 0x{SEED:x}",
                      *label(f"seed_{name}"), "    addi t0, s4, 0", *label(f"op_{name}")))
        if kind == "send":
            lines.append("    sd t1, 0(t2) # actual device ESR write delivers a message")
            if op["repeat"] != 1:
                lines.extend(("    addi t4, t4, -1", f"    bnez t4, op_{name}"))
        elif kind == "config":
            lines.append(f"    csrrw s4, {op['csr']}, t1")
        else:
            lines.append(f"    csrr s4, {op['csr']}")
        lines.extend((*label(f"resume_{name}"), f"    csrr s6, portctrl{p}"))
        if kind in ("head", "headnb"):
            lines.extend((f"    la s9, target_{p}", "    addi s9, s9, 64", "    add s9, s9, s4",
                          *label(f"payload_{name}"), f"    {'lwu' if width == 4 else 'ld'} s1, 0(s9)"))
        lines.append(f"    la t3, record_{name}")
        for offset, reg in ((0, "s5"), (8, "s6"), (16, "s4"), (24, "s1"), (48, "s9")):
            lines.extend((*label(f"capture_{reg}_{name}"), f"    sd {reg}, {offset}(t3)"))
        for offset, which, csr, reg in ((32, "error", "tensor_error", "s7"),
                                       (40, "cache", "mcache_control", "s8"), (56, "status", "mstatus", "s10")):
            lines.extend((*label(f"read_{which}_{name}"), f"    csrr {reg}, {csr}", f"    sd {reg}, {offset}(t3)"))
    lines.extend((f"    li t0, 0x{DONE:x}", "    la t1, completion", "    sw t0, 0(t1)",
                  *label("park"), "    wfi", "    j park", *finish_data(case, ops, range(4))))
    return "\n".join(lines) + "\n"


def blocking_kernel(case, ops, way):
    lines = [*startup(), *label("read_hart"), "    csrr t0, mhartid", "    bnez t0, sender",
             *receiver_setup((0,), way), *config_operand(0, 8, 2, way, 2),
             *label("op_receiver_config"), "    csrrw s4, portctrl0, t1", *label("blocking_control"),
             "    csrr s5, portctrl0", f"    li s4, 0x{SEED:x}", *label("blocking_seed"), "    addi t0, s4, 0",
             "    la t3, handshake", "    li t0, 1", *label("receiver_ready"), "    sd t0, 0(t3)",
             *label("op_receiver_head"), "    csrr s4, porthead0 # empty -> wait; wake retries this same PC",
             *label("receiver_resumed"), "    csrr s6, portctrl0", "    la s9, target_0", "    addi s9, s9, 64",
             "    add s9, s9, s4", *label("blocking_payload"), "    ld s1, 0(s9)",
             "    la t3, blocking_record", "    sd s5, 0(t3)", "    sd s6, 8(t3)",
             *label("blocking_return"), "    sd s4, 16(t3)", "    sd s1, 24(t3)", "    sd s9, 48(t3)",
             *label("blocking_error"), "    csrr s7, tensor_error", "    sd s7, 32(t3)",
             *label("blocking_cache"), "    csrr s8, mcache_control", "    sd s8, 40(t3)",
             *label("blocking_status"), "    csrr s10, mstatus", "    sd s10, 56(t3)",
             f"    li t0, 0x{DONE:x}", "    la t1, completion", "    sw t0, 0(t1)",
             *label("park"), "    wfi", "    j park", "sender:",
             # H2 is minion 1/thread 0. No stack calls or shared trap handler writes on success.
             "    li t1, 2", "    bne t0, t1, trap_handler", "    la t3, handshake",
             *label("sender_poll"), "    ld t0, 0(t3)", "    beqz t0, sender_poll",
             "    li t0, 64", "sender_delay:", "    addi t0, t0, -1", "    bnez t0, sender_delay",
             "    la t1, input_payloads", *label("sender_input"), "    ld t1, 0(t1)", f"    li t2, 0x{PORT_ESR:x}",
             *label("op_sender_send"), "    sd t1, 0(t2) # H2 -> H0 port 0, entirely device-side",
             "    li t0, 1", *label("sender_done"), "    sd t0, 8(t3)", *label("sender_park"),
             "    wfi", "    j sender_park", *finish_data(case, ops, (0,))]
    return "\n".join(lines) + "\n"


def one(events, pc, hart=0, mnemonic=""):
    matches = [e for e in events if e["pc"] == pc and e["hart"].split()[0] == f"H{hart}" and
               e["disassembly"].startswith(mnemonic)]
    if len(matches) != 1:
        raise RuntimeError(f"expected one H{hart} event {mnemonic} at {pc:#x}, found {len(matches)}")
    return matches[0]


def raw_blocks(trace):
    """Keep actual instruction groups, including target-hart asynchronous logs."""
    blocks, current = {}, None
    for line in trace.splitlines():
        match = re.search(r"\[(H\d+) .*?\] I\(M\): 0x([0-9a-f]+)", line)
        if match:
            current = (int(match.group(1)[1:]), int(match.group(2), 16))
            blocks.setdefault(current, []).append([])
        if current is not None:
            blocks[current][-1].append(line)
    return blocks


def sends_in(lines):
    return [(int(hart), int(port), int(word, 16), int(addr, 16)) for hart, port, word, addr in re.findall(
        r"Writing MSG_PORT \(H(\d+) p(\d+)\) data 0x([0-9a-f]+) to addr 0x\s*([0-9a-f]+)", "\n".join(lines))]


def execute(case, env):
    out = OUT if case == "primary" else OUT / case
    out.mkdir(parents=True, exist_ok=True)
    log = out / "commands.log"
    log.write_text("")
    ops = operations(case)
    (out / "kernel.S").write_text(kernel(case, ops))
    (out / "link.ld").write_text(LINKER)
    for name in ("result.json", "registers.json", "trace.log", "prestart.bin", "output.bin"):
        (out / name).unlink(missing_ok=True)
    stage = f"/tmp/etsoc1-message-ports-{uuid.uuid4().hex[:10]}"
    container, podman = env["kind"] == "podman", shutil.which("podman") or "podman"
    def checked(argv):
        result = run_logged(log, argv)
        if result.returncode:
            raise RuntimeError(f"message-port command failed ({result.returncode}); inspect {log}")
        return result
    if container:
        checked([podman, "exec", env["container"], "mkdir", "-p", stage])
        for name in ("kernel.S", "link.ld"):
            checked([podman, "cp", str(out / name), f"{env['container']}:{stage}/{name}"])
    work = stage if container else str(out)
    shell = command(env, ["bash", "-lc"])
    tp, qwork = shlex.quote(env["tool_prefix"]), shlex.quote(work)
    built = run_logged(log, [*shell, f"set -euo pipefail; cd {qwork}; "
        f"{tp}as --march=rv64imfc -mabi=lp64f -o kernel.o kernel.S; "
        f"{tp}ld --no-relax --build-id=none -T link.ld -o kernel.elf kernel.o; "
        f"{tp}objdump -d -M numeric kernel.elf > kernel.asm; "
        f"{tp}readelf -h -l -S kernel.elf > elf-inspection.txt; "
        f"{tp}objdump -h kernel.elf > sections.txt; {tp}nm -n --defined-only kernel.elf > symbols.txt; "
        f"{tp}objcopy -O binary --only-section=.text kernel.elf text.bin"])
    if container:
        checked([podman, "cp", f"{env['container']}:{stage}/.", str(out)])
    if built.returncode:
        raise RuntimeError(f"assemble message-port ELF failed; inspect {log}")
    syms, inspection = symbols((out / "symbols.txt").read_text()), (out / "elf-inspection.txt").read_text()
    entry_match = re.search(r"Entry point address:\s+0x([0-9a-f]+)", inspection)
    text_match = re.search(r"^\s*\[\s*\d+\]\s+\.text\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", inspection, re.MULTILINE)
    if not entry_match or not text_match:
        raise RuntimeError("missing ELF entry/text mapping")
    entry = int(entry_match.group(1), 16)
    text_vma, text_offset, text_size = (int(text_match.group(i), 16) for i in (1, 2, 3))
    text, asm = (out / "text.bin").read_bytes(), (out / "kernel.asm").read_text()
    instructions = []
    for op in ops:
        pc = syms[f"op_{op['name']}"]
        raw = text[pc - text_vma:pc - text_vma + 4]
        word = int.from_bytes(raw, "little")
        csr = CSRS[op["csr"]] if op["csr"] else None
        send, config = op["kind"] == "send", op["kind"] == "config"
        valid = ((word & 0x7F, word >> 12 & 7, word >> 15 & 31, word >> 20 & 31) == (0x23, 3, 7, 6)) if send else \
                ((word & 0x7F, word >> 20, word >> 12 & 7, word >> 7 & 31, word >> 15 & 31) ==
                 (0x73, csr, 1 if config else 2, 20, 6 if config else 0))
        decoded = [line.strip() for line in asm.splitlines() if re.search(rf"\b{pc:x}:\s", line)]
        if not valid or len(raw) != 4 or len(decoded) != 1:
            raise RuntimeError(f"wrong message-port instruction {op['name']}: {decoded}")
        instructions.append(dict(name=op["name"], csr=f"0x{csr:03x}" if csr else None, csr_name=op["csr"],
            hart=f"H{op['hart']}", mnemonic="sd" if send else "csrrw" if config else "csrrs", pc=f"0x{pc:x}",
            expected_executions=2 if case.startswith("blocking") and op["kind"] == "head" else op.get("repeat", 1),
            word=f"0x{word:08x}", bytes_memory_order=raw.hex(" "), file_offset=f"0x{text_offset + pc - text_vma:x}", decoded=decoded[0]))
    (out / "operations.json").write_text(json.dumps(instructions, indent=2) + "\n")
    (out / "operations.bin").write_bytes(b"".join(bytes.fromhex(row["bytes_memory_order"]) for row in instructions))
    (out / "op.bin").write_bytes(bytes.fromhex(instructions[0]["bytes_memory_order"]))
    dump_addr, dump_size = syms["__monitor_start"], syms["__monitor_end"] - syms["__monitor_start"]
    blocking = case.startswith("blocking")
    (out / "elf-layout.json").write_text(json.dumps(dict(entry=f"0x{entry:x}", selected_harts=["H0", "H2"] if blocking else ["H0"],
        executable_sections=[".text"], text_vma=f"0x{text_vma:x}", text_file_offset=f"0x{text_offset:x}", text_size=text_size,
        monitor_address=f"0x{dump_addr:x}", monitor_size=dump_size, operations=instructions,
        symbols={name: f"0x{addr:x}" for name, addr in syms.items()}), indent=2) + "\n")
    sim = [env["simulator"], "-l", "-ls", "0,0x5" if blocking else "0,0x1", "-sp_dis", "-Werror=memory",
           "-reset_pc", hex(entry), "-single_thread", "-minions", "0x3" if blocking else "0x1", "-shires", "0x1",
           "-max_cycles", "20000", "-elf_load", f"{work}/kernel.elf",
           "-dump_at_pc_pc", hex(entry), "-dump_at_pc_addr", hex(dump_addr), "-dump_at_pc_size", hex(dump_size),
           "-dump_at_pc_file", f"{work}/prestart.bin", "-dump_addr", hex(dump_addr), "-dump_size", str(dump_size),
           "-dump_file", f"{work}/output.bin"]
    run = run_logged(log, command(env, ["timeout", "--signal=TERM", "--kill-after=5s", "90s", *sim]))
    (out / "trace.log").write_text(run.stdout or "")
    if container:
        checked([podman, "cp", f"{env['container']}:{stage}/.", str(out)])
        checked([podman, "exec", env["container"], "rm", "-rf", stage])
    if run.returncode:
        raise RuntimeError(f"execute message-port ELF failed ({run.returncode}); inspect {out}/trace.log")
    validate(case, ops, instructions, out, syms, dump_addr, dump_size)


def validate(case, ops, instructions, out, syms, start, size):
    trace = (out / "trace.log").read_text()
    if ("Finishing emulation" not in trace or "Error, max cycles reached" in trace or
            re.search(r"\b(?:Trapping|exception)\b|PORT_WRITE .* unlocked", trace, re.I)):
        raise RuntimeError("message-port execution did not complete normally")
    events, _ = trace_data(trace)
    blocks, accesses = raw_blocks(trace), memory_events(trace)
    memory, pre = (out / "output.bin").read_bytes(), (out / "prestart.bin").read_bytes()
    if len(memory) != size or len(pre) != size:
        raise RuntimeError("incomplete simulated memory dumps")
    off = lambda name: syms[name] - start
    expected = bytearray(pre)
    values = payloads(case)
    if struct.unpack_from(f"<{len(values)}Q", pre, off("input_payloads")) != tuple(values):
        raise RuntimeError("wrong deterministic input memory")
    feature_before, feature_after, status = struct.unpack_from("<3Q", memory, off("feature_state"))
    for name, value in (("feature_before", feature_before), ("feature_after", feature_after), ("status_initial", status)):
        if one(events, syms[name])["registers"]["x5:="] != value:
            raise RuntimeError("setup state is not the real ESR/CSR readback")
    if feature_after != feature_before & ~FEATURE_CLEAR or status & 8:
        raise RuntimeError("wrong feature/global interrupt state")
    expected[off("feature_state"):off("feature_state") + 24] = struct.pack("<3Q", feature_before, feature_after, status)
    width, capacity, way, flags = parameters(case)
    blocking = case.startswith("blocking")
    ports = (0,) if blocking else range(4)
    locks = cache_events(trace)
    for p in ports:
        address = syms[f"target_{p}"] + 64
        one(events, syms[f"lock_{p}"], mnemonic="csrrw")
        if locks[syms[f"lock_{p}"]]["accesses"] != [dict(bits=512, address=f"0x{address:x}", direction="write", bytes=bytes(64).hex(" "))]:
            raise RuntimeError("port backing line was not zeroed by a real hard-lock command")
        if pre[off(f"target_{p}"):off(f"target_{p}") + 192] != bytes([0xA5]) * 192:
            raise RuntimeError("target and guards were not seeded")
        expected[off(f"target_{p}") + 64:off(f"target_{p}") + 128] = bytes(64)
    one(events, syms["park"], mnemonic="wfi")
    if set(e["hart"].split()[0] for e in events) != ({"H0", "H2"} if blocking else {"H0"}):
        raise RuntimeError("unexpected execution harts")
    if blocking:
        rows, registers, proof = validate_blocking(case, instructions, events, blocks, accesses, syms, memory, expected, off, status)
    else:
        rows, registers = [], []
        if case.startswith("overflow") and struct.unpack_from("<Q", pre, off("input_count"))[0] != 255:
            raise RuntimeError("wrong real bulk-send input count")
        for p in ports:
            address = syms[f"target_{p}"] + 64
            configured = (way << 24) | (((address >> 6) & 15) << 16) | ((capacity - 1) << 8) | ((width.bit_length() - 1) << 5) | flags | 1 | 0x8000
            control, pointer = 0x8040, 0
            for op, inst in [(op, inst) for op, inst in zip(ops, instructions) if op["port"] == p]:
                name, kind, suffix = op["name"], op["kind"], op["suffix"]
                pc = int(inst["pc"], 16)
                actual_events = [e for e in events if e["pc"] == pc and e["hart"].split()[0] == "H0"]
                if len(actual_events) != inst["expected_executions"] or any(e["word"] != int(inst["word"], 16) for e in actual_events):
                    raise RuntimeError("executed word differs from the ELF")
                event = actual_events[0]
                before, after, returned, payload, payload_address = control, control, SEED, SEED, SEED
                if kind == "config":
                    after = (3 << 24) | (1 << 16) | 0x8F12 | ((2 if case == "primary" else 5) << 5) if suffix == "clamp" else configured & ~int(suffix == "disable")
                    returned, control, pointer = before, after, 0
                elif kind == "control":
                    returned = control
                elif kind == "empty":
                    returned = MASK64
                elif kind == "send":
                    send_value = values[p * 7 + op["index"]]
                    if any(e["registers"] != {"x6::": send_value, "x7::": PORT_ESR + p * 64} for e in actual_events):
                        raise RuntimeError("actual ESR send address or operand differs")
                    if one(events, syms[f"input_{name}"])["registers"]["x6:="] != send_value:
                        raise RuntimeError("send did not load its actual device input")
                    if len(blocks[(0, pc)]) != len(actual_events):
                        raise RuntimeError("missing repeated send instruction groups")
                    for block in blocks[(0, pc)]:
                        wanted = [] if suffix == "send_disabled" else [(0, p, send_value >> (i * 32) & 0xFFFFFFFF, address + pointer * width + 4 * i) for i in range(width // 4)]
                        if sends_in(block) != wanted:
                            raise RuntimeError("raw message-port writes disagree with the expected delivery/drop")
                        if suffix != "send_disabled":
                            pos = off(f"target_{p}") + 64 + pointer * width
                            expected[pos:pos + width] = send_value.to_bytes(8, "little")[:width]
                            pointer = (pointer + 1) % capacity
                    if accesses.get(pc) != [dict(bits=64, address=f"0x{PORT_ESR + p * 64:x}", direction="write", value=f"0x{send_value:x}")] * len(actual_events):
                        raise RuntimeError("message was not sent by an actual device ESR store")
                    if suffix == "bulk_send" and one(events, syms[f"count_{name}"])["registers"]["x29:="] != len(actual_events):
                        raise RuntimeError("bulk count did not come from the actual device input")
                elif kind in ("head", "headnb"):
                    returned = op.get("return_slot", op["index"] % capacity) * width
                    payload_address, payload = address + returned, values[p * 7 + op["index"]] & ((1 << (width * 8)) - 1)
                    # insn_lwu prints "lw" in this pinned SysEmu. Verify the
                    # unsigned-load funct3 and destination explicitly as well.
                    load = one(events, syms[f"payload_{name}"], mnemonic="lw" if width == 4 else "ld")
                    if (load["word"] & 0x7F, load["word"] >> 12 & 7, load["word"] >> 7 & 31, load["word"] >> 15 & 31) != (3, 6 if width == 4 else 3, 9, 25):
                        raise RuntimeError("head payload used the wrong encoded scalar load")
                    if load["registers"]["x9:="] != payload or load["registers"]["x25::"] != payload_address:
                        raise RuntimeError("head payload was not read from the actual returned memory offset")
                    if accesses.get(load["pc"]) != [dict(bits=width * 8, address=f"0x{payload_address:x}", direction="read", value=f"0x{payload:x}")]:
                        raise RuntimeError("head payload load has the wrong actual memory access")
                actual = [one(events, syms[f"before_{name}"])["registers"]["x21:="],
                          one(events, syms[f"resume_{name}"])["registers"]["x22:="],
                          one(events, syms[f"capture_s4_{name}"])["registers"]["x20::"],
                          one(events, syms[f"capture_s1_{name}"])["registers"]["x9::"],
                          one(events, syms[f"read_error_{name}"])["registers"]["x23:="],
                          one(events, syms[f"read_cache_{name}"])["registers"]["x24:="],
                          one(events, syms[f"capture_s9_{name}"])["registers"]["x25::"],
                          one(events, syms[f"read_status_{name}"])["registers"]["x26:="]]
                seed = one(events, syms[f"seed_{name}"])["registers"]["x20::"]
                if seed != SEED or (kind != "send" and event["registers"]["x20:="] != actual[2]):
                    raise RuntimeError("destination seed/write/snapshot mismatch")
                record = off(f"record_{name}")
                if pre[record:record + 128] != bytes([0xA5]) * 128 or struct.unpack_from("<8Q", memory, record) != tuple(actual):
                    raise RuntimeError("state records are not the actual seeded device snapshots")
                reference = [before, after, returned, payload, 0, 0, payload_address, status]
                expected[record:record + 64] = struct.pack("<8Q", *reference)
                passed = actual == reference
                rows.append({**inst, "pass": passed, "actual": [f"0x{x:x}" for x in actual], "expected": [f"0x{x:x}" for x in reference]})
                registers.append({**inst, "cycle": event["cycle"], "destination_before": f"0x{seed:x}",
                    "state_names": ["control_before", "control_after", "returned", "payload", "tensor_error", "mcache_control", "payload_address", "mstatus"],
                    "actual": [f"0x{x:x}" for x in actual], "instruction_event": event, "instruction_events": actual_events,
                    "raw_operation_events": [line for block in blocks[(0, pc)] for line in block]})
        if re.search(r"(?:Start|Stop) waiting for message", trace):
            raise RuntimeError("self-loop nonblocking/nonempty reads unexpectedly waited")
        proof = None
    queue_proof = None
    if case.startswith("overflow"):
        by_name = {row["name"]: row for row in rows}
        queue_proof = []
        for p in ports:
            stage = lambda suffix: by_name[f"p{p}_{suffix}"]["actual"]
            queue_proof.append(dict(port=p, capacity=capacity, overfill_head_results=[stage(f"head{i}")[2] for i in range(3)],
                overfill_payloads=[stage(f"head{i}")[3] for i in range(3)], empty_after_drain=stage("empty_after")[2],
                bulk_send_count=len([e for e in events if e["pc"] == syms[f"op_p{p}_bulk_send"]]),
                probe255_result=stage("probe255")[2], empty_after_wrap=stage("empty_wrap")[2],
                tensor_error=stage("wrap256")[4], counter_interpretation="uint8 size reconstructed from complete real send/head events; not directly exposed by a CSR"))
    completion, marker, cause = struct.unpack_from("<IIQ", memory, off("completion"))
    expected[off("completion"):off("completion") + 4] = struct.pack("<I", DONE)
    passed = all(row["pass"] for row in rows) and memory == expected and (completion, marker, cause) == (DONE, 0, 0)
    (out / "expected.bin").write_bytes(expected)
    (out / "registers.json").write_text(json.dumps(dict(source="actual SysEmu register events, device snapshots and raw message-port memory-write logs",
        feature_before=f"0x{feature_before:x}", feature_after=f"0x{feature_after:x}", operations=registers, blocking_proof=proof, queue_proof=queue_proof), indent=2) + "\n")
    (out / "result.json").write_text(json.dumps(dict(case=case, operation_count=len(ops), csr_count=2 if blocking else 12,
        message_width=8 if blocking else width, capacity=2 if blocking else capacity, operations=rows,
        whole_monitor_matches=memory == expected, blocking_proof=proof, queue_proof=queue_proof, completion_word=f"0x{completion:08x}", trap_marker=marker, trap_cause=cause, **{"pass": passed}), indent=2) + "\n")
    if not passed:
        differences = [i for i, (a, b) in enumerate(zip(memory, expected)) if a != b]
        raise RuntimeError(f"message-port state/reference mismatch: {out}/result.json; first differing memory offsets: {differences[:8]}")
    if blocking:
        print(f"  H0 PC={proof['retry_pc']} head results={proof['head_results']}; H2 send cycle={proof['send_cycle']}; retry gap={proof['wait_cycle_gap']} cycles")
        print(f"  actual payload={proof['payload']}; guarded memory PASS")
    elif case.startswith("overflow"):
        for row in queue_proof:
            print(f"  port {row['port']}: two slots, 3 sends -> offsets {row['overfill_head_results']}; "
                  f"{row['bulk_send_count']} bulk sends -> head {row['probe255_result']}; "
                  f"consume/refill/send -> empty {row['empty_after_wrap']}, tensor_error={row['tensor_error']}")
    else:
        for p in ports:
            heads = [row for row in rows if row['name'].startswith(f'p{p}_head')]
            print(f"  port {p}: first head PC={heads[0]['pc']} word={heads[0]['word']}; actual offsets={[int(row['actual'][2], 16) for row in heads]}")
    scope = "real H2 -> H0 blocking wake/retry" if blocking else f"{width}B " + (
        "queue overfill and uint8 count wrap" if case.startswith("overflow") else "FIFO/wrap/reset/drop")
    print(f"Message ports {case}: {len(ops)} sites, {scope}, PASS; {out}")


def validate_blocking(case, instructions, events, blocks, accesses, syms, memory, expected, off, status):
    pc = syms["op_receiver_head"]
    heads = [e for e in events if e["pc"] == pc and e["hart"].split()[0] == "H0"]
    send = one(events, syms["op_sender_send"], hart=2, mnemonic="sd")
    config = one(events, syms["op_receiver_config"], mnemonic="csrrw")
    by_name = {row["name"]: row for row in instructions}
    if len(heads) != 2 or [e["registers"]["x20:="] for e in heads] != [MASK64, 0] or any(e["word"] != int(by_name["receiver_head"]["word"], 16) for e in heads):
        raise RuntimeError("blocking read did not execute and retry the same CSR instruction with -1 then 0")
    if not heads[0]["cycle"] < send["cycle"] <= heads[1]["cycle"]:
        raise RuntimeError("sender did not run after the receiver actually blocked")
    waiting = [(int(cycle), hart, action) for cycle, hart, action in re.findall(
        r"^(\d+): DEBUG EMU: \[(H\d+) .*?\]\s+(Start|Stop) waiting for message$", ("\n".join(line for groups in blocks.values() for group in groups for line in group)), re.MULTILINE)]
    if len(waiting) != 2 or [r[1:] for r in waiting] != [("H0", "Start"), ("H0", "Stop")] or waiting[0][0] != heads[0]["cycle"] or waiting[1][0] != send["cycle"]:
        raise RuntimeError("missing actual receiver wait/wake transitions around the device send")
    value, address = payloads(case)[0], syms["target_0"] + 64
    if send["word"] != int(by_name["sender_send"]["word"], 16) or send["registers"]["x6::"] != value or send["registers"]["x7::"] != PORT_ESR:
        raise RuntimeError("wrong actual second-minion send instruction/operands")
    if sends_in(blocks[(2, send["pc"])][0]) != [(0, 0, value & 0xFFFFFFFF, address), (0, 0, value >> 32, address + 4)]:
        raise RuntimeError("second-minion message did not write both real words into the receiver line")
    if accesses.get(send["pc"]) != [dict(bits=64, address=f"0x{PORT_ESR:x}", direction="write", value=f"0x{value:x}")]:
        raise RuntimeError("second-minion send lacks a real ESR store")
    one(events, syms["sender_park"], hart=2, mnemonic="wfi")
    if one(events, syms["sender_input"], hart=2)["registers"]["x6:="] != value:
        raise RuntimeError("second-minion input was not loaded on the device")
    if struct.unpack_from("<2Q", memory, off("handshake")) != (1, 1):
        raise RuntimeError("receiver-ready and sender-done handshake did not complete")
    for name, hart, offset in (("receiver_ready", 0, 0), ("sender_done", 2, 8)):
        event = one(events, syms[name], hart=hart, mnemonic="sd")
        if event["registers"]["x5::"] != 1 or accesses.get(event["pc"]) != [dict(bits=64,
                address=f"0x{syms['handshake'] + offset:x}", direction="write", value="0x1")]:
            raise RuntimeError("handshake was not written by the selected device hart")
    load = one(events, syms["blocking_payload"], mnemonic="ld")
    actual = [one(events, syms["blocking_control"])["registers"]["x21:="],
              one(events, syms["receiver_resumed"])["registers"]["x22:="],
              one(events, syms["blocking_return"])["registers"]["x20::"], load["registers"]["x9:="],
              one(events, syms["blocking_error"])["registers"]["x23:="],
              one(events, syms["blocking_cache"])["registers"]["x24:="], load["registers"]["x25::"],
              one(events, syms["blocking_status"])["registers"]["x26:="]]
    control = (parameters(case)[2] << 24) | (((address >> 6) & 15) << 16) | 0x8163
    reference = [control, control, 0, value, 0, 0, address, status]
    if config["registers"]["x20:="] != 0x8040 or config["word"] != int(by_name["receiver_config"]["word"], 16) or one(events, syms["blocking_seed"])["registers"]["x20::"] != SEED:
        raise RuntimeError("wrong actual control return, encoding or destination seed")
    if accesses.get(load["pc"]) != [dict(bits=64, address=f"0x{address:x}", direction="read", value=f"0x{value:x}")]:
        raise RuntimeError("woken receiver did not read the actual message payload")
    if struct.unpack_from("<8Q", memory, off("blocking_record")) != tuple(actual):
        raise RuntimeError("blocking state snapshots differ from actual register writes")
    expected[off("blocking_record"):off("blocking_record") + 64] = struct.pack("<8Q", *reference)
    expected[off("handshake"):off("handshake") + 16] = struct.pack("<2Q", 1, 1)
    expected[off("target_0") + 64:off("target_0") + 72] = struct.pack("<Q", value)
    proof = dict(receiver_hart="H0", sender_hart="H2", retry_pc=f"0x{pc:x}", head_cycles=[e["cycle"] for e in heads],
        head_results=[f"0x{e['registers']['x20:=']:x}" for e in heads], send_cycle=send["cycle"], wait_events=waiting,
        wait_cycle_gap=heads[1]["cycle"] - heads[0]["cycle"], payload=f"0x{actual[3]:016x}")
    rows = [{**inst, "pass": actual == reference} for inst in instructions]
    registers = [{**inst, "instruction_events": heads if inst["name"] == "receiver_head" else [config] if inst["name"] == "receiver_config" else [send],
                  "raw_operation_events": blocks[(int(inst["hart"][1:]), int(inst["pc"], 16))]} for inst in instructions]
    registers[1].update(actual=[f"0x{x:x}" for x in actual], expected=[f"0x{x:x}" for x in reference])
    return rows, registers, proof


def main():
    selected = sys.argv[1:] or list(CASES)
    if any(case not in CASES for case in selected):
        raise SystemExit("usage: python3 examples/message_ports.py [" + "|".join(CASES) + " ...]")
    env = runtime()
    for case in selected:
        execute(case, env)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print(f"message_ports.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
