#!/usr/bin/env python3
"""Observe the eight unimplemented ET handlers and the disabled graphics gate.

This diagnostic intentionally takes traps. It verifies fault delivery and
unchanged destinations; it does not implement any missing arithmetic.
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
import struct
import subprocess
import sys
import uuid

from gemm import LINKER, ROOT, command, report_lanes, runtime, symbols, trace_data
from add import event_at, run_logged


OUT = ROOT / "out" / "trap-stubs"
DONE = 0x4B4F5445
SEED = 0xA5A5A5A5
SCALAR_SEED = 0x5AA55AA55AA55AA5
OPERATIONS = [
    ("fdiv.pi", "fdiv.pi f20, f10, f11", 30),
    ("fdiv.ps", "fdiv.ps f20, f10, f11, rne", 30),
    ("fdivu.pi", "fdivu.pi f20, f10, f11", 30),
    ("frem.pi", "frem.pi f20, f10, f11", 30),
    ("fremu.pi", "fremu.pi f20, f10, f11", 30),
    ("frsq.ps", "frsq.ps f20, f10", 30),
    ("fsin.ps", "fsin.ps f20, f10", 30),
    ("fsqrt.ps", "fsqrt.ps f20, f10", 30),
    ("bitmixb", "bitmixb s4, t1, t2", 2),
]


def name(mnemonic: str) -> str:
    return mnemonic.replace(".", "_")


def kernel(case: str) -> str:
    a = (1, 2, 3, 4, 5, 6, 7, 8) if case == "primary" else (8, 7, 6, 5, 4, 3, 2, 1)
    b = (10, 20, 30, 40, 50, 60, 70, 80) if case == "primary" else (3, 5, 7, 9, 11, 13, 15, 17)
    lines = ["# SPDX-License-Identifier: Apache-2.0",
             "# Startup provenance: Copyright (c) 2025 Ainekko, Co.; ET Platform boot.S.",
             ".option push", ".option norelax", ".option norvc", '.section .text.entry,"ax",@progbits',
             ".globl _start", "_start:", "    csrwi satp, 0", "    csrr t0, mstatus", "    li t1, 0x6000",
             "    or t0, t0, t1", "    csrw mstatus, t0", "    csrwi fcsr, 0", "    csrwi mip, 0",
             "    csrwi tensor_mask, 0", "    la sp, __stack_top", "    la t0, trap_handler", "    csrw mtvec, t0",
             "    li s1, 0", "    li t0, 255", "    mova.m.x t0", "    la t0, input_a", "    flq2 f10, 0(t0)",
             "    la t0, input_b", "    flq2 f11, 0(t0)",
             "    li t6, 0x01c0340000", ".globl feature_read", "feature_read:", "    ld t0, 0(t6)",
             "    la t1, feature_state", "    sd t0, 0(t1)"]
    for mnemonic, assembly, cause in OPERATIONS:
        label = name(mnemonic)
        lines.extend((f"    la s0, record_{label}", "    la t0, seed", "    flq2 f20, 0(t0)",
                      f"    li s4, 0x{SCALAR_SEED:x}", "    li t1, 0xaa55", "    li t2, 0xc396",
                      f".globl before_{label}", f"before_{label}:", "    fsq2 f20, 32(s0)",
                      f"scalar_before_{label}:", "    sd s4, 96(s0)", f".globl op_{label}", f"op_{label}:", f"    {assembly}",
                      f".globl after_{label}", f"after_{label}:", "    fsq2 f20, 64(s0)",
                      f"scalar_after_{label}:", "    sd s4, 104(s0)"))
    lines.extend(("    la t0, trap_count", "    sd s1, 0(t0)", f"    li t1, 0x{DONE:x}",
                  "    la t0, completion", "    sw t1, 0(t0)", ".globl park", "park:", "    wfi", "    j park",
                  ".balign 4096", "trap_handler:", ".globl capture_mcause", "capture_mcause:", "    csrr t0, mcause",
                  "    sd t0, 0(s0)", ".globl capture_mepc", "capture_mepc:", "    csrr t0, mepc", "    sd t0, 8(s0)",
                  ".globl capture_mtval", "capture_mtval:", "    csrr t1, mtval", "    sd t1, 16(s0)",
                  "    addi s1, s1, 1", "    addi t0, t0, 4", "    csrw mepc, t0", "    mret", ".option pop",
                  '.section .data,"aw",@progbits', ".balign 32", ".globl __monitor_start", "__monitor_start:",
                  "feature_state:", "    .dword 0xa5a5a5a5a5a5a5a5"))
    for mnemonic, _, _ in OPERATIONS:
        lines.extend((".balign 32", f"record_{name(mnemonic)}:", "    .fill 128,1,0xa5"))
    lines.extend(("trap_count:", "    .dword 0", "completion:", "    .word 0", "seed:", "    .fill 32,1,0xa5",
                  "input_a:", "    .word " + ", ".join(str(x) for x in a),
                  "input_b:", "    .word " + ", ".join(str(x) for x in b),
                  ".globl __monitor_end", "__monitor_end:"))
    return "\n".join(lines) + "\n"


def execute(case: str, env: dict[str, str]) -> None:
    out = OUT if case == "primary" else OUT / case
    out.mkdir(parents=True, exist_ok=True)
    log = out / "commands.log"
    log.write_text("")
    for file in ("result.json", "registers.json", "output.bin", "prestart.bin", "trace.log"):
        (out / file).unlink(missing_ok=True)
    (out / "kernel.S").write_text(kernel(case))
    (out / "link.ld").write_text(LINKER)
    stage = f"/tmp/etsoc1-trap-stubs-{uuid.uuid4().hex[:10]}"
    container, podman = env["kind"] == "podman", shutil.which("podman") or "podman"

    def checked(argv):
        result = run_logged(log, argv)
        if result.returncode:
            raise RuntimeError(f"trap diagnostic command failed ({result.returncode}); inspect {log}")
        return result

    if container:
        checked([podman, "exec", env["container"], "mkdir", "-p", stage])
        for file in ("kernel.S", "link.ld"):
            checked([podman, "cp", str(out / file), f"{env['container']}:{stage}/{file}"])
        work, shell = stage, command(env, ["bash", "-lc"])
    else:
        work, shell = str(out), ["bash", "-lc"]
    tp, qwork = shlex.quote(env["tool_prefix"]), shlex.quote(work)
    build = (f"set -euo pipefail; cd {qwork}; "
             f"{tp}as --march=rv64imfc -mabi=lp64f -o kernel.o kernel.S; "
             f"{tp}ld --no-relax --build-id=none -T link.ld -o kernel.elf kernel.o; "
             f"{tp}objdump -d -M numeric kernel.elf > kernel.asm; "
             f"{tp}readelf -h -l -S kernel.elf > elf-inspection.txt; "
             f"{tp}nm -n --defined-only kernel.elf > symbols.txt; "
             f"{tp}objcopy -O binary --only-section=.text kernel.elf text.bin")
    built = run_logged(log, [*shell, build])
    if container:
        checked([podman, "cp", f"{env['container']}:{stage}/.", str(out)])
    if built.returncode:
        raise RuntimeError(f"trap diagnostic assembly failed; inspect {log}")
    syms, inspection = symbols((out / "symbols.txt").read_text()), (out / "elf-inspection.txt").read_text()
    entry_match = re.search(r"Entry point address:\s+0x([0-9a-fA-F]+)", inspection)
    section = re.search(r"^\s*\[\s*\d+\]\s+\.text\s+\S+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)", inspection, re.MULTILINE)
    if not entry_match or not section:
        raise RuntimeError("missing trap diagnostic ELF entry or text mapping")
    entry = int(entry_match.group(1), 16)
    text_vma, text_offset, text_size = (int(section.group(i), 16) for i in (1, 2, 3))
    text, disassembly = (out / "text.bin").read_bytes(), (out / "kernel.asm").read_text()
    instructions = []
    for mnemonic, _, cause in OPERATIONS:
        pc = syms[f"op_{name(mnemonic)}"]
        raw = text[pc - text_vma:pc - text_vma + 4]
        decoded = [line.strip() for line in disassembly.splitlines() if re.search(rf"\b{pc:x}:\s", line)]
        if len(raw) != 4 or len(decoded) != 1 or mnemonic not in decoded[0]:
            raise RuntimeError(f"wrong assembled trap diagnostic instruction: {mnemonic}")
        instructions.append({"mnemonic": mnemonic, "pc": f"0x{pc:x}", "expected_cause": cause,
                             "file_offset": f"0x{text_offset + pc - text_vma:x}", "word": f"0x{int.from_bytes(raw, 'little'):08x}",
                             "bytes_memory_order": raw.hex(" "), "decoded": decoded[0]})
    (out / "operations.json").write_text(json.dumps(instructions, indent=2) + "\n")
    (out / "operations.bin").write_bytes(b"".join(bytes.fromhex(row["bytes_memory_order"]) for row in instructions))
    (out / "op.bin").write_bytes(bytes.fromhex(instructions[0]["bytes_memory_order"]))
    dump_addr, dump_size = syms["__monitor_start"], syms["__monitor_end"] - syms["__monitor_start"]
    (out / "elf-layout.json").write_text(json.dumps({
        "entry": f"0x{entry:x}", "selected_hart": "H0 S0:N0:C0:T0", "executable_sections": [".text"],
        "text_vma": f"0x{text_vma:x}", "text_file_offset": f"0x{text_offset:x}", "text_size": text_size,
        "monitor_address": f"0x{dump_addr:x}", "monitor_size": dump_size,
        "symbols": {label: f"0x{address:x}" for label, address in syms.items()},
    }, indent=2) + "\n")
    sim = [env["simulator"], "-l", "-lm", "0", "-lt", "0", "-sp_dis", "-Werror=memory",
           "-reset_pc", hex(entry), "-single_thread", "-minions", "0x1", "-shires", "0x1",
           "-max_cycles", "10000", "-elf_load", f"{work}/kernel.elf", "-dump_at_pc_pc", hex(entry),
           "-dump_at_pc_addr", hex(dump_addr), "-dump_at_pc_size", hex(dump_size), "-dump_at_pc_file", f"{work}/prestart.bin",
           "-dump_addr", hex(dump_addr), "-dump_size", str(dump_size), "-dump_file", f"{work}/output.bin"]
    run = run_logged(log, command(env, ["timeout", "--signal=TERM", "--kill-after=5s", "90s", *sim]))
    trace = run.stdout or ""
    (out / "trace.log").write_text(trace)
    if container:
        checked([podman, "cp", f"{env['container']}:{stage}/.", str(out)])
        checked([podman, "exec", env["container"], "rm", "-rf", stage])
    if run.returncode or "Finishing emulation" not in trace or "Error, max cycles reached" in trace:
        raise RuntimeError(f"trap diagnostic did not complete normally; inspect {out}")
    events, regs = trace_data(trace)
    event_at(events, syms["park"], "wfi")
    pre, memory = (out / "prestart.bin").read_bytes(), (out / "output.bin").read_bytes()
    if len(pre) != dump_size or len(memory) != dump_size:
        raise RuntimeError("incomplete trap diagnostic memory dumps")
    relative = lambda label: syms[label] - dump_addr
    feature = struct.unpack_from("<Q", memory, relative("feature_state"))[0]
    if not feature & 1 or regs[(syms["feature_read"], "x5", "=")] != feature:
        raise RuntimeError("graphics feature was not actually disabled")
    trap_entries = [event for event in events if event["pc"] == syms["capture_mcause"]]
    trap_epcs = [event for event in events if event["pc"] == syms["capture_mepc"]]
    trap_tvals = [event for event in events if event["pc"] == syms["capture_mtval"]]
    if any(len(es) != len(OPERATIONS) for es in (trap_entries, trap_epcs, trap_tvals)):
        raise RuntimeError("unexpected, repeated or missing trap handler entry")
    trap_logs = re.findall(r"\[(H\d+ S\d+:N\d+:C\d+:T\d+)\].*Trapping to M-mode with cause 0x([0-9a-f]+) and tval 0x([0-9a-f]+)", trace)
    if len(trap_logs) != len(OPERATIONS):
        raise RuntimeError("unexpected number of actual trap events")
    rows = []
    for index, inst in enumerate(instructions):
        mnemonic, pc = inst["mnemonic"], int(inst["pc"], 16)
        label, offset = name(mnemonic), relative(f"record_{name(mnemonic)}")
        cause, epc, tval = struct.unpack_from("<3Q", memory, offset)
        hart, logged_cause, logged_tval = trap_logs[index]
        expected_word = int(inst["word"], 16)
        if (hart != "H0 S0:N0:C0:T0" or cause != inst["expected_cause"] or epc != pc or tval != expected_word or
                int(logged_cause, 16) != cause or int(logged_tval, 16) != tval):
            raise RuntimeError(f"wrong actual cause, fault PC or instruction word at {mnemonic}: {cause}/{epc:#x}/{tval:#x}")
        for event, register, expected in ((trap_entries[index], "x5", cause), (trap_epcs[index], "x5", epc),
                                          (trap_tvals[index], "x6", tval)):
            if event["hart"] != hart or event["registers"].get(register + ":=") != expected:
                raise RuntimeError(f"trap CSR read trace and memory snapshot disagree at {mnemonic}")
        before_pc, after_pc = syms[f"before_{label}"], syms[f"after_{label}"]
        event_at(events, before_pc, "fsq2")
        event_at(events, after_pc, "fsq2")
        before, after = regs[(before_pc, "f20", ":")], regs[(after_pc, "f20", ":")]
        scalar_before, scalar_after = struct.unpack_from("<2Q", memory, offset + 96)
        for suffix, actual in (("before", scalar_before), ("after", scalar_after)):
            snapshot_pc = syms[f"scalar_{suffix}_{label}"]
            event_at(events, snapshot_pc, "sd")
            if regs[(snapshot_pc, "x20", ":")] != actual:
                raise RuntimeError(f"scalar register trace and memory snapshot disagree at {mnemonic}")
        if (before != (SEED,) * 8 or after != before or struct.unpack_from("<8I", memory, offset + 32) != before or
                struct.unpack_from("<8I", memory, offset + 64) != after or
                scalar_before != SCALAR_SEED or scalar_after != scalar_before):
            raise RuntimeError(f"a trapping instruction changed its destination at {mnemonic}")
        if (pre[offset:offset + 128] != bytes([0xA5]) * 128 or
                memory[offset + 24:offset + 32] != bytes([0xA5]) * 8 or
                memory[offset + 112:offset + 128] != bytes([0xA5]) * 16):
            raise RuntimeError(f"missing record sentinel or overwritten guard at {mnemonic}")
        if (pc, "f20", "=") in regs or (pc, "x20", "=") in regs:
            raise RuntimeError(f"unexpected destination write at trapping instruction {mnemonic}")
        rows.append({**inst, "hart": hart, "actual_cause": cause, "actual_mepc": f"0x{epc:x}", "actual_mtval": f"0x{tval:x}",
                     "f20_before": report_lanes(before), "f20_after": report_lanes(after),
                     "x20_before": f"0x{scalar_before:x}", "x20_after": f"0x{scalar_after:x}", "pass": True})
        print(f"  {mnemonic:<10} PC={pc:#x} word={expected_word:#010x} actual cause={cause} destination unchanged PASS")
    for label in ("input_a", "input_b", "seed"):
        offset = relative(label)
        if memory[offset:offset + 32] != pre[offset:offset + 32]:
            raise RuntimeError(f"trap diagnostic changed input memory: {label}")
    count = struct.unpack_from("<Q", memory, relative("trap_count"))[0]
    complete = struct.unpack_from("<I", memory, relative("completion"))[0]
    if count != len(OPERATIONS) or complete != DONE:
        raise RuntimeError("trap diagnostic completion/count checks failed")
    (out / "registers.json").write_text(json.dumps({"operations": rows}, indent=2, allow_nan=False) + "\n")
    (out / "result.json").write_text(json.dumps({"case": case, "diagnostic": "expected traps only; no missing arithmetic implemented",
        "trap_count": count, "operation_count": len(OPERATIONS), "graphics_feature": feature,
        "completion_word": f"0x{complete:08x}", "operations": rows, "pass": True}, indent=2) + "\n")
    print(f"Trap diagnostic {case}: 8 cause-30 stubs and 1 disabled-graphics cause-2 trap, PASS; {out}")


def main() -> int:
    cases = sys.argv[1:] or ["primary", "exact"]
    if any(case not in ("primary", "exact") for case in cases):
        raise SystemExit("usage: python3 examples/trap_stubs.py [primary|exact ...]")
    env = runtime()
    for case in cases:
        execute(case, env)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print(f"trap_stubs.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
