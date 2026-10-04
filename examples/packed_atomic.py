#!/usr/bin/env python3
"""Execute all 22 ET packed atomic handlers and check old values/new memory."""

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
from add import event_at, require, run_logged
from packed_memory import memory_events


OUT = ROOT / "out" / "packed-atomic"
DONE = 0x4B4F5445
SIM_TIMEOUT = 90
SIM_CYCLES = 10_000
TARGET_SIZE = 128
SENTINEL = 0xA5A5A5A5

# These are actual, independently assembled ET instructions, not an emulator
# implemented by Python. Python computes only the reference for validation.
ATOMIC_OPS = [
    ("famoaddg.pi", "add"), ("famoaddl.pi", "add"),
    ("famoandg.pi", "and"), ("famoandl.pi", "and"),
    ("famomaxg.pi", "max_s"), ("famomaxl.pi", "max_s"),
    ("famomaxug.pi", "max_u"), ("famomaxul.pi", "max_u"),
    ("famoming.pi", "min_s"), ("famominl.pi", "min_s"),
    ("famominug.pi", "min_u"), ("famominul.pi", "min_u"),
    ("famoorg.pi", "or"), ("famoorl.pi", "or"),
    ("famoswapg.pi", "swap"), ("famoswapl.pi", "swap"),
    ("famoxorg.pi", "xor"), ("famoxorl.pi", "xor"),
    ("famomaxg.ps", "max_f"), ("famomaxl.ps", "max_f"),
    ("famoming.ps", "min_f"), ("famominl.ps", "min_f"),
]


def raw(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0]


def signed(value: int) -> int:
    return value if value < 0x80000000 else value - 0x100000000


def reference(op: str, old: int, operand: int) -> int:
    if op == "add":
        return (old + operand) & 0xFFFFFFFF
    if op == "and":
        return old & operand
    if op == "or":
        return old | operand
    if op == "xor":
        return old ^ operand
    if op == "swap":
        return operand
    if op in ("max_s", "min_s", "max_u", "min_u"):
        key = signed if op.endswith("s") else lambda x: x
        return (max if op.startswith("max") else min)((old, operand), key=key)
    left, right = (struct.unpack("<f", struct.pack("<I", x))[0] for x in (old, operand))
    if left == 0.0 and right == 0.0:
        # The upstream FP atomic min/max explicitly order negative/positive zero.
        return (old & operand) if op == "max_f" else (old | operand)
    return (old if left >= right else operand) if op == "max_f" else (old if left <= right else operand)


def cases(case: str) -> list[dict[str, object]]:
    initial_pi = (0xFFFFFFF0, 32, 0x80000000, 0xFFFFFFFF, 7, 0x7FFFFFFF, 0xAAAA5555, 0x12345678)
    operand_pi = (5, 0xFFFFFFFE, 15, 1, 0x80000001, 5, 0xFFFF0000, 0x0000FFFF)
    initial_fp = tuple(raw(x) for x in (-4.0, 2.0, 0.0, -0.0, 8.0, 16.0, -8.0, 1.5))
    operand_fp = tuple(raw(x) for x in (-8.0, 4.0, -0.0, 0.0, 4.0, 32.0, -4.0, 0.5))
    offsets = (-32, -24, -16, -8, 0, 8, 16, 24)
    mask = 0xFF
    if case == "exact":
        initial_pi = tuple(x ^ 0x00FF00FF for x in initial_pi[::-1])
        operand_pi = tuple(x ^ 0x0F0F0F0F for x in operand_pi[::-1])
        initial_fp, operand_fp = operand_fp[::-1], initial_fp[::-1]
        offsets, mask = offsets[::-1], 0x55
    elif case == "alias":
        offsets = (0,) * 8
    elif case != "primary":
        raise ValueError(f"unknown case: {case}")
    operations = []
    for mnemonic, operation in ATOMIC_OPS:
        initial, operands = (initial_fp, operand_fp) if mnemonic.endswith(".ps") else (initial_pi, operand_pi)
        target = bytearray([0xA5] * TARGET_SIZE)
        for lane, old in enumerate(initial):
            struct.pack_into("<I", target, lane * 8, old)
        expected = bytearray(target)
        expected_register = list(operands)
        accesses = []
        for lane, offset in enumerate(offsets):
            if not mask >> lane & 1:
                continue
            index = 32 + offset
            old = struct.unpack_from("<I", expected, index)[0]
            new = reference(operation, old, operands[lane])
            struct.pack_into("<I", expected, index, new)
            expected_register[lane] = old
            accesses.extend(((index, "read", old), (index, "write", new)))
        operations.append({"name": mnemonic.replace(".", "_"), "mnemonic": mnemonic,
                           "operation": operation, "mask": mask, "offsets": offsets,
                           "operands": operands, "initial_memory": bytes(target),
                           "expected_memory": bytes(expected), "expected_register": tuple(expected_register),
                           "expected_accesses": accesses})
    return operations


def words(values) -> str:
    return "    .word " + ", ".join(f"0x{x & 0xFFFFFFFF:08x}" for x in values)


def kernel(ops: list[dict[str, object]]) -> str:
    lines = ["# SPDX-License-Identifier: Apache-2.0",
             "# Startup provenance: Copyright (c) 2025 Ainekko, Co.; ET Platform boot.S.",
             ".option push", ".option norelax", ".option norvc", '.section .text.entry,"ax",@progbits',
             ".globl _start", "_start:", "    csrwi satp, 0", "    csrr t0, mstatus", "    li t1, 0x6000",
             "    or t0, t0, t1", "    csrw mstatus, t0", "    csrwi fcsr, 0", "    csrwi mip, 0",
             "    csrwi tensor_mask, 0", "    csrwi 0x840, 0 # gsc_progress",
             "    la sp, __stack_top", "    la t0, trap_handler", "    csrw mtvec, t0",
             "    la t3, lane_offsets", "    flq2 f10, 0(t3)"]
    for op in ops:
        name = op["name"]
        lines.extend((f"    la t3, operands_{name}", f".globl seed_{name}", f"seed_{name}:", "    flq2 f20, 0(t3)",
                      f"    li t0, {op['mask']}", f".globl mask_{name}", f"mask_{name}:", "    mova.m.x t0",
                      f"    la t1, target_{name}", "    addi t1, t1, 32", f".globl op_{name}", f"op_{name}:",
                      f"    {op['mnemonic']} f20, f10(t1)",
                      f"    la t3, snapshot_{name}", f".globl capture_{name}", f"capture_{name}:",
                      "    fsq2 f20, 0(t3) # return old values, preserving inactive operands"))
    lines.extend(("    li t0, 0x4b4f5445", "    la t1, completion", "    sw t0, 0(t1)",
                  ".globl park", "park:", "    wfi", "    j park", ".balign 4096",
                  "trap_handler:", "    csrr t0, mcause", "    la t1, trap_cause", "    sd t0, 0(t1)",
                  "    li t0, 1", "    la t1, trap_marker", "    sw t0, 0(t1)", "    j park", ".option pop",
                  '.section .data,"aw",@progbits', ".balign 32", "lane_offsets:", words(ops[0]["offsets"])))
    for op in ops:
        lines.extend((f"operands_{op['name']}:", words(op["operands"])))
    lines.extend((".globl __monitor_start", "__monitor_start:"))
    for op in ops:
        name = op["name"]
        lines.extend((".balign 32", f".globl target_{name}", f"target_{name}:",
                      "    .byte " + ", ".join(str(x) for x in op["initial_memory"]),
                      f".globl snapshot_{name}", f"snapshot_{name}:", "    .fill 32,1,0xa5"))
    lines.extend((".globl completion", "completion:", "    .word 0", ".globl trap_marker", "trap_marker:",
                  "    .word 0", ".globl trap_cause", "trap_cause:", "    .dword 0",
                  ".globl __monitor_end", "__monitor_end:"))
    return "\n".join(lines) + "\n"


def execute(case: str, env: dict[str, str]) -> None:
    out = OUT if case == "primary" else OUT / case
    out.mkdir(parents=True, exist_ok=True)
    log = out / "commands.log"
    log.write_text("")
    ops = cases(case)
    (out / "kernel.S").write_text(kernel(ops))
    (out / "link.ld").write_text(LINKER)
    for filename in ("result.json", "registers.json", "output.bin", "prestart.bin", "trace.log"):
        (out / filename).unlink(missing_ok=True)
    stage = f"/tmp/etsoc1-packed-atomic-{uuid.uuid4().hex[:10]}"
    container, podman = env["kind"] == "podman", shutil.which("podman") or "podman"
    def checked(argv):
        result = run_logged(log, argv)
        require(result, "packed-atomic command")
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
    require(built, "assemble packed-atomic ELF")
    syms = symbols((out / "symbols.txt").read_text())
    inspection = (out / "elf-inspection.txt").read_text()
    entry_match = re.search(r"Entry point address:\s+0x([0-9a-fA-F]+)", inspection)
    text_match = re.search(r"^\s*\[\s*\d+\]\s+\.text\s+\S+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)", inspection, re.MULTILINE)
    if not entry_match or not text_match:
        raise RuntimeError("missing ELF entry or executable section mapping")
    entry = int(entry_match.group(1), 16)
    text_vma, text_offset, text_size = (int(text_match.group(i), 16) for i in (1, 2, 3))
    text, disassembly = (out / "text.bin").read_bytes(), (out / "kernel.asm").read_text()
    instructions = []
    for op in ops:
        pc = syms[f"op_{op['name']}"]
        raw = text[pc - text_vma:pc - text_vma + 4]
        decoded = [line.strip() for line in disassembly.splitlines() if re.search(rf"\b{pc:x}:\s", line)]
        if len(raw) != 4 or len(decoded) != 1 or op["mnemonic"] not in decoded[0]:
            raise RuntimeError(f"wrong assembled atomic at {op['name']}: {decoded}")
        instructions.append({"name": op["name"], "mnemonic": op["mnemonic"], "pc": f"0x{pc:x}",
                             "file_offset": f"0x{text_offset + pc - text_vma:x}",
                             "word": f"0x{int.from_bytes(raw, 'little'):08x}", "bytes_memory_order": raw.hex(" "),
                             "decoded": decoded[0]})
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
           "-max_cycles", str(SIM_CYCLES), "-elf_load", f"{work}/kernel.elf",
           "-dump_at_pc_pc", hex(entry), "-dump_at_pc_addr", hex(dump_addr), "-dump_at_pc_size", hex(dump_size),
           "-dump_at_pc_file", f"{work}/prestart.bin", "-dump_addr", hex(dump_addr),
           "-dump_size", str(dump_size), "-dump_file", f"{work}/output.bin"]
    run = run_logged(log, command(env, ["timeout", "--signal=TERM", "--kill-after=5s", f"{SIM_TIMEOUT}s", *sim]))
    (out / "trace.log").write_text(run.stdout or "")
    if container:
        checked([podman, "cp", f"{env['container']}:{stage}/.", str(out)])
        checked([podman, "exec", env["container"], "rm", "-rf", stage])
    require(run, "execute packed-atomic ELF")
    trace = run.stdout or ""
    if "Finishing emulation" not in trace or "Error, max cycles reached" in trace or re.search(r"\b(?:trap|exception)\b", trace, re.I):
        raise RuntimeError("packed-atomic execution did not complete normally")
    events, regs = trace_data(trace)
    event_at(events, syms["park"], "wfi")
    accesses = memory_events(trace)
    pre, memory = (out / "prestart.bin").read_bytes(), (out / "output.bin").read_bytes()
    if len(pre) != dump_size or len(memory) != dump_size:
        raise RuntimeError("incomplete simulator memory dumps")
    relative = lambda name: syms[name] - dump_addr
    results, register_rows = [], []
    for op, inst in zip(ops, instructions):
        name, pc = str(op["name"]), int(inst["pc"], 16)
        event = event_at(events, pc, str(op["mnemonic"]))
        if event["word"] != int(inst["word"], 16) or event["state"].get("m0::") != op["mask"]:
            raise RuntimeError(f"wrong atomic word or mask at {name}")
        seed_pc, capture_pc = syms[f"seed_{name}"], syms[f"capture_{name}"]
        event_at(events, seed_pc, "flq2")
        event_at(events, capture_pc, "fsq2")
        before, returned = regs[(seed_pc, "f20", "=")], regs[(pc, "f20", "=")]
        snapshot = regs[(capture_pc, "f20", ":")]
        target_off, snapshot_off = relative(f"target_{name}"), relative(f"snapshot_{name}")
        target = memory[target_off:target_off + TARGET_SIZE]
        if pre[target_off:target_off + TARGET_SIZE] != op["initial_memory"] or pre[snapshot_off:snapshot_off + 32] != bytes([0xA5]) * 32:
            raise RuntimeError(f"initial atomic data/guards are wrong for {name}")
        if before != op["operands"] or regs[(pc, "f20", ":")] != before:
            raise RuntimeError(f"missing/wrong atomic operands at {name}")
        if regs[(pc, "f10", ":")] != tuple(x & 0xFFFFFFFF for x in op["offsets"]):
            raise RuntimeError(f"wrong atomic lane offsets at {name}")
        if snapshot != returned or returned != struct.unpack_from("<8I", memory, snapshot_off):
            raise RuntimeError(f"atomic return trace and device snapshot disagree at {name}")
        target_address = syms[f"target_{name}"]
        observed = accesses.get(pc, [])
        expected_accesses = [{"bits": 32, "address": f"0x{target_address + offset:x}", "direction": direction,
                              "value": f"0x{value:x}"} for offset, direction, value in op["expected_accesses"]]
        passed = returned == op["expected_register"] and target == op["expected_memory"] and observed == expected_accesses
        results.append({"name": name, "mnemonic": op["mnemonic"], "pass": passed,
                        "returned_actual": [f"0x{x:08x}" for x in returned],
                        "returned_expected": [f"0x{x:08x}" for x in op["expected_register"]],
                        "target_actual_bytes": target.hex(" "), "target_expected_bytes": op["expected_memory"].hex(" "),
                        "accesses": observed, "accesses_expected": expected_accesses})
        register_rows.append({**inst, "hart": event["hart"], "cycle": event["cycle"], "mask": f"0x{op['mask']:02x}",
                              "f20_before": report_lanes(before), "f20_after": report_lanes(returned),
                              "f10_offsets_raw_u32": list(regs[(pc, "f10", ":")]),
                              "source": "SysEmu atomic register read/write and full-lane fsq2 snapshots"})
        print(f"  {op['mnemonic']:<13} PC={inst['pc']} word={inst['word']} M0=0x{op['mask']:02x} {'PASS' if passed else 'FAIL'}")
    complete = struct.unpack_from("<I", memory, relative("completion"))[0]
    trap_marker = struct.unpack_from("<I", memory, relative("trap_marker"))[0]
    trap_cause = struct.unpack_from("<Q", memory, relative("trap_cause"))[0]
    passed = all(row["pass"] for row in results) and complete == DONE and not trap_marker and not trap_cause
    (out / "registers.json").write_text(json.dumps({"operations": register_rows}, indent=2, allow_nan=False) + "\n")
    (out / "result.json").write_text(json.dumps({"case": case, "operation_count": len(ops), "operations": results,
        "completion_word": f"0x{complete:08x}", "trap_marker": trap_marker, "trap_cause": trap_cause, "pass": passed}, indent=2) + "\n")
    if not passed:
        raise RuntimeError(f"packed-atomic reference/completion checks failed; inspect {out}/result.json")
    print(f"Packed atomic {case}: {len(ops)} sites, completion=0x{complete:08x}, traps=0/0, PASS; {out}")


def main() -> int:
    selected = sys.argv[1:] or ["primary", "exact", "alias"]
    if any(case not in ("primary", "exact", "alias") for case in selected):
        raise SystemExit("usage: python3 examples/packed_atomic.py [primary|exact|alias ...]")
    env = runtime()
    for case in selected:
        print(f"\nPacked atomic {case}: H0 S0:N0:C0:T0")
        execute(case, env)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print(f"packed_atomic.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
