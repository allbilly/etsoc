#!/usr/bin/env python3
"""Execute ET scalar local/global atomics, coherent stores and packb."""

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
from packed_memory import memory_events


OUT = ROOT / "out" / "scalar-memory"
DONE = 0x4B4F5445
SEED = 0x5AA55AA55AA55AA5
SIM_TIMEOUT = 90
SIM_CYCLES = 10_000
GUARD_SIZE = 128

ATOMIC_OPS = [
    ("amoaddg.w", "add", 4), ("amoaddl.w", "add", 4),
    ("amoandg.w", "and", 4), ("amoandl.w", "and", 4),
    ("amomaxg.w", "max_s", 4), ("amomaxl.w", "max_s", 4),
    ("amomaxug.w", "max_u", 4), ("amomaxul.w", "max_u", 4),
    ("amoming.w", "min_s", 4), ("amominl.w", "min_s", 4),
    ("amominug.w", "min_u", 4), ("amominul.w", "min_u", 4),
    ("amoorg.w", "or", 4), ("amoorl.w", "or", 4),
    ("amoswapg.w", "swap", 4), ("amoswapl.w", "swap", 4),
    ("amoxorg.w", "xor", 4), ("amoxorl.w", "xor", 4),
    ("amocmpswapg.w", "compare_swap", 4), ("amocmpswapl.w", "compare_swap", 4),
    ("amoaddg.d", "add", 8), ("amoaddl.d", "add", 8),
    ("amoandg.d", "and", 8), ("amoandl.d", "and", 8),
    ("amomaxg.d", "max_s", 8), ("amomaxl.d", "max_s", 8),
    ("amomaxug.d", "max_u", 8), ("amomaxul.d", "max_u", 8),
    ("amoming.d", "min_s", 8), ("amominl.d", "min_s", 8),
    ("amominug.d", "min_u", 8), ("amominul.d", "min_u", 8),
    ("amoorg.d", "or", 8), ("amoorl.d", "or", 8),
    ("amoswapg.d", "swap", 8), ("amoswapl.d", "swap", 8),
    ("amoxorg.d", "xor", 8), ("amoxorl.d", "xor", 8),
    ("amocmpswapg.d", "compare_swap", 8), ("amocmpswapl.d", "compare_swap", 8),
]
OTHER_OPS = [("sbg", "store", 1), ("sbl", "store", 1),
             ("shg", "store", 2), ("shl", "store", 2), ("packb", "pack", 0)]


def reference(operation: str, old: int, operand: int, width: int, comparison: int) -> int:
    mask = (1 << (width * 8)) - 1
    operand &= mask
    if operation == "add":
        return (old + operand) & mask
    if operation == "and":
        return old & operand
    if operation == "or":
        return old | operand
    if operation == "xor":
        return old ^ operand
    if operation == "swap":
        return operand
    if operation == "compare_swap":
        return operand if old == comparison & mask else old
    def key(value: int) -> int:
        return value - (mask + 1) if operation.endswith("s") and value >> (width * 8 - 1) else value
    return (max if operation.startswith("max") else min)((old, operand), key=key)


def operations(case: str) -> list[dict[str, object]]:
    if case not in ("primary", "exact"):
        raise ValueError(f"unknown case: {case}")
    result = []
    for mnemonic, operation, width in ATOMIC_OPS + OTHER_OPS:
        name = mnemonic.replace(".", "_")
        memory = bytearray([0xA5] * GUARD_SIZE)
        old = (0x80000005 if width == 4 else 0x8000000000000005) if case == "primary" else (
               0x7FFFFFF9 if width == 4 else 0x7FFFFFFFFFFFFFF9)
        operand = (0xFFFF12347FFFFFFB if width == 4 else 0x7FFFFFFFFFFFFFFB) if case == "primary" else (
                   0x1234FFFF80000003 if width == 4 else 0x8000000000000003)
        compare = old if case == "primary" else old ^ 1
        expected_return = SEED
        accesses = []
        if operation == "store":
            operand = 0xFEDCBA9876543210 if case == "primary" else 0x0123456789ABCDEF
            expected = bytearray(memory)
            expected[32:32 + width] = operand.to_bytes(8, "little")[:width]
            accesses = [(32, "write", operand & ((1 << (width * 8)) - 1))]
            asm = f"{mnemonic} t2, 0(t1)"
        elif operation == "pack":
            old = 0xFEDCBA9876543210 if case == "primary" else 0x0123456789ABCDEF
            operand = 0x1234567890ABCDEF if case == "primary" else 0xFEDCBA9876543210
            expected, expected_return = bytearray(memory), (old & 0xFF) | ((operand & 0xFF) << 8)
            asm = "packb s4, t1, t2"
        else:
            memory[32:32 + width] = old.to_bytes(width, "little")
            expected = bytearray(memory)
            new = reference(operation, old, operand, width, compare)
            expected[32:32 + width] = new.to_bytes(width, "little")
            expected_return = old | 0xFFFFFFFF00000000 if width == 4 and old & 0x80000000 else old
            accesses = [(32, "read", old)]
            if operation != "compare_swap" or old == compare:
                accesses.append((32, "write", new))
            asm = f"{mnemonic} s4, t2, 0(t1)"
        result.append({"name": name, "mnemonic": mnemonic, "operation": operation, "width": width,
                       "old": old, "operand": operand, "comparison": compare, "asm": asm,
                       "initial": bytes(memory), "expected_memory": bytes(expected),
                       "expected_return": expected_return, "expected_accesses": accesses})
    return result


def kernel(ops: list[dict[str, object]]) -> str:
    lines = ["# SPDX-License-Identifier: Apache-2.0",
             "# Startup provenance: Copyright (c) 2025 Ainekko, Co.; ET Platform boot.S.",
             ".option push", ".option norelax", ".option norvc", '.section .text.entry,"ax",@progbits',
             ".globl _start", "_start:", "    csrwi satp, 0", "    csrwi mip, 0",
             "    la sp, __stack_top", "    la t0, trap_handler", "    csrw mtvec, t0"]
    for op in ops:
        name = op["name"]
        if op["operation"] == "pack":
            lines.append(f"    li t1, 0x{op['old']:x}")
        else:
            lines.extend((f"    la t1, target_{name}", "    addi t1, t1, 32"))
        lines.extend((f"    li t2, 0x{op['operand']:x}", f"    li x31, 0x{op['comparison']:x}",
                      f"    li s4, 0x{SEED:x}", f".globl before_{name}", f"before_{name}:", "    addi t0, s4, 0",
                      f".globl op_{name}", f"op_{name}:", f"    {op['asm']}",
                      f"    la t3, snapshot_{name}", f".globl capture_{name}", f"capture_{name}:", "    sd s4, 0(t3)"))
    lines.extend(("    li t0, 0x4b4f5445", "    la t1, completion", "    sw t0, 0(t1)",
                  ".globl park", "park:", "    wfi", "    j park", ".balign 4096",
                  "trap_handler:", "    csrr t0, mcause", "    la t1, trap_cause", "    sd t0, 0(t1)",
                  "    li t0, 1", "    la t1, trap_marker", "    sw t0, 0(t1)", "    j park", ".option pop",
                  '.section .data,"aw",@progbits', ".balign 32", ".globl __monitor_start", "__monitor_start:"))
    for op in ops:
        name = op["name"]
        lines.extend((".balign 32", f".globl target_{name}", f"target_{name}:",
                      "    .byte " + ", ".join(str(x) for x in op["initial"]),
                      f".globl snapshot_{name}", f"snapshot_{name}:", "    .fill 8,1,0xa5"))
    lines.extend((".globl completion", "completion:", "    .word 0", ".globl trap_marker", "trap_marker:", "    .word 0",
                  ".globl trap_cause", "trap_cause:", "    .dword 0", ".globl __monitor_end", "__monitor_end:"))
    return "\n".join(lines) + "\n"


def execute(case: str, env: dict[str, str]) -> None:
    out = OUT if case == "primary" else OUT / case
    out.mkdir(parents=True, exist_ok=True)
    log = out / "commands.log"
    log.write_text("")
    ops = operations(case)
    (out / "kernel.S").write_text(kernel(ops))
    (out / "link.ld").write_text(LINKER)
    for name in ("result.json", "registers.json", "output.bin", "prestart.bin", "trace.log"):
        (out / name).unlink(missing_ok=True)
    stage = f"/tmp/etsoc1-scalar-memory-{uuid.uuid4().hex[:10]}"
    container, podman = env["kind"] == "podman", shutil.which("podman") or "podman"
    def checked(argv):
        result = run_logged(log, argv)
        require(result, "scalar-memory command")
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
    require(built, "assemble scalar-memory ELF")
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
        if len(raw) != 4 or len(decoded) != 1 or op["mnemonic"] not in decoded[0]:
            raise RuntimeError(f"wrong assembled scalar instruction: {op['name']}: {decoded}")
        instructions.append({"name": op["name"], "mnemonic": op["mnemonic"], "pc": f"0x{pc:x}",
                             "file_offset": f"0x{text_offset + pc - text_vma:x}", "word": f"0x{int.from_bytes(raw, 'little'):08x}",
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
           "-max_cycles", str(SIM_CYCLES), "-elf_load", f"{work}/kernel.elf",
           "-dump_at_pc_pc", hex(entry), "-dump_at_pc_addr", hex(dump_addr), "-dump_at_pc_size", hex(dump_size),
           "-dump_at_pc_file", f"{work}/prestart.bin", "-dump_addr", hex(dump_addr),
           "-dump_size", str(dump_size), "-dump_file", f"{work}/output.bin"]
    run = run_logged(log, command(env, ["timeout", "--signal=TERM", "--kill-after=5s", f"{SIM_TIMEOUT}s", *sim]))
    (out / "trace.log").write_text(run.stdout or "")
    if container:
        checked([podman, "cp", f"{env['container']}:{stage}/.", str(out)])
        checked([podman, "exec", env["container"], "rm", "-rf", stage])
    require(run, "execute scalar-memory ELF")
    trace = run.stdout or ""
    if "Finishing emulation" not in trace or "Error, max cycles reached" in trace or re.search(r"\b(?:trap|exception)\b", trace, re.I):
        raise RuntimeError("scalar-memory execution did not complete normally")
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
        if event["word"] != int(inst["word"], 16):
            raise RuntimeError(f"executed word differs from ELF at {name}")
        before_pc, capture_pc = syms[f"before_{name}"], syms[f"capture_{name}"]
        event_at(events, before_pc, "addi")
        event_at(events, capture_pc, "sd")
        before, after = regs[(before_pc, "x20", ":")], regs[(capture_pc, "x20", ":")]
        if before != SEED:
            raise RuntimeError(f"missing destination seed at {name}")
        if op["operation"] != "store" and regs.get((pc, "x20", "=")) != after:
            raise RuntimeError(f"destination write and snapshot disagree at {name}")
        target_off, snapshot_off = relative(f"target_{name}"), relative(f"snapshot_{name}")
        target = memory[target_off:target_off + GUARD_SIZE]
        if pre[target_off:target_off + GUARD_SIZE] != op["initial"] or pre[snapshot_off:snapshot_off + 8] != bytes([0xA5]) * 8:
            raise RuntimeError(f"incorrect initial memory/guards at {name}")
        if after != struct.unpack_from("<Q", memory, snapshot_off)[0]:
            raise RuntimeError(f"snapshot trace and memory disagree at {name}")
        target_address = syms[f"target_{name}"]
        source_address = op["old"] if op["operation"] == "pack" else target_address + 32
        if regs[(pc, "x6", ":")] != source_address or regs[(pc, "x7", ":")] != op["operand"]:
            raise RuntimeError(f"incorrect traced scalar inputs at {name}")
        if op["operation"] == "compare_swap" and regs.get((pc, "x31", ":")) != op["comparison"]:
            raise RuntimeError(f"incorrect compare-swap X31 operand at {name}")
        observed = accesses.get(pc, [])
        expected_accesses = [{"bits": int(op["width"]) * 8, "address": f"0x{target_address + offset:x}",
                              "direction": direction, "value": f"0x{value:x}"}
                             for offset, direction, value in op["expected_accesses"]]
        passed = after == op["expected_return"] and target == op["expected_memory"] and observed == expected_accesses
        results.append({"name": name, "mnemonic": op["mnemonic"], "pass": passed,
                        "returned_actual": f"0x{after:016x}", "returned_expected": f"0x{op['expected_return']:016x}",
                        "target_actual_bytes": target.hex(" "), "target_expected_bytes": op["expected_memory"].hex(" "),
                        "accesses": observed, "accesses_expected": expected_accesses})
        register_rows.append({**inst, "hart": event["hart"], "cycle": event["cycle"],
                              "x20_before": f"0x{before:016x}", "x20_after": f"0x{after:016x}",
                              "x6_before": f"0x{regs[(pc, 'x6', ':')]:016x}", "x7_before": f"0x{regs[(pc, 'x7', ':')]:016x}",
                              "x31_before": f"0x{regs[(pc, 'x31', ':')]:016x}" if (pc, "x31", ":") in regs else None})
        print(f"  {op['mnemonic']:<15} PC={inst['pc']} word={inst['word']} {'PASS' if passed else 'FAIL'}")
    complete = struct.unpack_from("<I", memory, relative("completion"))[0]
    trap_marker = struct.unpack_from("<I", memory, relative("trap_marker"))[0]
    trap_cause = struct.unpack_from("<Q", memory, relative("trap_cause"))[0]
    passed = all(row["pass"] for row in results) and complete == DONE and not trap_marker and not trap_cause
    (out / "registers.json").write_text(json.dumps({"operations": register_rows}, indent=2) + "\n")
    (out / "result.json").write_text(json.dumps({"case": case, "operation_count": len(ops), "operations": results,
        "completion_word": f"0x{complete:08x}", "trap_marker": trap_marker, "trap_cause": trap_cause, "pass": passed}, indent=2) + "\n")
    if not passed:
        raise RuntimeError(f"scalar-memory reference/completion checks failed; inspect {out}/result.json")
    print(f"Scalar memory {case}: {len(ops)} sites, completion=0x{complete:08x}, traps=0/0, PASS; {out}")


def main() -> int:
    selected = sys.argv[1:] or ["primary", "exact"]
    if any(case not in ("primary", "exact") for case in selected):
        raise SystemExit("usage: python3 examples/scalar_memory.py [primary|exact ...]")
    env = runtime()
    for case in selected:
        print(f"\nScalar memory {case}: H0 S0:N0:C0:T0")
        execute(case, env)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print(f"scalar_memory.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
