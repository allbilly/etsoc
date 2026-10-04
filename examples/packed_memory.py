#!/usr/bin/env python3
"""Execute ET-SOC1 packed loads, stores, broadcasts, gathers and scatters."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import struct
import subprocess
import sys
import uuid
from pathlib import Path

from gemm import LINKER, ROOT, command, report_lanes, runtime, symbols, trace_data
from add import event_at, require, run_logged


OUT = ROOT / "out" / "packed-memory"
SENTINEL = 0xA5A5A5A5
DONE = 0x4B4F5445
SIM_CYCLES = 10_000
SIM_TIMEOUT = 90
MASK_ALL = 0xFF
TARGET_SIZE = 128

# Every mnemonic is visible here. The syntax comes from the pinned ET binutils
# opcode table; behavior comes from packed_loadstore.cpp and
# coherent_packed_loadstore.cpp, including the A0 full-mask coherent stores.
MEMORY_OPS = [
    ("fbc.ps", "broadcast", 4),
    ("flq2", "load", 4), ("flw.ps", "load", 4),
    ("flwg.ps", "load", 4), ("flwl.ps", "load", 4),
    ("fgb.ps", "gather", 1), ("fgh.ps", "gather", 2), ("fgw.ps", "gather", 4),
    ("fgbg.ps", "gather", 1), ("fgbl.ps", "gather", 1),
    ("fghg.ps", "gather", 2), ("fghl.ps", "gather", 2),
    ("fgwg.ps", "gather", 4), ("fgwl.ps", "gather", 4),
    ("fg32b.ps", "gather32", 1), ("fg32h.ps", "gather32", 2), ("fg32w.ps", "gather32", 4),
    ("fsq2", "store", 4), ("fsw.ps", "store", 4),
    ("fswg.ps", "store", 4), ("fswl.ps", "store", 4),
    ("fscb.ps", "scatter", 1), ("fsch.ps", "scatter", 2), ("fscw.ps", "scatter", 4),
    ("fscbg.ps", "scatter", 1), ("fscbl.ps", "scatter", 1),
    ("fschg.ps", "scatter", 2), ("fschl.ps", "scatter", 2),
    ("fscwg.ps", "scatter", 4), ("fscwl.ps", "scatter", 4),
    ("fsc32b.ps", "scatter32", 1), ("fsc32h.ps", "scatter32", 2), ("fsc32w.ps", "scatter32", 4),
]


def dataset(case: str) -> tuple[bytes, tuple[int, ...], tuple[int, ...]]:
    if case == "primary":
        source = bytes((129 + 37 * i) % 256 for i in range(TARGET_SIZE))
        values = (0x01020304, 0x81828384, 0xFFFFFFFF, 0x80000001,
                  0x11223344, 0xA0B0C0D0, 0x55AA55AA, 0xFEDCBA98)
        offsets = (-16, -8, 0, 4, 12, 24, 40, 56)
    elif case == "exact":
        source = bytes((17 + 53 * i) % 256 for i in range(TARGET_SIZE))
        values = (0xF0010203, 0x80010002, 0x76543210, 0xFFFFFFFF,
                  0x01234567, 0xAA55AA55, 0x80818283, 0x00445566)
        offsets = (56, 40, 24, 12, 4, 0, -8, -16)
    else:
        raise ValueError(f"unknown case: {case}")
    return source, values, offsets


def operation_cases(case: str) -> list[dict[str, object]]:
    source, values, offsets = dataset(case)
    ops = []
    for mnemonic, kind, width in MEMORY_OPS:
        name = mnemonic.replace(".", "_")
        mask = MASK_ALL if case == "primary" or mnemonic in ("fswg.ps", "fswl.ps") else 0x55
        effective_mask = MASK_ALL if mnemonic in ("flq2", "fsq2") else mask
        base = 0
        packed_indices = None
        if kind.endswith("32"):
            base = 64 + 12  # nonzero low address bits also exercise 32-byte wrapping
            indices = {1: (31, 0, 27, 4, 16, 8, 21, 12),
                       2: (15, 0, 11, 3, 8, 4, 13, 6),
                       4: (7, 1, 5, 3, 0, 6, 2, 4)}[width]
            if case == "exact":
                indices = indices[::-1]
            field_bits = {1: 5, 2: 4, 4: 3}[width]
            packed_indices = sum(index << (field_bits * lane) for lane, index in enumerate(indices))
            addresses = tuple((base & ~31) + ((base + index * width) & (32 - width)) for index in indices)
            asm = f"{mnemonic} f20, t2(t1)"
        elif kind in ("gather", "scatter"):
            base = 32
            addresses = tuple(base + index for index in offsets)
            asm = f"{mnemonic} f20, f10(t1)"
        else:
            addresses = (0,) * 8 if kind == "broadcast" else tuple(4 * lane for lane in range(8))
            asm = f"{mnemonic} f20, 0(t1)"
        store = kind.startswith("s")
        expected_memory = bytearray([0xA5] * TARGET_SIZE)
        expected_register = list(values if store else (SENTINEL,) * 8)
        for lane, address in enumerate(addresses):
            if not effective_mask >> lane & 1:
                continue
            if store:
                expected_memory[address:address + width] = values[lane].to_bytes(4, "little")[:width]
            else:
                signed = kind.startswith("gather") and width < 4
                expected_register[lane] = int.from_bytes(source[address:address + width], "little", signed=signed) & 0xFFFFFFFF
        ops.append({"name": name, "mnemonic": mnemonic, "kind": kind, "width": width,
                    "asm": asm, "mask": mask, "effective_mask": effective_mask,
                    "base_offset": base, "addresses": addresses, "indices": packed_indices,
                    "store": store, "expected_register": tuple(expected_register),
                    "expected_memory": bytes(expected_memory)})
    return ops


def words(values: tuple[int, ...]) -> str:
    return "    .word " + ", ".join(f"0x{x & 0xFFFFFFFF:08x}" for x in values)


def kernel(case: str, ops: list[dict[str, object]]) -> str:
    source, values, offsets = dataset(case)
    lines = [
        "# SPDX-License-Identifier: Apache-2.0",
        "# Startup provenance: Copyright (c) 2025 Ainekko, Co.; ET Platform boot.S.",
        ".option push", ".option norelax", ".option norvc",
        '.section .text.entry,"ax",@progbits', ".globl _start", "_start:",
        "    csrwi satp, 0", "    csrr t0, mstatus", "    li t1, 0x6000",
        "    or t0, t0, t1", "    csrw mstatus, t0", "    csrwi fcsr, 0",
        "    csrwi mip, 0", "    csrwi tensor_mask, 0", "    csrwi 0x840, 0 # gsc_progress",
        "    la sp, __stack_top", "    la t0, trap_handler", "    csrw mtvec, t0",
        "    li t0, 255", "    mova.m.x t0", "    la t3, lane_offsets", "    flq2 f10, 0(t3)",
    ]
    for op in ops:
        name = op["name"]
        lines.extend((f"    la t3, {'store_values' if op['store'] else 'register_seed'}",
                      f".globl seed_{name}", f"seed_{name}:", "    flq2 f20, 0(t3)",
                      f"    li t0, {op['mask']}", f".globl mask_{name}", f"mask_{name}:", "    mova.m.x t0",
                      f"    la t1, {'target_' + str(name) if op['store'] else 'source_data'}"))
        if op["base_offset"]:
            lines.append(f"    addi t1, t1, {op['base_offset']}")
        if op["indices"] is not None:
            lines.append(f"    li t2, 0x{op['indices']:x}")
        lines.extend((f".globl op_{name}", f"op_{name}:", f"    {op['asm']}",
                      f"    la t3, snapshot_{name}", f".globl capture_{name}", f"capture_{name}:",
                      "    fsq2 f20, 0(t3) # capture all lanes irrespective of M0"))
    lines.extend(("    li t0, 0x4b4f5445", "    la t1, completion", "    sw t0, 0(t1)",
                  ".globl park", "park:", "    wfi", "    j park", ".balign 4096",
                  "trap_handler:", "    csrr t0, mcause", "    la t1, trap_cause", "    sd t0, 0(t1)",
                  "    li t0, 1", "    la t1, trap_marker", "    sw t0, 0(t1)", "    j park",
                  ".option pop", '.section .data,"aw",@progbits', ".balign 32",
                  "register_seed:", words((SENTINEL,) * 8), "store_values:", words(values),
                  "lane_offsets:", words(offsets), ".globl __monitor_start", "__monitor_start:",
                  ".globl source_data", "source_data:",
                  "    .byte " + ", ".join(str(x) for x in source)))
    for op in ops:
        name = op["name"]
        lines.extend((".balign 32", f".globl target_{name}", f"target_{name}:", "    .fill 128,1,0xa5",
                      f".globl snapshot_{name}", f"snapshot_{name}:", "    .fill 32,1,0xa5"))
    lines.extend((".globl completion", "completion:", "    .word 0",
                  ".globl trap_marker", "trap_marker:", "    .word 0",
                  ".globl trap_cause", "trap_cause:", "    .dword 0",
                  ".globl __monitor_end", "__monitor_end:"))
    return "\n".join(lines) + "\n"


def memory_events(trace: str) -> dict[int, list[dict[str, object]]]:
    """Retain the simulator's actual access addresses, widths and data."""
    result: dict[int, list[dict[str, object]]] = {}
    pc = None
    for line in trace.splitlines():
        instruction = re.search(r"I\(M\): 0x([0-9a-fA-F]+)", line)
        if instruction:
            pc = int(instruction.group(1), 16)
            result.setdefault(pc, [])
        access = re.search(r"MEM(8|16|32|64)\[0x([0-9a-fA-F]+)\] ([=:]) 0x([0-9a-fA-F]+)", line)
        if access and pc is not None:
            result[pc].append({"bits": int(access.group(1)), "address": f"0x{int(access.group(2), 16):x}",
                               "direction": "write" if access.group(3) == "=" else "read",
                               "value": f"0x{int(access.group(4), 16):x}"})
    return result


def execute(case: str, env: dict[str, str]) -> None:
    out = OUT if case == "primary" else OUT / case
    out.mkdir(parents=True, exist_ok=True)
    log = out / "commands.log"
    log.write_text("")
    ops = operation_cases(case)
    (out / "kernel.S").write_text(kernel(case, ops))
    (out / "link.ld").write_text(LINKER)
    # Do not leave an old passing summary beside a failed current run.
    for filename in ("result.json", "registers.json", "output.bin", "prestart.bin", "trace.log"):
        (out / filename).unlink(missing_ok=True)
    stage = f"/tmp/etsoc1-packed-memory-{uuid.uuid4().hex[:10]}"
    container = env["kind"] == "podman"
    podman = shutil.which("podman") or "podman"
    def checked(argv: list[str]) -> subprocess.CompletedProcess[str]:
        result = run_logged(log, argv)
        require(result, "packed-memory command")
        return result
    if container:
        checked([podman, "exec", env["container"], "mkdir", "-p", stage])
        for name in ("kernel.S", "link.ld"):
            checked([podman, "cp", str(out / name), f"{env['container']}:{stage}/{name}"])
        work = stage
        shell = command(env, ["bash", "-lc"])
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
    require(built, "assemble packed-memory ELF")
    syms = symbols((out / "symbols.txt").read_text())
    inspection = (out / "elf-inspection.txt").read_text()
    entry_match = re.search(r"Entry point address:\s+0x([0-9a-fA-F]+)", inspection)
    text_match = re.search(r"^\s*\[\s*\d+\]\s+\.text\s+\S+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)", inspection, re.MULTILINE)
    if not entry_match or not text_match:
        raise RuntimeError("missing ELF entry or executable section mapping")
    entry = int(entry_match.group(1), 16)
    text_vma, text_offset, text_size = (int(text_match.group(i), 16) for i in (1, 2, 3))
    if entry != syms["_start"]:
        raise RuntimeError("ELF entry does not match startup")
    text = (out / "text.bin").read_bytes()
    disassembly = (out / "kernel.asm").read_text()
    instructions = []
    for op in ops:
        pc = syms[f"op_{op['name']}"]
        raw = text[pc - text_vma:pc - text_vma + 4]
        decoded = [line.strip() for line in disassembly.splitlines() if re.search(rf"\b{pc:x}:\s", line)]
        if len(raw) != 4 or len(decoded) != 1 or op["mnemonic"] not in decoded[0]:
            raise RuntimeError(f"wrong assembled instruction at {op['name']}: {decoded}")
        instructions.append({"name": op["name"], "mnemonic": op["mnemonic"], "pc": f"0x{pc:x}",
                             "file_offset": f"0x{text_offset + pc - text_vma:x}",
                             "word": f"0x{int.from_bytes(raw, 'little'):08x}",
                             "bytes_memory_order": raw.hex(" "), "decoded": decoded[0]})
    (out / "operations.json").write_text(json.dumps(instructions, indent=2) + "\n")
    (out / "operations.bin").write_bytes(b"".join(bytes.fromhex(row["bytes_memory_order"]) for row in instructions))
    (out / "op.bin").write_bytes(bytes.fromhex(instructions[0]["bytes_memory_order"]))
    dump_addr, dump_size = syms["__monitor_start"], syms["__monitor_end"] - syms["__monitor_start"]
    (out / "elf-layout.json").write_text(json.dumps({
        "entry": f"0x{entry:x}", "selected_hart": "H0 S0:N0:C0:T0", "executable_sections": [".text"],
        "text_vma": f"0x{text_vma:x}", "text_file_offset": f"0x{text_offset:x}", "text_size": text_size,
        "monitor_address": f"0x{dump_addr:x}", "monitor_size": dump_size,
        "operations": instructions, "symbols": {name: f"0x{addr:x}" for name, addr in syms.items()},
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
    require(run, "execute packed-memory ELF")
    trace = run.stdout or ""
    if "Finishing emulation" not in trace or "Error, max cycles reached" in trace or re.search(r"\b(?:trap|exception)\b", trace, re.I):
        raise RuntimeError("packed-memory execution did not complete normally")
    events, regs = trace_data(trace)
    accesses = memory_events(trace)
    event_at(events, syms["park"], "wfi")
    pre, memory = (out / "prestart.bin").read_bytes(), (out / "output.bin").read_bytes()
    if len(pre) != dump_size or len(memory) != dump_size:
        raise RuntimeError("incomplete simulator memory dumps")
    relative = lambda name: syms[name] - dump_addr
    source, values, offsets = dataset(case)
    if pre[:len(source)] != source or memory[:len(source)] != source:
        raise RuntimeError("a packed store modified the shared input data")
    results, register_rows = [], []
    for op, inst in zip(ops, instructions):
        name, pc = str(op["name"]), int(inst["pc"], 16)
        event = event_at(events, pc, str(op["mnemonic"]))
        if event["word"] != int(inst["word"], 16):
            raise RuntimeError(f"executed word differs from ELF at {name}")
        mask_event = event_at(events, syms[f"mask_{name}"], "mova.m.x")
        if mask_event["state"].get("m0:=") != op["mask"]:
            raise RuntimeError(f"mask initialization was not observed at {name}")
        if "m0::" in event["state"] and event["state"]["m0::"] != op["mask"]:
            raise RuntimeError(f"wrong active mask at {name}")
        seed_pc, capture_pc = syms[f"seed_{name}"], syms[f"capture_{name}"]
        event_at(events, seed_pc, "flq2")
        event_at(events, capture_pc, "fsq2")
        before = regs[(seed_pc, "f20", "=")]
        after = regs[(capture_pc, "f20", ":")]
        target_off, snapshot_off = relative(f"target_{name}"), relative(f"snapshot_{name}")
        target = memory[target_off:target_off + TARGET_SIZE]
        if pre[target_off:target_off + TARGET_SIZE] != bytes([0xA5]) * TARGET_SIZE or pre[snapshot_off:snapshot_off + 32] != bytes([0xA5]) * 32:
            raise RuntimeError(f"missing initial sentinels for {name}")
        if before != (values if op["store"] else (SENTINEL,) * 8):
            raise RuntimeError(f"f20 seed was not observed for {name}")
        if after != struct.unpack_from("<8I", memory, snapshot_off):
            raise RuntimeError(f"snapshot trace and memory disagree for {name}")
        if op["store"]:
            if regs.get((pc, "f20", ":")) != before or after != before:
                raise RuntimeError(f"store changed its source register at {name}")
        elif regs.get((pc, "f20", "=")) != after:
            raise RuntimeError(f"load destination write and snapshot disagree at {name}")
        base_address = syms[f"target_{name}" if op["store"] else "source_data"]
        expected_addresses = [base_address + address for lane, address in enumerate(op["addresses"])
                              if int(op["effective_mask"]) >> lane & 1]
        if op["kind"] == "broadcast":
            expected_addresses = [base_address]  # one scalar read, followed by lane replication
        observed = accesses.get(pc, [])
        if [int(row["address"], 16) for row in observed] != expected_addresses:
            raise RuntimeError(f"unexpected memory accesses at {name}: {observed}")
        if any(row["bits"] != int(op["width"]) * 8 or row["direction"] != ("write" if op["store"] else "read") for row in observed):
            raise RuntimeError(f"wrong access width/direction at {name}")
        passed = after == op["expected_register"] and target == op["expected_memory"]
        results.append({"name": name, "mnemonic": op["mnemonic"], "pass": passed,
                        "register_actual": [f"0x{x:08x}" for x in after],
                        "register_expected": [f"0x{x:08x}" for x in op["expected_register"]],
                        "target_address": f"0x{base_address:x}", "target_actual_bytes": target.hex(" "),
                        "target_expected_bytes": op["expected_memory"].hex(" "), "accesses": observed})
        register_rows.append({**inst, "hart": event["hart"], "cycle": event["cycle"],
                              "f20_before": report_lanes(before), "f20_after": report_lanes(after),
                              "source": "traced flq2 seed, operation events, and full-lane fsq2 snapshot",
                              "mask": f"0x{op['mask']:02x}", "mask_evidence_pc": f"0x{mask_event['pc']:x}",
                              "operation_mask_read": event["state"].get("m0::"),
                              "f10_offsets": list(regs[(pc, "f10", ":")]) if (pc, "f10", ":") in regs else None})
        print(f"  {op['mnemonic']:<11} PC={inst['pc']} word={inst['word']} M0=0x{op['mask']:02x} accesses={len(observed)} {'PASS' if passed else 'FAIL'}")
    complete = struct.unpack_from("<I", memory, relative("completion"))[0]
    trap_marker = struct.unpack_from("<I", memory, relative("trap_marker"))[0]
    trap_cause = struct.unpack_from("<Q", memory, relative("trap_cause"))[0]
    passed = all(row["pass"] for row in results) and complete == DONE and not trap_marker and not trap_cause
    (out / "registers.json").write_text(json.dumps({"operations": register_rows}, indent=2, allow_nan=False) + "\n")
    (out / "result.json").write_text(json.dumps({"case": case, "operation_count": len(ops), "operations": results,
        "completion_word": f"0x{complete:08x}", "trap_marker": trap_marker, "trap_cause": trap_cause, "pass": passed}, indent=2) + "\n")
    if not passed:
        raise RuntimeError(f"packed-memory reference or completion checks failed; inspect {out}")
    print(f"Packed memory {case}: {len(ops)} sites, completion=0x{complete:08x}, traps=0/0, PASS; {out}")


def main() -> int:
    cases = sys.argv[1:] or ["primary", "exact"]
    if any(case not in ("primary", "exact") for case in cases):
        raise SystemExit("usage: python3 examples/packed_memory.py [primary|exact ...]")
    env = runtime()
    for case in cases:
        print(f"\nPacked memory {case}: H0 S0:N0:C0:T0")
        execute(case, env)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print(f"packed_memory.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
