#!/usr/bin/env python3
"""Enable the ET graphics feature from device code and execute its ISA handlers."""

from __future__ import annotations

import math
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
from packed_memory import memory_events


OUT = ROOT / "out" / "graphics"
FEATURE_ESR = 0x01C0340000  # S0, machine-privilege shire ESR; esrs_et.cpp.
SENTINEL = 0xA5A5A5A5
SCALAR_SEED = 0x5AA55AA55AA55AA5
DONE = 0x4B4F5445
SIM_TIMEOUT = 90
SIM_CYCLES = 10_000


def f32(x: float) -> int:
    return struct.unpack("<I", struct.pack("<f", x))[0]


def tiny_encode(x: float, mantissa_bits: int) -> int:
    """Finite, normal positive test values: unsigned E5M5/E5M6, truncation."""
    if x <= 0:
        return 0
    fraction, exponent = math.frexp(x)
    return ((exponent + 14) << mantissa_bits) | int((2 * fraction - 1) * (1 << mantissa_bits))


def tiny_decode(word: int, mantissa_bits: int) -> int:
    mask = (1 << mantissa_bits) - 1
    exponent, mantissa = (word >> mantissa_bits) & 31, word & mask
    return f32(0.0 if not exponent and not mantissa else
               math.ldexp(1 + mantissa / (1 << mantissa_bits), exponent - 15))


def bitmix(selector: int, source: int) -> int:
    low, high, answer = source & 255, (source >> 8) & 255, 0
    for pos in range(16):
        if selector >> pos & 1:
            answer |= (high & 1) << pos
            high >>= 1
        else:
            answer |= (low & 1) << pos
            low >>= 1
    return answer


def operations(case: str) -> list[dict[str, object]]:
    """Reference calculations validate execution; they never supply device results."""
    mask = 0xFF if case == "primary" else 0x55
    reverse = lambda xs: tuple(xs if case == "primary" else reversed(xs))
    faces = reverse(range(8))
    signs = tuple(f32((-1 if i & 1 else 1) * (i + 1) / 2) for i in range(8))
    if case == "exact":
        signs = tuple(x ^ 0x80000000 for x in signs)
    seed = reverse((0, 1, 0, 1, 0, 1, 0, 1))
    result = []

    def vector(mnemonic, expected, a, b=None, *, initial=(SENTINEL,) * 8, assembly=None):
        inputs = {"f10": tuple(a)}
        if b is not None:
            inputs["f11"] = tuple(b)
        result.append({"name": mnemonic.replace(".", "_"), "mnemonic": mnemonic,
                       "asm": assembly or f"{mnemonic} f20, f10" + (", f11" if b is not None else ""),
                       "kind": "vector", "inputs": inputs, "seed": tuple(initial), "mask": mask,
                       "expected": tuple(x if mask >> i & 1 else initial[i] for i, x in enumerate(expected))})

    vector("cubeface.ps", tuple((0 if y & 1 else 1) if d & 1 else (0 if x & 1 else 2)
                               for d, x, y in zip(seed, faces, reversed(faces))),
           faces, tuple(reversed(faces)), initial=seed)
    vector("cubefaceidx.ps", tuple(0x7FC00000 if x & 3 == 3 else f32(2 * (x & 3) + (y >> 31))
                                   for x, y in zip(faces, signs)), faces, signs)
    vector("cubesgnsc.ps", tuple((y & 0x7FFFFFFF) | (0x80000000 if x & 7 in (0, 5) else 0)
                                 for x, y in zip(faces, signs)), faces, signs)
    vector("cubesgntc.ps", tuple((y & 0x7FFFFFFF) | (0 if x & 7 == 2 else 0x80000000)
                                 for x, y in zip(faces, signs)), faces, signs)
    tiny_input = (-1.0, 0.0, 0.5, 1.0, 1.046875, 2.5, 128.0, 0.03125) if case == "primary" else (
                  1.0234375, 1.9921875, 0.03125, 2 ** -10, 4.0, 8.0, 16.0, -0.0)
    for mnemonic, count in (("fcvt.f10.ps", 5), ("fcvt.f11.ps", 6)):
        vector(mnemonic, tuple(tiny_encode(x, count) for x in tiny_input), tuple(f32(x) for x in tiny_input))
    for mnemonic, count in (("fcvt.ps.f10", 5), ("fcvt.ps.f11", 6)):
        values = reverse((0, 15 << count, 16 << count, (15 << count) | 3,
                          10 << count, 20 << count, (17 << count) | 7, 14 << count))
        vector(mnemonic, tuple(tiny_decode(x, count) for x in values), tuple(0xBEEF0000 | x for x in values))

    fixed_input = reverse((0, 65536, -65536, 32768, -32768, 16384, 17, -17))
    vector("fcvt.ps.rast", tuple(f32(x / 65536) for x in fixed_input), tuple(x & 0xFFFFFFFF for x in fixed_input))
    raster_input = (0.0, 0.5, -0.5, 1.0, -1.0, 1 / 16384, -1 / 16384, 3 / 16384) if case == "primary" else (
                   0.25, -0.25, 1.5, -1.5, 2 / 16384, -2 / 16384, 5 / 16384, -5 / 16384)
    # f32_to_fxp1714 adds 0.5 before the RNE integer conversion. This is
    # deliberately checked, including signed half-integer ties.
    vector("fcvt.rast.ps", tuple((round(x * 16384 + 0.5) if x else 0) & 0xFFFFFFFF for x in raster_input),
           tuple(f32(x) for x in raster_input))
    for mnemonic, width in (("fcvt.ps.sn8", 8), ("fcvt.ps.sn16", 16)):
        maximum = (1 << (width - 1)) - 1
        values = reverse((0, maximum, -maximum, -maximum - 1, 1, -1, maximum // 2, -maximum // 2))
        vector(mnemonic, tuple(f32(max(-1.0, x / maximum)) for x in values),
               tuple(0xBEEF0000 | (x & ((1 << width) - 1)) for x in values))
    for mnemonic, width in (("fcvt.ps.un2", 2), ("fcvt.ps.un8", 8), ("fcvt.ps.un10", 10),
                             ("fcvt.ps.un16", 16), ("fcvt.ps.un24", 24)):
        maximum = (1 << width) - 1
        values = reverse((0, maximum, maximum // 2, 1, maximum - 1, maximum // 3, 2 * maximum // 3, maximum // 4))
        vector(mnemonic, tuple(f32(x / maximum) for x in values), tuple(0xAB000000 | x for x in values))
    norm_input = (-1.5, -1.0, -0.5, -0.0, 0.0, 0.25, 0.5, 1.5) if case == "primary" else (
                 0.125, 0.375, 0.625, 0.875, 1.0, -0.125, -0.375, -2.0)
    # SN/UN output conversion uses fixed nearest, ties away from zero,
    # regardless of the active FRM. Results occupy low bits of each 32-bit lane.
    for mnemonic, width in (("fcvt.sn8.ps", 8), ("fcvt.sn16.ps", 16)):
        maximum = (1 << (width - 1)) - 1
        expected = tuple(((-1 if x < 0 else 1) * math.floor(min(abs(x), 1) * maximum + 0.5)) &
                         ((1 << width) - 1) for x in norm_input)
        vector(mnemonic, expected, tuple(f32(x) for x in norm_input))
    for mnemonic, width in (("fcvt.un2.ps", 2), ("fcvt.un8.ps", 8), ("fcvt.un10.ps", 10),
                             ("fcvt.un16.ps", 16), ("fcvt.un24.ps", 24)):
        maximum = (1 << width) - 1
        vector(mnemonic, tuple(math.floor(max(0, min(x, 1)) * maximum + 0.5) for x in norm_input),
               tuple(f32(x) for x in norm_input))
    area = reverse((65536, 131072, 32768, 65536, 262144, 98304, 8192, 49152))
    estimate = reverse((16384, 4096, 16384, 8192, 2048, 8192, 32768, 16384))
    if case == "exact":
        estimate = tuple(x // 2 for x in estimate)
    expected = tuple((y * ((2 << 30) - x * y)) // (1 << 30) for x, y in zip(area, estimate))
    vector("frcp.fix.rast", expected, area, estimate, assembly="frcp_fix.rast f20, f10, f11")
    selector, source = (0xFFFF1234AA55, 0xBEEF0096C3) if case == "primary" else (0xAAAA5678C33C, 0x1234005AA5)
    result.append({"name": "bitmixb", "mnemonic": "bitmixb", "asm": "bitmixb s4, t1, t2",
                   "kind": "scalar", "scalar_inputs": (selector, source), "expected": bitmix(selector, source)})
    m1, m2 = (0xAA, 0xC3) if case == "primary" else (0x96, 0x69)
    for selector, selected in enumerate((0x0F, 0x3C, 0xF0, 0xFF)):
        result.append({"name": f"maskpopc_rast_{selector}", "mnemonic": "maskpopc.rast",
                       "asm": f"maskpopc.rast s4, m1, m2, {selector}", "kind": "mask", "masks": (m1, m2),
                       "expected": (m1 & selected).bit_count() + (m2 & selected).bit_count()})
    return result


def kernel(ops: list[dict[str, object]]) -> str:
    lines = ["# SPDX-License-Identifier: Apache-2.0",
             "# Startup provenance: Copyright (c) 2025 Ainekko, Co.; ET Platform boot.S.",
             ".option push", ".option norelax", ".option norvc", '.section .text.entry,"ax",@progbits',
             ".globl _start", "_start:", "    csrwi satp, 0", "    csrr t0, mstatus", "    li t1, 0x6000",
             "    or t0, t0, t1", "    csrw mstatus, t0", "    csrwi fcsr, 0", "    csrwi mip, 0",
             "    csrwi tensor_mask, 0", "    la sp, __stack_top", "    la t0, trap_handler", "    csrw mtvec, t0",
             f"    li t6, 0x{FEATURE_ESR:x}", ".globl feature_read_before", "feature_read_before:", "    ld t0, 0(t6)",
             "    la t1, feature_before", "    sd t0, 0(t1)", "    andi t0, t0, -2",
             ".globl feature_write", "feature_write:", "    sd t0, 0(t6)",
             ".globl feature_read_after", "feature_read_after:", "    ld t0, 0(t6)",
             "    la t1, feature_after", "    sd t0, 0(t1)"]
    for op in ops:
        name = op["name"]
        lines.extend(("    csrwi fcsr, 0", "    li t0, 255", "    mova.m.x t0"))
        if op["kind"] == "vector":
            for register in ("f20", *op["inputs"]):
                lines.extend((f"    la t3, input_{name}_{register}", f"    flq2 {register}, 0(t3)"))
            lines.extend((f"    li t0, {op['mask']}", "    mova.m.x t0", f"    la t3, before_{name}"))
            before = "fsq2 f20, 0(t3)"
        else:
            lines.extend((f"    li s4, 0x{SCALAR_SEED:x}", f"    la t3, before_{name}"))
            before = "sd s4, 0(t3)"
            if op["kind"] == "scalar":
                a, b = op["scalar_inputs"]
                lines.extend((f"    li t1, 0x{a:x}", f"    li t2, 0x{b:x}"))
            else:
                m1, m2 = op["masks"]
                lines.extend((f"    li t0, 0x{(m2 << 16) | (m1 << 8) | 255:x}", "    mova.m.x t0"))
        lines.extend((f".globl capture_before_{name}", f"capture_before_{name}:", f"    {before}",
                      f".globl fcsr_before_{name}", f"fcsr_before_{name}:", "    csrr t5, fcsr",
                      f".globl op_{name}", f"op_{name}:", f"    {op['asm']}",
                      f".globl fcsr_after_{name}", f"fcsr_after_{name}:", "    csrr t5, fcsr",
                      f"    la t3, result_{name}", f".globl capture_after_{name}", f"capture_after_{name}:",
                      "    fsq2 f20, 0(t3)" if op["kind"] == "vector" else "    sd s4, 0(t3)"))
    lines.extend((f"    li t0, 0x{DONE:x}", "    la t1, completion", "    sw t0, 0(t1)",
                  ".globl park", "park:", "    wfi", "    j park", ".balign 4096", "trap_handler:",
                  "    csrr t0, mcause", "    la t1, trap_cause", "    sd t0, 0(t1)",
                  "    li t0, 1", "    la t1, trap_marker", "    sw t0, 0(t1)", "    j park", ".option pop",
                  '.section .data,"aw",@progbits', ".balign 32", ".globl __monitor_start", "__monitor_start:",
                  "feature_before:", "    .dword 0xa5a5a5a5a5a5a5a5", "feature_after:", "    .dword 0xa5a5a5a5a5a5a5a5"))
    for op in ops:
        name = op["name"]
        lines.extend((".balign 32", f"before_{name}:", "    .fill 32,1,0xa5", f"result_{name}:", "    .fill 32,1,0xa5"))
        if op["kind"] == "vector":
            for register, words in {"f20": op["seed"], **op["inputs"]}.items():
                lines.extend((f"input_{name}_{register}:", "    .word " + ", ".join(f"0x{x:08x}" for x in words)))
    lines.extend(("completion:", "    .word 0", "trap_marker:", "    .word 0", "trap_cause:", "    .dword 0",
                  ".globl __monitor_end", "__monitor_end:"))
    return "\n".join(lines) + "\n"


def execute(case: str, env: dict[str, str]) -> None:
    out = OUT if case == "primary" else OUT / case
    out.mkdir(parents=True, exist_ok=True)
    log = out / "commands.log"
    log.write_text("")
    for name in ("result.json", "registers.json", "output.bin", "prestart.bin", "trace.log"):
        (out / name).unlink(missing_ok=True)
    ops = operations(case)
    (out / "kernel.S").write_text(kernel(ops))
    (out / "link.ld").write_text(LINKER)
    stage = f"/tmp/etsoc1-graphics-{uuid.uuid4().hex[:10]}"
    container, podman = env["kind"] == "podman", shutil.which("podman") or "podman"

    def checked(argv):
        result = run_logged(log, argv)
        if result.returncode:
            raise RuntimeError(f"command failed with status {result.returncode}; inspect {log}")
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
        raise RuntimeError(f"graphics assembly failed; inspect {log}")
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
        if len(raw) != 4 or len(decoded) != 1 or op["asm"].split()[0] not in decoded[0]:
            raise RuntimeError(f"wrong assembled graphics instruction: {op['name']}: {decoded}")
        instructions.append({"name": op["name"], "mnemonic": op["mnemonic"], "assembly": op["asm"], "pc": f"0x{pc:x}",
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
    trace = run.stdout or ""
    (out / "trace.log").write_text(trace)
    if container:
        checked([podman, "cp", f"{env['container']}:{stage}/.", str(out)])
        checked([podman, "exec", env["container"], "rm", "-rf", stage])
    if run.returncode or "Finishing emulation" not in trace or "Error, max cycles reached" in trace or re.search(r"\b(?:trap|exception)\b", trace, re.I):
        raise RuntimeError(f"graphics execution did not complete normally; inspect {out}")
    events, regs = trace_data(trace)
    event_at(events, syms["park"], "wfi")
    pre, memory = (out / "prestart.bin").read_bytes(), (out / "output.bin").read_bytes()
    if len(pre) != dump_size or len(memory) != dump_size:
        raise RuntimeError("incomplete simulator memory dumps")
    relative = lambda name: syms[name] - dump_addr
    feature_before = struct.unpack_from("<Q", memory, relative("feature_before"))[0]
    feature_after = struct.unpack_from("<Q", memory, relative("feature_after"))[0]
    accesses = memory_events(trace)
    for label, direction, val in (("feature_read_before", "read", feature_before),
                                  ("feature_write", "write", feature_after), ("feature_read_after", "read", feature_after)):
        pc = syms[label]
        event_at(events, pc, "ld" if direction == "read" else "sd")
        if accesses.get(pc) != [{"bits": 64, "address": f"0x{FEATURE_ESR:x}", "direction": direction, "value": f"0x{val:x}"}]:
            raise RuntimeError(f"missing actual graphics feature ESR access at {label}")
    if not feature_before & 1 or feature_after != feature_before & ~1:
        raise RuntimeError(f"unexpected graphics feature transition: {feature_before:#x} -> {feature_after:#x}")
    results, register_rows = [], []
    for op, inst in zip(ops, instructions):
        name, pc = op["name"], int(inst["pc"], 16)
        event = event_at(events, pc, op["mnemonic"])
        if event["word"] != int(inst["word"], 16):
            raise RuntimeError(f"executed word differs from ELF at {name}")
        before_pc, after_pc = syms[f"capture_before_{name}"], syms[f"capture_after_{name}"]
        expected_size, register = (32, "f20") if op["kind"] == "vector" else (8, "x20")
        expected_before = op["seed"] if op["kind"] == "vector" else SCALAR_SEED
        before, after = regs[(before_pc, register, ":")], regs[(after_pc, register, ":")]
        if before != expected_before or regs.get((pc, register, "=")) != after:
            raise RuntimeError(f"destination seed, write or snapshot disagree at {name}")
        for label, val in ((f"before_{name}", before), (f"result_{name}", after)):
            offset = relative(label)
            raw = memory[offset:offset + expected_size]
            snap = struct.unpack("<8I", raw) if expected_size == 32 else struct.unpack("<Q", raw)[0]
            if val != snap or pre[offset:offset + 32] != bytes([0xA5]) * 32:
                raise RuntimeError(f"incorrect snapshot/sentinel at {label}")
            if memory[offset + expected_size:offset + 32] != bytes([0xA5]) * (32 - expected_size):
                raise RuntimeError(f"scalar snapshot overwrote guards at {label}")
        captured = {}
        if op["kind"] == "vector":
            for reg, words in op["inputs"].items():
                captured[reg] = regs[(pc, reg, ":")]
                if captured[reg] != words:
                    raise RuntimeError(f"incorrect traced input at {name} {reg}")
                offset = relative(f"input_{name}_{reg}")
                if memory[offset:offset + 32] != pre[offset:offset + 32]:
                    raise RuntimeError(f"graphics operation changed its input memory at {name}")
            if event["state"].get("m0::") != op["mask"]:
                raise RuntimeError(f"incorrect active lane mask at {name}")
        elif op["kind"] == "scalar":
            captured = {reg: regs[(pc, reg, ":")] for reg in ("x6", "x7")}
            if tuple(captured.values()) != op["scalar_inputs"]:
                raise RuntimeError("incorrect bitmixb scalar inputs")
        else:
            captured = {reg: event["state"][reg + "::"] for reg in ("m1", "m2")}
            if tuple(captured.values()) != op["masks"]:
                raise RuntimeError(f"incorrect maskpopc.rast inputs at {name}")
        before_fcsr = event_at(events, syms[f"fcsr_before_{name}"], "csrr")["state"]["fcsr"]
        after_fcsr = event_at(events, syms[f"fcsr_after_{name}"], "csrr")["state"]["fcsr"]
        if before_fcsr != 0:
            raise RuntimeError(f"FP state was not initialized at {name}")
        passed = after == op["expected"]
        results.append({"name": name, "pass": passed, "expected_raw": op["expected"], "actual_raw": after})
        register_rows.append({**inst, "hart": event["hart"], "cycle": event["cycle"],
                              "destination": register, "before": report_lanes(before) if expected_size == 32 else before,
                              "after": report_lanes(after) if expected_size == 32 else after,
                              "inputs_raw": captured, "active_mask": event["state"].get("m0::"),
                              "fcsr_before": before_fcsr, "fcsr_after": after_fcsr})
        print(f"  {name:<20} PC={inst['pc']} word={inst['word']} {'PASS' if passed else 'FAIL'}")
    complete = struct.unpack_from("<I", memory, relative("completion"))[0]
    trap_marker = struct.unpack_from("<I", memory, relative("trap_marker"))[0]
    trap_cause = struct.unpack_from("<Q", memory, relative("trap_cause"))[0]
    passed = all(row["pass"] for row in results) and complete == DONE and not trap_marker and not trap_cause
    (out / "registers.json").write_text(json.dumps({"feature_before": feature_before, "feature_after": feature_after,
                                                  "operations": register_rows}, indent=2, allow_nan=False) + "\n")
    (out / "result.json").write_text(json.dumps({"case": case, "operation_count": len(ops), "operations": results,
        "feature_before": feature_before, "feature_after": feature_after,
        "completion_word": f"0x{complete:08x}", "trap_marker": trap_marker, "trap_cause": trap_cause, "pass": passed}, indent=2) + "\n")
    if not passed:
        raise RuntimeError(f"graphics reference/completion checks failed; inspect {out}/result.json")
    print(f"Graphics {case}: {len(ops)} sites, feature={feature_before:#x}->{feature_after:#x}, completion=0x{complete:x}, PASS; {out}")


def main() -> int:
    cases = sys.argv[1:] or ["primary", "exact"]
    if any(case not in ("primary", "exact") for case in cases):
        raise SystemExit("usage: python3 examples/graphics.py [primary|exact ...]")
    env = runtime()
    for case in cases:
        execute(case, env)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print(f"graphics.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
