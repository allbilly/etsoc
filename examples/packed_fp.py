#!/usr/bin/env python3
"""Exercise implemented ET-SOC1 packed-FP instructions in upstream SysEmu."""

from __future__ import annotations

import json
import math
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import uuid
from pathlib import Path

from gemm import LINKER, command, logged, report_lanes, runtime, symbols, trace_data


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out" / "packed-fp"
N = 8
SENTINEL = 0xA5A5A5A5
DONE = 0x4B4F5445
SIM_TIMEOUT = 90
SIM_CYCLES = 10_000
MASK_ALL = 0xFF


def bits(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0]


def value(word: int) -> float:
    return struct.unpack("<f", struct.pack("<I", word & 0xFFFFFFFF))[0]


def vector(values: tuple[float, ...] | list[float]) -> tuple[int, ...]:
    return tuple(bits(x) for x in values)


def f32(value_: float) -> int:
    return bits(value_)


def round_rne(value_: float) -> float:
    rounded = float(round(value_))
    return math.copysign(0.0, value_) if rounded == 0.0 else rounded


def vmap(fn, a: tuple[int, ...], b: tuple[int, ...] | None = None,
         c: tuple[int, ...] | None = None) -> tuple[int, ...]:
    if b is None:
        return tuple(f32(fn(value(x))) for x in a)
    if c is None:
        return tuple(f32(fn(value(x), value(y))) for x, y in zip(a, b))
    return tuple(f32(fn(value(x), value(y), value(z))) for x, y, z in zip(a, b, c))


def class_code(word: int) -> int:
    sign = word >> 31
    exponent = (word >> 23) & 0xFF
    fraction = word & 0x7FFFFF
    if exponent == 0xFF:
        if fraction == 0:
            return 1 << (0 if sign else 7)
        return 1 << (8 if not (fraction & 0x400000) else 9)
    if exponent == 0:
        if fraction == 0:
            return 1 << (3 if sign else 4)
        return 1 << (2 if sign else 5)
    return 1 << (1 if sign else 6)


def half_to_float_word(word: int) -> int:
    half = word & 0xFFFF
    return bits(struct.unpack("<e", struct.pack("<H", half))[0])


def float_to_half_word(word: int) -> int:
    return struct.unpack("<H", struct.pack("<e", value(word)))[0]


def arithmetic_inputs(case: str):
    if case == "primary":
        a = vector((1, 2, 3, 4, 5, 6, 7, 8))
        b = vector((2, 3, 4, 5, 6, 7, 8, 9))
        c = vector((0.5,) * N)
    elif case == "exact":
        a = vector((0.5, -1.5, 2.5, -3.5, 4.5, -5.5, 6.5, -7.5))
        b = vector((2, -2, 0.5, -0.5, 4, -4, 0.25, -0.25))
        c = vector((0.25, -0.25, 0.5, -0.5, 1, -1, 2, -2))
    else:
        raise ValueError(case)
    return a, b, c


def operation_table(case: str) -> list[dict[str, object]]:
    a, b, c = arithmetic_inputs(case)
    zero_one = tuple(bits(x) for x in (0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0))
    choose_a = tuple(0 if i % 2 == 0 else 0xFFFFFFFF for i in range(N))
    choose_b = tuple(0x3F800000 if x else 0 for x in (1, 0, 1, 0, 1, 0, 1, 0))
    choose_c = tuple(bits(float(i + 20)) for i in range(N))
    class_input = (0xBF800000, 0x00000000, 0x80000000, 0x7F800000,
                   0xFF800000, 0x7FC00001, 0x00000001, 0x3F800000)
    half_input = tuple((half | (0xDEAD << 16)) for half in
                       (0x3C00, 0xC000, 0x3800, 0x4400, 0x4500, 0x3400, 0x4C00, 0xC800))
    round_input = vector((-2.5, -1.5, -0.5, 0.5, 1.5, 2.5, 3.5, -3.5))
    unsigned_round_input = vector((0, 0.5, 1.5, 2.5, 3.5, 4.5, 5.5, 6.5))
    float_integer_input = tuple(x & 0xFFFFFFFF for x in (-3, -1, 0, 1, 2, 4, 7, 127))
    uint_integer_input = (0, 1, 2, 3, 4, 5, 0x7FFFFFFF, 0xFFFFFFFF)
    reciprocal_input = vector((0.5, 1, 2, 4, 8, 16, 0.25, 0.125))
    log_input = vector((0.25, 0.5, 1, 2, 4, 8, 16, 32))
    exp_input = vector((-2, -1, 0, 1, 2, 3, 4, -3))
    frac_input = vector((-3.25, -2.5, -1.75, -0.5, 0.25, 1.5, 2.75, 8.125))
    sign_a = vector((1, -2, 3, -4, 5, -6, 7, -8))
    sign_b = (0x80000000, 0, 0x80000000, 0, 0x80000000, 0, 0x80000000, 0)
    compare_a = vector((-2, -1, 0, 1, 2, 3, 4, 5))
    compare_b = vector((-2, 0, 0, 0, 1, 4, 3, 5))
    compare_eq = tuple(value(x) == value(y) for x, y in zip(compare_a, compare_b))
    compare_le = tuple(value(x) <= value(y) for x, y in zip(compare_a, compare_b))
    compare_lt = tuple(value(x) < value(y) for x, y in zip(compare_a, compare_b))
    f16_input = vector((1, -2, 0.5, 4, 5.5, 0.25, 16, -8))

    def make(name, asm, expected, inputs=None, kind="vector", mask=MASK_ALL, scalar=None):
        return {"name": name, "asm": asm, "expected": tuple(expected),
                "inputs": inputs or {}, "kind": kind, "mask": mask, "scalar": scalar}

    ops = [
        make("fadd_ps", "fadd.ps f20, f10, f11, rne", vmap(lambda x, y: x + y, a, b), {"f10": a, "f11": b}),
        make("fsub_ps", "fsub.ps f20, f10, f11, rne", vmap(lambda x, y: x - y, a, b), {"f10": a, "f11": b}),
        make("fmul_ps", "fmul.ps f20, f10, f11, rne", vmap(lambda x, y: x * y, a, b), {"f10": a, "f11": b}),
        make("fmadd_ps", "fmadd.ps f20, f10, f11, f13, rne", vmap(lambda x, y, z: x * y + z, a, b, c), {"f10": a, "f11": b, "f13": c}),
        make("fmsub_ps", "fmsub.ps f20, f10, f11, f13, rne", vmap(lambda x, y, z: x * y - z, a, b, c), {"f10": a, "f11": b, "f13": c}),
        make("fnmadd_ps", "fnmadd.ps f20, f10, f11, f13, rne", vmap(lambda x, y, z: -(x * y + z), a, b, c), {"f10": a, "f11": b, "f13": c}),
        make("fnmsub_ps", "fnmsub.ps f20, f10, f11, f13, rne", vmap(lambda x, y, z: -(x * y) + z, a, b, c), {"f10": a, "f11": b, "f13": c}),
        make("masked_fadd_ps", "fadd.ps f20, f10, f11, rne", tuple(f32(value(x) + value(y)) if (0x55 >> i) & 1 else SENTINEL for i, (x, y) in enumerate(zip(a, b))), {"f10": a, "f11": b}, mask=0x55),
        make("fbci_ps", "fbci.ps f20, 0x3f800", (bits(1.0),) * N),
        make("fbcx_ps", "fbcx.ps f20, t0", (bits(3.0),) * N, kind="vector", scalar=0x40400000),
        make("fclass_ps", "fclass.ps f20, f10", tuple(class_code(x) for x in class_input), {"f10": class_input}),
        make("fcmov_ps", "fcmov.ps f20, f10, f11, f13", tuple(y if s else z for s, y, z in zip(choose_a, choose_b, choose_c)), {"f10": choose_a, "f11": choose_b, "f13": choose_c}),
        make("fcmovm_ps", "fcmovm.ps f20, f10, f11", tuple(x if (0xAA >> i) & 1 else y for i, (x, y) in enumerate(zip(a, b))), {"f10": a, "f11": b}, mask=0xAA),
        make("fcvt_f16_ps", "fcvt.f16.ps f20, f10", tuple(float_to_half_word(x) for x in f16_input), {"f10": f16_input}),
        make("fcvt_ps_f16", "fcvt.ps.f16 f20, f10", tuple(half_to_float_word(x) for x in half_input), {"f10": half_input}),
        make("fcvt_ps_pw", "fcvt.ps.pw f20, f10, rne", tuple(f32(float(x if x < 0x80000000 else x - 0x100000000)) for x in float_integer_input), {"f10": float_integer_input}),
        make("fcvt_ps_pwu", "fcvt.ps.pwu f20, f10, rne", tuple(f32(float(x)) for x in uint_integer_input), {"f10": uint_integer_input}),
        make("fcvt_pw_ps", "fcvt.pw.ps f20, f10, rne", tuple(round(value(x)) & 0xFFFFFFFF for x in round_input), {"f10": round_input}),
        make("fcvt_pwu_ps", "fcvt.pwu.ps f20, f10, rne", tuple(round(value(x)) & 0xFFFFFFFF for x in unsigned_round_input), {"f10": unsigned_round_input}),
        make("feq_ps", "feq.ps f20, f10, f11", tuple(0xFFFFFFFF if flag else 0 for flag in compare_eq), {"f10": compare_a, "f11": compare_b}),
        make("fle_ps", "fle.ps f20, f10, f11", tuple(0xFFFFFFFF if flag else 0 for flag in compare_le), {"f10": compare_a, "f11": compare_b}),
        make("flt_ps", "flt.ps f20, f10, f11", tuple(0xFFFFFFFF if flag else 0 for flag in compare_lt), {"f10": compare_a, "f11": compare_b}),
        make("feqm_ps", "feqm.ps m4, f10, f11", tuple(int(flag) for flag in compare_eq), {"f10": compare_a, "f11": compare_b}, kind="mask"),
        make("flem_ps", "flem.ps m4, f10, f11", tuple(int(flag) for flag in compare_le), {"f10": compare_a, "f11": compare_b}, kind="mask"),
        make("fltm_ps", "fltm.ps m4, f10, f11", tuple(int(flag) for flag in compare_lt), {"f10": compare_a, "f11": compare_b}, kind="mask"),
        make("ffrc_ps", "ffrc.ps f20, f10", vmap(lambda x: math.modf(x)[0], frac_input), {"f10": frac_input}),
        make("fmax_ps", "fmax.ps f20, f10, f11", vmap(max, a, b), {"f10": a, "f11": b}),
        make("fmin_ps", "fmin.ps f20, f10, f11", vmap(min, a, b), {"f10": a, "f11": b}),
        make("fmvs_x_ps", "fmvs.x.ps t0, f10, 7", (), {"f10": (0, 1, 2, 3, 4, 5, 6, 0x80000001)}, kind="scalar", scalar=(0x80000001, True)),
        make("fmvz_x_ps", "fmvz.x.ps t0, f10, 7", (), {"f10": (0, 1, 2, 3, 4, 5, 6, 0x80000001)}, kind="scalar", scalar=(0x80000001, False)),
        make("fround_ps", "fround.ps f20, f10, rne", tuple(f32(round_rne(value(x))) for x in round_input), {"f10": round_input}),
        make("fsgnj_ps", "fsgnj.ps f20, f10, f11", tuple((x & 0x7FFFFFFF) | (y & 0x80000000) for x, y in zip(sign_a, sign_b)), {"f10": sign_a, "f11": sign_b}),
        make("fsgnjn_ps", "fsgnjn.ps f20, f10, f11", tuple((x & 0x7FFFFFFF) | ((~y) & 0x80000000) for x, y in zip(sign_a, sign_b)), {"f10": sign_a, "f11": sign_b}),
        make("fsgnjx_ps", "fsgnjx.ps f20, f10, f11", tuple((x & 0x7FFFFFFF) | ((x ^ y) & 0x80000000) for x, y in zip(sign_a, sign_b)), {"f10": sign_a, "f11": sign_b}),
        make("fswizz_ps", "fswizz.ps f20, f10, 0x1b", tuple(sign_a[(i & ~3) | (3 - (i & 3))] for i in range(N)), {"f10": sign_a}),
        make("frcp_ps", "frcp.ps f20, f10", vmap(lambda x: 1.0 / x, reciprocal_input), {"f10": reciprocal_input}),
        make("flog_ps", "flog.ps f20, f10", vmap(math.log2, log_input), {"f10": log_input}),
        make("fexp_ps", "fexp.ps f20, f10", vmap(lambda x: 2.0 ** x, exp_input), {"f10": exp_input}),
    ]
    return ops


def kernel(ops: list[dict[str, object]]) -> str:
    lines = [
        "# SPDX-License-Identifier: Apache-2.0",
        "# Bare-metal startup follows the minimal ET-SOC1 conventions documented in README.md.",
        ".option push", ".option norelax", ".option norvc",
        '.section .text.entry,"ax",@progbits', ".globl _start", "_start:",
        "    csrwi satp, 0", "    csrr t0, mstatus", "    li t1, 0x6000", "    or t0, t0, t1",
        "    csrw mstatus, t0", "    csrwi fcsr, 0", "    csrwi mip, 0", "    csrwi tensor_mask, 0",
        "    la sp, __stack_top", "    la t0, trap_handler", "    csrw mtvec, t0",
        "    li t0, 255", "    mova.m.x t0", "    la t4, result_data",
    ]
    for index, op in enumerate(ops):
        name = str(op["name"])
        active = int(op["mask"])
        lines.extend(("    li t0, 255", "    mova.m.x t0"))
        lines.extend(("    la t3, seed_vector", "    flw.ps f20, 0(t3)"))
        for freg, words in op["inputs"].items():
            label = f"input_{index}_{freg}"
            lines.extend((f"    la t3, {label}", f"    flw.ps {freg}, 0(t3)"))
        if active != MASK_ALL:
            lines.extend((f"    li t0, {active}", "    mova.m.x t0"))
        if op["scalar"] is not None and name == "fbcx_ps":
            lines.append(f"    li t0, 0x{int(op['scalar']):08x}")
        lines.extend((f".globl op_{name}", f"op_{name}:", f"    {op['asm']}"))
        if name == "fcmovm_ps":
            # The instruction ignores M0 for its write, but the following store
            # obeys M0. Restore all lanes so memory captures the full register.
            lines.extend(("    li t0, 255", "    mova.m.x t0"))
        if op["kind"] == "vector":
            lines.append(f"    fsw.ps f20, {index * 32}(t4)")
        elif op["kind"] == "scalar":
            lines.append(f"    sd t0, {index * 32}(t4)")
        else:
            lines.extend(("    mova.x.m t0", f"    sd t0, {index * 32}(t4)"))
    lines.extend((
        "    li t0, 0x4b4f5445", "    la t1, completion", "    sw t0, 0(t1)",
        ".globl park", "park:", "    wfi", "    j park", ".balign 4096", "trap_handler:",
        "    csrr t0, mcause", "    la t1, trap_cause", "    sd t0, 0(t1)",
        "    li t0, 1", "    la t1, trap_marker", "    sw t0, 0(t1)", "    j park",
        ".option pop", '.section .data,"aw",@progbits', ".balign 32", ".globl __monitor_start",
        "__monitor_start:", ".globl result_data", "result_data:", f"    .rept {len(ops) * 8}",
        f"    .word 0x{SENTINEL:08x}", "    .endr", ".globl completion", "completion:", "    .word 0",
        ".globl trap_marker", "trap_marker:", "    .word 0", ".globl trap_cause", "trap_cause:",
        "    .dword 0", "seed_vector:", "    .rept 8", f"    .word 0x{SENTINEL:08x}", "    .endr",
    ))
    for index, op in enumerate(ops):
        for freg, words in op["inputs"].items():
            lines.append(f".balign 32\ninput_{index}_{freg}:")
            lines.extend(f"    .word 0x{word & 0xffffffff:08x}" for word in words)
    lines.extend((".globl __monitor_end", "__monitor_end:"))
    return "\n".join(lines) + "\n"


def main() -> int:
    cases = sys.argv[1:] or ["primary", "exact"]
    if any(case not in ("primary", "exact") for case in cases):
        raise SystemExit("usage: python3 examples/packed_fp.py [primary|exact ...]")
    env = runtime()
    passed_all = True
    for case in cases:
        ops = operation_table(case)
        out = OUT if case == "primary" else OUT / case
        out.mkdir(parents=True, exist_ok=True)
        log = out / "commands.log"
        log.write_text("")
        (out / "kernel.S").write_text(kernel(ops))
        (out / "link.ld").write_text(LINKER)
        stage = f"/tmp/etsoc1-packed-fp-{uuid.uuid4().hex[:10]}"
        containerized = env["kind"] == "podman"
        if containerized:
            podman = shutil.which("podman") or "podman"
            logged(log, [podman, "exec", env["container"], "mkdir", "-p", stage])
            for filename in ("kernel.S", "link.ld"):
                logged(log, [podman, "cp", str(out / filename), f"{env['container']}:{stage}/{filename}"])
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
        logged(log, [*shell, build])
        if containerized:
            logged(log, [shutil.which("podman") or "podman", "cp", f"{env['container']}:{stage}/.", str(out)])
        syms = symbols((out / "symbols.txt").read_text())
        if any(f"op_{op['name']}" not in syms for op in ops):
            raise RuntimeError("linked kernel is missing packed-FP operation labels")
        elf = (out / "elf-inspection.txt").read_text()
        entry_match = re.search(r"Entry point address:\s+0x([0-9a-fA-F]+)", elf)
        section = re.search(r"^\s*\[\s*\d+\]\s+\.text\s+\S+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)", elf, re.MULTILINE)
        if not entry_match or not section:
            raise RuntimeError("could not map .text virtual and file addresses")
        entry = int(entry_match.group(1), 16)
        text_vma, text_offset, text_size = (int(section.group(i), 16) for i in (1, 2, 3))
        text = (out / "text.bin").read_bytes()
        disasm = (out / "kernel.asm").read_text()
        instructions = []
        for op in ops:
            pc = syms[f"op_{op['name']}"]
            raw = text[pc - text_vma:pc - text_vma + 4]
            decoded = [line.strip() for line in disasm.splitlines() if re.search(rf"\b{pc:x}:\s", line)]
            if len(raw) != 4 or len(decoded) != 1 or str(op["asm"]).split()[0] not in decoded[0]:
                raise RuntimeError(f"ET toolchain did not decode {op['name']} at 0x{pc:x}: {decoded}")
            instructions.append({"name": op["name"], "pc": f"0x{pc:x}",
                                 "mnemonic": str(op["asm"]).split()[0],
                                 "bytes_memory_order": raw.hex(" "),
                                 "word": f"0x{int.from_bytes(raw, 'little'):08x}", "decoded": decoded[0],
                                 "kind": op["kind"], "mask_expected": f"0x{int(op['mask']):02x}"})
        (out / "operations.json").write_text(json.dumps(instructions, indent=2) + "\n")
        (out / "operations.bin").write_bytes(b"".join(bytes.fromhex(item["bytes_memory_order"]) for item in instructions))
        (out / "op.bin").write_bytes(bytes.fromhex(instructions[0]["bytes_memory_order"]))
        dump_addr = syms["__monitor_start"]
        dump_size = syms["__monitor_end"] - dump_addr
        (out / "elf-layout.json").write_text(json.dumps({
            "entry": f"0x{entry:x}", "selected_hart": "H0 S0:N0:C0:T0",
            "text_vma": f"0x{text_vma:x}", "text_file_offset": f"0x{text_offset:x}",
            "text_size": text_size, "operation_count": len(ops), "operations": instructions,
            "operation_file_offsets": {
                op["name"]: f"0x{text_offset + syms['op_' + str(op['name'])] - text_vma:x}"
                for op in ops
            },
            "executable_sections": [".text"], "monitor_address": f"0x{dump_addr:x}",
            "monitor_size": dump_size,
        }, indent=2, allow_nan=False) + "\n")
        sim = [env["simulator"], "-l", "-lm", "0", "-lt", "0", "-sp_dis", "-reset_pc", hex(entry),
               "-single_thread", "-minions", "0x1", "-shires", "0x1", "-max_cycles", str(SIM_CYCLES),
               "-elf_load", f"{work}/kernel.elf", "-dump_at_pc_pc", hex(entry),
               "-dump_at_pc_addr", hex(dump_addr), "-dump_at_pc_size", hex(dump_size),
               "-dump_at_pc_file", f"{work}/prestart.bin", "-dump_addr", hex(dump_addr),
               "-dump_size", str(dump_size), "-dump_file", f"{work}/output.bin"]
        timed = command(env, ["timeout", "--signal=TERM", "--kill-after=5s", f"{SIM_TIMEOUT}s", *sim])
        run = logged(log, timed)
        if containerized:
            logged(log, [shutil.which("podman") or "podman", "cp", f"{env['container']}:{stage}/.", str(out)])
            logged(log, [shutil.which("podman") or "podman", "exec", env["container"], "rm", "-rf", stage])
        trace = run.stdout or ""
        (out / "trace.log").write_text(trace)
        if run.returncode or "Finishing emulation" not in trace or "Error, max cycles reached" in trace:
            raise RuntimeError(f"SysEmu did not complete normally; inspect {out}/trace.log")
        events, regs = trace_data(trace)
        op_events = []
        for item in instructions:
            pc = int(item["pc"], 16)
            found = [event for event in events if event["pc"] == pc]
            if len(found) != 1:
                raise RuntimeError(f"SysEmu executed {len(found)} times at {item['name']} PC 0x{pc:x}")
            event = found[0]
            if event["hart"] != "H0 S0:N0:C0:T0":
                raise RuntimeError(f"{item['name']} ran on unexpected hart {event['hart']}")
            if event["word"] != int(item["word"], 16) or not str(event["disassembly"]).startswith(item["mnemonic"]):
                raise RuntimeError(f"{item['name']} executed a different instruction from its ELF encoding")
            op_events.append(event)
        pre = (out / "prestart.bin").read_bytes()
        memory = (out / "output.bin").read_bytes()
        if len(pre) != dump_size or len(memory) != dump_size:
            raise RuntimeError("SysEmu did not dump the complete monitor range")
        result_off = syms["result_data"] - dump_addr
        result_rows, register_rows = [], []
        for index, (op, event, inst) in enumerate(zip(ops, op_events, instructions)):
            offset = result_off + index * 32
            if struct.unpack_from("<8I", pre, offset) != (SENTINEL,) * N:
                raise RuntimeError(f"{op['name']} output slot lacks its sentinel before execution")
            raw = memory[offset:offset + 32]
            expected = tuple(op["expected"])
            actual: tuple[int, ...] | int
            expected_scalar = None
            if op["kind"] == "vector":
                actual = struct.unpack("<8I", raw)
                passed = actual == expected
                dest_reg = regs.get((event["pc"], "f20", "="))
                if dest_reg != actual:
                    raise RuntimeError(f"{op['name']} register write trace and memory result differ")
            elif op["kind"] == "scalar":
                actual = struct.unpack_from("<Q", raw)[0]
                source, sign_extend = op["scalar"]
                expected_scalar = ((source | 0xFFFFFFFF00000000) if sign_extend and source & 0x80000000 else source)
                passed = actual == expected_scalar
                expected = (expected_scalar,)
                trace_scalar = regs.get((event["pc"], "x5", "="))
                if trace_scalar != expected_scalar:
                    raise RuntimeError(f"{op['name']} SysEmu x5 write trace differs from the stored scalar")
            else:
                actual64 = struct.unpack_from("<Q", raw)[0]
                actual = actual64
                mask_value = sum((int(flag) & 1) << lane for lane, flag in enumerate(expected))
                expected_mask64 = mask_value << (4 * 8)
                expected_mask64 |= MASK_ALL  # mova.x.m returns M0 in bits 0..7 too.
                passed = actual64 == expected_mask64
                expected = (expected_mask64,)
                mask_write = event["state"].get("m4:=")
                if mask_write is None or mask_write & 0xFF != mask_value:
                    raise RuntimeError(f"{op['name']} did not write expected m4 mask 0x{mask_value:02x}")
            if op["kind"] != "vector" and raw[8:] != bytes.fromhex("a5" * 24):
                raise RuntimeError(f"{op['name']} wrote beyond its eight-byte scalar/mask result")
            mask_now = event["state"].get("m0::")
            if op["kind"] != "scalar" and mask_now != int(op["mask"]):
                raise RuntimeError(f"{op['name']} active M0={mask_now}; expected 0x{int(op['mask']):02x}")
            result_rows.append({"name": op["name"], "instruction": inst["decoded"],
                                "actual": [f"0x{x:08x}" for x in actual] if isinstance(actual, tuple) else f"0x{actual:016x}",
                                "expected": [f"0x{x:08x}" for x in expected] if op["kind"] != "mask" else f"0x{expected[0]:016x}",
                                "output_memory_bytes": raw.hex(" "), "pass": passed})
            register_rows.append({"name": op["name"], "pc": inst["pc"], "hart": event["hart"],
                                  "word": inst["word"], "bytes_memory_order": inst["bytes_memory_order"],
                                  "decoded": inst["decoded"],
                                  "active_mask": f"0x{mask_now:02x}" if mask_now is not None else "not read by instruction",
                                  "reads": {key: report_lanes(regs[(event["pc"], key, ":")])
                                            for key in op["inputs"] if (event["pc"], key, ":") in regs},
                                  "f20_after": report_lanes(regs[(event["pc"], "f20", "=")])
                                               if (event["pc"], "f20", "=") in regs else None,
                                  "x5_after": f"0x{trace_scalar:016x}" if op["kind"] == "scalar" else None,
                                  "mask_m4_after": f"0x{event['state']['m4:=']:02x}"
                                                   if "m4:=" in event["state"] else None})
        completion = struct.unpack_from("<I", memory, syms["completion"] - dump_addr)[0]
        trap_marker = struct.unpack_from("<I", memory, syms["trap_marker"] - dump_addr)[0]
        trap_cause = struct.unpack_from("<Q", memory, syms["trap_cause"] - dump_addr)[0]
        passed = all(row["pass"] for row in result_rows) and completion == DONE and not trap_marker and not trap_cause
        if not passed:
            raise RuntimeError("packed-FP output/reference, completion, or trap checks failed")
        (out / "registers.json").write_text(json.dumps({
            "source": "SysEmu execution register trace; vector memory results checked against destination-register writes",
            "hart": "H0 S0:N0:C0:T0", "active_mask_policy": "M0 checked at each operation PC",
            "operations": register_rows,
        }, indent=2) + "\n")
        (out / "result.json").write_text(json.dumps({
            "case": case, "operation_count": len(ops), "output_actual": result_rows,
            "completion_word": f"0x{completion:08x}", "trap_marker": trap_marker,
            "trap_cause": trap_cause, "pass": passed,
        }, indent=2) + "\n")
        print(f"\nPacked FP {case}: {len(ops)} instruction sites; entry=0x{entry:x}; hart=H0 S0:N0:C0:T0")
        for row in result_rows:
            print(f"  {row['name']}: {row['instruction']} -> {row['actual']} {'PASS' if row['pass'] else 'FAIL'}")
        print(f"  completion=0x{completion:08x}; traps={trap_marker}/{trap_cause}; PASS; artifacts: {out}")
        passed_all &= passed
    return 0 if passed_all else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError, struct.error) as exc:
        print(f"packed_fp.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
