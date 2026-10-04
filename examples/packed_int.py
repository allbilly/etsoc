#!/usr/bin/env python3
"""Execute the decoded ET packed-integer ALU instructions on SysEmu."""

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

from gemm import ROOT, command, logged, runtime, symbols, trace_data


OUT = ROOT / "out" / "packed-int"
MASK = 0xFFFFFFFF
SENTINEL = 0xA5A5A5A5
MASK_SENTINEL = 0xA5A5A5A5A5A5A5A5
DONE = 0x4B4F5445
SIM_TIMEOUT = 90
SIM_CYCLES = 10_000


def u32(value: int) -> int:
    return value & MASK


def s32(value: int) -> int:
    value &= MASK
    return value if value < 0x80000000 else value - 0x100000000


def packed_u32(values: list[int]) -> bytes:
    return struct.pack(f"<{len(values)}I", *(u32(x) for x in values))


def sat8(value: int) -> int:
    return min(max(s32(value), -128), 127) & 0xFF


def satu8(value: int) -> int:
    return min(max(s32(value), 0), 255)


def packrepb(values: list[int]) -> list[int]:
    data = packed_u32(values)
    return [sum(data[(16 * lane + 4 * byte) % len(data)] << (8 * byte)
                for byte in range(4)) for lane in range(8)]


def packreph(values: list[int]) -> list[int]:
    data = packed_u32(values)
    halfwords = struct.unpack("<16H", data)
    return [halfwords[(4 * lane) % len(halfwords)] |
            (halfwords[(4 * lane + 2) % len(halfwords)] << 16) for lane in range(8)]


# Inputs are raw 32-bit integer elements held in the minion floating-point
# register file. Every operation below appears as an explicit ET instruction
# in the generated kernel.S and is decoded again by GNU objdump and SysEmu.
VECTOR_OPS = [
    ("fadd_pi", "fadd.pi f20, f10, f11", lambda a, b: u32(a + b)),
    ("faddi_pi", "faddi.pi f20, f10, -17", lambda a, b: u32(a - 17)),
    ("fsub_pi", "fsub.pi f20, f10, f11", lambda a, b: u32(a - b)),
    ("fmul_pi", "fmul.pi f20, f10, f11", lambda a, b: u32(a * b)),
    ("fmulh_pi", "fmulh.pi f20, f10, f11", lambda a, b: u32((s32(a) * s32(b)) >> 32)),
    ("fmulhu_pi", "fmulhu.pi f20, f10, f11", lambda a, b: u32((a * b) >> 32)),
    ("fand_pi", "fand.pi f20, f10, f11", lambda a, b: a & b),
    ("fandi_pi", "fandi.pi f20, f10, 341", lambda a, b: a & 341),
    ("for_pi", "for.pi f20, f10, f11", lambda a, b: a | b),
    ("fxor_pi", "fxor.pi f20, f10, f11", lambda a, b: a ^ b),
    ("fnot_pi", "fnot.pi f20, f10", lambda a, b: u32(~a)),
    ("feq_pi", "feq.pi f20, f10, f11", lambda a, b: MASK if a == b else 0),
    ("fle_pi", "fle.pi f20, f10, f11", lambda a, b: MASK if s32(a) <= s32(b) else 0),
    ("flt_pi", "flt.pi f20, f10, f11", lambda a, b: MASK if s32(a) < s32(b) else 0),
    ("fltu_pi", "fltu.pi f20, f10, f11", lambda a, b: MASK if a < b else 0),
    ("fmax_pi", "fmax.pi f20, f10, f11", lambda a, b: u32(max(s32(a), s32(b)))),
    ("fmaxu_pi", "fmaxu.pi f20, f10, f11", lambda a, b: max(a, b)),
    ("fmin_pi", "fmin.pi f20, f10, f11", lambda a, b: u32(min(s32(a), s32(b)))),
    ("fminu_pi", "fminu.pi f20, f10, f11", lambda a, b: min(a, b)),
    ("fsll_pi", "fsll.pi f20, f10, f11", lambda a, b: 0 if b >= 32 else u32(a << b)),
    ("fslli_pi", "fslli.pi f20, f10, 3", lambda a, b: u32(a << 3)),
    ("fsra_pi", "fsra.pi f20, f10, f11", lambda a, b: u32(s32(a) >> min(b, 31))),
    ("fsrai_pi", "fsrai.pi f20, f10, 3", lambda a, b: u32(s32(a) >> 3)),
    ("fsrl_pi", "fsrl.pi f20, f10, f11", lambda a, b: 0 if b >= 32 else a >> b),
    ("fsrli_pi", "fsrli.pi f20, f10, 3", lambda a, b: a >> 3),
    ("fsat8_pi", "fsat8.pi f20, f10", lambda a, b: sat8(a)),
    ("fsatu8_pi", "fsatu8.pi f20, f10", lambda a, b: satu8(a)),
    ("fpackrepb_pi", "fpackrepb.pi f20, f10", lambda a, b: 0),
    ("fpackreph_pi", "fpackreph.pi f20, f10", lambda a, b: 0),
    ("fbci_pi", "fbci.pi f20, 123", lambda a, b: 123),
]
MASK_OPS = [
    ("mova_m_x_test", "mova.m.x t0"),
    ("maskand", "maskand m3, m1, m2"),
    ("masknot", "masknot m4, m1"),
    ("maskor", "maskor m5, m1, m2"),
    ("maskxor", "maskxor m6, m1, m2"),
    ("maskpopc", "maskpopc t0, m3"),
    ("maskpopcz", "maskpopcz t0, m1"),
    ("mov_m_x_test", "mov.m.x m7, t0, 15"),
    ("mova_x_m_test", "mova.x.m t0"),
]

PRIMARY = (
    [0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x00000000,
     0x00000100, 0x12345678, 0x00000005, 0x80000001],
    [0x00000002, 0x00000002, 0x00000001, 0xFFFFFFFF,
     0x00000008, 0x00000004, 0x00000020, 0x0000001F],
)
EXACT = (
    [0x00000000, 0x00000001, 0x00000002, 0x00000003,
     0x00000004, 0x00000005, 0x7FFFFFFF, 0x80000000],
    [0x00000000, 0x00000003, 0x00000001, 0x00000002,
     0xFFFFFFFF, 0x00000008, 0x00000001, 0xFFFFFFFF],
)


LINKER = """/* SPDX-License-Identifier: Apache-2.0 */
OUTPUT_ARCH("riscv")
ENTRY(_start)
SECTIONS {
  .text 0x8000001000 : { KEEP(*(.text.entry)) *(.text .text.*) }
  .data 0x8000100000 : { *(.data .data.*) }
  .stack 0x8000200000 (NOLOAD) : { __stack_bottom = .; . += 0x4000; __stack_top = .; }
}
"""


def expected_vectors(a: list[int], b: list[int]) -> dict[str, list[int]]:
    expected = {name: [u32(fn(x, y)) for x, y in zip(a, b)] for name, _, fn in VECTOR_OPS}
    expected["fpackrepb_pi"] = packrepb(a)
    expected["fpackreph_pi"] = packreph(a)
    return expected


def kernel_source(a: list[int], b: list[int]) -> str:
    lines = [
        "# SPDX-License-Identifier: Apache-2.0",
        "# Minimal startup follows the pinned ET-SOC1 bare-metal conventions in README.md.",
        ".option push", ".option norelax", ".option norvc",
        '.section .text.entry,"ax",@progbits', ".globl _start", "_start:",
        "    csrwi satp, 0", "    csrr t0, mstatus", "    li t1, 0x6000", "    or t0, t0, t1",
        "    csrw mstatus, t0", "    csrwi fcsr, 0", "    csrwi mip, 0", "    csrwi tensor_mask, 0",
        "    la sp, __stack_top", "    la t0, trap_handler", "    csrw mtvec, t0",
        "    li t0, 255", "    mova.m.x t0", "    la t1, input_a", "    flw.ps f10, 0(t1)",
        "    la t1, input_b", "    flw.ps f11, 0(t1)", "    la t3, result_data",
    ]
    for index, (name, instruction, _) in enumerate(VECTOR_OPS):
        lines.extend((f".globl op_{name}", f"op_{name}:", f"    {instruction}",
                      f"    fsw.ps f20, {index * 32}(t3)"))
    lines.extend((
        ".globl op_fsetm_pi", "op_fsetm_pi:", "    fsetm.pi m0, f10",
        "    mova.x.m t0", "    la t4, result_masks", "    sd t0, 0(t4)",
        "    li t0, 255", "    mova.m.x t0",
        ".globl op_fltm_pi", "op_fltm_pi:", "    fltm.pi m0, f10, f11",
        "    mova.x.m t0", "    sd t0, 8(t4)",
        "    li t0, 255", "    mova.m.x t0",
        "    li t0, 0x00ccaaff",
    ))
    for name, instruction in MASK_OPS:
        if name == "mov_m_x_test":
            lines.append("    li t0, 0xa0")
        lines.extend((f".globl op_{name}", f"op_{name}:", f"    {instruction}"))
        if name == "maskpopc":
            lines.extend(("    la t4, mask_counts", "    sw t0, 0(t4)"))
        elif name == "maskpopcz":
            lines.append("    sw t0, 4(t4)")
        elif name == "mova_x_m_test":
            lines.extend(("    la t4, result_masks", "    sd t0, 16(t4)"))
    lines.extend((
        "    li t0, 0x4b4f5445", "    la t1, completion", "    sw t0, 0(t1)",
        ".globl park", "park:", "    wfi", "    j park", ".balign 4096", "trap_handler:",
        "    csrr t0, mcause", "    la t1, trap_cause", "    sd t0, 0(t1)",
        "    li t0, 1", "    la t1, trap_marker", "    sw t0, 0(t1)", "    j park",
        ".option pop", '.section .data,"aw",@progbits', ".balign 32", "input_a:",
    ))
    lines.extend(f"    .word 0x{x:08x}" for x in a)
    lines.append("input_b:")
    lines.extend(f"    .word 0x{x:08x}" for x in b)
    lines.extend((".balign 32", ".globl __monitor_start", "__monitor_start:",
                  ".globl result_data", "result_data:", ".rept 8",))
    lines.extend((f"    .word 0x{SENTINEL:08x}",) * len(VECTOR_OPS))
    lines.extend((".endr", ".globl result_masks", "result_masks:",
                  f"    .dword 0x{MASK_SENTINEL:016x}", f"    .dword 0x{MASK_SENTINEL:016x}",
                  f"    .dword 0x{MASK_SENTINEL:016x}",
                  ".globl mask_counts", "mask_counts:",
                  f"    .word 0x{SENTINEL:08x}", f"    .word 0x{SENTINEL:08x}",
                  ".globl completion", "completion:", "    .word 0",
                  ".globl trap_marker", "trap_marker:", "    .word 0",
                  ".globl trap_cause", "trap_cause:", "    .dword 0",
                  ".globl __monitor_end", "__monitor_end:"))
    return "\n".join(lines) + "\n"


def execute_case(case: str, a: list[int], b: list[int], env: dict[str, str]) -> bool:
    out = OUT if case == "primary" else OUT / case
    out.mkdir(parents=True, exist_ok=True)
    log = out / "commands.log"
    log.write_text("")
    (out / "kernel.S").write_text(kernel_source(a, b))
    (out / "link.ld").write_text(LINKER)
    run_id = uuid.uuid4().hex[:10]
    stage = f"/tmp/etsoc1-packed-int-{run_id}"
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
    tp = shlex.quote(env["tool_prefix"])
    qwork = shlex.quote(work)
    build = (f"set -euo pipefail; cd {qwork}; "
             f"{tp}as --march=rv64imfc -mabi=lp64f -o kernel.o kernel.S; "
             f"{tp}ld --no-relax --build-id=none -T link.ld -o kernel.elf kernel.o; "
             f"{tp}objdump -d -M numeric kernel.elf > kernel.asm; "
             f"{tp}readelf -h -l -S kernel.elf > elf-inspection.txt; "
             f"{tp}nm -n --defined-only kernel.elf > symbols.txt; "
             f"{tp}objcopy -O binary --only-section=.text kernel.elf text.bin")
    logged(log, [*shell, build])
    if containerized:
        logged(log, [shutil.which("podman") or "podman", "cp", f"{env['container']}:{stage}/.", str(out)])
    sym = symbols((out / "symbols.txt").read_text())
    elf = (out / "elf-inspection.txt").read_text()
    entry_match = re.search(r"Entry point address:\s+0x([0-9a-fA-F]+)", elf)
    section = re.search(r"^\s*\[\s*\d+\]\s+\.text\s+\S+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)",
                        elf, re.MULTILINE)
    if not entry_match or not section:
        raise RuntimeError("could not derive ELF entry and .text mapping")
    entry = int(entry_match.group(1), 16)
    text_vma, text_offset, text_size = (int(section.group(i), 16) for i in (1, 2, 3))
    text = (out / "text.bin").read_bytes()
    disassembly = (out / "kernel.asm").read_text()
    op_names = ([name for name, _, _ in VECTOR_OPS] + ["fsetm_pi", "fltm_pi"] +
                [name for name, _ in MASK_OPS])
    operation_mnemonics = {name: instruction.split()[0] for name, instruction, _ in VECTOR_OPS}
    operation_mnemonics.update({name: instruction.split()[0] for name, instruction in MASK_OPS})
    operation_mnemonics.update({"fsetm_pi": "fsetm.pi", "fltm_pi": "fltm.pi"})
    operations = []
    for name in op_names:
        pc = sym[f"op_{name}"]
        decoded = [line.strip() for line in disassembly.splitlines() if re.search(rf"\b{pc:x}:\s", line)]
        code = text[pc - text_vma:pc - text_vma + 4]
        mnemonic = operation_mnemonics[name]
        if len(decoded) != 1 or not code or not re.search(rf"\b{re.escape(mnemonic)}\b", decoded[0]):
            raise RuntimeError(f"missing or misdecoded {name} at 0x{pc:x}: {decoded}")
        operations.append({"name": name, "mnemonic": mnemonic,
                           "pc": f"0x{pc:x}", "word": f"0x{int.from_bytes(code, 'little'):08x}",
                           "bytes_memory_order": code.hex(" "), "disassembly": decoded[0]})
    (out / "operations.json").write_text(json.dumps(operations, indent=2) + "\n")
    (out / "operations.bin").write_bytes(b"".join(bytes.fromhex(item["bytes_memory_order"]) for item in operations))
    dump_addr = sym["__monitor_start"]
    dump_size = sym["__monitor_end"] - dump_addr
    (out / "elf-layout.json").write_text(json.dumps({
        "entry": f"0x{entry:x}", "selected_hart": "H0 S0:N0:C0:T0",
        "text_vma": f"0x{text_vma:x}", "text_file_offset": f"0x{text_offset:x}",
        "text_size": text_size, "monitor_address": f"0x{dump_addr:x}", "monitor_size": dump_size,
        "operation_file_offsets": {item["name"]: f"0x{(text_offset + int(item['pc'], 16) - text_vma):x}"
                                   for item in operations},
    }, indent=2) + "\n")
    sim = [env["simulator"], "-l", "-lm", "0", "-lt", "0", "-sp_dis", "-reset_pc", hex(entry),
           "-single_thread", "-minions", "0x1", "-shires", "0x1", "-max_cycles", str(SIM_CYCLES),
           "-elf_load", f"{work}/kernel.elf", "-dump_at_pc_pc", hex(entry),
           "-dump_at_pc_addr", hex(dump_addr), "-dump_at_pc_size", hex(dump_size),
           "-dump_at_pc_file", f"{work}/prestart.bin", "-dump_addr", hex(dump_addr),
           "-dump_size", str(dump_size), "-dump_file", f"{work}/output.bin"]
    result = logged(log, command(env, ["timeout", "--signal=TERM", "--kill-after=5s", f"{SIM_TIMEOUT}s", *sim]))
    if containerized:
        logged(log, [shutil.which("podman") or "podman", "cp", f"{env['container']}:{stage}/.", str(out)])
        logged(log, [shutil.which("podman") or "podman", "exec", env["container"], "rm", "-rf", stage])
    trace = result.stdout or ""
    (out / "trace.log").write_text(trace)
    if "Finishing emulation" not in trace or "Error, max cycles reached" in trace:
        raise RuntimeError(f"SysEmu did not finish normally; inspect {out}/trace.log")
    events, register_writes = trace_data(trace)
    executed = [event for event in events if event["pc"] in {int(x["pc"], 16) for x in operations}]
    if [event["pc"] for event in executed] != [int(x["pc"], 16) for x in operations]:
        raise RuntimeError(f"SysEmu executed {len(executed)} target ops, expected {len(operations)}")
    for event, item in zip(executed, operations):
        if event["hart"] != "H0 S0:N0:C0:T0" or not str(event["disassembly"]).startswith(item["mnemonic"]):
            raise RuntimeError(f"wrong hart or instruction at {item['pc']}: {event}")
        if event["word"] != int(item["word"], 16):
            raise RuntimeError(f"executed word differs from the ELF instruction at {item['pc']}")
        if item["name"] in {name for name, _, _ in VECTOR_OPS} | {"fsetm_pi", "fltm_pi"} and \
           event["state"].get("m0::") != 0xFF:
            raise RuntimeError(f"M0 was not 0xff before {item['name']}")
    if len((out / "output.bin").read_bytes()) != dump_size:
        raise RuntimeError("SysEmu did not save the complete output monitor")
    before = (out / "prestart.bin").read_bytes()
    output = (out / "output.bin").read_bytes()
    relative = lambda name: sym[name] - dump_addr
    data_offset = relative("result_data")
    before_words = struct.unpack_from(f"<{len(VECTOR_OPS) * 8}I", before, data_offset)
    if before_words != (SENTINEL,) * (len(VECTOR_OPS) * 8):
        raise RuntimeError("one or more packed integer result lanes lacked the initial sentinel")
    actual = {}
    registers = []
    wanted = expected_vectors(a, b)
    passed = True
    for index, (name, instruction, _) in enumerate(VECTOR_OPS):
        values = list(struct.unpack_from("<8I", output, data_offset + index * 32))
        actual[name] = values
        pc = sym[f"op_{name}"]
        traced = register_writes.get((pc, "f20", "="))
        if traced is None or tuple(values) != traced:
            raise RuntimeError(f"memory output and SysEmu f20 write differ for {name}")
        if values != wanted[name]:
            passed = False
        event = next(e for e in events if e["pc"] == pc)
        evidence = {"instruction": name, "pc": f"0x{pc:x}", "hart": event["hart"],
                    "cycle": event["cycle"], "f20_after_u32": list(traced), "active_mask": "0xff"}
        if "f10" in instruction:
            evidence["f10_before_u32"] = list(register_writes[(pc, "f10", ":")])
        if "f11" in instruction:
            evidence["f11_before_u32"] = list(register_writes[(pc, "f11", ":")])
        registers.append(evidence)
    mask_before = struct.unpack_from("<2Q", before, relative("result_masks"))
    masks = struct.unpack_from("<2Q", output, relative("result_masks"))
    expected_masks = (
        sum((1 << lane) for lane, x in enumerate(a) if x != 0),
        sum((1 << lane) for lane, (x, y) in enumerate(zip(a, b)) if s32(x) < s32(y)),
    )
    if mask_before != (MASK_SENTINEL, MASK_SENTINEL) or masks != expected_masks:
        passed = False
    mask_seed = 0x00CCAAFF
    expected_all_masks = 0xAF66EE5588CCAAFF
    mask_registers_before = struct.unpack_from("<Q", before, relative("result_masks") + 16)[0]
    mask_registers_after = struct.unpack_from("<Q", output, relative("result_masks") + 16)[0]
    count_before = struct.unpack_from("<2I", before, relative("mask_counts"))
    mask_counts = struct.unpack_from("<2I", output, relative("mask_counts"))
    if mask_registers_before != MASK_SENTINEL or count_before != (SENTINEL, SENTINEL):
        passed = False
    if mask_registers_after != expected_all_masks or mask_counts != (2, 4):
        passed = False
    mask_write_expectations = {"maskand": ("m3", 0x88), "masknot": ("m4", 0x55),
                               "maskor": ("m5", 0xEE), "maskxor": ("m6", 0x66),
                               "mov_m_x_test": ("m7", 0xAF)}
    for name, (register, value) in mask_write_expectations.items():
        event = next(event for event in events if event["pc"] == sym[f"op_{name}"])
        if event["state"].get(f"{register}:=") != value:
            passed = False
    if register_writes.get((sym["op_maskpopc"], "x5", "=")) != 2 or \
       register_writes.get((sym["op_maskpopcz"], "x5", "=")) != 4 or \
       register_writes.get((sym["op_mova_x_m_test"], "x5", "=")) != expected_all_masks:
        passed = False
    mova_event = next(event for event in events if event["pc"] == sym["op_mova_m_x_test"])
    if any(mova_event["state"].get(f"m{index}:=") != ((mask_seed >> (8 * index)) & 0xFF)
           for index in range(8)):
        passed = False
    completion = struct.unpack_from("<I", output, relative("completion"))[0]
    trap = struct.unpack_from("<I", output, relative("trap_marker"))[0]
    cause = struct.unpack_from("<Q", output, relative("trap_cause"))[0]
    if completion != DONE or trap or cause:
        passed = False
    (out / "registers.json").write_text(json.dumps({
        "source": "SysEmu instruction trace register-write events, tied to each op PC and hart",
        "operations": registers,
        "mask_results": {"fsetm.pi": f"0x{masks[0]:x}", "fltm.pi": f"0x{masks[1]:x}"},
        "mask_alu": {"masks_m0_to_m7": f"0x{mask_registers_after:016x}",
                     "maskpopc_m3": mask_counts[0], "maskpopcz_m1": mask_counts[1],
                     "expected_m0_to_m7": f"0x{expected_all_masks:016x}"},
    }, indent=2) + "\n")
    report = {"case": case, "input_a_u32": a, "input_b_u32": b,
              "actual_u32": actual, "expected_u32": wanted,
              "actual_memory_bytes": output[data_offset:data_offset + len(VECTOR_OPS) * 32].hex(" "),
              "mask_results": {"fsetm.pi": f"0x{masks[0]:x}", "fltm.pi": f"0x{masks[1]:x}"},
              "expected_masks": {"fsetm.pi": f"0x{expected_masks[0]:x}", "fltm.pi": f"0x{expected_masks[1]:x}"},
              "mask_alu": {"masks_m0_to_m7": f"0x{mask_registers_after:016x}",
                           "maskpopc_m3": mask_counts[0], "maskpopcz_m1": mask_counts[1]},
              "completion_word": f"0x{completion:08x}", "trap_marker": trap,
              "trap_cause": cause, "instruction_count": len(executed), "pass": passed}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    if not passed:
        raise RuntimeError(f"packed integer reference mismatch; inspect {out}/result.json and trace.log")
    print(f"\nPACKED INT {case}: {len(VECTOR_OPS)} vector integer operations + "
          f"{len(MASK_OPS) + 2} mask operations")
    print("  mask=0xff; completion=0x%08x; traps=%d/%d" % (completion, trap, cause))
    for name, values in actual.items():
        print(f"  {name}: {[f'0x{x:08x}' for x in values]}")
    print(f"  fsetm.pi mask=0x{masks[0]:02x}; fltm.pi mask=0x{masks[1]:02x}")
    print(f"  mask ALU packed m0..m7=0x{mask_registers_after:016x}; popcounts={mask_counts}")
    print(f"  PASS; artifacts: {out}")
    return passed


def main() -> int:
    selected = sys.argv[1:] or ["primary", "exact"]
    if any(case not in ("primary", "exact") for case in selected):
        raise SystemExit("usage: python3 examples/packed_int.py [primary|exact ...]")
    env = runtime()
    return 0 if all(execute_case(case, *(PRIMARY if case == "primary" else EXACT), env)
                     for case in selected) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print(f"packed_int.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
