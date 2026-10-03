#!/usr/bin/env python3
"""Compare the measured ADD/MUL builds and run a one-instruction ELF patch."""

from __future__ import annotations

import difflib
import json
import os
import shlex
import shutil
import struct
import subprocess
import sys
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out" / "compare"
sys.path.insert(0, str(ROOT / "examples"))
import add as add_example  # shares only the small trace and process helpers


def write_diff(path: Path, left_name: str, left: str, right_name: str, right: str) -> str:
    diff = "".join(difflib.unified_diff(left.splitlines(True), right.splitlines(True),
                                       fromfile=left_name, tofile=right_name))
    path.write_text(diff)
    return diff


def byte_changes(left: bytes, right: bytes) -> list[tuple[int, int | None, int | None]]:
    size = max(len(left), len(right))
    return [(i, left[i] if i < len(left) else None, right[i] if i < len(right) else None)
            for i in range(size) if i >= len(left) or i >= len(right) or left[i] != right[i]]


def byte_diff_text(changes: list[tuple[int, int | None, int | None]]) -> str:
    rows = ["offset      ADD byte  MUL byte\n"]
    for offset, before, after in changes:
        old = "--" if before is None else f"{before:02x}"
        new = "--" if after is None else f"{after:02x}"
        rows.append(f"0x{offset:08x}  {old}        {new}\n")
    return "".join(rows)


def bits(word: int) -> dict[str, int]:
    return {"opcode": word & 0x7F, "rd": word >> 7 & 0x1F,
            "rm_funct3": word >> 12 & 7, "rs1": word >> 15 & 0x1F,
            "rs2": word >> 20 & 0x1F, "funct7": word >> 25 & 0x7F}


def save_patch_execution(elf: Path, layout: dict[str, object], mul_result: dict[str, object],
                         directory: Path, runtime: dict[str, str]) -> dict[str, object]:
    directory.mkdir(parents=True, exist_ok=True)
    log = directory / "commands.log"
    log.write_text("")
    run_id = uuid.uuid4().hex[:10]
    stage = f"/tmp/etsoc1-patched-{run_id}"
    container = runtime["kind"] == "podman"
    podman = shutil.which("podman") or "podman"
    if container:
        add_example.require(add_example.run_logged(log, [podman, "exec", runtime["container"], "mkdir", "-p", stage]),
                            "create patched-run staging directory")
        add_example.require(add_example.run_logged(log, [podman, "cp", str(elf),
                                                         f"{runtime['container']}:{stage}/kernel.elf"]),
                            "copy patched ELF into SysEmu environment")
        work = stage
        prefix = [podman, "exec", runtime["container"]]
    else:
        work = str(directory)
        shutil.copy2(elf, directory / "kernel.elf")
        prefix = []

    dump_addr = int(layout["monitor_address"], 16)
    dump_size = int(layout["monitor_size"])
    entry = int(layout["entry"], 16)
    op_pc = int(layout["operation_pc"], 16)
    simulator = runtime["simulator"]
    sim = [simulator, "-l", "-lm", "0", "-lt", "0", "-sp_dis", "-reset_pc", hex(entry),
           "-single_thread", "-minions", "0x1", "-shires", "0x1", "-max_cycles", "10000",
           "-elf_load", f"{work}/kernel.elf", "-dump_at_pc_pc", hex(entry),
           "-dump_at_pc_addr", hex(dump_addr), "-dump_at_pc_size", hex(dump_size),
           "-dump_at_pc_file", f"{work}/prestart.bin", "-dump_addr", hex(dump_addr),
           "-dump_size", str(dump_size), "-dump_file", f"{work}/output.bin"]
    result = add_example.run_logged(log, [*prefix, "timeout", "--signal=TERM", "--kill-after=5s", "90s", *sim], 120)
    if container:
        pulled = add_example.run_logged(log, [podman, "cp", f"{runtime['container']}:{stage}/.", str(directory)])
        if pulled.returncode != 0:
            raise RuntimeError("failed to retrieve patched-ELF evidence; container staging files remain")
        add_example.run_logged(log, [podman, "exec", runtime["container"], "rm", "-rf", stage])
    trace = result.stdout or ""
    (directory / "trace.log").write_text(trace)
    if result.returncode != 0 or "Finishing emulation" not in trace or "Error, max cycles reached" in trace:
        raise RuntimeError(f"patched ELF did not complete successfully (SysEmu status {result.returncode})")

    symbols = {name: int(value, 16) for name, value in layout["symbols"].items()}
    events, regs = add_example.trace_events(trace)
    op = add_example.event_at(events, op_pc, "fmul.ps")
    source_a, source_b = regs[(op_pc, "f10", ":")], regs[(op_pc, "f11", ":")]
    result_f12 = regs[(op_pc, "f12", "=")]
    post: dict[str, tuple[int, ...]] = {}
    output = (directory / "output.bin").read_bytes()
    initial = (directory / "prestart.bin").read_bytes()
    start = dump_addr
    for n in (10, 11, 12):
        pc_match = [e for e in events if str(e["disassembly"]).startswith("fsw.ps f%d," % n)]
        if len(pc_match) != 1:
            # The linker exports each after-operation capture PC in the source
            # ELF symbol table; those addresses are also in the normalized layout.
            cap_name = f"capture_f{n}_after"
            cap_pc = layout.get("capture_pcs", {}).get(cap_name)
            if cap_pc is None:
                raise RuntimeError(f"missing patched-run snapshot PC for f{n}")
            pc_match = [e for e in events if e["pc"] == int(cap_pc, 16)]
        pc = int(pc_match[0]["pc"])
        post[f"f{n}"] = regs[(pc, f"f{n}", ":")]
        snap = symbols[f"snapshot_f{n}"] - start
        if post[f"f{n}"] != struct.unpack_from("<8I", output, snap):
            raise RuntimeError(f"patched-run f{n} trace and device snapshot differ")

    def monitor_offset(name: str) -> int:
        return symbols[name] - dump_addr

    initial_c = initial[monitor_offset("result_c"):monitor_offset("result_c") + 32]
    actual = output[monitor_offset("result_c"):monitor_offset("result_c") + 32]
    complete = struct.unpack_from("<I", output, monitor_offset("completion"))[0]
    trap_marker = struct.unpack_from("<I", output, monitor_offset("trap_marker"))[0]
    trap_cause = struct.unpack_from("<Q", output, monitor_offset("trap_cause"))[0]
    expected = bytes.fromhex(mul_result["actual_output_bytes"].replace(" ", ""))
    if initial_c != bytes([0xA5]) * 32 or actual != expected or complete != add_example.DONE_WORD or trap_marker or trap_cause:
        raise RuntimeError("patched ELF failed its sentinel, output, completion, or trap checks")

    fcsr_after_pc = layout["capture_pcs"]["capture_fcsr_after"]
    fcsr_event = add_example.event_at(events, int(fcsr_after_pc, 16), "csrr")
    mask = op["state"].get("m0::")
    register_report = {
        "source": "SysEmu execution trace and device-side fsw.ps snapshots from the patched ELF",
        "operation_pc": f"0x{op_pc:x}", "hart": op["hart"], "cycle": op["cycle"],
        "decoded_instruction": op["disassembly"],
        "f10": {"before": add_example.lane_report(source_a), "after": add_example.lane_report(post["f10"])},
        "f11": {"before": add_example.lane_report(source_b), "after": add_example.lane_report(post["f11"])},
        "f12": {"before": add_example.lane_report(add_example.trace_events(trace)[1][
            (int(layout["seed_load_pc"], 16), "f12", "=")]), "after": add_example.lane_report(result_f12)},
        "active_mask": f"0x{mask:02x}", "fcsr_after": f"0x{add_example.state_value(fcsr_event, 'fcsr'):x}",
        "output_memory_bytes": actual.hex(" "), "completion_word": f"0x{complete:08x}",
        "trap_marker": trap_marker, "trap_cause": trap_cause,
    }
    (directory / "registers.json").write_text(json.dumps(register_report, indent=2) + "\n")
    (directory / "result.json").write_text(json.dumps({
        "operation": "fmul.ps", "output_bytes": actual.hex(" "),
        "output": struct.unpack("<8f", actual), "expected": mul_result["actual_output"],
        "pass": True,
    }, indent=2) + "\n")
    return {"status": result.returncode, "output": struct.unpack("<8f", actual),
            "registers": register_report, "operation": op["disassembly"]}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    patched_dir = OUT / "patched"
    patched_dir.mkdir(parents=True, exist_ok=True)
    commands = OUT / "commands.log"
    commands.write_text("")
    for script in (ROOT / "examples" / "add.py", ROOT / "examples" / "mul.py"):
        result = add_example.run_logged(commands, [sys.executable, str(script)], 600)
        add_example.require(result, f"run {script.name} for primary and exact inputs")

    add_root, mul_root = ROOT / "out" / "add", ROOT / "out" / "mul"
    add_layout = json.loads((add_root / "elf-layout.json").read_text())
    mul_layout = json.loads((mul_root / "elf-layout.json").read_text())
    add_result = json.loads((add_root / "result.json").read_text())
    mul_result = json.loads((mul_root / "result.json").read_text())
    if not add_result["pass"] or not mul_result["pass"]:
        raise RuntimeError("one or both primary arithmetic results did not pass")
    if add_layout["operation_pc"] != mul_layout["operation_pc"] or add_layout["entry"] != mul_layout["entry"]:
        raise RuntimeError("ADD and MUL linker layouts do not match")

    source_diff = write_diff(OUT / "source.diff", "add/kernel.S", (add_root / "kernel.S").read_text(),
                             "mul/kernel.S", (mul_root / "kernel.S").read_text())
    if (add_root / "kernel.S").read_text().replace("fadd.ps", "<packed-op>") != \
       (mul_root / "kernel.S").read_text().replace("fmul.ps", "<packed-op>"):
        raise RuntimeError("the device source changed beyond the ADD-to-MUL instruction")
    disassembly_diff = write_diff(OUT / "disassembly.diff", "add/kernel.asm", (add_root / "kernel.asm").read_text(),
                                  "mul/kernel.asm", (mul_root / "kernel.asm").read_text())
    op_add, op_mul = (add_root / "op.bin").read_bytes(), (mul_root / "op.bin").read_bytes()
    if len(op_add) != 4 or len(op_mul) != 4:
        raise RuntimeError("expected two four-byte packed instructions")
    word_add, word_mul = int.from_bytes(op_add, "little"), int.from_bytes(op_mul, "little")
    word_xor = word_add ^ word_mul
    changed_bits = [bit for bit in range(32) if word_xor & (1 << bit)]
    fields_add, fields_mul = bits(word_add), bits(word_mul)
    if fields_add["funct7"] != 0x00 or fields_mul["funct7"] != 0x08:
        raise RuntimeError(f"measured instruction fields do not match SysEmu decoder: {fields_add}, {fields_mul}")
    if any(fields_add[k] != fields_mul[k] for k in fields_add if k != "funct7"):
        raise RuntimeError("some decoded field other than funct7 changed")

    platform = Path(os.environ.get("ET_PLATFORM_SOURCE", Path.home() / "et-platform"))
    commit = subprocess.run(["git", "-C", str(platform), "rev-parse", "HEAD"],
                            check=True, text=True, capture_output=True).stdout.strip()
    env = add_example.runtime()
    if env.get("platform_commit") and env["platform_commit"] != commit:
        raise RuntimeError("checked-out ET Platform revision differs from setup.sh's recorded revision")
    decoder = (platform / "sw-sysemu" / "processor.cpp").read_text()
    start = decoder.index("static insn_exec_funct_t dec_custom3")
    end = decoder.index("\n}\n", start) + 3
    decoder_block = decoder[start:end]
    for needle in ("case 0x00: return insn_fadd_ps;", "case 0x08: return insn_fmul_ps;"):
        if needle not in decoder_block:
            raise RuntimeError(f"pinned SysEmu decoder no longer contains the measured mapping: {needle}")
    (OUT / "simulator-decoder.txt").write_text(
        f"ET Platform commit: {commit}\nSource: sw-sysemu/processor.cpp dec_custom3\n\n{decoder_block}")

    add_text, mul_text = (add_root / "text.bin").read_bytes(), (mul_root / "text.bin").read_bytes()
    if len(add_text) != len(mul_text):
        raise RuntimeError("the executable .text sections have different lengths")
    op_index = int(add_layout["operation_pc"], 16) - int(add_layout["text_vma"], 16)
    text_changes = [i for i, (a, b) in enumerate(zip(add_text, mul_text)) if a != b]
    if text_changes != [i for i in range(op_index, op_index + 4) if add_text[i] != mul_text[i]]:
        raise RuntimeError(".text differs outside the four-byte arithmetic operation")
    whole_add, whole_mul = (add_root / "kernel.elf").read_bytes(), (mul_root / "kernel.elf").read_bytes()
    elf_changes = byte_changes(whole_add, whole_mul)
    file_offset = int(add_layout["operation_file_offset"], 16)
    if any(not file_offset <= pos < file_offset + 4 for pos, _, _ in elf_changes):
        raise RuntimeError("whole ELF contains changes outside the operation bytes; see elf-diff.txt")
    (OUT / "elf-diff.txt").write_text(
        f"ADD bytes: {len(whole_add)}\nMUL bytes: {len(whole_mul)}\nChanged byte offsets: {len(elf_changes)}\n" +
        byte_diff_text(elf_changes))

    decoder_args = bits(word_add)
    decoder_mul_args = bits(word_mul)
    patch = bytearray(whole_add)
    old_instruction = bytes(patch[file_offset:file_offset + 4])
    if old_instruction != op_add:
        raise RuntimeError("ELF file offset derived from .text did not contain the ADD instruction")
    patch[file_offset:file_offset + 4] = op_mul
    patched_elf = patched_dir / "kernel.elf"
    patched_elf.write_bytes(patch)
    patched_diff = byte_changes(whole_add, bytes(patch))
    if any(not file_offset <= pos < file_offset + 4 for pos, _, _ in patched_diff):
        raise RuntimeError("the patched ELF differs from ADD outside the one four-byte replacement")
    xor_delta = bytes(a ^ b for a, b in zip(whole_add, patch))
    (OUT / "patch.xor.bin").write_bytes(xor_delta)
    (OUT / "patch.diff.txt").write_text(
        f"ELF virtual operation PC: 0x{int(add_layout['operation_pc'], 16):x}\n"
        f".text file offset: 0x{file_offset:x}\n"
        f"ADD bytes: {op_add.hex(' ')}\nMUL replacement bytes: {op_mul.hex(' ')}\n"
        f"ELF size before/after: {len(whole_add)}/{len(patch)}\n"
        f"Changed byte offsets (expected only within the four-byte instruction): {len(patched_diff)}\n" +
        byte_diff_text(patched_diff))

    capture_names = ("capture_fcsr_after", "seed_load", "capture_f10_after",
                     "capture_f11_after", "capture_f12_after")
    # Add the linker-derived capture PCs needed to normalize the patched run.
    symbols_text = (add_root / "symbols.txt").read_text()
    symbols = add_example.parse_symbols(symbols_text)
    add_layout["capture_pcs"] = {name: f"0x{symbols[name]:x}" for name in capture_names if name in symbols}
    add_layout["seed_load_pc"] = add_layout["capture_pcs"]["seed_load"]
    patched_execution = save_patch_execution(patched_elf, add_layout, mul_result, patched_dir, env)

    # Verify both deterministic cases, and verify the patched ELF matches the
    # independently assembled MUL run without changing any other input byte.
    case_summaries = []
    for case_name in ("primary", "exact"):
        left = json.loads((add_root / ("result.json" if case_name == "primary" else f"{case_name}/result.json")).read_text())
        right = json.loads((mul_root / ("result.json" if case_name == "primary" else f"{case_name}/result.json")).read_text())
        if left["input_a"] != right["input_a"] or left["input_b"] != right["input_b"]:
            raise RuntimeError(f"input data differed between ADD and MUL for {case_name}")
        if not left["pass"] or not right["pass"]:
            raise RuntimeError(f"an example failed its independent Python reference for {case_name}")
        case_summaries.append({"case": case_name, "add": left["actual_output"], "mul": right["actual_output"]})
    add_regs = json.loads((add_root / "registers.json").read_text())
    mul_regs = json.loads((mul_root / "registers.json").read_text())
    for reg in ("f10", "f11"):
        if add_regs[reg] != mul_regs[reg]:
            raise RuntimeError(f"{reg} changed between ADD and MUL")
    if add_regs["f12"]["before"] != mul_regs["f12"]["before"]:
        raise RuntimeError("destination-register initialization changed between ADD and MUL")
    register_diff = ["Register/result comparison from SysEmu traces and snapshots:\n"]
    for name in ("f10", "f11"):
        register_diff.append(f"{name}: before equal={add_regs[name]['before'] == mul_regs[name]['before']}; "
                             f"after equal={add_regs[name]['after'] == mul_regs[name]['after']}\n")
    register_diff.append(f"f12 before equal=True: {add_regs['f12']['before']['f32']}\n")
    register_diff.append(f"f12 after ADD: {add_regs['f12']['after']['f32']}\n")
    register_diff.append(f"f12 after MUL: {mul_regs['f12']['after']['f32']}\n")
    register_diff.append(f"C after ADD: {add_result['actual_output']}\n")
    register_diff.append(f"C after MUL: {mul_result['actual_output']}\n")
    (OUT / "register-result.diff.txt").write_text("".join(register_diff))

    report = {
        "platform_commit": commit, "simulator_decoder": "sw-sysemu/processor.cpp dec_custom3",
        "add": {"pc": add_layout["operation_pc"], "bytes_memory_order": op_add.hex(" "),
                "word": f"0x{word_add:08x}", "fields": decoder_args},
        "mul": {"pc": add_layout["operation_pc"], "bytes_memory_order": op_mul.hex(" "),
                "word": f"0x{word_mul:08x}", "fields": decoder_mul_args},
        "xor": f"0x{word_xor:08x}", "changed_bit_positions_lsb0": changed_bits,
        "changed_encoding_field": "funct7 bits [31:25], selected by the pinned SysEmu custom-3 decoder",
        "elf_operation_file_offset": f"0x{file_offset:x}", "whole_elf_changed_byte_count": len(elf_changes),
        "whole_elf_changed_offsets": [f"0x{p:x}" for p, _, _ in elf_changes],
        "source_diff": "source.diff", "disassembly_diff": "disassembly.diff",
        "elf_diff": "elf-diff.txt", "patch_diff": "patch.diff.txt",
        "patched_elf": "patched/kernel.elf", "patch_xor_binary": "patch.xor.bin",
        "patched_execution": patched_execution,
        "cases": case_summaries,
    }
    (OUT / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print("\n=== kernel.S diff ===")
    print(source_diff or "(no source difference)", end="")
    print("\n=== disassembly diff ===")
    print(disassembly_diff or "(no disassembly difference)", end="")
    print(f"\nADD word 0x{word_add:08x} bytes {op_add.hex(' ')}")
    print(f"MUL word 0x{word_mul:08x} bytes {op_mul.hex(' ')}")
    print(f"XOR 0x{word_xor:08x}; changed bit positions (LSB=0): {changed_bits}")
    print(f"decoder funct7: ADD 0x{fields_add['funct7']:02x}, MUL 0x{fields_mul['funct7']:02x}; all other decoded fields are equal")
    print("registers: f10/f11 are unchanged; f12's simulator-captured value changes as shown in out/compare/register-result.diff.txt")
    print(f"primary results: ADD {add_result['actual_output']}  MUL {mul_result['actual_output']}")
    print(f".text differences are confined to the operation. Whole ELF changed bytes: {len(elf_changes)} at {[hex(p) for p, _, _ in elf_changes]}")
    print(f"patched ELF PC 0x{int(add_layout['operation_pc'], 16):x} maps to file offset 0x{file_offset:x}")
    print(f"patched run decoded {patched_execution['operation']} and produced {patched_execution['output']}")
    print(f"patched ELF PASS; report and binary diffs are in {OUT}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, KeyError, ValueError) as exc:
        print(f"compare.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
