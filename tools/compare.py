#!/usr/bin/env python3
"""Run the ET ISA examples and compare the packed-float operation experiments."""

from __future__ import annotations

import difflib
import json
import os
import re
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
        if elf.resolve() != (directory / "kernel.elf").resolve():
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
    if re.search(r"\b(?:Trap|trap|exception|Exception)\b", trace):
        raise RuntimeError("unexpected trap/exception text appears in the patched-ELF trace")

    symbols = {name: int(value, 16) for name, value in layout["symbols"].items()}
    events, regs = add_example.trace_events(trace)
    op = add_example.event_at(events, op_pc, "fmul.ps")
    file_offset = int(layout["operation_file_offset"], 16)
    expected_word = int.from_bytes(elf.read_bytes()[file_offset:file_offset + 4], "little")
    if op["word"] != expected_word:
        raise RuntimeError("the patched execution word differs from the replacement instruction")
    source_a, source_b = regs[(op_pc, "f10", ":")], regs[(op_pc, "f11", ":")]
    result_f12 = regs[(op_pc, "f12", "=")]
    post: dict[str, tuple[int, ...]] = {}
    output = (directory / "output.bin").read_bytes()
    initial = (directory / "prestart.bin").read_bytes()
    if len(output) != dump_size or len(initial) != dump_size:
        raise RuntimeError("patched-run memory dumps do not cover the complete monitor range")
    start = dump_addr
    for n in (10, 11, 12):
        pc = int(layout["capture_pcs"][f"capture_f{n}_after"], 16)
        add_example.event_at(events, pc, f"fsw.ps f{n},")
        post[f"f{n}"] = regs[(pc, f"f{n}", ":")]
        snap = symbols[f"snapshot_f{n}"] - start
        if post[f"f{n}"] != struct.unpack_from("<8I", output, snap):
            raise RuntimeError(f"patched-run f{n} trace and device snapshot differ")

    def monitor_offset(name: str) -> int:
        return symbols[name] - dump_addr

    initial_c = initial[monitor_offset("result_c"):monitor_offset("result_c") + 32]
    actual = output[monitor_offset("result_c"):monitor_offset("result_c") + 32]
    if source_a != post["f10"] or source_b != post["f11"]:
        raise RuntimeError("the patched operation changed a source register")
    if result_f12 != post["f12"] or actual != struct.pack("<8I", *result_f12):
        raise RuntimeError("patched operation write, snapshot, and output memory disagree")
    complete = struct.unpack_from("<I", output, monitor_offset("completion"))[0]
    trap_marker = struct.unpack_from("<I", output, monitor_offset("trap_marker"))[0]
    trap_cause = struct.unpack_from("<Q", output, monitor_offset("trap_cause"))[0]
    expected = bytes.fromhex(mul_result["actual_output_bytes"].replace(" ", ""))
    if initial_c != bytes([0xA5]) * 32 or actual != expected or complete != add_example.DONE_WORD or trap_marker or trap_cause:
        raise RuntimeError("patched ELF failed its sentinel, output, completion, or trap checks")

    fcsr_after_pc = layout["capture_pcs"]["capture_fcsr_after"]
    fcsr_event = add_example.event_at(events, int(fcsr_after_pc, 16), "csrr")
    mask = op["state"].get("m0::")
    if mask != 0xFF:
        raise RuntimeError("the patched operation did not execute with all eight lanes enabled")
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
    if sys.argv[1:] not in ([], ["--reuse"]):
        raise SystemExit("usage: python3 tools/compare.py [--reuse]")
    reuse = sys.argv[1:] == ["--reuse"]
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "comparison.json").unlink(missing_ok=True)
    patched_dir = OUT / "patched"
    patched_dir.mkdir(parents=True, exist_ok=True)
    commands = OUT / "commands.log"
    commands.write_text("EXAMPLE_EXECUTION_MODE: " +
                       ("reuse saved real execution artifacts; independently audit them; freshly run patched ELF\n" if reuse else
                        "run all examples; independently audit them; freshly run patched ELF\n"))
    for script in (ROOT / "examples" / "add.py", ROOT / "examples" / "mul.py",
                   ROOT / "examples" / "sub.py", ROOT / "examples" / "gemm.py",
                   ROOT / "examples" / "packed_int.py", ROOT / "examples" / "packed_fp.py",
                   ROOT / "examples" / "packed_memory.py", ROOT / "examples" / "packed_atomic.py",
                   ROOT / "examples" / "scalar_memory.py", ROOT / "examples" / "graphics.py",
                   ROOT / "examples" / "trap_stubs.py", ROOT / "examples" / "cache_control.py",
                   ROOT / "examples" / "synchronization.py", ROOT / "examples" / "message_ports.py",
                   ROOT / "examples" / "synchronization_peers.py", ROOT / "examples" / "message_port_privilege.py",
                   ROOT / "examples" / "scalar_fp.py", ROOT / "examples" / "scalar_integer.py"):
        if reuse:
            continue
        # Four peer cases audit every event in roughly 180 MiB of raw traces.
        # Allow their host validation to finish; each SysEmu invocation retains
        # its own 90-second timeout and cycle watchdog.
        driver_timeout = 1200 if script.name == "synchronization_peers.py" else 600
        result = add_example.run_logged(commands, [sys.executable, str(script)], driver_timeout)
        if result.returncode:
            raise RuntimeError(f"run {script.name} failed with exit status {result.returncode}; inspect {commands}")
    gemm_result = json.loads((ROOT / "out" / "gemm" / "result.json").read_text())
    gemm_exact = json.loads((ROOT / "out" / "gemm" / "exact" / "result.json").read_text())
    if any(not result["pass"] or result["fma_count"] != 64 or result["broadcast_count"] != 64
           for result in (gemm_result, gemm_exact)):
        raise RuntimeError("GEMM primary/exact result or its 64 FMA/broadcast trace checks failed")
    packed_int = json.loads((ROOT / "out" / "packed-int" / "result.json").read_text())
    packed_int_exact = json.loads((ROOT / "out" / "packed-int" / "exact" / "result.json").read_text())
    if (not packed_int["pass"] or not packed_int_exact["pass"] or
            packed_int["instruction_count"] != 41 or packed_int_exact["instruction_count"] != 41):
        raise RuntimeError("packed integer primary/exact run or its 41-instruction trace check failed")
    packed_fp = json.loads((ROOT / "out" / "packed-fp" / "result.json").read_text())
    packed_fp_exact = json.loads((ROOT / "out" / "packed-fp" / "exact" / "result.json").read_text())
    if (not packed_fp["pass"] or not packed_fp_exact["pass"] or
            packed_fp["operation_count"] != 38 or packed_fp_exact["operation_count"] != 38):
        raise RuntimeError("packed FP primary/exact run or its 38-operation trace check failed")
    memory_results = [json.loads((ROOT / "out" / "packed-memory" / subdir / "result.json").read_text())
                      for subdir in ("", "exact")]
    atomic_results = [json.loads((ROOT / "out" / "packed-atomic" / subdir / "result.json").read_text())
                      for subdir in ("", "exact", "alias")]
    scalar_results = [json.loads((ROOT / "out" / "scalar-memory" / subdir / "result.json").read_text())
                      for subdir in ("", "exact")]
    graphics_results = [json.loads((ROOT / "out" / "graphics" / subdir / "result.json").read_text())
                        for subdir in ("", "exact")]
    trap_results = [json.loads((ROOT / "out" / "trap-stubs" / subdir / "result.json").read_text())
                    for subdir in ("", "exact")]
    cache_results = [json.loads((ROOT / "out" / "cache-control" / subdir / "result.json").read_text())
                     for subdir in ("", "exact")]
    sync_results = [json.loads((ROOT / "out" / "synchronization" / subdir / "result.json").read_text())
                    for subdir in ("", "exact")]
    port_results = [json.loads((ROOT / "out" / "message-ports" / subdir / "result.json").read_text())
                    for subdir in ("", "exact", "blocking-primary", "blocking-exact", "overflow-primary", "overflow-exact")]
    peer_results = [json.loads((ROOT / "out" / "synchronization-peers" / subdir / "result.json").read_text())
                    for subdir in ("", "exact", "threads-primary", "threads-exact")]
    privilege_results = [json.loads((ROOT / "out/message-port-privilege" / subdir / "result.json").read_text())
                         for subdir in ("", "exact")]
    for result in privilege_results:
        if (not result["pass"] or not result["whole_monitor_matches"] or result["operation_count"] != 92 or
                result["csr_count"] != 12 or result["illegal_trap_count"] != 32 or result["user_ecall_count"] != 12 or
                result["successful_head_count"] != 20):
            raise RuntimeError("message-port real M/U permission checks failed")
    for result in peer_results:
        proof = result["proof"]
        thread_case = result["case"].startswith("threads")
        if (not result["pass"] or not result["whole_monitor_matches"] or result["operation_count"] != (12 if thread_case else 10) or
                result["stage_count"] != (10 if thread_case else 8) or proof["bulk_increment_count"] != 65535 or proof["overflow_error"] != "0x8" or
                proof["destination_written_on_first_attempt"] or proof["wait_cycles"][1] <= proof["wait_cycles"][0] + 1):
            raise RuntimeError("peer synchronization wait/restart/barrier/overflow checks failed")
        if thread_case and (proof["receiver_hart"] != "H1" or proof["sender_hart"] != "H0" or
                not proof["wait_cycles"][0] < proof["wrong_thread_credit_cycle"] < proof["other_credit_cycle"] < proof["matching_credit_cycle"] < proof["wait_cycles"][1]):
            raise RuntimeError("T1 FCC wait and wrong-thread/wrong-counter isolation checks failed")
    for result, count in zip(port_results, (80, 80, 3, 3, 60, 60)):
        if not result["pass"] or not result["whole_monitor_matches"] or result["operation_count"] != count:
            raise RuntimeError("message-port CSR/ESR or memory checks failed")
        if result["case"].startswith("blocking") and (not result["blocking_proof"] or
                result["blocking_proof"]["head_results"] != ["0xffffffffffffffff", "0x0"] or
                result["blocking_proof"]["wait_cycle_gap"] <= 1):
            raise RuntimeError("message-port blocking read/wake/retry checks failed")
        if result["case"].startswith("overflow"):
            proof = result["queue_proof"]
            if len(proof) != 4 or any(row["bulk_send_count"] != 255 or row["capacity"] != 2 or
                    row["overfill_head_results"] != ["0x0", hex(result["message_width"]), "0x0"] or
                    row["probe255_result"] != "0x0" or row["empty_after_wrap"] != "0xffffffffffffffff" or
                    row["tensor_error"] != "0x0" for row in proof):
                raise RuntimeError("message-port overcapacity/count-wrap checks failed")
    for result, count in zip(sync_results, (23, 24)):
        if not result["pass"] or result["operation_count"] != count or result["timer_wait_cycles"] <= 1:
            raise RuntimeError("synchronization CSR/ESR and real timed-wait checks failed")
    for suite, results, count in (("packed memory", memory_results, 33), ("packed atomic", atomic_results, 22),
                                  ("scalar memory", scalar_results, 45), ("graphics", graphics_results, 30),
                                  ("expected traps", trap_results, 9), ("cache control", cache_results, 37)):
        if any(not result["pass"] or result["operation_count"] != count for result in results):
            raise RuntimeError(f"{suite} case validation or per-PC execution checks failed")
    # The raw peer evidence contains about 180 MiB of trace data. This is a
    # host audit deadline; per-device 90-second timeouts remain unchanged.
    inventory_run = add_example.run_logged(commands, [sys.executable, str(ROOT / "tools" / "inventory.py"),
                                                      "--require-complete"], 1200)
    add_example.require(inventory_run, "audit complete nontrapping ET extension coverage")
    inventory = json.loads((ROOT / "out" / "isa" / "instruction-inventory.json").read_text())
    scalar_fp_results = [json.loads((ROOT / "out/scalar-fp" / suffix / "result.json").read_text())
                         for suffix in ("", "exact")]
    if any(not result['pass'] or (result['operation_count'],result['nontrapping_handler_count'],result['trap_stub_count'],result['trap_count']) != (31,22,6,6)
           for result in scalar_fp_results):
        raise RuntimeError('scalar FP primary/exact execution, register or fault checks failed')
    cpu_inventory = json.loads((ROOT / "out/isa/full-cpu-source-inventory.json").read_text())
    evidence_reports = [inventory, *[json.loads((ROOT / "out/isa" / filename).read_text()) for filename in
        ('cache-csr-inventory.json','synchronization-inventory.json','message-port-inventory.json',
         'synchronization-peer-inventory.json','message-port-privilege-inventory.json',
         'scalar-fp-inventory.json','scalar-integer-inventory.json')]]
    example_runs = {run['run'] for evidence in evidence_reports for run in evidence['verified_runs']}
    example_runs.update(run['run'] for rows in inventory['trap_evidence'].values() for run in rows)
    integer_results = [json.loads((ROOT / "out/scalar-integer" / suffix / "result.json").read_text())
                       for suffix in ("", "exact")]
    if any(not result['pass'] or (result['operation_count'],result['handler_count'],result['trap_count']) != (61,43,0)
           for result in integer_results):
        raise RuntimeError('scalar integer primary/exact execution, register or guard checks failed')

    add_root, mul_root, sub_root = (ROOT / "out" / name for name in ("add", "mul", "sub"))
    add_layout = json.loads((add_root / "elf-layout.json").read_text())
    mul_layout = json.loads((mul_root / "elf-layout.json").read_text())
    sub_layout = json.loads((sub_root / "elf-layout.json").read_text())
    add_result = json.loads((add_root / "result.json").read_text())
    mul_result = json.loads((mul_root / "result.json").read_text())
    sub_result = json.loads((sub_root / "result.json").read_text())
    if not all(result["pass"] for result in (add_result, mul_result, sub_result)):
        raise RuntimeError("one or more supported elementwise arithmetic results did not pass")
    if len({layout["operation_pc"] for layout in (add_layout, mul_layout, sub_layout)}) != 1 or \
       len({layout["entry"] for layout in (add_layout, mul_layout, sub_layout)}) != 1:
        raise RuntimeError("ADD, MUL, and SUB linker layouts do not match")

    source_diff = write_diff(OUT / "source.diff", "add/kernel.S", (add_root / "kernel.S").read_text(),
                             "mul/kernel.S", (mul_root / "kernel.S").read_text())
    if (add_root / "kernel.S").read_text().replace("fadd.ps", "<packed-op>") != \
       (mul_root / "kernel.S").read_text().replace("fmul.ps", "<packed-op>"):
        raise RuntimeError("the device source changed beyond the ADD-to-MUL instruction")
    add_source = (add_root / "kernel.S").read_text()
    sub_source = (sub_root / "kernel.S").read_text()
    sub_source_diff = write_diff(OUT / "add-sub.source.diff", "add/kernel.S", add_source,
                                 "sub/kernel.S", sub_source)
    if add_source.replace("fadd.ps", "<packed-op>") != sub_source.replace("fsub.ps", "<packed-op>"):
        raise RuntimeError("the device source changed beyond the ADD-to-SUB instruction")
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
    op_sub = (sub_root / "op.bin").read_bytes()
    if len(op_sub) != 4:
        raise RuntimeError("expected one four-byte SUB instruction")
    word_sub = int.from_bytes(op_sub, "little")
    fields_sub = bits(word_sub)
    if fields_sub["funct7"] != 0x04 or any(fields_add[k] != fields_sub[k]
                                            for k in fields_add if k != "funct7"):
        raise RuntimeError(f"measured SUB fields do not match the pinned decoder: {fields_sub}")
    if (add_layout["operation_file_offset"] != sub_layout["operation_file_offset"] or
            add_layout["text_vma"] != sub_layout["text_vma"]):
        raise RuntimeError("ADD and SUB operation locations do not match")
    sub_disassembly_diff = write_diff(OUT / "add-sub.disassembly.diff", "add/kernel.asm",
                                      (add_root / "kernel.asm").read_text(),
                                      "sub/kernel.asm", (sub_root / "kernel.asm").read_text())
    add_text, sub_text = (root / "text.bin" for root in (add_root, sub_root))
    add_text_bytes, sub_text_bytes = add_text.read_bytes(), sub_text.read_bytes()
    if len(add_text_bytes) != len(sub_text_bytes):
        raise RuntimeError("ADD and SUB executable sections have different lengths")
    op_index_for_sub = int(add_layout["operation_pc"], 16) - int(add_layout["text_vma"], 16)
    sub_changes = [i for i, (a, b) in enumerate(zip(add_text_bytes, sub_text_bytes)) if a != b]
    if sub_changes != [i for i in range(op_index_for_sub, op_index_for_sub + 4)
                       if add_text_bytes[i] != sub_text_bytes[i]]:
        raise RuntimeError("ADD and SUB .text differ outside the arithmetic operation")

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
    for needle in ("case 0x00: return insn_fadd_ps;", "case 0x04: return insn_fsub_ps;",
                   "case 0x08: return insn_fmul_ps;"):
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
    # Executable .text equality is checked above. Whole-ELF metadata may
    # differ independently; report those differences without conflating them
    # with a changed device instruction. The patched copy is checked strictly.
    other_elf_changes = [(pos, before, after) for pos, before, after in elf_changes
                         if not file_offset <= pos < file_offset + 4]
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
        sub = json.loads((sub_root / ("result.json" if case_name == "primary" else f"{case_name}/result.json")).read_text())
        if any(left[key] != right[key] or left[key] != sub[key] for key in ("input_a", "input_b")):
            raise RuntimeError(f"input data differed between ADD/MUL/SUB for {case_name}")
        if not left["pass"] or not right["pass"] or not sub["pass"]:
            raise RuntimeError(f"an example failed its independent Python reference for {case_name}")
        case_summaries.append({"case": case_name, "add": left["actual_output"],
                               "mul": right["actual_output"], "sub": sub["actual_output"]})
    add_regs = json.loads((add_root / "registers.json").read_text())
    mul_regs = json.loads((mul_root / "registers.json").read_text())
    for reg in ("f10", "f11"):
        if add_regs[reg] != mul_regs[reg]:
            raise RuntimeError(f"{reg} changed between ADD and MUL")
    if add_regs["f12"]["before"] != mul_regs["f12"]["before"]:
        raise RuntimeError("destination-register initialization changed between ADD and MUL")
    sub_regs = json.loads((sub_root / "registers.json").read_text())
    register_diff = ["Register/result comparison from SysEmu traces and snapshots:\n"]
    for name in ("f10", "f11"):
        register_diff.append(f"{name}: before equal={add_regs[name]['before'] == mul_regs[name]['before']}; "
                             f"after equal={add_regs[name]['after'] == mul_regs[name]['after']}\n")
    register_diff.append(f"f12 before equal=True: {add_regs['f12']['before']['f32']}\n")
    register_diff.append(f"f12 after ADD: {add_regs['f12']['after']['f32']}\n")
    register_diff.append(f"f12 after MUL: {mul_regs['f12']['after']['f32']}\n")
    register_diff.append(f"f12 after SUB: {sub_regs['f12']['after']['f32']}\n")
    register_diff.append(f"C after ADD: {add_result['actual_output']}\n")
    register_diff.append(f"C after MUL: {mul_result['actual_output']}\n")
    register_diff.append(f"C after SUB: {sub_result['actual_output']}\n")
    (OUT / "register-result.diff.txt").write_text("".join(register_diff))

    elementwise = {
        "scope": "the three operations currently enabled by the pinned ggml-et el_map_f32.c reference",
        "decoder": "ET Platform dec_custom3; fadd/fsub/fmul selected by funct7",
        "operations": [
            {"name": "fadd.ps", "word": f"0x{word_add:08x}", "bytes": op_add.hex(" "),
             "funct7": fields_add["funct7"], "result": add_result["actual_output"]},
            {"name": "fsub.ps", "word": f"0x{word_sub:08x}", "bytes": op_sub.hex(" "),
             "funct7": fields_sub["funct7"], "result": sub_result["actual_output"]},
            {"name": "fmul.ps", "word": f"0x{word_mul:08x}", "bytes": op_mul.hex(" "),
             "funct7": fields_mul["funct7"], "result": mul_result["actual_output"]},
        ],
        "add_sub_source_diff": "add-sub.source.diff",
        "add_sub_disassembly_diff": "add-sub.disassembly.diff",
    }
    (OUT / "elementwise-operations.json").write_text(json.dumps(elementwise, indent=2) + "\n")

    report = {
        "example_execution_mode": "saved real execution artifacts" if reuse else "fresh example executions",
        "example_artifact_count": len(example_runs), "example_runs": sorted(example_runs),
        "fresh_device_execution_count": 1 if reuse else len(example_runs) + 1,
        "platform_commit": commit, "simulator_decoder": "sw-sysemu/processor.cpp dec_custom3",
        "add": {"pc": add_layout["operation_pc"], "bytes_memory_order": op_add.hex(" "),
                "word": f"0x{word_add:08x}", "fields": decoder_args},
        "mul": {"pc": add_layout["operation_pc"], "bytes_memory_order": op_mul.hex(" "),
                "word": f"0x{word_mul:08x}", "fields": decoder_mul_args},
        "xor": f"0x{word_xor:08x}", "changed_bit_positions_lsb0": changed_bits,
        "changed_encoding_field": "funct7 bits [31:25], selected by the pinned SysEmu custom-3 decoder",
        "elf_operation_file_offset": f"0x{file_offset:x}", "whole_elf_changed_byte_count": len(elf_changes),
        "whole_elf_changed_offsets": [f"0x{p:x}" for p, _, _ in elf_changes],
        "whole_elf_changes_outside_operation": [f"0x{p:x}" for p, _, _ in other_elf_changes],
        "source_diff": "source.diff", "disassembly_diff": "disassembly.diff",
        "elf_diff": "elf-diff.txt", "patch_diff": "patch.diff.txt",
        "patched_elf": "patched/kernel.elf", "patch_xor_binary": "patch.xor.bin",
        "patched_execution": patched_execution,
        "cases": case_summaries,
        "elementwise_operations": elementwise,
        "gemm": {"shape": gemm_result["shape"], "device_instruction": gemm_result["device_instruction"],
                 "fma_count": gemm_result["fma_count"], "primary_pass": gemm_result["pass"],
                 "broadcast_count": gemm_result["broadcast_count"],
                 "exact_pass": gemm_exact["pass"], "output": gemm_result["output_actual"]},
        "packed_integer": {"instruction_count": packed_int["instruction_count"],
                           "primary_pass": packed_int["pass"], "exact_pass": packed_int_exact["pass"],
                           "primary_masks": packed_int["mask_results"],
                           "exact_masks": packed_int_exact["mask_results"]},
        "packed_float": {"instruction_count": packed_fp["operation_count"],
                         "primary_pass": packed_fp["pass"], "exact_pass": packed_fp_exact["pass"],
                         "operations": [row["name"] for row in packed_fp["output_actual"]]},
        "scalar_float": {"instruction_count": 31, "implemented_handler_count": 22, "fault_stub_count": 6,
                         "cases": {result['case']: result['pass'] for result in scalar_fp_results}},
        "scalar_integer": {"instruction_count": 61, "handler_count": 43,
                           "cases": {result['case']: result['pass'] for result in integer_results}},
        "cpu_handler_coverage": {key: cpu_inventory[key] for key in
            ('decoded_handler_count','verified_dedicated_handler_count','remaining_dedicated_handler_count',
             'remaining_other_handler_count','remaining_explicit_mcode_stub_count')},
        "packed_memory": {"instruction_count": 33,
                          "cases": {result["case"]: result["pass"] for result in memory_results}},
        "packed_atomic": {"instruction_count": 22,
                          "cases": {result["case"]: result["pass"] for result in atomic_results}},
        "scalar_memory": {"instruction_count": 45,
                          "cases": {result["case"]: result["pass"] for result in scalar_results}},
        "graphics": {"instruction_count": 30,
                     "cases": {result["case"]: result["pass"] for result in graphics_results}},
        "expected_traps": {"instruction_count": 9,
                           "cases": {result["case"]: result["pass"] for result in trap_results}},
        "cache_control": {"instruction_count": 37, "csr_count": 13,
                          "cases": {result["case"]: result["pass"] for result in cache_results},
                          "scope": "separate CSR commands; mode/readback, actual cache-line accesses and intentional error feedback"},
        "synchronization": {"csr_count": 5, "cases": {result["case"]: {
            "pass": result["pass"], "instruction_count": result["operation_count"],
            "timer_wait_cycles": result["timer_wait_cycles"]} for result in sync_results},
            "scope": "separate CSR/ESR commands; barriers, self-supplied credits and actual STALL wait/wake"},
        "message_ports": {"csr_count": 12, "cases": {result["case"]: {
            "pass": result["pass"], "instruction_count": result["operation_count"],
            "message_width": result["message_width"], "blocking_proof": result["blocking_proof"],
            "queue_proof": result["queue_proof"]} for result in port_results},
            "scope": "four-port 4/8-byte FIFO/wrap/reset/drop, H2 -> H0 blocking, overcapacity overwrite and uint8 count wrap"},
        "synchronization_peers": {"cases": {result["case"]: {
            "pass": result["pass"], "instruction_count": result["operation_count"], "proof": result["proof"]} for result in peer_results},
            "credit_esr_routes": sorted({result["proof"]["credit_esr"] for result in peer_results}),
            "scope": "T0/T1 FCC0/FCC1 routing, zero-credit wait/restart, wrong-thread/wrong-counter isolation, real overflow and ordered FLB"},
        "message_port_privilege": {"csr_count": 12, "cases": {result["case"]: {
            "pass": result["pass"], "instruction_count": result["operation_count"], "message_width": result["message_width"],
            "illegal_trap_count": result["illegal_trap_count"], "user_ecall_count": result["user_ecall_count"],
            "successful_head_count": result["successful_head_count"]} for result in privilege_results},
            "scope": "real M/U execution; denied reads retain messages, enabled U reads, disabled-port and U control faults"},
        "extension_coverage": {"handler_count": inventory["unique_handler_count"],
                               "verified_nontrapping_handlers": inventory["verified_execution_handler_count"],
                               "unimplemented_trap_stubs": inventory["trap_stub_mnemonics"],
                               "verified_trap_stubs": inventory["verified_trap_stub_count"],
                               "unverified_nontrapping_handlers": inventory["unverified_nontrapping_handlers"],
                               "runs_missing_evidence": inventory["runs_missing_evidence"]},
    }
    (OUT / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Comparison mode: " + ("independently audited saved example executions + one fresh patched-ELF run" if reuse else
                                 "fresh example executions + fresh patched-ELF run"))
    print("\n=== kernel.S diff ===")
    print(source_diff or "(no source difference)", end="")
    print("\n=== disassembly diff ===")
    print(disassembly_diff or "(no disassembly difference)", end="")
    print(f"\nADD word 0x{word_add:08x} bytes {op_add.hex(' ')}")
    print(f"MUL word 0x{word_mul:08x} bytes {op_mul.hex(' ')}")
    print(f"SUB word 0x{word_sub:08x} bytes {op_sub.hex(' ')}")
    print(f"XOR 0x{word_xor:08x}; changed bit positions (LSB=0): {changed_bits}")
    print(f"decoder funct7: ADD 0x{fields_add['funct7']:02x}, MUL 0x{fields_mul['funct7']:02x}; all other decoded fields are equal")
    print("registers: f10/f11 are unchanged; f12's simulator-captured value changes as shown in out/compare/register-result.diff.txt")
    print(f"primary results: ADD {add_result['actual_output']}  MUL {mul_result['actual_output']}  SUB {sub_result['actual_output']}")
    print(f"ADD/SUB source and disassembly diffs are in add-sub.source.diff and add-sub.disassembly.diff")
    print(f"GEMM {gemm_result['shape']} via {gemm_result['fma_count']} {gemm_result['device_instruction']} instructions: PASS")
    print(f"packed integer: {packed_int['instruction_count']} ops in primary/exact cases: PASS")
    print(f"packed floating-point: {packed_fp['operation_count']} sites in primary/exact cases: PASS")
    print('scalar floating-point: 31 sites per case, 22 implemented handlers and 6 cause-30 stubs: PASS')
    print('scalar integer: 61 sites per case, 43 handlers with zero-divisor/overflow/overshift cases: PASS')
    print("packed memory: 33 sites in primary/exact cases: PASS")
    print("packed atomic: 22 sites in primary/exact/alias cases: PASS")
    print("scalar memory: 45 sites in primary/exact cases: PASS")
    print("cache control: 37 sites across 13 CSRs in primary/exact cases: PASS")
    print("synchronization: 23/24 sites across 5 CSRs and actual timed STALL wait/wake: PASS")
    print("message ports: 80 sites across 12 CSRs per FIFO case; both blocking cases and both 60-site overcapacity/count-wrap cases: PASS")
    print("message-port privilege: both 92-site real M/U cases, 32 illegal faults and 12 U ECALL exits per case: PASS")
    print("peer synchronization: all four T0/T1 FCC routes, block/restart, wrong-thread/wrong-counter isolation, real 16-bit overflow and ordered FLB: PASS")
    print("graphics: 30 sites in primary/exact cases: PASS")
    print("expected traps: 8 cause-30 arithmetic stubs and disabled-graphics cause-2 fault: PASS")
    print(f"ET extension handlers with verified execution: {inventory['verified_execution_handler_count']}; "
          f"nontrapping gaps: {len(inventory['unverified_nontrapping_handlers'])}")
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
