#!/usr/bin/env python3
"""Run a small 8x8x8 FP32 GEMM using ET minion packed-FP instructions."""

from __future__ import annotations

import json
import math
import os
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out" / "gemm"
N = 8
HOST_TIMEOUT = 120
SIM_TIMEOUT = 90
SIM_CYCLES = 10_000
DONE_WORD = 0x4B4F5445
SENTINEL = 0xA5A5A5A5


def matrices(case: str) -> tuple[list[list[float]], list[list[float]]]:
    if case == "primary":
        return (
            [[float(row * N + k + 1) for k in range(N)] for row in range(N)],
            [[float((k + 1) * (col + 1)) for col in range(N)] for k in range(N)],
        )
    if case == "exact":
        return (
            [[(row - 3) * (k + 1) / 4.0 for k in range(N)] for row in range(N)],
            [[(k + 1) * (col - 2) / 8.0 for col in range(N)] for k in range(N)],
        )
    raise SystemExit("usage: python3 examples/gemm.py [primary|exact ...]")


def f32(value: float) -> str:
    return format(value, ".9g")


def packed(values: list[float]) -> bytes:
    return struct.pack(f"<{len(values)}f", *values)


def assembly(a: list[list[float]], b: list[list[float]]) -> str:
    # A and B are row-major. Device fbc.ps broadcasts A[r,k] to all eight
    # lanes; one packed FMA updates C[r,0:8] for each reduction index k.
    a_lanes = [a[row][k] for row in range(N) for k in range(N)]
    b_lanes = [b[k][col] for k in range(N) for col in range(N)]
    lines = [
        "# SPDX-License-Identifier: Apache-2.0",
        "# Startup provenance: Copyright (c) 2025 Ainekko, Co.; ET Platform boot.S.",
        "# Bare-metal startup follows the minimal ET-SOC1 conventions documented in README.md.",
        ".option push", ".option norelax", ".option norvc",
        '.section .text.entry,"ax",@progbits', ".globl _start", "_start:",
        "    csrwi satp, 0", "    csrr t0, mstatus", "    li t1, 0x6000",
        "    or t0, t0, t1", "    csrw mstatus, t0", "    csrwi fcsr, 0",
        "    csrwi mip, 0", "    csrwi tensor_mask, 0", "    la sp, __stack_top",
        "    la t0, trap_handler", "    csrw mtvec, t0", "    li t0, 255", "    mova.m.x t0",
        "    la t1, matrix_a", "    la t2, matrix_b", "    la t3, result_c",
        "    la t4, zero_vector",
    ]
    for row in range(N):
        lines.append("    flw.ps f12, 0(t4)")
        for k in range(N):
            a_offset = (row * N + k) * 4
            b_offset = k * N * 4
            lines.extend((f".globl gemm_broadcast_{row}_{k}", f"gemm_broadcast_{row}_{k}:",
                          f"    fbc.ps f10, {a_offset}(t1)",
                          f"    flw.ps f11, {b_offset}(t2)"))
            if row == N - 1 and k == N - 1:
                lines.extend((".globl gemm_mstatus_before", "gemm_mstatus_before:",
                              "    csrr t0, mstatus", ".globl gemm_fcsr_before", "gemm_fcsr_before:",
                              "    csrr t0, fcsr"))
            lines.extend((f".globl gemm_fma_{row}_{k}", f"gemm_fma_{row}_{k}:",
                          "    fmadd.ps f12, f10, f11, f12, rne"))
            if row == N - 1 and k == N - 1:
                lines.extend((".globl gemm_fcsr_after", "gemm_fcsr_after:", "    csrr t0, fcsr",
                              ".globl gemm_mstatus_after", "gemm_mstatus_after:", "    csrr t0, mstatus",
                              "    la t5, snapshot_f10", ".globl capture_snapshot_f10",
                              "capture_snapshot_f10:", "    fsw.ps f10, 0(t5)",
                              "    la t5, snapshot_f11", ".globl capture_snapshot_f11",
                              "capture_snapshot_f11:", "    fsw.ps f11, 0(t5)",
                              "    la t5, snapshot_f12", ".globl capture_snapshot_f12",
                              "capture_snapshot_f12:", "    fsw.ps f12, 0(t5)"))
        lines.append(f"    fsw.ps f12, {row * N * 4}(t3)")
    lines.extend((
        "    li t0, 0x4b4f5445", "    la t1, completion", "    sw t0, 0(t1)",
        ".globl park", "park:", "    wfi", "    j park", ".balign 4096", "trap_handler:",
        "    csrr t0, mcause", "    la t1, trap_cause", "    sd t0, 0(t1)",
        "    li t0, 1", "    la t1, trap_marker", "    sw t0, 0(t1)", "    j park",
        ".option pop", '.section .data,"aw",@progbits', ".balign 32",
        ".globl __monitor_start", "__monitor_start:", "matrix_a:",
    ))
    lines.extend(f"    .float {f32(value)}" for value in a_lanes)
    lines.extend(("matrix_b:",))
    lines.extend(f"    .float {f32(value)}" for value in b_lanes)
    lines.extend(("zero_vector:", "    .rept 8", "    .float 0.0", "    .endr",
                  ".balign 32",
                  ".globl result_c", "result_c:", ".rept 64", f"    .word 0x{SENTINEL:08x}",
                  ".endr", ".globl completion", "completion:", "    .word 0",
                  ".globl trap_marker", "trap_marker:", "    .word 0",
                  ".globl trap_cause", "trap_cause:", "    .dword 0",
                  ".balign 32", ".globl snapshot_f10", "snapshot_f10:", "    .zero 32",
                  ".globl snapshot_f11", "snapshot_f11:", "    .zero 32",
                  ".globl snapshot_f12", "snapshot_f12:", "    .zero 32",
                  ".globl __monitor_end", "__monitor_end:"))
    return "\n".join(lines) + "\n"


LINKER = """/* SPDX-License-Identifier: Apache-2.0 */
OUTPUT_ARCH("riscv")
ENTRY(_start)
SECTIONS {
  .text 0x8000001000 : { KEEP(*(.text.entry)) *(.text .text.*) }
  .data 0x8000100000 : { *(.data .data.*) }
  .stack 0x8000200000 (NOLOAD) : { __stack_bottom = .; . += 0x4000; __stack_top = .; }
}
"""


def runtime() -> dict[str, str]:
    record = ROOT / "out" / "setup" / "environment.json"
    if not record.is_file():
        raise RuntimeError("run ./setup.sh first so the checked ET tool paths are recorded")
    env = json.loads(record.read_text())
    prefix = os.environ.get("ET_CONTAINER_PREFIX", os.environ.get("ET_PREFIX", env["prefix"]))
    env["container"] = os.environ.get("ET_CONTAINER", env.get("container", ""))
    for stem in ("riscv64-unknown-elf-", "riscv-unknown-elf-"):
        if env["kind"] == "host":
            base = Path(os.environ.get("ET_PREFIX", prefix)) / "bin"
            if (base / "sys_emu").is_file() and (base / (stem + "as")).is_file():
                env.update(tool_prefix=str(base / stem), simulator=str(base / "sys_emu"))
                return env
        elif env["kind"] == "podman" and shutil.which("podman"):
            base = f"{prefix}/bin/"
            probe = subprocess.run([shutil.which("podman"), "exec", env["container"],
                                    "test", "-x", base + stem + "as"], capture_output=True)
            sim = subprocess.run([shutil.which("podman"), "exec", env["container"],
                                  "test", "-x", base + "sys_emu"], capture_output=True)
            if probe.returncode == sim.returncode == 0:
                env.update(prefix=prefix, tool_prefix=base + stem, simulator=base + "sys_emu")
                return env
    raise RuntimeError("recorded ET toolchain/SysEmu is no longer available; rerun ./setup.sh")


def command(env: dict[str, str], argv: list[str]) -> list[str]:
    if env["kind"] == "podman":
        return [shutil.which("podman") or "podman", "exec", env["container"], *argv]
    return argv


def logged(path: Path, argv: list[str], timeout: int = HOST_TIMEOUT) -> subprocess.CompletedProcess[str]:
    with path.open("a") as log:
        log.write(f"COMMAND: {shlex.join(argv)}\n")
        log.flush()
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                               start_new_session=True)
    try:
        output, _ = process.communicate(timeout=timeout)
        status = process.returncode
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            output, _ = process.communicate()
        output, status = output + "\nHOST_TIMEOUT_EXPIRED\n", 124
    with path.open("a") as log:
        log.write(output or "")
        log.write(f"EXIT_STATUS: {status}\n\n")
    result = subprocess.CompletedProcess(argv, status, output, "")
    if status:
        raise RuntimeError(f"command failed ({status}); inspect {path}\n" + "\n".join((output or "").splitlines()[-40:]))
    return result


def symbols(text: str) -> dict[str, int]:
    found = {}
    for line in text.splitlines():
        match = re.match(r"^([0-9a-fA-F]+)\s+\S\s+(\S+)$", line.strip())
        if match:
            found[match.group(2)] = int(match.group(1), 16)
    return found


def trace_data(text: str):
    insn_re = re.compile(r"^(\d+): DEBUG EMU: \[(H\d+ S\d+:N\d+:C\d+:T\d+)\] I\(M\): "
                         r"0x([0-9a-fA-F]+) \(0x([0-9a-fA-F]{8})\) (.*)$")
    freg_re = re.compile(r"\bf(\d+) ([=:]) \{([^}]*)\}")
    xreg_re = re.compile(r"\bx(\d+) ([=:]) 0x([0-9a-fA-F]+)")
    csr_re = re.compile(r"\b(mstatus|fcsr) ([=:]) 0x([0-9a-fA-F]+)")
    mreg_re = re.compile(r"\bm(\d+) ([=:]) 0x([0-9a-fA-F]+)")
    events, regs = [], {}
    current = None
    for line in text.splitlines():
        match = insn_re.match(line)
        if match:
            current = {"cycle": int(match.group(1)), "hart": match.group(2),
                       "pc": int(match.group(3), 16), "word": int(match.group(4), 16),
                       "disassembly": match.group(5), "registers": {}, "state": {}}
            events.append(current)
            continue
        if current is None:
            continue
        freg = freg_re.search(line)
        if freg:
            lanes = tuple(int(word, 16) for word in re.findall(r"\d+:0x([0-9a-fA-F]{8})", freg.group(3)))
            if len(lanes) == 8:
                regs[(current["pc"], f"f{freg.group(1)}", freg.group(2))] = lanes
                current["registers"][f"f{freg.group(1)}:{freg.group(2)}"] = lanes
        xreg = xreg_re.search(line)
        if xreg:
            value = int(xreg.group(3), 16)
            regs[(current["pc"], f"x{xreg.group(1)}", xreg.group(2))] = value
            current["registers"][f"x{xreg.group(1)}:{xreg.group(2)}"] = value
        csr = csr_re.search(line)
        if csr:
            current["state"][csr.group(1)] = int(csr.group(3), 16)
        mreg = mreg_re.search(line)
        if mreg:
            current["state"][f"m{mreg.group(1)}:{mreg.group(2)}"] = int(mreg.group(3), 16)
    return events, regs


def report_lanes(words: tuple[int, ...]) -> dict[str, object]:
    values = struct.unpack("<8f", struct.pack("<8I", *words))
    # Keep JSON interoperable even when integer/compare bits decode as NaNs.
    decoded = [x if math.isfinite(x) else "nan" if math.isnan(x) else
               "+inf" if x > 0 else "-inf" for x in values]
    return {"raw_u32": [f"0x{x:08x}" for x in words],
            "f32": decoded}


def main() -> int:
    from add import event_at, run_logged
    from packed_memory import memory_events

    cases = sys.argv[1:] or ["primary", "exact"]
    if any(case not in ("primary", "exact") for case in cases):
        raise SystemExit("usage: python3 examples/gemm.py [primary|exact ...]")
    env = runtime()
    all_passed = True
    for case in cases:
        out = OUT if case == "primary" else OUT / case
        out.mkdir(parents=True, exist_ok=True)
        (out / "commands.log").write_text("")
        for name in ("result.json", "registers.json", "output.bin", "prestart.bin", "trace.log"):
            (out / name).unlink(missing_ok=True)
        a, b = matrices(case)
        (out / "kernel.S").write_text(assembly(a, b))
        (out / "link.ld").write_text(LINKER)
        run_id = uuid.uuid4().hex[:10]
        stage = f"/tmp/etsoc1-gemm-{run_id}"
        containerized = env["kind"] == "podman"
        if containerized:
            podman = shutil.which("podman") or "podman"
            logged(out / "commands.log", [podman, "exec", env["container"], "mkdir", "-p", stage])
            for name in ("kernel.S", "link.ld"):
                logged(out / "commands.log", [podman, "cp", str(out / name), f"{env['container']}:{stage}/{name}"])
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
                 f"{tp}objdump -h kernel.elf > sections.txt; "
                 f"{tp}readelf -h -l -S kernel.elf > elf-inspection.txt; "
                 f"{tp}nm -n --defined-only kernel.elf > symbols.txt; "
                 f"{tp}objcopy -O binary --only-section=.text kernel.elf text.bin")
        logged(out / "commands.log", [*shell, build])
        if containerized:
            logged(out / "commands.log", [shutil.which("podman") or "podman", "cp",
                                           f"{env['container']}:{stage}/.", str(out)])

        syms = symbols((out / "symbols.txt").read_text())
        required = ["_start", "park", "matrix_a", "matrix_b", "result_c", "completion",
                    "trap_marker", "trap_cause", "__monitor_start", "__monitor_end",
                    "snapshot_f10", "snapshot_f11", "snapshot_f12", "gemm_mstatus_before",
                    "gemm_fcsr_before", "gemm_fcsr_after", "gemm_mstatus_after",
                    "capture_snapshot_f10", "capture_snapshot_f11", "capture_snapshot_f12"]
        required += [f"gemm_fma_{r}_{k}" for r in range(N) for k in range(N)]
        required += [f"gemm_broadcast_{r}_{k}" for r in range(N) for k in range(N)]
        if any(name not in syms for name in required):
            raise RuntimeError("linked ELF is missing expected GEMM symbols")
        elf_text = (out / "elf-inspection.txt").read_text()
        entry_match = re.search(r"Entry point address:\s+0x([0-9a-fA-F]+)", elf_text)
        section = re.search(r"^\s*\[\s*\d+\]\s+\.text\s+\S+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)",
                            elf_text, re.MULTILINE)
        if not entry_match or not section:
            raise RuntimeError("could not map ELF entry and .text section")
        entry = int(entry_match.group(1), 16)
        text_vma, text_offset, text_size = (int(section.group(i), 16) for i in (1, 2, 3))
        text = (out / "text.bin").read_bytes()
        operation_rows = []
        disassembly = (out / "kernel.asm").read_text()
        for row in range(N):
            for k in range(N):
                pc = syms[f"gemm_fma_{row}_{k}"]
                code = text[pc - text_vma:pc - text_vma + 4]
                decoded = [line.strip() for line in disassembly.splitlines()
                           if re.search(rf"\b{pc:x}:\s", line)]
                if len(code) != 4 or len(decoded) != 1 or "fmadd.ps" not in decoded[0]:
                    raise RuntimeError(f"ET tools did not assemble/decode expected FMA at 0x{pc:x}")
                operation_rows.append({"row": row, "k": k, "pc": f"0x{pc:x}",
                                       "bytes_memory_order": code.hex(" "),
                                       "word": f"0x{int.from_bytes(code, 'little'):08x}",
                                       "decoded": decoded[0]})
        if len({item["pc"] for item in operation_rows}) != N * N:
            raise RuntimeError("GEMM FMA symbols overlap or repeat")
        (out / "operations.bin").write_bytes(b"".join(bytes.fromhex(x["bytes_memory_order"]) for x in operation_rows))
        selected = operation_rows[-1]
        (out / "op.bin").write_bytes(bytes.fromhex(selected["bytes_memory_order"]))
        (out / "operations.json").write_text(json.dumps(operation_rows, indent=2) + "\n")
        broadcast_rows = []
        for row in range(N):
            for k in range(N):
                pc = syms[f"gemm_broadcast_{row}_{k}"]
                raw = text[pc - text_vma:pc - text_vma + 4]
                decoded = [line.strip() for line in disassembly.splitlines()
                           if re.search(rf"\b{pc:x}:\s", line)]
                if len(raw) != 4 or len(decoded) != 1 or "fbc.ps" not in decoded[0]:
                    raise RuntimeError(f"wrong assembled scalar broadcast at 0x{pc:x}")
                broadcast_rows.append({"row": row, "k": k, "pc": f"0x{pc:x}", "mnemonic": "fbc.ps",
                                       "word": f"0x{int.from_bytes(raw, 'little'):08x}",
                                       "bytes_memory_order": raw.hex(" "), "decoded": decoded[0],
                                       "source_address": f"0x{syms['matrix_a'] + (row * N + k) * 4:x}"})
        (out / "broadcasts.json").write_text(json.dumps(broadcast_rows, indent=2) + "\n")
        (out / "broadcasts.bin").write_bytes(b"".join(bytes.fromhex(x["bytes_memory_order"]) for x in broadcast_rows))
        dump_addr = syms["__monitor_start"]
        dump_size = syms["__monitor_end"] - dump_addr
        op_file_offset = text_offset + int(selected["pc"], 16) - text_vma
        (out / "elf-layout.json").write_text(json.dumps({
            "entry": f"0x{entry:x}", "selected_hart": "H0 S0:N0:C0:T0",
            "text_vma": f"0x{text_vma:x}", "text_file_offset": f"0x{text_offset:x}",
            "text_size": text_size, "operation": selected,
            "operation_file_offset": f"0x{op_file_offset:x}",
            "executable_sections": [".text"], "data_sections": [".data"],
            "monitor_address": f"0x{dump_addr:x}", "monitor_size": dump_size,
            "input_layout": "row-major A and B; device fbc.ps broadcasts A scalars",
            "input_a_address": f"0x{syms['matrix_a']:x}", "input_b_address": f"0x{syms['matrix_b']:x}",
        }, indent=2) + "\n")

        sim = [env["simulator"], "-l", "-lm", "0", "-lt", "0", "-sp_dis",
               "-reset_pc", hex(entry), "-single_thread", "-minions", "0x1", "-shires", "0x1",
               "-max_cycles", str(SIM_CYCLES), "-elf_load", f"{work}/kernel.elf",
               "-dump_at_pc_pc", hex(entry), "-dump_at_pc_addr", hex(dump_addr),
               "-dump_at_pc_size", hex(dump_size), "-dump_at_pc_file", f"{work}/prestart.bin",
               "-dump_addr", hex(dump_addr), "-dump_size", str(dump_size), "-dump_file", f"{work}/output.bin"]
        timed = command(env, ["timeout", "--signal=TERM", "--kill-after=5s", f"{SIM_TIMEOUT}s", *sim])
        run = run_logged(out / "commands.log", timed)
        trace = run.stdout or ""
        (out / "trace.log").write_text(trace)
        if containerized:
            logged(out / "commands.log", [shutil.which("podman") or "podman", "cp",
                                           f"{env['container']}:{stage}/.", str(out)])
            logged(out / "commands.log", [shutil.which("podman") or "podman", "exec",
                                           env["container"], "rm", "-rf", stage])
        if (run.returncode or "Finishing emulation" not in trace or "Error, max cycles reached" in trace or
                re.search(r"\b(?:trap|exception)\b", trace, re.I)):
            raise RuntimeError(f"SysEmu did not finish normally; see {out}/trace.log")
        events, regs = trace_data(trace)
        event_at(events, syms["park"], "wfi")
        memory_accesses = memory_events(trace)
        fma_events = [event for event in events if str(event["disassembly"]).startswith("fmadd.ps")]
        if [event["pc"] for event in fma_events] != [int(item["pc"], 16) for item in operation_rows]:
            raise RuntimeError(f"SysEmu executed {len(fma_events)} packed FMAs; expected exactly 64")
        for event, instruction in zip(fma_events, operation_rows):
            if (event["hart"] != "H0 S0:N0:C0:T0" or event["state"].get("m0::") != 0xFF or
                    event["word"] != int(instruction["word"], 16)):
                raise RuntimeError(f"wrong hart, lane mask, or instruction word at GEMM PC {instruction['pc']}")
        fma_registers, broadcast_registers = [], []
        accumulators = [[0.0] * N for _ in range(N)]
        for event, instruction, broadcast in zip(fma_events, operation_rows, broadcast_rows):
            row, k, pc = instruction["row"], instruction["k"], event["pc"]
            expected_a = struct.unpack("<I", packed([a[row][k]]))[0]
            expected_b = struct.unpack("<8I", packed(b[k]))
            broadcast_pc = int(broadcast["pc"], 16)
            load = event_at(events, broadcast_pc, "fbc.ps")
            if load["word"] != int(broadcast["word"], 16) or load["state"].get("m0::") != 0xFF:
                raise RuntimeError(f"incorrect executed broadcast word or mask at {broadcast['pc']}")
            if memory_accesses.get(broadcast_pc) != [{"bits": 32, "address": broadcast["source_address"],
                                                     "direction": "read", "value": f"0x{expected_a:x}"}]:
                raise RuntimeError(f"broadcast did not read the actual A scalar at {broadcast['pc']}")
            actual_a = regs[(broadcast_pc, "f10", "=")]
            before_acc = struct.unpack("<8I", packed(accumulators[row]))
            accumulators[row] = [x + a[row][k] * y for x, y in zip(accumulators[row], b[k])]
            after_acc = struct.unpack("<8I", packed(accumulators[row]))
            if (actual_a != (expected_a,) * N or regs[(pc, "f10", ":")] != actual_a or
                    regs[(pc, "f11", ":")] != expected_b or regs[(pc, "f12", ":")] != before_acc or
                    regs[(pc, "f12", "=")] != after_acc):
                raise RuntimeError(f"actual broadcast/FMA state differs from the reference at {instruction['pc']}")
            broadcast_registers.append({**broadcast, "hart": load["hart"], "cycle": load["cycle"],
                                        "f10_after": report_lanes(actual_a), "memory_accesses": memory_accesses[broadcast_pc]})
            fma_registers.append({**instruction, "hart": event["hart"], "cycle": event["cycle"],
                                  "f10_before": report_lanes(regs[(pc, "f10", ":")]),
                                  "f11_before": report_lanes(regs[(pc, "f11", ":")]),
                                  "f12_before": report_lanes(regs[(pc, "f12", ":")]),
                                  "f12_after": report_lanes(regs[(pc, "f12", "=")])})
        selected_event = fma_events[-1]
        mask = selected_event["state"].get("m0::")
        if selected_event["hart"] != "H0 S0:N0:C0:T0" or mask != 0xFF:
            raise RuntimeError("selected GEMM FMA did not execute on the configured full-mask minion")
        if not (out / "output.bin").is_file() or (out / "output.bin").stat().st_size != dump_size:
            raise RuntimeError("SysEmu did not save the complete output memory range")
        before = (out / "prestart.bin").read_bytes()
        memory = (out / "output.bin").read_bytes()
        relative = lambda name: syms[name] - dump_addr
        for label, values in (("matrix_a", [x for row in a for x in row]), ("matrix_b", [x for row in b for x in row])):
            offset, raw_input = relative(label), packed(values)
            if before[offset:offset + len(raw_input)] != raw_input or memory[offset:offset + len(raw_input)] != raw_input:
                raise RuntimeError(f"GEMM input memory is missing, incorrect or changed: {label}")
        c_offset = relative("result_c")
        if struct.unpack_from("<64I", before, c_offset) != (SENTINEL,) * 64:
            raise RuntimeError("output memory did not contain all 64 sentinel values before execution")
        actual_bytes = memory[c_offset:c_offset + 64 * 4]
        actual = struct.unpack("<64f", actual_bytes)
        expected_matrix = [[sum(a[row][k] * b[k][col] for k in range(N)) for col in range(N)]
                            for row in range(N)]
        expected = tuple(value for row in expected_matrix for value in row)
        complete = struct.unpack_from("<I", memory, relative("completion"))[0]
        trap_marker = struct.unpack_from("<I", memory, relative("trap_marker"))[0]
        trap_cause = struct.unpack_from("<Q", memory, relative("trap_cause"))[0]
        passed = actual_bytes == packed(list(expected)) and complete == DONE_WORD and not trap_marker and not trap_cause
        if not passed:
            raise RuntimeError(f"GEMM result/check marker failed; inspect {out}/trace.log and result.json")
        for reg in ("f10", "f11", "f12"):
            post_pc = syms[f"capture_snapshot_{reg}"]
            event = next(e for e in events if e["pc"] == post_pc and str(e["disassembly"]).startswith("fsw.ps"))
            captured = regs[(post_pc, reg, ":")]
            if captured != struct.unpack_from("<8I", memory, relative(f"snapshot_{reg}")):
                raise RuntimeError(f"trace and device-side snapshot disagree for {reg}")
        op_pc = int(selected["pc"], 16)
        state_events = {}
        for name in ("gemm_mstatus_before", "gemm_fcsr_before", "gemm_fcsr_after", "gemm_mstatus_after"):
            event = next(e for e in events if e["pc"] == syms[name])
            csr_name = "mstatus" if "mstatus" in name else "fcsr"
            if csr_name not in event["state"]:
                raise RuntimeError(f"SysEmu trace omitted {csr_name} at {name}")
            state_events[name] = event["state"][csr_name]
        regs_doc = {
            "source": "SysEmu register-write trace and device-side fsw.ps snapshots",
            "hart": selected_event["hart"], "operation_pc": selected["pc"],
            "instruction": selected["decoded"], "word": selected["word"],
            "bytes_memory_order": selected["bytes_memory_order"], "cycle": selected_event["cycle"],
            "active_mask": "0xff",
            "mstatus_before": f"0x{state_events['gemm_mstatus_before']:x}",
            "mstatus_after": f"0x{state_events['gemm_mstatus_after']:x}",
            "fcsr_before": f"0x{state_events['gemm_fcsr_before']:x}",
            "fcsr_after": f"0x{state_events['gemm_fcsr_after']:x}",
            "f10_before": report_lanes(regs[(op_pc, "f10", ":")]),
            "f11_before": report_lanes(regs[(op_pc, "f11", ":")]),
            "f12_before": report_lanes(regs[(op_pc, "f12", ":")]),
            "f10_after": report_lanes(regs[(syms["capture_snapshot_f10"], "f10", ":")]),
            "f11_after": report_lanes(regs[(syms["capture_snapshot_f11"], "f11", ":")]),
            "f12_after": report_lanes(regs[(syms["capture_snapshot_f12"], "f12", ":")]),
            "fma_count": len(fma_events),
            "broadcast_count": len(broadcast_registers), "broadcasts": broadcast_registers,
            "fma_registers": fma_registers,
        }
        (out / "registers.json").write_text(json.dumps(regs_doc, indent=2) + "\n")
        result_doc = {"case": case, "shape": [N, N, N], "device_instruction": "fmadd.ps",
                      "input_a": a, "input_b": b, "output_actual": actual,
                      "output_expected": expected, "output_memory_bytes": actual_bytes.hex(" "),
                      "completion_word": f"0x{complete:08x}", "trap_marker": trap_marker,
                      "trap_cause": trap_cause, "fma_count": len(fma_events),
                      "broadcast_count": len(broadcast_registers), "input_layout": "row-major A and B", "pass": passed}
        (out / "result.json").write_text(json.dumps(result_doc, indent=2) + "\n")
        print(f"\nGEMM {case}: {N}x{N}x{N}, entry=0x{entry:x}, hart={selected_event['hart']}")
        print(f"  final instruction: {selected['decoded']}")
        print(f"  final FMA PC={selected['pc']} bytes={selected['bytes_memory_order']} word={selected['word']}")
        print(f"  mask=0xff; executed FMAs={len(fma_events)}; completion=0x{complete:08x}; traps={trap_marker}/{trap_cause}")
        print(f"  device scalar broadcasts={len(broadcast_registers)}; all 64 FMA input/accumulator states checked")
        for row in range(N):
            print(f"  C[{row},:]=" + str(list(actual[row * N:(row + 1) * N])))
        print(f"  PASS; artifacts: {out}")
        all_passed &= passed
    return 0 if all_passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"gemm.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
