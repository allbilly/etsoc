#!/usr/bin/env python3
"""Assemble, run, and report one ET-SOC1 packed-float ADD on real SysEmu."""

from __future__ import annotations

import json
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
OUT = ROOT / "out" / "add"
HOST_TIMEOUT = 120
SIM_TIMEOUT = 90
SIM_CYCLES = 10_000
DONE_WORD = 0x4B4F5445  # bytes spell ETOK in memory order
OUTPUT_SENTINEL = 0xA5A5A5A5
F12_SEED = (-1.25, -2.25, -3.25, -4.25, -5.25, -6.25, -7.25, -8.25)
CASES = {
    "primary": (
        (1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0),
        (10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0),
    ),
    "exact": (
        (1.5, -2.0, 0.5, 4.0, -8.0, 16.0, 0.0, 32.0),
        (2.0, 0.25, -8.0, 0.5, -0.5, 2.0, -3.0, 0.125),
    ),
}


def runtime() -> dict[str, str]:
    """Use setup.sh's recorded tools, or discover the same host/container layout."""
    record = ROOT / "out" / "setup" / "environment.json"
    if record.is_file():
        env = json.loads(record.read_text())
        env["container"] = os.environ.get("ET_CONTAINER", env.get("container", ""))
        if env["kind"] == "host":
            prefix = os.environ.get("ET_PREFIX", env["prefix"])
            if Path(prefix, "bin", "sys_emu").is_file():
                for stem in ("riscv64-unknown-elf-", "riscv-unknown-elf-"):
                    if Path(prefix, "bin", stem + "as").is_file():
                        env.update(prefix=prefix, tool_prefix=str(Path(prefix, "bin", stem)),
                                   simulator=str(Path(prefix, "bin", "sys_emu")))
                        return env
        elif env["kind"] == "podman":
            prefix = os.environ.get("ET_CONTAINER_PREFIX", os.environ.get("ET_PREFIX", env["prefix"]))
            podman = shutil.which("podman")
            if podman:
                for stem in ("riscv64-unknown-elf-", "riscv-unknown-elf-"):
                    probe = subprocess.run([podman, "exec", env["container"], "test", "-x",
                                            f"{prefix}/bin/{stem}as"],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    sim_probe = subprocess.run([podman, "exec", env["container"], "test", "-x",
                                                f"{prefix}/bin/sys_emu"],
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if probe.returncode == 0 and sim_probe.returncode == 0:
                        env.update(prefix=prefix, tool_prefix=f"{prefix}/bin/{stem}",
                                   simulator=f"{prefix}/bin/sys_emu")
                        return env
        raise RuntimeError("The recorded ET installation is unavailable or incompatible; rerun ./setup.sh.")
        return env

    prefix = os.environ.get("ET_PREFIX", "/opt/et")
    if Path(prefix, "bin", "sys_emu").is_file():
        for stem in ("riscv64-unknown-elf-", "riscv-unknown-elf-"):
            if Path(prefix, "bin", stem + "as").is_file():
                return {"kind": "host", "prefix": prefix, "tool_prefix": str(Path(prefix, "bin", stem)),
                        "simulator": str(Path(prefix, "bin", "sys_emu"))}

    container = os.environ.get("ET_CONTAINER", "et-platform-rebuild")
    prefix = os.environ.get("ET_CONTAINER_PREFIX", os.environ.get("ET_PREFIX", prefix))
    podman = shutil.which("podman")
    if podman:
        probe = subprocess.run([podman, "exec", container, "test", "-x", f"{prefix}/bin/sys_emu"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if probe.returncode == 0:
            for stem in ("riscv64-unknown-elf-", "riscv-unknown-elf-"):
                check = subprocess.run([podman, "exec", container, "test", "-x", f"{prefix}/bin/{stem}as"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if check.returncode == 0:
                    return {"kind": "podman", "container": container, "prefix": prefix,
                            "tool_prefix": f"{prefix}/bin/{stem}", "simulator": f"{prefix}/bin/sys_emu"}
    raise RuntimeError("ET tools were not found. Run ./setup.sh or set ET_PREFIX / ET_CONTAINER.")


def command(runtime_info: dict[str, str], argv: list[str]) -> list[str]:
    if runtime_info["kind"] == "podman":
        return [shutil.which("podman") or "podman", "exec", runtime_info["container"], *argv]
    return argv


def run_logged(log: Path, argv: list[str], timeout: int = HOST_TIMEOUT) -> subprocess.CompletedProcess[str]:
    """Run an external tool with a host timeout; keep command, output, and status."""
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a") as stream:
        stream.write(f"COMMAND: {shlex.join(argv)}\n")
        stream.flush()
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            start_new_session=True)
    try:
        output, _ = proc.communicate(timeout=timeout)
        result = subprocess.CompletedProcess(argv, proc.returncode, output, "")
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            output, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            output, _ = proc.communicate()
        result = subprocess.CompletedProcess(argv, 124, output + "\nHOST_TIMEOUT_EXPIRED\n", "")
    with log.open("a") as stream:
        stream.write(result.stdout or "")
        stream.write(f"EXIT_STATUS: {result.returncode}\n\n")
    if result.stdout and result.returncode != 0:
        sys.stderr.write("\n".join(result.stdout.splitlines()[-60:]) + "\n")
    return result


def require(result: subprocess.CompletedProcess[str], what: str) -> None:
    if result.returncode != 0:
        raise RuntimeError(f"{what} failed with exit status {result.returncode}; see out/add/commands.log and trace.log")


def asm_float(value: float) -> str:
    return format(value, ".9g")


def assembly(a: tuple[float, ...], b: tuple[float, ...]) -> str:
    # Startup is deliberately small. It follows only the needed state setup
    # from et-platform sw-sysemu/examples/common/boot.S (Apache-2.0): bare
    # address translation, machine FP enable, clean fcsr, an eight-lane mask,
    # stack, and a trap target. It does not copy the upstream register-clear
    # loop or validation-CSR bookkeeping.
    return f"""# SPDX-License-Identifier: Apache-2.0
# ET-SOC1 minion startup conventions adapted from aifoundry-org/et-platform
# sw-sysemu/examples/common/boot.S, pinned by README.md.
.option push
.option norelax
.option norvc
.section .text.entry,"ax",@progbits
.globl _start
_start:
    csrwi satp, 0
    csrr  t0, mstatus
    li    t1, 0x6000
    or    t0, t0, t1
    csrw  mstatus, t0
    csrwi fcsr, 0
    csrwi mip, 0
    csrwi tensor_mask, 0
    la    sp, __stack_top
    la    t0, trap_handler
    csrw  mtvec, t0
    li    t0, 255
    mova.m.x t0

    la    t1, input_a
    flw.ps f10, 0(t1)
    la    t1, input_b
    flw.ps f11, 0(t1)
    la    t1, seed_f12
seed_load:
    flw.ps f12, 0(t1)

.globl capture_mstatus_before
capture_mstatus_before:
    csrr  t0, mstatus
.globl capture_fcsr_before
capture_fcsr_before:
    csrr  t0, fcsr

.globl operation
operation:
    fadd.ps f12, f10, f11, rne

.globl capture_fcsr_after
capture_fcsr_after:
    csrr  t0, fcsr
.globl capture_mstatus_after
capture_mstatus_after:
    csrr  t0, mstatus

    la    t1, result_c
    fsw.ps f12, 0(t1)
.globl capture_f10_after
    la    t1, snapshot_f10
capture_f10_after:
    fsw.ps f10, 0(t1)
.globl capture_f11_after
    la    t1, snapshot_f11
capture_f11_after:
    fsw.ps f11, 0(t1)
.globl capture_f12_after
    la    t1, snapshot_f12
capture_f12_after:
    fsw.ps f12, 0(t1)

    li    t0, 0x4b4f5445
    la    t1, completion
    sw    t0, 0(t1)
.globl park
park:
    wfi
    j     park

.balign 4096
trap_handler:
    csrr  t0, mcause
    la    t1, trap_cause
    sd    t0, 0(t1)
    li    t0, 1
    la    t1, trap_marker
    sw    t0, 0(t1)
    j     park
.option pop

.section .data,"aw",@progbits
.balign 32
input_a:
    .float {", ".join(asm_float(x) for x in a)}
input_b:
    .float {", ".join(asm_float(x) for x in b)}
seed_f12:
    .float {", ".join(asm_float(x) for x in F12_SEED)}

.balign 32
.globl __monitor_start
__monitor_start:
.globl result_c
result_c:
    .rept 8
    .word 0x{OUTPUT_SENTINEL:08x}
    .endr
.globl completion
completion:
    .word 0
.globl trap_marker
trap_marker:
    .word 0
.globl trap_cause
trap_cause:
    .dword 0
.balign 32
snapshot_f10:
    .zero 32
snapshot_f11:
    .zero 32
snapshot_f12:
    .zero 32
.globl __monitor_end
__monitor_end:
"""


LINKER = """/* SPDX-License-Identifier: Apache-2.0 */
OUTPUT_ARCH("riscv")
ENTRY(_start)
SECTIONS {
  .text 0x8000001000 : { KEEP(*(.text.entry)) *(.text .text.*) }
  .data 0x8000100000 : { *(.data .data.*) }
  .stack 0x8000200000 (NOLOAD) : {
    __stack_bottom = .;
    . += 0x4000;
    __stack_top = .;
  }
}
"""


def pack_floats(values: tuple[float, ...]) -> bytes:
    return struct.pack("<8f", *values)


def parse_symbols(text: str) -> dict[str, int]:
    found: dict[str, int] = {}
    for line in text.splitlines():
        match = re.match(r"^([0-9a-fA-F]+)\s+\S\s+(\S+)$", line.strip())
        if match:
            found[match.group(2)] = int(match.group(1), 16)
    return found


def lane_words(line: str) -> tuple[int, ...]:
    words = tuple(int(word, 16) for word in re.findall(r"\d+:0x([0-9a-fA-F]{8})", line))
    if len(words) != 8:
        raise RuntimeError(f"expected eight lanes in simulator register event: {line.strip()}")
    return words


def lane_report(words: tuple[int, ...]) -> dict[str, object]:
    return {"raw_u32": [f"0x{x:08x}" for x in words],
            "f32": list(struct.unpack("<8f", struct.pack("<8I", *words)))}


def trace_events(trace: str) -> tuple[list[dict[str, object]], dict[tuple[int, str, str], tuple[int, ...]]]:
    insn_re = re.compile(
        r"^(\d+): DEBUG EMU: \[(H\d+ S\d+:N\d+:C\d+:T\d+)\] I\(M\): "
        r"0x([0-9a-fA-F]+) \(0x([0-9a-fA-F]{8})\) (.*)$")
    freg_re = re.compile(r"\bf(\d+) ([=:]) \{([^}]*)\}")
    csr_re = re.compile(r"\b(mstatus|fcsr|fflags) ([=:]) 0x([0-9a-fA-F]+)")
    mreg_re = re.compile(r"\bm(\d+) ([=:]) 0x([0-9a-fA-F]+)")
    events: list[dict[str, object]] = []
    regs: dict[tuple[int, str, str], tuple[int, ...]] = {}
    current: dict[str, object] | None = None
    for line in trace.splitlines():
        insn = insn_re.match(line)
        if insn:
            current = {"cycle": int(insn.group(1)), "hart": insn.group(2),
                       "pc": int(insn.group(3), 16), "word": int(insn.group(4), 16),
                       "disassembly": insn.group(5), "registers": {}, "state": {}}
            events.append(current)
            continue
        if current is None:
            continue
        freg = freg_re.search(line)
        if freg:
            key = (int(current["pc"]), f"f{freg.group(1)}", freg.group(2))
            regs[key] = lane_words(f"{{{freg.group(3)}}}")
            current["registers"][f"f{freg.group(1)}:{freg.group(2)}"] = list(regs[key])
        csr = csr_re.search(line)
        if csr:
            current["state"][csr.group(1)] = int(csr.group(3), 16)
        mreg = mreg_re.search(line)
        if mreg:
            current["state"][f"m{mreg.group(1)}:{mreg.group(2)}"] = int(mreg.group(3), 16)
    return events, regs


def event_at(events: list[dict[str, object]], pc: int, begins: str = "") -> dict[str, object]:
    matches = [e for e in events if e["pc"] == pc and str(e["disassembly"]).startswith(begins)]
    if len(matches) != 1:
        raise RuntimeError(f"expected one traced instruction {begins!r} at 0x{pc:x}, found {len(matches)}")
    return matches[0]


def state_value(event: dict[str, object], name: str) -> int:
    if name not in event["state"]:
        raise RuntimeError(f"SysEmu did not report {name} for instruction PC 0x{event['pc']:x}")
    return int(event["state"][name])


def main() -> int:
    selected = sys.argv[1:] or ["primary", "exact"]
    if any(name not in CASES for name in selected):
        raise SystemExit("usage: python3 examples/add.py [primary|exact ...]")
    OUT.mkdir(parents=True, exist_ok=True)
    env = runtime()
    all_ok = True
    for case_name in selected:
        case_dir = OUT if case_name == "primary" else OUT / case_name
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "commands.log").write_text("")
        a, b = CASES[case_name]
        (case_dir / "kernel.S").write_text(assembly(a, b))
        (case_dir / "link.ld").write_text(LINKER)

        run_id = uuid.uuid4().hex[:10]
        stage = f"/tmp/etsoc1-add-{run_id}"
        is_container = env["kind"] == "podman"
        if is_container:
            podman = shutil.which("podman") or "podman"
            require(run_logged(case_dir / "commands.log", [podman, "exec", env["container"], "mkdir", "-p", stage]),
                    "create simulator staging directory")
            for name in ("kernel.S", "link.ld"):
                require(run_logged(case_dir / "commands.log",
                                   [podman, "cp", str(case_dir / name), f"{env['container']}:{stage}/{name}"]),
                        f"copy {name} into simulator environment")
            work = stage
            shell = command(env, ["bash", "-lc"])
        else:
            work = str(case_dir)
            shell = ["bash", "-lc"]

        tp = env["tool_prefix"]
        ap = shlex.quote(tp + "as")
        lp = shlex.quote(tp + "ld")
        dp = shlex.quote(tp + "objdump")
        cp = shlex.quote(tp + "objcopy")
        np = shlex.quote(tp + "nm")
        rp = shlex.quote(tp + "readelf")
        qwork = shlex.quote(work)
        build = (
            f"set -euo pipefail; cd {qwork}; "
            f"{ap} --march=rv64imfc -mabi=lp64f -o kernel.o kernel.S; "
            f"{lp} --no-relax --build-id=none -T link.ld -o kernel.elf kernel.o; "
            f"{dp} -d -M numeric kernel.elf > kernel.asm; "
            f"{dp} -h kernel.elf > sections.txt; "
            f"{rp} -h -l -S kernel.elf > elf-inspection.txt; "
            f"{np} -n --defined-only kernel.elf > symbols.txt; "
            f"{cp} -O binary --only-section=.text kernel.elf text.bin"
        )
        require(run_logged(case_dir / "commands.log", [*shell, build]), "assemble and link ET-SOC1 ELF")
        if is_container:
            require(run_logged(case_dir / "commands.log",
                               [shutil.which("podman") or "podman", "cp", f"{env['container']}:{stage}/.", str(case_dir)]),
                    "retrieve ELF and inspection artifacts")

        symbols = parse_symbols((case_dir / "symbols.txt").read_text())
        required_symbols = ("_start", "operation", "seed_load", "capture_mstatus_before",
                            "capture_fcsr_before", "capture_fcsr_after", "capture_mstatus_after",
                            "capture_f10_after", "capture_f11_after", "capture_f12_after",
                            "park", "result_c", "completion", "trap_marker", "trap_cause",
                            "snapshot_f10", "snapshot_f11", "snapshot_f12", "__monitor_start", "__monitor_end")
        missing = [name for name in required_symbols if name not in symbols]
        if missing:
            raise RuntimeError(f"missing ELF symbols: {', '.join(missing)}")
        elf_text = (case_dir / "elf-inspection.txt").read_text()
        entry_match = re.search(r"Entry point address:\s+0x([0-9a-fA-F]+)", elf_text)
        text_match = re.search(r"^\s*\[\s*\d+\]\s+\.text\s+\S+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)",
                               elf_text, re.MULTILINE)
        if not entry_match or not text_match:
            raise RuntimeError("could not derive ELF entry and .text mapping from readelf output")
        entry = int(entry_match.group(1), 16)
        text_vma, text_offset, text_size = (int(text_match.group(i), 16) for i in (1, 2, 3))
        op_pc = symbols["operation"]
        if entry != symbols["_start"] or not (text_vma <= op_pc and op_pc + 4 <= text_vma + text_size):
            raise RuntimeError("ELF entry or operation is outside the linked .text section")
        text_bytes = (case_dir / "text.bin").read_bytes()
        op_index = op_pc - text_vma
        op_bytes = text_bytes[op_index:op_index + 4]
        if len(op_bytes) != 4:
            raise RuntimeError("the packed instruction is not four bytes in .text")
        (case_dir / "op.bin").write_bytes(op_bytes)
        op_word = int.from_bytes(op_bytes, "little")
        decoded = [line.strip() for line in (case_dir / "kernel.asm").read_text().splitlines()
                   if re.search(rf"\b{op_pc:x}:\s", line)]
        if len(decoded) != 1 or "fadd.ps" not in decoded[0]:
            raise RuntimeError(f"pinned objdump did not decode the operation as fadd.ps: {decoded}")
        dump_addr = symbols["__monitor_start"]
        dump_size = symbols["__monitor_end"] - dump_addr
        (case_dir / "elf-layout.json").write_text(json.dumps({
            "entry": f"0x{entry:x}", "text_vma": f"0x{text_vma:x}",
            "text_file_offset": f"0x{text_offset:x}", "text_size": text_size,
            "operation_pc": f"0x{op_pc:x}", "operation_file_offset": f"0x{text_offset + op_pc - text_vma:x}",
            "operation_bytes_memory_order": op_bytes.hex(" "), "operation_word": f"0x{op_word:08x}",
            "selected_hart": "H0 S0:N0:C0:T0", "executable_sections": [".text"],
            "data_sections": [".data"], "stack_section": ".stack (NOBITS)",
            "monitor_address": f"0x{dump_addr:x}", "monitor_size": dump_size,
            "symbols": {name: f"0x{value:x}" for name, value in symbols.items()
                        if name in ("result_c", "completion", "trap_marker", "trap_cause",
                                    "snapshot_f10", "snapshot_f11", "snapshot_f12",
                                    "__monitor_start", "__monitor_end")}
        }, indent=2) + "\n")

        sim_args = [env["simulator"], "-l", "-lm", "0", "-lt", "0", "-sp_dis",
                    "-reset_pc", hex(entry), "-single_thread", "-minions", "0x1", "-shires", "0x1",
                    "-max_cycles", str(SIM_CYCLES), "-elf_load", f"{work}/kernel.elf",
                    "-dump_at_pc_pc", hex(entry), "-dump_at_pc_addr", hex(dump_addr),
                    "-dump_at_pc_size", hex(dump_size), "-dump_at_pc_file", f"{work}/prestart.bin",
                    "-dump_addr", hex(dump_addr), "-dump_size", str(dump_size), "-dump_file", f"{work}/output.bin"]
        timed = command(env, ["timeout", "--signal=TERM", "--kill-after=5s", f"{SIM_TIMEOUT}s", *sim_args])
        result = run_logged(case_dir / "commands.log", timed, HOST_TIMEOUT)
        if is_container:
            pull = run_logged(case_dir / "commands.log",
                              [shutil.which("podman") or "podman", "cp", f"{env['container']}:{stage}/.", str(case_dir)])
            if pull.returncode != 0:
                raise RuntimeError("could not retrieve simulator output; staging files remain in the container")
            run_logged(case_dir / "commands.log", [shutil.which("podman") or "podman", "exec",
                                                     env["container"], "rm", "-rf", stage])
        trace = result.stdout or ""
        (case_dir / "trace.log").write_text(trace)
        if result.returncode != 0:
            raise RuntimeError(f"SysEmu returned {result.returncode}; diagnostics are preserved in {case_dir}")
        if "Error, max cycles reached" in trace or "Finishing emulation" not in trace:
            raise RuntimeError("SysEmu did not show successful completion before its cycle limit")
        if re.search(r"\b(?:Trap|trap|exception|Exception)\b", trace):
            raise RuntimeError("unexpected trap/exception text appears in the SysEmu trace")
        events, reg_events = trace_events(trace)
        park = event_at(events, symbols["park"], "wfi")
        operation = event_at(events, op_pc, "fadd.ps")
        seed = event_at(events, symbols["seed_load"], "flw.ps")
        fcsr_before = event_at(events, symbols["capture_fcsr_before"], "csrr")
        fcsr_after = event_at(events, symbols["capture_fcsr_after"], "csrr")
        mstatus_before = event_at(events, symbols["capture_mstatus_before"], "csrr")
        mstatus_after = event_at(events, symbols["capture_mstatus_after"], "csrr")
        source_a = reg_events[(op_pc, "f10", ":")]
        source_b = reg_events[(op_pc, "f11", ":")]
        result_f12 = reg_events[(op_pc, "f12", "=")]
        seed_f12 = reg_events[(symbols["seed_load"], "f12", "=")]
        if seed_f12 != struct.unpack("<8I", pack_floats(F12_SEED)):
            raise RuntimeError("f12 was not initialized from the visible eight-lane seed data")
        post_regs: dict[str, tuple[int, ...]] = {}
        if not (case_dir / "output.bin").is_file() or (case_dir / "output.bin").stat().st_size != dump_size:
            raise RuntimeError("simulator did not produce the complete output-memory dump")
        output = (case_dir / "output.bin").read_bytes()
        if not (case_dir / "prestart.bin").is_file() or (case_dir / "prestart.bin").stat().st_size != dump_size:
            raise RuntimeError("SysEmu did not capture initialized output memory at the ELF entry point")
        before = (case_dir / "prestart.bin").read_bytes()
        offset = lambda name: symbols[name] - dump_addr
        initial_c = before[offset("result_c"):offset("result_c") + 32]
        sentinel_bytes = struct.pack("<8I", *([OUTPUT_SENTINEL] * 8))
        if initial_c != sentinel_bytes:
            raise RuntimeError("the output buffer did not contain its ELF sentinel before execution")
        if struct.unpack_from("<I", before, offset("completion"))[0] != 0:
            raise RuntimeError("completion word was not initially clear")
        if struct.unpack_from("<I", before, offset("trap_marker"))[0] != 0:
            raise RuntimeError("trap marker was not initially clear")
        for n in (10, 11, 12):
            pc = symbols[f"capture_f{n}_after"]
            event = event_at(events, pc, "fsw.ps")
            post_regs[f"f{n}"] = reg_events[(pc, f"f{n}", ":")]
            if post_regs[f"f{n}"] != struct.unpack_from(
                    "<8I", output, symbols[f"snapshot_f{n}"] - dump_addr):
                raise RuntimeError(f"SysEmu trace and device snapshot disagree for f{n}")
        actual_bytes = output[offset("result_c"):offset("result_c") + 32]
        expected = tuple(x + y for x, y in zip(a, b))
        expected_bytes = pack_floats(expected)
        complete = struct.unpack_from("<I", output, offset("completion"))[0]
        trap_marker = struct.unpack_from("<I", output, offset("trap_marker"))[0]
        trap_cause = struct.unpack_from("<Q", output, offset("trap_cause"))[0]
        passed = actual_bytes == expected_bytes and complete == DONE_WORD and trap_marker == 0 and trap_cause == 0

        mask_event = next(e for e in events if str(e["disassembly"]).startswith("mova.m.x"))
        # WRITE_VD reads M0 immediately before the packed operation writes f12.
        mask = operation["state"].get("m0::", mask_event["state"].get("m0:="))
        if mask != 0xFF:
            raise RuntimeError(f"active lane mask was not 0xff: {mask!r}")

        registers = {
            "source": "SysEmu -l register events plus device-side fsw.ps snapshots; all events are H0/S0/N0/C0/T0",
            "operation_pc": f"0x{op_pc:x}", "operation_hart": operation["hart"],
            "operation_cycle": operation["cycle"], "decoded_instruction": operation["disassembly"],
            "f10": {"before": lane_report(source_a), "after": lane_report(post_regs["f10"])},
            "f11": {"before": lane_report(source_b), "after": lane_report(post_regs["f11"])},
            "f12": {"before": lane_report(seed_f12), "after": lane_report(result_f12)},
            "active_mask": {"before_operation": "0x%02x" % mask, "after_operation": "0x%02x" % mask,
                            "evidence_pc": f"0x{int(mask_event['pc']):x}", "mova_event": mask_event["disassembly"]},
            "mstatus": {"before": f"0x{state_value(mstatus_before, 'mstatus'):x}",
                        "after": f"0x{state_value(mstatus_after, 'mstatus'):x}"},
            "fcsr": {"before": f"0x{state_value(fcsr_before, 'fcsr'):x}",
                     "after": f"0x{state_value(fcsr_after, 'fcsr'):x}",
                     "frm_after": state_value(fcsr_after, "fcsr") >> 5 & 7,
                     "fflags_after": state_value(fcsr_after, "fcsr") & 31},
            "trace_evidence": {"f12_seed_pc": f"0x{int(seed['pc']):x}",
                               "capture_f10_pc": f"0x{symbols['capture_f10_after']:x}",
                               "capture_f11_pc": f"0x{symbols['capture_f11_after']:x}",
                               "capture_f12_pc": f"0x{symbols['capture_f12_after']:x}"},
        }
        (case_dir / "registers.json").write_text(json.dumps(registers, indent=2) + "\n")
        (case_dir / "result.json").write_text(json.dumps({
            "case": case_name, "operation": "fadd.ps", "input_a": a, "input_b": b,
            "actual_output_bytes": actual_bytes.hex(" "),
            "actual_output": struct.unpack("<8f", actual_bytes), "expected_output": expected,
            "initial_output_sentinel_bytes": initial_c.hex(" "),
            "completion_word": f"0x{complete:08x}", "trap_marker": trap_marker,
            "trap_cause": trap_cause, "pass": passed,
        }, indent=2) + "\n")

        print(f"\nADD {case_name}: entry=0x{entry:x} hart={operation['hart']} op_pc=0x{op_pc:x}")
        print(f"  instruction: {decoded[0]}")
        print(f"  memory-order bytes: {op_bytes.hex(' ')}  decoded word: 0x{op_word:08x}")
        print(f"  cycle={operation['cycle']} mask=0x{mask:02x} "
              f"mstatus={state_value(mstatus_before, 'mstatus'):#x}->{state_value(mstatus_after, 'mstatus'):#x} "
              f"fcsr={state_value(fcsr_before, 'fcsr'):#x}->{state_value(fcsr_after, 'fcsr'):#x}")
        for name in ("f10", "f11", "f12"):
            report = registers[name]
            print(f"  {name} before={report['before']['f32']} raw={report['before']['raw_u32']}")
            print(f"  {name} after ={report['after']['f32']} raw={report['after']['raw_u32']}")
        print(f"  C bytes={actual_bytes.hex(' ')} actual={struct.unpack('<8f', actual_bytes)}")
        print(f"  expected={expected} completion=0x{complete:08x} trap={trap_marker}/{trap_cause}")
        print(f"  {'PASS' if passed else 'FAIL'}; artifacts: {case_dir}")
        all_ok &= passed
    return 0 if all_ok else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"add.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
