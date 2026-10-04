#!/usr/bin/env python3
"""Inventory ET instruction handlers reachable from the pinned SysEmu decoders."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DECODERS = {
    "custom-0": "dec_custom0",
    "custom-1": "dec_custom1",
    "custom-2": "dec_custom2",
    "custom-3": "dec_custom3",
    "48-bit-0": "dec_insn_48b_0",
    "48-bit-1": "dec_insn_48b_1",
    "64-bit": "dec_insn_64b",
    "fp-load": "dec_load_fp",
    "fp-store": "dec_store_fp",
    "op-32": "dec_op_32",
    "reserved-2": "dec_reserved2",
}

# ET instructions also occupy normally standard or reserved opcode slots.
# Keep this inventory about ET extensions while including those paths. Base
# RISC-V instructions and the Erbium-only branch of dec_op_32 are excluded.
EXTRA_SOURCES = {
    "fp-load": {"insns/packed_loadstore.cpp"},
    "fp-store": {"insns/packed_loadstore.cpp"},
    "op-32": {"insns/arith_atomic.cpp", "insns/arith_graphics.cpp",
              "insns/coherent_arith_loadstore.cpp"},
}

EXAMPLE_RUNS = {
    "add": ("primary", "exact"), "mul": ("primary", "exact"), "sub": ("primary", "exact"),
    "gemm": ("primary", "exact"), "packed-int": ("primary", "exact"),
    "packed-fp": ("primary", "exact"), "packed-memory": ("primary", "exact"),
    "packed-atomic": ("primary", "exact", "alias"),
    "scalar-memory": ("primary", "exact"),
    "graphics": ("primary", "exact"),
}


def execution_evidence() -> tuple[dict[str, list[dict[str, object]]], list[dict[str, object]], list[str]]:
    """Count labeled sites backed by passing results, ELF bytes and raw trace.

    Source-string mentions remain a separate field. This audit verifies that
    the instruction really executed; the example's own reference, register,
    sentinel and completion checks establish its recorded validation result.
    """
    evidence: dict[str, list[dict[str, object]]] = {}
    runs, missing = [], []
    instruction_re = re.compile(r"^\d+: DEBUG EMU: \[(H\d+ S\d+:N\d+:C\d+:T\d+)\] I\(M\): "
                                r"0x([0-9a-fA-F]+) \(0x([0-9a-fA-F]{8})\) (.*)$", re.MULTILINE)
    for suite, cases in EXAMPLE_RUNS.items():
        for case in cases:
            directory = ROOT / "out" / suite
            if case != "primary":
                directory /= case
            required = ("result.json", "elf-layout.json", "kernel.elf", "trace.log", "output.bin", "registers.json")
            run_name = str(directory.relative_to(ROOT))
            if any(not (directory / name).is_file() for name in required):
                missing.append(run_name)
                continue
            result = json.loads((directory / "result.json").read_text())
            if not result.get("pass") or result.get("trap_marker") or result.get("trap_cause") or result.get("completion_word") != "0x4b4f5445":
                raise RuntimeError(f"execution evidence lacks passing output/completion/trap checks: {run_name}")
            layout = json.loads((directory / "elf-layout.json").read_text())
            if (directory / "operations.json").is_file():
                sites = json.loads((directory / "operations.json").read_text())
            else:
                sites = [{"pc": layout["operation_pc"], "word": layout["operation_word"],
                          "bytes_memory_order": layout["operation_bytes_memory_order"], "mnemonic": result["operation"]}]
            if (directory / "broadcasts.json").is_file():
                sites += json.loads((directory / "broadcasts.json").read_text())
            elf = (directory / "kernel.elf").read_bytes()
            trace = (directory / "trace.log").read_text()
            events: dict[int, list[tuple[str, int, str]]] = {}
            for match in instruction_re.finditer(trace):
                events.setdefault(int(match.group(2), 16), []).append(
                    (match.group(1), int(match.group(3), 16), match.group(4)))
            for site in sites:
                pc, word = int(site["pc"], 16), int(site["word"], 16)
                observed = events.get(pc, [])
                if len(observed) != 1 or observed[0][0] != "H0 S0:N0:C0:T0" or observed[0][1] != word:
                    raise RuntimeError(f"missing, repeated or wrong instruction execution: {run_name} PC {pc:#x}")
                raw = bytes.fromhex(site["bytes_memory_order"])
                offset = int(layout["text_file_offset"], 16) + pc - int(layout["text_vma"], 16)
                if raw != word.to_bytes(4, "little") or elf[offset:offset + 4] != raw:
                    raise RuntimeError(f"ELF and executed bytes disagree: {run_name} PC {pc:#x}")
                mnemonic = observed[0][2].split()[0]
                if site.get("mnemonic", mnemonic) != mnemonic:
                    raise RuntimeError(f"wrong traced mnemonic: {run_name} PC {pc:#x}")
                evidence.setdefault(mnemonic, []).append({"run": run_name, "pc": f"0x{pc:x}",
                                                         "word": f"0x{word:08x}"})
            runs.append({"run": run_name, "validated_sites": len(sites), "pass": True,
                         "sha256": {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                                    for name in required}})
    return evidence, runs, missing


def function_body(source: str, signature: str) -> str:
    match = re.search(signature, source)
    if not match:
        raise RuntimeError(f"missing source function: {signature}")
    start = source.index("{", match.end())
    depth = 1
    pos = start + 1
    while depth:
        char = source[pos]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        pos += 1
    return source[start:pos]


def trap_evidence(stubs: list[str]) -> tuple[dict[str, list[dict[str, object]]], list[str]]:
    """Audit expected faults separately from successful arithmetic execution."""
    evidence, missing = {}, []
    for suffix in ("", "exact"):
        directory = ROOT / "out" / "trap-stubs" / suffix
        required = ("result.json", "elf-layout.json", "kernel.elf", "trace.log", "output.bin", "registers.json")
        if any(not (directory / name).is_file() for name in required):
            missing.append(str(directory.relative_to(ROOT)))
            continue
        result = json.loads((directory / "result.json").read_text())
        layout = json.loads((directory / "elf-layout.json").read_text())
        memory, elf = (directory / "output.bin").read_bytes(), (directory / "kernel.elf").read_bytes()
        if not result["pass"] or result["completion_word"] != "0x4b4f5445" or result["trap_count"] != len(stubs) + 1:
            raise RuntimeError(f"expected-trap diagnostic did not pass: {directory}")
        rows = result["operations"]
        if sorted(row["mnemonic"] for row in rows if row["expected_cause"] == 30) != sorted(stubs):
            raise RuntimeError("trap diagnostic does not cover the source-defined stubs")
        trace = (directory / "trace.log").read_text()
        logged = re.findall(r"\[(H\d+ S\d+:N\d+:C\d+:T\d+)\].*Trapping to M-mode with cause 0x([0-9a-f]+) and tval 0x([0-9a-f]+)", trace)
        if len(logged) != len(rows):
            raise RuntimeError("expected-trap raw trace count disagrees with the result")
        start = int(layout["monitor_address"], 16)
        for row, (hart, cause, tval) in zip(rows, logged):
            pc, word = int(row["pc"], 16), int(row["word"], 16)
            offset = int(layout["text_file_offset"], 16) + pc - int(layout["text_vma"], 16)
            record = int(layout["symbols"]["record_" + row["mnemonic"].replace(".", "_")], 16) - start
            actual = struct.unpack_from("<3Q", memory, record)
            if (elf[offset:offset + 4] != word.to_bytes(4, "little") or hart != "H0 S0:N0:C0:T0" or
                    actual != (row["expected_cause"], pc, word) or int(cause, 16) != actual[0] or int(tval, 16) != word):
                raise RuntimeError(f"raw ELF/trap/memory evidence disagrees at {row['mnemonic']}")
            evidence.setdefault(row["mnemonic"], []).append({"run": str(directory.relative_to(ROOT)),
                "pc": row["pc"], "word": row["word"], "cause": actual[0],
                "sha256": {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in required}})
    return evidence, missing


def definitions(directory: Path) -> dict[str, dict[str, object]]:
    found = {}
    for path in sorted(directory.glob("*.cpp")):
        source = path.read_text()
        for match in re.finditer(r"void\s+insn_(\w+)\s*\([^)]*\)\s*\{", source):
            name = match.group(1)
            body = function_body(source, rf"void\s+insn_{re.escape(name)}\s*\([^)]*\)\s*")
            mnemonic = re.search(r'DISASM_\w+\s*\(\s*"([^"]+)"', body)
            found[name] = {
                "mnemonic": mnemonic.group(1) if mnemonic else None,
                "source": str(path.relative_to(directory.parent)),
                "trap_stub": "throw trap_mcode_instruction" in body,
                "requires_graphics_feature": "require_feature_gfx()" in body,
            }
    return found


def cache_csr_evidence(source_root: Path, commit: str) -> tuple[dict[str, object], list[str]]:
    """Audit CSR-launched cache evidence separately from custom instruction handlers."""
    names = {"cache_invalidate", "mcache_control", "ucache_control", "evict_sw", "flush_sw",
             "lock_sw", "unlock_sw", "prefetch_va", "evict_va", "flush_va", "lock_va", "unlock_va", "dcache_debug"}
    declarations = {name: int(number, 16) for number, name in re.findall(
        r"CSRDEF\((0x[0-9a-f]+),\s*(\w+),", (source_root / "sw-sysemu/csrs.h").read_text()) if name in names}
    if set(declarations) != names:
        raise RuntimeError("cache CSR declarations changed; review the selected source")
    runs, missing, coverage = [], [], set()
    for case in ("primary", "exact"):
        directory = ROOT / "out/cache-control" / ("" if case == "primary" else case)
        required = ("result.json", "elf-layout.json", "kernel.elf", "kernel.S", "trace.log", "output.bin", "registers.json", "operations.json")
        run_name = str(directory.relative_to(ROOT))
        if any(not (directory / name).is_file() for name in required):
            missing.append(run_name)
            continue
        result = json.loads((directory / "result.json").read_text())
        layout = json.loads((directory / "elf-layout.json").read_text())
        sites = json.loads((directory / "operations.json").read_text())
        if (not result.get("pass") or not result.get("whole_monitor_matches") or
                result.get("operation_count") != 37 or result.get("csr_count") != len(names) or
                result.get("completion_word") != "0x4b4f5445" or result.get("trap_marker") or result.get("trap_cause")):
            raise RuntimeError(f"cache CSR validation/completion failed: {run_name}")
        if (len(sites) != 37 or len(result["operations"]) != len(sites) or
                len({site["name"] for site in sites}) != len(sites) or {site["csr_name"] for site in sites} != names):
            raise RuntimeError(f"incomplete cache command sites: {run_name}")
        elf, memory = (directory / "kernel.elf").read_bytes(), (directory / "output.bin").read_bytes()
        if elf[:6] != b"\x7fELF\x02\x01":
            raise RuntimeError("cache experiment is not a little-endian ELF64")
        phoff, phsize, phcount = struct.unpack_from("<Q", elf, 32)[0], *struct.unpack_from("<HH", elf, 54)
        segments = [struct.unpack_from("<II6Q", elf, phoff + i * phsize) for i in range(phcount)]
        def file_offset(pc):
            matches = [row[2] + pc - row[3] for row in segments
                       if row[0] == 1 and row[1] & 1 and row[3] <= pc and pc + 4 <= row[3] + row[5]]
            if len(matches) != 1:
                raise RuntimeError("cache PC is not in one executable PT_LOAD segment")
            return matches[0]
        trace = (directory / "trace.log").read_text()
        if "Finishing emulation" not in trace or "Error, max cycles reached" in trace or "Trapping to" in trace:
            raise RuntimeError("cache raw trace lacks successful normal completion")
        observed = {}
        for hart, pc, word in re.findall(r"\[(H\d+ S\d+:N\d+:C\d+:T\d+)\] I\(M\): 0x([0-9a-f]+) \(0x([0-9a-f]{8})\)", trace):
            observed.setdefault(int(pc, 16), []).append((hart, int(word, 16)))
        for site, validation in zip(sites, result["operations"]):
            pc, word = int(site["pc"], 16), int(site["word"], 16)
            csr_name = site["csr_name"]
            if (observed.get(pc) != [("H0 S0:N0:C0:T0", word)] or
                    elf[file_offset(pc):file_offset(pc) + 4] != word.to_bytes(4, "little") or
                    word & 0x7F != 0x73 or word >> 20 != declarations[csr_name] or
                    word >> 12 & 7 != (2 if csr_name == "dcache_debug" else 1) or not validation["pass"]):
                raise RuntimeError(f"cache CSR ELF/trace evidence disagrees: {run_name}/{site['name']}")
            record = int(layout["symbols"]["record_" + site["name"]], 16) - int(layout["monitor_address"], 16)
            actual = struct.unpack_from("<5Q", memory, record)
            if tuple(int(value, 16) for value in validation["actual_readbacks"]) != actual:
                raise RuntimeError("cache CSR readback memory disagrees with the validation report")
            coverage.add(csr_name)
        completion = int(layout["symbols"]["completion"], 16) - int(layout["monitor_address"], 16)
        if struct.unpack_from("<IIQ", memory, completion) != (0x4B4F5445, 0, 0):
            raise RuntimeError("cache CSR completion/trap memory disagrees")
        runs.append({"run": run_name, "pass": True, "validated_sites": len(sites),
                     "sha256": {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in required}})
    paths = ("csrs.h", "cache.h", "insn_util.h", "insns/zicsr.cpp", "insns/cache_control.cpp")
    report = {"et_platform_commit": commit, "scope": "13 cache control/action/debug CSRs; base RISC-V SYSTEM encodings, separate from the 213 ET extension handlers",
              "csr_declarations": {name: f"0x{number:03x}" for name, number in sorted(declarations.items())},
              "verified_csr_count": len(coverage), "missing_csrs": sorted(names - coverage),
              "verified_runs": runs, "runs_missing_evidence": missing,
              "source_sha256": {"sw-sysemu/" + path: hashlib.sha256((source_root / "sw-sysemu" / path).read_bytes()).hexdigest() for path in paths}}
    target = ROOT / "out/isa/cache-csr-inventory.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2) + "\n")
    return report, missing


def synchronization_evidence(source_root: Path, commit: str) -> tuple[dict[str, object], list[str]]:
    """Keep synchronization CSR/ESR evidence outside the packed-op handler count."""
    names = {"excl_mode", "flb", "fcc", "stall", "fccnb"}
    declarations = {name: int(number, 16) for number, name in re.findall(
        r"CSRDEF\((0x[0-9a-f]+),\s*(\w+),", (source_root / "sw-sysemu/csrs.h").read_text()) if name in names}
    if set(declarations) != names:
        raise RuntimeError("synchronization CSR declarations changed")
    runs, missing, coverage = [], [], set()
    for case, count in (("primary", 23), ("exact", 24)):
        directory = ROOT / "out/synchronization" / ("" if case == "primary" else case)
        required = ("result.json", "elf-layout.json", "kernel.elf", "kernel.S", "trace.log", "output.bin", "registers.json", "operations.json")
        run_name = str(directory.relative_to(ROOT))
        if any(not (directory / name).is_file() for name in required):
            missing.append(run_name)
            continue
        result = json.loads((directory / "result.json").read_text())
        layout = json.loads((directory / "elf-layout.json").read_text())
        sites = json.loads((directory / "operations.json").read_text())
        if (not result.get("pass") or not result.get("whole_monitor_matches") or result.get("operation_count") != count or
                len(sites) != count or len(result["operations"]) != count or len({row["name"] for row in sites}) != count or
                {row["csr_name"] for row in sites if row["csr_name"]} != names):
            raise RuntimeError(f"incomplete synchronization validation/sites: {run_name}")
        elf, memory = (directory / "kernel.elf").read_bytes(), (directory / "output.bin").read_bytes()
        phoff, phsize, phcount = struct.unpack_from("<Q", elf, 32)[0], *struct.unpack_from("<HH", elf, 54)
        segments = [struct.unpack_from("<II6Q", elf, phoff + i * phsize) for i in range(phcount)]
        def file_offset(pc):
            matches = [row[2] + pc - row[3] for row in segments if row[0] == 1 and row[1] & 1 and row[3] <= pc and pc + 4 <= row[3] + row[5]]
            if len(matches) != 1:
                raise RuntimeError("synchronization PC lacks one executable PT_LOAD mapping")
            return matches[0]
        trace = (directory / "trace.log").read_text()
        if "Finishing emulation" not in trace or "Error, max cycles reached" in trace or "Trapping to" in trace:
            raise RuntimeError("synchronization raw trace did not complete normally")
        observed = {}
        for cycle, hart, pc, word in re.findall(r"^(\d+): DEBUG EMU: \[(H\d+ S\d+:N\d+:C\d+:T\d+)\] I\(M\): 0x([0-9a-f]+) \(0x([0-9a-f]{8})\)", trace, re.MULTILINE):
            observed.setdefault(int(pc, 16), []).append((hart, int(word, 16), int(cycle)))
        for site, validation in zip(sites, result["operations"]):
            pc, word, name = int(site["pc"], 16), int(site["word"], 16), site["csr_name"]
            actual = observed.get(pc, [])
            if len(actual) != 1 or actual[0][:2] != ("H0 S0:N0:C0:T0", word) or elf[file_offset(pc):file_offset(pc) + 4] != word.to_bytes(4, "little") or not validation["pass"]:
                raise RuntimeError("synchronization instruction ELF/trace evidence disagrees")
            if name:
                if word & 0x7F != 0x73 or word >> 20 != declarations[name] or word >> 12 & 7 != (2 if name == "fccnb" else 1):
                    raise RuntimeError("synchronization SYSTEM/CSR encoding disagrees")
                coverage.add(name)
            elif (word & 0x7F, word >> 12 & 7, word >> 15 & 31, word >> 20 & 31, word >> 25, word >> 7 & 31) != (0x23, 3, 7, 6, 0, 0):
                raise RuntimeError("credit source is not the declared device ESR-store instruction")
            record = int(layout["symbols"]["record_" + site["name"]], 16) - int(layout["monitor_address"], 16)
            if struct.unpack_from("<8Q", memory, record) != tuple(int(value, 16) for value in validation["actual"]):
                raise RuntimeError("synchronization raw state snapshot disagrees")
        timer_pc = int(layout["symbols"]["op_stall_timer"], 16)
        resume_pc = int(layout["symbols"]["resume_stall_timer"], 16)
        start, end = observed[timer_pc][0][2], observed[resume_pc][0][2]
        waits = re.findall(r"^(\d+): DEBUG EMU: \[(H\d+ S\d+:N\d+:C\d+:T\d+)\]\s+(Start|Stop) waiting for interrupt$", trace, re.MULTILINE)
        transitions = [(int(cycle), hart, action) for cycle, hart, action in waits if start <= int(cycle) <= end]
        if (end - start != result["timer_wait_cycles"] or end - start <= 1 or [row[2] for row in transitions] != ["Start", "Stop"] or
                any(row[1] != "H0 S0:N0:C0:T0" for row in transitions)):
            raise RuntimeError("synchronization timed wait/wake is not backed by the raw trace")
        completion = int(layout["symbols"]["completion"], 16) - int(layout["monitor_address"], 16)
        if struct.unpack_from("<IIQ", memory, completion) != (0x4B4F5445, 0, 0):
            raise RuntimeError("synchronization completion/trap memory disagrees")
        runs.append({"run": run_name, "pass": True, "validated_sites": count, "timer_wait_cycles": end - start,
                     "sha256": {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in required}})
    paths = ("csrs.h", "esrs_et.cpp", "flb.cpp", "processor.cpp", "processor.h", "system.cpp", "system.h",
             "insns/zicsr.cpp", "devices/rvtimer.h", "memory/etsoc1/main_memory.cpp")
    report = {"et_platform_commit": commit, "scope": "FLB/FCC/FCCNB/STALL/exclusive-mode CSR and self-credit/timer ESR evidence; separate from ET extension-handler coverage",
              "csr_declarations": {name: f"0x{number:03x}" for name, number in sorted(declarations.items())},
              "verified_csr_count": len(coverage), "missing_csrs": sorted(names - coverage), "verified_runs": runs,
              "runs_missing_evidence": missing, "limitations": ["FCC consumes pre-supplied credits; zero-credit block/wake and counter overflow not exercised", "single hart; no multi-hart barrier or contention test"],
              "source_sha256": {"sw-sysemu/" + path: hashlib.sha256((source_root / "sw-sysemu" / path).read_bytes()).hexdigest() for path in paths}}
    target = ROOT / "out/isa/synchronization-inventory.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2) + "\n")
    return report, missing


def message_port_evidence(source_root: Path, commit: str) -> tuple[dict[str, object], list[str]]:
    """Audit port CSRs, delivery, blocking/retry and actual overcapacity sends."""
    names = {f"port{kind}{p}" for kind in ("ctrl", "head", "headnb") for p in range(4)}
    declarations = {name: int(number, 16) for number, name in re.findall(
        r"CSRDEF\((0x[0-9a-f]+),\s*(\w+),", (source_root / "sw-sysemu/csrs.h").read_text()) if name in names}
    if set(declarations) != names:
        raise RuntimeError("message-port CSR declarations changed")
    runs, missing, coverage = [], [], set()
    for case in ("primary", "exact", "blocking-primary", "blocking-exact", "overflow-primary", "overflow-exact"):
        directory = ROOT / "out/message-ports" / ("" if case == "primary" else case)
        required = ("result.json", "elf-layout.json", "kernel.elf", "kernel.S", "trace.log", "output.bin",
                    "prestart.bin", "expected.bin", "registers.json", "operations.json")
        run_name = str(directory.relative_to(ROOT))
        if any(not (directory / name).is_file() for name in required):
            missing.append(run_name)
            continue
        result = json.loads((directory / "result.json").read_text())
        layout = json.loads((directory / "elf-layout.json").read_text())
        sites = json.loads((directory / "operations.json").read_text())
        blocking, overflow = case.startswith("blocking"), case.startswith("overflow")
        count = 3 if blocking else 60 if overflow else 80
        width, capacity = (8, 2) if blocking else (4 if case.endswith("primary") else 8, 2 if overflow or case.endswith("exact") else 4)
        if (not result.get("pass") or not result.get("whole_monitor_matches") or result.get("operation_count") != count or
                len(sites) != count or len(result["operations"]) != count or len({row["name"] for row in sites}) != count or
                result.get("csr_count") != (2 if blocking else 12) or result.get("message_width") != width or result.get("capacity") != capacity):
            raise RuntimeError(f"incomplete message-port validation/sites: {run_name}")
        elf, memory, pre = ((directory / name).read_bytes() for name in ("kernel.elf", "output.bin", "prestart.bin"))
        if elf[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", elf, 18)[0] != 243:
            raise RuntimeError("message-port ELF is not little-endian RISC-V ELF64")
        phoff, phsize, phcount = struct.unpack_from("<Q", elf, 32)[0], *struct.unpack_from("<HH", elf, 54)
        segments = [struct.unpack_from("<II6Q", elf, phoff + i * phsize) for i in range(phcount)]
        def file_offset(pc, size=4, executable=True):
            matches = [row[2] + pc - row[3] for row in segments if row[0] == 1 and (not executable or row[1] & 1)
                       and row[3] <= pc and pc + size <= row[3] + row[5]]
            if len(matches) != 1:
                raise RuntimeError("message-port address lacks one file-backed PT_LOAD mapping")
            return matches[0]
        start, size = int(layout["monitor_address"], 16), layout["monitor_size"]
        if len(memory) != size or len(pre) != size or pre != elf[file_offset(start, size, False):file_offset(start, size, False) + size]:
            raise RuntimeError("message-port prestart memory differs from the ELF data")
        if memory != (directory / "expected.bin").read_bytes():
            raise RuntimeError("message-port guarded memory/reference evidence disagrees")
        syms = {name: int(addr, 16) for name, addr in layout["symbols"].items()}
        trace = (directory / "trace.log").read_text()
        if "Finishing emulation" not in trace or "Error, max cycles reached" in trace or "Trapping to" in trace or "unlocked!" in trace:
            raise RuntimeError("message-port raw trace did not complete normally")
        observed, current = {}, None
        for line in trace.splitlines():
            match = re.match(r"^(\d+): DEBUG EMU: \[(H\d+) .*?\] I\(M\): 0x([0-9a-f]+) \(0x([0-9a-f]{8})\)", line)
            if match:
                cycle, hart, pc, word = match.groups()
                current = dict(cycle=int(cycle), hart=hart, pc=int(pc, 16), word=int(word, 16), registers={}, raw=[])
                observed.setdefault((hart, int(pc, 16)), []).append(current)
            if current is not None:
                current["raw"].append(line)
                reg = re.search(r"\bx(\d+) ([=:]) 0x([0-9a-f]+)", line)
                if reg:
                    current["registers"][(int(reg.group(1)), reg.group(2))] = int(reg.group(3), 16)
        def register(label, rd, direction="=", hart="H0"):
            rows = observed.get((hart, syms[label]), [])
            if len(rows) != 1:
                raise RuntimeError(f"message-port state capture lacks one real instruction: {label}")
            return rows[0]["registers"][(rd, direction)]
        pointers, backing = {p: 0 for p in range(4)}, {p: bytearray(64) for p in range(4)}
        for site, validation in zip(sites, result["operations"]):
            pc, word, name = int(site["pc"], 16), int(site["word"], 16), site["csr_name"]
            events = observed.get((site["hart"], pc), [])
            wanted_count = 2 if blocking and site["name"] == "receiver_head" else 255 if overflow and site["name"].endswith("_bulk_send") else 1
            if (len(events) != wanted_count or any(e["word"] != word for e in events) or not validation["pass"] or
                    site.get("expected_executions") != wanted_count or
                    elf[file_offset(pc):file_offset(pc) + 4] != word.to_bytes(4, "little") or
                    int(site["file_offset"], 16) != file_offset(pc)):
                raise RuntimeError("message-port instruction ELF/trace evidence disagrees")
            if name:
                if word & 0x7F != 0x73 or word >> 20 != declarations[name] or word >> 12 & 7 != (1 if "ctrl" in name and site["mnemonic"] == "csrrw" else 2):
                    raise RuntimeError("message-port SYSTEM/CSR encoding disagrees")
                coverage.add(name)
            elif (word & 0x7F, word >> 12 & 7, word >> 15 & 31, word >> 20 & 31, word >> 25, word >> 7 & 31) != (0x23, 3, 7, 6, 0, 0):
                raise RuntimeError("message source is not the declared device ESR-store instruction")
            if not blocking:
                n = site["name"]
                raw_state = (register("before_" + n, 21), register("resume_" + n, 22), register("capture_s4_" + n, 20, ":"),
                             register("capture_s1_" + n, 9, ":"), register("read_error_" + n, 23), register("read_cache_" + n, 24),
                             register("capture_s9_" + n, 25, ":"), register("read_status_" + n, 26))
                record = syms["record_" + n] - start
                if (struct.unpack_from("<8Q", memory, record) != raw_state or
                        tuple(int(v, 16) for v in validation["actual"]) != raw_state or validation["actual"] != validation["expected"]):
                    raise RuntimeError("message-port real register writes/snapshot/reference disagree")
                if name and events[0]["registers"].get((20, "=")) != raw_state[2]:
                    raise RuntimeError("message-port CSR destination write differs from the real snapshot")
                port = int(n[1])
                address = syms[f"target_{port}"] + 64
                if name and "ctrl" in name and site["mnemonic"] == "csrrw":
                    pointers[port] = 0
                if name is None:
                    value = register("input_" + n, 6)
                    load = observed[("H0", syms["input_" + n])][0]
                    reads = re.findall(r"MEM64\[0x([0-9a-f]+)\] : 0x([0-9a-f]+)", "\n".join(load["raw"]))
                    if len(reads) != 1:
                        raise RuntimeError("message input lacks one real device memory read")
                    input_addr, input_value = (int(x, 16) for x in reads[0])
                    if (not syms["input_payloads"] <= input_addr < syms["input_payloads"] + 28 * 8 or
                            input_addr & 7 or input_value != value or struct.unpack_from("<Q", pre, input_addr - start)[0] != value):
                        raise RuntimeError("message input load does not match actual ELF input memory")
                    for event in events:
                        if event["registers"] != {(6, ":"): value, (7, ":"): 0x0100000800 + port * 64}:
                            raise RuntimeError("message send source/address differs from the real input")
                        raw = "\n".join(event["raw"])
                        writes = [(int(h), int(p), int(v, 16), int(a, 16)) for h, p, v, a in re.findall(
                            r"Writing MSG_PORT \(H(\d+) p(\d+)\) data 0x([0-9a-f]+) to addr 0x\s*([0-9a-f]+)", raw)]
                        enabled = raw_state[0] & 1
                        slot = pointers[port] * width
                        wanted = [(0, port, value >> (i * 32) & 0xFFFFFFFF, address + slot + i * 4) for i in range(width // 4)] if enabled else []
                        stores = [(int(a, 16), int(v, 16)) for a, v in re.findall(r"MEM64\[0x([0-9a-f]+)\] = 0x([0-9a-f]+)", raw)]
                        if writes != wanted or stores != [(0x0100000800 + port * 64, value)]:
                            raise RuntimeError("message send lacks actual ESR/delivery memory writes")
                        if enabled:
                            backing[port][slot:slot + width] = value.to_bytes(8, "little")[:width]
                            pointers[port] = (pointers[port] + 1) % capacity
                    if wanted_count == 255 and (register("count_" + n, 29) != 255 or
                            struct.unpack_from("<Q", pre, syms["input_count"] - start)[0] != 255):
                        raise RuntimeError("bulk send count does not match real input load")
                elif "head" in name and "_empty" not in n:
                    returned = events[0]["registers"].get((20, "="))
                    if returned is None or returned != raw_state[2] or not 0 <= returned <= 64 - width or returned % width:
                        raise RuntimeError("message head has no valid actual offset result")
                    load = observed[("H0", syms["payload_" + n])][0]
                    reads = [(int(a, 16), int(v, 16)) for a, v in re.findall(
                        rf"MEM{width * 8}\[0x([0-9a-f]+)\] : 0x([0-9a-f]+)", "\n".join(load["raw"]))]
                    value = int.from_bytes(backing[port][returned:returned + width], "little")
                    if (reads != [(address + returned, value)] or load["registers"].get((9, "=")) != value or
                            load["registers"].get((25, ":")) != address + returned or raw_state[3] != value or raw_state[6] != address + returned):
                        raise RuntimeError("message head payload differs from actual delivered bytes")
        proof = result.get("blocking_proof")
        if blocking:
            heads, send = observed[("H0", syms["op_receiver_head"])], observed[("H2", syms["op_sender_send"])][0]
            values = [event["registers"][(20, "=")] for event in heads]
            waits = [(int(cycle), hart, action) for cycle, hart, action in re.findall(
                r"^(\d+): DEBUG EMU: \[(H\d+) .*?\]\s+(Start|Stop) waiting for message$", trace, re.MULTILINE)]
            if (not proof or values != [(1 << 64) - 1, 0] or not heads[0]["cycle"] < send["cycle"] <= heads[1]["cycle"] or
                    waits != [(heads[0]["cycle"], "H0", "Start"), (send["cycle"], "H0", "Stop")] or
                    proof["head_cycles"] != [event["cycle"] for event in heads] or proof["send_cycle"] != send["cycle"]):
                raise RuntimeError("message-port blocking/wake/retry is not backed by the raw trace")
            state = (register("blocking_control", 21), register("receiver_resumed", 22), register("blocking_return", 20, ":"),
                     register("blocking_payload", 9), register("blocking_error", 23), register("blocking_cache", 24),
                     register("blocking_payload", 25, ":"), register("blocking_status", 26))
            if struct.unpack_from("<8Q", memory, syms["blocking_record"] - start) != state:
                raise RuntimeError("message-port blocking snapshots disagree with actual register writes")
            address, payload = syms["target_0"] + 64, state[3]
            writes = [(int(word, 16), int(addr, 16)) for word, addr in re.findall(
                r"Writing MSG_PORT \(H0 p0\) data 0x([0-9a-f]+) to addr 0x\s*([0-9a-f]+)", "\n".join(send["raw"]))]
            if (state[2] != 0 or state[6] != address or state[4:6] != (0, 0) or
                    writes != [(payload & 0xFFFFFFFF, address), (payload >> 32, address + 4)] or
                    send["registers"][(6, ":")] != payload or send["registers"][(7, ":")] != 0x0100000800 or
                    struct.unpack_from("<Q", memory, address - start)[0] != payload or
                    struct.unpack_from("<2Q", memory, syms["handshake"] - start) != (1, 1)):
                raise RuntimeError("message-port wake lacks real sender/receiver/memory evidence")
        elif proof or re.search(r"(?:Start|Stop) waiting for message", trace):
            raise RuntimeError("nonblocking/nonempty port cases unexpectedly waited")
        queue_proof = result.get("queue_proof")
        if overflow:
            if not queue_proof or len(queue_proof) != 4:
                raise RuntimeError("missing all-four-port overcapacity evidence")
            rows = {row["name"]: row for row in result["operations"]}
            for port, queue in enumerate(queue_proof):
                state = lambda suffix: tuple(int(v, 16) for v in rows[f"p{port}_{suffix}"]["actual"])
                values = struct.unpack_from("<7Q", pre, syms["input_payloads"] - start + port * 56)
                payloads = [values[index] & ((1 << (width * 8)) - 1) for index in (2, 1, 2)]
                if (queue["port"] != port or queue["capacity"] != 2 or queue["bulk_send_count"] != 255 or
                        queue["overfill_head_results"] != [hex(v) for v in (0, width, 0)] or
                        queue["overfill_payloads"] != [hex(v) for v in payloads] or
                        queue["empty_after_drain"] != hex((1 << 64) - 1) or queue["empty_after_wrap"] != hex((1 << 64) - 1) or
                        queue["probe255_result"] != "0x0" or queue["tensor_error"] != "0x0" or
                        [state(f"head{i}")[2] for i in range(3)] != [0, width, 0] or
                        [state(f"head{i}")[3] for i in range(3)] != payloads or
                        state("empty_after")[2] != (1 << 64) - 1 or state("empty_wrap")[2] != (1 << 64) - 1 or
                        state("probe255")[2:4] != (0, values[3] & ((1 << (width * 8)) - 1)) or state("wrap256")[4] != 0):
                    raise RuntimeError("overcapacity/count-wrap proof disagrees with real register snapshots")
        elif queue_proof is not None:
            raise RuntimeError("unexpected queue-overflow proof in another port case")
        captured = json.loads((directory / "registers.json").read_text())
        if captured.get("queue_proof") != queue_proof:
            raise RuntimeError("port register report/queue proof disagree")
        if struct.unpack_from("<IIQ", memory, syms["completion"] - start) != (0x4B4F5445, 0, 0):
            raise RuntimeError("message-port completion/trap memory disagrees")
        runs.append(dict(run=run_name, **{"pass": True}, validated_sites=count, blocking_proof=proof, queue_proof=queue_proof,
                         sha256={name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in required}))
    paths = ("csrs.h", "emu_defines.h", "esrs.h", "esrs_et.cpp", "msgport.cpp", "processor.cpp", "processor.h",
             "insns/zicsr.cpp", "insns/cache_control.cpp", "insns/arith_loadstore.cpp", "memory/sysreg_region.h")
    port_type = re.search(r"struct Port\s*\{(.*?)\};", (source_root / "sw-sysemu/processor.h").read_text(), re.S)
    if not port_type or not re.search(r"uint8_t\s+size;", port_type.group(1)):
        raise RuntimeError("port queue count type differs from the verified uint8 wrap model")
    report = dict(et_platform_commit=commit, scope="12 message-port CSRs; FIFO/wrap/reset/drop, H2 -> H0 blocking, overcapacity overwrite and uint8 count wrap",
        csr_declarations={name: f"0x{number:03x}" for name, number in sorted(declarations.items())}, verified_csr_count=len(coverage),
        missing_csrs=sorted(names - coverage), verified_runs=runs, runs_missing_evidence=missing,
        limitations=["direct ESR sends cover 4/8 bytes; 16/32-byte delivery engines unverified", "direct/delayed upstream delivery supplies OOB zero; no nonzero minion producer in pinned source", "U-mode access unverified"],
        source_sha256={"sw-sysemu/" + path: hashlib.sha256((source_root / "sw-sysemu" / path).read_bytes()).hexdigest() for path in paths})
    target = ROOT / "out/isa/message-port-inventory.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2) + "\n")
    return report, missing


def message_port_privilege_evidence(source_root: Path, commit: str) -> tuple[dict[str, object], list[str]]:
    """Independently audit real U-mode port reads, faults and retained messages."""
    declarations = {name: int(number, 16) for number, name in re.findall(
        r"CSRDEF\((0x[0-9a-f]+),\s*(\w+),", (source_root / "sw-sysemu/csrs.h").read_text()) if name.startswith("port")}
    if len(declarations) != 12:
        raise RuntimeError("message-port privilege CSR declarations changed")
    runs, missing = [], []
    for case in ("primary", "exact"):
        directory = ROOT / "out/message-port-privilege" / ("" if case == "primary" else case)
        required = ("result.json", "elf-layout.json", "kernel.elf", "kernel.S", "trace.log", "output.bin",
                    "prestart.bin", "expected.bin", "registers.json", "operations.json", "text.bin", "text-user.bin")
        run_name = str(directory.relative_to(ROOT))
        if any(not (directory / name).is_file() for name in required):
            missing.append(run_name)
            continue
        result, layout, sites, registers = (json.loads((directory / name).read_text()) for name in
                                           ("result.json", "elf-layout.json", "operations.json", "registers.json"))
        if (not result.get("pass") or not result.get("whole_monitor_matches") or result.get("operation_count") != 92 or
                result.get("illegal_trap_count") != 32 or result.get("user_ecall_count") != 12 or
                result.get("successful_head_count") != 20 or len(sites) != 92 or len(registers["operations"]) != 64):
            raise RuntimeError("incomplete message-port privilege result/site records")
        if result.get("csr_count") != 12 or result.get("message_width") != (4 if case == "primary" else 8):
            raise RuntimeError("privilege normalized CSR/width counts disagree with the audited cases")
        elf, pre, memory = ((directory / name).read_bytes() for name in ("kernel.elf", "prestart.bin", "output.bin"))
        if elf[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", elf, 18)[0] != 243:
            raise RuntimeError("privilege ELF is not little-endian RISC-V ELF64")
        phoff, phsize, phcount = struct.unpack_from("<Q", elf, 32)[0], *struct.unpack_from("<HH", elf, 54)
        segments = [struct.unpack_from("<II6Q", elf, phoff + i * phsize) for i in range(phcount)]
        def offset(address, size=4, executable=True):
            matches = [p[2] + address - p[3] for p in segments if p[0] == 1 and (not executable or p[1] & 1)
                       and p[3] <= address and address + size <= p[3] + p[5]]
            if len(matches) != 1:
                raise RuntimeError("privilege address lacks one PT_LOAD mapping")
            return matches[0]
        syms = {k: int(v, 16) for k, v in layout["symbols"].items()}
        start, size = int(layout["monitor_address"], 16), layout["monitor_size"]
        data_offset = offset(start, size, False)
        if len(pre) != size or len(memory) != size or pre != elf[data_offset:data_offset + size] or \
                memory != (directory / "expected.bin").read_bytes():
            raise RuntimeError("privilege input/output/ELF memory mismatch")
        trace = (directory / "trace.log").read_text()
        if "Finishing emulation" not in trace or "Error, max cycles reached" in trace or "unlocked!" in trace or \
                re.search(r"(?:Start|Stop) waiting for message", trace):
            raise RuntimeError("privilege diagnostic stalled or did not complete")
        observed, current = {}, None
        for line in trace.splitlines():
            match = re.match(r"^(\d+): DEBUG EMU: \[(H\d+) .*?\] I\(([MSU])\): 0x([0-9a-f]+) \(0x([0-9a-f]{8})\)", line)
            if match:
                cycle, hart, mode, pc, word = match.groups()
                current = dict(cycle=int(cycle), hart=hart, mode=mode, pc=int(pc, 16), word=int(word, 16), registers={}, raw=[], accesses=[])
                observed.setdefault(int(pc, 16), []).append(current)
            if current is not None:
                current["raw"].append(line)
                reg = re.search(r"\bx(\d+) ([=:]) 0x([0-9a-f]+)", line)
                if reg:
                    current["registers"][(int(reg[1]), reg[2])] = int(reg[3], 16)
                access = re.search(r"MEM(8|16|32|64)\[0x([0-9a-f]+)\] ([=:]) 0x([0-9a-f]+)", line)
                if access:
                    current["accesses"].append((int(access[1]), int(access[2], 16), access[3], int(access[4], 16)))
        if {e["hart"] for events in observed.values() for e in events} != {"H0"}:
            raise RuntimeError("unexpected hart in privilege trace")
        def event(label, mode="M"):
            events = observed.get(syms[label], [])
            if len(events) != 1 or events[0]["mode"] != mode:
                raise RuntimeError(f"missing actual {mode} instruction at {label}")
            return events[0]
        relative = lambda name: syms[name] - start
        expected = bytearray(pre)
        width, way, flags = (4, 1, 0) if case == "primary" else (8, 2, 2)
        values = struct.unpack_from("<16Q", pre, relative("input_payloads"))
        inputs = [(0xABCDEF0000000000 | (0x81234567 + p * 0x1010101 + i * 0x11111111)) if case == "primary" else
                  (0xFEDCBA9876543210 ^ (p * 0x1111111111111111) ^ (i * 0x102030405060708)) for p in range(4) for i in range(4)]
        if values != tuple(inputs):
            raise RuntimeError("privilege deterministic ELF inputs differ")
        feature = struct.unpack_from("<3Q", memory, relative("feature_state"))
        if feature[1] != feature[0] & ~0x2E or feature[2] & 8:
            raise RuntimeError("wrong actual privilege feature/interrupt setup")
        for label, value in zip(("feature_before", "feature_after", "status_initial"), feature):
            if event(label)["registers"][(5, "=")] != value:
                raise RuntimeError("privilege setup snapshot differs from real read")
        expected[relative("feature_state"):relative("feature_state") + 24] = struct.pack("<3Q", *feature)
        names = set()
        for p in range(4):
            for phase in ("deny", "allow", "disabled"):
                names.add(f"p{p}_{phase}_config")
                names.add(f"p{p}_{phase}_exit")
                names.update(f"p{p}_{phase}_u_{suffix}" for suffix in ("head", "headnb"))
                if phase != "disabled":
                    names.update(f"p{p}_{phase}_{suffix}" for suffix in ("send0", "send1", "u_control"))
                if phase == "allow": names.add(f"p{p}_{phase}_u_empty")
                else: names.update(f"p{p}_{phase}_m_{suffix}" for suffix in ("head", "headnb"))
            lock = event(f"lock_{p}")
            address, pos = syms[f"target_{p}"] + 64, relative(f"target_{p}") + 64
            raw = "\n".join(lock["raw"])
            if not re.search(rf"MEM512\[0x0*{address:x}\] = \{{(?:\s*\d+:0x00000000){{16}}\s*\}}", raw) or \
                    pre[pos - 64:pos + 128] != bytes([0xA5]) * 192:
                raise RuntimeError("privilege backing-memory lock/guards lack raw evidence")
            expected[pos:pos + 64] = bytes(64)
            for phase in ("deny", "allow", "disabled"):
                entered = event(f"enter_p{p}_{phase}")
                if entered["word"] != 0x30200073 or "prv = U" not in "\n".join(entered["raw"]) or \
                        not 0x8004000000 <= syms[f"user_p{p}_{phase}"] < 0x8100000000:
                    raise RuntimeError("actual mret/U-mode entry or permitted user address missing")
        if {s["name"] for s in sites} != names:
            raise RuntimeError("privilege selected sites do not cover all four port permission paths")
        snapshots = {r["name"]: r for r in registers["operations"]}
        captures = {k: observed.get(syms[f"capture_{k}"], []) for k in ("cause", "epc", "tval", "status")}
        trap_logs = re.findall(r"\[H0 S0:N0:C0:T0\].*Trapping to M-mode with cause 0x([0-9a-f]+) and tval 0x([0-9a-f]+)", trace)
        if len(trap_logs) != 44 or any(len(rows) != 44 or any(e["mode"] != "M" for e in rows) for rows in captures.values()):
            raise RuntimeError("privilege fault count/handler modes disagree")
        fault_index, verified = 0, []
        for site in sites:
            name = site["name"]
            p, phase, suffix = re.fullmatch(r"p([0-3])_(deny|allow|disabled)_(.+)", name).groups()
            p = int(p)
            kind = "config" if suffix == "config" else "send" if suffix.startswith("send") else "ecall" if suffix == "exit" else "read"
            mode = "U" if suffix == "exit" or suffix.startswith("u_") else "M"
            cause = 8 if kind == "ecall" else 2 if kind == "read" and (phase == "disabled" or suffix.endswith("control") or mode == "U" and phase == "deny") else 0
            actual = event(f"op_{name}", mode)
            pc, word = actual["pc"], actual["word"]
            filepos = offset(pc)
            if word != int(site["word"], 16) or elf[filepos:filepos + 4] != bytes.fromhex(site["bytes_memory_order"]) or \
                    filepos != int(site["file_offset"], 16) or int.from_bytes(elf[filepos:filepos + 4], "little") != word or \
                    site["mode"] != mode or site["kind"] != kind or site.get("cause", 0) != cause:
                raise RuntimeError("privilege ELF/instruction/permission metadata disagrees")
            if kind in ("config", "read"):
                family = "ctrl" if kind == "config" or suffix.endswith("control") else "head" if suffix.endswith("_head") else "headnb"
                csr = declarations[f"port{family}{p}"]
                if (word & 127, word >> 20, word >> 12 & 7, word >> 7 & 31, word >> 15 & 31) != \
                        (0x73, csr, 1 if kind == "config" else 2, 0 if kind == "config" else 20, 6 if kind == "config" else 0):
                    raise RuntimeError("privilege actual SYSTEM/CSR encoding differs")
            elif kind == "ecall" and word != 0x73:
                raise RuntimeError("wrong encoded U ECALL")
            elif kind == "send" and (word & 127, word >> 12 & 7, word >> 15 & 31, word >> 20 & 31) != (0x23, 3, 7, 6):
                raise RuntimeError("wrong encoded privilege device send")
            if kind == "config":
                address = syms[f"target_{p}"] + 64
                control = (way << 24) | (((address >> 6) & 15) << 16) | 0x100 | ((width.bit_length() - 1) << 5) | flags | \
                          (0x10 if phase != "deny" else 0) | int(phase != "disabled") | 0x8000
                if actual["registers"][(6, ":")] != control & ~0x8000 or \
                        event(f"control_{name}")["registers"][(5, "=")] != control:
                    raise RuntimeError("privilege actual config operand/readback differs")
                expected[relative(f"control_record_{name}"):relative(f"control_record_{name}") + 8] = struct.pack("<Q", control)
            elif kind == "send":
                slot = int(suffix[-1])
                index = p * 4 + slot + (2 if phase == "allow" else 0)
                value = values[index]
                source = event(f"input_{name}")
                address = syms[f"target_{p}"] + 64 + slot * width
                wanted = [(p, value >> (i * 32) & 0xFFFFFFFF, address + 4 * i) for i in range(width // 4)]
                delivery = [(int(q), int(v, 16), int(a, 16)) for q, v, a in re.findall(
                    r"Writing MSG_PORT \(H0 p(\d+)\) data 0x([0-9a-f]+) to addr 0x\s*([0-9a-f]+)", "\n".join(actual["raw"]))]
                if source["registers"][(6, "=")] != value or source["accesses"] != [(64, syms["input_payloads"] + index * 8, ":", value)] or \
                        actual["registers"] != {(6, ":"): value, (7, ":"): 0x0100000800 + p * 64} or \
                        actual["accesses"] != [(64, 0x0100000800 + p * 64, "=", value)] or delivery != wanted:
                    raise RuntimeError("privilege sender/input/receiver raw evidence differs")
                pos = relative(f"target_{p}") + 64 + slot * width
                expected[pos:pos + width] = value.to_bytes(8, "little")[:width]
            else:
                pos = relative(f"record_{name}")
                record = struct.unpack_from("<8Q", memory, pos)
                seed, sentinel = 0x5AA55AA55AA55AA5, 0xA5A5A5A5A5A5A5A5
                wanted = [seed, seed, sentinel, sentinel, sentinel, sentinel, sentinel, sentinel]
                if event(f"before_{name}", mode)["registers"][(20, ":")] != seed or \
                        event(f"after_{name}", "M" if kind == "ecall" else mode)["registers"][(20, ":")] != record[1]:
                    raise RuntimeError("privilege before/after destination lacks real snapshot evidence")
                if cause:
                    states = [captures[k][fault_index]["registers"][(5, "=")] for k in ("cause", "epc", "tval", "status")]
                    tval = 0 if kind == "ecall" else word
                    if states[:3] != [cause, pc, tval] or (states[3] >> 11 & 3) != (0 if mode == "U" else 3) or \
                            tuple(int(x, 16) for x in trap_logs[fault_index]) != (cause, tval) or (20, "=") in actual["registers"]:
                        raise RuntimeError("privilege actual cause/epc/tval/MPP/destination disagrees")
                    wanted[2:6] = states
                    fault_index += 1
                else:
                    slot = None if suffix.endswith("empty") else 0 if suffix.endswith("_head") else 1
                    returned = (1 << 64) - 1 if slot is None else slot * width
                    if actual["registers"][(20, "=")] != returned:
                        raise RuntimeError("privilege actual successful head return differs")
                    wanted[1] = returned
                    if slot is not None:
                        value = values[p * 4 + slot + (2 if phase == "allow" else 0)] & ((1 << (width * 8)) - 1)
                        address = syms[f"target_{p}"] + 64 + returned
                        load = event(f"payload_{name}", mode)
                        if load["registers"][(9, "=")] != value or load["registers"][(25, ":")] != address or \
                                load["accesses"] != [(width * 8, address, ":", value)] or \
                                (load["word"] & 127, load["word"] >> 12 & 7) != (3, 6 if width == 4 else 3):
                            raise RuntimeError("privilege payload load lacks actual memory/unsigned encoding evidence")
                        wanted[6:8] = [value, address]
                if record != tuple(wanted) or snapshots[name]["actual"] != [hex(v) for v in record] or \
                        pre[pos:pos + 128] != bytes([0xA5]) * 128:
                    raise RuntimeError("privilege normalized snapshots disagree with raw execution")
                expected[pos:pos + 64] = struct.pack("<8Q", *wanted)
            verified.append(dict(name=name, mode=mode, pc=hex(pc), word=hex(word), cause=cause, cycle=actual["cycle"]))
        event("park")
        expected[relative("completion"):relative("completion") + 4] = struct.pack("<I", 0x4B4F5445)
        if memory != expected:
            raise RuntimeError("privilege entire reconstructed monitor/guards/completion differ")
        runs.append(dict(run=run_name, case=case, instruction_count=92, csr_count=12, message_width=width,
                         illegal_trap_count=32, user_ecall_count=12, successful_head_count=20, verified_operations=verified,
                         sha256={name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in required}))
    paths = ("csrs.h", "msgport.cpp", "processor.h", "memmap.h", "pma_et.cpp", "mmu.cpp", "emu_gio.h",
             "insn_util.h", "insns/system.cpp", "insns/zicsr.cpp", "esrs_et.cpp", "processor.cpp")
    report = dict(et_platform_commit=commit, scope="real M/U permissions on all four message ports; denied reads retain messages, enabled U reads, disabled M/U faults and U control privilege faults",
                  verified_runs=runs, runs_missing_evidence=missing,
                  limitations=["S-mode and U-mode blocking/wake unverified", "read-only CSR write side effects unverified", "nonzero OOB and 16/32-byte delivery engines unverified"],
                  source_sha256={"sw-sysemu/" + name: hashlib.sha256((source_root / "sw-sysemu" / name).read_bytes()).hexdigest() for name in paths})
    (ROOT / "out/isa/message-port-privilege-inventory.json").write_text(json.dumps(report, indent=2) + "\n")
    return report, missing


def synchronization_peer_evidence(source_root: Path, commit: str) -> tuple[dict[str, object], list[str]]:
    """Audit both threads' FCC routes, restart/overflow and ordered FLB arrivals."""
    names = {"fcc", "fccnb", "flb"}
    declarations = {name: int(number, 16) for number, name in re.findall(
        r"CSRDEF\((0x[0-9a-f]+),\s*(\w+),", (source_root / "sw-sysemu/csrs.h").read_text()) if name in names}
    if set(declarations) != names:
        raise RuntimeError("peer synchronization CSR declarations changed")
    esrs = {int(index): int(address, 16) for index, address in re.findall(
        r"#define ESR_FCC_CREDINC_([0-3])\s+(0x[0-9a-fA-F]+)ULL", (source_root / "sw-sysemu/esrs_et.cpp").read_text())}
    if esrs != {index: 0x01003400C0 + index * 8 for index in range(4)}:
        raise RuntimeError("peer synchronization FCC ESR declarations changed")
    runs, missing = [], []
    routes = set()
    cases = (("primary", 0, 3, 1, "H0", "H2", 0x01003400C0),
             ("exact", 1, 31, (1 << 63) | 1, "H0", "H2", 0x01003400C0),
             ("threads-primary", 0, 3, 1, "H1", "H0", 0x01003400D0),
             ("threads-exact", 1, 31, (1 << 63) | 1, "H1", "H0", 0x01003400D0))
    for case, counter, barrier, mask, rx_hart, tx_hart, credit_base in cases:
        directory = ROOT / "out/synchronization-peers" / ("" if case == "primary" else case)
        required = ("result.json", "elf-layout.json", "kernel.elf", "kernel.S", "trace.log", "output.bin",
                    "prestart.bin", "expected.bin", "registers.json", "operations.json")
        run_name = str(directory.relative_to(ROOT))
        if any(not (directory / name).is_file() for name in required):
            missing.append(run_name)
            continue
        result = json.loads((directory / "result.json").read_text())
        layout = json.loads((directory / "elf-layout.json").read_text())
        sites = json.loads((directory / "operations.json").read_text())
        thread_case = case.startswith("threads")
        site_count, stage_count = (12, 10) if thread_case else (10, 8)
        if (result.get("case") != case or not result.get("pass") or not result.get("whole_monitor_matches") or
                result.get("operation_count") != site_count or result.get("stage_count") != stage_count or
                len(sites) != site_count or len(result["stages"]) != stage_count or
                layout["selected_harts"] != sorted([rx_hart, tx_hart]) or
                layout["receiver_hart"] != rx_hart or layout["sender_hart"] != tx_hart):
            raise RuntimeError(f"peer synchronization validation/sites incomplete: {run_name}")
        syms = {name: int(addr, 16) for name, addr in layout["symbols"].items()}
        elf, memory, pre = ((directory / name).read_bytes() for name in ("kernel.elf", "output.bin", "prestart.bin"))
        if elf[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", elf, 18)[0] != 243:
            raise RuntimeError("peer synchronization ELF is not little-endian RISC-V ELF64")
        phoff, phsize, phcount = struct.unpack_from("<Q", elf, 32)[0], *struct.unpack_from("<HH", elf, 54)
        segments = [struct.unpack_from("<II6Q", elf, phoff + i * phsize) for i in range(phcount)]
        def file_offset(address, size=4, executable=True):
            matches = [row[2] + address - row[3] for row in segments if row[0] == 1 and (not executable or row[1] & 1)
                       and row[3] <= address and address + size <= row[3] + row[5]]
            if len(matches) != 1:
                raise RuntimeError("peer synchronization address lacks one PT_LOAD mapping")
            return matches[0]
        start, size = int(layout["monitor_address"], 16), layout["monitor_size"]
        data_offset = file_offset(start, size, False)
        if (len(memory) != size or pre != elf[data_offset:data_offset + size] or memory != (directory / "expected.bin").read_bytes() or
                struct.unpack_from("<4Q", pre, syms["input_controls"] - start) != (counter, barrier, mask, 65535)):
            raise RuntimeError("peer synchronization input/guarded memory does not match ELF/reference")
        by_pc = {int(row["pc"], 16): row for row in sites}
        if len(by_pc) != site_count:
            raise RuntimeError("peer synchronization PCs are not unique")
        for pc, site in by_pc.items():
            expected_hart = tx_hart if site["name"] in ("sender_other", "sender_credit", "flb_sender", "wrong_thread", "consume_thread") else rx_hart
            if site["hart"] != expected_hart or pc != syms["op_" + site["name"]]:
                raise RuntimeError("peer synchronization operation hart/symbol disagrees")
            word, offset = int(site["word"], 16), file_offset(pc)
            if elf[offset:offset + 4] != word.to_bytes(4, "little") or int(site["file_offset"], 16) != offset:
                raise RuntimeError("peer synchronization operation bytes/mapping disagree")
            if site["csr"]:
                csr_name = "flb" if site["name"].startswith("flb") else "fcc"
                if (word & 0x7F, word >> 20, word >> 12 & 7, word >> 7 & 31, word >> 15 & 31) != (0x73, declarations[csr_name], 1, 20, 6):
                    raise RuntimeError("peer synchronization CSR encoding disagrees")
            elif (word & 0x7F, word >> 12 & 7, word >> 15 & 31, word >> 20 & 31, word >> 25, word >> 7 & 31) != (0x23, 3, 7, 6, 0, 0):
                raise RuntimeError("peer synchronization increment is not the declared device SD")
        observed, current, bulk_count, harts, waits = {}, None, 0, set(), []
        wanted = set(syms.values())
        instruction = re.compile(r"^(\d+): DEBUG EMU: \[(H\d+) .*?\] I\(M\): 0x([0-9a-f]+) \(0x([0-9a-f]{8})\)")
        scalar = re.compile(r"\bx(\d+) ([=:]) 0x([0-9a-f]+)")
        memory_event = re.compile(r"MEM(8|16|32|64)\[0x([0-9a-f]+)\] ([=:]) 0x([0-9a-f]+)")
        receiver = re.compile(r"\[(H\d+) .*?\].*Receiving credits: fcc0 = 0x([0-9a-f]+), fcc1 = 0x([0-9a-f]+)")
        wait_event = re.compile(r"^(\d+): DEBUG EMU: \[(H\d+) .*?\]\s+(Start|Stop) waiting for FCC([01])$")
        def finish(event):
            nonlocal bulk_count
            if event is None:
                return
            if event["pc"] != syms["op_bulk"]:
                observed.setdefault((event["hart"], event["pc"]), []).append(event)
                return
            bulk_count += 1
            packed = bulk_count << (16 * counter)
            if (event["hart"] != rx_hart or event["word"] != int(by_pc[event["pc"]]["word"], 16) or
                    event["registers"] != {(7, ":"): credit_base + counter * 8, (6, ":"): mask} or
                    event["memory"] != [(64, credit_base + counter * 8, "=", mask)] or
                    event["credits"] != [(rx_hart, packed & 65535, packed >> 16)]):
                raise RuntimeError(f"peer synchronization bulk increment {bulk_count} lacks real matching evidence")
        finished = False
        with (directory / "trace.log").open() as stream:
            for line in stream:
                if "Error, max cycles reached" in line or "Trapping to" in line:
                    raise RuntimeError("peer synchronization trace did not complete normally")
                finished |= "Finishing emulation" in line
                match = wait_event.match(line.rstrip())
                if match:
                    cycle, hart, action, c = match.groups()
                    waits.append((int(cycle), hart, action, int(c)))
                match = instruction.match(line)
                if match:
                    finish(current)
                    cycle, hart, pc, word = match.groups()
                    pc = int(pc, 16)
                    harts.add(hart)
                    current = dict(cycle=int(cycle), hart=hart, pc=pc, word=int(word, 16), registers={}, memory=[], credits=[])
                    if pc not in wanted:
                        current = None
                if current is None:
                    continue
                match = scalar.search(line)
                if match:
                    current["registers"][(int(match.group(1)), match.group(2))] = int(match.group(3), 16)
                match = memory_event.search(line)
                if match:
                    bits, address, direction, value = match.groups()
                    current["memory"].append((int(bits), int(address, 16), direction, int(value, 16)))
                match = receiver.search(line)
                if match:
                    current["credits"].append((match.group(1), int(match.group(2), 16), int(match.group(3), 16)))
        finish(current)
        if not finished or bulk_count != 65535 or harts != {rx_hart, tx_hart}:
            raise RuntimeError("peer synchronization bulk count/harts/completion disagree")
        def one(name, hart=rx_hart):
            rows = observed.get((hart, syms[name]), [])
            if len(rows) != 1:
                raise RuntimeError(f"peer synchronization state lacks one real read: {name}")
            return rows[0]
        for pc, site in by_pc.items():
            if site["name"] == "bulk":
                continue
            events = observed.get((site["hart"], pc), [])
            count = 2 if site["name"] == "wait" else 1
            if len(events) != count or any(e["word"] != int(site["word"], 16) for e in events):
                raise RuntimeError("peer synchronization actual instruction/occurrence count disagrees")
            if site["csr"]:
                operand = ((1 << 13) | (1 << 5) | barrier) if site["name"].startswith("flb") else (
                    (counter ^ 1 if site["name"] == "consume_other" else counter) | 0x100)
                if any(e["registers"].get((6, ":")) != operand for e in events):
                    raise RuntimeError("peer synchronization actual FCC/FLB source operand disagrees")
        attempts = observed[(rx_hart, syms["op_wait"])]
        other_send, correct_send = one("op_sender_other", tx_hart), one("op_sender_credit", tx_hart)
        if (not attempts[0]["cycle"] < other_send["cycle"] < correct_send["cycle"] < attempts[1]["cycle"] or
                one("seed_wait")["registers"].get((20, ":")) != 0x5AA55AA55AA55AA5 or
                (20, "=") in attempts[0]["registers"] or attempts[1]["registers"].get((20, "=")) != 0 or
                waits != [(attempts[0]["cycle"], rx_hart, "Start", counter), (correct_send["cycle"], rx_hart, "Stop", counter)]):
            raise RuntimeError("peer FCC wrong-counter/no-credit wait and matching-credit restart are unproven")
        one_value, other_value, max_value = 1 << (16 * counter), 1 << (16 * (counter ^ 1)), 65535 << (16 * counter)
        for name, selected, packed in (("sender_other", counter ^ 1, other_value), ("sender_credit", counter, other_value | one_value),
                                       ("wrap", counter, 0), ("refill", counter, one_value)):
            event = one("op_" + name, tx_hart if name.startswith("sender") else rx_hart)
            if (event["registers"] != {(7, ":"): credit_base + selected * 8, (6, ":"): mask} or
                    event["memory"] != [(64, credit_base + selected * 8, "=", mask)] or
                    event["credits"] != [(rx_hart, packed & 65535, packed >> 16)]):
                raise RuntimeError("peer boundary credit lacks matching ESR store/receiver counters")
        wrong_thread = one("op_wrong_thread", tx_hart) if thread_case else None
        if wrong_thread and (not attempts[0]["cycle"] < wrong_thread["cycle"] < other_send["cycle"] or
                wrong_thread["registers"] != {(7, ":"): 0x01003400C0 + counter * 8, (6, ":"): mask} or
                wrong_thread["memory"] != [(64, 0x01003400C0 + counter * 8, "=", mask)] or
                wrong_thread["credits"] != [(tx_hart, one_value & 65535, one_value >> 16)]):
            raise RuntimeError("T0 credit delivery while T1 waits is unproven")
        if wrong_thread and not wrong_thread["cycle"] < one("op_consume_thread", tx_hart)["cycle"] < other_send["cycle"]:
            raise RuntimeError("T0 did not consume its own credit before the T1 send")
        references = {"wait": (0, other_value, 0, 0), "consume_other": (other_value, 0, 0, 0),
                      "flb_receiver": (0, 1, 0, 0), "flb_sender": (1, 0, 1, 0),
                      "bulk": (0, max_value, 0x5AA55AA55AA55AA5, 0), "wrap": (max_value, 0, 0x5AA55AA55AA55AA5, 8),
                      "refill": (0, one_value, 0x5AA55AA55AA55AA5, 0), "consume_refill": (one_value, 0, 0, 0)}
        if thread_case:
            references.update(wrong_thread=(0, one_value, 0x5AA55AA55AA55AA5, 0), consume_thread=(one_value, 0, 0, 0))
        if {row["name"] for row in result["stages"]} != set(references):
            raise RuntimeError("peer snapshot stages differ from independently defined cases")
        for row in result["stages"]:
            name, hart = row["name"], row["hart"]
            if hart != (tx_hart if name in ("flb_sender", "wrong_thread", "consume_thread") else rx_hart):
                raise RuntimeError("peer snapshot is attributed to the wrong hart")
            before, after = one("before_" + name, hart), one("after_" + name, hart)
            actual = [before["registers"][(21, "=")], after["registers"][(22, "=")], one("capture_s4_" + name, hart)["registers"][(20, ":")]]
            for field, csr, rd in (("error", 0x808, 23), ("status", 0x300, 24), ("enabled", 0x304, 25), ("pending", 0x344, 26), ("hart", 0xF14, 27)):
                event = one("read_" + field + "_" + name, hart)
                if event["word"] != (csr << 20) | (2 << 12) | (rd << 7) | 0x73:
                    raise RuntimeError("peer snapshot CSR word is not the declared state read")
                actual.append(event["registers"][(rd, "=")])
            if not name.startswith("flb"):
                for event, rd in ((before, 21), (after, 22)):
                    if event["word"] != (declarations["fccnb"] << 20) | (2 << 12) | (rd << 7) | 0x73:
                        raise RuntimeError("peer before/after state did not read FCCNB")
            if (tuple(actual[:4]) != references[name] or actual[4] & 8 or actual[5:] != [0, 0, int(hart[1:])] or
                    tuple(actual) != struct.unpack_from("<8Q", memory, syms["record_" + name] - start) or
                    [f"0x{v:x}" for v in actual] != row["actual"] or row["actual"] != row["expected"] or not row["pass"]):
                raise RuntimeError("peer real scalar reads/snapshots/reference disagree")
            if name.startswith("flb"):
                address = 0x0100340100 + barrier * 8
                if (before["memory"] != [(64, address, ":", actual[0])] or after["memory"] != [(64, address, ":", actual[1])] or
                        one("op_" + name, hart)["registers"].get((20, "=")) != actual[2]):
                    raise RuntimeError("peer FLB ESR loads/return disagree with snapshots")
            elif name not in ("bulk", "wrap", "refill", "wrong_thread"):
                event = attempts[-1] if name == "wait" else one("op_" + name, hart)
                if event["registers"].get((20, "=")) != actual[2]:
                    raise RuntimeError("peer FCC destination write disagrees with snapshot")
        proof = result["proof"]
        captured = json.loads((directory / "registers.json").read_text())
        if captured["stages"] != result["stages"] or captured["proof"] != proof:
            raise RuntimeError("peer register report disagrees with independently audited state")
        if (proof["counter"] != counter or proof["bulk_increment_count"] != bulk_count or proof["overflow_error"] != "0x8" or
                proof["receiver_hart"] != rx_hart or proof["sender_hart"] != tx_hart or
                proof["credit_esr"] != hex(correct_send["registers"][(7, ":")]) or
                proof["wrong_thread_credit_cycle"] != (wrong_thread["cycle"] if wrong_thread else None) or
                proof["other_credit_cycle"] != other_send["cycle"] or proof["matching_credit_cycle"] != correct_send["cycle"] or
                proof["retry_pc"] != hex(syms["op_wait"]) or proof["destination_after"] != "0x0" or
                proof["barrier"] != barrier or proof["flb_arrival_harts"] != [rx_hart, tx_hart] or
                proof["wait_cycles"] != [e["cycle"] for e in attempts] or proof["destination_written_on_first_attempt"] or
                struct.unpack_from("<2Q", memory, syms["handshake"] - start) != (2, 1) or
                struct.unpack_from("<2Q", memory, syms["final_state"] - start) != (0, 0x5A) or
                struct.unpack_from("<IIQ", memory, syms["completion"] - start) != (0x4B4F5445, 0, 0)):
            raise RuntimeError("peer proof/completion/guarded memory disagree")
        if one("op_flb_receiver")["cycle"] >= one("op_flb_sender", tx_hart)["cycle"]:
            raise RuntimeError("peer FLB arrivals are not ordered by the handshake")
        routes.add(correct_send["registers"][(7, ":")])
        runs.append(dict(run=run_name, **{"pass": True}, validated_sites=site_count, bulk_increment_count=bulk_count, proof=proof,
                         sha256={name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in required}))
    paths = ("csrs.h", "esrs_et.cpp", "flb.cpp", "system.cpp", "processor.cpp", "processor.h", "insns/zicsr.cpp", "insn_util.h")
    report = dict(et_platform_commit=commit, scope="T0/T1 FCC0/FCC1 routing, block/wake/restart, wrong-thread isolation, 16-bit overflow and ordered FLB arrivals",
        csr_declarations={name: f"0x{number:03x}" for name, number in sorted(declarations.items())}, verified_runs=runs,
        verified_credit_esr_routes=[hex(address) for address in sorted(routes)],
        runs_missing_evidence=missing, limitations=["ordered FLB arrivals; simultaneous contention/coherence not covered", "T1 coverage is FCC routing and ordered FLB; other T1-specific state untested"],
        source_sha256={"sw-sysemu/" + path: hashlib.sha256((source_root / "sw-sysemu" / path).read_bytes()).hexdigest() for path in paths})
    target = ROOT / "out/isa/synchronization-peer-inventory.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2) + "\n")
    return report, missing


def scalar_fp_evidence(source_root: Path, commit: str) -> tuple[dict[str, object], list[str]]:
    """Audit all scalar FP handlers using real trace groups and guarded memory."""
    handlers = {name: row for name, row in definitions(source_root / 'sw-sysemu/insns').items()
                if row['source'] == 'insns/float.cpp'}
    normal = {row['mnemonic'] for row in handlers.values() if not row['trap_stub']}
    faults = {row['mnemonic'] for row in handlers.values() if row['trap_stub']}
    if (len(normal), len(faults)) != (22, 6):
        raise RuntimeError('pinned scalar FP handler inventory changed')
    runs, missing = [], []
    for case in ('primary', 'exact'):
        directory = ROOT / 'out/scalar-fp' / ('' if case == 'primary' else case)
        required = ('result.json','elf-layout.json','kernel.elf','kernel.S','trace.log','output.bin',
                    'prestart.bin','expected.bin','registers.json','operations.json','text.bin','symbols.txt','commands.log')
        run_name = str(directory.relative_to(ROOT))
        if any(not (directory/name).is_file() for name in required):
            missing.append(run_name)
            continue
        result, layout, sites, registers = (json.loads((directory/name).read_text()) for name in
                                            ('result.json','elf-layout.json','operations.json','registers.json'))
        if not result.get('pass') or (result['operation_count'],result['nontrapping_handler_count'],result['trap_stub_count'],result['trap_count']) != (31,22,6,6):
            raise RuntimeError('incomplete scalar FP result counts')
        if len(sites)!=31 or len(registers['operations'])!=31:
            raise RuntimeError('incomplete scalar FP operation/register records')
        if {s['mnemonic'] for s in sites if not s['cause']}!=normal or {s['mnemonic'] for s in sites if s['cause']}!=faults:
            raise RuntimeError('scalar FP source handlers lack complete operation coverage')
        elf, pre, memory = ((directory/name).read_bytes() for name in ('kernel.elf','prestart.bin','output.bin'))
        if elf[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',elf,18)[0]!=243:
            raise RuntimeError('scalar FP ELF architecture mismatch')
        entry, phoff, shoff = struct.unpack_from('<3Q',elf,24)
        phsize, phcount, shsize, shcount, strings = struct.unpack_from('<5H',elf,54)
        segments = [struct.unpack_from('<II6Q',elf,phoff+i*phsize) for i in range(phcount)]
        sections = [struct.unpack_from('<II4QII2Q',elf,shoff+i*shsize) for i in range(shcount)]
        names = elf[sections[strings][4]:sections[strings][4]+sections[strings][5]]
        sections = {names[s[0]:].split(b'\0',1)[0].decode():s for s in sections}
        if [name for name,s in sections.items() if s[2]&4 and s[5]]!=['.text'] or int(layout['entry'],16)!=entry:
            raise RuntimeError('scalar FP executable section/entry mismatch')
        text = sections['.text']
        if (directory/'text.bin').read_bytes()!=elf[text[4]:text[4]+text[5]]:
            raise RuntimeError('scalar FP text bytes differ from ELF section')
        start, size = int(layout['monitor_address'],16),layout['monitor_size']
        mappings = [p[2]+start-p[3] for p in segments if p[0]==1 and p[3]<=start and start+size<=p[3]+p[5]]
        if len(mappings)!=1 or len(pre)!=size or len(memory)!=size or pre!=elf[mappings[0]:mappings[0]+size]:
            raise RuntimeError('scalar FP complete pre-execution monitor differs from ELF input bytes')
        syms = {s[2]:int(s[0],16) for line in (directory/'symbols.txt').read_text().splitlines() if len(s:=line.split())==3}
        trace = (directory/'trace.log').read_text()
        if 'Finishing emulation' not in trace or 'Error, max cycles reached' in trace:
            raise RuntimeError('scalar FP lacks normal simulator completion')
        events, current = [], None
        for line in trace.splitlines():
            match = re.match(r'^\d+: DEBUG EMU: \[(H\d+ S\d+:N\d+:C\d+:T\d+)\] I\(M\): 0x([0-9a-f]+) \(0x([0-9a-f]{8})\) (.*)$',line)
            if match:
                current = dict(hart=match[1],pc=int(match[2],16),word=int(match[3],16),decoded=match[4],regs={})
                events.append(current)
            elif current is not None:
                match = re.search(r'\b(f\d+) ([=:]) \{([^}]+)\}',line)
                if match:
                    words = tuple(int(x,16) for x in re.findall(r'\d+:0x([0-9a-f]{8})',match[3]))
                    if len(words)!=8: raise RuntimeError('scalar FP incomplete actual vector register event')
                    current['regs'][match[1]+match[2]]=words
                match = re.search(r'\b(x\d+) ([=:]) 0x([0-9a-f]+)',line)
                if match: current['regs'][match[1]+match[2]]=int(match[3],16)
        if any(e['hart']!='H0 S0:N0:C0:T0' for e in events):
            raise RuntimeError('scalar FP unexpected executing hart')
        def event(label):
            matches = [e for e in events if e['pc']==syms[label]]
            if len(matches)!=1: raise RuntimeError(f'scalar FP missing/repeated actual site: {label}')
            return matches[0]
        state, before = {}, {}
        pcs = {int(s['pc'],16) for s in sites}
        for e in events:
            if e['pc'] in pcs: before[e['pc']]=dict(state)
            for key, value in e['regs'].items():
                if key.endswith('='): state[key[:-1]]=value
        expected, trap_index = bytearray(pre), 0
        actual_traps = re.findall(r'\[(H\d+ S\d+:N\d+:C\d+:T\d+)\].*Trapping to M-mode with cause 0x([0-9a-f]+) and tval 0x([0-9a-f]+)',trace)
        csr_events = {csr:[e for e in events if e['pc']==syms['capture_'+csr]] for csr in ('mcause','mepc','mtval','mstatus')}
        for site,row in zip(sites,registers['operations']):
            name, mnemonic, pc = site['name'],site['mnemonic'],int(site['pc'],16)
            op = event('op_'+name)
            offsets = [p[2]+pc-p[3] for p in segments if p[0]==1 and p[1]&1 and p[3]<=pc and pc+4<=p[3]+p[5]]
            raw = bytes.fromhex(site['bytes_memory_order'])
            if len(offsets)!=1 or raw!=elf[offsets[0]:offsets[0]+4] or offsets[0]!=int(site['file_offset'],16):
                raise RuntimeError('scalar FP operation PC/file-offset bytes mismatch')
            word = int.from_bytes(raw,'little')
            if word!=int(site['word'],16) or word!=op['word'] or not op['decoded'].startswith(mnemonic):
                raise RuntimeError('scalar FP assembled bytes differ from actual execution')
            if word&127 not in (0x53,0x43,0x47,0x4B,0x4F) or word>>7&31!=20:
                raise RuntimeError('scalar FP operation opcode/destination mismatch')
            source = before[pc]
            for reg in ('f10','f11','f13'):
                address = syms[f'input_{name}_{reg}']-start
                loaded = struct.unpack_from('<8I',pre,address)
                if source.get(reg)!=loaded or event(f'load_{name}_{reg}')['regs'].get(reg+'=')!=loaded:
                    raise RuntimeError('scalar FP input lacks actual full-register load evidence')
                if row['inputs_before'][reg]['raw_u32']!=[f'0x{x:08x}' for x in loaded]:
                    raise RuntimeError('normalized scalar FP source state differs from actual events')
            aw,bw,cw = (source[r][0] for r in ('f10','f11','f13'))
            a,b,c = (struct.unpack('<f',struct.pack('<I',x))[0] for x in (aw,bw,cw))
            fbefore, fafter = (event(f'{phase}_{name}')['regs'].get('f20:') for phase in ('before','after'))
            xbefore, xafter = (event(f'x_{phase}_{name}')['regs'].get('x20:') for phase in ('before','after'))
            masks = tuple(event(f'mask_{phase}_{name}')['regs'].get('x5=') for phase in ('before','after'))
            controls = tuple(event(f'fcsr_{phase}_{name}')['regs'].get('x5=') for phase in ('before','after'))
            if fbefore!=(0xA5A5A5A5,)*8 or source.get('f20')!=fbefore or xbefore!=0x5AA55AA55AA55AA5 or source.get('x20')!=xbefore:
                raise RuntimeError('scalar FP pre-operation destination not actually seeded')
            fp_result, int_result, flags = None, None, 0
            arithmetic = {'fadd.s':a+b,'fsub.s':a-b,'fmul.s':a*b,'fmadd.s':a*b+c,
                          'fmsub.s':a*b-c,'fnmadd.s':-(a*b+c),'fnmsub.s':-a*b+c,'fmin.s':min(a,b),'fmax.s':max(a,b)}
            if not site['cause']:
                if mnemonic in arithmetic: fp_result=struct.unpack('<I',struct.pack('<f',arithmetic[mnemonic]))[0]
                elif mnemonic.startswith('fsgnj'):
                    sign = bw&0x80000000 if mnemonic=='fsgnj.s' else (~bw)&0x80000000 if mnemonic=='fsgnjn.s' else (aw^bw)&0x80000000
                    fp_result=(aw&0x7FFFFFFF)|sign
                elif mnemonic in ('fcvt.w.s','fcvt.wu.s'):
                    rounded = int(a) if word>>12&7==1 else round(a)
                    flags=int(rounded!=a)
                    int_result=rounded&0xFFFFFFFF
                    if int_result&0x80000000: int_result|=0xFFFFFFFF00000000
                elif mnemonic in ('fcvt.s.w','fcvt.s.wu'):
                    integer=source['x5']&0xFFFFFFFF
                    if mnemonic=='fcvt.s.w' and integer&0x80000000: integer-=1<<32
                    fp_result=struct.unpack('<I',struct.pack('<f',float(integer)))[0]
                    flags=int(struct.unpack('<f',struct.pack('<I',fp_result))[0]!=integer)
                elif mnemonic=='fmv.w.x': fp_result=source['x5']&0xFFFFFFFF
                elif mnemonic=='fmv.x.w': int_result=aw|(0xFFFFFFFF00000000 if aw&0x80000000 else 0)
                elif mnemonic in ('feq.s','fle.s','flt.s'): int_result=int(a==b if mnemonic=='feq.s' else a<=b if mnemonic=='fle.s' else a<b)
                elif mnemonic=='fclass.s':
                    exponent,fraction,sign=aw>>23&255,aw&0x7FFFFF,aw>>31
                    code=(8 if fraction and not fraction&0x400000 else 9 if fraction else 0 if sign else 7) if exponent==255 else (3 if sign else 4) if exponent==0 and fraction==0 else (2 if sign else 5) if exponent==0 else (1 if sign else 6)
                    int_result=1<<code
                else: raise RuntimeError('scalar FP reference does not cover handler')
            wanted_fp=(fp_result,0,0,0,0,0,0,0) if fp_result is not None else fbefore
            wanted_x=int_result if int_result is not None else xbefore
            wanted_mask=0 if name=='mask_zero_fadd_s' else 255
            if (fafter,xafter,masks,controls)!=(wanted_fp,wanted_x,(wanted_mask,wanted_mask),(0,flags)):
                raise RuntimeError('scalar FP actual snapshots disagree with independent reference')
            if fp_result is not None and op['regs'].get('f20=')!=fafter or int_result is not None and op['regs'].get('x20=')!=xafter:
                raise RuntimeError('scalar FP result lacks matching actual write event')
            offset=syms['record_'+name]-start
            if pre[offset:offset+192]!=bytes([0xA5])*192: raise RuntimeError('scalar FP record lacks pre-execution sentinel')
            wanted=bytearray([0xA5]*192)
            struct.pack_into('<16I6Q',wanted,0,*fbefore,*fafter,xbefore,xafter,*masks,*controls)
            if site['cause']:
                fault=struct.unpack_from('<4Q',memory,offset+112)
                if fault[:3]!=(30,pc,word) or fault[3]>>11&3!=3 or 'f20=' in op['regs'] or 'x20=' in op['regs']:
                    raise RuntimeError('scalar FP unexpected fault/destination mutation')
                if actual_traps[trap_index]!=('H0 S0:N0:C0:T0','1e',f'{word:x}'):
                    raise RuntimeError('scalar FP fault snapshot differs from raw trap event')
                for csr,value in zip(csr_events,fault):
                    if csr_events[csr][trap_index]['regs'].get('x5=')!=value: raise RuntimeError('scalar FP trap CSR read mismatch')
                struct.pack_into('<4Q',wanted,112,*fault)
                trap_index+=1
            if row['f20_before']['raw_u32']!=[f'0x{x:08x}' for x in fbefore] or row['f20_after']['raw_u32']!=[f'0x{x:08x}' for x in fafter]:
                raise RuntimeError('scalar FP normalized destination state differs from real register reads')
            if any(int(row[key],16)!=value for key,value in [('x20_before',xbefore),('x20_after',xafter),('mask_before',masks[0]),('mask_after',masks[1]),('fcsr_before',controls[0]),('fcsr_after',controls[1])]):
                raise RuntimeError('scalar FP normalized integer/control state differs from real reads')
            expected[offset:offset+192]=wanted
        if trap_index!=6 or len(actual_traps)!=6 or any(len(es)!=6 for es in csr_events.values()):
            raise RuntimeError('scalar FP unexpected/missing fault count')
        struct.pack_into('<Q',expected,syms['trap_count']-start,6)
        struct.pack_into('<I',expected,syms['completion']-start,0x4B4F5445)
        if memory!=expected or (directory/'expected.bin').read_bytes()!=expected or not event('park')['decoded'].startswith('wfi'):
            raise RuntimeError('scalar FP whole guarded monitor/termination mismatch')
        runs.append(dict(run=run_name,validated_sites=31,normal_handler_count=22,trap_stub_count=6,**{'pass':True},
            sha256={name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in required}))
    paths=['processor.cpp','insns/float.cpp','insns/packed_loadstore.cpp','insn_util.h','fpu/f32_mulSub.c','fpu/f32_subMulAdd.c','fpu/f32_subMulSub.c']
    report=dict(scope='scalar FP actual execution, complete register-write reconstruction and device snapshots; separate from packed ET extensions',
        et_platform_commit=commit,verified_normal_handlers=sorted(normal) if not missing else [],verified_fault_stubs=sorted(faults) if not missing else [],
        verified_runs=runs,runs_missing_evidence=missing,limitations=['selected exactly representable inputs and specific RNE/RTZ rounding cases; exhaustive IEEE edge/exception coverage not claimed'],
        source_sha256={'sw-sysemu/'+name:hashlib.sha256((source_root/'sw-sysemu'/name).read_bytes()).hexdigest() for name in paths})
    (ROOT/'out/isa/scalar-fp-inventory.json').write_text(json.dumps(report,indent=2)+'\n')
    return report, missing


def scalar_integer_evidence(source_root: Path, commit: str) -> tuple[dict[str, object], list[str]]:
    """Audit scalar integer encodings, actual operands/results and guarded memory."""
    normal = {row['mnemonic'] for name,row in definitions(source_root/'sw-sysemu/insns').items()
              if row['source'] in ('insns/arith.cpp','insns/muldiv.cpp') and name!='reserved'}
    if len(normal)!=43: raise RuntimeError('pinned scalar integer handler inventory changed')
    def sign(x,n):
        x &= (1<<n)-1
        return x-(1<<n) if x>>(n-1) else x
    def decoded_reference(word,a,b,pc):
        opcode,f3,f7=word&127,word>>12&7,word>>25
        narrow=opcode in (0x1B,0x3B); width=32 if narrow else 64
        a &= (1<<width)-1; b &= (1<<width)-1
        if opcode in (0x37,0x17):
            name='lui' if opcode==0x37 else 'auipc'
            return name,(sign(word&0xFFFFF000,32)+(pc if opcode==0x17 else 0))&((1<<64)-1)
        if opcode in (0x13,0x1B):
            name={0:'addi',1:'slli',2:'slti',3:'sltiu',4:'xori',5:'srai' if word>>30&1 else 'srli',6:'ori',7:'andi'}[f3]
            if narrow and f3 not in (0,1,5): raise RuntimeError('unexpected scalar word immediate encoding')
            b=(word>>20)&(width-1) if f3 in (1,5) else sign(word>>20,12)
            if f3 in (1,5) and word>>(25 if narrow else 26) != (0x20 if narrow else 0x10) * int(name=='srai'):
                raise RuntimeError('integer shift immediate encoding mismatch')
        elif opcode in (0x33,0x3B):
            table = {0:('add','sll','slt','sltu','xor','srl','or','and'),
                     1:('mul','mulh','mulhsu','mulhu','div','divu','rem','remu'),
                     0x20:('sub',None,None,None,None,'sra',None,None)}
            if f7 not in table or table[f7][f3] is None: raise RuntimeError('integer register encoding mismatch')
            name=table[f7][f3]
            if narrow and (f7==0 and f3 not in (0,1,5) or f7==1 and f3 not in (0,4,5,6,7)):
                raise RuntimeError('unexpected scalar word register encoding')
        else: raise RuntimeError('unexpected scalar integer opcode')
        operation=name[:-1] if name.endswith('i') else name
        if operation=='add': result=a+b
        elif operation=='sub': result=a-b
        elif operation=='and': result=a&b
        elif operation=='or': result=a|b
        elif operation=='xor': result=a^b
        elif operation=='sll': result=a<<(b&(width-1))
        elif operation=='srl': result=a>>(b&(width-1))
        elif operation=='sra': result=sign(a,width)>>(b&(width-1))
        elif operation=='slt': result=int(sign(a,width)<(b if name=='slti' else sign(b,width)))
        elif operation=='sltu' or name=='sltiu': result=int(a<(b&((1<<width)-1)))
        elif operation=='mul': result=a*b
        elif operation=='mulh': result=(sign(a,64)*sign(b,64))>>64
        elif operation=='mulhsu': result=(sign(a,64)*b)>>64
        elif operation=='mulhu': result=(a*b)>>64
        elif operation in ('div','divu','rem','remu'):
            aa,bb=(sign(a,width),sign(b,width)) if operation in ('div','rem') else (a,b)
            if bb==0: result=-1 if operation.startswith('div') else aa
            else:
                q=abs(aa)//abs(bb)*(-1 if (aa<0)!=(bb<0) else 1)
                result=q if operation.startswith('div') else aa-q*bb
        else: raise RuntimeError('missing independent scalar integer reference')
        return name+('w' if narrow else ''),(sign(result,32) if narrow else result)&((1<<64)-1)
    runs,missing=[],[]
    for case in ('primary','exact'):
        directory=ROOT/'out/scalar-integer'/('' if case=='primary' else case)
        required=('result.json','elf-layout.json','kernel.elf','kernel.S','trace.log','output.bin','prestart.bin',
                  'expected.bin','registers.json','operations.json','text.bin','symbols.txt','commands.log')
        run_name=str(directory.relative_to(ROOT))
        if any(not (directory/name).is_file() for name in required): missing.append(run_name); continue
        result,layout,sites,registers=(json.loads((directory/name).read_text()) for name in
                                     ('result.json','elf-layout.json','operations.json','registers.json'))
        if not result.get('pass') or not result.get('whole_monitor_matches') or result['case']!=case or (result['operation_count'],result['handler_count'],result['trap_count'])!=(61,43,0):
            raise RuntimeError('incomplete scalar integer result counts')
        if len(sites)!=61 or len(registers['operations'])!=61 or {s['mnemonic'] for s in sites}!=normal:
            raise RuntimeError('scalar integer source handlers lack full selected-site coverage')
        variants={v:sum(s['variant']==v for s in sites) for v in {s['variant'] for s in sites}}
        if variants!={'ordinary':43,'divide by zero':8,'minimum signed value divided by -1':4,'register shift count masks high bits':6}:
            raise RuntimeError('integer edge-case coverage changed')
        elf,pre,memory=((directory/name).read_bytes() for name in ('kernel.elf','prestart.bin','output.bin'))
        if elf[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',elf,18)[0]!=243: raise RuntimeError('integer ELF architecture mismatch')
        entry,phoff,shoff=struct.unpack_from('<3Q',elf,24)
        phsize,phcount,shsize,shcount,strings=struct.unpack_from('<5H',elf,54)
        segments=[struct.unpack_from('<II6Q',elf,phoff+i*phsize) for i in range(phcount)]
        sections=[struct.unpack_from('<II4QII2Q',elf,shoff+i*shsize) for i in range(shcount)]
        names=elf[sections[strings][4]:sections[strings][4]+sections[strings][5]]
        sections={names[s[0]:].split(b'\0',1)[0].decode():s for s in sections}
        if [name for name,s in sections.items() if s[2]&4 and s[5]]!=['.text'] or entry!=int(layout['entry'],16): raise RuntimeError('integer entry/section mismatch')
        text=sections['.text']
        if (directory/'text.bin').read_bytes()!=elf[text[4]:text[4]+text[5]]: raise RuntimeError('integer text dump mismatch')
        start,size=int(layout['monitor_address'],16),layout['monitor_size']
        mappings=[p[2]+start-p[3] for p in segments if p[0]==1 and p[3]<=start and start+size<=p[3]+p[5]]
        if len(mappings)!=1 or len(pre)!=size or len(memory)!=size or pre!=elf[mappings[0]:mappings[0]+size]: raise RuntimeError('integer prestart input/guard bytes differ from linked ELF')
        syms={s[2]:int(s[0],16) for line in (directory/'symbols.txt').read_text().splitlines() if len(s:=line.split())==3}
        trace=(directory/'trace.log').read_text()
        if 'Finishing emulation' not in trace or 'Error, max cycles reached' in trace or re.search(r'\b(?:trap|exception)\b',trace,re.I): raise RuntimeError('integer incomplete/faulting execution')
        events,current=[],None
        for line in trace.splitlines():
            match=re.match(r'^\d+: DEBUG EMU: \[(H\d+ S\d+:N\d+:C\d+:T\d+)\] I\(M\): 0x([0-9a-f]+) \(0x([0-9a-f]{8})\) (.*)$',line)
            if match:
                current=dict(hart=match[1],pc=int(match[2],16),word=int(match[3],16),decoded=match[4],regs={},memory=[]); events.append(current)
            elif current is not None:
                match=re.search(r'\b(x\d+) ([=:]) 0x([0-9a-f]+)',line)
                if match: current['regs'][match[1]+match[2]]=int(match[3],16)
                match=re.search(r'MEM(8|16|32|64)\[0x([0-9a-f]+)\] ([=:]) 0x([0-9a-f]+)',line)
                if match: current['memory'].append((int(match[1]),int(match[2],16),match[3],int(match[4],16)))
        if any(e['hart']!='H0 S0:N0:C0:T0' for e in events): raise RuntimeError('integer unexpected hart')
        def event(name):
            matches=[e for e in events if e['pc']==syms[name]]
            if len(matches)!=1: raise RuntimeError('integer missing/repeated actual site: '+name)
            return matches[0]
        expected=bytearray(pre)
        for site,row in zip(sites,registers['operations']):
            name,pc=site['name'],int(site['pc'],16); op=event('op_'+name)
            offsets=[p[2]+pc-p[3] for p in segments if p[0]==1 and p[1]&1 and p[3]<=pc and pc+4<=p[3]+p[5]]
            raw=bytes.fromhex(site['bytes_memory_order']); word=int.from_bytes(raw,'little')
            if len(offsets)!=1 or raw!=elf[offsets[0]:offsets[0]+4] or offsets[0]!=int(site['file_offset'],16) or word!=int(site['word'],16) or word!=op['word']:
                raise RuntimeError('integer operation PC/file bytes differ from actual execution')
            if word>>7&31!=20: raise RuntimeError('integer destination register changed')
            inputs=struct.unpack_from('<2Q',pre,syms['input_'+name]-start)
            for j,reg in enumerate(('x10','x11')):
                load=event(('load_a_' if j==0 else 'load_b_')+name)
                if load['regs'].get(reg+'=')!=inputs[j] or load['memory']!=[(64,syms['input_'+name]+8*j,':',inputs[j])]: raise RuntimeError('integer input lacks actual register/memory-load evidence')
            decoded,answer=decoded_reference(word,*inputs,pc)
            if decoded!=site['mnemonic'] or not op['decoded'].startswith(decoded): raise RuntimeError('integer encoding field decoder mismatch')
            if word&127 not in (0x37,0x17) and (word>>15&31!=10 or op['regs'].get('x10:')!=inputs[0]): raise RuntimeError('integer source A field/read mismatch')
            if word&127 in (0x33,0x3B) and (word>>20&31!=11 or op['regs'].get('x11:')!=inputs[1]): raise RuntimeError('integer source B field/read mismatch')
            if any(row[key]!=site[key] for key in ('name','mnemonic','pc','word','bytes_memory_order')) or row['hart']!=op['hart']:
                raise RuntimeError('integer normalized operation identity differs from real site')
            wanted=(*inputs,0x5AA55AA55AA55AA5,*inputs,answer)
            offset=syms['record_'+name]-start
            if pre[offset:offset+128]!=bytes([0xA5])*128: raise RuntimeError('integer pre-execution record sentinel missing')
            actual=[]
            for phase in ('before','after'):
                for suffix,reg in (('a','x10'),('b','x11'),('x','x20')):
                    snapshot=event(phase+'_'+suffix+'_'+name)
                    actual.append(snapshot['regs'].get(reg+':'))
                    j=len(actual)-1
                    if snapshot['memory']!=[(64,start+offset+8*j,'=',wanted[j])]: raise RuntimeError('integer actual snapshot store differs from reference')
            if tuple(actual)!=wanted or op['regs'].get('x20=')!=answer: raise RuntimeError('integer result/reference/raw write mismatch')
            for key,value in zip(('x10_before','x11_before','x20_before','x10_after','x11_after','x20_after'),wanted):
                if int(row[key],16)!=value: raise RuntimeError('integer normalized register state differs from actual reads')
            expected[offset:offset+48]=struct.pack('<6Q',*wanted)
        struct.pack_into('<I',expected,syms['completion']-start,0x4B4F5445)
        if memory!=expected or (directory/'expected.bin').read_bytes()!=expected or not event('park')['decoded'].startswith('wfi'): raise RuntimeError('integer complete guarded memory/termination mismatch')
        runs.append(dict(run=run_name,validated_sites=61,handler_count=43,variants=variants,**{'pass':True},
            sha256={name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in required}))
    paths=('processor.cpp','insns/arith.cpp','insns/muldiv.cpp','insn_util.h','insn.h')
    report=dict(scope='scalar integer actual instruction encodings, register/memory events and selected arithmetic edge cases; separate from packed ET instructions',
        et_platform_commit=commit,verified_handlers=sorted(normal) if not missing else [],verified_runs=runs,runs_missing_evidence=missing,
        limitations=['selected normal, zero-divisor, signed-overflow and overshift cases; exhaustive operands/aliases and SysEmu software hints not claimed'],
        source_sha256={'sw-sysemu/'+name:hashlib.sha256((source_root/'sw-sysemu'/name).read_bytes()).hexdigest() for name in paths})
    (ROOT/'out/isa/scalar-integer-inventory.json').write_text(json.dumps(report,indent=2)+'\n')
    return report,missing


def base_memory_evidence(source_root: Path, commit: str) -> tuple[dict[str, object], list[str]]:
    """Independently audit ordinary memory decoder fields and actual state effects."""
    selected={name for name,row in definitions(source_root/'sw-sysemu/insns').items()
              if row['source'] in ('insns/arith_loadstore.cpp','insns/float_loadstore.cpp')}
    if selected!={'lb','lbu','lh','lhu','lw','lwu','ld','sb','sh','sw','sd','flw','fsw','fence'}:
        raise RuntimeError('pinned base-memory handler inventory changed')
    def signed12(value): return value-4096 if value&2048 else value
    def decode(word):
        # processor.cpp dec_load, dec_store, dec_load_fp, dec_store_fp, dec_misc_mem.
        opcode,f3=word&127,word>>12&7
        if opcode==3:
            name=('lb','lh','lw','ld','lbu','lhu','lwu',None)[f3]; kind='load'
        elif opcode==0x23:
            name=('sb','sh','sw','sd',None,None,None,None)[f3]; kind='store'
        elif opcode in (7,0x27) and f3==2:
            name='flw' if opcode==7 else 'fsw'; kind='load' if opcode==7 else 'store'
        elif opcode==0xF and f3==0:
            if word!=0x0FF0000F: raise RuntimeError('unexpected fence predecessor/successor encoding')
            return 'fence','fence',0,0
        else: raise RuntimeError('unexpected ordinary memory opcode/funct3')
        if name is None or word>>15&31!=10: raise RuntimeError('invalid memory selector/base field')
        if kind=='load' and word>>7&31!=20 or kind=='store' and word>>20&31!=11:
            raise RuntimeError('base-memory destination/source register field differs')
        immediate=signed12(word>>20 if kind=='load' else ((word>>25)<<5)|(word>>7&31))
        width=32 if name in ('flw','fsw') else (8,16,32,64)[f3&3]
        return name,kind,width,immediate
    runs,missing=[],[]
    for case in ('primary','exact'):
        directory=ROOT/'out/base-memory'/('' if case=='primary' else case)
        required=('result.json','registers.json','operations.json','elf-layout.json','kernel.S','link.ld',
                  'kernel.elf','kernel.asm','text.bin','operations.bin','op.bin','elf-inspection.txt',
                  'symbols.txt','commands.log','prestart.bin','output.bin','expected.bin')
        run_name=str(directory.relative_to(ROOT))
        if any(not (directory/name).is_file() for name in required): missing.append(run_name); continue
        result,registers,sites,layout=(json.loads((directory/name).read_text()) for name in
                                      ('result.json','registers.json','operations.json','elf-layout.json'))
        if not result.get('pass') or not result.get('whole_monitor_matches') or result['case']!=case or (result['operation_count'],result['handler_count'],result['trap_count'])!=(14,14,0):
            raise RuntimeError('base-memory result count/completion failure')
        if len(sites)!=14 or len(registers['operations'])!=14 or result['operations']!=registers['operations'] or {s['name'] for s in sites}!=selected:
            raise RuntimeError('base-memory operation coverage or normalized rows differ')
        elf,pre,memory=((directory/name).read_bytes() for name in ('kernel.elf','prestart.bin','output.bin'))
        if elf[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',elf,18)[0]!=243: raise RuntimeError('base-memory ELF architecture mismatch')
        entry,phoff,shoff=struct.unpack_from('<3Q',elf,24)
        phsize,phcount,shsize,shcount,strings=struct.unpack_from('<5H',elf,54)
        segments=[struct.unpack_from('<II6Q',elf,phoff+i*phsize) for i in range(phcount)]
        sections=[struct.unpack_from('<II4QII2Q',elf,shoff+i*shsize) for i in range(shcount)]
        names=elf[sections[strings][4]:sections[strings][4]+sections[strings][5]]
        sections={names[s[0]:].split(b'\0',1)[0].decode():s for s in sections}
        if [name for name,s in sections.items() if s[2]&4 and s[5]]!=['.text'] or entry!=int(layout['entry'],16): raise RuntimeError('base-memory executable section/entry mismatch')
        text=sections['.text']
        if (directory/'text.bin').read_bytes()!=elf[text[4]:text[4]+text[5]]: raise RuntimeError('base-memory text extraction mismatch')
        start,size=int(layout['monitor_address'],16),layout['monitor_size']
        mappings=[p[2]+start-p[3] for p in segments if p[0]==1 and p[3]<=start and start+size<=p[3]+p[5]]
        if len(mappings)!=1 or len(pre)!=size or len(memory)!=size or pre!=elf[mappings[0]:mappings[0]+size]: raise RuntimeError('base-memory initial inputs/guards differ from linked ELF')
        syms={s[2]:int(s[0],16) for line in (directory/'symbols.txt').read_text().splitlines() if len(s:=line.split())==3}
        trace=(directory/'trace.log').read_text()
        if 'Finishing emulation' not in trace or 'Error, max cycles reached' in trace or re.search(r'\b(?:trap|exception)\b',trace,re.I): raise RuntimeError('base-memory incomplete/faulting execution')
        events,current=[],None
        for line in trace.splitlines():
            match=re.match(r'^\d+: DEBUG EMU: \[(H\d+ S\d+:N\d+:C\d+:T\d+)\] I\(M\): 0x([0-9a-f]+) \(0x([0-9a-f]{8})\) (.*)$',line)
            if match:
                current=dict(hart=match[1],pc=int(match[2],16),word=int(match[3],16),decoded=match[4],regs={},memory=[]); events.append(current)
            elif current is not None:
                match=re.search(r'\b(f\d+) ([=:]) \{([^}]+)\}',line)
                if match:
                    words=tuple(int(x,16) for x in re.findall(r'\d+:0x([0-9a-f]{8})',match[3]))
                    if len(words)!=8: raise RuntimeError('incomplete base-memory FP register trace')
                    current['regs'][match[1]+match[2]]=words
                match=re.search(r'\b(x\d+) ([=:]) 0x([0-9a-f]+)',line)
                if match: current['regs'][match[1]+match[2]]=int(match[3],16)
                match=re.search(r'MEM(8|16|32|64)\[0x([0-9a-f]+)\] ([=:]) 0x([0-9a-f]+)',line)
                if match: current['memory'].append((int(match[1]),int(match[2],16),match[3],int(match[4],16)))
        if any(e['hart']!='H0 S0:N0:C0:T0' for e in events): raise RuntimeError('base-memory unexpected executing hart')
        def event(name):
            matches=[e for e in events if e['pc']==syms[name]]
            if len(matches)!=1: raise RuntimeError('base-memory missing/repeated site '+name)
            return matches[0]
        state,before={},{}
        pcs={int(s['pc'],16) for s in sites}
        for e in events:
            if e['pc'] in pcs: before[e['pc']]=dict(state)
            for key,value in e['regs'].items():
                if key.endswith('='): state[key[:-1]]=value
        integer=struct.unpack_from('<Q',pre,syms['input_x']-start)[0]
        fp=struct.unpack_from('<8I',pre,syms['input_fp']-start)
        if integer!=(0xFEDCBA9889ABCDEF if case=='primary' else 0x0123456776543210) or fp[0]!=(0xBFC00000 if case=='primary' else 0x40200000):
            raise RuntimeError('base-memory deterministic input case differs')
        expected=bytearray(pre); assembled=[]
        for site,row in zip(sites,registers['operations']):
            name,pc=site['name'],int(site['pc'],16); op=event('op_'+name)
            offsets=[p[2]+pc-p[3] for p in segments if p[0]==1 and p[1]&1 and p[3]<=pc and pc+4<=p[3]+p[5]]
            raw=bytes.fromhex(site['bytes_memory_order']); word=int.from_bytes(raw,'little'); assembled.append(raw)
            if len(raw)!=4 or len(offsets)!=1 or elf[offsets[0]:offsets[0]+4]!=raw or offsets[0]!=int(site['file_offset'],16) or word!=int(site['word'],16) or word!=op['word']:
                raise RuntimeError('base-memory operation ELF/PC/trace word mismatch')
            decoded,kind,width,immediate=decode(word)
            if decoded!=name or site['mnemonic']!=name or site['kind']!=kind or site['width']!=width or (kind!='fence' and site['immediate']!=immediate): raise RuntimeError('memory encoding fields differ from declared operation')
            if kind!='fence' and immediate!=(24 if case=='primary' else -24): raise RuntimeError('signed memory offset case missing')
            if op['decoded'].split()[0]!=('lw' if name=='lwu' else name): raise RuntimeError('base-memory trace mnemonic differs from decoder')
            address=syms['target_'+name]+32; base=address-site['immediate']; offset=syms['record_'+name]-start
            source=before[pc]; seed=(0xA5A5A5A5,)*8; xseed=0x5AA55AA55AA55AA5
            if any(source.get(reg)!=value for reg,value in [('f20',seed),('f11',fp),('x10',base),('x11',integer),('x20',xseed)]): raise RuntimeError('memory operand state lacks complete actual write reconstruction')
            for symbol,reg,words,addr,bits in [('load_x_','x11',(integer,),syms['input_x'],64),('load_fp_','f11',fp,syms['input_fp'],32),('load_seed_','f20',seed,syms['seed'],32)]:
                load=event(symbol+name)
                if load['regs'].get(reg+'=')!=(words[0] if bits==64 else words) or load['memory']!=[(bits,addr+j*bits//8,':',v) for j,v in enumerate(words)]: raise RuntimeError('memory input/sentinel load register/MEM events differ')
            target=syms['target_'+name]-start
            initial_payload=fp[0] if name=='flw' else integer
            initial=bytes([0x5A])*32+(initial_payload.to_bytes(8,'little') if kind=='load' else bytes([0x5A])*8)+bytes([0x5A])*88
            if pre[target:target+128]!=initial or pre[offset:offset+256]!=bytes([0xA5])*256: raise RuntimeError('memory initial target/record guards differ')
            payload=int.from_bytes(pre[address-start:address-start+width//8],'little'); answer=xseed; after_fp=seed
            if kind=='load' and name!='flw':
                answer=payload-(1<<width) if name in ('lb','lh','lw') and payload>>(width-1) else payload
                answer &= (1<<64)-1
            elif name=='flw': after_fp=(payload,0,0,0,0,0,0,0)
            if kind=='load': wanted_mem=[(width,address,':',payload)]
            elif kind=='store':
                value=(fp[0] if name=='fsw' else integer)&((1<<width)-1); wanted_mem=[(width,address,'=',value)]
                expected[address-start:address-start+width//8]=value.to_bytes(width//8,'little')
            else: wanted_mem=[]
            if op['memory']!=wanted_mem or kind!='fence' and op['regs'].get('x10:')!=base: raise RuntimeError('actual memory access width/address/value/base differs')
            if kind=='store' and op['regs'].get('f11:' if name=='fsw' else 'x11:')!=(fp if name=='fsw' else integer): raise RuntimeError('store source read differs')
            if name=='flw' and op['regs'].get('f20=')!=after_fp or kind=='load' and name!='flw' and op['regs'].get('x20=')!=answer: raise RuntimeError('memory result write differs')
            if (name!='flw' and 'f20=' in op['regs']) or (kind!='load' or name=='flw') and 'x20=' in op['regs']: raise RuntimeError('unexpected memory destination write')
            if any(row[k]!=site[k] for k in ('name','mnemonic','pc','word','bytes_memory_order')) or row['hart']!=op['hart'] or int(row['address'],16)!=address: raise RuntimeError('normalized memory site identity differs')
            for reg,phase,off,words in [('f20','before',0,seed),('f20','after',32,after_fp),('f11','before',64,fp),('f11','after',96,fp)]:
                snapshot=event(f'{phase}_{reg}_{name}')
                if snapshot['regs'].get(reg+':')!=words or snapshot['memory']!=[(32,start+offset+off+4*j,'=',v) for j,v in enumerate(words)]: raise RuntimeError('FP snapshot read/store differs from independent reference')
                if row[reg+'_'+phase]['raw_u32']!=[f'0x{v:08x}' for v in words]: raise RuntimeError('normalized FP memory result differs')
                struct.pack_into('<8I',expected,offset+off,*words)
            wanted=(base,integer,xseed,base,integer,answer)
            for j,(phase,reg,xreg) in enumerate((p,r,x) for p in ('before','after') for r,x in [('a0','x10'),('a1','x11'),('s4','x20')]):
                snapshot=event(f'{phase}_{reg}_{name}')
                if snapshot['regs'].get(xreg+':')!=wanted[j] or snapshot['memory']!=[(64,start+offset+128+8*j,'=',wanted[j])] or int(row[xreg+'_'+phase],16)!=wanted[j]: raise RuntimeError('scalar memory snapshot/reference differs')
            struct.pack_into('<6Q',expected,offset+128,*wanted)
            for category,off in [('mask',176),('fcsr',192),('mstatus',208)]:
                reads=[event(f'{phase}_{category}_{name}') for phase in ('before','after')]
                for read in reads:
                    word=read['word']
                    if category=='mask':
                        if word&127!=0x7B or word>>25!=0x6B or word&0x01FFF000 or word>>7&31!=5:
                            raise RuntimeError('mask snapshot is not actual mova.x.m x5')
                    elif word&0xFFFFF!=0x022F3 or word>>20!=({'fcsr':3,'mstatus':0x300}[category]):
                        raise RuntimeError('FP control snapshot is not actual CSR read')
                pair=[read['regs'].get('x5=') for read in reads]
                if pair[0]!=pair[1] or category!='mstatus' and pair!=[0,0] or category=='mstatus' and (pair[0]&0x6008)!=0x6000: raise RuntimeError('FP/mask/status initialization or preservation differs')
                for phase,value in zip(('before','after'),pair):
                    store=event(f'store_{phase}_{category}_{name}')
                    if store['regs'].get('x5:')!=value or store['memory']!=[(64,start+offset+off+8*(phase=='after'),'=',value)] or int(row[category+'_'+phase],16)!=value: raise RuntimeError('actual control-state snapshot differs')
                struct.pack_into('<2Q',expected,offset+off,*pair)
            if bytes.fromhex(row['target_before_bytes'])!=pre[target:target+128] or bytes.fromhex(row['target_after_bytes'])!=memory[target:target+128]: raise RuntimeError('normalized target bytes differ from actual dumps')
            if row['memory_events']!=[dict(width=w,address=hex(a),access=access,value=hex(v)) for w,a,access,v in wanted_mem]: raise RuntimeError('normalized memory events differ from raw access events')
        if (directory/'operations.bin').read_bytes()!=b''.join(assembled) or (directory/'op.bin').read_bytes()!=assembled[0]: raise RuntimeError('memory operation binary extraction differs')
        struct.pack_into('<I',expected,syms['completion']-start,0x4B4F5445)
        if memory!=expected or (directory/'expected.bin').read_bytes()!=expected or not event('park')['decoded'].startswith('wfi'): raise RuntimeError('whole guarded memory/completion differs')
        runs.append(dict(run=run_name,validated_sites=14,handler_count=14,**{'pass':True},sha256={name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in required}))
    paths=('processor.cpp','insns/arith_loadstore.cpp','insns/float_loadstore.cpp','insn_util.h','insn.h')
    report=dict(scope='ordinary scalar memory instruction fields, signed offsets, actual register/MEM events and whole guarded dumps; separate from coherent and packed handlers',
        et_platform_commit=commit,verified_handlers=sorted(selected) if not missing else [],verified_runs=runs,runs_missing_evidence=missing,
        limitations=['aligned selected cases only; misalignment/page/protection faults, aliases and concurrent memory ordering are not covered',
                    'fence handler only logs and returns in this SysEmu revision; this checks decoded execution and state preservation, not hardware ordering',
                    'lwu is labeled lw in SysEmu trace; opcode=3/funct3=6 and actual zero-extended result establish lwu identity'],
        source_sha256={'sw-sysemu/'+name:hashlib.sha256((source_root/'sw-sysemu'/name).read_bytes()).hexdigest() for name in paths})
    (ROOT/'out/isa/base-memory-inventory.json').write_text(json.dumps(report,indent=2)+'\n')
    return report,missing


def branch_evidence(source_root: Path, commit: str) -> tuple[dict[str, object], list[str]]:
    """Decode B/J/I fields and independently prove actual branch/jump paths."""
    selected={name for name,row in definitions(source_root/'sw-sysemu/insns').items() if row['source']=='insns/branch.cpp'}
    if selected!={'beq','bne','blt','bge','bltu','bgeu','jal','jalr'}: raise RuntimeError('pinned branch handler inventory changed')
    def sign(value,width): return value-(1<<width) if value>>(width-1) else value
    def decode(word):
        # processor.cpp dec_branch/dec_jal/dec_jalr and insn.h immediate fields.
        opcode=word&127
        if opcode==0x63:
            name={0:'beq',1:'bne',4:'blt',5:'bge',6:'bltu',7:'bgeu'}.get(word>>12&7)
            if name is None or word>>15&31!=10 or word>>20&31!=11: raise RuntimeError('branch selector/source fields differ')
            immediate=((word>>31)<<12)|((word>>7&1)<<11)|((word>>25&63)<<5)|((word>>8&15)<<1)
            return name,sign(immediate,13),0
        if opcode==0x6F:
            immediate=((word>>31)<<20)|((word>>12&255)<<12)|((word>>20&1)<<11)|((word>>21&1023)<<1)
            return 'jal',sign(immediate,21),word>>7&31
        if opcode==0x67 and word>>12&7==0 and word>>15&31==10:
            return 'jalr',sign(word>>20,12),word>>7&31
        raise RuntimeError('unexpected branch/jump opcode or source field')
    runs,missing=[],[]
    for case in ('primary','exact'):
        directory=ROOT/'out/branches'/('' if case=='primary' else case)
        required=('result.json','registers.json','operations.json','elf-layout.json','kernel.S','link.ld',
                  'kernel.elf','kernel.asm','text.bin','operations.bin','op.bin','elf-inspection.txt',
                  'symbols.txt','commands.log','prestart.bin','output.bin','expected.bin')
        run_name=str(directory.relative_to(ROOT))
        if any(not (directory/name).is_file() for name in required): missing.append(run_name); continue
        result,registers,sites,layout=(json.loads((directory/name).read_text()) for name in ('result.json','registers.json','operations.json','elf-layout.json'))
        if not result.get('pass') or not result.get('whole_monitor_matches') or result['case']!=case or (result['operation_count'],result['handler_count'],result['trap_count'])!=(16,8,0): raise RuntimeError('branch result/count/completion failure')
        if len(sites)!=16 or len(registers['operations'])!=16 or result['operations']!=registers['operations'] or {s['mnemonic'] for s in sites}!=selected: raise RuntimeError('branch site coverage or normalized rows differ')
        elf,pre,memory=((directory/name).read_bytes() for name in ('kernel.elf','prestart.bin','output.bin'))
        if elf[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',elf,18)[0]!=243: raise RuntimeError('branch ELF architecture differs')
        entry,phoff,shoff=struct.unpack_from('<3Q',elf,24)
        phsize,phcount,shsize,shcount,strings=struct.unpack_from('<5H',elf,54)
        segments=[struct.unpack_from('<II6Q',elf,phoff+i*phsize) for i in range(phcount)]
        sections=[struct.unpack_from('<II4QII2Q',elf,shoff+i*shsize) for i in range(shcount)]
        names=elf[sections[strings][4]:sections[strings][4]+sections[strings][5]]
        sections={names[s[0]:].split(b'\0',1)[0].decode():s for s in sections}
        if [name for name,s in sections.items() if s[2]&4 and s[5]]!=['.text'] or entry!=int(layout['entry'],16): raise RuntimeError('branch executable section/entry mismatch')
        text=sections['.text']
        if (directory/'text.bin').read_bytes()!=elf[text[4]:text[4]+text[5]]: raise RuntimeError('branch text extraction differs')
        start,size=int(layout['monitor_address'],16),layout['monitor_size']
        maps=[p[2]+start-p[3] for p in segments if p[0]==1 and p[3]<=start and start+size<=p[3]+p[5]]
        if len(maps)!=1 or len(pre)!=size or len(memory)!=size or pre!=elf[maps[0]:maps[0]+size]: raise RuntimeError('branch initial memory differs from ELF data')
        syms={s[2]:int(s[0],16) for line in (directory/'symbols.txt').read_text().splitlines() if len(s:=line.split())==3}
        trace=(directory/'trace.log').read_text()
        if 'Finishing emulation' not in trace or 'Error, max cycles reached' in trace or re.search(r'\b(?:trap|exception)\b',trace,re.I): raise RuntimeError('branch incomplete/faulting execution')
        events,current=[],None
        for line in trace.splitlines():
            match=re.match(r'^\d+: DEBUG EMU: \[(H\d+ S\d+:N\d+:C\d+:T\d+)\] I\(M\): 0x([0-9a-f]+) \(0x([0-9a-f]{8})\) (.*)$',line)
            if match:
                current=dict(hart=match[1],pc=int(match[2],16),word=int(match[3],16),decoded=match[4],regs={},memory=[]); events.append(current)
            elif current is not None:
                match=re.search(r'\b(x\d+) ([=:]) 0x([0-9a-f]+)',line)
                if match: current['regs'][match[1]+match[2]]=int(match[3],16)
                match=re.search(r'MEM(8|16|32|64)\[0x([0-9a-f]+)\] ([=:]) 0x([0-9a-f]+)',line)
                if match: current['memory'].append((int(match[1]),int(match[2],16),match[3],int(match[4],16)))
        if any(e['hart']!='H0 S0:N0:C0:T0' for e in events): raise RuntimeError('branch unexpected executing hart')
        by_pc={}
        for index,e in enumerate(events): by_pc.setdefault(e['pc'],[]).append((index,e))
        def event(name):
            found=by_pc.get(syms[name],[])
            if len(found)!=1: raise RuntimeError('branch missing/repeated actual site '+name)
            return found[0][1]
        state,before={},{}
        pcs={int(s['pc'],16) for s in sites}
        for e in events:
            if e['pc'] in pcs: before[e['pc']]=dict(state)
            for key,value in e['regs'].items():
                if key.endswith('='): state[key[:-1]]=value
        expected,assembled,conditional_outcomes=bytearray(pre),[],{}
        for site,row in zip(sites,registers['operations']):
            name,pc=site['name'],int(site['pc'],16); op=event('op_'+name)
            offsets=[p[2]+pc-p[3] for p in segments if p[0]==1 and p[1]&1 and p[3]<=pc and pc+4<=p[3]+p[5]]
            raw=bytes.fromhex(site['bytes_memory_order']); word=int.from_bytes(raw,'little'); assembled.append(raw)
            if len(raw)!=4 or len(offsets)!=1 or elf[offsets[0]:offsets[0]+4]!=raw or offsets[0]!=int(site['file_offset'],16) or word!=int(site['word'],16) or word!=op['word']: raise RuntimeError('branch actual ELF bytes/offset/trace mismatch')
            mnemonic,immediate,rd=decode(word)
            if mnemonic!=site['mnemonic'] or op['decoded'].split()[0]!=mnemonic or rd!=site['rd']: raise RuntimeError('branch decoder identity/register fields differ')
            a,b=struct.unpack_from('<2Q',pre,syms['input_'+name]-start)
            for j,reg in enumerate(('x10','x11')):
                load=event(('load_a_' if j==0 else 'load_b_')+name); value=(a,b)[j]
                if load['regs'].get(reg+'=')!=value or load['memory']!=[(64,syms['input_'+name]+8*j,':',value)]: raise RuntimeError('branch operands lack actual register/MEM load evidence')
            source=before[pc]
            if tuple(source.get(r) for r in ('x10','x11','x20','x21'))!=(a,b,0x5AA55AA55AA55AA5,0xCAFE): raise RuntimeError('branch operands/seeds lack complete actual write reconstruction')
            target=syms['target_'+name]
            negative,positive=(-3,5) if case=='primary' else (-17,9)
            if mnemonic=='jalr':
                if immediate!=(24 if case=='primary' else -24) or a!=target-immediate+1 or (a+immediate)&1!=1 or rd not in (10,20): raise RuntimeError('jalr signed offset/odd target/alias case differs')
                taken=True; next_pc=(a+immediate)&~1
            elif mnemonic=='jal':
                if a!=negative&((1<<64)-1) or rd not in (0,20): raise RuntimeError('jal source/link variants differ')
                taken=True; next_pc=pc+immediate
            else:
                if word>>15&31!=10 or word>>20&31!=11 or op['regs'].get('x10:')!=a or op['regs'].get('x11:')!=b: raise RuntimeError('conditional branch operand fields/reads differ')
                aa,bb=sign(a,64),sign(b,64)
                taken={'beq':a==b,'bne':a!=b,'blt':aa<bb,'bge':aa>=bb,'bltu':a<b,'bgeu':a>=b}[mnemonic]
                conditional_outcomes.setdefault(mnemonic,[]).append(taken)
                if pc+immediate!=target or {a,b}-{negative&((1<<64)-1),positive}: raise RuntimeError('branch immediate/selected signed inputs differ')
                next_pc=target if taken else pc+4
            if b!=positive and not (mnemonic in ('beq','bne','blt','bge','bltu','bgeu') and b==negative&((1<<64)-1)): raise RuntimeError('branch input case B differs')
            direction='forward' if case=='primary' else 'backward'
            if site['direction']!=direction or (target>pc)!=(direction=='forward') or next_pc!=(target if taken else pc+4): raise RuntimeError('branch target direction/decoded next PC differs')
            index=by_pc[pc][0][0]
            if events[index+1]['pc']!=next_pc or len(by_pc.get(target,[]))!=int(taken) or len(by_pc.get(syms['fall_'+name],[]))!=int(not taken): raise RuntimeError('actual next instruction/selected path differs')
            if mnemonic=='jalr' and op['regs'].get('x10:')!=a: raise RuntimeError('jalr original source read differs')
            wanted_write={f'x{rd}=':pc+4} if rd else {}
            if {k:v for k,v in op['regs'].items() if k.endswith('=')}!=wanted_write or op['memory']: raise RuntimeError('jump link writes/branch side effects differ')
            join=syms['join_'+name]; joined=event('join_'+name)
            if joined['word']!=0x00000B17 or joined['regs'].get('x22=')!=join: raise RuntimeError('joined PC lacks actual AUIPC evidence')
            offset=syms['record_'+name]-start
            if pre[offset:offset+128]!=bytes([0xA5])*128: raise RuntimeError('branch record sentinel differs')
            wanted=(a,b,0x5AA55AA55AA55AA5,0xCAFE,pc+4 if rd==10 else a,b,pc+4 if rd==20 else 0x5AA55AA55AA55AA5,0x54414B45 if taken else 0x46414C4C)
            for j,(phase,suffix,reg) in enumerate((p,s,r) for p in ('before','after') for s,r in [('a','x10'),('b','x11'),('link','x20'),('path','x21')]):
                snapshot=event(phase+'_'+suffix+'_'+name)
                if snapshot['regs'].get(reg+':')!=wanted[j] or snapshot['memory']!=[(64,start+offset+8*j,'=',wanted[j])] or int(row[reg+'_'+phase],16)!=wanted[j]: raise RuntimeError('branch actual register/snapshot/reference differs')
            for suffix,phase,off,value,rs2 in [('pc','after',64,join,22),('zero','before',72,0,0),('zero','after',80,0,0)]:
                snapshot=event(phase+'_'+suffix+'_'+name)
                if snapshot['word']&127!=0x23 or snapshot['word']>>12&7!=3 or snapshot['word']>>20&31!=rs2 or snapshot['memory']!=[(64,start+offset+off,'=',value)]: raise RuntimeError('branch PC/x0 device snapshot differs')
            if any(row[k]!=site[k] for k in ('name','mnemonic','pc','word','bytes_memory_order')) or row['hart']!=op['hart'] or row['actual_taken']!=taken or site['taken']!=taken or (int(row['target_pc'],16),int(row['next_pc'],16),int(row['joined_pc'],16))!=(target,next_pc,join) or (row['x0_before'],row['x0_after'])!=(0,0): raise RuntimeError('branch normalized state/path identity differs')
            struct.pack_into('<11Q',expected,offset,*wanted,join,0,0)
            if bytes.fromhex(row['output_memory_bytes'])!=memory[offset:offset+128]: raise RuntimeError('branch normalized output bytes differ')
        if any(sorted(conditional_outcomes.get(name,[]))!=[False,True] for name in selected-{'jal','jalr'}): raise RuntimeError('both conditional outcomes not proven')
        if {s['rd'] for s in sites if s['mnemonic']=='jal'}!={0,20} or {s['rd'] for s in sites if s['mnemonic']=='jalr'}!={10,20}: raise RuntimeError('jump link/discard/alias coverage missing')
        if (directory/'operations.bin').read_bytes()!=b''.join(assembled) or (directory/'op.bin').read_bytes()!=assembled[0]: raise RuntimeError('branch operation extraction differs')
        struct.pack_into('<I',expected,syms['completion']-start,0x4B4F5445)
        if memory!=expected or (directory/'expected.bin').read_bytes()!=expected or not event('park')['decoded'].startswith('wfi'): raise RuntimeError('branch whole guarded memory/completion mismatch')
        runs.append(dict(run=run_name,validated_sites=16,handler_count=8,target_direction=direction,both_conditional_outcomes=True,**{'pass':True},sha256={name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in required}))
    paths=('processor.cpp','insns/branch.cpp','insn_util.h','insn.h')
    report=dict(scope='ordinary branch/jump decoder fields, actual next-PC paths, link/alias/x0 snapshots and whole guarded memory',
        et_platform_commit=commit,verified_handlers=sorted(selected) if not missing else [],verified_runs=runs,runs_missing_evidence=missing,
        limitations=['selected forward/backward offsets and signed operands only; full immediate ranges, misaligned/faulting targets and privilege transitions are separate'],
        source_sha256={'sw-sysemu/'+name:hashlib.sha256((source_root/'sw-sysemu'/name).read_bytes()).hexdigest() for name in paths})
    (ROOT/'out/isa/branch-inventory.json').write_text(json.dumps(report,indent=2)+'\n')
    return report,missing


def full_cpu_source_inventory(source_root: Path, commit: str, extension: dict, scalar: dict, integer: dict, memory: dict, branches: dict) -> dict:
    """Enumerate active CPU decoder selectors; record dedicated audited coverage."""
    path = source_root / 'sw-sysemu/processor.cpp'
    source = path.read_text()
    handlers = definitions(source_root / 'sw-sysemu/insns')
    selectors, all_selectors, decoded_by = {}, set(), {}
    for function in re.findall(r'static\s+insn_exec_funct_t\s+(dec_\w+)\s*\(',source):
        body = function_body(source,rf'static\s+insn_exec_funct_t\s+{function}\s*\(')
        body = re.sub(r'/\*.*?\*/|//[^\n]*','',body,flags=re.S)
        all_selectors.update(re.findall(r'\binsn_(\w+)',body))
        # The pinned CPU decoder has two literal #if 0 branches with #else.
        # Other conditional compilation would need an explicit build-aware audit.
        body = re.sub(r'#if\s+0\b.*?#else\b(.*?)#endif\b',r'\1',body,flags=re.S)
        if re.search(r'^\s*#\s*(?:if|else|elif|endif)',body,re.M):
            raise RuntimeError('CPU decoder conditional compilation needs inspection')
        names = sorted(set(re.findall(r'\binsn_(\w+)',body))-{'reserved','illegal','exec_funct_t'})
        selectors[function]=names
        for name in names: decoded_by.setdefault(name,[]).append(function)
    missing = sorted(set(decoded_by)-set(handlers))
    if missing: raise RuntimeError(f'active CPU decoder references absent handler definitions: {missing}')
    extension_covered = {op['handler'] for op in extension['operations']
                         if op['execution_evidence'] or op['mnemonic'] in extension['trap_evidence']}
    scalar_normal = set(scalar['verified_normal_handlers'])
    scalar_faults = set(scalar['verified_fault_stubs'])
    integer_normal = set(integer['verified_handlers'])
    memory_normal = set(memory['verified_handlers'])
    branch_normal = set(branches['verified_handlers'])
    rows = []
    for name in sorted(decoded_by):
        row = handlers[name]
        covered = 'ET extension execution/fault audit' if 'insn_'+name in extension_covered else \
                  'scalar FP execution audit' if row['mnemonic'] in scalar_normal else \
                  'scalar FP fault audit' if row['mnemonic'] in scalar_faults else \
                  'scalar integer execution audit' if row['mnemonic'] in integer_normal else \
                  'ordinary scalar memory execution audit' if name in memory_normal else \
                  'ordinary branch/jump execution audit' if name in branch_normal else \
                  'not independently audited by a dedicated operation suite'
        rows.append(dict(handler='insn_'+name,**row,decoder_functions=decoded_by[name],dedicated_coverage=covered))
    remaining = [row for row in rows if row['dedicated_coverage'].startswith('not independently')]
    report=dict(status='active source selectors plus dedicated execution/fault audits; broader CPU coverage remains incomplete',
        et_platform_commit=commit,decoded_handler_count=len(rows),defined_selected_handler_count=len(rows),missing_definitions=missing,
        verified_dedicated_handler_count=len(rows)-len(remaining),remaining_dedicated_handler_count=len(remaining),
        remaining_explicit_mcode_stub_count=sum(row['trap_stub'] for row in remaining),
        remaining_other_handler_count=sum(not row['trap_stub'] for row in remaining),
        et_extension_nontrapping_checkpoint_count=extension['verified_execution_handler_count'],
        et_extension_fault_checkpoint_count=extension['verified_trap_stub_count'],
        verified_scalar_fp_handler_count=len(scalar_normal),verified_scalar_fp_fault_count=len(scalar_faults),
        verified_scalar_integer_handler_count=len(integer_normal),
        verified_base_memory_handler_count=len(memory_normal),
        verified_branch_handler_count=len(branch_normal),
        decoder_handlers=selectors,operations=rows,disabled_source_handler_mentions=sorted(all_selectors-set(decoded_by)-{'reserved','illegal','exec_funct_t'}),
        source_sha256={'sw-sysemu/processor.cpp':hashlib.sha256(path.read_bytes()).hexdigest()},
        limits=['Counts are handler selectors, not distinct instruction encodings or exhaustive test cases.',
                'Remaining non-microcode handlers include architectural traps and reserved/illegal compressed handlers.',
                'Incidental base instructions in startup are not counted as dedicated operation audits.',
                'Dynamic CSR engine commands are separate; tensor command paths remain unverified.'])
    (ROOT/'out/isa/full-cpu-source-inventory.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def main() -> int:
    if sys.argv[1:] not in ([], ["--require-complete"]):
        raise SystemExit("usage: python3 tools/inventory.py [--require-complete]")
    env_path = ROOT / "out" / "setup" / "environment.json"
    env = json.loads(env_path.read_text()) if env_path.is_file() else {}
    source_root = Path(os.environ.get("ET_PLATFORM_SOURCE", Path.home() / "et-platform"))
    if not source_root.is_dir():
        raise RuntimeError(f"ET Platform source checkout not found: {source_root}")
    commit = subprocess.run(["git", "-C", str(source_root), "rev-parse", "HEAD"],
                            check=True, capture_output=True, text=True).stdout.strip()
    expected = env.get("platform_commit")
    if expected and expected != commit:
        raise RuntimeError(f"ET Platform is at {commit}, but setup recorded {expected}")
    processor = source_root / "sw-sysemu" / "processor.cpp"
    insns = source_root / "sw-sysemu" / "insns"
    source = processor.read_text()
    handlers = definitions(insns)
    example_sources = {path: path.read_text() for path in sorted((ROOT / "examples").glob("*.py"))}
    evidence, verified_runs, missing_runs = execution_evidence()
    operations = []
    for family, function in DECODERS.items():
        body = function_body(source, rf"static\s+insn_exec_funct_t\s+{function}\s*\(")
        body = re.sub(r"/\*.*?\*/|//[^\n]*", "", body, flags=re.S)
        names = sorted(set(re.findall(r"\binsn_([A-Za-z0-9_]+)", body)) -
                       {"reserved", "illegal", "exec_funct_t"})
        if family in EXTRA_SOURCES:
            names = [name for name in names if name in handlers and
                     handlers[name]["source"] in EXTRA_SOURCES[family]]
        for name in names:
            if name not in handlers:
                raise RuntimeError(f"decoder {function} references missing handler insn_{name}")
            item = {"decoder_family": family, "handler": f"insn_{name}", **handlers[name]}
            item["example_sources"] = [str(path.relative_to(ROOT)) for path, text in example_sources.items()
                                        if item["mnemonic"] and re.search(
                                            rf"(?<![\w.]){re.escape(item['mnemonic'])}(?![\w.])", text)]
            item["execution_evidence"] = evidence.get(item["mnemonic"], [])
            operations.append(item)

    stubs = sorted(op["mnemonic"] for op in operations if op["trap_stub"])
    faults, missing_faults = trap_evidence(stubs)
    files = [processor, *sorted(insns.glob("*.cpp"))]
    digests = {str(path.relative_to(source_root)): hashlib.sha256(path.read_bytes()).hexdigest()
               for path in files}
    output = ROOT / "out" / "isa" / "instruction-inventory.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "et_platform_commit": commit,
        "scope": "ET extension handlers selected by custom, 48/64-bit, FP load/store, op-32 and reserved-2 decoders; base RISC-V and CSR-launched tensor/cache commands are separate",
        "decoder_counts": {family: sum(op["decoder_family"] == family for op in operations)
                           for family in DECODERS},
        "handler_count": len(operations),
        "unique_handler_count": len({op["handler"] for op in operations}),
        "nontrapping_handler_count": sum(not op["trap_stub"] for op in operations),
        "trap_stub_mnemonics": stubs,
        "verified_trap_stub_count": sum(mnemonic in faults for mnemonic in stubs),
        "trap_evidence": faults, "trap_runs_missing_evidence": missing_faults,
        "mnemonics_mentioned_by_examples": sorted({op["mnemonic"] for op in operations
                                                     if op["example_sources"]}),
        "verified_execution_handler_count": len({op["handler"] for op in operations if op["execution_evidence"]}),
        "unverified_nontrapping_handlers": sorted({op["handler"] for op in operations
                                                   if not op["trap_stub"] and not op["execution_evidence"]}),
        "verified_runs": verified_runs, "runs_missing_evidence": missing_runs,
        "source_sha256": digests,
        "operations": operations,
    }
    output.write_text(json.dumps(document, indent=2) + "\n")
    cache_report, missing_cache = cache_csr_evidence(source_root, commit)
    sync_report, missing_sync = synchronization_evidence(source_root, commit)
    port_report, missing_ports = message_port_evidence(source_root, commit)
    privilege_report, missing_privilege = message_port_privilege_evidence(source_root, commit)
    peer_report, missing_peers = synchronization_peer_evidence(source_root, commit)
    scalar_fp_report, missing_scalar_fp = scalar_fp_evidence(source_root, commit)
    integer_report, missing_integer = scalar_integer_evidence(source_root, commit)
    memory_report, missing_memory = base_memory_evidence(source_root, commit)
    branch_report, missing_branches = branch_evidence(source_root, commit)
    cpu_report = full_cpu_source_inventory(source_root, commit, document, scalar_fp_report, integer_report, memory_report, branch_report)
    print(f"ET Platform {commit}")
    print(f"decoded ET handler selectors: {len(operations)}")
    print(f"handlers that explicitly trap: {document['trap_stub_mnemonics']}")
    print(f"handlers with validated ELF/trace execution evidence: {document['verified_execution_handler_count']}")
    print(f"nontrapping handlers without execution evidence: {len(document['unverified_nontrapping_handlers'])}")
    print(f"trap stubs with verified cause-30 fault evidence: {document['verified_trap_stub_count']}")
    print(f"mnemonics named in examples: {', '.join(document['mnemonics_mentioned_by_examples'])}")
    print(f"full decoder inventory: {output}")
    print(f"separate cache CSR coverage: {cache_report['verified_csr_count']}/13; {ROOT / 'out/isa/cache-csr-inventory.json'}")
    print(f"separate synchronization CSR coverage: {sync_report['verified_csr_count']}/5; {ROOT / 'out/isa/synchronization-inventory.json'}")
    print(f"separate message-port CSR coverage: {port_report['verified_csr_count']}/12; {ROOT / 'out/isa/message-port-inventory.json'}")
    print(f"message-port real M/U permission cases: {len(privilege_report['verified_runs'])}/2; {ROOT / 'out/isa/message-port-privilege-inventory.json'}")
    print(f"peer synchronization cases with audited T0/T1 routing/block/wake/overflow: {len(peer_report['verified_runs'])}/4; {ROOT / 'out/isa/synchronization-peer-inventory.json'}")
    print(f"scalar FP: {len(scalar_fp_report['verified_normal_handlers'])}/22 implemented handlers and {len(scalar_fp_report['verified_fault_stubs'])}/6 fault stubs; {ROOT / 'out/isa/scalar-fp-inventory.json'}")
    print(f"scalar integer: {len(integer_report['verified_handlers'])}/43 handlers with actual encoding/register/memory evidence; {ROOT / 'out/isa/scalar-integer-inventory.json'}")
    print(f"ordinary scalar memory: {len(memory_report['verified_handlers'])}/14 handlers with actual width/address/register/memory evidence; {ROOT / 'out/isa/base-memory-inventory.json'}")
    print(f"ordinary branch/jump: {len(branch_report['verified_handlers'])}/8 handlers with actual next-PC/link/alias/memory evidence; {ROOT / 'out/isa/branch-inventory.json'}")
    print(f"all active CPU selectors with dedicated audits: {cpu_report['verified_dedicated_handler_count']}/{cpu_report['decoded_handler_count']}; remaining {cpu_report['remaining_dedicated_handler_count']} (including {cpu_report['remaining_explicit_mcode_stub_count']} microcode stubs)")
    if "--require-complete" in sys.argv and (missing_runs or document["unverified_nontrapping_handlers"] or
            missing_faults or document["verified_trap_stub_count"] != len(stubs)):
        raise RuntimeError("incomplete ET extension execution/fault evidence; inspect the inventory gaps")
    if "--require-complete" in sys.argv and (missing_cache or cache_report["missing_csrs"]):
        raise RuntimeError("incomplete cache CSR execution evidence; inspect the separate cache inventory")
    if "--require-complete" in sys.argv and (missing_sync or sync_report["missing_csrs"]):
        raise RuntimeError("incomplete synchronization execution evidence; inspect the separate synchronization inventory")
    if "--require-complete" in sys.argv and (missing_ports or port_report["missing_csrs"]):
        raise RuntimeError("incomplete message-port execution evidence; inspect the separate port inventory")
    if "--require-complete" in sys.argv and missing_privilege:
        raise RuntimeError("incomplete message-port M/U permission evidence; inspect the separate privilege inventory")
    if "--require-complete" in sys.argv and missing_peers:
        raise RuntimeError("incomplete peer synchronization execution evidence; inspect the separate peer inventory")
    if "--require-complete" in sys.argv and missing_scalar_fp:
        raise RuntimeError("incomplete scalar FP execution/fault evidence; inspect the separate scalar FP inventory")
    if "--require-complete" in sys.argv and missing_integer:
        raise RuntimeError("incomplete scalar integer execution/register evidence; inspect the separate integer inventory")
    if "--require-complete" in sys.argv and missing_memory:
        raise RuntimeError("incomplete ordinary scalar memory execution/register evidence; inspect the separate memory inventory")
    if "--require-complete" in sys.argv and missing_branches:
        raise RuntimeError("incomplete ordinary branch/jump execution evidence; inspect the separate branch inventory")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"inventory.py: {exc}")
        raise SystemExit(1)
