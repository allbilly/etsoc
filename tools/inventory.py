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
    peer_report, missing_peers = synchronization_peer_evidence(source_root, commit)
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
    print(f"peer synchronization cases with audited T0/T1 routing/block/wake/overflow: {len(peer_report['verified_runs'])}/4; {ROOT / 'out/isa/synchronization-peer-inventory.json'}")
    if "--require-complete" in sys.argv and (missing_runs or document["unverified_nontrapping_handlers"] or
            missing_faults or document["verified_trap_stub_count"] != len(stubs)):
        raise RuntimeError("incomplete ET extension execution/fault evidence; inspect the inventory gaps")
    if "--require-complete" in sys.argv and (missing_cache or cache_report["missing_csrs"]):
        raise RuntimeError("incomplete cache CSR execution evidence; inspect the separate cache inventory")
    if "--require-complete" in sys.argv and (missing_sync or sync_report["missing_csrs"]):
        raise RuntimeError("incomplete synchronization execution evidence; inspect the separate synchronization inventory")
    if "--require-complete" in sys.argv and (missing_ports or port_report["missing_csrs"]):
        raise RuntimeError("incomplete message-port execution evidence; inspect the separate port inventory")
    if "--require-complete" in sys.argv and missing_peers:
        raise RuntimeError("incomplete peer synchronization execution evidence; inspect the separate peer inventory")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"inventory.py: {exc}")
        raise SystemExit(1)
