#!/usr/bin/env python3
"""Enter real U mode and observe ET message-port access and fault behavior."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import struct
import subprocess
import sys
import uuid

from add import run_logged
from gemm import ROOT, command, runtime, symbols
from message_ports import CSRS, DONE, FEATURE_CLEAR, MASK64, PORT_ESR, SEED
from message_ports import config_operand, label, receiver_setup, sends_in, startup
from cache_control import cache_events


OUT = ROOT / "out" / "message-port-privilege"
SENTINEL = 0xA5A5A5A5A5A5A5A5
LINKER = """/* SPDX-License-Identifier: Apache-2.0 */
OUTPUT_ARCH("riscv")
ENTRY(_start)
SECTIONS {
  .text 0x8000001000 : { KEEP(*(.text.entry)) }
  .text.user 0x8004001000 : { *(.text.user) }
  .data 0x8004100000 : { *(.data .data.*) }
  .stack 0x8000200000 (NOLOAD) : { __stack_bottom = .; . += 0x4000; __stack_top = .; }
}
"""


def payloads(case):
    return [(0xABCDEF0000000000 | (0x81234567 + p * 0x1010101 + i * 0x11111111))
            if case == "primary" else (0xFEDCBA9876543210 ^ (p * 0x1111111111111111) ^ (i * 0x102030405060708))
            for p in range(4) for i in range(4)]


def operations():
    ops = []
    for p in range(4):
        for phase in ("deny", "allow", "disabled"):
            ops.append(dict(name=f"p{p}_{phase}_config", port=p, phase=phase, kind="config", mode="M", csr=f"portctrl{p}"))
            if phase != "disabled":
                for i in range(2):
                    ops.append(dict(name=f"p{p}_{phase}_send{i}", port=p, phase=phase, kind="send", mode="M", csr=None,
                                    input_index=p * 4 + i + (2 if phase == "allow" else 0)))
            reads = [("head", f"porthead{p}"), ("headnb", f"portheadnb{p}")]
            if phase == "allow":
                reads.append(("empty", f"portheadnb{p}"))
            if phase != "disabled":
                reads.append(("control", f"portctrl{p}"))
            for suffix, csr in reads:
                ops.append(dict(name=f"p{p}_{phase}_u_{suffix}", port=p, phase=phase, kind="read", mode="U", csr=csr,
                                cause=2 if phase != "allow" or suffix == "control" else 0,
                                slot=0 if suffix == "head" else 1 if suffix == "headnb" else None))
            ops.append(dict(name=f"p{p}_{phase}_exit", port=p, phase=phase, kind="ecall", mode="U", csr=None, cause=8))
            if phase != "allow":
                for i, (suffix, csr) in enumerate((("head", f"porthead{p}"), ("headnb", f"portheadnb{p}"))):
                    ops.append(dict(name=f"p{p}_{phase}_m_{suffix}", port=p, phase=phase, kind="read", mode="M", csr=csr,
                                    cause=2 if phase == "disabled" else 0, slot=i))
    return ops


def kernel(case, ops):
    width, way, flags = (4, 1, 0) if case == "primary" else (8, 2, 2)
    lines = [*startup(), "    csrwi medeleg, 0", "    csrwi mideleg, 0", *receiver_setup(range(4), way)]
    for op in ops:
        p, phase, name, kind = (op[k] for k in ("port", "phase", "name", "kind"))
        if kind == "config":
            lines.extend((*config_operand(p, width, 2, way, flags | (0x10 if phase != "deny" else 0), phase != "disabled"),
                          *label(f"op_{name}"), f"    csrw portctrl{p}, t1", *label(f"control_{name}"),
                          f"    csrr t0, portctrl{p}", f"    la t1, control_record_{name}", "    sd t0, 0(t1)"))
        elif kind == "send":
            lines.extend(("    la t1, input_payloads", *label(f"input_{name}"), f"    ld t1, {op['input_index'] * 8}(t1)",
                          f"    li t2, 0x{PORT_ESR + p * 64:x}", *label(f"op_{name}"), "    sd t1, 0(t2)"))
        else:
            # Each phase enters U with MPP=U, MIE=MPIE=0. The actual mret and
            # the I(U) trace prove privilege; a configured flag is insufficient.
            if name.endswith("_u_head"):
                entry = f"user_p{p}_{phase}"
                lines.extend((f"    la s2, after_p{p}_{phase}_exit", f"    la t0, {entry}", "    csrw mepc, t0", "    csrr t0, mstatus",
                              "    li t1, -6281 # clear MPP[12:11], MPIE[7], MIE[3]", "    and t0, t0, t1",
                              "    csrw mstatus, t0", *label(f"enter_p{p}_{phase}"), "    mret",
                              '.section .text.user,"ax",@progbits', *label(entry)))
            lines.extend((f"    la s0, record_{name}", f"    li s4, 0x{SEED:x}",
                          *label(f"before_{name}"), "    sd s4, 0(s0)", *label(f"op_{name}"),
                          "    ecall" if kind == "ecall" else f"    csrr s4, {op['csr']}"))
            if kind == "ecall":
                lines.append('.section .text.entry,"ax",@progbits')
            lines.extend((*label(f"after_{name}"), "    sd s4, 8(s0)"))
            if kind == "read" and not op["cause"] and op["slot"] is not None:
                lines.extend((f"    la s9, target_{p}", "    addi s9, s9, 64", "    add s9, s9, s4",
                              *label(f"payload_{name}"), f"    {'lwu' if width == 4 else 'ld'} s1, 0(s9)",
                              "    sd s1, 48(s0)", "    sd s9, 56(s0)"))
    lines.extend((f"    li t0, 0x{DONE:x}", "    la t1, completion", "    sw t0, 0(t1)",
                  *label("park"), "    wfi", "    j park", ".balign 4096", *label("trap_handler"),
                  "    csrr t0, mcause", "    li t1, 2", "    beq t0, t1, expected_trap",
                  "    li t1, 8", "    beq t0, t1, expected_trap", "    la t1, unexpected_trap",
                  "    sd t0, 0(t1)", "    csrr t0, mepc", "    sd t0, 8(t1)",
                  "    csrr t0, mtval", "    sd t0, 16(t1)", "    j park", "expected_trap:"))
    for name, csr, offset in (("cause", "mcause", 16), ("epc", "mepc", 24), ("tval", "mtval", 32), ("status", "mstatus", 40)):
        lines.extend((*label(f"capture_{name}"), f"    csrr t0, {csr}", f"    sd t0, {offset}(s0)"))
    # Illegal instructions resume in their original privilege and leave x20
    # untouched. U ECALL is the explicit phase exit; only that trap returns M.
    lines.extend(("    csrr t0, mcause", "    li t1, 8", "    bne t0, t1, trap_resume",
                  "    csrr t0, mstatus", "    li t1, 0x1800", "    or t0, t0, t1", "    csrw mstatus, t0",
                  "    csrw mepc, s2", "    mret",
                  "trap_resume:", "    csrr t0, mepc", "    addi t0, t0, 4", "    csrw mepc, t0", "    mret", ".option pop",
                  '.section .data,"aw",@progbits', ".balign 64", *label("__monitor_start"), *label("input_payloads"),
                  "    .dword " + ", ".join(f"0x{x:x}" for x in payloads(case)),
                  *label("feature_state"), "    .fill 64,1,0xa5"))
    for p in range(4):
        lines.extend((*label(f"target_{p}"), "    .fill 192,1,0xa5"))
    for op in ops:
        if op["kind"] == "config":
            lines.extend((*label(f"control_record_{op['name']}"), "    .fill 64,1,0xa5"))
        elif op["kind"] != "send":
            lines.extend((*label(f"record_{op['name']}"), "    .fill 128,1,0xa5"))
    lines.extend((*label("unexpected_trap"), "    .dword 0,0,0", *label("completion"), "    .word 0", *label("__monitor_end")))
    return "\n".join(lines) + "\n"


def execution_events(trace):
    """Parse actual M/U instruction groups; retain their complete raw evidence."""
    events, current = [], None
    for line in trace.splitlines():
        match = re.match(r"^(\d+): DEBUG EMU: \[(H\d+ S\d+:N\d+:C\d+:T\d+)\] I\(([MSU])\): "
                         r"0x([0-9a-f]+) \(0x([0-9a-f]{8})\) (.*)$", line)
        if match:
            cycle, hart, mode, pc, word, decoded = match.groups()
            current = dict(cycle=int(cycle), hart=hart, mode=mode, pc=int(pc, 16), word=int(word, 16),
                           decoded=decoded, registers={}, raw=[], accesses=[])
            events.append(current)
        if current is not None:
            current["raw"].append(line)
            reg = re.search(r"\bx(\d+) ([=:]) 0x([0-9a-f]+)", line)
            if reg:
                current["registers"][f"x{reg[1]}:{reg[2]}"] = int(reg[3], 16)
            access = re.search(r"MEM(8|16|32|64)\[0x([0-9a-f]+)\] ([=:]) 0x([0-9a-f]+)", line)
            if access:
                current["accesses"].append(dict(bits=int(access[1]), address=int(access[2], 16),
                                               direction="write" if access[3] == "=" else "read", value=int(access[4], 16)))
    return events


def execute(case, env):
    out = OUT if case == "primary" else OUT / case
    out.mkdir(parents=True, exist_ok=True)
    log = out / "commands.log"
    log.write_text("")
    for name in ("result.json", "registers.json", "output.bin", "prestart.bin", "trace.log"):
        (out / name).unlink(missing_ok=True)
    ops = operations()
    (out / "kernel.S").write_text(kernel(case, ops))
    (out / "link.ld").write_text(LINKER)
    container, podman = env["kind"] == "podman", shutil.which("podman") or "podman"
    stage = f"/tmp/etsoc1-port-privilege-{uuid.uuid4().hex[:10]}"
    work = stage if container else str(out)
    def checked(argv):
        result = run_logged(log, argv)
        if result.returncode:
            raise RuntimeError(f"port privilege command failed ({result.returncode}); inspect {log}")
        return result
    try:
        if container:
            checked([podman, "exec", env["container"], "mkdir", "-p", stage])
            for name in ("kernel.S", "link.ld"):
                checked([podman, "cp", str(out / name), f"{env['container']}:{stage}/{name}"])
        tp, wd = shlex.quote(env["tool_prefix"]), shlex.quote(work)
        built = run_logged(log, command(env, ["bash", "-lc", f"set -euo pipefail; cd {wd}; "
            f"{tp}as --march=rv64imfc -mabi=lp64f -o kernel.o kernel.S; "
            f"{tp}ld --no-relax --build-id=none -T link.ld -o kernel.elf kernel.o; "
            f"{tp}objdump -d -M numeric kernel.elf > kernel.asm; {tp}readelf -h -l -S kernel.elf > elf-inspection.txt; "
            f"{tp}nm -n --defined-only kernel.elf > symbols.txt; {tp}objcopy -O binary --only-section=.text kernel.elf text.bin; "
            f"{tp}objcopy -O binary --only-section=.text.user kernel.elf text-user.bin"]))
        if container:
            checked([podman, "cp", f"{env['container']}:{stage}/.", str(out)])
        if built.returncode:
            raise RuntimeError("port privilege assembly failed")
        syms = symbols((out / "symbols.txt").read_text())
        inspection, text, asm = ((out / name).read_text() if name != "text.bin" else (out / name).read_bytes()
                                 for name in ("elf-inspection.txt", "text.bin", "kernel.asm"))
        entry_match = re.search(r"Entry point address:\s+0x([0-9a-f]+)", inspection)
        section = re.search(r"^\s*\[\s*\d+\]\s+\.text\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", inspection, re.M)
        if not entry_match or not section:
            raise RuntimeError("missing privilege ELF layout")
        entry = int(entry_match[1], 16)
        vma, offset, text_size = (int(section[i], 16) for i in (1, 2, 3))
        elf = (out / "kernel.elf").read_bytes()
        phoff, phsize, phcount = struct.unpack_from("<Q", elf, 32)[0], *struct.unpack_from("<HH", elf, 54)
        segments = [struct.unpack_from("<II6Q", elf, phoff + i * phsize) for i in range(phcount)]
        sites = []
        for op in ops:
            pc = syms[f"op_{op['name']}"]
            mappings = [row[2] + pc - row[3] for row in segments if row[0] == 1 and row[1] & 1 and row[3] <= pc and pc + 4 <= row[3] + row[5]]
            if len(mappings) != 1:
                raise RuntimeError("privilege instruction lacks one executable PT_LOAD mapping")
            raw = elf[mappings[0]:mappings[0] + 4]
            word = int.from_bytes(raw, "little")
            decoded = [line.strip() for line in asm.splitlines() if re.search(rf"\b{pc:x}:\s", line)]
            csr = CSRS[op["csr"]] if op["csr"] else None
            if op["kind"] == "send":
                valid = (word & 127, word >> 12 & 7, word >> 15 & 31, word >> 20 & 31) == (0x23, 3, 7, 6)
            elif op["kind"] == "ecall":
                valid = word == 0x73
            else:
                config = op["kind"] == "config"
                valid = (word & 127, word >> 20, word >> 12 & 7, word >> 7 & 31, word >> 15 & 31) == \
                        (0x73, csr, 1 if config else 2, 0 if config else 20, 6 if config else 0)
            if len(raw) != 4 or len(decoded) != 1 or not valid:
                raise RuntimeError(f"wrong privilege instruction: {op['name']}")
            sites.append({**op, "pc": hex(pc), "word": f"0x{word:08x}", "bytes_memory_order": raw.hex(" "),
                          "file_offset": hex(mappings[0]), "decoded": decoded[0]})
        (out / "operations.json").write_text(json.dumps(sites, indent=2) + "\n")
        (out / "operations.bin").write_bytes(b"".join(bytes.fromhex(s["bytes_memory_order"]) for s in sites))
        (out / "op.bin").write_bytes(bytes.fromhex(sites[0]["bytes_memory_order"]))
        start, size = syms["__monitor_start"], syms["__monitor_end"] - syms["__monitor_start"]
        (out / "elf-layout.json").write_text(json.dumps(dict(entry=hex(entry), selected_harts=["H0"],
            executable_sections=[".text", ".text.user"], text_vma=hex(vma), text_file_offset=hex(offset), text_size=text_size,
            section_dumps={".text": "text.bin", ".text.user": "text-user.bin"},
            monitor_address=hex(start), monitor_size=size, symbols={k: hex(v) for k, v in syms.items()}), indent=2) + "\n")
        sim = [env["simulator"], "-l", "-lm", "0", "-lt", "0", "-sp_dis", "-Werror=memory",
               "-reset_pc", hex(entry), "-single_thread", "-minions", "0x1", "-shires", "0x1",
               "-max_cycles", "10000", "-elf_load", f"{work}/kernel.elf", "-dump_at_pc_pc", hex(entry),
               "-dump_at_pc_addr", hex(start), "-dump_at_pc_size", hex(size), "-dump_at_pc_file", f"{work}/prestart.bin",
               "-dump_addr", hex(start), "-dump_size", str(size), "-dump_file", f"{work}/output.bin"]
        run = run_logged(log, command(env, ["timeout", "--signal=TERM", "--kill-after=5s", "90s", *sim]))
        (out / "trace.log").write_text(run.stdout or "")
        if container:
            checked([podman, "cp", f"{env['container']}:{stage}/.", str(out)])
        if run.returncode:
            raise RuntimeError(f"port privilege execution failed ({run.returncode})")
        validate(case, sites, out, syms, start, size)
    finally:
        if container:
            # Copy failure diagnostics before removing only this run's staging directory.
            run_logged(log, [podman, "cp", f"{env['container']}:{stage}/.", str(out)])
            run_logged(log, [podman, "exec", env["container"], "rm", "-rf", stage])


def validate(case, sites, out, syms, start, size):
    trace = (out / "trace.log").read_text()
    if "Finishing emulation" not in trace or "Error, max cycles reached" in trace or "unlocked!" in trace:
        raise RuntimeError("privilege diagnostic did not complete")
    events = execution_events(trace)
    if {e["hart"] for e in events} != {"H0 S0:N0:C0:T0"} or {e["mode"] for e in events} != {"M", "U"}:
        raise RuntimeError("wrong actual harts/privilege modes")
    def event(name, mode="M"):
        found = [e for e in events if e["pc"] == syms[name]]
        if len(found) != 1 or found[0]["mode"] != mode:
            raise RuntimeError(f"expected one real {mode}-mode instruction at {name}")
        return found[0]
    pre, memory = ((out / name).read_bytes() for name in ("prestart.bin", "output.bin"))
    if len(pre) != size or len(memory) != size:
        raise RuntimeError("incomplete privilege memory dumps")
    off = lambda name: syms[name] - start
    expected, values = bytearray(pre), payloads(case)
    if struct.unpack_from("<16Q", pre, off("input_payloads")) != tuple(values):
        raise RuntimeError("wrong actual input payloads")
    width, way, flags = (4, 1, 0) if case == "primary" else (8, 2, 2)
    feature = struct.unpack_from("<3Q", memory, off("feature_state"))
    if feature[1] != feature[0] & ~FEATURE_CLEAR or feature[2] & 8:
        raise RuntimeError("wrong feature/interrupt initialization")
    for name, value in zip(("feature_before", "feature_after", "status_initial"), feature):
        if event(name)["registers"]["x5:="] != value:
            raise RuntimeError("feature/status snapshot differs from actual register read")
    expected[off("feature_state"):off("feature_state") + 24] = struct.pack("<3Q", *feature)
    locks = cache_events(trace)
    for p in range(4):
        address, pos = syms[f"target_{p}"] + 64, off(f"target_{p}") + 64
        if locks[syms[f"lock_{p}"]]["accesses"] != [dict(bits=512, address=hex(address), direction="write", bytes=bytes(64).hex(" "))]:
            raise RuntimeError("missing actual hard-lock backing-memory write")
        if pre[pos - 64:pos + 128] != bytes([0xA5]) * 192:
            raise RuntimeError("target guards were not seeded")
        expected[pos:pos + 64] = bytes(64)
    faults = [s for s in sites if s.get("cause")]
    trap_logs = re.findall(r"\[H0 S0:N0:C0:T0\].*Trapping to M-mode with cause 0x([0-9a-f]+) and tval 0x([0-9a-f]+)", trace)
    captures = {kind: [e for e in events if e["pc"] == syms[f"capture_{kind}"]] for kind in ("cause", "epc", "tval", "status")}
    if len(trap_logs) != len(faults) or any(len(rows) != len(faults) for rows in captures.values()):
        raise RuntimeError("unexpected/missing trap handler entries")
    fault_index, rows, records = 0, [], []
    for site in sites:
        name, p, phase, kind = (site[k] for k in ("name", "port", "phase", "kind"))
        actual = event(f"op_{name}", site["mode"])
        if actual["word"] != int(site["word"], 16):
            raise RuntimeError("executed operation differs from assembled ELF")
        if kind == "config":
            address = syms[f"target_{p}"] + 64
            control = (way << 24) | (((address >> 6) & 15) << 16) | 0x100 | ((width.bit_length() - 1) << 5) | flags | \
                      (0x10 if phase != "deny" else 0) | int(phase != "disabled") | 0x8000
            observed = event(f"control_{name}")["registers"]["x5:="]
            if observed != control or struct.unpack_from("<Q", memory, off(f"control_record_{name}"))[0] != observed:
                raise RuntimeError("real port configuration readback mismatch")
            expected[off(f"control_record_{name}"):off(f"control_record_{name}") + 8] = struct.pack("<Q", control)
        elif kind == "send":
            value, slot = values[site["input_index"]], site["input_index"] % 2
            address = syms[f"target_{p}"] + 64 + slot * width
            if actual["registers"] != {"x6::": value, "x7::": PORT_ESR + p * 64} or \
                    event(f"input_{name}")["registers"]["x6:="] != value:
                raise RuntimeError("actual device send input/address mismatch")
            if actual["accesses"] != [dict(bits=64, address=PORT_ESR + p * 64, direction="write", value=value)] or \
                    sends_in(actual["raw"]) != [(0, p, value >> (i * 32) & 0xFFFFFFFF, address + 4 * i) for i in range(width // 4)]:
                raise RuntimeError("missing actual sender/receiver message writes")
            pos = off(f"target_{p}") + 64 + slot * width
            expected[pos:pos + width] = value.to_bytes(8, "little")[:width]
        else:
            offset = off(f"record_{name}")
            record = struct.unpack_from("<8Q", memory, offset)
            if pre[offset:offset + 128] != bytes([0xA5]) * 128 or event(f"before_{name}", site["mode"])["registers"]["x20::"] != SEED:
                raise RuntimeError("missing real seeded destination snapshot")
            after_mode = "M" if kind == "ecall" else site["mode"]
            if event(f"after_{name}", after_mode)["registers"]["x20::"] != record[1]:
                raise RuntimeError("destination snapshot differs from actual register")
            wanted = [SEED, SEED, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL]
            if site["cause"]:
                index, fault_index = fault_index, fault_index + 1
                captured = [captures[k][index]["registers"]["x5:="] for k in ("cause", "epc", "tval", "status")]
                expected_tval = 0 if kind == "ecall" else actual["word"]
                if captured[:3] != [site["cause"], actual["pc"], expected_tval] or \
                        tuple(int(x, 16) for x in trap_logs[index]) != (site["cause"], expected_tval) or \
                        (captured[3] >> 11 & 3) != (0 if site["mode"] == "U" else 3) or "x20:=" in actual["registers"]:
                    raise RuntimeError(f"wrong real fault state/destination at {name}")
                wanted[2:6] = captured
            else:
                returned = MASK64 if site["slot"] is None else site["slot"] * width
                if actual["registers"].get("x20:=") != returned:
                    raise RuntimeError(f"wrong real head return at {name}")
                wanted[1] = returned
                if site["slot"] is not None:
                    index = p * 4 + site["slot"] + (2 if phase == "allow" else 0)
                    value = values[index] & ((1 << (width * 8)) - 1)
                    address = syms[f"target_{p}"] + 64 + returned
                    load = event(f"payload_{name}", site["mode"])
                    if load["registers"].get("x9:=") != value or load["registers"].get("x25::") != address or \
                            load["accesses"] != [dict(bits=width * 8, address=address, direction="read", value=value)] or \
                            (load["word"] & 127, load["word"] >> 12 & 7) != (3, 6 if width == 4 else 3):
                        raise RuntimeError("head payload was not loaded from actual returned offset")
                    wanted[6:8] = [value, address]
            if record != tuple(wanted):
                raise RuntimeError(f"fault/head memory record mismatch: {name}")
            expected[offset:offset + 64] = struct.pack("<8Q", *wanted)
            records.append({**site, "actual": [hex(x) for x in record], "instruction_event": actual,
                            "destination_after_mode": after_mode})
        rows.append({**site, "cycle": actual["cycle"], "pass": True})
    for p in range(4):
        for phase in ("deny", "allow", "disabled"):
            entered = event(f"enter_p{p}_{phase}")
            if entered["word"] != 0x30200073 or not any("prv = U" in line for line in entered["raw"]):
                raise RuntimeError("U-mode entry lacks actual mret/privilege transition evidence")
    if re.search(r"(?:Start|Stop) waiting for message", trace):
        raise RuntimeError("denied/disabled head incorrectly stalled")
    parked = event("park")
    if not parked["decoded"].startswith("wfi"):
        raise RuntimeError("missing M-mode termination")
    complete = struct.unpack_from("<I", memory, off("completion"))[0]
    expected[off("completion"):off("completion") + 4] = struct.pack("<I", DONE)
    (out / "expected.bin").write_bytes(expected)
    if complete != DONE or memory != expected:
        raise RuntimeError("completion/whole guarded monitor mismatch")
    (out / "registers.json").write_text(json.dumps(dict(source="actual M/U SysEmu instruction groups and device snapshots",
        state_names=["x20_before", "x20_after", "mcause", "mepc", "mtval", "mstatus_at_trap", "payload", "payload_address"],
        operations=records), indent=2) + "\n")
    illegal_count = sum(int(cause, 16) == 2 for cause, _ in trap_logs)
    ecall_count = sum(int(cause, 16) == 8 for cause, _ in trap_logs)
    head_count = sum(site["kind"] == "read" and "x20:=" in event(f"op_{site['name']}", site["mode"])["registers"] for site in sites)
    (out / "result.json").write_text(json.dumps(dict(case=case, operation_count=len(sites), csr_count=12,
        message_width=width, illegal_trap_count=illegal_count, user_ecall_count=ecall_count, successful_head_count=head_count,
        whole_monitor_matches=True, completion_word=hex(complete), operations=rows, **{"pass": True}), indent=2) + "\n")
    print(f"Message-port privilege {case}: {len(sites)} sites, real M/U execution across four ports, PASS")
    print("  U denied: head/headnb cause 2, destinations unchanged; subsequent M reads retain both messages")
    print("  U enabled: head/headnb return 0/width; empty headnb returns -1; U control reads cause 2")
    print(f"  Disabled M/U heads cause 2 without waiting; {illegal_count} illegal faults + {ecall_count} U ECALL exits; {out}")


def main():
    cases = sys.argv[1:] or ["primary", "exact"]
    if any(case not in ("primary", "exact") for case in cases):
        raise SystemExit("usage: python3 examples/message_port_privilege.py [primary|exact ...]")
    env = runtime()
    for case in cases:
        execute(case, env)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print(f"message_port_privilege.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
