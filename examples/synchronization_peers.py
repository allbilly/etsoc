#!/usr/bin/env python3
"""Minion/thread FCC routing, block/wake, FLB arrivals and real credit overflow."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import struct
import subprocess
import sys
import uuid

from gemm import ROOT, LINKER, command, runtime, symbols
from add import run_logged


OUT = ROOT / "out" / "synchronization-peers"
DONE, SEED = 0x4B4F5445, 0x5AA55AA55AA55AA5
FEATURE, FCC, FLB = 0x01C0340000, 0x01003400C0, 0x0100340100
CSRS = {"fcc": 0x821, "fccnb": 0xCC0, "flb": 0x820}
STAGES = ("wait", "consume_other", "flb_receiver", "bulk", "wrap", "refill", "consume_refill", "flb_sender")
CASES = ("primary", "exact", "threads-primary", "threads-exact")


def parameters(case):
    if case not in CASES:
        raise ValueError(f"unknown case: {case}")
    return (0, 3, 1) if case.endswith("primary") else (1, 31, (1 << 63) | 1)


def routing(case):
    # system.cpp: index/2 selects T0/T1, index%2 selects FCC0/FCC1.
    receiver, sender = (1, 0) if case.startswith("threads") else (0, 2)
    return f"H{receiver}", f"H{sender}", FCC + (receiver % 2) * 16


def stages(case):
    return (*STAGES, "wrong_thread", "consume_thread") if case.startswith("threads") else STAGES


def label(name):
    return [f".globl {name}", f"{name}:"]


def capture(name):
    # These fields are real scalar register reads, written by the device. The
    # host independently checks them against raw trace events and references.
    lines = [f"    la t3, record_{name}"]
    for offset, reg in ((0, "s5"), (8, "s6"), (16, "s4")):
        lines.extend((*label(f"capture_{reg}_{name}"), f"    sd {reg}, {offset}(t3)"))
    for offset, field, csr, reg in ((24, "error", "tensor_error", "s7"), (32, "status", "mstatus", "s8"),
                                   (40, "enabled", "mie", "s9"), (48, "pending", "mip", "s10"), (56, "hart", "mhartid", "s11")):
        lines.extend((*label(f"read_{field}_{name}"), f"    csrr {reg}, {csr}", f"    sd {reg}, {offset}(t3)"))
    return lines


def kernel(case):
    counter, barrier, send_mask = parameters(case)
    receiver, sender, credit_base = routing(case)
    other, barrier_addr, guard_addr = counter ^ 1, FLB + barrier * 8, FLB + ((barrier + 1) % 32) * 8
    thread_test = []
    if case.startswith("threads"):
        thread_test = [*label("before_wrong_thread"), "    csrr s5, fccnb", f"    li s4, 0x{SEED:x}",
                       f"    li t2, 0x{FCC + counter * 8:x}", *label("op_wrong_thread"),
                       "    sd t1, 0(t2) # T0 matching counter must not wake T1", *label("after_wrong_thread"),
                       "    csrr s6, fccnb", *capture("wrong_thread"), *label("before_consume_thread"),
                       "    csrr s5, fccnb", f"    li t1, {counter | 0x100}", *label("op_consume_thread"),
                       "    csrrw s4, fcc, t1", *label("after_consume_thread"), "    csrr s6, fccnb", *capture("consume_thread"),
                       "    la t1, input_controls", "    ld t1, 16(t1)", "    la t3, handshake"]
    select_receiver = ["    bnez t0, sender"] if receiver == "H0" else ["    li t1, 1", "    bne t0, t1, sender"]
    lines = ["# SPDX-License-Identifier: Apache-2.0",
             "# Startup provenance: Copyright (c) 2025 Ainekko, Co.; ET Platform boot.S.",
             ".option push", ".option norelax", ".option norvc", '.section .text.entry,"ax",@progbits',
             *label("_start"), "    csrwi satp, 0", "    csrwi mie, 0", "    csrwi mip, 0", "    csrci mstatus, 8",
             "    la sp, __stack_top", "    la t0, trap_handler", "    csrw mtvec, t0", "    csrwi tensor_error, 0",
             *label("read_hart"), "    csrr t0, mhartid", *select_receiver,
             "    la t3, feature_state", f"    li t1, 0x{FEATURE:x}", *label("feature_before"), "    ld t0, 0(t1)",
             "    sd t0, 0(t3)", "    andi t0, t0, -3", "    sd t0, 0(t1)", *label("feature_after"),
             "    ld t0, 0(t1)", "    sd t0, 8(t3)", f"    li t2, 0x{barrier_addr:x}", "    sd zero, 0(t2)",
             f"    li t2, 0x{guard_addr:x}", "    li t0, 0x5a", "    sd t0, 0(t2)",
             *label("before_wait"), "    csrr s5, fccnb", f"    li s4, 0x{SEED:x}", *label("seed_wait"), "    addi t0, s4, 0",
             f"    li t1, {counter | 0x100}", "    la t3, handshake", "    li t0, 1", *label("receiver_ready"), "    sd t0, 0(t3)",
             *label("op_wait"), "    csrrw s4, fcc, t1 # zero credits -> restart; no destination write yet",
             *label("after_wait"), "    csrr s6, fccnb", *capture("wait"),
             *label("before_consume_other"), "    csrr s5, fccnb", f"    li t1, {other | 0x100}",
             *label("op_consume_other"), "    csrrw s4, fcc, t1", *label("after_consume_other"), "    csrr s6, fccnb", *capture("consume_other"),
             f"    li t2, 0x{barrier_addr:x}", *label("before_flb_receiver"), "    ld s5, 0(t2)",
             f"    li t1, {(1 << 13) | (1 << 5) | barrier}", *label("op_flb_receiver"), "    csrrw s4, flb, t1",
             *label("after_flb_receiver"), "    ld s6, 0(t2)", *capture("flb_receiver"), "    la t3, handshake", "    li t0, 2",
             *label("receiver_second_phase"), "    sd t0, 0(t3)", "receiver_poll:", "    ld t0, 8(t3)", "    beqz t0, receiver_poll",
             f"    li t2, 0x{barrier_addr:x}", *label("barrier_final"), "    ld s1, 0(t2)", f"    li t2, 0x{guard_addr:x}",
             *label("guard_final"), "    ld s2, 0(t2)", "    la t3, final_state", "    sd s1, 0(t3)", "    sd s2, 8(t3)",
             "    la t1, input_controls", *label("input_mask_receiver"), "    ld t1, 16(t1)", f"    li t2, 0x{credit_base + counter * 8:x}",
             *label("before_bulk"), "    csrr s5, fccnb", f"    li s4, 0x{SEED:x}", "    la t3, input_controls",
             *label("input_count"), "    ld t3, 24(t3)", *label("op_bulk"), "    sd t1, 0(t2) # 65,535 actual credit increments",
             "    addi t3, t3, -1", "    bnez t3, op_bulk", *label("after_bulk"), "    csrr s6, fccnb", *capture("bulk"),
             *label("before_wrap"), "    csrr s5, fccnb", *label("op_wrap"), "    sd t1, 0(t2) # increment 65,536 wraps the uint16 counter",
             *label("after_wrap"), "    csrr s6, fccnb", *capture("wrap"),
             *label("error_clear"), "    csrwi tensor_error, 0", *label("before_refill"), "    csrr s5, fccnb",
             *label("op_refill"), "    sd t1, 0(t2)", *label("after_refill"), "    csrr s6, fccnb", *capture("refill"),
             *label("before_consume_refill"), "    csrr s5, fccnb", f"    li t1, {counter | 0x100}",
             *label("op_consume_refill"), "    csrrw s4, fcc, t1", *label("after_consume_refill"), "    csrr s6, fccnb", *capture("consume_refill"),
             f"    li t0, 0x{DONE:x}", "    la t1, completion", "    sw t0, 0(t1)", *label("park"), "    wfi", "    j park",
             "sender:", f"    li t1, {int(sender[1:])}", "    bne t0, t1, trap_handler", "    la t3, handshake", "sender_poll_ready:",
             "    ld t0, 0(t3)", "    beqz t0, sender_poll_ready", "    li t0, 64", "sender_delay:",
             "    addi t0, t0, -1", "    bnez t0, sender_delay", "    la t1, input_controls", *label("input_mask_sender"),
             "    ld t1, 16(t1)", *thread_test, f"    li t2, 0x{credit_base + other * 8:x}", *label("op_sender_other"),
             "    sd t1, 0(t2) # wrong counter must not wake the receiver", "    li t0, 32", "sender_delay_other:",
             "    addi t0, t0, -1", "    bnez t0, sender_delay_other", f"    li t2, 0x{credit_base + counter * 8:x}",
             *label("op_sender_credit"), "    sd t1, 0(t2)", "sender_poll_phase:", "    ld t0, 0(t3)",
             "    li t4, 2", "    bne t0, t4, sender_poll_phase", f"    li t2, 0x{barrier_addr:x}",
             *label("before_flb_sender"), "    ld s5, 0(t2)", f"    li t1, {(1 << 13) | (1 << 5) | barrier}",
             *label("op_flb_sender"), "    csrrw s4, flb, t1", *label("after_flb_sender"), "    ld s6, 0(t2)", *capture("flb_sender"),
             "    la t3, handshake", "    li t0, 1", *label("sender_done"), "    sd t0, 8(t3)", *label("sender_park"),
             "    wfi", "    j sender_park", ".balign 4096", "trap_handler:", "    csrr t0, mcause", "    la t1, trap_cause",
             "    sd t0, 0(t1)", "    li t0, 1", "    la t1, trap_marker", "    sw t0, 0(t1)", "    j park", ".option pop",
             '.section .data,"aw",@progbits', ".balign 64", *label("__monitor_start"), *label("input_controls"),
             f"    .dword {counter}, {barrier}, {send_mask}, 65535", "    .fill 32,1,0xa5", *label("feature_state"),
             "    .fill 64,1,0xa5", *label("handshake"), "    .dword 0,0", "    .fill 48,1,0xa5", *label("final_state"), "    .fill 64,1,0xa5"]
    for name in stages(case):
        lines.extend((*label(f"record_{name}"), "    .fill 128,1,0xa5"))
    lines.extend((*label("completion"), "    .word 0", *label("trap_marker"), "    .word 0", *label("trap_cause"),
                  "    .dword 0", *label("__monitor_end")))
    return "\n".join(lines) + "\n"


def execute(case, env):
    receiver, sender, _ = routing(case)
    out = OUT if case == "primary" else OUT / case
    out.mkdir(parents=True, exist_ok=True)
    log = out / "commands.log"
    log.write_text("")
    (out / "kernel.S").write_text(kernel(case))
    (out / "link.ld").write_text(LINKER)
    for name in ("result.json", "registers.json", "trace.log", "prestart.bin", "output.bin"):
        (out / name).unlink(missing_ok=True)
    stage = f"/tmp/etsoc1-synchronization-peers-{uuid.uuid4().hex[:10]}"
    container, podman = env["kind"] == "podman", shutil.which("podman") or "podman"
    def checked(argv):
        result = run_logged(log, argv)
        if result.returncode:
            raise RuntimeError(f"synchronization peers command failed ({result.returncode}); inspect {log}")
        return result
    if container:
        checked([podman, "exec", env["container"], "mkdir", "-p", stage])
        for name in ("kernel.S", "link.ld"):
            checked([podman, "cp", str(out / name), f"{env['container']}:{stage}/{name}"])
    work = stage if container else str(out)
    tp, qwork = shlex.quote(env["tool_prefix"]), shlex.quote(work)
    built = run_logged(log, [*command(env, ["bash", "-lc"]), f"set -euo pipefail; cd {qwork}; "
        f"{tp}as --march=rv64imfc -mabi=lp64f -o kernel.o kernel.S; "
        f"{tp}ld --no-relax --build-id=none -T link.ld -o kernel.elf kernel.o; "
        f"{tp}objdump -d -M numeric kernel.elf > kernel.asm; {tp}readelf -h -l -S kernel.elf > elf-inspection.txt; "
        f"{tp}objdump -h kernel.elf > sections.txt; {tp}nm -n --defined-only kernel.elf > symbols.txt; "
        f"{tp}objcopy -O binary --only-section=.text kernel.elf text.bin"])
    if container:
        checked([podman, "cp", f"{env['container']}:{stage}/.", str(out)])
    if built.returncode:
        raise RuntimeError(f"assemble synchronization peers ELF failed; inspect {log}")
    syms, inspection = symbols((out / "symbols.txt").read_text()), (out / "elf-inspection.txt").read_text()
    entry_match = re.search(r"Entry point address:\s+0x([0-9a-f]+)", inspection)
    text_match = re.search(r"^\s*\[\s*\d+\]\s+\.text\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", inspection, re.MULTILINE)
    if not entry_match or not text_match:
        raise RuntimeError("missing ELF entry/text mapping")
    entry = int(entry_match.group(1), 16)
    vma, offset, size = (int(text_match.group(i), 16) for i in (1, 2, 3))
    text, asm = (out / "text.bin").read_bytes(), (out / "kernel.asm").read_text()
    instructions = []
    for name in (*stages(case), "sender_other", "sender_credit"):
        pc = syms[f"op_{name}"]
        raw, word = text[pc - vma:pc - vma + 4], int.from_bytes(text[pc - vma:pc - vma + 4], "little")
        send = name in ("bulk", "wrap", "refill", "sender_other", "sender_credit", "wrong_thread")
        csr = CSRS["flb" if name.startswith("flb") else "fcc"] if not send else None
        if send:
            valid = (word & 0x7F, word >> 12 & 7, word >> 15 & 31, word >> 20 & 31, word >> 25, word >> 7 & 31) == (0x23, 3, 7, 6, 0, 0)
        else:
            valid = (word & 0x7F, word >> 20, word >> 12 & 7, word >> 7 & 31, word >> 15 & 31) == (0x73, csr, 1, 20, 6)
        decoded = [line.strip() for line in asm.splitlines() if re.search(rf"\b{pc:x}:\s", line)]
        if not valid or len(raw) != 4 or len(decoded) != 1:
            raise RuntimeError(f"wrong assembled peer instruction: {name}: {decoded}")
        instructions.append(dict(name=name, hart=sender if name in ("flb_sender", "sender_other", "sender_credit", "wrong_thread", "consume_thread") else receiver,
            mnemonic="sd" if send else "csrrw", csr=f"0x{csr:x}" if csr else None, pc=f"0x{pc:x}", word=f"0x{word:08x}",
            bytes_memory_order=raw.hex(" "), file_offset=f"0x{offset + pc - vma:x}", decoded=decoded[0],
            expected_executions=65535 if name == "bulk" else 2 if name == "wait" else 1))
    (out / "operations.json").write_text(json.dumps(instructions, indent=2) + "\n")
    (out / "operations.bin").write_bytes(b"".join(bytes.fromhex(row["bytes_memory_order"]) for row in instructions))
    (out / "op.bin").write_bytes(bytes.fromhex(instructions[0]["bytes_memory_order"]))
    start, monitor_size = syms["__monitor_start"], syms["__monitor_end"] - syms["__monitor_start"]
    (out / "elf-layout.json").write_text(json.dumps(dict(entry=f"0x{entry:x}", selected_harts=sorted([receiver, sender]), receiver_hart=receiver, sender_hart=sender,
        executable_sections=[".text"],
        text_vma=f"0x{vma:x}", text_file_offset=f"0x{offset:x}", text_size=size, monitor_address=f"0x{start:x}", monitor_size=monitor_size,
        operations=instructions, symbols={name: f"0x{addr:x}" for name, addr in syms.items()}), indent=2) + "\n")
    both_threads = case.startswith("threads")
    sim = [env["simulator"], "-l", "-ls", "0,0x3" if both_threads else "0,0x5", "-sp_dis", "-Werror=memory", "-reset_pc", hex(entry),
           *([] if both_threads else ["-single_thread"]), "-minions", "0x1" if both_threads else "0x3", "-shires", "0x1",
           "-max_cycles", "500000", "-elf_load", f"{work}/kernel.elf",
           "-dump_at_pc_pc", hex(entry), "-dump_at_pc_addr", hex(start), "-dump_at_pc_size", hex(monitor_size),
           "-dump_at_pc_file", f"{work}/prestart.bin", "-dump_addr", hex(start), "-dump_size", str(monitor_size), "-dump_file", f"{work}/output.bin"]
    run = run_logged(log, command(env, ["timeout", "--signal=TERM", "--kill-after=5s", "90s", *sim]))
    (out / "trace.log").write_text(run.stdout or "")
    if container:
        checked([podman, "cp", f"{env['container']}:{stage}/.", str(out)])
        checked([podman, "exec", env["container"], "rm", "-rf", stage])
    if run.returncode:
        raise RuntimeError(f"execute synchronization peers ELF failed ({run.returncode}); inspect {out}/trace.log")
    validate(case, out, syms, instructions, start, monitor_size)


def observe(trace, wanted, bulk_pc, counter, send_mask, bulk_word, receiver, sender, credit_base):
    """Retain selected real events; validate every bulk send without expanding JSON."""
    events, current, bulk_count, bulk_samples, harts = {}, None, 0, [], set()
    instruction = re.compile(r"^(\d+): DEBUG EMU: \[(H\d+) .*?\] I\(M\): 0x([0-9a-f]+) \(0x([0-9a-f]{8})\) (.*)$")
    reg = re.compile(r"\bx(\d+) ([=:]) 0x([0-9a-f]+)")
    mem = re.compile(r"MEM(8|16|32|64)\[0x([0-9a-f]+)\] ([=:]) 0x([0-9a-f]+)")
    credit = re.compile(r"\[(H\d+) .*?\].*Receiving credits: fcc0 = 0x([0-9a-f]+), fcc1 = 0x([0-9a-f]+)")
    def finish(event):
        nonlocal bulk_count
        if event is None:
            return
        if event["pc"] != bulk_pc:
            events.setdefault((event["hart"], event["pc"]), []).append(event)
            return
        bulk_count += 1
        packed = bulk_count << (counter * 16)
        if (event["hart"] != receiver or event["word"] != bulk_word or event["registers"] != {"x7::": credit_base + counter * 8, "x6::": send_mask} or
                event["memory"] != [[64, credit_base + counter * 8, "=", send_mask]] or
                event["credits"] != [[receiver, packed & 65535, packed >> 16]]):
            raise RuntimeError(f"bulk device credit {bulk_count} lacks matching instruction/ESR/receiver evidence")
        if bulk_count in (1, 65535):
            bulk_samples.append(event)
    for line in trace.splitlines():
        match = instruction.match(line)
        if match:
            finish(current)
            cycle, hart, pc, word, decoded = match.groups()
            pc = int(pc, 16)
            harts.add(hart)
            current = dict(cycle=int(cycle), hart=hart, pc=pc, word=int(word, 16), disassembly=decoded,
                           registers={}, memory=[], credits=[], raw=[]) if pc in wanted or pc == bulk_pc else None
        if current is None:
            continue
        current["raw"].append(line)
        match = reg.search(line)
        if match:
            current["registers"][f"x{match.group(1)}:{match.group(2)}"] = int(match.group(3), 16)
        match = mem.search(line)
        if match:
            bits, address, direction, value = match.groups()
            current["memory"].append([int(bits), int(address, 16), direction, int(value, 16)])
        match = credit.search(line)
        if match:
            current["credits"].append([match.group(1), int(match.group(2), 16), int(match.group(3), 16)])
    finish(current)
    if bulk_count != 65535 or harts != {receiver, sender}:
        raise RuntimeError("wrong actual bulk increment count or execution harts")
    return events, bulk_count, bulk_samples


def validate(case, out, syms, instructions, start, size):
    trace = (out / "trace.log").read_text()
    if "Finishing emulation" not in trace or "Error, max cycles reached" in trace or re.search(r"\b(?:Trapping|exception)\b", trace, re.I):
        raise RuntimeError("peer synchronization did not complete normally")
    counter, barrier, send_mask = parameters(case)
    receiver, sender, credit_base = routing(case)
    events, bulk_count, samples = observe(trace, set(syms.values()), syms["op_bulk"], counter, send_mask,
                                           int(next(r["word"] for r in instructions if r["name"] == "bulk"), 16), receiver, sender, credit_base)
    for inst in instructions:
        if inst["name"] == "bulk":
            continue  # every occurrence is checked while streaming the trace
        observed = events.get((inst["hart"], int(inst["pc"], 16)), [])
        if len(observed) != inst["expected_executions"] or any(e["word"] != int(inst["word"], 16) for e in observed):
            raise RuntimeError("peer operation's actual execution count/word differs from ELF")
    def one(name, hart=receiver):
        rows = events.get((hart, syms[name]), [])
        if len(rows) != 1:
            raise RuntimeError(f"expected one {hart} peer event at {name}, found {len(rows)}")
        return rows[0]
    pre, memory = (out / "prestart.bin").read_bytes(), (out / "output.bin").read_bytes()
    if len(pre) != size or len(memory) != size:
        raise RuntimeError("incomplete peer memory dumps")
    off = lambda name: syms[name] - start
    if struct.unpack_from("<4Q", pre, off("input_controls")) != (counter, barrier, send_mask, 65535):
        raise RuntimeError("wrong deterministic control input")
    expected = bytearray(pre)
    feature_before, feature_after = struct.unpack_from("<2Q", memory, off("feature_state"))
    if (one("feature_before")["registers"]["x5:="] != feature_before or one("feature_after")["registers"]["x5:="] != feature_after or
            feature_after != feature_before & ~2):
        raise RuntimeError("wrong actual ML feature state")
    expected[off("feature_state"):off("feature_state") + 16] = struct.pack("<2Q", feature_before, feature_after)
    for name, hart in (("park", receiver), ("sender_park", sender)):
        if one(name, hart)["disassembly"] != "wfi":
            raise RuntimeError("both minions did not park")
    wait = events.get((receiver, syms["op_wait"]), [])
    other_send, correct_send = one("op_sender_other", sender), one("op_sender_credit", sender)
    if (len(wait) != 2 or "x20:=" in wait[0]["registers"] or wait[1]["registers"].get("x20:=") != 0 or
            not wait[0]["cycle"] < other_send["cycle"] < correct_send["cycle"] < wait[1]["cycle"] or
            one("seed_wait")["registers"]["x20::"] != SEED):
        raise RuntimeError("zero-credit FCC did not restart unchanged and consume after the matching credit")
    waiting = [(int(cycle), hart, action, int(c)) for cycle, hart, action, c in re.findall(
        r"^(\d+): DEBUG EMU: \[(H\d+) .*?\]\s+(Start|Stop) waiting for FCC([01])$", trace, re.MULTILINE)]
    if waiting != [(wait[0]["cycle"], receiver, "Start", counter), (correct_send["cycle"], receiver, "Stop", counter)]:
        raise RuntimeError("wrong-counter credit woke FCC or actual wait/wake evidence is missing")
    other_value, max_value, one_value = 1 << (16 * (counter ^ 1)), 65535 << (16 * counter), 1 << (16 * counter)
    references = {"wait": (0, other_value, 0, 0), "consume_other": (other_value, 0, 0, 0),
                  "flb_receiver": (0, 1, 0, 0), "flb_sender": (1, 0, 1, 0), "bulk": (0, max_value, SEED, 0),
                  "wrap": (max_value, 0, SEED, 8), "refill": (0, one_value, SEED, 0), "consume_refill": (one_value, 0, 0, 0)}
    if case.startswith("threads"):
        references.update(wrong_thread=(0, one_value, SEED, 0), consume_thread=(one_value, 0, 0, 0))
    rows = []
    for name in stages(case):
        hart = sender if name in ("flb_sender", "wrong_thread", "consume_thread") else receiver
        before, after = one("before_" + name, hart), one("after_" + name, hart)
        actual = [before["registers"]["x21:="], after["registers"]["x22:="], one("capture_s4_" + name, hart)["registers"]["x20::"]]
        for field, rd in (("error", 23), ("status", 24), ("enabled", 25), ("pending", 26), ("hart", 27)):
            event = one("read_" + field + "_" + name, hart)
            actual.append(event["registers"][f"x{rd}:="])
        record = off("record_" + name)
        if pre[record:record + 128] != bytes([0xA5]) * 128 or struct.unpack_from("<8Q", memory, record) != tuple(actual):
            raise RuntimeError("peer records are not the actual seeded device snapshots")
        # Reset mstatus is captured as evidence; only relevant interrupt bits are
        # asserted. It is not synthesized from a host reset constant.
        status = actual[4]
        reference = [*references[name], status, 0, 0, int(hart[1:])]
        if status & 8:
            raise RuntimeError("global interrupts unexpectedly enabled")
        expected[record:record + 64] = struct.pack("<8Q", *reference)
        rows.append(dict(name=name, hart=hart, actual=[f"0x{x:x}" for x in actual], expected=[f"0x{x:x}" for x in reference],
                         **{"pass": actual == reference}, before_pc=hex(before["pc"]), after_pc=hex(after["pc"])))
        if name.startswith("flb"):
            address = FLB + barrier * 8
            if before["memory"] != [[64, address, ":", actual[0]]] or after["memory"] != [[64, address, ":", actual[1]]]:
                raise RuntimeError("peer FLB state did not come from real ESR loads")
            op = one("op_" + name, hart)
            body = "\n".join(op["raw"])
            if (op["registers"]["x20:="] != actual[2] or
                    f"fast_local_barrier{barrier} : {actual[0]} (limit : 1)" not in body or
                    f"fast_local_barrier{barrier} = {actual[1]}" not in body):
                raise RuntimeError("peer FLB helper logs/return disagree with actual ESR state")
        elif name not in ("bulk", "wrap", "refill", "wrong_thread"):
            event = wait[-1] if name == "wait" else one("op_" + name, hart)
            if event["registers"]["x20:="] != actual[2]:
                raise RuntimeError("FCC destination write/snapshot disagree")
    if one("op_flb_receiver")["cycle"] >= one("op_flb_sender", sender)["cycle"]:
        raise RuntimeError("FLB arrivals did not follow the real peer handshake")
    for name, selected, packed in (("sender_other", counter ^ 1, other_value), ("sender_credit", counter, other_value | one_value),
                                    ("wrap", counter, 0), ("refill", counter, one_value)):
        event = one("op_" + name, sender if name.startswith("sender") else receiver)
        if (event["registers"] != {"x7::": credit_base + selected * 8, "x6::": send_mask} or
                event["memory"] != [[64, credit_base + selected * 8, "=", send_mask]] or
                event["credits"] != [[receiver, packed & 65535, packed >> 16]]):
            raise RuntimeError("actual peer/boundary credit ESR store and receiver counters disagree")
    if one("input_count")["registers"]["x28:="] != bulk_count:
        raise RuntimeError("bulk iteration count was not loaded from the real input")
    for name, hart in (("input_mask_receiver", receiver), ("input_mask_sender", sender)):
        if one(name, hart)["registers"]["x6:="] != send_mask:
            raise RuntimeError("credit mask did not come from the real device input")
    final_barrier, guard = struct.unpack_from("<2Q", memory, off("final_state"))
    if (final_barrier, guard) != (0, 0x5A) or one("barrier_final")["registers"]["x9:="] != final_barrier or one("guard_final")["registers"]["x18:="] != guard:
        raise RuntimeError("peer final barrier/guard snapshots disagree")
    expected[off("final_state"):off("final_state") + 16] = struct.pack("<2Q", 0, 0x5A)
    if struct.unpack_from("<2Q", memory, off("handshake")) != (2, 1):
        raise RuntimeError("peer handshake did not finish")
    expected[off("handshake"):off("handshake") + 16] = struct.pack("<2Q", 2, 1)
    completion, marker, cause = struct.unpack_from("<IIQ", memory, off("completion"))
    expected[off("completion"):off("completion") + 4] = struct.pack("<I", DONE)
    wrong_thread_event = one("op_wrong_thread", sender) if case.startswith("threads") else None
    if wrong_thread_event:
        if (not wait[0]["cycle"] < wrong_thread_event["cycle"] < other_send["cycle"] or
                wrong_thread_event["registers"] != {"x7::": FCC + counter * 8, "x6::": send_mask} or
                wrong_thread_event["memory"] != [[64, FCC + counter * 8, "=", send_mask]] or
                wrong_thread_event["credits"] != [[sender, one_value & 65535, one_value >> 16]]):
            raise RuntimeError("wrong-thread credit was not really delivered to T0 while T1 remained blocked")
    proof = dict(counter=counter, receiver_hart=wait[0]["hart"], sender_hart=correct_send["hart"], credit_esr=hex(correct_send["registers"]["x7::"]),
        wrong_thread_credit_cycle=wrong_thread_event["cycle"] if wrong_thread_event else None,
        retry_pc=hex(syms["op_wait"]), wait_cycles=[e["cycle"] for e in wait],
        other_credit_cycle=other_send["cycle"], matching_credit_cycle=correct_send["cycle"], wait_events=waiting,
        destination_written_on_first_attempt="x20:=" in wait[0]["registers"], destination_after=hex(wait[-1]["registers"]["x20:="]),
        bulk_increment_count=bulk_count, overflow_error=next(row["actual"][3] for row in rows if row["name"] == "wrap"),
        barrier=barrier, flb_arrival_harts=[one("op_flb_receiver")["hart"], one("op_flb_sender", sender)["hart"]])
    passed = all(row["pass"] for row in rows) and memory == expected and (completion, marker, cause) == (DONE, 0, 0)
    (out / "expected.bin").write_bytes(expected)
    (out / "registers.json").write_text(json.dumps(dict(source="real SysEmu register/credit/ESR events plus guarded device snapshots",
        stages=rows, proof=proof, bulk_samples=samples, events=[e for values in events.values() for e in values]), indent=2) + "\n")
    (out / "result.json").write_text(json.dumps(dict(case=case, operation_count=len(instructions), stage_count=len(stages(case)),
        stages=rows, proof=proof, whole_monitor_matches=memory == expected, completion_word=f"0x{completion:08x}", trap_marker=marker, trap_cause=cause,
        **{"pass": passed}), indent=2) + "\n")
    if not passed:
        raise RuntimeError(f"peer synchronization checks failed; inspect {out}/result.json")
    print(f"Synchronization peers {case}: {sender} -> {receiver} FCC{counter} ESR={proof['credit_esr']} wait/retry cycles {proof['wait_cycles']}; PASS")
    print(f"  FLB{barrier}: {receiver} 0->1 return 0, {sender} 1->0 return 1; {bulk_count}+1 real stores: counter wrap, error=0x8; clear/refill/consume PASS")
    if wrong_thread_event:
        print(f"  T0 credit at cycle {wrong_thread_event['cycle']} and wrong-counter credit at {other_send['cycle']} did not wake T1")
    print(f"  guarded state memory PASS; {out}")


def main():
    selected = sys.argv[1:] or list(CASES)
    for case in selected:
        parameters(case)
    env = runtime()
    for case in selected:
        execute(case, env)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print(f"synchronization_peers.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
