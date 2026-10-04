#!/usr/bin/env python3
"""Execute ET-SOC1 system instructions, real M/S/U transitions and faults."""

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

OUT = ROOT/'out/system'
DONE = 0x4B4F5445
XSEED = 0x5AA55AA55AA55AA5
RECORD_SIZE = 256
PRIV = {'U': 0, 'S': 1, 'M': 3}
LINKER = '''/* SPDX-License-Identifier: Apache-2.0 */
OUTPUT_ARCH("riscv")
ENTRY(_start)
SECTIONS {
  .text 0x8000001000 : { KEEP(*(.text.entry)) }
  .text.os 0x8004001000 : { *(.text.os) }
  .data 0x8004100000 : { *(.data .data.*) }
  .stack 0x8000200000 (NOLOAD) : { __stack_bottom = .; . += 0x4000; __stack_top = .; }
}
'''


def operations():
    rows = []

    def add(name, mnemonic, mode='M', target=None, cause=0, flag=0, exclusive=0, waiting=False):
        rows.append(dict(name=name, mnemonic=mnemonic, handler=mnemonic.replace('.', '_'), mode=mode,
            after_mode='M' if cause else target or mode, target=target, cause=cause, flag=flag,
            exclusive=exclusive, waiting=waiting, asm=mnemonic+(' a0, a1' if mnemonic == 'sfence.vma' else '')))

    for mode in ('M', 'S', 'U'):
        add('ecall_'+mode, 'ecall', mode, cause={'M': 11, 'S': 9, 'U': 8}[mode])
        add('ebreak_'+mode, 'ebreak', mode, cause=3)
    for target in ('M', 'S', 'U'):
        add('mret_to_'+target, 'mret', target=target)
    for mode in ('S', 'U'):
        add('mret_denied_'+mode, 'mret', mode, cause=2)
    for mode in ('M', 'S'):
        for target in ('S', 'U'):
            add('sret_'+mode+'_to_'+target, 'sret', mode, target)
    add('sret_TSR', 'sret', 'S', cause=2, flag=1<<22)
    add('sret_denied_U', 'sret', 'U', cause=2)
    for mode in ('M', 'S'):
        add('wfi_exclusive_'+mode, 'wfi', mode, exclusive=1)
    add('wfi_denied_U', 'wfi', 'U', cause=2)
    add('wfi_TW', 'wfi', 'S', cause=2, flag=1<<21)
    add('fence_i_stub', 'fence.i', cause=30)
    add('sfence_vma_stub', 'sfence.vma', cause=30)
    add('wfi_wait', 'wfi', waiting=True)
    assert len(rows) == 24 and sum(bool(op['cause']) for op in rows) == 14
    return rows


def label(name):
    return [f'.globl {name}', f'{name}:']


def kernel(ops, case):
    a, b = ((0xFEDCBA9889ABCDEF, 0x0123456789ABCDEF) if case == 'primary'
            else (0x0123456776543210, 0xFEDCBA9876543210))
    mpie, spie = (0, 1) if case == 'primary' else (1, 0)
    lines = ['# SPDX-License-Identifier: Apache-2.0',
        '# Startup provenance: Copyright (c) 2025 Ainekko, Co.; ET Platform boot.S.',
        '.option push', '.option norelax', '.option norvc', '.section .text.entry,"ax",@progbits', *label('_start'),
        '    csrwi satp, 0', '    csrwi mie, 0', '    csrwi mip, 0', '    csrwi medeleg, 0', '    csrwi mideleg, 0',
        '    csrwi tensor_mask, 0', '    la sp, __stack_top', '    la t0, trap_handler', '    csrw mtvec, t0',
        '    li s1, 0', '    li s10, 0']
    for op in ops:
        name, mode = op['name'], op['mode']
        mpp = PRIV[op['target']] if op['mnemonic'] == 'mret' and not op['cause'] else PRIV[mode]
        spp = int(op['target'] == 'S') if op['mnemonic'] == 'sret' and not op['cause'] else 0
        flags = (mpp<<11) | (mpie<<7) | ((1-mpie)<<3) | (spp<<8) | (spie<<5) | ((1-spie)<<1) | op['flag']
        lines += ['.section .text.entry,"ax",@progbits', f'    la s0, record_{name}', f'    la t0, input_{name}',
            *label('load_a_'+name), '    ld a0, 0(t0)', *label('load_b_'+name), '    ld a1, 8(t0)',
            f'    li s4, 0x{XSEED:x}', f'    li s3, {op["cause"]}', '    li s7, 0',
            f'    la s2, after_{name}', f'    la s6, done_{name}',
            # Write relevant control bits explicitly; retain read-only XLEN state.
            '    csrr t0, mstatus', '    li t1, 0xf00018000', '    and t0, t0, t1', f'    li t1, 0x{flags:x}',
            '    or t0, t0, t1', *label('configure_status_'+name), '    csrw mstatus, t0',
            *label('configured_status_read_'+name), '    csrr t0, mstatus', '    sd t0, 128(s0)',
            f'    csrwi excl_mode, {op["exclusive"]}', *label('configured_excl_read_'+name), '    csrr t0, excl_mode', '    sd t0, 136(s0)',
            f'    la t0, after_{name}', '    csrw sepc, t0', '    csrw mepc, t0']
        if mode == 'M':
            lines += [f'    la t0, begin_{name}', '    jr t0']
        else:
            lines += [f'    la t0, begin_{name}', '    csrw mepc, t0', *label('enter_'+name), '    mret']
        lines += [*label('done_'+name)]
        if op['waiting']:
            # The terminal WFI does not return; any accidental return is a failure.
            lines += ['    la t0, unexpected', '    jr t0']
        lines += ['.section .text.os,"ax",@progbits', *label('begin_'+name)]
        for j, (suffix, reg) in enumerate([('a', 'a0'), ('b', 'a1'), ('x', 's4')]):
            lines += [*label('before_'+suffix+'_'+name), f'    sd {reg}, {8*j}(s0)']
        if mode == 'M':
            lines += [*label('before_status_read_'+name), '    csrr t0, mstatus', *label('before_status_'+name), '    sd t0, 48(s0)']
        if op['waiting']:
            lines += ['    la t0, trap_count', '    sd s1, 0(t0)', '    la t0, escape_count', '    sd s10, 0(t0)',
                f'    li t0, 0x{DONE:x}', '    la t1, completion', *label('complete'), '    sw t0, 0(t1)']
        lines += [*label('op_'+name), '    '+op['asm']]
        if not op['cause'] and op['mnemonic'] in ('mret', 'sret'):
            lines += [*label('fallthrough_'+name), '    li s4, 0', '    la t0, unexpected', '    jr t0']
        if op['waiting']:
            lines += [*label('after_'+name), *label('unexpected_after_wait'), '    la t0, unexpected', '    jr t0']
            continue
        lines += [*label('after_'+name)]
        for j, (suffix, reg) in enumerate([('a', 'a0'), ('b', 'a1'), ('x', 's4')]):
            lines += [*label('after_'+suffix+'_'+name), f'    sd {reg}, {24+8*j}(s0)']
        if op['after_mode'] == 'M':
            lines += [*label('after_status_read_'+name), '    csrr t0, mstatus', *label('after_status_'+name), '    sd t0, 56(s0)',
                f'    la t0, done_{name}', '    jr t0']
        else:
            lines += ['    li s7, 1', f'    li s3, {9 if op["after_mode"] == "S" else 8}', *label('escape_'+name), '    ecall',
                '    la t0, unexpected', '    jr t0']
    lines += ['.section .text.entry,"ax",@progbits', '.balign 4096', *label('trap_handler'),
        '    csrr t0, mcause', '    bne t0, s3, unexpected', '    bnez s7, escape_handler']
    for csr, offset in [('mcause', 64), ('mepc', 72), ('mtval', 80), ('mstatus', 88)]:
        lines += [*label('capture_'+csr), f'    csrr t0, {csr}', f'    sd t0, {offset}(s0)']
    lines += ['    addi s1, s1, 1', '    csrw mepc, s2', '    j return_M', *label('escape_handler')]
    for csr, offset in [('mcause', 160), ('mepc', 168), ('mtval', 176), ('mstatus', 184)]:
        lines += [*label('escape_capture_'+csr), f'    csrr t0, {csr}', f'    sd t0, {offset}(s0)']
    lines += ['    addi s10, s10, 1', '    csrw mepc, s6', *label('return_M'), '    csrr t0, mstatus',
        '    li t1, 0x1800', '    or t0, t0, t1', '    csrw mstatus, t0', *label('trap_return'), '    mret',
        *label('unexpected'), '    la t1, unexpected_trap', '    csrr t0, mcause', '    sd t0, 0(t1)',
        '    csrr t0, mepc', '    sd t0, 8(t1)', '    csrr t0, mtval', '    sd t0, 16(t1)',
        *label('park'), '    wfi', '    j park', '.option pop', '.section .data,"aw",@progbits', '.balign 32', *label('__monitor_start')]
    for op in ops:
        lines += [*label('record_'+op['name']), f'    .fill {RECORD_SIZE},1,0xa5']
    lines += [*label('trap_count'), '    .dword 0', *label('escape_count'), '    .dword 0', *label('completion'), '    .word 0', '.balign 8',
        *label('unexpected_trap'), '    .dword 0,0,0']
    for op in ops:
        lines += ['.balign 8', *label('input_'+op['name']), f'    .dword 0x{a:x},0x{b:x}']
    return '\n'.join([*lines, *label('__monitor_end')])+'\n'


def execute(case, env):
    ops = operations()
    out = OUT if case == 'primary' else OUT/case
    out.mkdir(parents=True, exist_ok=True)
    log = out/'commands.log'
    log.write_text('')
    for name in ('result.json','registers.json','trace.log','output.bin','prestart.bin','expected.bin'):
        (out/name).unlink(missing_ok=True)
    (out/'kernel.S').write_text(kernel(ops,case))
    (out/'link.ld').write_text(LINKER)
    container = env['kind'] == 'podman'
    podman = shutil.which('podman') or 'podman'
    stage = f'/tmp/etsoc1-system-{uuid.uuid4().hex[:10]}'
    work = stage if container else str(out)

    def checked(argv):
        result = run_logged(log, argv)
        if result.returncode:
            raise RuntimeError(f'command failed ({result.returncode}); inspect {log}')
        return result

    try:
        if container:
            checked([podman,'exec',env['container'],'mkdir','-p',stage])
            for name in ('kernel.S','link.ld'):
                checked([podman,'cp',str(out/name),f'{env["container"]}:{stage}/{name}'])
        tp, wd = shlex.quote(env['tool_prefix']), shlex.quote(work)
        checked(command(env, ['bash','-lc', f'set -euo pipefail; cd {wd}; '
            f'{tp}as --march=rv64imfc_zicsr_zifencei -mabi=lp64f -o kernel.o kernel.S; '
            f'{tp}ld --no-relax --build-id=none -T link.ld -o kernel.elf kernel.o; '
            f'{tp}objdump -d -z -M numeric,no-aliases kernel.elf > kernel.asm; '
            f'{tp}readelf -h -l -S kernel.elf > elf-inspection.txt; '
            f'{tp}nm -n --defined-only kernel.elf > symbols.txt; '
            f'{tp}objcopy -O binary --only-section=.text kernel.elf text.bin; '
            f'{tp}objcopy -O binary --only-section=.text.os kernel.elf text.os.bin']))
        if container:
            checked([podman,'cp',f'{env["container"]}:{stage}/.',str(out)])
        syms = symbols((out/'symbols.txt').read_text())
        elf, asm = (out/'kernel.elf').read_bytes(), (out/'kernel.asm').read_text()
        if elf[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H',elf,18)[0] != 243:
            raise RuntimeError('expected RV64 little-endian ELF')
        entry, phoff, shoff = struct.unpack_from('<3Q',elf,24)
        phsize, phcount, shsize, shcount, strings = struct.unpack_from('<5H',elf,54)
        segments = [struct.unpack_from('<II6Q',elf,phoff+i*phsize) for i in range(phcount)]
        sections = [struct.unpack_from('<II4QII2Q',elf,shoff+i*shsize) for i in range(shcount)]
        names = elf[sections[strings][4]:sections[strings][4]+sections[strings][5]]
        sections = {names[s[0]:].split(b'\0',1)[0].decode():s for s in sections}
        if [name for name,s in sections.items() if s[2]&4 and s[5]] != ['.text', '.text.os']:
            raise RuntimeError('unexpected executable sections')
        text = sections['.text']
        if any((out/dump).read_bytes()!=elf[sections[name][4]:sections[name][4]+sections[name][5]] for name,dump in [('.text','text.bin'),('.text.os','text.os.bin')]):
            raise RuntimeError('text section extraction differs from ELF')
        sites = []
        for op in ops:
            pc = syms[f'op_{op["name"]}']
            offsets = [p[2]+pc-p[3] for p in segments if p[0]==1 and p[1]&1 and p[3]<=pc and pc+4<=p[3]+p[5]]
            if len(offsets) != 1:
                raise RuntimeError('operation lacks unique executable PT_LOAD mapping')
            raw = elf[offsets[0]:offsets[0]+4]
            decoded = [line.strip() for line in asm.splitlines() if re.search(rf'\b{pc:x}:\s',line)]
            if len(decoded)!=1 or op['mnemonic'] not in decoded[0] or len(raw)!=4:
                raise RuntimeError(f'ET disassembler mismatch: {op["name"]}: {decoded}')
            sites.append({k:op[k] for k in ('name','handler','mnemonic','mode','after_mode','target','cause','flag','exclusive','waiting')} | dict(pc=hex(pc),
                word=f'0x{int.from_bytes(raw,"little"):08x}', bytes_memory_order=raw.hex(' '),
                file_offset=hex(offsets[0]), decoded=decoded[0]))
        start, size = syms['__monitor_start'], syms['__monitor_end']-syms['__monitor_start']
        (out/'operations.json').write_text(json.dumps(sites,indent=2)+'\n')
        (out/'operations.bin').write_bytes(b''.join(bytes.fromhex(s['bytes_memory_order']) for s in sites))
        (out/'op.bin').write_bytes(bytes.fromhex(sites[0]['bytes_memory_order']))
        (out/'elf-layout.json').write_text(json.dumps(dict(entry=hex(entry),selected_hart='H0 S0:N0:C0:T0',
            text_vma=hex(text[3]),text_file_offset=hex(text[4]),text_size=text[5],executable_sections=['.text','.text.os'],section_dumps={'.text':'text.bin','.text.os':'text.os.bin'},
            monitor_address=hex(start),monitor_size=size,operation_count=len(sites),operations=sites),indent=2)+'\n')
        sim = [env['simulator'],'-l','-lm','0','-lt','0','-sp_dis','-reset_pc',hex(entry),
            '-single_thread','-minions','0x1','-shires','0x1','-max_cycles','20000','-elf_load',f'{work}/kernel.elf',
            '-dump_at_pc_pc',hex(entry),'-dump_at_pc_addr',hex(start),'-dump_at_pc_size',hex(size),
            '-dump_at_pc_file',f'{work}/prestart.bin','-dump_addr',hex(start),'-dump_size',str(size),
            '-dump_file',f'{work}/output.bin']
        run = run_logged(log,command(env,['timeout','--signal=TERM','--kill-after=5s','90s',*sim]))
        (out/'trace.log').write_text(run.stdout or '')
        if container:
            checked([podman,'cp',f'{env["container"]}:{stage}/.',str(out)])
        if run.returncode or 'Finishing emulation' not in (run.stdout or '') or 'Error, max cycles reached' in (run.stdout or ''):
            raise RuntimeError(f'SysEmu did not complete normally; inspect {out}')
        validate(out,ops,sites,syms,start,size,case)
    finally:
        if container:
            # Retrieve the assembly, ELF and partial dump even after failures.
            pulled = run_logged(log,[podman,'cp',f'{env["container"]}:{stage}/.',str(out)])
            if pulled.returncode == 0:
                checked([podman,'exec',env['container'],'rm','-rf',stage])


def execution_events(trace):
    """Reconstruct state from actual read/write events; retain raw groups."""
    events, current, state = [], None, {}
    for line in trace.splitlines():
        match = re.match(r'^(\d+): DEBUG EMU: \[(H\d+ S\d+:N\d+:C\d+:T\d+)\] I\(([MSU])\): '
                         r'0x([0-9a-f]+) \(0x([0-9a-f]{8})\) (.*)$', line)
        if match:
            current = dict(cycle=int(match[1]), hart=match[2], mode=match[3], pc=int(match[4], 16), word=int(match[5], 16),
                           decoded=match[6], before_state=state.copy(), regs={}, csrs=[], memory=[], raw=[])
            events.append(current)
        if current is None:
            continue
        current['raw'].append(line)
        match = re.search(r'\b(x\d+) ([=:]) 0x([0-9a-f]+)', line)
        if match:
            current['regs'][match[1]+match[2]] = int(match[3], 16)
            if match[2] == '=':
                state[match[1]] = int(match[3], 16)
        match = re.search(r'\t(mstatus|mepc|sepc|mcause|mtval|excl_mode) ([=:]) 0x([0-9a-f]+)', line)
        if match:
            value = int(match[3], 16)
            current['csrs'].append((match[1], match[2], value))
            state[match[1]] = value
        match = re.search(r'MEM(8|16|32|64)\[0x([0-9a-f]+)\] ([=:]) 0x([0-9a-f]+)', line)
        if match:
            current['memory'].append((int(match[1]), int(match[2], 16), match[3], int(match[4], 16)))
    return events


def validate(out, ops, sites, syms, start, size, case):
    trace = (out/'trace.log').read_text()
    events = execution_events(trace)
    if any(e['hart'] != 'H0 S0:N0:C0:T0' for e in events):
        raise RuntimeError('system unexpected executing hart')
    by_pc = {}
    for index, e in enumerate(events):
        by_pc.setdefault(e['pc'], []).append((index, e))

    def event(name):
        found = by_pc.get(syms[name], [])
        if len(found) != 1:
            raise RuntimeError('missing/repeated system site '+name)
        return found[0][1]

    pre, memory, elf = ((out/name).read_bytes() for name in ('prestart.bin', 'output.bin', 'kernel.elf'))
    phoff = struct.unpack_from('<Q', elf, 32)[0]
    phsize, phcount = struct.unpack_from('<HH', elf, 54)
    segments = [struct.unpack_from('<II6Q', elf, phoff+i*phsize) for i in range(phcount)]
    offsets = [p[2]+start-p[3] for p in segments if p[0] == 1 and p[3] <= start and start+size <= p[3]+p[5]]
    if len(offsets) != 1 or len(pre) != size or len(memory) != size or pre != elf[offsets[0]:offsets[0]+size]:
        raise RuntimeError('system monitor inputs/guards differ from ELF')
    expected, rows, faults, escapes = bytearray(pre), [], 0, 0
    capture_counts = {'capture': 14, 'escape_capture': 7}
    captures = {(prefix, csr): [e for e in events if e['pc'] == syms[prefix+'_'+csr]]
                for prefix in capture_counts for csr in ('mcause', 'mepc', 'mtval', 'mstatus')}
    traps = re.findall(r'\[(H\d+ S\d+:N\d+:C\d+:T\d+)\].*Trapping to M-mode with cause 0x([0-9a-f]+) and tval 0x([0-9a-f]+)', trace)

    def capture_fault(prefix, index, record, base, cause, pc, tval, status):
        values = struct.unpack_from('<4Q', memory, record+base)
        if values != (cause, pc, tval, status):
            raise RuntimeError('system trap CSR snapshot differs: '+prefix)
        for j, (csr, value) in enumerate(zip(('mcause', 'mepc', 'mtval', 'mstatus'), values)):
            found = captures[prefix, csr]
            if len(found) <= index or found[index]['regs'].get('x5=') != value or found[index]['csrs'] != [(csr, ':', value)]:
                raise RuntimeError('system trap snapshot lacks real CSR read')
            following = events[by_pc[found[index]['pc']][index][0]+1]
            if following['memory'] != [(64, start+record+base+8*j, '=', value)]:
                raise RuntimeError('system trap snapshot lacks real store')
        struct.pack_into('<4Q', expected, record+base, *values)
        return dict(mcause=cause, mepc=hex(pc), mtval=hex(tval), mstatus=hex(status))

    for op, site in zip(ops, sites):
        name, actual = op['name'], event('op_'+op['name'])
        pc, word = actual['pc'], actual['word']
        record = syms['record_'+name]-start
        if word != int(site['word'], 16) or actual['mode'] != op['mode'] or not actual['decoded'].startswith(op['mnemonic']):
            raise RuntimeError('system executed instruction/mode differs')
        if pre[record:record+RECORD_SIZE] != bytes([0xA5])*RECORD_SIZE:
            raise RuntimeError('system initial sentinel missing')
        a, b = struct.unpack_from('<2Q', pre, syms['input_'+name]-start)
        for j, (suffix, reg, value) in enumerate([('a', 'x10', a), ('b', 'x11', b)]):
            load = event('load_'+suffix+'_'+name)
            if load['regs'].get(reg+'=') != value or load['memory'] != [(64, syms['input_'+name]+8*j, ':', value)]:
                raise RuntimeError('system input lacks actual memory/register load')
        for phase, base in [('before', 0), ('after', 24)]:
            if phase == 'after' and op['waiting']:
                continue
            for j, (suffix, reg, value) in enumerate([('a', 'x10', a), ('b', 'x11', b), ('x', 'x20', XSEED)]):
                snapshot = event(phase+'_'+suffix+'_'+name)
                mode = op['mode'] if phase == 'before' else op['after_mode']
                if snapshot['mode'] != mode or snapshot['regs'].get(reg+':') != value or \
                        snapshot['memory'] != [(64, start+record+base+8*j, '=', value)]:
                    raise RuntimeError('system actual GPR snapshot or privilege differs')
            struct.pack_into('<3Q', expected, record+base, a, b, XSEED)
        status = actual['before_state'].get('mstatus')
        if status is None or any(actual['before_state'].get(k) != v for k, v in [('x10', a), ('x11', b), ('x20', XSEED), ('excl_mode', op['exclusive'])]):
            raise RuntimeError('system prior state lacks actual trace reconstruction')
        for suffix, base, csr in [('configured_status', 128, 'mstatus'), ('configured_excl', 136, 'excl_mode')]:
            read = event(suffix+'_read_'+name)
            value = read['regs'].get('x5=')
            if read['csrs'] != [(csr, ':', value)] or events[by_pc[read['pc']][0][0]+1]['memory'] != [(64, start+record+base, '=', value)]:
                raise RuntimeError('system configured state lacks CSR/store evidence')
            struct.pack_into('<Q', expected, record+base, value)
        configured = event('configured_status_read_'+name)['regs']['x5=']
        mpie, spie = (0, 1) if case == 'primary' else (1, 0)
        if (configured>>7&1, configured>>5&1, configured>>3&1, configured>>1&1) != (mpie, spie, 1-mpie, 1-spie) or \
                configured & ((1<<21)|(1<<22)) != op['flag']:
            raise RuntimeError('system deterministic control initialization differs')
        if actual['memory'] or any(key.endswith('=') for key in actual['regs']):
            raise RuntimeError('system instruction unexpectedly wrote GPR/memory')
        fault, escape, after_status, next_pc = None, None, status, None
        index = by_pc[pc][0][0]
        if op['cause']:
            after_status = (status & 0xFFFFFFFFFFFFE777) | (PRIV[op['mode']]<<11) | ((status>>3&1)<<7)
            tval = pc if op['mnemonic'] == 'ebreak' else 0 if op['mnemonic'] == 'ecall' else word
            fault = capture_fault('capture', faults, record, 64, op['cause'], pc, tval, after_status)
            if len(traps) <= faults+escapes or traps[faults+escapes] != ('H0 S0:N0:C0:T0', f'{op["cause"]:x}', f'{tval:x}'):
                raise RuntimeError('system raw trap differs from capture')
            faults += 1
            next_pc = syms['trap_handler']
        elif op['mnemonic'] in ('mret', 'sret'):
            if op['mnemonic'] == 'mret':
                after_status = (status & 0xFFFFFFFFFFFFE777) | ((status>>7&1)<<3) | 0x80
                target = actual['before_state'].get('mepc')
                mode = 'USHM'[status>>11&3]
            else:
                after_status = (status & 0xFFFFFFFFFFFFFEDD) | ((status>>5&1)<<1) | 0x20
                target = actual['before_state'].get('sepc')
                mode = 'US'[status>>8&1]
            if actual['csrs'] != [('mstatus', '=', after_status)] or f'\tprv = {mode}' not in '\n'.join(actual['raw']) or mode != op['target'] or target != syms['after_'+name]:
                raise RuntimeError('system return status/target/privilege differs')
            if by_pc.get(syms['fallthrough_'+name]):
                raise RuntimeError('system return incorrectly fell through')
            next_pc = target
        elif op['waiting']:
            if index != len(events)-1 or 'Start waiting for interrupt' not in '\n'.join(actual['raw']) or actual['csrs']:
                raise RuntimeError('terminal WFI lacks real interrupt-wait evidence')
        else:
            if actual['csrs'] or 'Start waiting' in '\n'.join(actual['raw']):
                raise RuntimeError('exclusive WFI unexpectedly waited or wrote state')
            next_pc = pc+4
        if next_pc is not None and (index+1 >= len(events) or events[index+1]['pc'] != next_pc or events[index+1]['mode'] != ('M' if fault else op['after_mode'])):
            raise RuntimeError('system actual next PC/privilege differs')
        if op['after_mode'] in ('S', 'U') and not op['waiting']:
            exiting = event('escape_'+name)
            if exiting['mode'] != op['after_mode'] or exiting['word'] != 0x73 or exiting['before_state']['mstatus'] != after_status:
                raise RuntimeError('system lower-mode escape state differs')
            escape_status = (after_status & 0xFFFFFFFFFFFFE777) | (PRIV[op['after_mode']]<<11) | ((after_status>>3&1)<<7)
            cause = 9 if op['after_mode'] == 'S' else 8
            escape = capture_fault('escape_capture', escapes, record, 160, cause, exiting['pc'], 0, escape_status)
            if len(traps) <= faults+escapes or traps[faults+escapes] != ('H0 S0:N0:C0:T0', f'{cause:x}', '0'):
                raise RuntimeError('system escape raw trap differs')
            escapes += 1
        for phase, base, mode in [('before', 48, op['mode']), ('after', 56, op['after_mode'])]:
            if mode != 'M' or phase == 'after' and op['waiting']:
                continue
            read, store = event(phase+'_status_read_'+name), event(phase+'_status_'+name)
            value = read['regs'].get('x5=')
            if read['csrs'] != [('mstatus', ':', value)] or store['memory'] != [(64, start+record+base, '=', value)] or phase == 'before' and value != status:
                raise RuntimeError('system machine-mode status snapshot differs')
            struct.pack_into('<Q', expected, record+base, value)
        rows.append(dict(**site, hart=actual['hart'], cycle=actual['cycle'], registers_before={k: hex(actual['before_state'][k]) for k in ('x10', 'x11', 'x20')},
            registers_after=None if op['waiting'] else {k: hex(event('after_'+s+'_'+name)['regs'][k+':']) for s, k in [('a', 'x10'), ('b', 'x11'), ('x', 'x20')]},
            mstatus_before=hex(status), mstatus_after_operation=hex(after_status), next_pc=hex(next_pc) if next_pc is not None else None,
            fault=fault, escape=escape, waiting_observed=op['waiting'], output_memory_bytes=memory[record:record+RECORD_SIZE].hex(' '), **{'pass': True}))
    if (faults, escapes, len(traps)) != (14, 7, 21) or any(len(es) != capture_counts[prefix] for (prefix, csr), es in captures.items()):
        raise RuntimeError('system unexpected/missing fault or escape traps')
    struct.pack_into('<Q', expected, syms['trap_count']-start, 14)
    struct.pack_into('<Q', expected, syms['escape_count']-start, 7)
    struct.pack_into('<I', expected, syms['completion']-start, DONE)
    if memory != expected or by_pc.get(syms['unexpected']) or by_pc.get(syms['unexpected_after_wait']):
        raise RuntimeError('system whole guarded memory/completion mismatch')
    (out/'expected.bin').write_bytes(expected)
    (out/'registers.json').write_text(json.dumps(dict(source='actual H0 M/S/U register/CSR events, reconstructed prior state, device snapshots and raw wait evidence; terminal WFI has no after snapshot', operations=rows), indent=2)+'\n')
    (out/'result.json').write_text(json.dumps(dict(case=case, operation_count=24, handler_count=7, trap_count=14,
        escape_count=7, terminal_wait_observed=True, completion_word=hex(DONE), whole_monitor_matches=True, operations=rows, **{'pass': True}), indent=2)+'\n')
    for row in rows:
        print(f'  {row["name"]:<20} {row["word"]} {row["mode"]}->{row["after_mode"]} next={row["next_pc"]} '
              + (f'cause={row["fault"]["mcause"]} ' if row['fault'] else 'interrupt wait ' if row['waiting_observed'] else '')+'PASS')
    print(f'System {case}: 24 sites, seven handlers, 14 expected faults, seven real lower-mode escapes and terminal interrupt wait PASS; {out}')


def main():
    cases = sys.argv[1:] or ['primary', 'exact']
    if any(case not in ('primary', 'exact') for case in cases):
        raise SystemExit('usage: python3 examples/system.py [primary|exact ...]')
    env = runtime()
    for case in cases:
        execute(case, env)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.SubprocessError, struct.error) as exc:
        print(f'system.py: {exc}', file=sys.stderr)
        raise SystemExit(1)
