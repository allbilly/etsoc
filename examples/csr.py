#!/usr/bin/env python3
"""Execute all six CSR instruction forms and their read/write suppression rules."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import struct
import subprocess
import sys
import uuid

from gemm import LINKER, ROOT, command, runtime, symbols, trace_data
from add import run_logged

OUT = ROOT / 'out/csr'
DONE = 0x4B4F5445
XSEED = 0x5AA55AA55AA55AA5
MASK64 = (1 << 64) - 1
RECORD_SIZE = 192


def operations(case):
    seed, mask = ((0xFEDCBA9889ABCDEF, 0xFFFF000055AA00F0) if case == 'primary'
                  else (0x0123456776543210, 0x01234567FEDCBA98))
    imm = 13 if case == 'primary' else 23
    rows = []

    def add(name, form, *, csr=0x340, rd=20, source=10, a=mask, variant='ordinary'):
        mnemonic = 'csrr' + form
        read = form not in ('w', 'wi') or rd != 0
        write = form in ('w', 'wi') or source != 0
        cause = 2 if csr == 0xF14 and write else 0
        operand = str(source) if form.endswith('i') else f'x{source}'
        rows.append(dict(name=name, mnemonic=mnemonic, handler=mnemonic, form=form, csr=csr,
            rd=rd, source=source, a=a, seed=seed, read=read, write=write, cause=cause, variant=variant,
            asm=f'{mnemonic} x{rd}, 0x{csr:x}, {operand}'))

    for form in ('w', 's', 'c', 'wi', 'si', 'ci'):
        add('ordinary_' + form, form, source=imm if form.endswith('i') else 10)
    add('discard_w', 'w', rd=0, variant='rd=x0 suppresses CSR read')
    add('discard_wi_zero', 'wi', rd=0, source=0, variant='rd=x0 suppresses read; immediate zero still writes')
    for form in ('s', 'c'):
        add('register_value_zero_' + form, form, a=0, variant='nonzero source register holding zero still writes')
    for form in ('s', 'c', 'si', 'ci'):
        add('no_write_' + form, form, source=0, variant='source field zero suppresses write')
    for form in ('w', 's', 'c', 'wi', 'si', 'ci'):
        add('readonly_fault_' + form, form, csr=0xF14, source=(0 if form == 'wi' else 1) if form.endswith('i') else 10,
            a=0 if form in ('s', 'c') else mask, variant='read-only CSR write traps before destination update')
    for form in ('s', 'c', 'si', 'ci'):
        add('readonly_read_' + form, form, csr=0xF14, source=0, variant='read-only CSR read without write succeeds')
    for form in ('w', 'wi'):
        add('write_zero_' + form, form, source=0, variant='source field zero writes zero and returns old CSR')
    assert len(rows) == 26
    return rows


def label(name):
    return [f'.globl {name}', f'{name}:']


def kernel(ops):
    lines = ['# SPDX-License-Identifier: Apache-2.0',
        '# Startup provenance: Copyright (c) 2025 Ainekko, Co.; ET Platform boot.S.',
        '.option push', '.option norelax', '.option norvc', '.section .text.entry,"ax",@progbits', *label('_start'),
        '    csrwi satp, 0', '    csrwi mie, 0', '    csrwi mip, 0', '    csrwi medeleg, 0', '    csrwi mideleg, 0',
        '    csrr t0, mstatus', '    li t1, -9', '    and t0, t0, t1', '    csrw mstatus, t0',
        '    csrwi tensor_mask, 0', '    la sp, __stack_top', '    la t0, trap_handler', '    csrw mtvec, t0', '    li s1, 0']
    for op in ops:
        name = op['name']
        lines += [f'    la s0, record_{name}', f'    la t0, input_{name}', *label('load_a_' + name), '    ld a0, 0(t0)',
            *label('load_seed_' + name), '    ld a1, 8(t0)', *label('seed_csr_' + name), '    csrrw zero, mscratch, a1',
            f'    li s4, 0x{XSEED:x}', f'    li s3, {op["cause"]}']
        for phase, base in [('before', 0), ('after', 48)]:
            if phase == 'after':
                lines += [*label('op_' + name), f'    {op["asm"]}']
            for j, (suffix, reg) in enumerate([('a', 'a0'), ('seed', 'a1'), ('x', 's4')]):
                lines += [*label(phase + '_' + suffix + '_' + name), f'    sd {reg}, {base + 8*j}(s0)']
            for j, (suffix, csr) in enumerate([('mscratch', 0x340), ('target', op['csr'])]):
                lines += [*label(phase + '_' + suffix + '_read_' + name), f'    csrrs t0, 0x{csr:x}, zero',
                    *label(phase + '_' + suffix + '_' + name), f'    sd t0, {base + 24 + 8*j}(s0)']
            lines += [*label(phase + '_zero_' + name), f'    sd zero, {base + 40}(s0)']
    lines += ['    la t0, trap_count', '    sd s1, 0(t0)', f'    li t0, 0x{DONE:x}', '    la t1, completion',
        '    sw t0, 0(t1)', *label('park'), '    wfi', '    j park', '.balign 4096', *label('trap_handler'),
        '    csrr t0, mcause', '    bne t0, s3, unexpected']
    for csr, offset in [('mcause', 96), ('mepc', 104), ('mtval', 112), ('mstatus', 120)]:
        lines += [*label('capture_' + csr), f'    csrr t0, {csr}', f'    sd t0, {offset}(s0)']
    lines += ['    addi s1, s1, 1', '    csrr t0, mepc', '    addi t0, t0, 4', '    csrw mepc, t0', '    mret',
        *label('unexpected'), '    la t1, unexpected_trap', '    csrr t0, mcause', '    sd t0, 0(t1)',
        '    csrr t0, mepc', '    sd t0, 8(t1)', '    csrr t0, mtval', '    sd t0, 16(t1)', '    j park', '.option pop',
        '.section .data,"aw",@progbits', '.balign 32', *label('__monitor_start')]
    for op in ops:
        lines += [*label('record_' + op['name']), f'    .fill {RECORD_SIZE},1,0xa5']
    lines += [*label('trap_count'), '    .dword 0', *label('completion'), '    .word 0', '.balign 8',
        *label('unexpected_trap'), '    .dword 0,0,0']
    for op in ops:
        lines += ['.balign 8', *label('input_' + op['name']), f'    .dword 0x{op["a"]:x},0x{op["seed"]:x}']
    return '\n'.join([*lines, *label('__monitor_end')]) + '\n'


def execute(case, env):
    ops = operations(case)
    out = OUT if case == 'primary' else OUT/case
    out.mkdir(parents=True, exist_ok=True)
    log = out/'commands.log'
    log.write_text('')
    for name in ('result.json','registers.json','trace.log','output.bin','prestart.bin','expected.bin'):
        (out/name).unlink(missing_ok=True)
    (out/'kernel.S').write_text(kernel(ops))
    (out/'link.ld').write_text(LINKER)
    container = env['kind'] == 'podman'
    podman = shutil.which('podman') or 'podman'
    stage = f'/tmp/etsoc1-csr-{uuid.uuid4().hex[:10]}'
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
            f'{tp}as --march=rv64imfc -mabi=lp64f -o kernel.o kernel.S; '
            f'{tp}ld --no-relax --build-id=none -T link.ld -o kernel.elf kernel.o; '
            f'{tp}objdump -d -z -M numeric,no-aliases kernel.elf > kernel.asm; '
            f'{tp}readelf -h -l -S kernel.elf > elf-inspection.txt; '
            f'{tp}nm -n --defined-only kernel.elf > symbols.txt; '
            f'{tp}objcopy -O binary --only-section=.text kernel.elf text.bin']))
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
        if [name for name,s in sections.items() if s[2]&4 and s[5]] != ['.text']:
            raise RuntimeError('unexpected executable sections')
        text = sections['.text']
        if (out/'text.bin').read_bytes() != elf[text[4]:text[4]+text[5]]:
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
            sites.append({k:op[k] for k in ('name','handler','mnemonic','form','csr','rd','source','read','write','cause','variant')} | dict(pc=hex(pc),
                word=f'0x{int.from_bytes(raw,"little"):08x}', bytes_memory_order=raw.hex(' '),
                file_offset=hex(offsets[0]), decoded=decoded[0]))
        start, size = syms['__monitor_start'], syms['__monitor_end']-syms['__monitor_start']
        (out/'operations.json').write_text(json.dumps(sites,indent=2)+'\n')
        (out/'operations.bin').write_bytes(b''.join(bytes.fromhex(s['bytes_memory_order']) for s in sites))
        (out/'op.bin').write_bytes(bytes.fromhex(sites[0]['bytes_memory_order']))
        (out/'elf-layout.json').write_text(json.dumps(dict(entry=hex(entry),selected_hart='H0 S0:N0:C0:T0',
            text_vma=hex(text[3]),text_file_offset=hex(text[4]),text_size=text[5],executable_sections=['.text'],
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


def validate(out, ops, sites, syms, start, size, case):
    trace = (out/'trace.log').read_text()
    events, _ = trace_data(trace)
    cursor = -1
    for e in events:
        e.update(memory=[], csrs=[])
    for line in trace.splitlines():
        match = re.search(r'I\(M\): 0x([0-9a-f]+) \(0x[0-9a-f]+\)', line)
        if match:
            cursor += 1
            if events[cursor]['pc'] != int(match[1], 16):
                raise RuntimeError('CSR trace event association differs')
        elif cursor >= 0:
            match = re.search(r'MEM(8|16|32|64)\[0x([0-9a-f]+)\] ([=:]) 0x([0-9a-f]+)', line)
            if match:
                events[cursor]['memory'].append((int(match[1]), int(match[2], 16), match[3], int(match[4], 16)))
            match = re.search(r'\t(mscratch|mhartid|mcause|mepc|mtval|mstatus) ([=:]) 0x([0-9a-f]+)', line)
            if match:
                events[cursor]['csrs'].append((match[1], match[2], int(match[3], 16)))
    if any(e['hart'] != 'H0 S0:N0:C0:T0' for e in events):
        raise RuntimeError('CSR unexpected executing hart')
    by_pc = {}
    for index, e in enumerate(events):
        by_pc.setdefault(e['pc'], []).append((index, e))

    def event(name):
        found = by_pc.get(syms[name], [])
        if len(found) != 1:
            raise RuntimeError('missing/repeated CSR site ' + name)
        return found[0][1]

    pre, memory = (out/'prestart.bin').read_bytes(), (out/'output.bin').read_bytes()
    elf = (out/'kernel.elf').read_bytes()
    phoff = struct.unpack_from('<Q', elf, 32)[0]
    phsize, phcount = struct.unpack_from('<HH', elf, 54)
    segments = [struct.unpack_from('<II6Q', elf, phoff+i*phsize) for i in range(phcount)]
    maps = [p[2]+start-p[3] for p in segments if p[0] == 1 and p[3] <= start and start+size <= p[3]+p[5]]
    if len(maps) != 1 or len(pre) != size or len(memory) != size or pre != elf[maps[0]:maps[0]+size]:
        raise RuntimeError('CSR monitor input/guard bytes differ from ELF')
    trap_logs = re.findall(r'\[(H\d+ S\d+:N\d+:C\d+:T\d+)\].*Trapping to M-mode with cause 0x([0-9a-f]+) and tval 0x([0-9a-f]+)', trace)
    captures = {csr: [e for e in events if e['pc'] == syms['capture_'+csr]] for csr in ('mcause', 'mepc', 'mtval', 'mstatus')}
    expected, rows, fault_index = bytearray(pre), [], 0
    for op, site in zip(ops, sites):
        name, csrname = op['name'], 'mscratch' if op['csr'] == 0x340 else 'mhartid'
        actual = event('op_' + name)
        pc, word = actual['pc'], actual['word']
        if word != int(site['word'], 16) or not actual['disassembly'].startswith(op['mnemonic']):
            raise RuntimeError('executed CSR differs from ELF/disassembly')
        fields = dict(opcode=word&127, funct3=word>>12&7, rd=word>>7&31, source=word>>15&31, csr=word>>20)
        if fields != dict(opcode=0x73, funct3={'w': 1, 's': 2, 'c': 3, 'wi': 5, 'si': 6, 'ci': 7}[op['form']],
                          rd=op['rd'], source=op['source'], csr=op['csr']):
            raise RuntimeError('CSR encoding fields differ from visible program')
        a, seed = struct.unpack_from('<2Q', pre, syms['input_'+name]-start)
        if (a, seed) != (op['a'], op['seed']):
            raise RuntimeError('CSR deterministic inputs differ')
        for suffix, reg, off, value in [('a', 'x10', 0, a), ('seed', 'x11', 8, seed)]:
            load = event('load_'+suffix+'_'+name)
            if load['registers'].get(reg+':=') != value or load['memory'] != [(64, syms['input_'+name]+off, ':', value)]:
                raise RuntimeError('CSR input lacks real load/write evidence')
        if event('seed_csr_'+name)['csrs'] != [('mscratch', '=', seed)]:
            raise RuntimeError('CSR seed lacks real write evidence')
        before, after = [], []
        record = syms['record_'+name]-start
        for phase, base, values in [('before', 0, before), ('after', 48, after)]:
            for j, (suffix, reg) in enumerate([('a', 'x10'), ('seed', 'x11'), ('x', 'x20'),
                                                ('mscratch', 'x5'), ('target', 'x5'), ('zero', None)]):
                snapshot = event(phase+'_'+suffix+'_'+name)
                value = snapshot['registers'].get(reg+'::') if reg else struct.unpack_from('<Q', memory, record+base+8*j)[0]
                if value is None or snapshot['memory'] != [(64, start+record+base+8*j, '=', value)]:
                    raise RuntimeError('CSR snapshot lacks actual store/register evidence')
                if suffix in ('mscratch', 'target'):
                    read = event(phase+'_'+suffix+'_read_'+name)
                    wanted_name = 'mscratch' if suffix == 'mscratch' else csrname
                    if read['registers'].get('x5:=') != value or read['csrs'] != [(wanted_name, ':', value)]:
                        raise RuntimeError('CSR state snapshot lacks actual CSR read')
                values.append(value)
        old = seed if csrname == 'mscratch' else 0
        if before != [a, seed, XSEED, seed, old, 0]:
            raise RuntimeError('CSR before-state differs')
        operand = op['source'] if op['form'].endswith('i') else a if op['source'] else 0
        new = operand if op['form'].startswith('w') else old | operand if op['form'].startswith('s') else old & ~operand
        new &= MASK64
        wanted = list(before)
        fault = None
        if op['cause']:
            cause, epc, tval, status = struct.unpack_from('<4Q', memory, record+96)
            if (cause, epc, tval) != (2, pc, word) or status>>11&3 != 3:
                raise RuntimeError('CSR fault cause/PC/tval/MPP differs')
            if fault_index >= len(trap_logs) or trap_logs[fault_index] != ('H0 S0:N0:C0:T0', f'{cause:x}', f'{tval:x}'):
                raise RuntimeError('CSR raw trap differs from memory snapshot')
            for csr, value in zip(captures, (cause, epc, tval, status)):
                capture = captures[csr][fault_index]
                if capture['registers'].get('x5:=') != value or capture['csrs'] != [(csr, ':', value)]:
                    raise RuntimeError('CSR fault CSR read differs')
            fault = dict(mcause=cause, mepc=hex(epc), mtval=hex(tval), mstatus=hex(status))
            fault_index += 1
            struct.pack_into('<4Q', expected, record+96, cause, epc, tval, status)
        else:
            if op['rd']:
                wanted[2] = old
            if op['write']:
                wanted[4] = new
                if csrname == 'mscratch':
                    wanted[3] = new
        csr_events = [] if fault else ([(csrname, ':', old)] if op['read'] else []) + ([(csrname, '=', new)] if op['write'] else [])
        writes = {key: value for key, value in actual['registers'].items() if key.endswith(':=')}
        if after != wanted or actual['csrs'] != csr_events or actual['memory'] or writes != ({} if fault or op['rd'] == 0 else {'x20:=': old}):
            raise RuntimeError('CSR result, write suppression or destination preservation differs: '+name)
        if not op['form'].endswith('i') and op['source'] and actual['registers'].get('x10::') != a:
            raise RuntimeError('CSR source operand lacks real read evidence')
        index = by_pc[pc][0][0]
        next_pc = events[index+1]['pc']
        if next_pc != (syms['trap_handler'] if fault else pc+4):
            raise RuntimeError('CSR next-PC transition differs')
        if pre[record:record+RECORD_SIZE] != bytes([0xA5])*RECORD_SIZE:
            raise RuntimeError('CSR sentinel missing')
        struct.pack_into('<12Q', expected, record, *before, *after)
        rows.append(dict(**site, hart=actual['hart'], cycle=actual['cycle'], encoding_fields=fields,
            before={key: hex(value) for key, value in zip(('x10', 'x11', 'x20', 'mscratch', 'target_csr', 'x0'), before)},
            after={key: hex(value) for key, value in zip(('x10', 'x11', 'x20', 'mscratch', 'target_csr', 'x0'), after)},
            csr_events=[dict(name=key, access=access, value=hex(value)) for key, access, value in actual['csrs']],
            fault=fault, next_pc=hex(next_pc), output_memory_bytes=memory[record:record+RECORD_SIZE].hex(' '), **{'pass': True}))
    if fault_index != 6 or len(trap_logs) != 6 or any(len(es) != 6 for es in captures.values()):
        raise RuntimeError('unexpected/missing CSR traps')
    struct.pack_into('<Q', expected, syms['trap_count']-start, 6)
    struct.pack_into('<I', expected, syms['completion']-start, DONE)
    if memory != expected or not event('park')['disassembly'].startswith('wfi'):
        raise RuntimeError('CSR whole guarded memory/completion mismatch')
    (out/'expected.bin').write_bytes(expected)
    (out/'registers.json').write_text(json.dumps(dict(source='actual H0 CSR/register/MEM events and device snapshots; x0 captured by real stores', operations=rows), indent=2)+'\n')
    (out/'result.json').write_text(json.dumps(dict(case=case, operation_count=26, handler_count=6, trap_count=6,
        completion_word=hex(DONE), whole_monitor_matches=True, operations=rows, **{'pass': True}), indent=2)+'\n')
    for row in rows:
        print(f'  {row["name"]:<25} {row["word"]} x20={row["after"]["x20"]} CSR={row["after"]["target_csr"]} '
              + ('cause=2 destination preserved ' if row['fault'] else '') + 'PASS')
    print(f'CSR {case}: 26 sites, six handlers, six expected read-only faults; real CSR/register/memory PASS; {out}')


def main():
    cases = sys.argv[1:] or ['primary', 'exact']
    if any(case not in ('primary', 'exact') for case in cases):
        raise SystemExit('usage: python3 examples/csr.py [primary|exact ...]')
    env = runtime()
    for case in cases:
        execute(case, env)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.SubprocessError, struct.error) as exc:
        print(f'csr.py: {exc}', file=sys.stderr)
        raise SystemExit(1)
