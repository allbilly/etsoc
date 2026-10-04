#!/usr/bin/env python3
"""Run all eight ordinary branch/jump handlers in upstream ET-SOC1 SysEmu."""

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

OUT = ROOT / 'out/branches'
DONE = 0x4B4F5445
XSEED = 0x5AA55AA55AA55AA5
PATHSEED = 0xCAFE
TAKE = 0x54414B45
FALL = 0x46414C4C
MASK64 = (1 << 64) - 1
RECORD_SIZE = 128


def signed(value):
    return value-(1<<64) if value>>63 else value


def predicate(name,a,b):
    return {'beq':a==b,'bne':a!=b,'blt':signed(a)<signed(b),
            'bge':signed(a)>=signed(b),'bltu':a<b,'bgeu':a>=b}[name]


def operations(case):
    negative,positive = (-3,5) if case=='primary' else (-17,9)
    direction = 'forward' if case=='primary' else 'backward'
    rows=[]
    pairs={'beq':(negative,negative),'bne':(negative,positive),'blt':(negative,positive),
           'bge':(positive,negative),'bltu':(positive,negative),'bgeu':(negative,positive)}
    for mnemonic,pair in pairs.items():
        for taken in (True,False):
            a,b=pair if taken else (negative,positive) if mnemonic=='beq' else (negative,negative) if mnemonic=='bne' else pair[::-1]
            name=mnemonic+('_taken' if taken else '_fall')
            rows.append(dict(name=name,mnemonic=mnemonic,kind='conditional',variant='taken' if taken else 'not taken',
                a=a&MASK64,b=b&MASK64,taken=taken,rd=0,immediate=0,direction=direction,
                asm=f'{mnemonic} a0, a1, target_{name}'))
    for name,mnemonic,rd,variant in [('jal_link','jal',20,'link'),('jal_discard','jal',0,'discard link'),
                                   ('jalr_link','jalr',20,'clear target low bit'),('jalr_alias','jalr',10,'source/destination alias')]:
        immediate=24 if case=='primary' else -24
        destination={0:'zero',10:'a0',20:'s4'}[rd]
        asm=f'jal {destination}, target_{name}' if mnemonic=='jal' else f'jalr {destination}, {immediate}(a0)'
        rows.append(dict(name=name,mnemonic=mnemonic,kind='jump',variant=variant,a=negative&MASK64,
                         b=positive,taken=True,rd=rd,immediate=immediate,direction=direction,asm=asm))
    return rows


def label(name):
    return [f'.globl {name}',f'{name}:']


def kernel(ops):
    lines=['# SPDX-License-Identifier: Apache-2.0',
        '# Startup provenance: Copyright (c) 2025 Ainekko, Co.; ET Platform boot.S.',
        '.option push','.option norelax','.option norvc','.section .text.entry,"ax",@progbits',*label('_start'),
        '    csrwi satp, 0','    csrwi mie, 0','    csrwi mip, 0','    csrwi medeleg, 0','    csrwi mideleg, 0',
        '    csrr t0, mstatus','    li t1, -9','    and t0, t0, t1','    csrw mstatus, t0',
        '    csrwi tensor_mask, 0','    la sp, __stack_top','    la t0, trap_handler','    csrw mtvec, t0']
    for op in ops:
        name=op['name']
        lines += [f'    la s0, record_{name}',f'    la t0, input_{name}',*label('load_a_'+name),'    ld a0, 0(t0)',
            *label('load_b_'+name),'    ld a1, 8(t0)',f'    li s4, 0x{XSEED:x}',f'    li s5, {PATHSEED}']
        for suffix,reg,offset in [('a','a0',0),('b','a1',8),('link','s4',16),('path','s5',24),('zero','zero',72)]:
            lines += [*label('before_'+suffix+'_'+name),f'    sd {reg}, {offset}(s0)']
        target=[*label('target_'+name),f'    li s5, {TAKE}',f'    jal zero, join_{name}']
        if op['direction']=='backward': lines += [f'    jal zero, op_{name}',*target]
        lines += [*label('op_'+name),f'    {op["asm"]}',*label('fall_'+name),f'    li s5, {FALL}',f'    jal zero, join_{name}']
        if op['direction']=='forward': lines += target
        lines += [*label('join_'+name),'    auipc s6, 0']
        for suffix,reg,offset in [('a','a0',32),('b','a1',40),('link','s4',48),('path','s5',56),('pc','s6',64),('zero','zero',80)]:
            lines += [*label('after_'+suffix+'_'+name),f'    sd {reg}, {offset}(s0)']
    lines += [f'    li t0, 0x{DONE:x}','    la t1, completion','    sw t0, 0(t1)',*label('park'),'    wfi','    j park',
        '.balign 4096',*label('trap_handler'),'    la t1, unexpected_trap',
        '    csrr t0, mcause','    sd t0, 0(t1)','    csrr t0, mepc','    sd t0, 8(t1)',
        '    csrr t0, mtval','    sd t0, 16(t1)','    j park','.option pop',
        '.section .data,"aw",@progbits','.balign 32',*label('__monitor_start')]
    for op in ops: lines += [*label('record_'+op['name']),f'    .fill {RECORD_SIZE},1,0xa5']
    lines += [*label('completion'),'    .word 0','.balign 8',*label('unexpected_trap'),'    .dword 0,0,0']
    for op in ops:
        a=f'target_{op["name"]} - ({op["immediate"]}) + 1' if op['mnemonic']=='jalr' else f'0x{op["a"]:x}'
        lines += ['.balign 8',*label('input_'+op['name']),f'    .dword {a},0x{op["b"]:x}']
    return '\n'.join([*lines,*label('__monitor_end')])+'\n'


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
    stage = f'/tmp/etsoc1-branches-{uuid.uuid4().hex[:10]}'
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
            f'{tp}objdump -d -M numeric,no-aliases kernel.elf > kernel.asm; '
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
            sites.append({k:op[k] for k in ('name','mnemonic','kind','variant','taken','rd','immediate','direction')} | dict(pc=hex(pc),
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
        validate(out,ops,sites,syms,start,size)
    finally:
        if container:
            # Retrieve the assembly, ELF and partial dump even after failures.
            pulled = run_logged(log,[podman,'cp',f'{env["container"]}:{stage}/.',str(out)])
            if pulled.returncode == 0:
                checked([podman,'exec',env['container'],'rm','-rf',stage])


def validate(out,ops,sites,syms,start,size):
    trace=(out/'trace.log').read_text()
    if re.search(r'\b(?:trap|exception)\b',trace,re.I): raise RuntimeError('unexpected branch execution trap')
    events,regs=trace_data(trace)
    if any(e['hart']!='H0 S0:N0:C0:T0' for e in events): raise RuntimeError('unexpected executing hart')
    stores,current={},None
    for line in trace.splitlines():
        match=re.search(r'I\(M\): 0x([0-9a-f]+) \(0x[0-9a-f]+\)',line)
        if match: current=int(match[1],16); stores.setdefault(current,[])
        elif current is not None:
            match=re.search(r'MEM64\[0x([0-9a-f]+)\] = 0x([0-9a-f]+)',line)
            if match: stores[current].append((int(match[1],16),int(match[2],16)))
    by_pc={}
    for index,e in enumerate(events): by_pc.setdefault(e['pc'],[]).append((index,e))
    def event(name):
        matches=by_pc.get(syms[name],[])
        if len(matches)!=1: raise RuntimeError('missing/repeated actual branch site: '+name)
        return matches[0][1]
    pre,memory=(out/'prestart.bin').read_bytes(),(out/'output.bin').read_bytes()
    if len(pre)!=size or len(memory)!=size: raise RuntimeError('incomplete branch monitor dump')
    elf=(out/'kernel.elf').read_bytes()
    phoff=struct.unpack_from('<Q',elf,32)[0]; phsize,phcount=struct.unpack_from('<HH',elf,54)
    segments=[struct.unpack_from('<II6Q',elf,phoff+i*phsize) for i in range(phcount)]
    mappings=[p[2]+start-p[3] for p in segments if p[0]==1 and p[3]<=start and start+size<=p[3]+p[5]]
    if len(mappings)!=1 or pre!=elf[mappings[0]:mappings[0]+size]: raise RuntimeError('branch inputs/guards differ from ELF')
    expected,rows=bytearray(pre),[]
    for op,site in zip(ops,sites):
        name=op['name']; actual=event('op_'+name); pc=actual['pc']; target=syms['target_'+name]
        if actual['word']!=int(site['word'],16) or actual['disassembly'].split()[0]!=op['mnemonic']:
            raise RuntimeError('branch executed word/disassembly differs from ELF operation')
        a,b=struct.unpack_from('<2Q',pre,syms['input_'+name]-start)
        wanted_a=target-op['immediate']+1 if op['mnemonic']=='jalr' else op['a']
        if (a,b)!=(wanted_a,op['b']): raise RuntimeError('linked branch input case differs')
        for reg,operand,suffix in [('x10',a,'a'),('x11',b,'b')]:
            if event('load_'+suffix+'_'+name)['registers'].get(reg+':=')!=operand: raise RuntimeError('missing actual branch operand load')
        taken=predicate(op['mnemonic'],a,b) if op['kind']=='conditional' else True
        if taken!=op['taken']: raise RuntimeError('branch predicate differs from requested outcome')
        index=by_pc[pc][0][0]
        next_pc=events[index+1]['pc']
        if next_pc!=(target if taken else pc+4): raise RuntimeError('actual next PC differs from branch/jump outcome')
        if op['direction']=='forward' and target<=pc or op['direction']=='backward' and target>=pc: raise RuntimeError('target direction differs')
        if op['kind']=='conditional' or op['mnemonic']=='jalr':
            if actual['registers'].get('x10::')!=a: raise RuntimeError('branch source A read differs')
        if op['kind']=='conditional' and actual['registers'].get('x11::')!=b: raise RuntimeError('branch source B read differs')
        link=pc+4
        if op['rd'] and actual['registers'].get(f'x{op["rd"]}:=')!=link: raise RuntimeError('jump did not write actual next-PC link')
        if not op['rd'] and any(k.endswith(':=') for k in actual['registers']): raise RuntimeError('branch/x0 jump unexpectedly wrote a register')
        recorded=[]
        for phase in ('before','after'):
            for suffix,reg in [('a','x10'),('b','x11'),('link','x20'),('path','x21')]:
                value=event(phase+'_'+suffix+'_'+name)['registers'].get(reg+'::')
                if value is None: raise RuntimeError('branch snapshot lacks actual register read')
                recorded.append(value)
        wanted=(a,b,XSEED,PATHSEED,link if op['rd']==10 else a,b,link if op['rd']==20 else XSEED,TAKE if taken else FALL)
        if tuple(recorded)!=wanted: raise RuntimeError('branch before/after registers or path marker differ')
        join=syms['join_'+name]
        if event('join_'+name)['registers'].get('x22:=')!=join or event('after_pc_'+name)['registers'].get('x22::')!=join:
            raise RuntimeError('joined PC lacks actual AUIPC/register snapshot evidence')
        offset=syms['record_'+name]-start
        if pre[offset:offset+RECORD_SIZE]!=bytes([0xA5])*RECORD_SIZE: raise RuntimeError('missing branch record sentinel')
        zeros=[]
        for phase,off in [('before',72),('after',80)]:
            snapshot=event(phase+'_zero_'+name)
            value=struct.unpack_from('<Q',memory,offset+off)[0]; zeros.append(value)
            if snapshot['word']>>20&31 or stores[snapshot['pc']]!=[(start+offset+off,value)] or value!=0:
                raise RuntimeError('actual x0 snapshot stores/dumped bytes differ')
        struct.pack_into('<11Q',expected,offset,*wanted,join,*zeros)
        rows.append(dict(**site,hart=actual['hart'],cycle=actual['cycle'],input_a=hex(a),input_b=hex(b),
            target_pc=hex(target),next_pc=hex(next_pc),joined_pc=hex(join),actual_taken=taken,
            x10_before=hex(recorded[0]),x11_before=hex(recorded[1]),x20_before=hex(recorded[2]),x21_before=hex(recorded[3]),
            x10_after=hex(recorded[4]),x11_after=hex(recorded[5]),x20_after=hex(recorded[6]),x21_after=hex(recorded[7]),
            x0_before=zeros[0],x0_after=zeros[1],output_memory_bytes=memory[offset:offset+RECORD_SIZE].hex(' '),**{'pass':True}))
    struct.pack_into('<I',expected,syms['completion']-start,DONE)
    if memory!=expected or not event('park')['disassembly'].startswith('wfi'): raise RuntimeError('branch whole memory/completion mismatch')
    (out/'expected.bin').write_bytes(expected)
    (out/'registers.json').write_text(json.dumps(dict(source='actual H0 register read/write events, next instruction PC and device-side snapshots',operations=rows),indent=2)+'\n')
    case='primary' if out==OUT else out.name
    (out/'result.json').write_text(json.dumps(dict(case=case,operation_count=16,handler_count=8,trap_count=0,
        completion_word=hex(DONE),whole_monitor_matches=True,operations=rows,**{'pass':True}),indent=2)+'\n')
    for row in rows: print(f'  {row["name"]:<14} PC={row["pc"]} word={row["word"]} next={row["next_pc"]} taken={row["actual_taken"]} x20={row["x20_after"]} PASS')
    print(f'Branches {case}: 16 sites, 8 handlers, {ops[0]["direction"]} targets; actual next PCs, links, alias, x0 and guarded memory PASS; {out}')


def main():
    cases=sys.argv[1:] or ['primary','exact']
    if any(case not in ('primary','exact') for case in cases): raise SystemExit('usage: python3 examples/branches.py [primary|exact ...]')
    env=runtime()
    for case in cases: execute(case,env)
    return 0


if __name__=='__main__':
    try: raise SystemExit(main())
    except (OSError,RuntimeError,KeyError,ValueError,subprocess.SubprocessError,struct.error) as exc:
        print(f'branches.py: {exc}',file=sys.stderr); raise SystemExit(1)
