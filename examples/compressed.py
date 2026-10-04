#!/usr/bin/env python3
"""Execute ET-SOC1 compressed arithmetic/memory/control and expected faults."""

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

OUT = ROOT / 'out/compressed'
DONE = 0x4B4F5445
XSEED = 0x5AA55AA55AA55AA5
RASEED = 0xCAFEF00DCAFEF00D
PATHSEED = 0xCAFE
TAKE, FALL = 0x54414B45, 0x46414C4C
MASK64 = (1 << 64) - 1
RECORD_SIZE = 192


def signed(value,width):
    value &= (1<<width)-1
    return value-(1<<width) if value>>(width-1) else value


def operations(case):
    a,b=(0x800000017FFFFFFB,0x7FFFFFFFFFFFFFED) if case=='primary' else (0x7FFFFFFE80000005,0x8000000000000003)
    imm=-13 if case=='primary' else 23; shift=63 if case=='primary' else 1
    rows=[]
    def add(name,asm,kind='arithmetic',aa=a,bb=b,immediate=0,width=0,cause=0,taken=False):
        rows.append(dict(name=name,handler=name.split('_taken')[0].split('_fall')[0],
            mnemonic=asm.split()[0] if cause==0 else 'c.ebreak' if cause==3 else 'illegal compressed opcode',
            asm=asm,kind=kind,a=aa&MASK64,b=bb&MASK64,immediate=immediate,width=width,cause=cause,taken=taken,
            direction='forward' if case=='primary' else 'backward'))
    for name in ('add','sub','xor','or','and','addw','subw','mv'):
        add('c_'+name,f'c.{name} a0, a1')
    for name in ('addi','addiw','andi','li'):
        add('c_'+name,f'c.{name} a0, {imm}',immediate=imm)
    for name in ('slli','srli','srai'):
        add('c_'+name,f'c.{name} a0, {shift}',immediate=shift)
    add('c_lui',f'c.lui a0, {0xFFFFF if case=="primary" else 1}',immediate=-4096 if case=='primary' else 4096)
    add('c_addi16sp',f'c.addi16sp sp, {-256 if case=="primary" else 128}',immediate=-256 if case=='primary' else 128)
    add('c_addi4spn',f'c.addi4spn a0, sp, {256 if case=="primary" else 128}',immediate=256 if case=='primary' else 128)
    payload=0xFEDCBA9889ABCDEF if case=='primary' else 0x0123456776543210
    offset=32 if case=='primary' else 64
    for name in ('lw','ld','sw','sd','lwsp','ldsp','swsp','sdsp'):
        kind='load' if name.startswith('l') else 'store'
        add('c_'+name,f'c.{name} a0, {offset}({"sp" if name.endswith("sp") else "a1"})',kind,
            aa=XSEED if kind=='load' else payload,immediate=offset,width=32 if name.startswith(('lw','sw')) else 64)
    for name in ('beqz','bnez'):
        for taken in (True,False):
            suffix='c_'+name+('_taken' if taken else '_fall')
            zero=taken if name=='beqz' else not taken
            add(suffix,f'c.{name} a0, target_{suffix}','branch',aa=0 if zero else (-3 if case=='primary' else 9),taken=taken)
    for name in ('j','jr','jalr'):
        suffix='c_'+name
        add(suffix,f'c.{name} '+(f'target_{suffix}' if name=='j' else 'a0'),'branch',taken=True)
    add('c_illegal','.2byte 0x0000','fault',cause=2)
    add('c_reserved','.2byte 0x8000','fault',cause=2)
    add('c_ebreak','c.ebreak','fault',cause=3)
    return rows


def label(name):
    return [f'.globl {name}',f'{name}:']


def kernel(ops,case):
    lines=['# SPDX-License-Identifier: Apache-2.0',
        '# Startup provenance: Copyright (c) 2025 Ainekko, Co.; ET Platform boot.S.',
        '.option push','.option norelax','.option norvc','.section .text.entry,"ax",@progbits',*label('_start'),
        '    csrwi satp, 0','    csrwi mie, 0','    csrwi mip, 0','    csrwi medeleg, 0','    csrwi mideleg, 0',
        '    csrr t0, mstatus','    li t1, -9','    and t0, t0, t1','    csrw mstatus, t0',
        '    csrwi tensor_mask, 0','    la sp, __stack_top','    la t0, trap_handler','    csrw mtvec, t0','    li s1, 0']
    for op in ops:
        name=op['name']
        lines += [f'    la s0, record_{name}',f'    la t0, input_{name}',*label('load_a_'+name),'    ld a0, 0(t0)',
            *label('load_b_'+name),'    ld a1, 8(t0)','    la sp, __stack_top','    addi sp, sp, -512',
            f'    li ra, 0x{RASEED:x}',f'    li s4, {PATHSEED}',f'    li s3, {op["cause"]}']
        if op['kind'] in ('load','store') and name.endswith('sp'):
            lines += [f'    la sp, target_{name}',f'    addi sp, sp, {32-op["immediate"]}']
        for j,(suffix,reg) in enumerate([('a','a0'),('b','a1'),('sp','sp'),('ra','ra'),('path','s4')]):
            lines += [*label('before_'+suffix+'_'+name),f'    sd {reg}, {8*j}(s0)']
        lines += [*label('before_zero_'+name),'    sd zero, 88(s0)']
        target=[*label('target_'+name),f'    li s4, {TAKE}',f'    jal zero, join_{name}']
        if op['kind']=='branch' and op['direction']=='backward': lines += [f'    jal zero, op_{name}',*target]
        lines += ['.option rvc',*label('op_'+name),f'    {op["asm"]}','.option norvc']
        if op['kind']=='branch':
            lines += [*label('fall_'+name),f'    li s4, {FALL}',f'    jal zero, join_{name}']
            if op['direction']=='forward': lines += target
        lines += [*label('join_'+name),'    auipc s6, 0']
        for j,(suffix,reg) in enumerate([('a','a0'),('b','a1'),('sp','sp'),('ra','ra'),('path','s4')]):
            lines += [*label('after_'+suffix+'_'+name),f'    sd {reg}, {40+8*j}(s0)']
        lines += [*label('after_pc_'+name),'    sd s6, 80(s0)',*label('after_zero_'+name),'    sd zero, 96(s0)']
    lines += ['    la sp, __stack_top','    la t0, trap_count','    sd s1, 0(t0)',f'    li t0, 0x{DONE:x}',
        '    la t1, completion','    sw t0, 0(t1)',*label('park'),'    wfi','    j park',
        '.balign 4096',*label('trap_handler'),'    csrr t0, mcause','    bne t0, s3, unexpected']
    for csr,offset in [('mcause',104),('mepc',112),('mtval',120),('mstatus',128)]:
        lines += [*label('capture_'+csr),f'    csrr t0, {csr}',f'    sd t0, {offset}(s0)']
    lines += ['    addi s1, s1, 1','    csrr t0, mepc','    addi t0, t0, 2','    csrw mepc, t0','    mret',
        *label('unexpected'),'    la t1, unexpected_trap','    csrr t0, mcause','    sd t0, 0(t1)',
        '    csrr t0, mepc','    sd t0, 8(t1)','    csrr t0, mtval','    sd t0, 16(t1)','    j park','.option pop',
        '.section .data,"aw",@progbits','.balign 32',*label('__monitor_start')]
    for op in ops: lines += [*label('record_'+op['name']),f'    .fill {RECORD_SIZE},1,0xa5']
    payload=0xFEDCBA9889ABCDEF if case=='primary' else 0x0123456776543210
    for op in ops:
        if op['kind'] not in ('load','store'): continue
        lines += [*label('target_'+op['name']),'    .fill 32,1,0x5a']
        lines += [f'    .dword 0x{payload:x}'] if op['kind']=='load' else ['    .fill 8,1,0x5a']
        lines += ['    .fill 88,1,0x5a']
    lines += [*label('trap_count'),'    .dword 0',*label('completion'),'    .word 0','.balign 8',*label('unexpected_trap'),'    .dword 0,0,0']
    for op in ops:
        a=f'target_{op["name"]} + 1' if op['handler'] in ('c_jr','c_jalr') else f'0x{op["a"]:x}'
        b=f'target_{op["name"]} + 32 - {op["immediate"]}' if op['kind'] in ('load','store') and not op['name'].endswith('sp') else f'0x{op["b"]:x}'
        lines += ['.balign 8',*label('input_'+op['name']),f'    .dword {a},{b}']
    return '\n'.join([*lines,*label('__monitor_end')])+'\n'


def execute(case, env):
    ops = operations(case)
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
    stage = f'/tmp/etsoc1-compressed-{uuid.uuid4().hex[:10]}'
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
            offsets = [p[2]+pc-p[3] for p in segments if p[0]==1 and p[1]&1 and p[3]<=pc and pc+2<=p[3]+p[5]]
            if len(offsets) != 1:
                raise RuntimeError('operation lacks unique executable PT_LOAD mapping')
            raw = elf[offsets[0]:offsets[0]+2]
            decoded = [line.strip() for line in asm.splitlines() if re.search(rf'\b{pc:x}:\s',line)]
            if len(decoded)!=1 or (not op['cause'] and op['mnemonic'] not in decoded[0]) or len(raw)!=2:
                raise RuntimeError(f'ET disassembler mismatch: {op["name"]}: {decoded}')
            sites.append({k:op[k] for k in ('name','handler','mnemonic','kind','cause','taken','width','immediate','direction')} | dict(pc=hex(pc),
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


def validate(out,ops,sites,syms,start,size,case):
    trace=(out/'trace.log').read_text(); events,_=trace_data(trace)
    if any(e['hart']!='H0 S0:N0:C0:T0' for e in events): raise RuntimeError('unexpected executing hart')
    cursor=-1
    for e in events: e['memory']=[]
    for line in trace.splitlines():
        match=re.search(r'I\(M\): 0x([0-9a-f]+) \(0x[0-9a-f]+\)',line)
        if match:
            cursor+=1
            if events[cursor]['pc']!=int(match[1],16): raise RuntimeError('trace event association differs')
        elif cursor>=0:
            match=re.search(r'MEM(8|16|32|64)\[0x([0-9a-f]+)\] ([=:]) 0x([0-9a-f]+)',line)
            if match: events[cursor]['memory'].append((int(match[1]),int(match[2],16),match[3],int(match[4],16)))
    by_pc={}
    for index,e in enumerate(events): by_pc.setdefault(e['pc'],[]).append((index,e))
    def event(name):
        found=by_pc.get(syms[name],[])
        if len(found)!=1: raise RuntimeError('missing/repeated compressed site '+name)
        return found[0][1]
    pre,memory=(out/'prestart.bin').read_bytes(),(out/'output.bin').read_bytes()
    if len(pre)!=size or len(memory)!=size: raise RuntimeError('incomplete compressed monitor dump')
    elf=(out/'kernel.elf').read_bytes(); phoff=struct.unpack_from('<Q',elf,32)[0]; phsize,phcount=struct.unpack_from('<HH',elf,54)
    segments=[struct.unpack_from('<II6Q',elf,phoff+i*phsize) for i in range(phcount)]
    maps=[p[2]+start-p[3] for p in segments if p[0]==1 and p[3]<=start and start+size<=p[3]+p[5]]
    if len(maps)!=1 or pre!=elf[maps[0]:maps[0]+size]: raise RuntimeError('compressed initial memory differs from ELF')
    trap_logs=re.findall(r'\[(H\d+ S\d+:N\d+:C\d+:T\d+)\].*Trapping to M-mode with cause 0x([0-9a-f]+) and tval 0x([0-9a-f]+)',trace)
    captures={csr:[e for e in events if e['pc']==syms['capture_'+csr]] for csr in ('mcause','mepc','mtval','mstatus')}
    expected,rows,fault_index=bytearray(pre),[],0
    payload=0xFEDCBA9889ABCDEF if case=='primary' else 0x0123456776543210
    for op,site in zip(ops,sites):
        name,handler=op['name'],op['handler']; actual=event('op_'+name); pc=actual['pc']
        trace_name={'c_bnez':'c.bneqz','c_sw':'c.sd'}.get(handler,op['mnemonic'])
        if actual['word']!=int(site['word'],16) or actual['word']&3==3 or not actual['disassembly'].startswith(trace_name):
            raise RuntimeError('compressed executed instruction differs from ELF/site')
        a,b=struct.unpack_from('<2Q',pre,syms['input_'+name]-start)
        for j,reg in enumerate(('x10','x11')):
            load=event(('load_a_' if j==0 else 'load_b_')+name)
            if load['registers'].get(reg+':=')!=(a,b)[j] or load['memory']!=[(64,syms['input_'+name]+8*j,':',(a,b)[j])]: raise RuntimeError('missing actual compressed input load')
        stack=syms['target_'+name]+32-op['immediate'] if op['kind'] in ('load','store') and name.endswith('sp') else syms['__stack_top']-512
        before,after=[],[]
        for phase,values in [('before',before),('after',after)]:
            for suffix,reg in [('a','x10'),('b','x11'),('sp','x2'),('ra','x1'),('path','x20')]:
                values.append(event(phase+'_'+suffix+'_'+name)['registers'].get(reg+'::'))
        if tuple(before)!=(a,b,stack,RASEED,PATHSEED): raise RuntimeError('actual compressed before state differs')
        wanted=list(before); wanted_mem=[]; fault=None; taken=False
        if op['kind']=='arithmetic':
            imm=op['immediate']
            if handler in ('c_add','c_addw'): value=a+b
            elif handler in ('c_sub','c_subw'): value=a-b
            elif handler=='c_xor': value=a^b
            elif handler=='c_or': value=a|b
            elif handler=='c_and': value=a&b
            elif handler=='c_mv': value=b
            elif handler in ('c_addi','c_addiw'): value=a+imm
            elif handler=='c_andi': value=a&imm
            elif handler in ('c_li','c_lui'): value=imm
            elif handler=='c_slli': value=a<<imm
            elif handler=='c_srli': value=a>>imm
            elif handler=='c_srai': value=signed(a,64)>>imm
            elif handler=='c_addi4spn': value=stack+imm
            elif handler=='c_addi16sp': value=a; wanted[2]=(stack+imm)&MASK64
            else: raise RuntimeError('unknown compressed arithmetic')
            if handler in ('c_addiw','c_addw','c_subw'): value=signed(value,32)
            wanted[0]=value&MASK64
            reg='x2' if handler=='c_addi16sp' else 'x10'
            if actual['registers'].get(reg+':=')!=wanted[2 if reg=='x2' else 0]: raise RuntimeError('compressed arithmetic write differs')
        elif op['kind'] in ('load','store'):
            address=syms['target_'+name]+32; width=op['width']; off=address-start
            if op['kind']=='load':
                value=int.from_bytes(pre[off:off+width//8],'little')
                wanted_mem=[(width,address,':',value)]; wanted[0]=(signed(value,32) if width==32 else value)&MASK64
                if actual['registers'].get('x10:=')!=wanted[0]: raise RuntimeError('compressed load write differs')
            else:
                value=a&((1<<width)-1); wanted_mem=[(width,address,'=',value)]
                expected[off:off+width//8]=value.to_bytes(width//8,'little')
            if actual['registers'].get(('x2' if name.endswith('sp') else 'x11')+'::')!=(stack if name.endswith('sp') else b): raise RuntimeError('compressed actual memory base read differs')
        elif op['kind']=='branch':
            taken=a==0 if handler=='c_beqz' else a!=0 if handler=='c_bnez' else True
            wanted[4]=TAKE if taken else FALL
            if handler=='c_jalr': wanted[3]=pc+2
            if taken!=op['taken']: raise RuntimeError('compressed branch outcome differs')
        elif op['kind']=='fault':
            cause,epc,tval,status=struct.unpack_from('<4Q',memory,syms['record_'+name]-start+104)
            if (cause,epc,tval)!=(op['cause'],pc,pc if cause==3 else 0) or status>>11&3!=3:
                raise RuntimeError('wrong compressed fault cause/PC/tval/MPP')
            if fault_index>=len(trap_logs) or trap_logs[fault_index]!=('H0 S0:N0:C0:T0',f'{cause:x}',f'{tval:x}'): raise RuntimeError('compressed fault snapshot differs from raw trap')
            for csr,value in zip(captures,(cause,epc,tval,status)):
                if captures[csr][fault_index]['registers'].get('x5:=')!=value: raise RuntimeError('compressed fault CSR read differs')
            fault=dict(mcause=cause,mepc=hex(epc),mtval=hex(tval),mstatus=hex(status));fault_index+=1
        if actual['memory']!=wanted_mem or after!=wanted: raise RuntimeError('compressed memory access or after-register state differs')
        writes={k:v for k,v in actual['registers'].items() if k.endswith(':=')}
        write_reg='x2' if handler=='c_addi16sp' else 'x10' if op['kind'] in ('arithmetic','load') else 'x1' if handler=='c_jalr' else None
        if writes!=({write_reg+':=':wanted[2 if write_reg=='x2' else 3 if write_reg=='x1' else 0]} if write_reg else {}): raise RuntimeError('unexpected compressed destination writes')
        index=by_pc[pc][0][0]; next_pc=events[index+1]['pc']
        target=syms['target_'+name] if op['kind']=='branch' else None
        if next_pc!=(syms['trap_handler'] if fault else target if taken else pc+2): raise RuntimeError('compressed next-PC transition differs')
        join=syms['join_'+name]
        if event('join_'+name)['registers'].get('x22:=')!=join: raise RuntimeError('compressed join PC lacks actual AUIPC evidence')
        offset=syms['record_'+name]-start
        if pre[offset:offset+RECORD_SIZE]!=bytes([0xA5])*RECORD_SIZE: raise RuntimeError('missing compressed record sentinel')
        for j,(phase,suffix,value) in enumerate((p,s,v) for p,values in [('before',before),('after',after)] for s,v in zip(('a','b','sp','ra','path'),values)):
            if event(phase+'_'+suffix+'_'+name)['memory']!=[(64,start+offset+8*j,'=',value)]: raise RuntimeError('compressed snapshot store differs')
        zero_values=[]
        for suffix,phase,off,value in [('pc','after',80,join),('zero','before',88,0),('zero','after',96,0)]:
            snapshot=event(phase+'_'+suffix+'_'+name)
            if snapshot['memory']!=[(64,start+offset+off,'=',value)]: raise RuntimeError('compressed PC/x0 snapshot differs')
            if suffix=='zero':
                zero_values.append(struct.unpack_from('<Q',memory,offset+off)[0])
                if zero_values[-1]!=0: raise RuntimeError('actual zero-register snapshot differs')
        struct.pack_into('<13Q',expected,offset,*before,*after,join,*zero_values)
        if fault: struct.pack_into('<4Q',expected,offset+104,cause,epc,tval,status)
        rows.append(dict(**site,hart=actual['hart'],cycle=actual['cycle'],trace_mnemonic=trace_name,
            registers_before={r:hex(v) for r,v in zip(('x10','x11','x2','x1','x20'),before)},
            registers_after={r:hex(v) for r,v in zip(('x10','x11','x2','x1','x20'),after)},
            x0_before=zero_values[0],x0_after=zero_values[1],next_pc=hex(next_pc),joined_pc=hex(join),
            target_pc=hex(target) if target is not None else None,actual_taken=taken,fault=fault,
            memory_events=[dict(width=w,address=hex(ad),access=access,value=hex(v)) for w,ad,access,v in actual['memory']],
            output_memory_bytes=memory[offset:offset+RECORD_SIZE].hex(' '),**{'pass':True}))
    if fault_index!=3 or len(trap_logs)!=3 or any(len(es)!=3 for es in captures.values()): raise RuntimeError('unexpected/missing compressed traps')
    struct.pack_into('<Q',expected,syms['trap_count']-start,3);struct.pack_into('<I',expected,syms['completion']-start,DONE)
    if memory!=expected or not event('park')['disassembly'].startswith('wfi'): raise RuntimeError('compressed whole memory/completion mismatch')
    (out/'expected.bin').write_bytes(expected)
    (out/'registers.json').write_text(json.dumps(dict(source='actual H0 register/MEM events and device-side snapshots; x0 is captured by real stores',operations=rows),indent=2)+'\n')
    (out/'result.json').write_text(json.dumps(dict(case=case,operation_count=36,handler_count=34,implemented_handler_count=31,
        architectural_fault_handler_count=3,trap_count=3,completion_word=hex(DONE),whole_monitor_matches=True,operations=rows,**{'pass':True}),indent=2)+'\n')
    for row in rows: print(f'  {row["name"]:<16} PC={row["pc"]} bytes={row["bytes_memory_order"]} x10={row["registers_after"]["x10"]} next={row["next_pc"]} '+(f'cause={row["fault"]["mcause"]} ' if row['fault'] else '')+'PASS')
    print(f'Compressed {case}: 36 sites, 31 implemented handlers + 3 architectural fault handlers; actual state/control/memory PASS; {out}')


def main():
    cases=sys.argv[1:] or ['primary','exact']
    if any(case not in ('primary','exact') for case in cases): raise SystemExit('usage: python3 examples/compressed.py [primary|exact ...]')
    env=runtime()
    for case in cases: execute(case,env)
    return 0


if __name__=='__main__':
    try: raise SystemExit(main())
    except (OSError,RuntimeError,KeyError,ValueError,subprocess.SubprocessError,struct.error) as exc:
        print(f'compressed.py: {exc}',file=sys.stderr); raise SystemExit(1)
