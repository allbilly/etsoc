#!/usr/bin/env python3
"""Execute all 14 ordinary scalar load/store/fence handlers in ET SysEmu."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import struct
import subprocess
import sys
import uuid

from gemm import LINKER, ROOT, command, report_lanes, runtime, symbols, trace_data
from add import run_logged

OUT = ROOT / 'out/base-memory'
DONE = 0x4B4F5445
XSEED = 0x5AA55AA55AA55AA5
SEED = (0xA5A5A5A5,) * 8
MASK64 = (1 << 64) - 1
RECORD_SIZE = 256


def operations(case):
    immediate = 24 if case == 'primary' else -24
    rows = []
    for mnemonic, width in [('lb',8),('lbu',8),('lh',16),('lhu',16),
                            ('lw',32),('lwu',32),('ld',64),('flw',32),
                            ('sb',8),('sh',16),('sw',32),('sd',64),('fsw',32),('fence',0)]:
        kind = 'fence' if mnemonic == 'fence' else 'load' if mnemonic in ('lb','lbu','lh','lhu','lw','lwu','ld','flw') else 'store'
        reg = 'f20' if mnemonic == 'flw' else 'f11' if mnemonic == 'fsw' else 's4' if kind == 'load' else 'a1'
        asm = 'fence iorw, iorw' if kind == 'fence' else f'{mnemonic} {reg}, {immediate}(a0)'
        rows.append(dict(name=mnemonic,mnemonic=mnemonic,kind=kind,width=width,
                         immediate=immediate,variant='positive offset' if immediate>0 else 'negative offset',asm=asm))
    return rows


def inputs(case):
    value = 0xFEDCBA9889ABCDEF if case == 'primary' else 0x0123456776543210
    first = -1.5 if case == 'primary' else 2.5
    words = tuple(struct.unpack('<I',struct.pack('<f',v))[0]
                  for v in (first,*(float(j+(20 if case=='primary' else 30)) for j in range(1,8))))
    return value,words


def label(name):
    return [f'.globl {name}',f'{name}:']


def kernel(ops, case):
    value, fp = inputs(case)
    lines = ['# SPDX-License-Identifier: Apache-2.0',
        '# Startup provenance: Copyright (c) 2025 Ainekko, Co.; ET Platform boot.S.',
        '.option push','.option norelax','.option norvc','.section .text.entry,"ax",@progbits',*label('_start'),
        '    csrwi satp, 0','    csrwi mie, 0','    csrwi mip, 0','    csrwi medeleg, 0','    csrwi mideleg, 0',
        '    csrr t0, mstatus','    li t1, 0x6000','    or t0, t0, t1',
        '    li t1, -9','    and t0, t0, t1','    csrw mstatus, t0','    csrwi fcsr, 0',
        '    csrwi tensor_mask, 0','    la sp, __stack_top','    la t0, trap_handler','    csrw mtvec, t0',
        '    mova.m.x zero']
    for op in ops:
        name = op['name']
        lines += [f'    la s0, record_{name}',f'    la a0, target_{name}',f'    addi a0, a0, {32-op["immediate"]}',
            '    la t0, input_x',*label('load_x_'+name),'    ld a1, 0(t0)',
            '    la t0, input_fp',*label('load_fp_'+name),'    flq2 f11, 0(t0)',
            '    la t0, seed',*label('load_seed_'+name),'    flq2 f20, 0(t0)',f'    li s4, 0x{XSEED:x}']
        for phase in ('before','after'):
            if phase == 'after': lines += [*label('op_'+name),f'    {op["asm"]}']
            for reg, offset in [('f20',0 if phase=='before' else 32),('f11',64 if phase=='before' else 96)]:
                lines += [*label(f'{phase}_{reg}_{name}'),f'    fsq2 {reg}, {offset}(s0)']
            for reg,offset in [('a0',128),('a1',136),('s4',144)]:
                lines += [*label(f'{phase}_{reg}_{name}'),f'    sd {reg}, {offset+(24 if phase=="after" else 0)}(s0)']
            for state,offset,asm in [('mask',176,'mova.x.m t0'),('fcsr',192,'csrr t0, fcsr'),('mstatus',208,'csrr t0, mstatus')]:
                lines += [*label(f'{phase}_{state}_{name}'),f'    {asm}',*label(f'store_{phase}_{state}_{name}'),
                          f'    sd t0, {offset+(8 if phase=="after" else 0)}(s0)']
    lines += [f'    li t0, 0x{DONE:x}','    la t1, completion','    sw t0, 0(t1)',*label('park'),'    wfi','    j park',
        '.balign 4096',*label('trap_handler'),'    la t1, unexpected_trap',
        '    csrr t0, mcause','    sd t0, 0(t1)','    csrr t0, mepc','    sd t0, 8(t1)',
        '    csrr t0, mtval','    sd t0, 16(t1)','    j park','.option pop',
        '.section .data,"aw",@progbits','.balign 32',*label('__monitor_start')]
    for op in ops: lines += [*label('record_'+op['name']),f'    .fill {RECORD_SIZE},1,0xa5']
    for op in ops:
        payload = fp[0] if op['mnemonic']=='flw' else value
        lines += [*label('target_'+op['name']),'    .fill 32,1,0x5a']
        lines += ['    .fill 8,1,0x5a'] if op['kind']!='load' else [f'    .dword 0x{payload:x}']
        lines += ['    .fill 88,1,0x5a']
    lines += [*label('completion'),'    .word 0','.balign 8',*label('unexpected_trap'),'    .dword 0,0,0',
        '.balign 32',*label('seed'),'    .fill 32,1,0xa5',*label('input_x'),f'    .dword 0x{value:x}',
        '.balign 32',*label('input_fp'),'    .word '+','.join(f'0x{x:08x}' for x in fp),*label('__monitor_end')]
    return '\n'.join(lines)+'\n'


def memory_events(trace):
    """Scalar MEM events, including each lane of unmasked packed snapshots."""
    result,current={},None
    for line in trace.splitlines():
        match=re.search(r'I\(M\): 0x([0-9a-f]+) \(0x[0-9a-f]+\)',line)
        if match: current=int(match[1],16); result.setdefault(current,[])
        elif current is not None:
            match=re.search(r'MEM(8|16|32|64)\[0x([0-9a-f]+)\] ([=:]) 0x([0-9a-f]+)',line)
            if match: result[current].append((int(match[1]),int(match[2],16),match[3],int(match[4],16)))
    return result


def execute(case, env):
    ops = operations(case)
    out = OUT if case == 'primary' else OUT/case
    out.mkdir(parents=True, exist_ok=True)
    log = out/'commands.log'
    log.write_text('')
    for name in ('result.json','registers.json','trace.log','output.bin','prestart.bin','expected.bin'):
        (out/name).unlink(missing_ok=True)
    (out/'kernel.S').write_text(kernel(ops, case))
    (out/'link.ld').write_text(LINKER)
    container = env['kind'] == 'podman'
    podman = shutil.which('podman') or 'podman'
    stage = f'/tmp/etsoc1-base-memory-{uuid.uuid4().hex[:10]}'
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
            f'{tp}objdump -d -M numeric kernel.elf > kernel.asm; '
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
            sites.append({k:op[k] for k in ('name','mnemonic','kind','variant','width','immediate')} | dict(pc=hex(pc),
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
    trace=(out/'trace.log').read_text()
    if re.search(r'\b(?:trap|exception)\b',trace,re.I): raise RuntimeError('unexpected base-memory trap')
    events,regs=trace_data(trace)
    mem=memory_events(trace)
    if any(e['hart']!='H0 S0:N0:C0:T0' for e in events): raise RuntimeError('unexpected executing hart')
    def event(name):
        matches=[e for e in events if e['pc']==syms[name]]
        if len(matches)!=1: raise RuntimeError('missing/repeated actual site: '+name)
        return matches[0]
    pre,memory=(out/'prestart.bin').read_bytes(),(out/'output.bin').read_bytes()
    if len(pre)!=size or len(memory)!=size: raise RuntimeError('incomplete monitor dump')
    elf=(out/'kernel.elf').read_bytes()
    phoff=struct.unpack_from('<Q',elf,32)[0]; phsize,phcount=struct.unpack_from('<HH',elf,54)
    segments=[struct.unpack_from('<II6Q',elf,phoff+i*phsize) for i in range(phcount)]
    mappings=[p[2]+start-p[3] for p in segments if p[0]==1 and p[3]<=start and start+size<=p[3]+p[5]]
    if len(mappings)!=1 or pre!=elf[mappings[0]:mappings[0]+size]: raise RuntimeError('prestart input/guard bytes differ from ELF')
    value=struct.unpack_from('<Q',pre,syms['input_x']-start)[0]
    fp=struct.unpack_from('<8I',pre,syms['input_fp']-start)
    if (value,fp)!=inputs(case): raise RuntimeError('linked input case differs')
    expected,rows=bytearray(pre),[]
    for op,site in zip(ops,sites):
        name=op['name']; actual=event('op_'+name); pc=actual['pc']
        trace_name='lw' if name=='lwu' else name
        if actual['word']!=int(site['word'],16) or actual['disassembly'].split()[0]!=trace_name:
            raise RuntimeError('executed instruction differs from assembled bytes')
        address=syms['target_'+name]+32
        base=address-op['immediate']
        before_fp,after_fp=(regs[(syms[phase+'_f20_'+name],'f20',':')] for phase in ('before','after'))
        before_src,after_src=(regs[(syms[phase+'_f11_'+name],'f11',':')] for phase in ('before','after'))
        if event('load_x_'+name)['registers'].get('x11:=')!=value or mem[syms['load_x_'+name]]!=[(64,syms['input_x'],':',value)]:
            raise RuntimeError('missing actual scalar input load')
        for symbol,reg,words,addr in [('load_fp_','f11',fp,syms['input_fp']),('load_seed_','f20',SEED,syms['seed'])]:
            if event(symbol+name)['registers'].get(reg+':=')!=words or mem[syms[symbol+name]]!=[(32,addr+4*j,':',w) for j,w in enumerate(words)]:
                raise RuntimeError('missing actual full FP source/sentinel load')
        if before_fp!=SEED or before_src!=fp or after_src!=fp: raise RuntimeError('FP sources/sentinel changed unexpectedly')
        payload=int.from_bytes(pre[address-start:address-start+op['width']//8],'little')
        answer=XSEED
        wanted_fp=SEED
        if op['kind']=='load' and name!='flw':
            answer=payload
            if name in ('lb','lh','lw') and answer>>(op['width']-1): answer-=1<<op['width']
            answer &= MASK64
        elif name=='flw': wanted_fp=(payload,0,0,0,0,0,0,0)
        actual_mem=mem.get(pc,[])
        if op['kind']=='load': wanted_mem=[(op['width'],address,':',payload)]
        elif op['kind']=='store':
            stored=(fp[0] if name=='fsw' else value)&((1<<op['width'])-1)
            wanted_mem=[(op['width'],address,'=',stored)]
            expected[address-start:address-start+op['width']//8]=stored.to_bytes(op['width']//8,'little')
        else: wanted_mem=[]
        if actual_mem!=wanted_mem or after_fp!=wanted_fp: raise RuntimeError('actual memory width/address/value or FP lanes differ')
        if op['kind']!='fence' and actual['registers'].get('x10::')!=base: raise RuntimeError('actual base-register read differs')
        if op['kind']=='store' and name!='fsw' and actual['registers'].get('x11::')!=value: raise RuntimeError('store source read differs')
        if name=='fsw' and actual['registers'].get('f11::')!=fp: raise RuntimeError('FP store source read differs')
        if name=='flw' and actual['registers'].get('f20:=')!=wanted_fp: raise RuntimeError('scalar FP write lacks full eight-lane evidence')
        if op['kind']=='load' and name!='flw' and actual['registers'].get('x20:=')!=answer: raise RuntimeError('scalar load result write differs')
        if (name!='flw' and 'f20:=' in actual['registers']) or (op['kind']!='load' or name=='flw') and 'x20:=' in actual['registers']:
            raise RuntimeError('unexpected destination write')
        offset=syms['record_'+name]-start
        if pre[offset:offset+RECORD_SIZE]!=bytes([0xA5])*RECORD_SIZE: raise RuntimeError('missing record sentinel')
        for phase,off,words in [('before',0,before_fp),('after',32,after_fp),('before',64,before_src),('after',96,after_src)]:
            reg='f20' if off<64 else 'f11'
            if mem[syms[f'{phase}_{reg}_{name}']]!=[(32,start+offset+off+4*j,'=',w) for j,w in enumerate(words)]:
                raise RuntimeError('device FP snapshot memory stores differ')
            struct.pack_into('<8I',expected,offset+off,*words)
        integers=[]
        for phase in ('before','after'):
            for reg,raw_reg in [('a0','x10'),('a1','x11'),('s4','x20')]:
                e=event(f'{phase}_{reg}_{name}'); integers.append(e['registers'].get(raw_reg+'::'))
                j=len(integers)-1
                if mem[e['pc']]!=[(64,start+offset+128+8*j,'=',integers[-1])]: raise RuntimeError('scalar snapshot store differs')
        if tuple(integers)!=(base,value,XSEED,base,value,answer): raise RuntimeError('scalar before/after state differs')
        struct.pack_into('<6Q',expected,offset+128,*integers)
        controls=[]
        for category,off in [('mask',176),('fcsr',192),('mstatus',208)]:
            pair=[]
            for phase in ('before','after'):
                read=event(f'{phase}_{category}_{name}'); word=read['registers'].get('x5:='); pair.append(word)
                store=event(f'store_{phase}_{category}_{name}')
                if mem[store['pc']]!=[(64,start+offset+off+8*(phase=='after'),'=',word)]: raise RuntimeError('control snapshot store differs')
            if pair[0]!=pair[1] or (category!='mstatus' and pair!=[0,0]) or category=='mstatus' and (pair[0]&0x6008)!=0x6000:
                raise RuntimeError('mask/FP status changed or FP not initialized')
            struct.pack_into('<2Q',expected,offset+off,*pair); controls.extend(pair)
        target=syms['target_'+name]-start
        rows.append(dict(**site,hart=actual['hart'],cycle=actual['cycle'],trace_mnemonic=trace_name,
            address=hex(address),x10_before=hex(integers[0]),x11_before=hex(integers[1]),x20_before=hex(integers[2]),
            x10_after=hex(integers[3]),x11_after=hex(integers[4]),x20_after=hex(integers[5]),
            f20_before=report_lanes(before_fp),f20_after=report_lanes(after_fp),
            f11_before=report_lanes(before_src),f11_after=report_lanes(after_src),
            mask_before=hex(controls[0]),mask_after=hex(controls[1]),fcsr_before=hex(controls[2]),fcsr_after=hex(controls[3]),
            mstatus_before=hex(controls[4]),mstatus_after=hex(controls[5]),
            memory_events=[dict(width=w,address=hex(a),access=access,value=hex(v)) for w,a,access,v in actual_mem],
            target_before_bytes=pre[target:target+128].hex(' '),target_after_bytes=memory[target:target+128].hex(' '),**{'pass':True}))
    struct.pack_into('<I',expected,syms['completion']-start,DONE)
    if memory!=expected or not event('park')['disassembly'].startswith('wfi'): raise RuntimeError('whole guarded memory/completion mismatch')
    (out/'expected.bin').write_bytes(expected)
    (out/'registers.json').write_text(json.dumps(dict(source='actual H0 register read/write and memory events plus device-side snapshots',operations=rows),indent=2)+'\n')
    (out/'result.json').write_text(json.dumps(dict(case=case,operation_count=14,handler_count=14,trap_count=0,
        completion_word=hex(DONE),whole_monitor_matches=True,operations=rows,**{'pass':True}),indent=2)+'\n')
    for row in rows: print(f'  {row["name"]:<6} PC={row["pc"]} word={row["word"]} x20={row["x20_after"]} f20[0]={row["f20_after"]["raw_u32"][0]} PASS')
    print(f'Base memory {case}: 14 handlers; actual widths/addresses, all FP lanes, M0=0 and guarded memory PASS; {out}')


def main():
    cases=sys.argv[1:] or ['primary','exact']
    if any(case not in ('primary','exact') for case in cases): raise SystemExit('usage: python3 examples/base_memory.py [primary|exact ...]')
    env=runtime()
    for case in cases: execute(case,env)
    return 0


if __name__=='__main__':
    try: raise SystemExit(main())
    except (OSError,RuntimeError,KeyError,ValueError,subprocess.SubprocessError,struct.error) as exc:
        print(f'base_memory.py: {exc}',file=sys.stderr); raise SystemExit(1)
