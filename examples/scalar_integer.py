#!/usr/bin/env python3
"""Run all ET-SOC1 scalar integer arithmetic handlers in upstream SysEmu."""

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

OUT = ROOT / 'out/scalar-integer'
DONE = 0x4B4F5445
XSEED = 0x5AA55AA55AA55AA5
MASK64 = (1 << 64) - 1
RECORD_SIZE = 128
REGISTER_OPS = ['add','sub','and','or','xor','sll','srl','sra','slt','sltu',
                'mul','mulh','mulhsu','mulhu','div','divu','rem','remu',
                'addw','subw','sllw','srlw','sraw','mulw','divw','divuw','remw','remuw']
IMMEDIATE_OPS = ['addi','andi','ori','xori','slti','sltiu','slli','srli','srai',
                 'addiw','slliw','srliw','sraiw']


def signed(value, width):
    value &= (1 << width) - 1
    return value - (1 << width) if value >> (width - 1) else value


def reference(mnemonic, a, b, immediate, pc):
    """Host validation only; all arithmetic under test runs in the ELF."""
    word = mnemonic.endswith('w')
    width = 32 if word else 64
    mask = (1 << width) - 1
    name = mnemonic[:-1] if word else mnemonic
    a &= mask
    operand = immediate if name in IMMEDIATE_OPS or name in ('addi','slli','srli','srai') else b & mask
    if name in ('lui','auipc'):
        result = signed(immediate << 12,32) + (pc if name=='auipc' else 0)
    elif name in ('add','addi'): result = a + operand
    elif name=='sub': result = a - operand
    elif name in ('and','andi'): result = a & operand
    elif name in ('or','ori'): result = a | operand
    elif name in ('xor','xori'): result = a ^ operand
    elif name in ('sll','slli'): result = a << (operand & (width-1))
    elif name in ('srl','srli'): result = a >> (operand & (width-1))
    elif name in ('sra','srai'): result = signed(a,width) >> (operand & (width-1))
    elif name in ('slt','slti'): result = int(signed(a,width) < (operand if name=='slti' else signed(operand,width)))
    elif name in ('sltu','sltiu'): result = int(a < (operand & mask))
    elif name=='mul': result = a * operand
    elif name=='mulh': result = (signed(a,64)*signed(operand,64)) >> 64
    elif name=='mulhsu': result = (signed(a,64)*operand) >> 64
    elif name=='mulhu': result = (a*operand) >> 64
    elif name in ('div','divu','rem','remu'):
        aa,bb = (signed(a,width),signed(operand,width)) if name in ('div','rem') else (a,operand)
        if bb==0: result = -1 if name.startswith('div') else aa
        else:
            quotient = abs(aa)//abs(bb)
            if (aa<0)!=(bb<0): quotient = -quotient
            result = quotient if name.startswith('div') else aa-quotient*bb
    else: raise ValueError(mnemonic)
    return (signed(result,32) if word else result) & MASK64


def operations(case):
    a,b = (0x800000017FFFFFFB,0x7FFFFFFFFFFFFFED) if case=='primary' else (0x7FFFFFFE80000005,0x8000000000000003)
    immediate = -13 if case=='primary' else 23
    rows=[]
    def add(name,mnemonic,aa=a,bb=b,imm=0,kind='register',variant='ordinary'):
        asm = f'{mnemonic} s4, a0, a1' if kind=='register' else f'{mnemonic} s4, a0, {imm}' if kind=='immediate' else f'{mnemonic} s4, 0x{imm:x}'
        rows.append(dict(name=name,mnemonic=mnemonic,asm=asm,a=aa&MASK64,b=bb&MASK64,
                         immediate=imm,kind=kind,variant=variant))
    for mnemonic in REGISTER_OPS:
        if mnemonic in ('div','rem'):
            aa,bb = (-17,5) if case=='primary' else (17,-5)
            add(mnemonic,mnemonic,aa,bb)
        else: add(mnemonic,mnemonic)
    for mnemonic in IMMEDIATE_OPS:
        shift = (31 if mnemonic.endswith('w') else 63) if case=='primary' else 1
        add(mnemonic,mnemonic,imm=shift if mnemonic.startswith(('sll','srl','sra')) else immediate,kind='immediate')
    for mnemonic in ('lui','auipc'):
        add(mnemonic,mnemonic,imm=0x80001 if case=='primary' else 0x7FFFE,kind='upper')
    for mnemonic in ('div','divu','divw','divuw','rem','remu','remw','remuw'):
        add(mnemonic+'_zero',mnemonic,bb=0,variant='divide by zero')
    for mnemonic in ('div','rem','divw','remw'):
        minimum = 0x1234567880000000 if mnemonic.endswith('w') else 0x8000000000000000
        add(mnemonic+'_overflow',mnemonic,aa=minimum,bb=-1,variant='minimum signed value divided by -1')
    for mnemonic in ('sll','srl','sra','sllw','srlw','sraw'):
        add(mnemonic+'_overshift',mnemonic,bb=65 if case=='primary' else 129,variant='register shift count masks high bits')
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
            *label('load_b_'+name),'    ld a1, 8(t0)',f'    li s4, 0x{XSEED:x}',
            *label('before_a_'+name),'    sd a0, 0(s0)',*label('before_b_'+name),'    sd a1, 8(s0)',
            *label('before_x_'+name),'    sd s4, 16(s0)',*label('op_'+name),f'    {op["asm"]}',
            *label('after_a_'+name),'    sd a0, 24(s0)',*label('after_b_'+name),'    sd a1, 32(s0)',
            *label('after_x_'+name),'    sd s4, 40(s0)']
    lines += [f'    li t0, 0x{DONE:x}','    la t1, completion','    sw t0, 0(t1)',*label('park'),'    wfi','    j park',
        '.balign 4096',*label('trap_handler'),'    la t1, unexpected_trap',
        '    csrr t0, mcause','    sd t0, 0(t1)','    csrr t0, mepc','    sd t0, 8(t1)',
        '    csrr t0, mtval','    sd t0, 16(t1)','    j park','.option pop',
        '.section .data,"aw",@progbits','.balign 32',*label('__monitor_start')]
    for op in ops: lines += [*label('record_'+op['name']),f'    .fill {RECORD_SIZE},1,0xa5']
    lines += [*label('completion'),'    .word 0','.balign 8',*label('unexpected_trap'),'    .dword 0,0,0']
    for op in ops: lines += ['.balign 8',*label('input_'+op['name']),f'    .dword 0x{op["a"]:x},0x{op["b"]:x}']
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
    stage = f'/tmp/etsoc1-scalar-integer-{uuid.uuid4().hex[:10]}'
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
            sites.append({k:op[k] for k in ('name','mnemonic','kind','variant')} | dict(pc=hex(pc),
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
    if re.search(r'\b(?:trap|exception)\b',trace,re.I): raise RuntimeError('unexpected integer execution trap')
    events,regs=trace_data(trace)
    if any(e['hart']!='H0 S0:N0:C0:T0' for e in events): raise RuntimeError('unexpected executing hart')
    def event(name):
        matches=[e for e in events if e['pc']==syms[name]]
        if len(matches)!=1: raise RuntimeError(f'missing/repeated actual integer site {name}')
        return matches[0]
    pre,memory=(out/'prestart.bin').read_bytes(),(out/'output.bin').read_bytes()
    if len(pre)!=size or len(memory)!=size: raise RuntimeError('incomplete integer monitor dump')
    elf=(out/'kernel.elf').read_bytes()
    phoff=struct.unpack_from('<Q',elf,32)[0]; phsize,phcount=struct.unpack_from('<HH',elf,54)
    segments=[struct.unpack_from('<II6Q',elf,phoff+i*phsize) for i in range(phcount)]
    mapping=[p[2]+start-p[3] for p in segments if p[0]==1 and p[3]<=start and start+size<=p[3]+p[5]]
    if len(mapping)!=1 or pre!=elf[mapping[0]:mapping[0]+size]: raise RuntimeError('actual integer inputs differ from ELF data')
    expected,rows=bytearray(pre),[]
    for op,site in zip(ops,sites):
        name,pc=op['name'],int(site['pc'],16)
        actual=event('op_'+name)
        if actual['word']!=int(site['word'],16) or not actual['disassembly'].startswith(op['mnemonic']):
            raise RuntimeError('integer executed instruction differs from assembled word')
        inputs=struct.unpack_from('<2Q',pre,syms['input_'+name]-start)
        if inputs!=(op['a'],op['b']): raise RuntimeError('linked integer operands differ from selected case')
        for reg,operand,suffix in [('x10',op['a'],'a'),('x11',op['b'],'b')]:
            if event('load_'+suffix+'_'+name)['registers'].get(reg+':=')!=operand:
                raise RuntimeError('integer operand lacks actual device load evidence')
        recorded=[]
        for phase in ('before','after'):
            for suffix,reg in [('a','x10'),('b','x11'),('x','x20')]:
                value=event(phase+'_'+suffix+'_'+name)['registers'].get(reg+'::')
                if value is None: raise RuntimeError('missing actual integer snapshot register read')
                recorded.append(value)
        result=reference(op['mnemonic'],*inputs,op['immediate'],pc)
        wanted=(op['a'],op['b'],XSEED,op['a'],op['b'],result)
        if tuple(recorded)!=wanted or actual['registers'].get('x20:=')!=result:
            raise RuntimeError(f'integer write/snapshot/reference mismatch at {name}: {recorded}')
        if op['kind']!='upper' and actual['registers'].get('x10::')!=op['a']:
            raise RuntimeError('integer source A read mismatch')
        if op['kind']=='register' and actual['registers'].get('x11::')!=op['b']:
            raise RuntimeError('integer source B read mismatch')
        offset=syms['record_'+name]-start
        if pre[offset:offset+RECORD_SIZE]!=bytes([0xA5])*RECORD_SIZE: raise RuntimeError('missing integer record sentinel')
        expected[offset:offset+48]=struct.pack('<6Q',*wanted)
        rows.append(dict(**site,hart=actual['hart'],cycle=actual['cycle'],x10_before=hex(recorded[0]),x11_before=hex(recorded[1]),
            x20_before=hex(recorded[2]),x10_after=hex(recorded[3]),x11_after=hex(recorded[4]),x20_after=hex(recorded[5]),
            expected=hex(result),output_memory_bytes=memory[offset:offset+RECORD_SIZE].hex(' '),**{'pass':True}))
    struct.pack_into('<I',expected,syms['completion']-start,DONE)
    if memory!=expected or not event('park')['disassembly'].startswith('wfi'):
        raise RuntimeError('integer completion or whole guarded monitor mismatch')
    (out/'expected.bin').write_bytes(expected)
    (out/'registers.json').write_text(json.dumps(dict(source='actual H0 register read/write trace and device-side snapshots',operations=rows),indent=2)+'\n')
    case='primary' if out==OUT else out.name
    (out/'result.json').write_text(json.dumps(dict(case=case,operation_count=len(sites),handler_count=43,trap_count=0,
        completion_word=hex(DONE),whole_monitor_matches=True,operations=rows,**{'pass':True}),indent=2)+'\n')
    for row in rows: print(f'  {row["name"]:<22} PC={row["pc"]} word={row["word"]} x20={row["x20_after"]} PASS')
    print(f'Scalar integer {case}: {len(sites)} sites, 43 handlers; real sources/results and whole guarded memory PASS; {out}')


def main():
    cases=sys.argv[1:] or ['primary','exact']
    if any(case not in ('primary','exact') for case in cases): raise SystemExit('usage: python3 examples/scalar_integer.py [primary|exact ...]')
    env=runtime()
    for case in cases: execute(case,env)
    return 0


if __name__=='__main__':
    try: raise SystemExit(main())
    except (OSError,RuntimeError,KeyError,ValueError,subprocess.SubprocessError,struct.error) as exc:
        print(f'scalar_integer.py: {exc}',file=sys.stderr); raise SystemExit(1)
