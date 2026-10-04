#!/usr/bin/env python3
"""Run ET-SOC1 scalar FP operations and explicit microcode faults in SysEmu."""

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

OUT = ROOT / "out" / "scalar-fp"
DONE = 0x4B4F5445
SEED = 0xA5A5A5A5
XSEED = 0x5AA55AA55AA55AA5
MASK64 = (1 << 64) - 1
RECORD_SIZE = 192


def bits(value):
    return struct.unpack('<I', struct.pack('<f', value))[0]


def signed32(word):
    return (word | (0xFFFFFFFF00000000 if word & 0x80000000 else 0)) & MASK64


def operations(case):
    # Only lane 0 participates. Other source lanes are distinct and nonzero.
    a, b, c = (3.0, 2.0, 0.5) if case == 'primary' else (-1.5, 4.0, -0.25)
    rows = []

    def add(name, asm, result=None, kind='fp', inputs=None, scalar=0, flags=0, cause=0, mask=255):
        values = inputs or (bits(a), bits(b), bits(c))
        vectors = {reg: (word, *(bits(20.0 + n + j) for j in range(7)))
                   for n, (reg, word) in enumerate(zip(('f10', 'f11', 'f13'), values))}
        rows.append(dict(name=name, mnemonic=asm.split()[0], asm=asm, kind=kind,
                         expected=result, inputs=vectors, scalar=scalar, flags=flags,
                         cause=cause, mask=mask))

    for name, expression in [('fadd_s', a+b), ('fsub_s', a-b), ('fmul_s', a*b)]:
        add(name, f"{name.replace('_', '.')} f20, f10, f11, rne", bits(expression))
    for name, expression in [('fmadd_s', a*b+c), ('fmsub_s', a*b-c),
                             ('fnmadd_s', -(a*b+c)), ('fnmsub_s', -a*b+c)]:
        add(name, f"{name.replace('_', '.')} f20, f10, f11, f13, rne", bits(expression))
    add('fmin_s', 'fmin.s f20, f10, f11', bits(min(a,b)))
    add('fmax_s', 'fmax.s f20, f10, f11', bits(max(a,b)))
    rounding = -2.5 if case == 'primary' else 3.5
    unsigned = 3.5 if case == 'primary' else 2.5
    add('fcvt_w_s', 'fcvt.w.s s4, f10, rne', signed32(round(rounding) & 0xFFFFFFFF),
        'integer', (bits(rounding), bits(b), bits(c)), flags=1)
    add('fcvt_wu_s', 'fcvt.wu.s s4, f10, rne', signed32(round(unsigned)),
        'integer', (bits(unsigned), bits(b), bits(c)), flags=1)
    integer = -3 if case == 'primary' else -7
    uint = 0x80000000 if case == 'primary' else 0xFFFFFF00
    add('fcvt_s_w', 'fcvt.s.w f20, t0, rne', bits(float(integer)), scalar=integer & MASK64)
    add('fcvt_s_wu', 'fcvt.s.wu f20, t0, rne', bits(float(uint)), scalar=uint)
    sa = bits(1.5 if case == 'primary' else -2.5)
    sb = 0x80000000 if case == 'primary' else 0
    for name, word in [('fsgnj_s', (sa & 0x7FFFFFFF) | (sb & 0x80000000)),
                       ('fsgnjn_s', (sa & 0x7FFFFFFF) | ((~sb) & 0x80000000)),
                       ('fsgnjx_s', (sa & 0x7FFFFFFF) | ((sa ^ sb) & 0x80000000))]:
        add(name, f"{name.replace('_', '.')} f20, f10, f11", word, inputs=(sa,sb,bits(c)))
    raw = 0x80000001 if case == 'primary' else 0x3F800001
    add('fmv_w_x', 'fmv.w.x f20, t0', raw, scalar=0x1234567800000000 | raw)
    add('fmv_x_w', 'fmv.x.w s4, f10', signed32(raw), 'integer', (raw,bits(b),bits(c)))
    eq_b = b if case == 'primary' else a
    add('feq_s', 'feq.s s4, f10, f11', int(a==eq_b), 'integer', (bits(a),bits(eq_b),bits(c)))
    le_b = b if case == 'primary' else a
    add('fle_s', 'fle.s s4, f10, f11', int(a<=le_b), 'integer', (bits(a),bits(le_b),bits(c)))
    lt_a, lt_b = (-2.0,1.0) if case == 'primary' else (2.0,-1.0)
    add('flt_s', 'flt.s s4, f10, f11', int(lt_a<lt_b), 'integer', (bits(lt_a),bits(lt_b),bits(c)))
    classification, code = (0x80000000,8) if case == 'primary' else (0x7FC00001,512)
    add('fclass_s', 'fclass.s s4, f10', code, 'integer', (classification,bits(b),bits(c)))
    for name, asm in [('fdiv_s','fdiv.s f20, f10, f11, rne'),
                      ('fsqrt_s','fsqrt.s f20, f10, rne'),
                      ('fcvt_l_s','fcvt.l.s s4, f10, rne'),
                      ('fcvt_lu_s','fcvt.lu.s s4, f10, rne'),
                      ('fcvt_s_l','fcvt.s.l f20, t0, rne'),
                      ('fcvt_s_lu','fcvt.s.lu f20, t0, rne')]:
        add(name, asm, kind='fault', scalar=3 if case == 'primary' else 7, cause=30)
    add('mask_zero_fadd_s', 'fadd.s f20, f10, f11, rne', bits(a+b), mask=0)
    add('fcvt_w_s_rtz', 'fcvt.w.s s4, f10, rtz', signed32(int(rounding) & 0xFFFFFFFF),
        'integer', (bits(rounding),bits(b),bits(c)), flags=1)
    # A rounding-sensitive result observes FCSR NX rather than merely clearing it.
    add('fcvt_s_wu_inexact', 'fcvt.s.wu f20, t0, rne', bits(float(0xFFFFFFFF)), scalar=0xFFFFFFFF, flags=1)
    return rows


def label(name):
    return [f'.globl {name}', f'{name}:']


def kernel(ops):
    lines = ['# SPDX-License-Identifier: Apache-2.0',
             '# Startup provenance: Copyright (c) 2025 Ainekko, Co.; ET Platform boot.S.',
             '.option push', '.option norelax', '.option norvc', '.section .text.entry,"ax",@progbits',
             *label('_start'), '    csrwi satp, 0', '    csrwi mie, 0', '    csrwi mip, 0',
             '    csrwi medeleg, 0', '    csrwi mideleg, 0', '    csrr t0, mstatus',
             '    li t1, 0x6000', '    or t0, t0, t1', '    li t1, -9', '    and t0, t0, t1',
             '    csrw mstatus, t0', '    csrwi fcsr, 0', '    csrwi tensor_mask, 0',
             '    la sp, __stack_top', '    la t0, trap_handler', '    csrw mtvec, t0', '    li s1, 0']
    for op in ops:
        name = op['name']
        lines += [f'    la s0, record_{name}', '    la t0, seed', '    flq2 f20, 0(t0)']
        for reg in op['inputs']:
            lines += [f'    la t0, input_{name}_{reg}', *label(f'load_{name}_{reg}'), f'    flq2 {reg}, 0(t0)']
        lines += [f'    li s4, 0x{XSEED:x}', f'    li t0, {op["mask"]}', '    mova.m.x t0',
                  '    csrwi fcsr, 0', f'    li s3, {op["cause"]}',
                  *label(f'before_{name}'), '    fsq2 f20, 0(s0)',
                  *label(f'x_before_{name}'), '    sd s4, 64(s0)',
                  *label(f'mask_before_{name}'), '    mova.x.m t0', '    sd t0, 80(s0)',
                  *label(f'fcsr_before_{name}'), '    csrr t0, fcsr', '    sd t0, 96(s0)',
                  f'    li t0, 0x{op["scalar"]:x}', *label(f'op_{name}'), f'    {op["asm"]}',
                  *label(f'after_{name}'), '    fsq2 f20, 32(s0)',
                  *label(f'x_after_{name}'), '    sd s4, 72(s0)',
                  *label(f'mask_after_{name}'), '    mova.x.m t0', '    sd t0, 88(s0)',
                  *label(f'fcsr_after_{name}'), '    csrr t0, fcsr', '    sd t0, 104(s0)']
    lines += ['    la t0, trap_count', '    sd s1, 0(t0)', f'    li t0, 0x{DONE:x}',
              '    la t1, completion', '    sw t0, 0(t1)', *label('park'), '    wfi', '    j park',
              '.balign 4096', *label('trap_handler'), '    csrr t0, mcause', '    bne t0, s3, unexpected',
              '    li t1, 30', '    bne t0, t1, unexpected']
    for csr, offset in [('mcause',112), ('mepc',120), ('mtval',128), ('mstatus',136)]:
        lines += [*label(f'capture_{csr}'), f'    csrr t0, {csr}', f'    sd t0, {offset}(s0)']
    lines += ['    addi s1, s1, 1', '    csrr t0, mepc', '    addi t0, t0, 4', '    csrw mepc, t0',
              '    mret', 'unexpected:', '    la t1, unexpected_trap', '    csrr t0, mcause', '    sd t0, 0(t1)',
              '    csrr t0, mepc', '    sd t0, 8(t1)', '    csrr t0, mtval', '    sd t0, 16(t1)', '    j park',
              '.option pop', '.section .data,"aw",@progbits', '.balign 32', *label('__monitor_start')]
    for op in ops:
        lines += [*label(f'record_{op["name"]}'), f'    .fill {RECORD_SIZE},1,0xa5']
    lines += [*label('trap_count'), '    .dword 0', *label('completion'), '    .word 0',
              '.balign 8', *label('unexpected_trap'), '    .dword 0,0,0', '.balign 32', 'seed:', '    .fill 32,1,0xa5']
    for op in ops:
        for reg, words in op['inputs'].items():
            lines += ['.balign 32', *label(f'input_{op["name"]}_{reg}'),
                      '    .word ' + ', '.join(f'0x{word:08x}' for word in words)]
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
    stage = f'/tmp/etsoc1-scalar-fp-{uuid.uuid4().hex[:10]}'
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
            sites.append({k:op[k] for k in ('name','mnemonic','kind','cause','mask')} | dict(pc=hex(pc),
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


def validate(out, ops, sites, syms, start, size):
    trace = (out/'trace.log').read_text()
    events, regs = trace_data(trace)
    if any(e['hart']!='H0 S0:N0:C0:T0' for e in events):
        raise RuntimeError('unexpected active hart')

    def event(name):
        found = [e for e in events if e['pc']==syms[name]]
        if len(found)!=1:
            raise RuntimeError(f'missing/repeated actual instruction at {name}')
        return found[0]

    # State is reconstructed only from complete actual register-write events.
    state, states = {}, {}
    for e in events:
        if any(e['pc']==int(s['pc'],16) for s in sites):
            states[e['pc']] = dict(state)
        for key,val in e['registers'].items():
            if key.endswith(':='):
                state[key[:-2]]=val
    pre, memory = (out/'prestart.bin').read_bytes(), (out/'output.bin').read_bytes()
    if len(pre)!=size or len(memory)!=size:
        raise RuntimeError('incomplete monitor memory dump')
    elf = (out/'kernel.elf').read_bytes()
    phoff = struct.unpack_from('<Q',elf,32)[0]
    phsize, phcount = struct.unpack_from('<HH',elf,54)
    segments = [struct.unpack_from('<II6Q',elf,phoff+i*phsize) for i in range(phcount)]
    mappings = [p[2]+start-p[3] for p in segments if p[0]==1 and p[3]<=start and start+size<=p[3]+p[5]]
    if len(mappings)!=1 or pre!=elf[mappings[0]:mappings[0]+size]:
        raise RuntimeError('pre-execution monitor dump differs from linked input/sentinel bytes')
    expected, rows = bytearray(pre), []
    trap_logs = re.findall(r'\[(H\d+ S\d+:N\d+:C\d+:T\d+)\].*Trapping to M-mode with cause 0x([0-9a-f]+) and tval 0x([0-9a-f]+)',trace)
    captures = {csr:[e for e in events if e['pc']==syms[f'capture_{csr}']] for csr in ('mcause','mepc','mtval','mstatus')}
    fault_index = 0
    for op,site in zip(ops,sites):
        name,pc = op['name'],int(site['pc'],16)
        actual, before_state = event(f'op_{name}'), states[pc]
        if actual['word']!=int(site['word'],16) or not actual['disassembly'].startswith(op['mnemonic']):
            raise RuntimeError(f'execution and assembled instruction differ: {name}')
        offset = syms[f'record_{name}']-start
        if pre[offset:offset+RECORD_SIZE] != bytes([0xA5])*RECORD_SIZE:
            raise RuntimeError('missing pre-execution record sentinel')
        for reg,words in op['inputs'].items():
            load = event(f'load_{name}_{reg}')
            if load['registers'].get(reg+':=')!=words or before_state.get(reg)!=words:
                raise RuntimeError(f'actual input register writes differ: {name}/{reg}')
        before, after = (regs[(syms[f'{phase}_{name}'],'f20',':')] for phase in ('before','after'))
        scalar_before, scalar_after, mask_before, mask_after, fcsr_before, fcsr_after = struct.unpack_from('<6Q',memory,offset+64)
        wanted_fp = (op['expected'],0,0,0,0,0,0,0) if op['kind']=='fp' else (SEED,)*8
        wanted_x = op['expected'] if op['kind']=='integer' else XSEED
        if (before!=(SEED,)*8 or before_state.get('f20')!=before or before_state.get('x20')!=XSEED or
                after!=wanted_fp or (scalar_before,scalar_after)!=(XSEED,wanted_x) or
                (mask_before,mask_after)!=(op['mask'],op['mask']) or (fcsr_before,fcsr_after)!=(0,op['flags'])):
            raise RuntimeError(f'actual FP/scalar/mask/FCSR state mismatch: {name}')
        for phase,word in (('before',scalar_before),('after',scalar_after)):
            if event(f'x_{phase}_{name}')['registers'].get('x20::')!=word:
                raise RuntimeError('integer snapshot differs from register read trace')
        for category,words in [('mask',(mask_before,mask_after)),('fcsr',(fcsr_before,fcsr_after))]:
            for phase,word in zip(('before','after'),words):
                if event(f'{category}_{phase}_{name}')['registers'].get('x5:=')!=word:
                    raise RuntimeError('control-state snapshot lacks actual device read evidence')
        if op['kind']=='fp' and actual['registers'].get('f20:=')!=after:
            raise RuntimeError('scalar FP write trace differs from complete register snapshot')
        if op['kind']=='integer' and actual['registers'].get('x20:=')!=scalar_after:
            raise RuntimeError('scalar integer write trace differs from device snapshot')
        wanted = bytearray([0xA5]*RECORD_SIZE)
        struct.pack_into('<8I',wanted,0,*before)
        struct.pack_into('<8I',wanted,32,*after)
        struct.pack_into('<6Q',wanted,64,scalar_before,scalar_after,mask_before,mask_after,fcsr_before,fcsr_after)
        fault = None
        if op['cause']:
            cause,epc,tval,status = struct.unpack_from('<4Q',memory,offset+112)
            if (cause,epc,tval)!=(30,pc,int(site['word'],16)) or status>>11&3!=3:
                raise RuntimeError('wrong actual trap cause/PC/word/MPP')
            if fault_index>=len(trap_logs) or trap_logs[fault_index] != ('H0 S0:N0:C0:T0',f'{cause:x}',f'{tval:x}'):
                raise RuntimeError('trap snapshot differs from raw trap event')
            for csr,word in zip(captures,(cause,epc,tval,status)):
                if fault_index>=len(captures[csr]) or captures[csr][fault_index]['registers'].get('x5:=')!=word:
                    raise RuntimeError('fault CSR snapshot differs from actual CSR read trace')
            if 'f20:=' in actual['registers'] or 'x20:=' in actual['registers']:
                raise RuntimeError('faulting instruction changed its destination')
            struct.pack_into('<4Q',wanted,112,cause,epc,tval,status)
            fault = dict(mcause=cause,mepc=hex(epc),mtval=hex(tval),mstatus=hex(status))
            fault_index += 1
        expected[offset:offset+RECORD_SIZE]=wanted
        rows.append(dict(**site,hart=actual['hart'],cycle=actual['cycle'],inputs_before={reg:report_lanes(before_state[reg]) for reg in op['inputs']},
            f20_before=report_lanes(before),f20_after=report_lanes(after),x20_before=hex(scalar_before),x20_after=hex(scalar_after),
            mask_before=hex(mask_before),mask_after=hex(mask_after),fcsr_before=hex(fcsr_before),fcsr_after=hex(fcsr_after),
            fault=fault,output_memory_bytes=memory[offset:offset+RECORD_SIZE].hex(' '),**{'pass':True}))
    if fault_index!=6 or len(trap_logs)!=6 or any(len(es)!=6 for es in captures.values()):
        raise RuntimeError('missing/repeated/unexpected traps')
    struct.pack_into('<Q',expected,syms['trap_count']-start,6)
    struct.pack_into('<I',expected,syms['completion']-start,DONE)
    if memory!=expected or not event('park')['disassembly'].startswith('wfi'):
        raise RuntimeError('whole guarded memory, completion or termination differs')
    (out/'expected.bin').write_bytes(expected)
    (out/'registers.json').write_text(json.dumps(dict(source='actual H0 register read/write trace and device-side snapshots; source state reconstructed from complete register writes',operations=rows),indent=2,allow_nan=False)+'\n')
    (out/'result.json').write_text(json.dumps(dict(case='primary' if out==OUT else out.name,operation_count=len(ops),
        nontrapping_handler_count=22,trap_stub_count=6,trap_count=6,completion_word=hex(DONE),whole_monitor_matches=True,
        operations=rows,**{'pass':True}),indent=2,allow_nan=False)+'\n')
    for row in rows:
        print(f'  {row["name"]:<22} PC={row["pc"]} word={row["word"]} FCSR={row["fcsr_before"]}->{row["fcsr_after"]} '
              f'{"cause 30, unchanged destinations" if row["fault"] else "lane0="+row["f20_after"]["raw_u32"][0]+", x20="+row["x20_after"]} PASS')
    case = 'primary' if out==OUT else out.name
    print(f'Scalar FP {case}: {len(ops)} sites, 22 implemented handlers + 6 cause-30 stubs; all eight register lanes and guarded memory verified PASS; {out}')


def main():
    cases = sys.argv[1:] or ['primary','exact']
    if any(case not in ('primary','exact') for case in cases):
        raise SystemExit('usage: python3 examples/scalar_fp.py [primary|exact ...]')
    env = runtime()
    for case in cases:
        execute(case,env)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError,RuntimeError,KeyError,ValueError,subprocess.SubprocessError,struct.error) as exc:
        print(f'scalar_fp.py: {exc}',file=sys.stderr)
        raise SystemExit(1)
