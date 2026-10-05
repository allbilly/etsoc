# ADD, MUL and GEMM

[Repository overview](../README.md) · [Example catalog](examples.md)

The device assembly, startup, register capture and binary-patch experiment
are explained here. See [setup](setup.md) for tools and pinned revisions.

- [Device programs and startup](#what-the-programs-do)
- [Register and memory capture](#captured-evidence)
- [8x8x8 GEMM](#8x8x8-gemm)
- [Measured ADD-to-MUL change](#measured-add-to-mul-change)

## What the programs do

ADD/MUL/SUB are self-contained standard-library Python scripts. GEMM and the
operation-family suites reuse process and trace helpers from earlier examples, while
keeping their device assembly and result checks in the example file. Each writes
and cross-assembles a visible `kernel.S` and `link.ld`, inspects the resulting
ELF with the ET `nm`, `readelf`, `objdump`, and `objcopy`, and runs it with the
upstream standalone `sys_emu -elf_load` interface. Arithmetic and operation-family runs enable
only minion 0 / shire 0 / thread 0 (`-minions 0x1 -shires 0x1 -single_thread`)
and disable the service processor. The message-port blocking cases enable
minions 0 and 1 with one hardware thread each (`-minions 0x3 -single_thread`):
H0 receives and H2 sends. They use the same standalone ELF interface.
Peer synchronization uses that configuration plus two cases with both threads
of minion 0 enabled: H1 receives and H0 sends.

The device operation is visibly written in each file:

```asm
    flw.ps  f10, 0(t1)       # eight FP32 lanes from A
    flw.ps  f11, 0(t1)       # eight FP32 lanes from B
operation:
    fadd.ps f12, f10, f11, rne  # mul.py changes this one instruction
    fsw.ps  f12, 0(t1)       # eight FP32 lanes to C
```

The actual source uses separate address loads between these instructions. The
active mask M0 is set to `0xff`, so all eight lanes participate. The two
datasets are:

| Case | A | B |
| --- | --- | --- |
| primary | `[1,2,3,4,5,6,7,8]` | `[10,20,30,40,50,60,70,80]` |
| exact | `[1.5,-2,0.5,4,-8,16,0,32]` | `[2,0.25,-8,0.5,-0.5,2,-3,0.125]` |

The exact case uses binary-representable values and checks results that do not
depend on decimal rounding. Each run seeds f12 with recognizable negative
values and initializes C to `0xA5A5A5A5` in every lane. A trap handler writes
`mcause` and a trap marker into memory. Successful termination stores
`0x4b4f5445` (the bytes `ETOK`) and executes `wfi`; neither a cycle-limit exit
nor a missing/unchanged result buffer counts as success. A 10,000-cycle SysEmu
watchdog and a 90-second simulator timeout run under a 120-second host
subprocess timeout.

Startup is kept small and visible. It disables address translation (`satp=0`),
sets `mstatus.FS=Dirty` so floating-point instructions are enabled, clears
`fcsr` and `mip`, clears the unused tensor mask, sets the stack pointer from
`__stack_top`, installs an aligned trap handler, and initializes M0. The
simulator's current direct-mode `mtvec` implementation masks its low 12 address
bits, so the trap handler is aligned to a 4 KiB boundary. The 16 KiB stack,
entry point, data labels, operation PC, and trap PC all come from the linker
layout / ELF symbols. The code does not depend on reset state or an opaque
upstream boot blob; it adapts only the needed startup conventions from
`sw-sysemu/examples/common/boot.S` (Apache-2.0).

## Captured evidence

The raw `-l` SysEmu trace captures all eight f10/f11 lanes read by the packed
operation and f12 as written by it. Device-side `fsw.ps` snapshots capture
the post-operation f10/f11/f12 values into memory and are checked against the
trace. f12-before comes from the traced `flw.ps` at `seed_load`. Explicit CSR
reads record `mstatus` and `fcsr`; the operation trace and a later snapshot store
record M0 before and after the arithmetic. The executed word must match the ELF,
and the destination write, snapshot, and C bytes must agree. This ties
the normalized `registers.json` report to a hart and PC without relying on
unavailable GDB names for ET mask state. `prestart.bin` proves the C sentinel
was loaded before execution; `output.bin` is the actual SysEmu memory dump
after execution. Raw trace, machine-readable register/result files, and
commands remain alongside the ELF.

`sub.py` uses the same two inputs, destination seed, ELF layout, and startup,
changing the operation to `fsub.ps`. Together, ADD/MUL/SUB match the operations
explicitly accepted by the pinned `ggml-et` `el_map_f32.c` elementwise kernel.
This is a specific reference-kernel subset, not the full SysEmu instruction
set.

## 8x8x8 GEMM

`gemm.py` stores A and B as ordinary row-major 8x8 matrices. For each output
row it clears f12, loads each scalar A[r,k] with device `fbc.ps f10, offset(t1)`,
loads B[k,0:8] with `flw.ps f11, offset(t2)`,
then executes eight `fmadd.ps f12, f10, f11, f12, rne` instructions: each
instruction adds A[r,k] * B[k,0:8] to the eight output columns. That produces
one full C row per eight packed FMAs, 64 FMAs total. All 64 scalar broadcasts
and multiply-accumulate operations execute as ET instructions in SysEmu.
The Python matrix multiply is used only as an independent result check.

The primary matrices contain small integers. The `exact` matrices use dyadic
fractions, so every product and accumulated result is exactly representable as
FP32. The generated `operations.json` lists each FMA PC, byte sequence, word,
and decoded instruction; `operations.bin` contains all 64 instruction words in
execution order. `broadcasts.json` and `broadcasts.bin` record the 64 `fbc.ps`
instructions, including each actual scalar memory-read address and word.
The simulator trace proves that all broadcasts and FMAs ran on H0 with
M0=`0xff`. Every FMA's f10/f11/f12 inputs and f12 result are checked against
the independent accumulating reference. The final FMA state is also checked
against device-side snapshots. Both input matrices are checked in memory
before and after execution. `result.json` records all 64 actual
and expected output values. The last operation is at PC `0x800000139c`; SysEmu
and GNU objdump decode bytes `5b 06 b5 60` (word `0x60b5065b`) as
`fmadd.ps f12,f10,f11,f12,rne`.

The linker places `.text` at `0x8000001000`, `.data` at `0x8000100000`, and a
16 KiB `NOBITS` stack at `0x8000200000`. Because the trap handler is page
aligned, `.text` includes an alignment gap and the handler; `.text` is the
only executable section in these arithmetic ELFs. The [M/U message-port diagnostic](communication.md#message-port-permissions-in-real-u-mode)
uses two executable sections. In ADD/MUL/SUB, C begins at
`0x8000100060` and the 160-byte monitored range also contains completion/trap
words and three register snapshots. GEMM has a larger monitor region sized
from its linked matrix output and snapshots. The scripts derive addresses
from ELF section headers and symbols rather than duplicating them in Python.

## Measured ADD-to-MUL change

Both independently assembled operation words use the current SysEmu custom-3
decoder and GNU objdump decoder:

| Instruction | Word | Bytes in memory order | decoded funct7 |
| --- | --- | --- | --- |
| `fadd.ps f12,f10,f11,rne` | `0x00b5067b` | `7b 06 b5 00` | `0x00` |
| `fsub.ps f12,f10,f11,rne` | `0x08b5067b` | `7b 06 b5 08` | `0x04` |
| `fmul.ps f12,f10,f11,rne` | `0x10b5067b` | `7b 06 b5 10` | `0x08` |

The ADD-to-MUL XOR is `0x10000000`, changing bit 28 (bit positions count from LSB 0).
The pinned SysEmu decoder in `processor.cpp::dec_custom3` maps `funct7=0x00`
to `insn_fadd_ps` and `funct7=0x08` to `insn_fmul_ps`; opcode, register
fields, and `funct3` are equal. The measured `.text` sections differ only in
the four-byte operation. The whole ELF files are both 14,376 bytes and differ
in one byte at file offset `0x106b` (the high byte of that instruction).
The comparison reports whole-ELF differences separately, allowing metadata
differences while still requiring identical executable bytes outside the operation.

`tools/compare.py` also copies the ADD ELF and patches only the instruction
at file offset `0x1068`. The virtual PC is `0x8000001068`; ELF mapping gives
file offset `0x1000 + (0x8000001068 - 0x8000001000) = 0x1068`. It writes the
independently assembled MUL bytes, checks every other byte is identical, runs
the patched copy in SysEmu, and checks the memory output and register
snapshots against the normal MUL run.
