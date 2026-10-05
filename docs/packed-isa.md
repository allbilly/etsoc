# Packed, atomic and graphics instructions

[Repository overview](../README.md) · [Example catalog](examples.md)

These examples run real ET extensions, inspect all eight lanes and preserve
raw execution evidence. Explicit upstream stubs are verified as faults.

- [Packed integer and mask operations](#packed-integer-and-mask-operations)
- [Packed floating point](#packed-floating-point-coverage)
- [Packed memory and atomics](#packed-memory-and-atomics)
- [Scalar memory and atomics](#scalar-memory-and-atomics)
- [Graphics extensions](#graphics-extensions)
- [Unimplemented handlers and fault delivery](#unimplemented-handlers-and-fault-delivery)

## Packed integer and mask operations

`packed_int.py` runs 41 labeled sites in each deterministic case: 30 packed
integer vector operations and 11 mask-operation sites. It checks actual raw
lane words, all eight mask registers and mask counts against simulator traces
and device-side memory snapshots. The second case uses distinct inputs.
Generated instruction encodings and execution evidence are in `out/packed-int/`.


## Packed floating-point coverage

`packed_fp.py` assembles and runs 38 labeled operation sites for each case.
It covers every non-trapping handler in the pinned `packed_float.cpp` and
`packed_trans.cpp` implementations: packed arithmetic/FMA variants, scalar
broadcast and immediate construction, classification, conditional moves,
F16 and integer conversions, value and mask comparisons, fractional part,
min/max, lane extraction, rounding, sign injection, swizzle, reciprocal,
base-2 logarithm, and base-2 exponential. It excludes the simulator handlers
that explicitly trap for packed divide, square root, reciprocal square root,
and sine.

The kernel seeds f20 and every output slot with `0xa5a5a5a5`. A partial-mask
`fadd.ps` checks preservation of inactive destination lanes. The run also
records an observed distinction in this SysEmu revision: `fcmovm.ps` writes
all eight result lanes even when M0 is partial, while the following packed
store obeys M0, so the example restores M0 before storing the full result.
For `feqm.ps`, `flem.ps`, and `fltm.ps`, it reads back the written m4 bits
through `mova.x.m`; that transfer includes M0 in the low byte as well.
`fmvs.x.ps` and `fmvz.x.ps` use lane 7 with `0x80000001` to show sign
extension versus zero extension. The two cases use separate inputs; exp2,
log2, and reciprocal use powers of two to make each expected FP32 result
exact.

In the pinned SysEmu implementation, `fnmadd.ps` dispatches to
`f32_subMulAdd` and `fnmsub.ps` to `f32_subMulSub`. The measured results are
`-(a*b+c)` and `-(a*b)+c`, respectively. Both outcomes are checked from actual
register writes against the source's sign handling. Registers that an
instruction does not expose in the trace are recorded as uncaptured (`null`).
Decoded nonfinite FP values use the strings `nan`, `+inf`, and `-inf` so the
reports remain valid JSON; the raw 32-bit words preserve sign and NaN payloads.

## Packed memory and atomics

`packed_memory.py` covers all 17 handlers in `packed_loadstore.cpp` and all
16 in `coherent_packed_loadstore.cpp`. It checks vector load/store, scalar
broadcast, signed byte/halfword gathers, word gathers, indexed scatters, and
the packed scalar index fields used by the `fg32*`/`fsc32*` instructions.
The latter cases use a nonzero offset within a 32-byte block and verify
wrapping inside that block. Indexed cases include signed negative offsets.
Each target has 128 bytes of recognizable initial data; checking the entire
region detects writes to inactive lanes and unintended surrounding bytes.
Every traced access address, width, and direction is checked.

The primary memory case uses M0=`0xff`; the second uses M0=`0x55` where
defined. `flq2` and `fsq2` load/store all eight lanes even with a partial mask.
Coherent vector stores `fswg.ps` and `fswl.ps` use a full mask in both cases,
because the pinned implementation declares partial masks undefined on A0.
Both kernels clear the gather/scatter progress CSR (`0x840`) explicitly.

`packed_atomic.py` covers all 22 handlers in `packed_atomic.cpp`: local/global
add, bitwise logic, swap, signed/unsigned integer min/max, and FP32 min/max.
For each lane it verifies the old value returned in f20 and the new memory
value, with guards around each target. It also checks the actual read/write
events against the reference addresses and values. The second case changes
the operands and offsets and uses a partial mask; inactive lanes retain their
original f20 operands and leave memory untouched. The `alias` case enables
all lanes at one shared address and checks the model's per-lane update sequence.
FP atomic cases include positive and negative zero.

These are functional checks on one minion/thread. Local/global variants are
executed, but cross-minion contention, coherence ordering, and hardware timing
have not been tested. Both suites use full-lane `fsq2` snapshots to preserve
every returned lane, including inactive lanes, and keep raw trace events next
to the memory dumps and normalized reports.

## Scalar memory and atomics

`scalar_memory.py` covers all 40 local/global word/doubleword atomic handlers
in `arith_atomic.cpp`, the four coherent byte/halfword stores (`sbg`, `sbl`,
`shg`, `shl`), and scalar `packb`. Each atomic returns the old memory value in
x20. Word variants sign-extend that value to 64 bits and operate on only the
low 32 bits of the supplied operand. The two cases exercise both sign bits,
different operands, signed/unsigned min/max, and arithmetic truncation.

Compare-swap reads its comparison from X31. The primary case matches and
writes the new value; the second case mismatches and leaves memory unchanged.
The suite checks that difference in both the memory dump and the actual
read/write events. Byte/halfword stores check operand truncation and preserve
the seeded x20 register. `packb` combines the low bytes of two scalar registers
without a memory access. Every site checks the traced operands and result,
the device-side result snapshot, and the entire guarded 128-byte target.
As with packed atomics, this is a single-hart functional check.

## Graphics extensions

`graphics.py` executes all 25 `packed_graphics.cpp` handlers, scalar `bitmixb`,
and `maskpopc.rast` with all four selectors (30 labeled sites). The primary
case uses M0=`0xff`; the second uses M0=`0x55` for vector instructions and
verifies that inactive destination lanes retain their seeded words.
Destination snapshots use full-lane `fsq2`; the operation's actual register
write and the final output-memory bytes must agree. Mask and scalar operations
capture their actual source registers, destination writes, and memory snapshots.
Every site records FCSR before and after execution.

The program reads S0's machine-privilege `minion_feature` ESR at
`0x01c0340000`, clears only bit 0, writes it back, and reads the result. This
enables the feature checked by `require_feature_gfx()`. In the tested
`-single_thread` configuration the observed transition is `0x11` to `0x10`:
bit 4 disables thread 1 and is preserved. Both the raw ESR read/write events
and device-side readback snapshots are checked. No simulator patch or fault
suppression is used.

The cases cover cube-face selection/signs, unsigned F10/F11 conversions,
signed/unsigned normalized conversions, two raster fixed-point conversions,
and the raster reciprocal refinement. F10/F11 are unsigned E5M5/E5M6 formats;
the tested finite positive FP32 inputs are truncated to their mantissa width
and negative inputs become zero. Normalized output conversion uses the pinned
implementation's fixed nearest rounding with ties away from zero. The raster
paths differ in scale: `fcvt.rast.ps` produces a 17.14 value after adding 0.5,
while `fcvt.ps.rast` reads signed 15.16 input. Signed half-integer ties and the
scale difference are checked explicitly. Binutils accepts `frcp_fix.rast`,
which SysEmu decodes as `frcp.fix.rast`; both spellings are saved in
`operations.json`. `bitmixb` checks the sequential bit selection from two
scalar bytes, while `maskpopc.rast` checks the `0x0f`, `0x3c`, `0xf0`, and
`0xff` selection windows on two mask registers.

## Unimplemented handlers and fault delivery

`trap_stubs.py` intentionally executes `fdiv.pi`, `fdiv.ps`, `fdivu.pi`,
`frem.pi`, `fremu.pi`, `frsq.ps`, `fsin.ps`, and `fsqrt.ps`. The pinned SysEmu
handlers throw `trap_mcode_instruction`: each actual trap has `mcause=30`,
`mepc` equal to the linked operation PC, and `mtval` equal to the independently
assembled instruction word. A ninth site executes `bitmixb` while graphics is
disabled and verifies illegal-instruction cause 2. Both deterministic cases
check those CSR read events against the device-side memory records, as well
as the raw trap log and unchanged f20/x20 destinations.

The diagnostic's bare-metal trap handler only records the fault, advances
`mepc` by the verified four-byte instruction length, and returns with `mret`.
The script requires exactly nine expected traps and rejects any wrong cause,
PC, instruction word, destination write, memory guard, or completion count.
This verifies the simulator's fault delivery; it does not implement the
missing arithmetic or run firmware microcode. Normal arithmetic examples
continue to require successful execution without unexpected traps.
