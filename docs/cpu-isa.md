# Scalar and compressed CPU instructions

[Repository overview](../README.md) · [Example catalog](examples.md)

These suites cover selected arithmetic, memory, control-flow, CSR and privilege
cases. Handler coverage does not establish exhaustive operand or privilege coverage.

- [Scalar floating point](#scalar-floating-point-coverage)
- [Scalar integer arithmetic](#scalar-integer-arithmetic)
- [Ordinary scalar memory](#ordinary-scalar-memory)
- [Branches and jumps](#ordinary-branches-and-jumps)
- [Compressed instructions](#compressed-instructions)
- [CSR instruction forms](#csr-instruction-forms)
- [System instructions and privilege](#system-instructions-returns-and-privilege)

## Scalar floating-point coverage

`scalar_fp.py` runs 31 labeled sites in each of two deterministic cases.
It covers all 28 handlers in the pinned
[`insns/float.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/float.cpp):
22 implemented arithmetic/FMA, min/max, conversion, sign, move, comparison,
and classification handlers, plus six explicit microcode stubs. The stubs are
scalar divide, square root, and all four signed/unsigned 64-bit FP conversions.
They raise cause 30 and leave f20/x20 unchanged; no arithmetic is substituted.

Each site loads f10/f11/f13 with one scalar and seven distinct nonzero upper
lanes, seeds f20 and x20, and captures both destinations, M0, and FCSR before
and after. In this implementation, scalar FP writes lane 0 and clears lanes
1–7 through `WRITE_FD_REG` in
[`insn_util.h`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insn_util.h).
The actual register-write event and an unmasked `fsq2` snapshot must agree
in all eight lanes. Scalar integer results preserve the seeded FP destination.
An additional `fadd.s` with M0=0 confirms that scalar arithmetic ignores M0;
both explicit mask readbacks remain zero while lane 0 changes and upper lanes clear.

RNE conversions check ties and FCSR NX. The extra RTZ conversion distinguishes
`3.5 -> 3` from RNE `3.5 -> 4`; unsigned `0xffffffff -> FP32` rounds to
`0x4f800000` and sets NX. `fmv.x.w` checks sign extension of `0x80000001`.
`fnmadd.s` and `fnmsub.s` use the same pinned sign-handling helpers as packed
FMA and produce `-(a*b+c)` and `-(a*b)+c`, respectively.

The 192-byte device records include unchanged guards, complete FP destination
lanes, scalar destinations, M0/FCSR readbacks, and actual mcause/mepc/mtval/mstatus
for each fault. Whole monitor memory must equal the reference and leave inputs,
guards, and the unexpected-trap record untouched. Source-register state is
reconstructed from complete actual H0 register-write events and checked against
the real vector loads; it is not filled from Python's reference values.
The independent inventory parser repeats the ELF/PT_LOAD, raw register,
reference, control-state, fault, and whole-memory checks. Normal completion and
one final `wfi` are required; the 20,000-cycle watchdog and 90-second simulator
timeout fail incomplete execution. Exhaustive IEEE edge/exception coverage is
not claimed for these selected inputs.

## Scalar integer arithmetic

`scalar_integer.py` runs all 43 active scalar arithmetic handlers from
[`arith.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/arith.cpp)
and [`muldiv.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/muldiv.cpp).
Each of two cases has 61 sites: 43 ordinary arithmetic/shift/compare/immediate/
upper-immediate operations, eight zero-divisor cases, four signed-overflow
cases, and six register shifts with counts 65 or 129.

The program loads actual 64-bit operands into x10/x11, seeds x20, executes the
visible selected instruction, and stores all three registers before and after
into guarded 128-byte records. Only x20 changes. Whole monitor memory must
match the reference, including unchanged operands, guards, and trap records.
The test uses both sign-bit cases and distinct upper/lower 32-bit words.
Word instructions ignore the high input bits and sign-extend their 32-bit result;
register shifts use the low five or six count bits. Multiply-high distinguishes
signed/signed, signed/unsigned, and unsigned/unsigned products. Signed division
truncates toward zero, including `-17 / 5 -> -3` and remainder `-2`.

Zero-divisor quotient results are all ones; remainders retain the dividend
(sign-extended from 32 bits for word operations). Minimum signed values divided
by -1 return the minimum bit pattern, with remainder zero. `lui` checks signed
32-bit upper-immediate expansion; `auipc` adds that expansion to the actual
operation PC derived from ELF symbols and observed in the trace.

The independent audit derives opcode/funct3/funct7/immediate fields from the
actual four instruction bytes using the pinned decoder tables, repeats the
arithmetic reference with actual loaded operands, and matches every device
load, register read/write, and snapshot store. An unexpected trap, missing
completion, watchdog expiry, timeout, or changed guard fails. The program needs
no FP register initialization. Exhaustive operands/aliases and SysEmu software
hints encoded as `slti x0,x0,hint` are not covered by this batch.

## Ordinary scalar memory

`base_memory.py` executes all 14 handlers from
[`arith_loadstore.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/arith_loadstore.cpp)
and [`float_loadstore.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/float_loadstore.cpp):
`lb`, `lbu`, `lh`, `lhu`, `lw`, `lwu`, `ld`, `sb`, `sh`, `sw`, `sd`, `flw`,
`fsw`, and `fence`. These are separate from the [coherent/atomic scalar-memory suite](packed-isa.md#scalar-memory-and-atomics). Both cases use aligned payloads in guarded 128-byte
targets. The primary case addresses them with offset +24 and a negative-bit
payload `0xfedcba9889abcdef`; the second uses offset -24 and positive payload
`0x0123456776543210`. The actual base register differs accordingly.

Signed integer loads extend the sign bit, unsigned loads extend with zeros,
and stores retain only their width's low source bits. The measured primary
`lw` result is `0xffffffff89abcdef`, versus `lwu` result `0x89abcdef`.
SysEmu logs both as `lw`; the audit distinguishes `lwu` using actual opcode 3,
funct3 6, and its zero-extended result, following the pinned decoder table.
The ET toolchain disassembly correctly names it `lwu`.

M0 is explicitly zero, FP state enabled, and FCSR cleared. Scalar `flw` still
loads lane 0 and clears lanes 1 through 7, as implemented by `LOAD_FD` in
[`insn_util.h`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insn_util.h).
Both cases load exactly representable values (-1.5 and 2.5). `fsw` stores only
lane 0 of a real eight-lane source and preserves the whole register. Unmasked
`flq2`/`fsq2` initialize and capture all lanes independently of M0.
Each guarded 256-byte record contains f20/f11 and x10/x11/x20 before/after,
plus real M0, FCSR, and mstatus reads. Raw MEM events prove access width,
effective address, direction and value. Whole monitor equality checks every
target, sentinel, guard, input, trap record, and completion word.

The independent parser decodes the real instruction bytes, reconstructs
source state from complete register writes, and checks every operand load and
snapshot store. `fence iorw,iorw` (`0x0ff0000f`) executes and preserves state;
the pinned simulator handler only logs and returns. This provides no concurrent
memory-ordering or hardware-fence claim. Misalignment/page/protection faults
and exhaustive aliases are not covered by these selected cases. Both the
20,000-cycle watchdog and 90-second simulator timeout remain mandatory.

## Ordinary branches and jumps

`branches.py` executes all eight handlers from
[`branch.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/branch.cpp):
`beq`, `bne`, `blt`, `bge`, `bltu`, `bgeu`, `jal`, and `jalr`.
Each case has 16 sites: both taken/untaken outcomes for the six predicates,
`jal` with a link register and x0 destination, and `jalr` with a separate link
register and source/destination alias. Negative versus positive operands
distinguish signed and unsigned comparisons. The primary case branches/jumps
forward; the second branches/jumps backward. A routing jump skips the backward
target block during setup, so each selected instruction executes exactly once.

Actual next-instruction PCs establish each decision. Each path writes a distinct
marker (`TAKE` or `FALL`), and an `auipc` at the join captures its actual PC.
Guarded 128-byte records contain x10/x11/x20/x21 before/after, the joined PC,
and actual x0 stores before/after. `jal` writes PC+4; the x0 variant discards
that write. `jalr` receives an odd base-plus-offset target and clears bit 0.
Its alias variant writes the link into x10 while jumping through the original
x10 value. Primary and second `jalr` offsets are +24 and -24.

SysEmu suppresses x0 register logging, so the zero-register evidence comes from
encoded `sd x0` instructions, raw MEM64 writes, and actual dumped bytes.
The first host-validation attempt incorrectly required an x0 read log, after
the ELF had completed normally; that diagnostic is preserved under
`out/isa/attempts/branches-x0-log/`. The corrected cases passed.

The independent audit decodes B/J/I immediates using
[`insn.h`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insn.h)
and the pinned decoder tables, reconstructs the actual operands from complete
register writes, recomputes predicates, and checks every load/snapshot store,
next PC, path marker and full guarded dump. Timeout, watchdog expiry, unexpected
traps, missing completion and changed guards fail. Full immediate ranges,
misaligned/faulting targets, and privilege transitions are separate coverage.

## Compressed instructions

`compressed.py` covers all 33 active handlers from
[`c_arith.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/c_arith.cpp),
[`c_loadstore.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/c_loadstore.cpp),
and [`c_branch.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/c_branch.cpp),
plus `c.ebreak` from `system.cpp`. Each deterministic case has 36 sites:
18 arithmetic handlers, eight memory handlers, seven branch/jump sites for
five handlers, and three expected architectural fault handlers.

Every selected instruction occupies two bytes. The fetch implementation
zero-extends those bytes into the trace's 32-bit printed word; links and
ordinary fallthrough advance PC by two. Startup, snapshots, routing and trap
code explicitly use uncompressed instructions. The disassembly command uses
`-z` to retain the illegal all-zero instruction; its initially omitted listing
and failed host check are preserved in
`out/isa/attempts/compressed-zero-disassembly/`. That attempt stopped before SysEmu.

Arithmetic checks signed six-bit immediates, negative/positive `c.lui`, word
sign extension, bit operations and shifts 63 versus 1. SP is explicitly
initialized from the ELF's allocated stack for arithmetic; `c.addi16sp` changes
it by -256/+128 and `c.addi4spn` adds +256/+128 into x10. Memory cases use
guarded 128-byte targets, offsets 32/64, integer load sign extension and store
truncation. Stack-relative cases derive SP from the target's actual symbol;
each site resets it before use and the final code restores the allocated stack.

Both `c.beqz` and `c.bnez` take both paths. Primary targets are forward and the
second case uses backward targets. `c.j`/`c.jr` discard the link; `c.jalr` writes
x1=PC+2. Register-target jumps receive odd addresses and clear bit 0. Raw next
PCs, path markers, joined-PC `auipc` captures and actual x0 stores prove these
effects. Two source trace labels need field-based identification: `c.bnez`
prints `c.bneqz`, and the 32-bit `c.sw` store prints `c.sd`.

Raw words `0x0000` and `0x8000` select `c_illegal` and `c_reserved` respectively;
both raise cause 2 with mtval=0. `c.ebreak` (`0x9002`) raises cause 3 with
mtval equal to its operation PC. All preserve the tested general registers.
The M-mode trap handler snapshots cause/PC/tval/mstatus and resumes at PC+2.
The pinned ordinary reset debug configuration selects breakpoint traps;
DCSR is debug-only and is not read from M mode. Compressed FP opcode slots
select `c_reserved` in this implementation; this suite makes no double-precision claim.

Each guarded 192-byte record contains x10/x11/SP/x1/path before/after, the
joined PC, x0 stores, and fault CSR snapshots where applicable. Whole monitor
equality checks all targets, inputs, guards, fault count and completion. The
independent parser repeats instruction-field, actual operand/write, reference,
MEM width/address/value, branch/link and trap checks. Its initial decoder
mistakenly treated register fields as an immediate; that failed audit is
preserved in `out/isa/attempts/compressed-register-immediate/` and the corrected
audit passed against the unchanged real execution evidence. Exhaustive hints,
reserved encodings, immediate ranges and memory-protection faults remain
outside these selected cases. The usual cycle watchdog and host timeout apply.

## CSR instruction forms

`csr.py` executes `csrrw`, `csrrs`, `csrrc`, `csrrwi`, `csrrsi` and `csrrci`
at 26 labeled sites per deterministic case. It explicitly seeds full-width
`mscratch` (`0x340`) from a device load and uses read-only `mhartid` (`0xf14`)
for successful reads and expected illegal-instruction faults. The selected
hart is H0, and its real `mhartid` reads return zero. These are CPU instruction
handlers; the addresses that launch tensor and other engines remain separate.

The source register is x10, the old-value destination is x20 unless explicitly
x0, and x11 holds the seed. The primary seed/mask are `fedcba9889abcdef` and
`ffff000055aa00f0`; the exact case uses `0123456776543210` and
`01234567fedcba98`. Immediate cases use 13 and 23 respectively. Each site resets
`mscratch` and x20 so prior results cannot conceal missing execution.

The tested rules follow the pinned
[`dec_system`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/processor.cpp#L718)
and [CSR handlers](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/zicsr.cpp#L1328):

| Selected case | Actual access rule checked |
| --- | --- |
| Ordinary six forms | Return old CSR to x20; write, set or clear using the register value or five-bit immediate |
| `csrrw/csrrwi rd=x0` | Suppress CSR read and discard the old value; CSR write still occurs |
| `csrrs/csrrc rs1=x0`, `csrrsi/csrrci imm=0` | Read old CSR and suppress write |
| `csrrs/csrrc rs1=x10`, x10 holding zero | Perform/log a write even though the resulting value is unchanged |
| `csrrw rs1=x0`, `csrrwi imm=0` | Write zero and return old CSR when rd is x20 |
| Read-only `mhartid`, six write attempts | Cause 2, `mepc=operation PC`, `mtval=instruction word`; preserve x20 and all seeded state |
| Read-only `mhartid`, four no-write forms | Read zero successfully with no CSR write |

`csrrs/csrrc` with x10 holding zero still fault on a read-only CSR: write
selection depends on the register number. The immediate-zero `csrrwi` case
also faults because that form always writes. Faulting instructions have no
completed CSR read/write logs and no destination write. This does not prove
that an internal `csrget` was never called: the pinned handlers can read the
old value before `csrset` rejects a read-only write. `mhartid` has no read side effect.

SYSTEM encoding is opcode `0x73`; bits 14:12 select 1/2/3/5/6/7 for the six
forms, bits 11:7 select rd, bits 19:15 select rs1 or the unsigned immediate,
and bits 31:20 select the CSR. The measured ordinary register encodings are
`0x34051a73`, `0x34052a73` and `0x34053a73`. The independent audit decodes
these fields directly from ELF bytes and matches raw instruction, operand,
destination and CSR events. It reconstructs the prior GPR/`mscratch` state
from complete actual writes, rather than filling a register report from inputs.

The program uses the [M-box arithmetic layout](arithmetic.md#what-the-programs-do), disables
interrupts and delegation, sets SATP bare, disables tensor lanes and installs
a trap handler. The handler snapshots four fault CSRs and skips four bytes
only for the six expected cause-2 faults. Unexpected faults record diagnostics
and fail. Each 192-byte record contains before/after x10/x11/x20, `mscratch`,
target CSR and real x0 stores, plus fault snapshots and 64 bytes of untouched
guards. The whole monitor, input bytes, trap count and completion marker are
checked. The simulator cycle watchdog and 90-second host timeout both apply.

Both actual cases and the independent audit passed. Their console logs and
exit statuses are `out/csr-all-console.log`/`.exit` and
`out/isa/csr-instruction-inventory.log`/`.exit`. Exhaustive CSR addresses,
register aliases and privilege combinations remain outside these selected cases.

## System instructions, returns and privilege

`system.py` exercises all seven remaining CPU handlers at 24 sites per case.
The primary and exact cases change the loaded GPR inputs and reverse the
configured MPIE/MIE and SPIE/SIE bits. All source and destination GPRs are
snapshotted from real execution. Neither control operations nor intentional
faults may change x10, x11 or the x20 sentinel.

| Instruction/path | Actual execution evidence checked |
| --- | --- |
| `ecall` in M/S/U | Causes 11/9/8, `mepc=PC`, `mtval=0`, correct prior privilege in MPP |
| `ebreak` in M/S/U | Cause 3, `mepc=PC`, `mtval=PC`, unchanged GPRs |
| `mret` in M to M/S/U | Actual status write, MIE from MPIE, MPIE=1, MPP cleared, real next privilege and jump to `mepc` |
| `mret` in S/U | Cause 2, instruction word in `mtval`, unchanged GPRs |
| `sret` in M/S to S/U | Actual status write, SIE from SPIE, SPIE=1, SPP cleared, real next privilege and jump to `sepc` |
| `sret` in S with TSR, or U | Cause 2 with instruction word in `mtval` |
| `wfi` in M/S with exclusive mode set | Instruction executes without waiting; next instruction retains privilege and state |
| `wfi` in S with TW, or U | Cause 2 with instruction word in `mtval` |
| `fence.i`, `sfence.vma a0,a1` | Pinned handlers raise cause 30; instruction word in `mtval`, unchanged GPRs |
| Terminal `wfi` in M, exclusive mode zero, local interrupts disabled | Explicit completion store precedes the instruction; raw `Start waiting for interrupt`, no later instruction, normal `Finishing emulation` |

The measured words are `00000073` (ECALL), `00100073` (EBREAK), `30200073`
(MRET), `10200073` (SRET), `10500073` (WFI), `0000100f` (FENCE.I) and
`12b50073` (`sfence.vma x10,x11`). Their selectors follow the pinned
[`dec_system`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/processor.cpp#L718)
and [FENCE decoder](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/processor.cpp),
with behavior from [`system.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/system.cpp)
and [`zifencei.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/zifencei.cpp).
The two fence handlers do not perform their architectural synchronization
operations in this simulator; passing those sites means observing their specified fault.

The linker emits two executable sections: `.text` at M-box `0x8000001000`
holds setup and the machine trap handler, and `.text.os` at `0x8004001000`
holds the instruction sites and snapshots accessible in M/S/U. Data is in
the OS box at `0x8004100000`; the initialized stack remains in the M box.
SATP is bare, interrupts and delegation are explicitly disabled, tensor lanes
are disabled, and relevant status/return/exclusive state is reset for every site.
Cross-section jumps load the address and use `jr`, because the sections are
64 MiB apart. The initial out-of-range JAL link attempt and host edit-count
assertion are preserved under `out/isa/attempts/system-cross-section-jal/`;
neither failed attempt invoked SysEmu.

Successful returns jump past a fall-through guard. The next raw instruction
must be at the linked target in its actual new privilege. Lower-mode GPR
snapshots execute in that privilege, followed by a real ECALL to return to the
M-box setup. There are seven such helper exits per case. The handler saves
four fault CSRs and explicitly returns to M for the next site; unexpected
traps record diagnostics and fail. Each case has exactly 14 selected-operation
faults, seven helper exits and 21 checked trap-handler returns.

Full `mstatus` is reconstructed from actual CSR reads/writes and return trace
events, including when S/U cannot read it directly. Before/after machine-mode
CSR snapshots and both trap/exit snapshots independently confirm that state.
Each 256-byte record includes GPR snapshots, available status snapshots, fault
and helper-exit records, configuration reads and untouched guards. Unavailable
S/U `mstatus` snapshot slots and terminal WFI after-GPR slots retain their
sentinels; the report explicitly marks the terminal after-GPR state absent.
The independent audit checks the complete guarded monitor, entry/target PCs,
actual mode changes, trap state and return state, both executable-section
dumps, and the terminal wait. The cycle watchdog and 90-second host timeout apply.

Both real cases and their independent audit passed. Actual commands/results
and zero exits are in `out/system-all-console.log`/`.exit` and
`out/isa/system-instruction-inventory.log`/`.exit`. Debug-mode behavior,
interrupt wake-up, pending-IRQ WFI and trap delegation are untested. This
finishes dedicated coverage of the selected CPU handler inventory; dynamic
CSR engine commands remain separate, and no tensor-engine execution is claimed.
