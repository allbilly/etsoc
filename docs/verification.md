# Verification and artifacts

[Repository overview](../README.md) · [Example catalog](examples.md)

These are recorded execution results from 2026-10-04, documented at commit
`b020a17`. Their source-hash manifests describe that checkpoint. Generated
evidence is local and ignored by Git; a new checkout creates it by running
the examples. The documentation reorganization did not rerun device programs.

## Recorded checkpoint

The full fresh `python3 tools/compare.py` at launch commit `42c5c8f` passed:
23 example drivers executed
53 bare-metal ELF cases, then a copied ADD ELF patched to MUL ran once more.
All **353 active CPU instruction handlers** have dedicated execution or
expected-fault audits. Sixteen pinned handlers are unimplemented microcode
stubs: their verified result is cause 30, rather than an arithmetic or fence result.
ADD, MUL and the 8x8x8 packed-FP GEMM pass both deterministic input cases.

The independent checkpoint audit verifies 567 artifact/upstream source hashes,
all executable sections, register/memory evidence and the single-byte ELF patch.
It also checks all 23 actual driver exits, all 53 fresh SysEmu command blocks,
and the source snapshot used to launch the run. Logs and machine-readable
evidence are `out/compare/fresh54-console.log`, its zero `.exit` file, and
`out/isa/fresh54-completion-audit.json`. The setup and full-platform integration
check were verified earlier; current installed tool digests were checked again.
The tested scope is the original standalone minion ISA scope. Tensor/matrix-engine
commands and hardware performance remain separate and unverified.

| Stage | Recorded status | Evidence |
| --- | --- | --- |
| Setup | Verified using the existing installation | `out/setup/`, upstream standalone smoke and three passing integration tests |
| Execution | Verified, 54 fresh SysEmu runs | `out/compare/fresh54-console.log`, `.exit` and `comparison.json` |
| Register capture | Verified from traces and device snapshots | Per-example `trace.log` and `registers.json` |
| Binary patch | Verified by executing the copied ELF | `out/compare/patched/` and patch diffs |

`out/isa/acceptance-audit.json` records the additional acceptance checks for
these four stages at the completed checkpoint.

## Observed results

On 2026-10-04, the upstream ET-SOC1 standalone example was rebuilt and run
first. Its trace contains `addi x31,x0,1453`, `x31 = 0x5ad`, and
`Finishing emulation`. The full-platform `it_test_code_loading` integration
check also passed all three tests (805.062 seconds); that is an additional
system-stack result, not a dependency of these examples.

Observed primary outputs were:

```text
ADD: [11, 22, 33, 44, 55, 66, 77, 88]
MUL: [10, 40, 90, 160, 250, 360, 490, 640]
SUB: [-9, -18, -27, -36, -45, -54, -63, -72]
GEMM C[0,:]: [204, 408, 612, 816, 1020, 1224, 1428, 1632]
PACKED FP: 38/38 operation sites pass in both primary and exact cases
SCALAR FP: 31/31 sites per case; all 22 implemented handlers and 6 cause-30 stubs pass
SCALAR INTEGER: 61/61 sites per case; all 43 scalar arithmetic handlers pass
PACKED INTEGER: 41/41 sites pass in both primary and exact cases
PACKED MEMORY: 33/33 sites pass in both primary and exact cases
PACKED ATOMIC: 22/22 sites pass in primary, exact, and alias cases
SCALAR MEMORY: 45/45 sites pass in both primary and exact cases
GRAPHICS: 30/30 sites pass in both primary and exact cases
GEMM: 64/64 device broadcasts and 64/64 FMA state checks pass in both cases
ET EXTENSIONS: 205/205 nontrapping handlers have verified ELF/trace evidence
EXPECTED TRAPS: 8 arithmetic stubs raise cause 30; disabled graphics raises cause 2
CACHE CONTROL: 37/37 sites across 13 CSRs pass in both primary and exact cases
SYNCHRONIZATION: 23/24 sites across 5 CSRs pass; real STALL wait/wake observed
MESSAGE PORTS: 80/80 sites across 12 CSRs in both FIFO cases; both blocking cases and both 60-site overcapacity/count-wrap cases pass
MESSAGE-PORT PRIVILEGE: both 92-site M/U cases pass; 32 illegal faults and 12 U ECALL exits per case
PEER SYNCHRONIZATION: all four T0/T1 FCC routes, block/restart, wrong-thread/wrong-counter isolation, real 16-bit overflow and ordered FLB pass
```

The `exact` case passed for ADD/MUL/SUB and both exact-value GEMM matrices;
MUL's exact case includes negative zero. `tools/compare.py` reports the
measured elementwise words, ADD-to-MUL XOR/bit position,
source/disassembly/register diffs, the GEMM run summary, and patched-ELF
execution result plus packed-suite summaries.
The scalar-memory summary is recorded in the same comparison report.

## Fresh comparison evidence

The complete default command `python3 tools/compare.py` passed after
54 fresh device executions: 53 example ELF cases across all 23 drivers and
one newly executed ADD-to-MUL patched ELF. The actual zero exit, complete
console and launch/finish metadata are `out/compare/fresh54-console.exit`,
`out/compare/fresh54-console.log` and `out/compare/fresh54-job.json`. Its
combined host duration was 1016.49 seconds; that is verification wall time,
not a device performance measurement. The run used repository commit
`42c5c8f981a8abd4778287877b6b767dfe93ba74`.
The independent fresh checkpoint audit passed across all 53 newly executed
ELF cases, the new patched run, 567 artifact/upstream hashes, 25 Python syntax
checks and 27 repository source hashes. It verifies every actual driver exit
and per-case SysEmu command/trace block, as well as fresh output timestamps
and the committed launch source snapshot. Its command is
`python3 out/isa/fresh54-checkpoint-audit.py`; log and zero exit are
`out/isa/fresh54-checkpoint-audit.log` and the matching `.exit` file.
The prior completed evidence was copied with Btrfs reflinks before regeneration
to `out/checkpoints/before-fresh54/`; all 567 copied artifact/upstream hashes
and 27 source hashes were checked. The current installed simulator, assembler,
objdump and GCC hashes match the recorded installation; that read-only check
is `out/setup/fresh54-tool-digests.log` with a zero `.exit` file. Setup and
`it_test_code_loading` were not rerun as part of the 54-run comparison.
The earlier setup and integration evidence is retained.

## Generated artifacts

Commands and paths below are relative to the repository root.

- `out/setup/`: environment, revisions, versions, executable checksums,
  SysEmu help/build config, upstream smoke ELF/log, and integration-test log.
- `out/add/`, `out/mul/`, and `out/sub/`: source, linker script, ELF, disassembly,
  `.text`, operation bytes, raw trace, register/result JSON, memory dumps,
  symbol/section inspection, and command logs. `exact/` contains the second
  deterministic case.
- `out/gemm/`: generated 8x8x8 kernel, ELF layout, all 64 FMA encodings,
  64 scalar-broadcast encodings and memory reads, simulator trace, every FMA's
  input/accumulator state, final-FMA snapshots, and output-memory dump. `exact/`
  contains the second matrix case.
- `out/packed-fp/`: generated 38-site packed-FP kernel, per-operation bytes
  and disassembly, raw simulator traces, register-state JSON, and output-memory
  dumps for both deterministic cases.
- `out/scalar-fp/`: both actual 31-site scalar-FP programs, ELF/PT_LOAD layouts,
  instruction bytes and decoded words, raw traces, complete destination and
  reconstructed source registers, mask/FCSR/trap CSR reads, prestart memory,
  actual/expected guarded memory, and command logs.
- `out/scalar-integer/`: both actual 61-site integer programs, ELF/PT_LOAD
  layouts, instruction encodings, raw input-load/register/snapshot-store events,
  before/after registers, complete guarded memory, and reproducible command logs.
- `out/base-memory/`: both actual 14-site ordinary scalar-memory programs,
  signed-offset instruction encodings, all eight source/destination FP lanes,
  scalar and M0/FCSR/mstatus snapshots, real memory access events, whole guarded
  targets, ELF-derived inputs, and command logs.
- `out/isa/base-memory-inventory.json`: all 14 handler identities, independent
  decoder-field and raw state/memory checks, both cases, and artifact/source hashes.
- `out/branches/`: both actual 16-site branch/jump programs, B/J/I encodings,
  real next-PC sequences, source/link/path register snapshots, x0 device stores,
  joined-PC capture, guarded monitor dumps, and reproducible command logs.
- `out/isa/branch-inventory.json`: all eight handlers, both conditional outcomes,
  forward/backward target evidence, odd-target clearing, source/destination alias,
  decoded instruction fields, and independently checked artifact/source hashes.
- `out/compressed/`: both real 36-site programs, two-byte instruction encodings,
  actual scalar/SP/link/path and x0 snapshots, next PCs, memory accesses, three
  architectural fault snapshots, guarded dumps and reproducible command logs.
- `out/isa/compressed-inventory.json`: all 34 selected handlers independently
  decoded and checked against actual register/MEM/control/trap events, plus
  complete guarded outputs and artifact/upstream source hashes.
- `out/csr/`: both real 26-site programs, SYSTEM encoding fields, CSR read/write
  logs, register and device snapshots, six expected faults, guarded dumps,
  completion and command/exit evidence.
- `out/isa/csr-instruction-inventory.json`: all six instruction handlers
  independently decoded and checked against real CSR/register/MEM/fault events,
  prior state reconstructed from actual writes, complete guarded outputs,
  34 artifact hashes and five pinned upstream source hashes.
- `out/system/`: both real 24-site programs, M/S/U instruction/register/status
  traces, `.text` and `.text.os` dumps, expected faults and lower-mode exits,
  terminal WFI waiting, guarded memory and completion/command/exit evidence.
- `out/isa/system-instruction-inventory.json`: all seven instruction handlers
  independently decoded and checked against real PC/privilege/status/GPR/MEM/
  trap/return/wait evidence; 36 artifact hashes and nine upstream source hashes.
- `out/isa/scalar-integer-inventory.json`: all 43 handlers matched against the
  pinned definitions, independently decoded operation fields and arithmetic
  references, zero/overflow/overshift evidence, and artifact/source hashes.
- `out/isa/scalar-fp-inventory.json`: independently checked scalar-FP ELF,
  register events, references, six cause-30 faults, full memory, pinned source
  hashes, and both sets of artifact hashes.
- `out/isa/full-cpu-source-inventory.json`: active CPU decoder selectors with
  dedicated audit coverage of all 353 handlers and zero remaining selectors.
  Exhaustive operands/privileges and dynamic CSR engine commands remain separate.
- `out/isa/fresh54-completion-audit.json`: final fresh comparison evidence,
  all 353 selected CPU handlers, 53 newly executed example ELF cases plus one
  newly executed patched ELF, 567 artifact/upstream hashes, 27 current and
  committed-launch source hashes, and actual driver/per-case command exits.
  `out/isa/fresh54-checkpoint-audit.py` reproduces the independent artifact audit.
- `out/checkpoints/before-fresh54/`: preserved prior verified execution,
  source and comparison artifacts, including the copied ADD-to-MUL patch,
  copy commands/exits and the independently verified snapshot manifest.
- `out/packed-int/`: 30 vector operations and 11 mask-operation sites,
  per-PC instruction encodings, trace register writes, masks, counts, and
  output-memory evidence for both deterministic cases.
- `out/packed-memory/`: 33-site kernel, per-PC encodings and register snapshots,
  actual memory accesses, complete guarded target regions, and reference results.
- `out/packed-atomic/`: 22-site kernel, atomic old-value returns and new memory,
  raw read/write events, guarded targets, and primary/exact/alias case evidence.
- `out/scalar-memory/`: 45-site kernel, scalar operands and returned values,
  sign-extension and compare-swap checks, actual memory events, guarded targets,
  and primary/exact case evidence.
- `out/graphics/`: 30-site kernel, feature ESR read/modify/write/readback,
  raw traces, vector/scalar register snapshots, mask inputs, FCSR, and
  output-memory evidence for both cases.
- `out/trap-stubs/`: nine-site intentional fault kernel, operation words,
  actual mcause/mepc/mtval records, unchanged destination snapshots, raw
  trap events, and primary/exact case evidence.
- `out/cache-control/`: 37-site CSR kernel, SYSTEM encodings, actual 512-bit
  memory reads/writes and cache-action logs, CSR readbacks, guarded whole-memory
  checks, duplicate-lock and access-error feedback, and both cases' raw evidence.
- `out/synchronization/`: FLB/FCC/STALL kernel, SYSTEM and ESR-store encodings,
  raw counter and interrupt/wait transitions, before/after state snapshots,
  real timer loads/arm/disarm stores, guarded memory, and both deterministic cases.
- `out/synchronization-peers/`: four FCC0/FCC1 two-minion/two-thread programs,
  bulk increment traces, actual wrong-thread/wrong-counter/matching-counter sends, restart evidence,
  overflow/error/clear/refill snapshots, ordered peer FLB arrivals, guarded
  memory and normalized first/last bulk samples for all four cases. The earlier
  two-minion-only checkpoint is preserved in `checkpoints/t0-only/`.
- `out/message-ports/`: four-port primary/exact FIFO kernels, two-minion
  blocking-primary/blocking-exact kernels and overflow-primary/overflow-exact
  kernels, CSR/send encodings, raw receiver
  memory writes, sender/receiver register events, wait/wake/retry evidence,
  complete 255-send loops, count-wrap readbacks, seeded snapshots, guarded
  memory and expected-byte files. `checkpoints/before-overflow/` preserves
  the earlier four-case programs and audit record.
- `out/message-port-privilege/`: both 92-site M/U kernels, separate M and U
  executable-section dumps, real instruction-mode and trap-state records,
  sender/receiver/payload events, guarded memory and actual register snapshots.
- `out/compare/`: ADD/MUL/SUB source/disassembly/register diffs, decoder excerpt,
  whole-ELF and patch diffs, patched ELF, patched execution evidence, and the
  verified GEMM, packed-suite, scalar-memory, graphics, expected-trap, cache,
  synchronization, peer-synchronization, message-port, permission and extension-coverage
  summaries in `comparison.json`.
- `out/isa/instruction-inventory.json`: revision-checked decoded ET handler
  names, implementation source files, feature gates, explicit trap stubs,
  per-PC execution evidence, separate expected-fault evidence, hashes of each
  verified run, and remaining gaps.
- `out/isa/cache-csr-inventory.json`: separate revision/source-hashed coverage
  for all 13 selected cache CSRs, executable segment mappings, and raw artifact
  hashes for both passing cache cases. Tensor/credit/communication command
  engines remain outside this cache inventory.
- `out/isa/synchronization-inventory.json`: source/revision-hashed audit of
  all five selected synchronization CSRs, both cases' ELF/trace/state-memory
  evidence, actual timed-wait events and artifact hashes. This single-hart
  inventory excludes blocking FCC, overflow and peer FLB; their evidence is
  recorded separately below.
- `out/isa/synchronization-peer-inventory.json`: independent source-hashed
  audit of all four peer cases, every 65,535-iteration bulk loop, actual FCC
  wait/retry, all four ESR routes, wrong-thread/wrong-counter isolation, CSR
  words and real register/snapshot evidence. Ordered FLB arrivals are covered;
  simultaneous contention and other T1-specific state remain unverified.
- `out/isa/message-port-inventory.json`: source/revision-hashed audit of all
  12 message-port CSRs, six case ELFs and raw traces, real per-site scalar
  register records, guarded memory, H2 device sends and H0 wait/wake/retry.
  Every repeated send is checked against source registers, ELF input bytes,
  actual ESR and receiver memory writes. Overcapacity overwrite and count
  wrap are checked on all four ports. Wider delivery engines and nonzero OOB
  remain unverified; the U-mode proof is recorded separately below.
- `out/isa/message-port-privilege-inventory.json`: independent audit of both
  real M/U cases, all 92 selected sites, explicit U entry and M exit,
  44 actual traps per case, preserved destinations, denied-read queue
  preservation, allowed U payload reads, complete guarded monitor bytes and
  source/artifact hashes. It extends the separate FIFO inventory above.

Earlier comparison audit files and failed attempts are indexed in [checkpoint history](history.md).
