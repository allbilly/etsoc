# Examples and coverage

[Repository overview](../README.md) · [Verification](verification.md)

Choose a driver below for a focused experiment. Commands and `out/` paths
are relative to the repository root.

## Run an example

Run from the repository root after [setup](setup.md). Each driver reports
`PASS` and exits zero when its execution and validation checks succeed.
Python uses only the standard library.

```sh
python3 examples/add.py
python3 examples/mul.py
python3 examples/gemm.py
```

Most drivers run `primary` and `exact` by default; pass either or both names
to select cases, for example `python3 examples/add.py exact`.
Packed atomics add `alias`. Message ports add `blocking-primary`,
`blocking-exact`, `overflow-primary` and `overflow-exact`. Peer synchronization
adds `threads-primary` and `threads-exact`.

## Example catalog

| Driver | What it exercises | Default ELF cases | Guide |
| --- | --- | --- | --- |
| [add.py](../examples/add.py) | Eight-lane `fadd.ps` | 2 | [Arithmetic](arithmetic.md) |
| [mul.py](../examples/mul.py) | Eight-lane `fmul.ps` | 2 | [Arithmetic](arithmetic.md) |
| [sub.py](../examples/sub.py) | Eight-lane `fsub.ps` | 2 | [Arithmetic](arithmetic.md) |
| [gemm.py](../examples/gemm.py) | 8×8×8 packed-FP matrix multiply | 2 | [GEMM](arithmetic.md#8x8x8-gemm) |
| [packed_int.py](../examples/packed_int.py) | 30 vector operations and 11 mask sites | 2 | [Packed ISA](packed-isa.md#packed-integer-and-mask-operations) |
| [packed_fp.py](../examples/packed_fp.py) | 38 packed-FP operation sites | 2 | [Packed FP](packed-isa.md#packed-floating-point-coverage) |
| [scalar_fp.py](../examples/scalar_fp.py) | 22 implemented FP handlers and six stubs | 2 | [CPU ISA](cpu-isa.md#scalar-floating-point-coverage) |
| [scalar_integer.py](../examples/scalar_integer.py) | 43 integer arithmetic handlers, 61 sites | 2 | [CPU ISA](cpu-isa.md#scalar-integer-arithmetic) |
| [base_memory.py](../examples/base_memory.py) | 14 ordinary load/store/fence handlers | 2 | [CPU ISA](cpu-isa.md#ordinary-scalar-memory) |
| [branches.py](../examples/branches.py) | Eight branch/jump handlers, 16 sites | 2 | [CPU ISA](cpu-isa.md#ordinary-branches-and-jumps) |
| [compressed.py](../examples/compressed.py) | 34 compressed handlers, 36 sites | 2 | [CPU ISA](cpu-isa.md#compressed-instructions) |
| [csr.py](../examples/csr.py) | Six CSR forms, 26 sites | 2 | [CPU ISA](cpu-isa.md#csr-instruction-forms) |
| [system.py](../examples/system.py) | Seven control handlers, M/S/U returns and faults | 2 | [CPU ISA](cpu-isa.md#system-instructions-returns-and-privilege) |
| [packed_memory.py](../examples/packed_memory.py) | 33 packed/coherent memory handlers | 2 | [Packed ISA](packed-isa.md#packed-memory-and-atomics) |
| [packed_atomic.py](../examples/packed_atomic.py) | 22 packed atomic handlers, shared-address alias | 3 | [Packed ISA](packed-isa.md#packed-memory-and-atomics) |
| [scalar_memory.py](../examples/scalar_memory.py) | 40 atomics, four coherent stores and `packb` | 2 | [Packed ISA](packed-isa.md#scalar-memory-and-atomics) |
| [graphics.py](../examples/graphics.py) | 27 graphics handlers, 30 sites | 2 | [Packed ISA](packed-isa.md#graphics-extensions) |
| [trap_stubs.py](../examples/trap_stubs.py) | Eight microcode faults and disabled graphics | 2 | [Fault delivery](packed-isa.md#unimplemented-handlers-and-fault-delivery) |
| [cache_control.py](../examples/cache_control.py) | 13 cache CSRs, 37 sites | 2 | [Cache control](communication.md#cache-control-csrs) |
| [synchronization.py](../examples/synchronization.py) | FLB/FCC/STALL, five selected CSRs | 2 | [Synchronization](communication.md#barriers-credits-and-stall) |
| [synchronization_peers.py](../examples/synchronization_peers.py) | T0/T1 FCC routes, overflow and ordered FLB | 4 | [Peer synchronization](communication.md#fcc-waitwake-overflow-and-peer-flb) |
| [message_ports.py](../examples/message_ports.py) | FIFO, blocking/wake, overwrite and count wrap | 6 | [Message ports](communication.md#message-ports) |
| [message_port_privilege.py](../examples/message_port_privilege.py) | Real M/U port permissions and faults | 2 | [Port privilege](communication.md#message-port-permissions-in-real-u-mode) |

## Comparison modes

```sh
python3 tools/compare.py
python3 tools/inventory.py --require-complete
```

The default comparison runs all 23 drivers: 53 example ELF cases, followed by
one execution of the copied ADD ELF patched to MUL. It compares source,
disassembly, bytes and real register/results, then independently audits the
saved raw evidence. See [measured encoding changes](arithmetic.md#measured-add-to-mul-change)
and [verification](verification.md) for the recorded checkpoint.

```sh
python3 tools/compare.py --reuse
```

`--reuse` audits existing real execution artifacts and freshly runs only the
patched ELF. The report identifies this mode and its fresh execution count;
missing or invalid saved evidence fails. It does not represent 54 new runs.

## Decoder and execution inventory

`tools/inventory.py` reads the selected ET Platform checkout, checks its
setup-recorded revision and writes decoder and execution audits to `out/isa/`.
Without `--require-complete`, it can be used before execution to inspect gaps.

The ET extension inventory finds 213 ET extension handler selectors. It includes
the custom-0/1/2/3 paths and ET instructions in the decoder functions named
48-bit, 64-bit, FP-load/store, op-32, and reserved-2. Those historical decoder
names do not imply that the emitted ET instructions are wider than four bytes.
Eight handlers explicitly trap as unimplemented
(`fdiv.ps`, `fsqrt.ps`, `frsq.ps`, `fsin.ps`, `fdiv.pi`, `fdivu.pi`, `frem.pi`,
and `fremu.pi`). Inventory is decoder/source evidence, not execution
coverage: runnable examples exercise `fadd.ps`, `fsub.ps`,
`fmul.ps`, `fmadd.ps`, 30 packed-integer vector operations,
`fsetm.pi`/`fltm.pi`, regular mask logic/count/transfer, and the non-trapping
packed-float/transcendental handlers. Each packed suite runs a second
deterministic case. Integer cases check raw lanes, all eight mask registers,
and mask counts. Packed-FP cases check raw lane words, inactive-lane
sentinels, conversions, compare masks, and scalar transfers. Graphics cases
enable the graphics feature through an actual device-side ESR write and check
all 27 graphics handlers. Tensor-engine operations remain outside execution coverage.
Packed memory covers 33 sites; packed atomics cover all 22 handlers in their
source file. Scalar memory covers 40 coherent atomic handlers, four coherent
byte/halfword stores, and `packb`. The inventory also
audits passing result artifacts against the raw instruction trace and ELF bytes
at each labeled PC. It verifies execution evidence for all 205 nontrapping
handlers; there are no nontrapping gaps in this ET extension inventory.
The eight unimplemented trap stubs are also executed in an intentional fault
diagnostic: all raise cause 30 and preserve their destinations. They do not
produce arithmetic results. Source-string mentions are recorded
separately and do not count toward that total. Base RISC-V and CSR-launched
commands are outside this extension-handler inventory. A separate cache
inventory checks 13 cache control/action/debug CSRs against the pinned CSR
declarations, actual SYSTEM instruction words, raw traces, memory readbacks,
and executable `PT_LOAD` mappings. This includes 12 writable control/action
CSRs and the read-only `dcache_debug` CSR; the latter currently reads zero.
The synchronization inventory separately checks five CSRs, self-credit ESR
stores, real counter readbacks, and the raw timed `stall` wait/wake events.
The message-port inventory separately checks all 12 port CSRs, both four-port
FIFO cases, both two-minion blocking read/wake/retry cases, and both
overcapacity/count-wrap cases.
`--require-complete` fails if any expected run lacks evidence, any nontrapping
ET extension handler is missing, or any trap stub lacks the expected fault
evidence. It also requires both cache cases and evidence for all 13 selected
cache CSRs, plus both synchronization cases and their five selected CSRs.
It also requires all six message-port cases and all 12 port CSRs.
All four peer-synchronization cases must supply real FCC restart, wrong-counter
or wrong-thread isolation, overflow and ordered FLB evidence.
Both M/U message-port permission cases must supply successful U reads,
expected privilege/disabled-port faults and retained-message evidence.
Both scalar-FP cases must supply all 22 implemented handlers and all six
expected faults. Both scalar-integer cases must supply all 43 handlers and
their selected arithmetic edge cases. This flag checks all selected active CPU
handlers; it is not a claim of exhaustive instruction/privilege/operand coverage.
Both ordinary scalar-memory cases must also supply all 14 handlers with actual
access-width/address/value, register, control-state, and complete guard evidence.
Both branch/jump cases must supply all eight handlers, both conditional paths,
real next PCs, jump link and alias behavior, and complete guarded memory.
Both compressed cases must supply all 34 selected handlers, two-byte encodings,
actual register/MEM effects, both zero-branch outcomes and all three expected faults.
Both CSR cases must supply all six instruction handlers, real CSR read/write
events, suppressed accesses, guarded snapshots and six expected read-only faults.
Both system cases must supply all seven handlers, real next-PC/privilege/status
transitions, all expected faults and helper exits, and actual WFI wait evidence.
`out/isa/full-cpu-source-inventory.json` enumerates all active decoder functions,
excludes literal `#if 0` branches, and ties selectors to the separate execution
audits. It finds 353 handlers: 213 ET extensions, 28 scalar-FP handlers,
43 scalar-integer handlers, 14 ordinary scalar-memory handlers, eight
branch/jump handlers, 33 compressed handlers plus `c.ebreak`, six CSR instruction
handlers, and seven system/control handlers. **All 353 active CPU handlers now
have dedicated execution or expected-fault audits.** This includes two explicit
microcode stubs (`fence.i`, `sfence.vma`) and `ecall`, `ebreak`, `mret`, `sret`, `wfi`.
These are handler counts, not a count
of distinct encodings or exhaustive test cases. Ordinary startup executes some
base instructions; incidental execution does not establish dedicated coverage.
The separate scalar-FP audit is `out/isa/scalar-fp-inventory.json`.
The scalar-integer audit is `out/isa/scalar-integer-inventory.json`.
The ordinary scalar-memory audit is `out/isa/base-memory-inventory.json`.
The branch/jump audit is `out/isa/branch-inventory.json`.
The compressed audit is `out/isa/compressed-inventory.json`.
The CSR instruction audit is `out/isa/csr-instruction-inventory.json`.
The system/control audit is `out/isa/system-instruction-inventory.json`.
Dynamic CSR engine commands remain separate from these counts.
Without that flag, the inventory
can also be used before running examples to inspect the outstanding gaps.
