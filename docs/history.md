# Checkpoint history and diagnostics

[Repository overview](../README.md) · [Example catalog](examples.md)

This is the historical milestone record, retained for provenance and debugging.
Counts and source hashes describe their respective checkpoints; use
[verification](verification.md) for the final fresh 54-run result. The referenced
logs and helper scripts live in ignored local `out/` directories.

## Earlier milestones

The completed checkpoint before the M/U permission extension exited zero after 38 actual
device runs, including both cache/synchronization cases, all six message-port
cases, all four peer-synchronization cases and the patched ELF.
Its console log and exit status are saved as
`out/compare/message-port-overflow-all-ops.log` and
`out/compare/message-port-overflow-all-ops.exit`. The standalone six-case
port run is saved in `out/message-ports-overflow-all-console.log` with exit
status zero in the matching `.exit` file. The independent port audit
is saved in `out/isa/message-port-overflow-inventory.log` and its `.exit` file.
Both standalone M/U permission cases and their independent trace audit passed;
their logs are `out/message-port-privilege-primary-console.log`,
`out/message-port-privilege-exact-console.log` and
`out/isa/message-port-privilege-inventory.log`, each with a zero `.exit` file.
The first expanded full comparison expired its combined 600-second peer-driver
host limit after SysEmu had completed the T1 ELF normally. That failed run and
a profile of its real trace prefix are preserved in
`out/compare/attempts/peer-host-validation-timeout/`. The driver audits about
180 MiB across four cases; its combined host limit is now 1200 seconds.
Each simulator invocation retains its 90-second timeout and cycle watchdog.
The corrected retry exited zero after 40 actual device runs: 39 example ELFs
and a fresh ADD-to-MUL patched ELF. Its console log and exit status are
`out/compare/message-port-privilege-all-ops.log` and the matching `.exit` file.
The previously failed host-timeout attempt is retained separately.
Both scalar-FP cases have passed independently, with all 31 sites and complete
register/control/fault/memory evidence checked by a second parser.
Together with scalar integer, ordinary scalar memory, branches, compressed, CSR and system instructions, the current default driver has 54 device runs
per complete run. At the earlier checkpoints below, the expanded driver's fresh
full comparison was still outstanding. The final fresh 54-run comparison now
passes. The saved-artifact audit mode labels its separate evidence explicitly.
The completed 40-run driver was launched before this addition; its exact source
is preserved under `out/compare/checkpoints/message-port-privilege-source/`
at commit `2f71f6b`. Its final inventory audit also checks the independently run
scalar-FP artifacts, but its own driver did not rerun those two cases.
The actual repository command `python3 examples/scalar_fp.py` and its exit zero
are saved in `out/scalar-fp-all-console.log` and the matching `.exit` file.
`out/isa/scalar-fp-inventory.log` records the independent audit; its `.exit`
file must be zero before treating this checkpoint as verified.
Both actual scalar-integer cases passed, with the repository command and exit
status saved in `out/scalar-integer-all-console.log` and its `.exit` file.
The independent audit is recorded in `out/isa/scalar-integer-inventory.log`
and the matching `.exit` file; it checks both actual ELF/trace/memory sets.
`python3 tools/compare.py --reuse` also exited zero. It independently audited
43 existing example artifact sets and freshly executed the patched ELF once;
it does not represent 44 newly run device programs. Its report records
`example_execution_mode`, `example_artifact_count=43`, and
`fresh_device_execution_count=1`. The console/exit files are
`out/compare/scalar-integer-reuse-console.log` and its `.exit` file.
The additional checkpoint audit passed: 43 saved ELF evidence audits plus
one fresh patched run, 394 artifact/upstream hashes, and 20 Python syntax checks.
Its log and exit zero are `out/isa/scalar-integer-checkpoint-audit.log` and the
matching `.exit` file.
The completed earlier 40-run comparison and patched evidence are preserved
under `out/compare/checkpoints/message-port-privilege-completed/`.
An audit-script filename mismatch briefly wrote the new summary to the earlier
checkpoint's JSON path. Diagnostics are preserved in
`out/isa/attempts/scalar-integer-audit-path/`. Both corrected audits passed:
the earlier 40-run summary was restored from the unchanged example artifacts,
archived original comparison/patched evidence, and the immutable `693fc4b`
source tree. The new summary has its own `scalar-integer-completion-audit.json`
path. No raw execution artifacts were changed by that correction.
Both actual ordinary scalar-memory cases and their independent audit passed.
The command `python3 examples/base_memory.py`, observed results, and exit zero
are saved in `out/base-memory-all-console.log` and its matching `.exit` file.
`out/isa/base-memory-inventory.log` and its zero `.exit` file record the
independent 14-handler audit of both actual ELF/trace/memory sets.
The expanded `python3 tools/compare.py --reuse` passed, independently auditing
45 saved example executions and freshly running the copied ADD-to-MUL ELF.
Its log and zero exit status are `out/compare/base-memory-reuse-console.log`
and the matching `.exit` file. The additional checkpoint audit also passed:
45 ELF evidence sets, one fresh patched run, 428 artifact/upstream hashes,
and 21 Python syntax checks. Its log/exit files are
`out/isa/base-memory-checkpoint-audit.log` and the matching `.exit` file.
That checkpoint had dedicated CPU coverage of 298/353 handlers, leaving 55,
and a 46-run default driver whose full fresh run remained outstanding.
Saved-artifact mode did not claim those 46 newly run programs. Its reports and
comparison/patched evidence are preserved under
`out/isa/checkpoints/before-branches/` and
`out/compare/checkpoints/base-memory-completed/`.
Both actual branch/jump cases and their independent audit passed.
`python3 examples/branches.py` and its exit zero are recorded in
`out/branches-all-console.log` and its matching `.exit` file. The independent
audit is `out/isa/branch-inventory.log` with a zero `.exit` file.
The expanded `python3 tools/compare.py --reuse` passed, auditing 47 saved
example executions and freshly running the patched ADD-to-MUL ELF once.
Its console and zero exit status are `out/compare/branches-reuse-console.log`
and the matching `.exit` file. The additional checkpoint audit passed across
47 ELF evidence sets, one fresh patched run, 462 artifact/upstream hashes,
and 22 Python syntax checks; its log and zero exit are
`out/isa/branches-checkpoint-audit.log` and the matching `.exit` file.
That checkpoint had dedicated CPU coverage of 306/353 handlers, leaving 47,
and a 48-run default driver whose full fresh run remained outstanding.
Saved-artifact mode did not claim those 48 newly run programs. The reports
and original comparison/patched evidence are preserved under
`out/isa/checkpoints/before-compressed/` and
`out/compare/checkpoints/branches-completed/`.
Both real compressed cases and their independent audit passed. Their actual
command `python3 examples/compressed.py`, observed results and zero exit are
saved in `out/compressed-all-console.log` and its matching `.exit` file.
The independent audit is `out/isa/compressed-inventory.log` with a zero `.exit` file.
The expanded `python3 tools/compare.py --reuse` passed: 49 saved example
execution sets were independently audited and the copied ADD-to-MUL ELF was
freshly executed once. Its log and zero exit status are
`out/compare/compressed-reuse-console.log` and the matching `.exit` file.
The additional checkpoint audit passed across 49 ELF evidence sets, one fresh
patched run, 496 artifact/upstream hashes and 23 Python syntax checks; its
log/zero exit files are `out/isa/compressed-checkpoint-audit.log` and the
matching `.exit` file. That checkpoint had dedicated CPU coverage of 340/353 handlers,
leaving 13. Its default driver required 50 fresh device runs; that
full fresh comparison was outstanding. Saved-artifact mode does not claim
50 newly executed programs.
Both CSR instruction cases and their independent audit have now passed: all
26 sites per case, six handlers and six expected read-only faults per case.
The real command `python3 examples/csr.py` and zero exit are preserved in
`out/csr-all-console.log` and its matching `.exit` file. The independent audit
is `out/isa/csr-instruction-inventory.log` with a zero `.exit` file.
That checkpoint had CPU coverage of 346/353 handlers, leaving seven. Its default
comparison required 52 fresh device runs; that full fresh comparison was
outstanding. Previous reports and comparison evidence are archived under
`out/isa/checkpoints/before-csr/` and
`out/compare/checkpoints/compressed-completed/`.
The expanded `python3 tools/compare.py --reuse` passed: 51 saved example
execution sets were independently audited and the copied ADD-to-MUL ELF was
freshly executed once. Its log and zero exit are
`out/compare/csr-reuse-console.log` and the matching `.exit` file. The additional
checkpoint audit passed across those 51 ELF evidence sets and one fresh patched
run, 530 artifact/upstream hashes and 24 Python syntax checks; its log and zero
exit are `out/isa/csr-instruction-checkpoint-audit.log` and the matching `.exit`
file. Saved-artifact mode does not claim 52 newly executed programs.
Both system instruction cases and their independent audit have now passed:
24 sites per case, seven handlers, 14 selected-operation faults and seven
lower-mode helper exits, actual M/S/U return state and terminal WFI waiting.
The real command `python3 examples/system.py` and zero exit are in
`out/system-all-console.log` and the matching `.exit` file. The independent
audit is `out/isa/system-instruction-inventory.log` with a zero `.exit` file.
All 353 selected CPU handlers had dedicated execution/fault evidence at that
checkpoint; its default comparison required 54 fresh device runs, and the fresh
complete run was still outstanding then. Previous reports and
comparison evidence are archived in `out/isa/checkpoints/before-system/`
and `out/compare/checkpoints/csr-completed/`.
The expanded `python3 tools/compare.py --reuse` passed: 53 saved example
execution sets were independently audited and the ADD-to-MUL patched ELF was
freshly executed once. Its log and zero exit are
`out/compare/system-reuse-console.log` and the matching `.exit` file. The
additional checkpoint audit passed across those 53 ELF evidence sets plus
one fresh patched run, 567 artifact/upstream hashes and 25 Python syntax
checks. Its log and zero exit are `out/isa/system-instruction-checkpoint-audit.log`
and the matching `.exit` file. Saved-artifact mode does not claim 54 newly
executed programs.

## Archived audit files

- `out/isa/system-instruction-completion-audit.json`: comparison checkpoint of
  all 353 CPU handlers, 53 saved execution sets plus one fresh patched run,
  567 artifact/upstream hashes, 27 repository source hashes, actual executable
  sections, complete guarded memory/fault/exit/completion checks and the
  independently verified single-byte ELF patch. The corresponding
  `out/isa/system-instruction-checkpoint-audit.py` reproduces the artifact audit.
- `out/isa/csr-instruction-completion-audit.json`: comparison checkpoint of 51
  saved execution sets plus one fresh patched run, 530 artifact/upstream hashes,
  26 repository source hashes, actual executable-section dumps, complete guarded
  memory/fault/completion checks and the independently verified single-byte ELF
  patch. `out/isa/csr-instruction-checkpoint-audit.py` reproduces the artifact audit.
- `out/isa/compressed-completion-audit.json`: comparison audit of 49 saved
  example executions plus one fresh patched run, 496 artifact/upstream hashes,
  25 repository source hashes, executable-section dumps, complete guard/fault/
  completion checks, and the independently verified single-byte ELF patch.
  `out/isa/compressed-checkpoint-audit.py` reproduces this artifact audit.
- `out/isa/branches-completion-audit.json`: comparison audit of 47 saved
  example executions plus one fresh patched run, 462 artifact/upstream hashes,
  24 repository source hashes, executable-section dumps, completion/guard
  checks and the independently verified single-byte ELF patch.
  `out/isa/branches-checkpoint-audit.py` reproduces this artifact audit.
- `out/isa/base-memory-completion-audit.json`: comparison audit of 45 saved
  example ELF executions and one fresh patched run, 428 artifact/upstream
  hashes, 23 repository source hashes, executable-section dumps, whole guarded
  output checks, and the independently verified single-byte ELF change.
  `out/isa/base-memory-checkpoint-audit.py` reproduces this artifact audit.
- `out/isa/scalar-integer-completion-audit.json`: comparison audit of 43 saved
  example ELF executions plus one fresh patched run, all raw artifact/upstream
  hashes, both scalar-FP/integer cases, all executable section dumps, complete
  guarded outputs, and the single changed ADD ELF byte. Its mode is recorded
  explicitly; at that checkpoint the fresh full 44-run default comparison
  remained unrun. Its reports and comparison/patched evidence are preserved in
  `out/isa/checkpoints/before-base-memory/` and
  `out/compare/checkpoints/scalar-integer-completed/`.
- `out/isa/completion-audit.json`: artifact audit of 23 example runs and the
  patched ELF, including ELF entry points, executable sections, instruction
  bytes, completion/trap memory, strict JSON, and independent `PT_LOAD`
  translation of the patch address. This audit covers the stated minion
  extension scope; the cache CSR audit is preserved separately as described above.
- `out/isa/cache-completion-audit.json`: earlier 26-run comparison checkpoint,
  183 checked artifact/upstream-source hashes, cache input memory mapped back
  to the ELF, guarded target checks, real CSR snapshot records, expected error
  feedback, preserved ADD-to-MUL patch proof, and repository source hashes.
  Its source hashes describe that earlier checkpoint.
- `out/isa/synchronization-completion-audit.json`: earlier 28-run checkpoint,
  all 27 example ELFs' executable sections and `.text` bytes, 206 matching
  artifact/upstream-source hashes, synchronization input memory mapped back
  to the ELF, all state snapshots matched to raw scalar register writes,
  actual timer wait/wake evidence, and the preserved ADD-to-MUL patch proof.
  It predates the message-port example; its source hashes describe that earlier
  checkpoint. Tensor command engines and the synchronization limits listed
  above remain unverified.
- `out/isa/message-port-completion-audit.json`: earlier 32-run checkpoint,
  all 31 example ELFs' executable sections and `.text` bytes, matching artifact
  and upstream source hashes, all 12 message-port CSRs, real H2-to-H0 blocking
  wake/retry evidence, guarded snapshots and the ADD-to-MUL patch proof.
  `out/isa/message-port-checkpoint-audit.py` reproduces this additional artifact
  audit. Its source hashes and limits describe that earlier checkpoint; the
  peer experiment extends its synchronization coverage.
- `out/isa/synchronization-peer-completion-audit.json`: earlier 34-run
  checkpoint, all 33 example ELFs' executable sections and `.text` bytes,
  artifact/upstream source hashes, all peer FCC block/restart/overflow and
  ordered FLB evidence, guarded snapshots and the preserved ADD-to-MUL patch
  proof. Its source hashes and T1 limit describe that earlier checkpoint;
  `checkpoints/t0-only/` preserves the earlier peer programs and audit records.
- `out/isa/synchronization-thread-completion-audit.json`: earlier 36-run
  checkpoint, all 35 example ELFs' executable sections and `.text` bytes,
  artifact/upstream source hashes, all four T0/T1 credit ESR routes, real
  wrong-thread/wrong-counter isolation, overflow, ordered FLB snapshots and
  the preserved ADD-to-MUL patch proof. Its source hashes describe that earlier
  checkpoint, before the message-port overflow cases.
- `out/isa/message-port-overflow-completion-audit.json`: earlier 38-run
  checkpoint, all 37 example ELFs' executable sections and `.text` bytes,
  matching artifact/upstream source hashes, all six message-port cases,
  complete 255-send trace sequences, overcapacity slot overwrite, count-wrap
  head results, all four peer cases and the ADD-to-MUL patch proof. Its source
  hashes and U-mode limitation describe that earlier checkpoint. Internal
  queue counts are inferred from complete
  device events and the pinned source type; they are not debugger reads.
  T1 state beyond the tested FCC/FLB paths, simultaneous synchronization
  contention, wider message delivery and tensor command paths remain unverified;
  U-mode port access is covered by the new diagnostic.
- `out/isa/message-port-privilege-completion-audit.json`: completed 40-run
  comparison checkpoint, independently checked across all 39 example ELF
  layouts, raw evidence hashes, both M/U permission cases, all four peer cases,
  and the fresh preserved ADD-to-MUL patch execution. The U-mode programs have
  both `.text` and `.text.user` executable sections; both byte dumps are checked.
  `out/isa/message-port-privilege-checkpoint-audit.py` reproduces that artifact
  audit. The 40-run driver source snapshot and later inventory source are
  identified separately; scalar-FP execution has its own milestone evidence.

## Preserved failed attempts

The first failed prestart-dump attempt is preserved in
`out/add/attempts/failed-prestart-dump/`; it exposed the hexadecimal radix of
SysEmu's `-dump_at_pc_size` argument. The initial compare-script import error is
preserved in `out/compare/attempts/missing-subprocess-import/`. Both were fixed
before the passing runs.
The first graphics run is preserved in `out/graphics/attempts/feature-state-check/`;
its program completed, but the host validator initially expected only the
reset graphics-disable bit and missed the thread-disable bit set by SysEmu.
The earlier passing GEMM with host-expanded A input is preserved in
`out/gemm/attempts/host-expanded-a-layout/` for comparison with device broadcasting.
The first synchronization validation attempt is preserved in
`out/synchronization/attempts/wake-cycle-check/`. The device completed and
the raw trace showed the wait and wake, but the host checker initially
excluded the resume cycle; wake and resume occur in the same emulator cycle.
The range was corrected before the passing runs.
The first message-port validation attempt is preserved in
`out/message-ports/attempts/lwu-trace-name/`. The device completed and produced
the correct payload, but the host initially required the literal `lwu` trace
name. The pinned scalar implementation prints `lw` for `lwu`; the checker now
verifies the actual unsigned-load encoding and zero-extended register result.
The first U-mode attempt is preserved in
`out/message-port-privilege/attempts/user-code-in-mbox/`: it hit an actual
instruction-access fault and failed the cycle watchdog. The corrected program
uses separate permitted M/U sections and fails on unexpected fault causes.
`attempts/stopped-container/` preserves the earlier host-side availability
failure after a reboot, before any new ELF executed.
