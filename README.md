# ET-SOC1 minion instruction experiments

Small host-side Python drivers assemble bare-metal ET-SOC1 minion programs,
run those ELFs in upstream `sys_emu`, and report instruction bytes, register
traces, and output memory. The ADD/MUL pair isolates one instruction change;
SUB adds the third operation in the inspected `ggml-et` elementwise kernel;
GEMM runs an 8x8x8 matrix multiply using packed fused multiply-add. The
packed-integer, packed-FP, packed-memory, packed-atomic, scalar-memory, and
graphics examples execute the remaining decoded ET extension families.
Cache-control, synchronization, and message-port examples separately exercise
CSR-launched commands and device ESR accesses.

The host Python arithmetic is only an independent check. The eight result
lanes are produced by ET instructions in SysEmu. These are standalone minion
ISA experiments: they do not execute a tensor-engine kernel, exercise the
PCIe driver or firmware path, or measure hardware performance.

## Run

The tested setup already had a working ET Platform installation in a running
Podman container. `setup.sh` reuses and checks an existing installation; it
does not download, build, install, or overwrite software under `/opt/et`.

```sh
./setup.sh
python3 examples/add.py
python3 examples/mul.py
python3 examples/sub.py
python3 examples/gemm.py
python3 examples/packed_int.py
python3 examples/packed_fp.py
python3 examples/scalar_fp.py
python3 examples/scalar_integer.py
python3 examples/base_memory.py
python3 examples/branches.py
python3 examples/packed_memory.py
python3 examples/packed_atomic.py
python3 examples/scalar_memory.py
python3 examples/graphics.py
python3 examples/trap_stubs.py
python3 examples/cache_control.py
python3 examples/synchronization.py
python3 examples/synchronization_peers.py
python3 examples/message_ports.py
python3 examples/message_port_privilege.py
python3 tools/compare.py
python3 tools/inventory.py --require-complete
```

ADD/MUL/SUB accept optional case names (`primary` and `exact`); without
arguments each runs both. The packed operation examples also run those two
deterministic cases. Packed atomics also run an `alias` case in which all eight
lanes access the same address. `tools/compare.py` reruns ADD/MUL/SUB, compares their
encodings and outputs, executes the one-instruction ADD-to-MUL patched ELF,
and reruns GEMM, all four packed-operation suites, scalar memory, and graphics.
It also runs the expected-trap diagnostic and requires execution evidence for
every nontrapping ET extension handler plus fault evidence for all eight
unimplemented stubs in the inventory. It reruns cache-control and synchronization
and audits their CSR coverage separately. It also reruns all six message-port
cases, including two real cross-minion blocking/wake cases and two cases that
overfill the configured ring and wrap the emulator's 8-bit message count.
It reruns four peer-synchronization cases for T0/T1 FCC routing, block/wake,
wrong-thread isolation, credit overflow and ordered FLB arrivals.
It also runs two message-port permission diagnostics that enter real U mode
and check access, fault state and unchanged destinations on all four ports.
It also runs both scalar-FP cases: 22 implemented handlers, six cause-30
microcode stubs, and additional mask/rounding checks.
It runs both 61-site scalar-integer cases covering all 43 arithmetic handlers
and selected zero-divisor, signed-overflow, and oversized-shift cases.
It runs both ordinary scalar-memory cases covering 14 load/store/fence handlers,
signed address offsets, integer extension/truncation, and all eight FP lanes.
It runs both 16-site branch/jump cases: all eight handlers, both conditional
outcomes, forward/backward targets, link writes, x0 discard and a `jalr` alias.
A successful run reports
`PASS` and exits zero. Host Python and the standard library are the only
Python dependencies.
`python3 tools/compare.py --reuse` independently audits the saved real execution
artifacts and freshly executes only the ADD-to-MUL patched ELF. Its report
labels that mode and records the actual number of fresh device executions.
The default command still reruns every example. Saved artifacts must pass
the same raw-trace/ELF/register/memory audits; missing evidence fails.
`tools/inventory.py` reads the selected ET Platform source, checks it against
the setup-recorded revision, and writes the decoder inventory to `out/isa/`.

That inventory currently finds 213 ET extension handler selectors. It includes
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
their selected arithmetic edge cases. This flag checks the implemented suites; the broader CPU
inventory still has explicit gaps and is not a claim of complete base-ISA coverage.
Both ordinary scalar-memory cases must also supply all 14 handlers with actual
access-width/address/value, register, control-state, and complete guard evidence.
Both branch/jump cases must supply all eight handlers, both conditional paths,
real next PCs, jump link and alias behavior, and complete guarded memory.
`out/isa/full-cpu-source-inventory.json` enumerates all active decoder functions,
excludes literal `#if 0` branches, and ties selectors to the separate execution
audits. It finds 353 handlers: 213 ET extensions, 28 scalar-FP handlers,
43 scalar-integer handlers, 14 ordinary scalar-memory handlers, eight
branch/jump handlers, and **47 handlers without dedicated per-operation audit coverage**.
Those 47 include two explicit microcode stubs (`fence.i`, `sfence.vma`).
The other 45 include ordinary base instructions, architectural trap handlers,
and reserved/illegal compressed handlers. These are handler counts, not a count
of distinct encodings or exhaustive test cases. Ordinary startup executes some
base instructions; incidental execution does not establish dedicated coverage.
The separate scalar-FP audit is `out/isa/scalar-fp-inventory.json`.
The scalar-integer audit is `out/isa/scalar-integer-inventory.json`.
The ordinary scalar-memory audit is `out/isa/base-memory-inventory.json`.
The branch/jump audit is `out/isa/branch-inventory.json`.
Dynamic CSR engine commands remain separate from these counts.
Without that flag, the inventory
can also be used before running examples to inspect the outstanding gaps.

To select another already installed tool prefix or container:

```sh
ET_PREFIX=/custom/et ./setup.sh                       # host install
ET_CONTAINER=my-et-container ET_CONTAINER_PREFIX=/opt/et ./setup.sh
```

`ET_PLATFORM_SOURCE` selects the ET Platform checkout; its default is
`$HOME/et-platform`. The setup script records the selected paths in
`out/setup/environment.json`. The examples read that record, while allowing
the same environment overrides. Ordinary example runs do not need `sudo`.
The Podman route is verified here. The host-prefix route remains untested;
its assembler-probe file-name error was corrected during review.
If the recorded container stopped after a host reboot, restart the same
installation with `podman start et-platform-rebuild` before running examples.
The recovered container's platform revision and simulator SHA-256 were checked
against the setup record, and its ET assembler/disassembler probe passed again.
Recovery commands and results are saved in `out/setup/container-recovery-*`.
On macOS, use a Linux VM or Linux container environment for the tools; this
repo does not attempt a native macOS simulator/toolchain port.

### Fresh installation

No fresh system or container installation was performed for this repo; the
working installation was already available. The verifier deliberately fails
if it cannot find compatible existing tools. For a new Ubuntu 24.04 x86-64
installation, follow the pinned [ET Platform build instructions](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/README.md)
and use the prebuilt toolchain asset recorded below. Before installing, choose
a new or intentionally empty prefix; do not unpack into an unrelated existing
installation. The following downloads and verifies the pinned toolchain
archive, but has not been run as part of this experiment:

```sh
ET_PREFIX=${ET_PREFIX:-/opt/et}
ASSET=$(mktemp /tmp/etsoc-toolchain.XXXXXXXX.tar.xz)
URL=https://github.com/aifoundry-org/riscv-gnu-toolchain/releases/download/2026.03.21/riscv64-elf-ubuntu-24.04-gcc-stripped.tar.xz
SHA256=e04a335de5f791a82ec0aed7c63d6458eef44d9e73477ac1ced03b9992fcb6fb
test ! -e "$ET_PREFIX" || { echo "Choose an empty prefix; refusing to overwrite $ET_PREFIX" >&2; exit 1; }
curl --fail --location --retry 3 "$URL" --output "$ASSET"
printf '%s  %s\n' "$SHA256" "$ASSET" | sha256sum --check
sudo install -d --owner "$(id -un)" --group "$(id -gn)" "$ET_PREFIX"
tar -xJf "$ASSET" --strip-components=1 -C "$ET_PREFIX"
```

Then install the Ubuntu dependencies listed in the pinned ET Platform README,
check out that Platform commit in a separate source directory, and build its
regular non-SDK configuration. The tested configuration was Release,
`SDK_RELEASE=OFF`, `BUILD_SHARED_LIBS=OFF`; it provides the standalone
`sys_emu` executable. Pick a conservative `JOBS` value based on the memory
limit, then run the full upstream install and this repo's `./setup.sh`:

```sh
ET_PLATFORM_SOURCE="$HOME/et-platform-836a4ab"
git clone https://github.com/aifoundry-org/et-platform.git "$ET_PLATFORM_SOURCE"
git -C "$ET_PLATFORM_SOURCE" checkout 836a4ab600e93c3059bb58c898edbc37744cd8d0
JOBS=${JOBS:-2}
cmake -S "$ET_PLATFORM_SOURCE" -B "$ET_PLATFORM_SOURCE/build" \
  -DTOOLCHAIN_DIR="$ET_PREFIX" -DCMAKE_INSTALL_PREFIX="$ET_PREFIX" \
  -DCMAKE_BUILD_TYPE=Release -DSDK_RELEASE=OFF -DBUILD_SHARED_LIBS=OFF
cmake --build "$ET_PLATFORM_SOURCE/build" --parallel "$JOBS"
cmake --install "$ET_PLATFORM_SOURCE/build"
ET_PLATFORM_SOURCE="$ET_PLATFORM_SOURCE" ET_PREFIX="$ET_PREFIX" ./setup.sh
```

This fresh-source recipe is documentation, not a claimed test result. The
upstream Dockerfile's `BUILD_JOBS` bounds its top-level make, but the current
`docker/get_toolchain.sh` source-build fallback invokes `make -j$(nproc)` on
its own. This run reused a prebuilt toolchain, so no build was started and no
parallel build limit was needed. If choosing a source toolchain build, account
for that nested command instead of assuming the top-level job limit controls
it. Current SysEmu CMake configuration requires `glog`, `lz4`, and
`erbium_hal`; it also checks for `libunwind` where configured.

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

### 8x8x8 GEMM

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
only executable section in these arithmetic ELFs. The M/U message-port
diagnostic uses two executable sections, described below. In ADD/MUL/SUB, C begins at
`0x8000100060` and the 160-byte monitored range also contains completion/trap
words and three register snapshots. GEMM has a larger monitor region sized
from its linked matrix output and snapshots. The scripts derive addresses
from ELF section headers and symbols rather than duplicating them in Python.

### Packed floating-point coverage

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

### Scalar floating-point coverage

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

### Scalar integer arithmetic

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

### Ordinary scalar memory

`base_memory.py` executes all 14 handlers from
[`arith_loadstore.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/arith_loadstore.cpp)
and [`float_loadstore.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/float_loadstore.cpp):
`lb`, `lbu`, `lh`, `lhu`, `lw`, `lwu`, `ld`, `sb`, `sh`, `sw`, `sd`, `flw`,
`fsw`, and `fence`. These are separate from the earlier coherent/atomic
`scalar_memory.py` suite. Both cases use aligned payloads in guarded 128-byte
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

### Ordinary branches and jumps

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

### Packed memory and atomics

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

### Scalar memory and atomics

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

### Cache-control CSRs

`cache_control.py` runs 37 labeled command/read sites in each of two cases.
It uses the same standalone minion layout and startup, disables address
translation and interrupts, installs a trap handler, and explicitly normalizes
cache mode through `mcache_control=1`, then `0`, then `ucache_control=0`.
It reads/modifies/writes the `minion_feature` ESR to clear feature-disable
bits 1, 2, 3 and 5, preserving the thread-1-disable and other unrelated bits.
The measured ESR is `0x11` before and after in this configuration.

| CSR | Address | Checked behavior |
| --- | --- | --- |
| `cache_invalidate` | `0x7d0` | Command executes; reads zero; execution continues |
| `mcache_control` | `0x7e0` | Modes 0, 1 and 3; rejected 0-to-3 and mode-2 writes; lock clearing |
| `ucache_control` | `0x810` | Machine-controlled bit 0; supported-bit masking; scratchpad on/off readback |
| `evict_sw`, `flush_sw` | `0x7f9`, `0x7fb` | Set/way wrap, tensor-mask selection, destination-zero skip, hard-lock behavior |
| `lock_sw`, `unlock_sw` | `0x7fd`, `0x7ff` | Actual 64-byte zeroing; duplicate way/address errors; unlock then successful relock |
| `prefetch_va` | `0x81f` | Actual 64-byte reads; stride, mask, destination selection and destination-3 skip |
| `evict_va`, `flush_va` | `0x89f`, `0x8bf` | Actual translated-address/action logs; mask, stride, destination-zero skip |
| `lock_va`, `unlock_va` | `0x8df`, `0x8ff` | Selected-line zeroing/translation; inactive lines preserved |
| `dcache_debug` | `0xfc0` | Actual read returns zero; it does not expose cache tags or lock state |

Primary uses tensor mask `0x000f` and stride 64; the second case changes all
input bytes, uses mask `0x0005`, stride 128, and another hard-lock way.
Low X31 bits are deliberately nonzero and verified to be excluded from the
effective stride. Every command has actual device-side readbacks of
`tensor_error`, machine/user cache control, the tensor mask, and its own CSR.
Those scalar register-write events must match the memory snapshots. Each
site also copies the hard-lock target line, checked against the actual scalar
load trace. The entire monitored memory region, including guards and inactive
lines, must match the reference.

Two deliberate duplicate locks report `tensor_error=0x20` without another
zeroing write. After unlock or a mode change, relocking succeeds and zeros a
refilled nonzero line. Each of the five VA command types also accesses the
reserved physical region at `0x0200000000`; the upstream command handler
reports `tensor_error=0x80` and returns. These are explicit error-feedback
checks, not arithmetic results. The program clears the error CSR before each
site and rejects unexpected errors. Architectural traps, missing completion,
cycle-watchdog expiry, and host timeout fail the run.

These instructions use the base RISC-V SYSTEM opcode `0x73`, with the CSR
address in bits `[31:20]`, rather than one of the packed arithmetic opcodes.
The pinned implementation is
[`zicsr.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/zicsr.cpp),
[`cache_control.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/cache_control.cpp),
and [`cache.h`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/cache.h).
The functional model zeros memory for lock commands and tracks hard locks.
It does not model soft-lock state or unlocked cache-line tags. Evict/flush
coverage therefore proves command selection and address/action handling,
not hardware cache traffic, coherence or timing. Fetch-buffer invalidation
is not directly exposed by the existing trace; the reported evidence is
limited to the command/readback and subsequent execution.

### Barriers, credits and stall

`synchronization.py` runs 23 primary and 24 second-case sites using `flb`
(`0x820`), `fcc` (`0x821`), `fccnb` (`0xcc0`), `stall` (`0x822`) and
`excl_mode` (`0x7d3`). The extra second-case site comes from its longer FLB
sequence. Every site snapshots actual before/after state, the scalar result,
`tensor_error`, exclusive mode, `mie`, `mip` and `mstatus`. Scalar register
events, CSR words in the ELF, snapshots and guarded output memory must agree.
The startup explicitly clears `mie`, `mip`, exclusive mode and tensor errors,
clears global MIE, and enables the ML feature while preserving unrelated ESR
bits. Completion still requires ETOK and a normal stop, with both watchdogs.

FLB state is initialized by actual ESR stores and observed through ESR reads.
The primary sequence uses barrier 3, limit 2; the second uses barrier 31,
limit 3. A write increments the counter unless its previous value equals the
limit, in which case it clears the counter and returns completion 1. The
barrier ID and limit occupy bits `[4:0]` and `[12:5]`; extra high operand bits
are ignored. A neighboring barrier holds a guard value checked at the end.
Two edge cases distinguish reaching limit 255 from overflowing the stored
8-bit counter: starting at 255 with limit 0 logs internal value 256, stores
counter 0 and returns completion 0. This is measured behavior of the pinned
[`write_flb`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/flb.cpp)
implementation, not a hardware conformance claim.

The device supplies its own FCC0/FCC1 credits by 64-bit stores to
`0x01003400c0`/`0x01003400c8`, with minion-mask bit 0 enabled. The two input
cases supply counts `(2,3)` and `(3,2)`, then consume credits in different
orders. `fcc` selects the counter from operand bit 0; `fccnb` reads
`(FCC1 << 16) | FCC0`. The checker verifies the actual ESR-store memory
event, receiver log, per-counter decrement log, and packed CSR readbacks.
No host credit injection is used. Consumes have credits available; zero-credit
blocking/wake and 16-bit credit overflow are not covered here.
The peer-synchronization example below covers those paths separately.

`stall` has three exercised paths. Exclusive mode makes it return immediately.
A device-generated software interrupt that is locally enabled but globally
masked also makes it return immediately. For a real wait, the program routes
the simulated PU timer to minion 0, resets/reads `mtime`, arms `mtimecmp`
8 or 12 ticks ahead, enables MTIE, and issues `stall`. The raw trace shows
Start/Stop waiting for interrupt and execution resuming with `mip[7]` set.
The measured operation-to-resume gaps are 734 and 1088 emulator cycles;
these are functional scheduler observations, not instruction latency or
hardware performance. Global MIE stays clear, so no architectural timer
trap is taken. Actual device stores disable the timer afterward.

The timer ESR addresses are derived from IO-shire ID 254 and its 22-bit shift:
`mtime=0x01ff800000`, `mtimecmp=0x01ff800008`; S0's target ESR is
`0x01c0340218`. These accesses use the actual ET-SOC1 implementation in
[`esrs_et.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/esrs_et.cpp),
[`zicsr.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/zicsr.cpp),
[`processor.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/processor.cpp),
and [`rvtimer.h`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/devices/rvtimer.h).
This is one-hart synchronization-state exploration; it does not verify a
multi-hart barrier, contention, message ports or tensor command engines.

### FCC wait/wake, overflow and peer FLB

`synchronization_peers.py` runs four cases through real credit synchronization
and ordered FLB arrivals. `primary` and `exact` use H0 receiving from H2
(two minions, one hardware thread each); `threads-primary` and `threads-exact`
use H1 receiving from H0 (both threads of one minion). The primary cases
select FCC0/barrier 3; exact cases select FCC1/barrier 31. Startup clears
interrupt state and tensor errors, installs a trap handler and enables ML
through a device-side feature ESR write. The input mask and bulk increment
count are loaded from ELF data on the device. Each exact case adds ignored
mask bit 63; the target still receives credits only through minion-mask bit 0.

The pinned `System::write_fcc_credinc` uses `index/2` to select the thread
within a minion and `index%2` to select its counter. All four routes are
validated against actual store addresses and receiving-hart counter logs:

| ESR index | Address | Receiver |
| --- | --- | --- |
| 0 | `0x01003400c0` | T0 FCC0 |
| 1 | `0x01003400c8` | T0 FCC1 |
| 2 | `0x01003400d0` | T1 FCC0 |
| 3 | `0x01003400d8` | T1 FCC1 |

The two-minion cases use `-single_thread -minions 0x3 -ls 0,0x5`.
The two-thread cases use `-minions 0x1 -ls 0,0x3` and omit `-single_thread`;
the current executable enables both hardware threads by default. Both modes
enable only shire 0 and disable the service processors. Run all four with
`python3 examples/synchronization_peers.py`, or pass the desired case names.

The two-minion sequence is:

| Phase | Actual result |
| --- | --- |
| Empty selected FCC | H0 waits and restarts the same CSR instruction; no destination write on the first attempt |
| H2 supplies the other counter | That counter gains one credit; H0 remains blocked |
| H2 supplies the selected counter | H0 wakes, retries, consumes it and returns zero |
| H0 consumes the other credit | Both counters are zero |
| Ordered FLB arrivals, limit 1 | H0 changes 0→1/returns 0; H2 changes 1→0/returns 1 |
| 65,535 real ESR stores | Selected counter reads `0xffff`, error zero |
| One more ESR store | Selected counter wraps to zero, `tensor_error=0x8` |
| Clear error, refill, consume | Error stays zero; selected counter changes 0→1→0 |

The FCC CSR address is `0x821`; the counter is selected by source-register
bit 0, with the extra operand bit 8 ignored. Unlike an empty message-port
head read, an empty FCC write throws the internal `instruction_restart`
before writing its destination. It does not return `-1` or take an
architectural trap. The destination sentinel and the two raw instruction
events prove this distinction. Both two-minion cases measured:

```text
cycle 49:  H0 PC 0x80000010c4, starts waiting for FCC0/FCC1; destination unchanged
cycle 186: H2 supplies the other counter; no wake
cycle 256: H2 supplies the selected counter; H0 stops waiting
cycle 257: H0 retries PC 0x80000010c4, decrements its credit and writes result zero
```

In the two-thread cases H0 first sends a credit to its own T0 counter and
captures/consumes that credit. H1 remains blocked. H0 then supplies H1's other
counter, which also does not wake H1. Only the matching T1 counter resumes
the receiver. Actual T0 and T1 FCCNB reads prove that these counters are
separate; host code does not supply credits or change a waiting hart.

Both two-thread cases measured:

```text
cycle 50:  H1 PC 0x80000010c8, starts waiting; destination unchanged
cycle 198: H0 supplies its own T0 counter; H1 remains waiting
cycle 243: H0 supplies the other T1 counter; no wake
cycle 313: H0 supplies the matching T1 counter; H1 stops waiting
cycle 314: H1 retries PC 0x80000010c8, consumes the credit and writes result zero
```

The overflow is not initialized through a debugger or patched simulator.
A device loop executes 65,535 stores at one labeled PC, followed by the
separately labeled overflow store. Every loop occurrence must have the actual
`sd` word, source mask, ESR address, memory-write event and ordered receiver
counter update. The raw 45/48 MB traces remain in `out/`; normalized JSON
retains the first/last bulk events and the independently checked count.
Eight seeded 128-byte records in each two-minion case, and ten in each
two-thread case, capture the real before/after counter or FLB
state, scalar result, tensor error, `mstatus`, `mie`, `mip`, and hart ID.
All register events, snapshots, guarded memory and references must agree.

Shared ready/phase/done flags establish the FLB arrival order; the final
counter and a neighboring barrier guard are checked by actual ESR loads.
The FLB CSR does not itself block the first arrival. This demonstrates the
counter/completion behavior across minions and between T0/T1; simultaneous
contention, memory coherence and hardware latency remain untested.
Both selected harts must park normally, the receiver must write ETOK, and unexpected
traps, the 500,000-cycle watchdog or host timeout fail the run.

These semantics come from pinned
[`zicsr.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/zicsr.cpp),
[`System::write_fcc_credinc`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/system.cpp),
[`flb.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/flb.cpp),
and [`processor.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/processor.cpp).
The overflow feedback is the upstream `uint16_t` wrap check setting tensor
error bit 3. No simulator instrumentation patch is used.

### Message ports

`message_ports.py` runs two 80-site FIFO cases on H0, two blocking cases with
H0 receiving and H2 sending, and two 60-site overcapacity/count-wrap cases on
H0. Each minion has one enabled hardware thread.
All traffic is produced by device instructions; the host does not inject a
message or force the receiver to resume.

| Interface | CSR/ESR addresses | Observed use |
| --- | --- | --- |
| `portctrl0..3` | `0x9cc..0x9cf` | Configure/reset, read control |
| `porthead0..3` | `0xcc8..0xccb` | Consume an available message; wait/retry when empty |
| `portheadnb0..3` | `0xccc..0xccf` | Consume or return `-1` immediately when empty |
| H0 port send ESRs | `0x0100000800 + 64*p` | Actual 64-bit device stores deliver 4/8-byte messages |

Port control contains enable bit 0, OOB-enable bit 1, U-mode-enable bit 4,
log2(message width) in `[7:5]`, capacity-minus-one in `[11:8]`, cache set in
`[23:16]`, and way in `[31:24]`. The pinned implementation clamps logsize to
2 through 5, reduces set modulo 16 and way modulo 4, discards other fields,
and reads bit 15 as one. Each FIFO case tests reserved/high write bits and width
clamping with a disabled port, then configures its working ring. Writing
control resets the queue pointers and discards any queued message; it does
not erase the backing data. No CSR exposes queue size/pointers. The register
reports contain actual scalar/CSR reads; FIFO/wrap evidence comes from real
sends, returned head offsets, payload loads and empty-read logs. The count-wrap
interpretation uses the complete send/head event sequence and pinned `uint8_t`
field, with its source identified separately from captured register values.

The primary case uses 4-byte messages, capacity 4 and cache way 1; the second
uses 8-byte messages, capacity 2 and way 2. Each port has its own hard-locked
64-byte backing line between two 64-byte guards. The ELF address determines
the cache set; startup normalizes cache mode and performs a real `lock_sw`.
The trace must show its 64-byte zero write and no unlocked-port warning.
Each port receives two messages before their ordered consumption, wraps its
write/read positions, handles an empty nonblocking read, discards a queued
message on reset, and drops a send while disabled. The five measured head
offsets are `[0,4,8,12,0]` and `[0,8,0,8,0]`. Per-site snapshots capture control
before/after, the returned scalar register, payload and address, tensor error,
cache mode and `mstatus`. All eight fields must match real register events
and output memory; the whole memory region, guards and input table are checked.

Both blocking cases use 8-byte messages. H0 sets a shared ready flag and
reads empty `porthead0`. H2 observes ready, delays, loads its payload from the
ELF data, and sends to H0's ESR. The measured sequence is:

```text
cycle 61:  H0 PC 0x80000010f4, porthead0 returns -1; Start waiting for message
cycle 199: H2 sends; H0 Stop waiting for message; actual port-buffer words written
cycle 200: H0 retries PC 0x80000010f4, returns offset 0, then loads its payload
payloads: 0x0123456789abcdef / 0xfedcba9876543210
```

Both harts park normally, receiver completion is ETOK, sender completion is
recorded, and unexpected traps or either watchdog fail the run. The 139-cycle
retry gap is a functional scheduler observation, not hardware latency.
`-ls 0,0x5` captures H0/H2; `-single_thread -minions 0x3 -shires 0x1 -sp_dis`
selects their execution. The initial ADD/MUL/GEMM runs remain single-hart.

`overflow-primary` and `overflow-exact` use 4-byte and 8-byte messages with
two slots on every port. Three real sends overwrite the oldest slot before
any head read. Three head reads then return offsets `[0,4,0]` or `[0,8,0]`,
with payloads `[third,second,third]`; the next nonblocking read returns `-1`.
This is the measured upstream behavior: it has no full-ring check, and the
message count can exceed the configured slot count.

After a queue reset, each port executes 255 stores at one labeled PC. A
nonblocking read returns offset zero and its actual payload, consuming one
message. One refill restores 255 outstanding messages; the next send wraps
the upstream 8-bit count to zero. A final nonblocking read returns `-1`,
although the latest two payloads remain in backing memory. `tensor_error`
reads zero throughout; no overflow trap or error bit is produced. Every
repeated instruction word, source input load, ESR write, destination data
write, head result, payload load and guarded snapshot is checked. Internal
count values are an interpretation of these events, not debugger reads.

Run all six cases with `python3 examples/message_ports.py`, or just the new
ones with `python3 examples/message_ports.py overflow-primary overflow-exact`.

The raw `Writing MSG_PORT` records expose the actual 32-bit data/address
writes; they are retained alongside the ESR-store event, scalar payload load,
final memory dump and normalized register report. SysEmu prints `lw` for
`lwu` in this revision; the checker verifies funct3=6 and the zero-extended
register result, while ET binutils correctly disassembles `lwu`. The empty
nonblocking read also prints `Blocking MSG_PORTNB`; the checker verifies that
it emits no message wait transition.

The authoritative paths are
[`msgport.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/msgport.cpp),
[`zicsr.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/zicsr.cpp),
[`esrs_et.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/esrs_et.cpp),
and [`SysregRegion`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/memory/sysreg_region.h).
The direct ESR path rejects message widths greater than 8; 16/32-byte
delivery requires another upstream engine path and remains unverified. OOB
enable is tested with zero OOB: the pinned direct and delayed delivery paths
both supply zero, and the inspected source has no nonzero minion producer.
Nonzero OOB has no execution proof. U-mode access is exercised by the separate
permission diagnostic below. No simulator patch is required.

### Message-port permissions in real U mode

`message_port_privilege.py` runs primary/exact cases with four-/eight-byte
messages. Each case executes 92 selected CSR, send and ECALL sites across all
four ports. It records 32 expected illegal-instruction faults, 12 U ECALL
phase exits and 20 successful head reads, including four empty nonblocking
reads. These fault counts describe this diagnostic; ordinary FIFO examples
still reject all traps.

For each port, the program configures and sends two messages in M mode with
the U-enable bit clear. It enters U through `mret` with `mstatus.MPP=U` and
interrupts disabled. Both head reads fault with `mcause=2`, linked `mepc` and
the actual instruction word in `mtval`. Their seeded x20 destinations remain
unchanged. After an explicit U ECALL exit, M reads return offsets 0 and the
message width with the original two payloads, proving denied reads did not
consume them. A second phase enables U access and verifies both successful
U heads and an empty nonblocking return of `-1`. Reading `portctrl` from U
still faults because its CSR address encodes a higher minimum privilege.
A third phase disables the port: both M and U heads fault without waiting,
even with its U-enable bit set.

The ELF has `.text` at `0x8000001000` for M code and `.text.user` at
`0x8004001000` for U code. Shared data starts at `0x8004100000`, in the
OS-box region that permits these accesses. The initial attempt used the
arithmetic link layout and took an instruction-access fault on the first U
fetch because that address lies in the protected machine box. The corrected
layout follows the pinned [`memmap.h`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/memmap.h)
and [`pma_et.cpp`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/pma_et.cpp)
without disabling protection. Every operation PC is translated through its
executable `PT_LOAD`; `text.bin` and `text-user.bin` preserve both sections.
The OS-box layout requires OS-box access to be enabled in the existing
machine protection configuration; actual fetches and memory accesses verify
this in the tested setup.

The trap handler captures `mcause`, `mepc`, `mtval` and `mstatus` before returning
from each expected fault. Illegal reads resume in their original mode; U ECALL
returns to an explicitly linked M continuation. Other fault causes record an
unexpected-trap diagnostic and park without setting completion. The host checks
actual `I(M)`/`I(U)` groups, `mret` privilege transitions, trap MPP bits,
destination writes/snapshots, sender and receiver memory accesses, payload
loads and every monitored byte/guard. An independent inventory audit repeats
those checks against ELF inputs and raw logs.

Run `python3 examples/message_port_privilege.py` for both cases. S-mode,
U-mode blocking/wake and read-only CSR write side effects remain unverified.

### Graphics extensions

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

### Unimplemented handlers and fault delivery

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

## Tested environment and provenance

| Component | Revision / observed version |
| --- | --- |
| ET Platform source and standalone SysEmu | `836a4ab600e93c3059bb58c898edbc37744cd8d0` |
| ET toolchain release | `2026.03.21`, source commit `b4f9cd542b162d1c0308ff9216ab7c2d09b89116` |
| Prebuilt toolchain asset | `riscv64-elf-ubuntu-24.04-gcc-stripped.tar.xz`; published SHA-256 `e04a335de5f791a82ec0aed7c63d6458eef44d9e73477ac1ced03b9992fcb6fb` |
| Compiler / binutils | GCC `15.2.0` (`g5115c7e44`), GNU Binutils `2.45` |
| Resolved executable prefix | `/opt/et/bin/riscv64-unknown-elf-` |
| Simulator | `/opt/et/bin/sys_emu`; regular Release build, `SDK_RELEASE=OFF`, `BUILD_SHARED_LIBS=OFF` |
| Host / runtime | Fedora 44 x86-64, 8 CPUs, 36 GiB RAM (29 GiB available), 377 GiB free disk, Podman 5.8.2; Ubuntu 24.04.5 x86-64 container with no explicit CPU/memory limit |

The upstream toolchain release digest is recorded, but its already-installed
archive was not present to rehash. `out/setup/installation.log` instead records
the installed simulator and GCC executable architectures and their own SHA-256
digests. The CMake cache and `sys_emu` link command are saved in
`out/setup/sysemu-build-config.log`; the actual `sys_emu --help` output is in
`out/setup/sys-emu-help.log` (that build prints help and returns status 1).

Reference revisions resolved on 2026-10-04:

| Reference | Commit |
| --- | --- |
| [allbilly/ane](https://github.com/allbilly/ane/tree/6838f343ff1e39bd28270302f7e25783a62b37c4) | `6838f343ff1e39bd28270302f7e25783a62b37c4` |
| [allbilly/rk3588](https://github.com/allbilly/rk3588/tree/c6944a6513de7c620aa51384f14dda257db4a574) | `c6944a6513de7c620aa51384f14dda257db4a574` |
| [llama.cpp `el_map_f32.c`](https://github.com/ggml-org/llama.cpp/blob/1537a0a8b2f8711d840878b0a0677ab2213c882c/ggml/src/ggml-et/et-kernels/src/el_map_f32.c) | `1537a0a8b2f8711d840878b0a0677ab2213c882c` |
| [llama.cpp `mul_mat_f32.c`](https://github.com/ggml-org/llama.cpp/blob/1537a0a8b2f8711d840878b0a0677ab2213c882c/ggml/src/ggml-et/et-kernels/src/mul_mat_f32.c) | `1537a0a8b2f8711d840878b0a0677ab2213c882c` |
| [llama.cpp `mul_mat_f32_matrix_engine.c`](https://github.com/ggml-org/llama.cpp/blob/836d57176dc699a726c55418e4f96b8ca628e1bf/ggml/src/ggml-et/et-kernels/src/mul_mat_f32_matrix_engine.c) | `836d57176dc699a726c55418e4f96b8ca628e1bf` |
| [GGML backend operation test gist](https://gist.github.com/marty1885/93e0ffec8d44f317f819ba3f6fc70200) | `bd32bde75108da1047f04110e3c78b17e3e0d688` |
| Local ET matrix-engine performance visualization repo | `2529391f38e2d931524cc2403e3740e7385e4822` |

The llama.cpp files are instruction/use references only and are not built or
copied. The linked matrix-engine kernel is TensorFMA32: it partitions 16x16x16
tiles across 32 compute shires and 32 minions per shire, issues tensor loads,
tensor FMA and stores, and can split/reduce K across minions. The accompanying
gist is GGML cross-backend operator test code, not a minion ISA reference.
The checked-in `gemm.py` remains a standalone minion `fmadd.ps` example; neither
the tensor-engine kernel nor PCIe/firmware launch path has been run here.
The startup provenance is pinned ET Platform
[`boot.S`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/examples/common/boot.S).
Source files inspected at the pinned Platform commit:

- [Platform README](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/README.md), [Dockerfile](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/docker/Dockerfile), [toolchain downloader](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/docker/get_toolchain.sh).
- [SysEmu CMake](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/CMakeLists.txt), [SysEmu README](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/README.md), [example Makefile](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/examples/Makefile), [common include](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/examples/common/include.mk), [boot.S](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/examples/common/boot.S), and [crt.S](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/examples/common/crt.S).
- SysEmu [argument parser/help](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/sys_emu/sys_emu_parse_args.cpp), [GDB stub](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/sys_emu/gdbstub.cpp), [packed-float implementation](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/packed_float.cpp), [instruction helpers](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insn_util.h), [processor state](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/processor.h), and [custom-3 decoder](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/processor.cpp).
- Memory and atomic implementations: [packed memory](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/packed_loadstore.cpp), [coherent packed memory](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/coherent_packed_loadstore.cpp), [packed atomics](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/packed_atomic.cpp), [scalar atomics](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/arith_atomic.cpp), and [coherent scalar stores](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/coherent_arith_loadstore.cpp).
- Graphics implementations: [packed graphics](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/packed_graphics.cpp), [scalar graphics](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/arith_graphics.cpp), [mask operations](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/packed_mask.cpp), [conversion rules](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/fpu/cvt.cpp), and [feature ESR](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/esrs_et.cpp).

In particular, current SysEmu help and CMake sources are used instead of
older README option names or example filenames.

## Results and artifacts

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
Together with scalar integer, ordinary scalar memory and branches, the current default driver has 48 device runs
per complete run. That expanded driver has not yet completed a fresh full
comparison. The saved-artifact audit mode labels its separate evidence explicitly.
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
The earlier setup and integration evidence
is retained; the full-platform integration test was not repeated for this
extension.

Generated outputs are ignored by Git and remain in `out/`:

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
- `out/isa/base-memory-completion-audit.json`: comparison audit of 45 saved
  example ELF executions and one fresh patched run, 428 artifact/upstream
  hashes, 23 repository source hashes, executable-section dumps, whole guarded
  output checks, and the independently verified single-byte ELF change.
  `out/isa/base-memory-checkpoint-audit.py` reproduces this artifact audit.
- `out/isa/scalar-integer-inventory.json`: all 43 handlers matched against the
  pinned definitions, independently decoded operation fields and arithmetic
  references, zero/overflow/overshift evidence, and artifact/source hashes.
- `out/isa/scalar-fp-inventory.json`: independently checked scalar-FP ELF,
  register events, references, six cause-30 faults, full memory, pinned source
  hashes, and both sets of artifact hashes.
- `out/isa/full-cpu-source-inventory.json`: active CPU decoder selectors with
  dedicated audit coverage and explicit remaining handlers; broader coverage
  is incomplete even when the implemented-suite gate passes.
- `out/isa/scalar-integer-completion-audit.json`: comparison audit of 43 saved
  example ELF executions plus one fresh patched run, all raw artifact/upstream
  hashes, both scalar-FP/integer cases, all executable section dumps, complete
  guarded outputs, and the single changed ADD ELF byte. Its mode is recorded
  explicitly; at that checkpoint the fresh full 44-run default comparison
  remained unrun. Its reports and comparison/patched evidence are preserved in
  `out/isa/checkpoints/before-base-memory/` and
  `out/compare/checkpoints/scalar-integer-completed/`.
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
