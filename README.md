# ET-SOC1 packed-FP instruction experiments

Small host-side Python drivers assemble a bare-metal ET-SOC1 minion program,
run that ELF in upstream `sys_emu`, and report the actual instruction bytes,
register trace, and output memory. The first pair keeps the device program
identical except for `fadd.ps` versus `fmul.ps`.

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
python3 tools/compare.py
```

Each example accepts optional case names (`primary` and `exact`); without
arguments it runs both. `tools/compare.py` reruns both examples and executes
the one-instruction patched ELF. A successful run reports `PASS` and exits
zero. Host Python and the standard library are the only Python dependencies.

To select another already installed tool prefix or container:

```sh
ET_PREFIX=/custom/et ./setup.sh                       # host install
ET_CONTAINER=my-et-container ET_CONTAINER_PREFIX=/opt/et ./setup.sh
```

`ET_PLATFORM_SOURCE` selects the ET Platform checkout; its default is
`$HOME/et-platform`. The setup script records the selected paths in
`out/setup/environment.json`. The examples read that record, while allowing
the same environment overrides. Ordinary example runs do not need `sudo`.
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

Both files are self-contained standard-library Python scripts. Each writes
and cross-assembles a visible `kernel.S` and `link.ld`, inspects the resulting
ELF with the ET `nm`, `readelf`, `objdump`, and `objcopy`, and runs it with the
upstream standalone `sys_emu -elf_load` interface. The simulator run enables
only minion 0 / shire 0 / thread 0 (`-minions 0x1 -shires 0x1 -single_thread`)
and disables the service processor.

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
reads record `mstatus` and `fcsr`; the operation trace records M0. This ties
the normalized `registers.json` report to a hart and PC without relying on
unavailable GDB names for ET mask state. `prestart.bin` proves the C sentinel
was loaded before execution; `output.bin` is the actual SysEmu memory dump
after execution. Raw trace, machine-readable register/result files, and
commands remain alongside the ELF.

The linker places `.text` at `0x8000001000`, `.data` at `0x8000100000`, and a
16 KiB `NOBITS` stack at `0x8000200000`. Because the trap handler is page
aligned, `.text` includes an alignment gap and the handler; `.text` is the
only executable section in these ELFs. C begins at `0x8000100060`; the
160-byte monitored data range also contains completion/trap words and the
three register snapshots. The scripts derive these addresses from ELF section
headers and symbols rather than duplicating them in Python.

## Measured ADD-to-MUL change

Both independently assembled operation words use the current SysEmu custom-3
decoder and GNU objdump decoder:

| Instruction | Word | Bytes in memory order | decoded funct7 |
| --- | --- | --- | --- |
| `fadd.ps f12,f10,f11,rne` | `0x00b5067b` | `7b 06 b5 00` | `0x00` |
| `fmul.ps f12,f10,f11,rne` | `0x10b5067b` | `7b 06 b5 10` | `0x08` |

Their XOR is `0x10000000`, changing bit 28 (bit positions count from LSB 0).
The pinned SysEmu decoder in `processor.cpp::dec_custom3` maps `funct7=0x00`
to `insn_fadd_ps` and `funct7=0x08` to `insn_fmul_ps`; opcode, register
fields, and `funct3` are equal. The measured `.text` sections differ only in
the four-byte operation. The whole ELF files are both 14,376 bytes and differ
in one byte at file offset `0x106b` (the high byte of that instruction).

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

The llama.cpp file is a syntax/use reference only and is not built or copied.
The startup provenance is pinned ET Platform
[`boot.S`](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/examples/common/boot.S).
Source files inspected at the pinned Platform commit:

- [Platform README](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/README.md), [Dockerfile](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/docker/Dockerfile), [toolchain downloader](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/docker/get_toolchain.sh).
- [SysEmu CMake](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/CMakeLists.txt), [SysEmu README](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/README.md), [example Makefile](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/examples/Makefile), [common include](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/examples/common/include.mk), [boot.S](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/examples/common/boot.S), and [crt.S](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/examples/common/crt.S).
- SysEmu [argument parser/help](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/sys_emu/sys_emu_parse_args.cpp), [GDB stub](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/sys_emu/gdbstub.cpp), [packed-float implementation](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insns/packed_float.cpp), [instruction helpers](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/insn_util.h), [processor state](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/processor.h), and [custom-3 decoder](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/sw-sysemu/processor.cpp).

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
```

The `exact` case passed for both operations, including MUL's negative zero
lane. `tools/compare.py` reports the measured words, XOR/bit position,
source/disassembly/register diffs, and patched-ELF execution result.

Generated outputs are ignored by Git and remain in `out/`:

- `out/setup/`: environment, revisions, versions, executable checksums,
  SysEmu help/build config, upstream smoke ELF/log, and integration-test log.
- `out/add/` and `out/mul/`: source, linker script, ELF, disassembly,
  `.text`, operation bytes, raw trace, register/result JSON, memory dumps,
  symbol/section inspection, and command logs. `exact/` contains the second
  deterministic case.
- `out/compare/`: textual source/disassembly/register diffs, decoder excerpt,
  whole-ELF and patch diffs, patched ELF, and patched execution evidence.

The first failed prestart-dump attempt is preserved in
`out/add/attempts/failed-prestart-dump/`; it exposed the hexadecimal radix of
SysEmu's `-dump_at_pc_size` argument. The initial compare-script import error is
preserved in `out/compare/attempts/missing-subprocess-import/`. Both were fixed
before the passing runs.
