# Setup and provenance

[Repository overview](../README.md) · [Example catalog](examples.md)

Run the commands from the repository root. Python stays on the host;
the ET toolchain and SysEmu run in Linux.

## Verify an existing installation

The tested setup already had a working ET Platform installation in a running
Podman container. `setup.sh` reuses and checks an existing installation; it
does not download, build, install, or overwrite software under `/opt/et`.

```sh
./setup.sh
```

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

## Fresh installation

No fresh system or container installation was performed for this repo; the
working installation was already available. The verifier deliberately fails
if it cannot find compatible existing tools. For a new Ubuntu 24.04 x86-64
installation, follow the pinned [ET Platform build instructions](https://github.com/aifoundry-org/et-platform/blob/836a4ab600e93c3059bb58c898edbc37744cd8d0/README.md)
and use the prebuilt toolchain asset recorded in this guide. Before installing, choose
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

## Tested environment and provenance

| Component | Revision / observed version |
| --- | --- |
| ET Platform source and standalone SysEmu | `836a4ab600e93c3059bb58c898edbc37744cd8d0` |
| ET toolchain release | `2026.03.21`, source commit `b4f9cd542b162d1c0308ff9216ab7c2d09b89116` |
| Prebuilt toolchain asset | `riscv64-elf-ubuntu-24.04-gcc-stripped.tar.xz`; published SHA-256 `e04a335de5f791a82ec0aed7c63d6458eef44d9e73477ac1ced03b9992fcb6fb` |
| Compiler / binutils | GCC `15.2.0` (`g5115c7e44`), GNU Binutils `2.45` |
| Resolved executable prefix | `/opt/et/bin/riscv64-unknown-elf-` |
| Simulator | `/opt/et/bin/sys_emu`; regular Release build, `SDK_RELEASE=OFF`, `BUILD_SHARED_LIBS=OFF` |
| Host / runtime | Fedora 44 x86-64, 8 CPUs, 36 GiB RAM (29 GiB available), 377 GiB free disk at setup, Podman 5.8.2; Ubuntu 24.04.5 x86-64 container with no explicit CPU/memory limit |

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
