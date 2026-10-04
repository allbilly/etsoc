#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
OUT="$ROOT/out/setup"
mkdir -p "$OUT"
PLATFORM_SOURCE=${ET_PLATFORM_SOURCE:-"$HOME/et-platform"}
HOST_PREFIX=${ET_PREFIX:-/opt/et}
CONTAINER_PREFIX=${ET_CONTAINER_PREFIX:-$HOST_PREFIX}
CONTAINER=${ET_CONTAINER:-et-platform-rebuild}
ET_RUN_IT_TEST=${ET_RUN_IT_TEST:-auto}

record() {
    local name=$1 limit=${2:-60} rc tmp
    shift 2
    local path="$OUT/$name.log"
    tmp=$(mktemp "$OUT/.${name}.XXXXXX")
    { printf 'COMMAND='; printf '%q ' "$@"; printf '\n'; } > "$path"
    if timeout --signal=TERM --kill-after=10s "${limit}s" "$@" > "$tmp" 2>&1; then rc=0; else rc=$?; fi
    cat "$tmp" >> "$path"
    printf 'EXIT_STATUS=%s\n' "$rc" >> "$path"
    cat "$path"
    rm -f "$tmp"
    RECORD_STATUS=$rc
}

{
    printf 'date=%s\n' "$(date --iso-8601=seconds)"
    printf 'uname=%s\narchitecture=%s\n' "$(uname -a)" "$(uname -m)"
    printf '\n--- /etc/os-release ---\n'; cat /etc/os-release
    printf '\n--- CPUs and memory ---\n'; nproc; free -h
    printf 'cgroup_memory_limit='; cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unavailable
    printf '\n--- filesystem space ---\n'; df -h "$ROOT" /opt
    printf '\n--- container tools ---\n'; command -v podman || true; command -v docker || true
    podman --version 2>&1 || true
} > "$OUT/host.txt"
cat "$OUT/host.txt"

if [[ ! -d "$PLATFORM_SOURCE/.git" ]]; then
    echo "ET Platform checkout not found at $PLATFORM_SOURCE (set ET_PLATFORM_SOURCE)." >&2
    exit 1
fi
PLATFORM_SHA=$(git -C "$PLATFORM_SOURCE" rev-parse HEAD)
{
    printf 'ET_PLATFORM_SOURCE=%s\nET_PLATFORM_COMMIT=%s\n' "$PLATFORM_SOURCE" "$PLATFORM_SHA"
    git -C "$PLATFORM_SOURCE" status --short --branch
    cat <<META
ET_TOOLCHAIN_RELEASE=2026.03.21
ET_TOOLCHAIN_COMMIT=b4f9cd542b162d1c0308ff9216ab7c2d09b89116
ET_TOOLCHAIN_ASSET=riscv64-elf-ubuntu-24.04-gcc-stripped.tar.xz
ET_TOOLCHAIN_ASSET_URL=https://github.com/aifoundry-org/riscv-gnu-toolchain/releases/download/2026.03.21/riscv64-elf-ubuntu-24.04-gcc-stripped.tar.xz
ET_TOOLCHAIN_ASSET_SHA256=e04a335de5f791a82ec0aed7c63d6458eef44d9e73477ac1ced03b9992fcb6fb
ET_TOOLCHAIN_CONFIGURE=--prefix=${CONTAINER_PREFIX} --with-arch=rv64imfc --with-abi=lp64f --with-languages=c,c++ --with-cmodel=medany
ET_TOOLCHAIN_NOTE=published release digest; installed archive unavailable for rehash; installed sys_emu and gcc binary digests recorded below
STYLE_ANE_COMMIT=6838f343ff1e39bd28270302f7e25783a62b37c4
STYLE_RK3588_COMMIT=c6944a6513de7c620aa51384f14dda257db4a574
INSTRUCTION_LLAMA_CPP_COMMIT=1537a0a8b2f8711d840878b0a0677ab2213c882c
META
} > "$OUT/revisions.txt"

KIND= PREFIX= TOOL_PREFIX= SIMULATOR=
if [[ -x "$HOST_PREFIX/bin/sys_emu" ]]; then
    KIND=host PREFIX=$HOST_PREFIX SIMULATOR="$HOST_PREFIX/bin/sys_emu"
    for stem in riscv64-unknown-elf- riscv-unknown-elf-; do
        if [[ -x "$HOST_PREFIX/bin/${stem}as" && -x "$HOST_PREFIX/bin/${stem}gcc" && -x "$HOST_PREFIX/bin/${stem}objdump" ]]; then
            TOOL_PREFIX="$HOST_PREFIX/bin/$stem"; break
        fi
    done
elif command -v podman >/dev/null && podman container exists "$CONTAINER" && \
     podman exec "$CONTAINER" test -x "$CONTAINER_PREFIX/bin/sys_emu"; then
    KIND=podman PREFIX=$CONTAINER_PREFIX SIMULATOR="$CONTAINER_PREFIX/bin/sys_emu"
    for stem in riscv64-unknown-elf- riscv-unknown-elf-; do
        if podman exec "$CONTAINER" test -x "$CONTAINER_PREFIX/bin/${stem}as" && \
           podman exec "$CONTAINER" test -x "$CONTAINER_PREFIX/bin/${stem}gcc" && \
           podman exec "$CONTAINER" test -x "$CONTAINER_PREFIX/bin/${stem}objdump"; then
            TOOL_PREFIX="$CONTAINER_PREFIX/bin/$stem"; break
        fi
    done
else
    echo "No ET installation at $HOST_PREFIX or running container '$CONTAINER'." >&2
    echo 'Set ET_PREFIX for host tools or ET_CONTAINER and ET_CONTAINER_PREFIX for a running Podman container.' >&2
    exit 1
fi
[[ -n "$TOOL_PREFIX" ]] || { echo "No supported riscv-unknown-elf or riscv64-unknown-elf tool prefix below $PREFIX/bin." >&2; exit 1; }
BIN_DIR=${TOOL_PREFIX%/*}
{
    printf 'runtime=%s\nprefix=%s\ncontainer=%s\ntool_prefix=%s\nsimulator=%s\nplatform_commit=%s\n' \
        "$KIND" "$PREFIX" "$CONTAINER" "$TOOL_PREFIX" "$SIMULATOR" "$PLATFORM_SHA"
} >> "$OUT/revisions.txt"
python3 - "$OUT/environment.json" "$KIND" "$PREFIX" "$CONTAINER" "$TOOL_PREFIX" "$SIMULATOR" "$PLATFORM_SHA" <<'PY'
import json, sys
path, kind, prefix, container, tool_prefix, simulator, commit = sys.argv[1:]
with open(path, "w") as f:
    json.dump({"kind": kind, "prefix": prefix, "container": container,
               "tool_prefix": tool_prefix, "simulator": simulator,
               "platform_commit": commit}, f, indent=2)
    f.write("\n")
PY
if [[ "$KIND" == podman ]]; then EXEC=(podman exec "$CONTAINER"); else EXEC=(); fi

if [[ "$KIND" == podman ]]; then
    record container-platform-revision 30 "${EXEC[@]}" bash -lc 'git -C /workspace rev-parse HEAD; git -C /workspace status --short --branch'
    [[ $RECORD_STATUS -eq 0 ]] && grep -Fq "$PLATFORM_SHA" "$OUT/container-platform-revision.log" || {
        echo 'The running container source revision differs from ~/et-platform.' >&2; exit 1;
    }
fi

SOURCE_FILES=(
    sw-sysemu/CMakeLists.txt
    sw-sysemu/README.md
    sw-sysemu/examples/Makefile
    sw-sysemu/examples/common/include.mk
    sw-sysemu/examples/common/boot.S
    sw-sysemu/examples/common/crt.S
    sw-sysemu/sys_emu/sys_emu_parse_args.cpp
    sw-sysemu/sys_emu/gdbstub.cpp
    sw-sysemu/insns/packed_float.cpp
    sw-sysemu/insn_util.h
    sw-sysemu/processor.h
    sw-sysemu/processor.cpp
)
record host-sysemu-source-files 30 bash -lc 'cd "$1" && shift && sha256sum "$@"' _ "$PLATFORM_SOURCE" "${SOURCE_FILES[@]}"
[[ $RECORD_STATUS -eq 0 ]] || exit 1
grep -E '^[0-9a-f]{64}  ' "$OUT/host-sysemu-source-files.log" > "$OUT/host-sysemu-source-hashes.txt"
if [[ "$KIND" == podman ]]; then
    record container-sysemu-source-files 30 "${EXEC[@]}" bash -lc 'cd /workspace && sha256sum "$@"' _ "${SOURCE_FILES[@]}"
    [[ $RECORD_STATUS -eq 0 ]] || exit 1
    grep -E '^[0-9a-f]{64}  ' "$OUT/container-sysemu-source-files.log" > "$OUT/container-sysemu-source-hashes.txt"
    diff -u "$OUT/host-sysemu-source-hashes.txt" "$OUT/container-sysemu-source-hashes.txt" > "$OUT/sysemu-source-hash-diff.txt" || {
        echo 'ET Platform SysEmu source files differ between host checkout and simulator container.' >&2; exit 1;
    }
fi

record installation 30 "${EXEC[@]}" bash -lc 'cat /etc/os-release; printf "\\nCPU: "; uname -m; printf "\\nExecutables: "; file "$1" "$2"; printf "\\nChecksums: "; sha256sum "$1" "$2"' _ "$SIMULATOR" "${TOOL_PREFIX}gcc"
[[ $RECORD_STATUS -eq 0 ]] || exit 1
record gcc-version 30 "${EXEC[@]}" "${TOOL_PREFIX}gcc" --version
[[ $RECORD_STATUS -eq 0 ]] || exit 1
record assembler-version 30 "${EXEC[@]}" "${TOOL_PREFIX}as" --version
[[ $RECORD_STATUS -eq 0 ]] || exit 1
record linker-version 30 "${EXEC[@]}" "${TOOL_PREFIX}ld" --version
[[ $RECORD_STATUS -eq 0 ]] || exit 1
record disassembler-version 30 "${EXEC[@]}" "${TOOL_PREFIX}objdump" --version
[[ $RECORD_STATUS -eq 0 ]] || exit 1

cat > "$OUT/toolchain-probe.S" <<'ASM'
.option norvc
.text
.globl probe
probe:
    fadd.ps f12, f10, f11, rne
    fmul.ps f12, f10, f11, rne
ASM
STAGE="/tmp/etsoc1-setup-$RANDOM-$$"
if [[ "$KIND" == podman ]]; then
    record probe-stage 30 "${EXEC[@]}" mkdir -p "$STAGE"
    [[ $RECORD_STATUS -eq 0 ]] || exit 1
    record probe-copy 30 podman cp "$OUT/toolchain-probe.S" "$CONTAINER:$STAGE/probe.S"
    [[ $RECORD_STATUS -eq 0 ]] || exit 1
    record assembler-probe 60 "${EXEC[@]}" bash -lc 'cd "$1" && "$2as" --march=rv64imfc -mabi=lp64f -o probe.o probe.S && "$2objdump" -d probe.o > probe.asm && cat probe.asm' _ "$STAGE" "$TOOL_PREFIX"
    [[ $RECORD_STATUS -eq 0 ]] || exit 1
    record probe-artifacts-copy 30 podman cp "$CONTAINER:$STAGE/." "$OUT/"
    [[ $RECORD_STATUS -eq 0 ]] || exit 1
    record probe-cleanup 30 "${EXEC[@]}" rm -rf "$STAGE"
else
    record assembler-probe 60 bash -lc 'cd "$1" && "$2as" --march=rv64imfc -mabi=lp64f -o probe.o toolchain-probe.S && "$2objdump" -d probe.o > probe.asm && cat probe.asm' _ "$OUT" "$TOOL_PREFIX"
fi
[[ $RECORD_STATUS -eq 0 ]] || exit 1
grep -q 'fadd.ps' "$OUT/assembler-probe.log" && grep -q 'fmul.ps' "$OUT/assembler-probe.log" || {
    echo 'The selected toolchain did not assemble and decode both packed instructions.' >&2; exit 1;
}

# Help deliberately reports a nonzero status in this SysEmu build; preserve it
# and validate the actual option text instead of assuming the exit convention.
record sys-emu-help 30 "${EXEC[@]}" "$SIMULATOR" --help || true
grep -q 'ET System Emulator' "$OUT/sys-emu-help.log" && grep -q -- '-elf_load' "$OUT/sys-emu-help.log" || {
    echo 'sys_emu help did not expose the standalone ELF interface.' >&2; exit 1;
}
if [[ "$KIND" == podman ]]; then
    record sysemu-build-config 30 "${EXEC[@]}" bash -lc 'd=/workspace/build/sw-sysemu-prefix/src/sw-sysemu-build; grep -E "^(CMAKE_BUILD_TYPE|CMAKE_INSTALL_PREFIX|SDK_RELEASE|BUILD_SHARED_LIBS):" "$d/CMakeCache.txt"; cat "$d/CMakeFiles/sys_emu.dir/flags.make"; cat "$d/CMakeFiles/sys_emu.dir/link.txt"; test -x /opt/et/bin/sys_emu; grep -q "SDK_RELEASE:BOOL=OFF" "$d/CMakeCache.txt"'
    [[ $RECORD_STATUS -eq 0 ]] || { echo 'No regular non-SDK SysEmu build configuration found.' >&2; exit 1; }
fi

# Build and run the current upstream ET-SOC1 test before our examples.
if [[ "$KIND" == podman ]]; then
    record upstream-standalone 120 "${EXEC[@]}" bash -lc 'set -euo pipefail; mkdir -p /tmp/etsoc1-upstream; make -C /workspace/sw-sysemu/examples RISCV="$1" BUILD_DIR=/tmp/etsoc1-upstream COMPILE_OPT=-O0 /tmp/etsoc1-upstream/etsoc1_test.elf; "$2" -l -lm 0 -lt 0 -sp_dis -reset_pc 0x8000001000 -single_thread -minions 0x1 -shires 0x1 -max_cycles 100000 -elf_load /tmp/etsoc1-upstream/etsoc1_test.elf' _ "$BIN_DIR" "$SIMULATOR"
else
    record upstream-standalone 120 bash -lc 'set -euo pipefail; mkdir -p /tmp/etsoc1-upstream; make -C "$1/sw-sysemu/examples" RISCV="$2" BUILD_DIR=/tmp/etsoc1-upstream COMPILE_OPT=-O0 /tmp/etsoc1-upstream/etsoc1_test.elf; "$3" -l -lm 0 -lt 0 -sp_dis -reset_pc 0x8000001000 -single_thread -minions 0x1 -shires 0x1 -max_cycles 100000 -elf_load /tmp/etsoc1-upstream/etsoc1_test.elf' _ "$PLATFORM_SOURCE" "$BIN_DIR" "$SIMULATOR"
fi
[[ $RECORD_STATUS -eq 0 ]] || { echo 'Upstream ET-SOC1 standalone smoke failed; see out/setup/upstream-standalone.log.' >&2; exit 1; }
grep -Fq 'addi x31,x0,1453' "$OUT/upstream-standalone.log" && \
    grep -Fq 'x31 = 0x5ad' "$OUT/upstream-standalone.log" && \
    grep -Fq 'Finishing emulation' "$OUT/upstream-standalone.log" && \
    ! grep -Fq 'Error, max cycles reached' "$OUT/upstream-standalone.log" || {
        echo 'Upstream smoke lacks expected instruction/register/completion evidence.' >&2; exit 1;
    }
if [[ "$KIND" == podman ]]; then
    record upstream-elf-copy 30 podman cp "$CONTAINER:/tmp/etsoc1-upstream/etsoc1_test.elf" "$OUT/upstream-etsoc1_test.elf"
    [[ $RECORD_STATUS -eq 0 ]] || exit 1
fi

HAS_IT_TEST=false
if [[ -x "$PREFIX/bin/it_test_code_loading" ]]; then
    HAS_IT_TEST=true
elif [[ "$KIND" == podman ]] && podman exec "$CONTAINER" test -x "$PREFIX/bin/it_test_code_loading"; then
    HAS_IT_TEST=true
fi
if [[ "$HAS_IT_TEST" == true ]]; then
    if [[ "$ET_RUN_IT_TEST" == 1 ]] || \
       { [[ "$ET_RUN_IT_TEST" == auto ]] && ! grep -Fq '[  PASSED  ]' "$OUT/it_test_code_loading.log" 2>/dev/null; }; then
        if [[ "$KIND" == podman ]]; then
            record it_test_code_loading 1230 "${EXEC[@]}" timeout --signal=TERM --kill-after=30s 1200s "$PREFIX/bin/it_test_code_loading"
        else
            record it_test_code_loading 1230 timeout --signal=TERM --kill-after=30s 1200s "$PREFIX/bin/it_test_code_loading"
        fi
        [[ $RECORD_STATUS -eq 0 ]] && grep -Fq '[  PASSED  ]' "$OUT/it_test_code_loading.log" || {
            echo 'it_test_code_loading failed or lacked its passing summary.' >&2; exit 1;
        }
    else
        printf 'Reusing recorded passing integration result: %s\n' "$OUT/it_test_code_loading.log"
    fi
fi

printf '\nSETUP_VERIFIED runtime=%s prefix=%s compiler=%s simulator=%s\n' "$KIND" "$PREFIX" "$TOOL_PREFIX" "$SIMULATOR"
printf 'Commands, statuses, versions, and smoke logs are in %s\n' "$OUT"
