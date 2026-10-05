# ET-SOC1 minion instruction experiments

Small Python drivers assemble bare-metal ET-SOC1 programs and execute them in
upstream SysEmu. Inspect the ELF, instruction bytes, real registers and output
memory, starting with eight-lane ADD/MUL and an 8×8×8 packed-FP GEMM.
Python runs on the host and computes references only for validation.

## Quick start

Use an existing ET-patched toolchain and standalone `sys_emu` in Linux.
`setup.sh` verifies a compatible installation and saves its configuration;
it does not download or install tools. The tested environment uses the
`et-platform-rebuild` Podman container and `/opt/et` inside it.
See [setup and provenance](docs/setup.md) for installation paths and revisions.

Run from the repository root:

```sh
./setup.sh
python3 examples/add.py
python3 examples/mul.py
python3 examples/gemm.py
```

Each example runs two deterministic input cases and reports `PASS` after
checking actual device execution. The Python drivers use the standard library.
Generated assembly, ELFs, traces, register JSON and memory dumps stay in ignored
`out/` directories. In `out/add/`, start with `kernel.S`, `kernel.asm`,
`registers.json` and `output.bin`.

## ADD → MUL

The two scripts keep the device startup, inputs, mask, registers and layout
identical, changing `fadd.ps f12,f10,f11,rne` to `fmul.ps f12,f10,f11,rne`.
The measured words are `0x00b5067b` and `0x10b5067b`: XOR `0x10000000`, bit 28.
The comparison tool also patches a copy of the ADD ELF with the assembled MUL
instruction and executes that copy to verify MUL results.

```sh
python3 tools/compare.py
python3 tools/inventory.py --require-complete
```

The comparison reruns all 23 example drivers plus the patched ELF. To audit
saved execution evidence and run only the patched copy, use
`python3 tools/compare.py --reuse`.
See [the arithmetic guide](docs/arithmetic.md) for startup, register capture,
encoding fields and ELF file-offset mapping.

## Verified scope

The recorded full comparison passed **54 fresh SysEmu executions**: 53 example
ELF cases and one patched ELF. All **353 selected CPU handlers** have dedicated
execution or expected-fault audits. Sixteen upstream microcode stubs are
verified cause-30 faults; their operations remain unimplemented.

ADD and MUL pass both input cases; GEMM checks all 64 output values using
64 device broadcasts and 64 packed `fmadd.ps` instructions per case. Setup,
register capture and the binary-patch experiment are verified in the
[recorded evidence](docs/verification.md).

These experiments explore minion instructions and architectural state.
Tensor/matrix-engine commands, PCIe/firmware integration and hardware
performance are outside the verified scope. Handler coverage is not exhaustive
operand, encoding or privilege coverage.

## Documentation

| Guide | Contents |
| --- | --- |
| [Setup and provenance](docs/setup.md) | Existing installation, fresh-install recipe, tested environment and pinned sources |
| [ADD, MUL and GEMM](docs/arithmetic.md) | Device programs, startup, memory layout, register capture and ELF patch |
| [Examples and coverage](docs/examples.md) | All 23 drivers, input cases, comparison modes and inventory checks |
| [Scalar and compressed CPU ISA](docs/cpu-isa.md) | Arithmetic, memory, branches, compressed instructions, CSR forms and privilege |
| [Packed, atomic and graphics ISA](docs/packed-isa.md) | Packed FP/integer, masks, memory, atomics, graphics and fault stubs |
| [Cache control and communication](docs/communication.md) | Cache CSRs, barriers, credits, peer synchronization and message ports |
| [Verification and artifacts](docs/verification.md) | Observed results, execution evidence and generated-file index |
| [Checkpoint history](docs/history.md) | Earlier milestones, archived audits and preserved diagnostics |
