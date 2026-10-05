# Cache control and communication

[Repository overview](../README.md) · [Example catalog](examples.md)

Device-side CSR commands and ESR accesses exercise cache state, barriers,
credits and message ports through standalone SysEmu. Their functional results
do not establish hardware traffic or timing.

- [Cache-control CSRs](#cache-control-csrs)
- [Barriers, credits and stall](#barriers-credits-and-stall)
- [FCC wait/wake, overflow and peer FLB](#fcc-waitwake-overflow-and-peer-flb)
- [Message ports](#message-ports)
- [Message-port permissions in U mode](#message-port-permissions-in-real-u-mode)

## Cache-control CSRs

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

## Barriers, credits and stall

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

## FCC wait/wake, overflow and peer FLB

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

## Message ports

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
selects their execution. The [ADD/MUL/GEMM runs](arithmetic.md) use one hart.

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

## Message-port permissions in real U mode

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
