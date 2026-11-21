# Hardware-backed kernel memory at EL0

The [pretranslated ELF backend](el0-pretranslated-memory.md) moves initial RAM
and resolved hardware tables into ELF loadable data and removes ordinary kernel
RAM wrappers plus 43 proven user memory sites. It passes the full workload with
no external page-table file, reducing runtime instructions to 17,086,418 and
the ratio to 5.6183:1. The required 0.20:1 ceiling remains unmet.

The separately selectable [native kernel-stack backend](el0-native-stack.md)
now lets ordinary kernel SP arithmetic and SP-relative loads/stores execute
their original instructions. It passes the full EL0 workload and reduces the
runtime ratio from 27.1518:1 to 21.5838:1. The 0.20:1 ceiling remains unmet.
The logical-stack backend described below remains available; select the new
backend with `--hardware-memory --native-kernel-stack`.

The complete executor has an optional `--hardware-memory` backend. It uses the
captured QEMU kernel mappings to construct EL0-accessible hardware aliases of
canonical RAM. Eligible kernel loads and stores execute natively without
entering the context gateway or walking the captured page tables in software.
Stack-pointer arithmetic also executes inline, including when application code
uses its logical stack. User memory and explicit user-copy accesses can execute
without a context gateway after inline checks of the live captured page tables.
Supported shadow-register reads/writes and indirect
calls, branches and returns also bypass the gateway. The actual SP remains
private to the runtime. Hardware-backed kernel exclusive windows and prefetch
hints now use the same direct path.

The aliases point to `flat_phys + captured_pa - ram_base`. Multiple virtual
aliases therefore refer to the same physical bytes used by the software path,
kernel page tables, allocator and validation. Physical UART/device addresses
are excluded. Read-only mappings remain read-only; the inline store ranges also
exclude every physical alias of admitted immutable code.

## Execution contract

The processor model establishes the hardware tables before ELF entry. Its
initialization can use privileged operations; the delivered checkpoint does not.
After entry, startup, user instructions, captured kernel computation, adapters
and validation all execute at EL0. The QEMU runner retains
`qemu-exceptions.log` and checks that its only event is the setup return from
EL1 to the ELF entry at EL0. It also verifies EL0t at entry and completion and
stops before the optional terminal exit. The validation report binds the log
by SHA-256 and reports `el0_interval_verified`. Ordinary memory operations use
the hardware MMU after an inline range/mode check, preserving scratch registers and NZCV on
the private stack. Pre/post-index writeback is handled inline. No adaptation is
inserted inside an exclusive window. Exclusive guards check the complete range,
write permission and alignment before its load. The original single/paired
exclusive sequence then runs intact; fall-through and conditional exits restore
scratch registers and the private stack while retaining comparison flags.
Prefetch hints retain their native instructions.

Shadow-only architectural operations preserve the shared emulator's field and
counter behavior without saving the full context. Operations requiring platform
actions retain their handler. Generic reads and plain writes check the live
known-register bitmap before accessing shadow values; unknown registers and
ordered counter inputs keep their handlers. PSTATE updates preserve the shared
emulator's DAIF/PAN behavior. Cache/TLB maintenance whose callbacks are empty
in this executor only increments the emulation count inline; address translation
and unsupported SYS encodings keep their handlers.

DC ZVA uses a writable-RAM guard and aligns to the captured block size. Model
setup checks the actual DCZID geometry before ELF entry; a mismatch stops before
any checkpoint instruction executes. User-mode, immutable-code and unmapped
zeroing keep the checked software path. Indirect branches search the admitted original-PC
table inline and enter a small resume thunk that restores all scratch registers,
NZCV and the private stack. BLR retains the original return PC, including when
its target register is X30. Missing targets restore the original context before
entering the existing diagnostic path. Neither lookup nor branch selection uses
recorded outcomes.

Address-discriminator TBZ/TBNZ sites check the captured lowered-address ranges
inline. Values outside those ranges retain their original bit test. A lowered
pointer uses the kernel discriminator value; an unreviewed bit-63 pointer test
restores the original registers, flags and stack before entering the existing
diagnostic handler. Successful paths update the emulation count exactly once.

A software-checked single memory access completes inline after its native
instruction. The completion restores the saved scratch register and applies
pre/post-index writeback, including logical SP, without a second context gateway.
Translation, permission, alignment and immutable-code checks still precede the
access. Exclusive windows keep their existing completion handlers; eligible
UART accesses use the inline register-buffer path described below. No completion runs when the initial check faults or skips a hint.

Eligible kernel UART loads/stores execute against the existing emulated register
buffer, and data-register writes append the observed low byte to the same UART
output ledger inline. User privilege, widths above four bytes, unsupported
register offsets and a full output ledger retain the checked handler. Reads are
admitted only at offset 0x18; writes only at offsets zero and 0x38. Indexed
writeback, scalar/SIMD results, registers and NZCV are preserved. The exporter
only enables this path when the dedicated UART mapping has no captured static
mapping collision, and the live configured address must still match. No physical
UART access or runtime EL1 service is introduced.

Logical SVC entry runs inline after checking user mode, supported PSTATE,
event capacity and the admitted exception-vector target. It appends the same
syscall number and six arguments to the event ledger, records the return PC and
syndrome, preserves FAR, switches the logical stack and enters the captured
kernel vector. Registers and NZCV are preserved. Rejected inputs restore the
original context before using the existing handler. This does not model syscall
results: the captured kernel still executes the syscall. ERET remains emulated,
including its user-code mapping validation.

The syscall-result observation hook also runs inline when its saved result slot
is naturally aligned and wholly inside an admitted kernel read range. It copies
the result into the same event record, marks completion and clears the pending
event. Unaligned, unmapped and out-of-range slots retain the checked translation
handler. An empty pending event preserves all state and continues normally.

User loads/stores and explicit user-copy accesses follow the current captured
TTBR0 in generated EL0 code. The fast path supports 4 KiB tables with 25–48 VA
bits and L1/L2 block mappings. It checks AF, leaf and inherited table access
permissions, RAM backing, alignment requirements and physical aliases of
immutable AOT text. Static kernel/device VA ranges are excluded while holes
between those ranges remain eligible user addresses, including the user stack.
Every access reads fresh PTEs, so leaf replacement, changed TTBR0 and permission
changes are visible without a translation cache or TLB service.

A successful single-page access executes its native load/store against canonical
RAM, restores scratch registers and applies logical writeback inline. This is
inline software address translation followed by a native memory instruction;
it does not install hardware mappings at the original user VA. Such hardware
mapping updates and TLB invalidations remain outside the no-EL1-service contract.
Cross-page, invalid, denied, missing-RAM and unsupported cases restore the input
context before entering the existing software handler. Actual page-fault handling,
device inputs and unsupported operations retain their handlers. Exclusive windows
without a safe direct mapping or sufficient scratch registers retain that path.
The existing workload's demand faults are detected in software and execute the
captured kernel fault path. They do not cause hardware exceptions. Eliminating
those kernel fault computations would change the captured workload.

The hardware run reproduced all 2,272 events, nine counter inputs and 92 UART
bytes with zero hardware exceptions. Its 2,549 gateway entries are down from
approximately 2,261,577 in the software backend, a reduction of about 99.9%.
Inline user translation removes 19,601 entries from the previous 24,587-entry
executor, a further 79.7% reduction. Ordinary user-memory pre-entries fall from
14,822 to 136 and explicit user-copy pre-entries from 4,964 to 49. Successful
accesses preserve their live translation and permission checks inline. Logical
syscall entry then removes another 2,136 gateways from 4,986 (42.8%) while
retaining all event recording and executing the captured kernel vector. Inline
UART register-buffer operations and output recording remove another 301 entries
from 2,850 (10.6%), preserving all 92 output bytes.

| Gateway operation | First hardware backend | Current backend |
| --- | ---: | ---: |
| Memory | 91,119 | 216 |
| Architectural | 106,662 | 2,332 |
| Indirect call/branch/return | 87,906 | 0 |
| Syscall, result observation and completion | 4,272 | 1 |
| Total | 289,959 | 2,549 |

The validation artifact is linked below. These are gateway counts, not
instruction or cycle counts; they do not establish a processor timing speedup.

The preceding image's separately measured execution interval contains 95,236,615
runtime/adaptation instructions and 3,041,214 original kernel operation visits:
**31.3153:1**. There are 2,817,604 native kernel payload instructions and 131,951
native application payload instructions. Startup and final validation increase
the whole-ELF runtime/kernel-operation ratio to 105.7026:1. These measurements
include the existing `PROFILE=1` bookkeeping. See
[dynamic instruction measurements](el0-instruction-profile.md) for definitions,
per-instruction counting, evidence and reproduction commands.

The current image adds a per-site indirect-target cache filled by the immutable
PC-table lookup. Hits compare the live original target and preserve all guest
registers and flags; changed/unknown targets retain the checked lookup. It
reduces runtime instructions to **82,574,553**, a **13.30%** reduction, and the
execution ratio to **27.1518:1**. All workload checks still pass. The required
ceiling is **0.20:1**, with a **0.10:1** target; both remain unmet. The instruction
budget check rejects the current image despite successful functional validation.

## Build and validate

Export from the existing captured package and independent reference:

```sh
python3 tools/export_el0_program.py \
  --package build/native-application-20261109a \
  --vmlinux build/linux-kernel-clang19-20261108/vmlinux \
  --user-elf build/linux-svc-machine-checkpoint-random-fault-20261108a/init \
  --oracle build/native-application-oracle-20261109b \
  --coverage build/el0-program-reference-code-20261109a.log \
  --hardware-memory --out build/my-hardware-executor

# On the existing AArch64 Linux toolchain host:
make -C runtime/el0_flat CC=clang-19 \
  OUT="$PWD/build/my-hardware-runtime" \
  IMAGE="$PWD/build/my-hardware-executor" program

python3 tools/el0_hardware_model.py prepare \
  --image build/my-hardware-executor --out build/my-hardware-model
python3 tools/el0_hardware_model.py run \
  --image build/my-hardware-executor --prepared build/my-hardware-model \
  --out build/my-hardware-validation
```

The existing LLVM 16 toolchain can also cross-build locally using
`CC='/opt/homebrew/opt/llvm@16/bin/clang --target=aarch64-none-elf'`.
Preparation defaults to the same LLVM directory; `--llvm` selects another one.

Preparation audits the ELF, binds the mapping metadata to the export, constructs
`page-tables.bin`, and writes `hardware-load-plan.json`. The plan specifies normal
RAM extents, ELF initialization, page-table bytes, initial architectural controls,
EL0 entry, completion PC and the RAM result. The current QEMU setup uses 2 GiB
of RAM and 4 KiB pages. It is separate from the older software-memory load plan;
Linux native and QEMU application-mode loaders cannot provide these aliases.

`setup.elf` is a QEMU initialization fixture, not an EL1 execution monitor. It
installs the declared tables and enters the checkpoint once. Every subsequent
exception vector stops rather than services or resumes the computation. The
runner checks EL0 at entry and completion and reads the embedded result before
terminal exit. A removed kernel alias is a negative regression: it must reach
the unexpected-exception stop and fail validation.

Current artifacts:

- [Executor](../build/el0-hardware-memory-20261113i/checkpoint)
- [Model load plan](../build/el0-hardware-model-20261113i/hardware-load-plan.json)
- [Functional validation](../build/el0-hardware-validation-20261113i/validation.json)
- [Gateway and memory profile](../build/el0-hardware-validation-20261113i/validation.json)
- [Dynamic instruction profile and budget assessment](../build/el0-instruction-profile-20261113b/counts.json)

To collect a gateway profile, build a separate export with `PROFILE=1` and a
fresh runtime `OUT` directory. The existing result ABI's diagnostic words hold
the marker and per-kind counts; the system runner emits `gateway_profile` and
checks that its sum equals the total entries. An optional RAM buffer supplies
`memory_profile`, separating user, kernel, user-copy, exclusive and hint
pre-entries from post-entries. Their sum must match the gateway memory count;
UART/fault counts are overlapping diagnostics. Exclusive pre-entries fell from
13,429 to five, and hint pre-entries from 12,236 to 21. Default builds compile
the counters out. The previous profiled and default executors both reproduced
the complete workload; the current validation artifact uses profiling. The
remaining architectural entries are 2,320 exception returns, nine ordered
counter reads and three platform register writes. All 2,483 address-discriminator
branches bypass the gateway in this workload; ambiguous pointer diagnostics
remain available for other inputs. Memory completion entries fell from 19,820
to five exclusive-window completions. All 209 UART pre-entries and 92 UART-output
completion entries now execute inline. Memory pre-entries total 211: 136 user,
49 user-copy, five exclusive and 21 hint entries. The previous user-memory gateway entries now
execute their successful translation and access checks inline. All 2,135 syscall
result observations now complete inline while preserving the existing event
records and validation. All 2,136 syscall entries also run inline; the final
completion boundary retains one gateway entry. ERET remains on the shared
emulator, accounting for 2,320 of the remaining 2,549 gateways.

The target-independent tests are registered as `el0_hardware` in CTest.
`el0_uart` runs 24,192 cases checking the full register buffer and output ledger,
byte/halfword/word and SIMD operations, sign extension and the zero register,
indexed/register-offset/logical-SP addressing, NZCV, privilege rejection,
changed UART configuration, forbidden offsets and capacity boundaries. The
isolated instruction harness uses EL1; complete workload validation checks EL0.
`el0_syscall` compares 16,384 cases against the shared syscall-entry emulator,
checking event capacity and contents, all GPRs/NZCV, stack switching, vector
hits/misses and empty tables, FAR preservation, entry-counter wraparound,
supported PSTATE and unchanged fallback state. Its QEMU instruction harness
runs at EL1; the complete checkpoint independently checks computation at EL0.
`el0_user_memory` compares 2,250 emitted-access cases against the existing C
translator under system QEMU. It covers 48/39/25-bit geometry, block/page leaves,
leaf and inherited permissions, AF, missing RAM, changed roots and leaf mappings,
static kernel-range rejection and valid high user addresses, immutable aliases,
scalar/pair/SIMD accesses, register offsets, indexed writeback, flags and logical
SP. The isolated instruction fixtures use an EL1 QEMU harness; the complete
checkpoint validation independently checks computation at EL0.
`el0_observe` runs 1,152 instruction cases under system QEMU, checking pending
and empty events, alignment and range boundaries, fallback, all event fields,
registers, flags and stack restoration.
`el0_memory_finish` runs 320 completion cases under system QEMU, checking scratch
and result registers, indexed writeback, logical SP, NZCV, SIMD preservation and
UART-output fallback.
`el0_lowered_branch` also runs 1,728 instruction cases under system QEMU when
an AArch64 cross compiler and QEMU are available. It checks empty/partial/full
range tables, half-open boundaries and holes, ordinary signed scalars, both
branch directions and discriminators, reviewed and ambiguous pointers,
register aliases, all NZCV combinations, stack restoration and counter wrap. Running
the same test module on AArch64 Linux also executes instruction-level checks for
scalar/SIMD memory, register offsets, logical SP, indexed writeback, scratch/flag
preservation and rejection paths. The native suite also compares 267 inline
shadow-register, PSTATE, guarded-register and maintenance forms across 32 seeds against the shared emulator and checks
indirect target/register aliases, flags, stack restoration, BLR links, empty
tables and lookup misses. Set `OSREC_EL0_HARDWARE_IMAGE` and
`OSREC_EL0_HARDWARE_PREPARED` to run the complete positive and missing-alias QEMU
checks, including rejection of a mismatched native zero-block geometry. Exclusive-window fixtures cover single/paired stores, conditional CAS,
CBNZ/TBNZ exits, read-only and unaligned rejection, user-mode fallback, flags and
stack restoration. Full-workload dynamic instruction counts are recorded in
[the measurement report](el0-instruction-profile.md). Hardware execution on RTL
and processor cycle measurements remain unverified.
