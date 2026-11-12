# Hardware-backed kernel memory at EL0

The complete executor has an optional `--hardware-memory` backend. It uses the
captured QEMU kernel mappings to construct EL0-accessible hardware aliases of
canonical RAM. Eligible kernel loads and stores execute natively without
entering the context gateway or walking the captured page tables in software.
Stack-pointer arithmetic also executes inline, including when application code
uses its logical stack. Supported shadow-register reads/writes and indirect
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
and validation all execute at EL0. Ordinary memory operations use the hardware
MMU after an inline range/mode check, preserving scratch registers and NZCV on
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
access. UART output and exclusive windows keep their existing completion
handlers. No completion runs when the initial check faults or skips a hint.

The syscall-result observation hook also runs inline when its saved result slot
is naturally aligned and wholly inside an admitted kernel read range. It copies
the result into the same event record, marks completion and clears the pending
event. Unaligned, unmapped and out-of-range slots retain the checked translation
handler. An empty pending event preserves all state and continues normally.

This backend retains software handling for changing user mappings, explicit
user-copy accesses, device inputs and unsupported operations. Exclusive windows
without a safe direct mapping or sufficient scratch registers retain that path.
The existing workload's demand faults are detected in software and execute the
captured kernel fault path. They do not cause hardware exceptions. Eliminating
those kernel fault computations would change the captured workload.

The hardware run reproduced all 2,272 events, nine counter inputs and 92 UART
bytes with zero hardware exceptions. Its 24,587 gateway entries are down from
approximately 2,261,577 in the software backend, a reduction of about 99%.
After native exclusive/prefetch paths reached 87,122 entries, inline PSTATE,
guarded shadow-register access, native zeroing and inert maintenance removed
another 44%. Inline address-discriminator branches then removed 2,483 entries
(5.1% of the remaining total). Inline completion of checked memory accesses
then removed another 19,723 entries (42.5% of the remaining total). Inline
result observation removed a further 2,135 entries (8.0%):

| Gateway operation | First hardware backend | Current backend |
| --- | ---: | ---: |
| Memory | 91,119 | 20,118 |
| Architectural | 106,662 | 2,332 |
| Indirect call/branch/return | 87,906 | 0 |
| Syscall, result observation and completion | 4,272 | 2,137 |
| Total | 289,959 | 24,587 |

The validation artifact is linked below. These are gateway counts, not
instruction or cycle counts; they do not establish a processor timing speedup.

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

- [Executor](../build/el0-hardware-memory-20261113d/checkpoint)
- [Model load plan](../build/el0-hardware-model-20261113d/hardware-load-plan.json)
- [Functional validation](../build/el0-hardware-validation-20261113d/validation.json)
- [Gateway, memory and instruction profile](../build/el0-hardware-validation-20261113d/validation.json)

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
to 97: 92 UART-output observations and five exclusive-window completions. The
initial translation/permission/fault checks still account for 20,021 entries;
this change removes their second gateway, not their checks. All 2,135 syscall
result observations now complete inline while preserving the existing event
records and validation. The other 2,137 entries are syscall entry and the final
completion boundary.

The target-independent tests are registered as `el0_hardware` in CTest.
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
stack restoration. Hardware execution on RTL and instruction/cycle measurements
remain unverified.
