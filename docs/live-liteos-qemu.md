# Live LiteOS-A kernel capture and native replay

`tools/liteos_qemu_demo.py` builds and boots the actual pinned LiteOS-A kernel in QEMU, executes a user read workload through the kernel's existing syscall dispatcher and VFS, captures its input/state observations, and exports a native executable that reproduces the declared syscall slice.

This uses a reduced real kernel configuration, with the MMU, VM, scheduler, GICv2, normal ARM exception handling, POSIX/VFS and RAMFS enabled. An embedded test init replaces the usual init workload. It is not the complete `qemu_small_system_demo` product with all services, nor the earlier freestanding harness. The image boots the original kernel startup and enters its scheduler before creating PID 1.

```text
QEMU boots actual LiteOS-A
       |
ARM startup -> MMU/GIC/timer/kernel init -> scheduler
       |
SystemInit prepares a real RAMFS file and report device
       |
PID 1 opens file and calls read using OHOS's SVC ABI
       |
existing exception dispatcher -> original SysRead
       |
actual fd mapping -> original VFS read -> RAMFS
       |
capture result/errno/returned bytes; return to user mode
       |
export capture and independent kernel/user observations over UART
       |
reconstruct native state -> replay SysRead -> compare every call
```

## Run

The bring-up was validated on macOS ARM64 with LLVM 16 clang/lld, CMake/Ninja, system `make`/C compiler and QEMU 9.2.3. The script uses Cortex-A7, `virt-9.2`, GICv2, one CPU, TCG and 1 GiB of emulated RAM. Paths currently use `build/ohos` for the managed boot tree and separate build directories for Kconfiglib and ARM compiler builtins.

```sh
python3 tools/liteos_qemu_demo.py --out build/live-liteos-run
build/live-liteos-run/replay
build/live-liteos-run/priority-replay
build/live-liteos-run/priority-min-replay
build/live-liteos-run/pid-replay
build/live-liteos-run/identity-replay
build/live-liteos-run/umask-replay
```

Choose an empty output directory. Add `--fetch` to acquire missing repositories at the exact revisions in `integrations/liteos_qemu/dependencies.json`. The original pinned replay checkout at `build/kernel_liteos_a` is also required; it remains unchanged. The separate managed boot checkout contains the build adaptations and recording hooks. Twelve repositories are locked, including the board/product, kernel dependencies, Kconfiglib and LLVM compiler-rt. Compiler-rt is cross-built for ARM; the host's Darwin builtins cannot be linked into this kernel.

Optional `--input PATH` supplies up to 64 bytes for the RAMFS fixture. The default is `ABCDE`. Startup writes those bytes into `/dev/shm/input.bin` through real filesystem APIs and closes it. PID 1 then opens that file itself. This makes input preparation explicit; the data source is a real guest RAMFS file, not a UART, physical sensor or QEMU semihost file.

The workload makes three reads through descriptor 3, followed by a zero-length read with a null buffer. For `ABCDE`, returns are `[4,1,0,0]`, file positions are `[4,5,5,5]`, and final buffer bytes are `00 11 41 42 45 44 66 77`. Each call uses the kernel's existing SVC ABI and `SysRead` implementation. The report device is opened and written only after the sequence finishes.

Before opening the report device, PID 1 also calls `sched_get_priority_max`
and `sched_get_priority_min` through the same SVC dispatcher for policies `2`,
`1` and `-1`. Maximum returns are `[31,-22,-22]`; minimum returns are
`[10,-22,-22]`. A `getpid` call returns `1`. Each observation includes user
CPU mode; priority observations also retain the argument bits.
The report driver safely copies a 376-byte workload report: 112 read bytes,
36 maximum-priority bytes, 36 minimum-priority bytes, 8 PID/mode bytes,
112 identity-query bytes and 72 umask-query bytes.
UART records are `OSREC_USER`, `OSREC_PRIORITY`, `OSREC_PRIORITY_MIN` and
`OSREC_PID`, emitted after recording ends.

`tools/live_priority_replay.py` validates captured arguments/mode and the
live kernel's exact source/constants against reviewed locks. It compiles
complete original function bodies into `priority-replay` and
`priority-min-replay`, executes each in isolation, and compares every return.
Both priority replays have no modeled dependencies. See the
[priority EL0 workflow](sched-priority-el0.md) for symbolic extraction
verification; the default live demo does not require KLEE.

`tools/live_pid_replay.py` similarly pins the exact `SysGetPID` body. Its
`pid-replay` restores the captured owner ID and implements
`LOS_GetCurrProcessID` as an explicit dependency model. It verifies both the
returned PID and that the body reaches that dependency once. It reproduces
no scheduler/process discovery and makes no symbolic equivalence claim.

## UID, GID and process-group queries

After the reads, PID 1 makes seven identity calls through the existing SVC
dispatcher. The UID/GID calls use their full-width ABI numbers 199/200;
legacy `getuid` number 24 is not the selected UID dispatcher entry.

| Invocation | Call | Live raw return |
| --- | --- | --- |
| 0 | `getuid32()` | 0 |
| 1 | `getgid32()` | 0 |
| 2 | `getpgrp(0)` | 1 |
| 3 | `getpgid(0)` | 1 |
| 4 | `getpgid(1)` | 1 |
| 5 | `getpgid(0xffffffff)` | -22 |
| 6 | `getpgid(0)` | 1 |

The pinned LiteOS-A dispatcher maps `getpgrp` to `SysGetProcessGroupID` with
one PID argument, just like `getpgid`. The user workload explicitly supplies
zero. This preserves the reviewed target ABI. `SysGetUserID`, `SysGetGroupID`
and `SysGetProcessGroupID` bodies are copied unchanged into replay.

Linker wrappers around those three syscall roots enable recording only for
selected PID 1 calls after the read session. Four dependency wrappers record
the actual `LOS_GetCurrProcessID`, `LOS_GetUserID`, `LOS_GetGroupID` and
`LOS_GetProcessGroupID` outcomes. Each event stores invocation index, boundary
kind, argument bits and result bits. Events are accepted only in supervisor
mode for the capture owner; reporting and unrelated calls are excluded.
This demo remains bounded to one CPU and one selected user workload.

UART output adds `OSREC_IDENTITY` (seven number/argument/return/user-mode
records) and `OSREC_IDENTITY_DEPS` (ten dependency events). The latter is a
separate kernel transcript, rather than a copy of expected syscall returns.
Zero PID queries reach both current-PID and group lookup boundaries; explicit
PID queries reach only group lookup. The invalid PID's negative return is
captured at the actual group lookup boundary.

`tools/live_identity_replay.py` pins source bodies, dispatcher and dependency
declarations against `integrations/liteos_a/identity-source-lock.json` in both
the reference and boot checkouts. Native dependency models consume the
transcript and verify invocation, kind and arguments. The original body
recomputes zero-PID substitution. Every raw return is compared after execution,
and unused or missing events fail export. Generated sources and the binary
are staged until native execution and metadata checks pass, preserving an
existing binary on a corrupt capture.

The completed live artifact is
`build/live-liteos-identity-final/identity-replay`. Its `--describe` metadata
contains the source identity, syscall observations, dependency transcript and
hashes binding the kernel image and captured bytes. The manifest also hashes
the executable. Replay requires no kernel image, source, QEMU or capture file.
Credential/process-group discovery, dependency internals, scheduler/IRQ replay
and symbolic equivalence for these identity queries remain outside this model.

## Stateful umask session

PID 1 next makes six `umask` SVC calls (ABI number 60). A wrapper around the
original `SysUmask` records each argument, process mask before execution, raw
return, mask after execution and supervisor/MMU mode. Sampling the mask uses
the actual scheduler lock; the original syscall runs with its own lock as
usual. The workload contains one selected process with no other umask writer.
User observations independently record argument, return and user CPU mode.
UART adds `OSREC_UMASK_USER` and `OSREC_UMASK_KERNEL` records.

The default live entry mask is octal `022` (decimal 18):

| Input mask | Raw return (previous mask) | Stored mask |
| --- | --- | --- |
| `0` | 18 | 0 |
| `022` | 0 | 18 |
| `0xffffffff` | 18 | 511 |
| `0x80000000` | 511 | 0 |
| `077` | 0 | 63 |
| `0` | 63 | 0 |

`tools/live_umask_replay.py` pins `fs/vfs/operation/vfs_other.c`, its exact
`SysUmask` body and relevant constant/process/lock/dispatch headers against
`integrations/liteos_a/umask-source-lock.json` in both checkouts. The generated
source retains the original license and function body; `mode_t` and `UINT32`
remain unsigned 32-bit, with `UMASK_FULL=0777`.

Native replay restores only the initial mask into a semantic process object.
`OsCurrProcessGet` exposes that object's mask. Explicit lock/unlock models
check lock state, saved-state matching, balanced operations and the two process
accesses per invocation. These model operations preserve the single-owner
contract; they execute no actual kernel spinlock or scheduler. Each original
call recomputes mask filtering, reads the prior mask and writes the next one.
Later captured masks are checked, never used to restore post-call state.
Both kernel/user returns and state continuity must agree, and wrong results
or state fail native execution before publishing a binary.

The completed artifact is `build/live-liteos-umask/umask-replay`. Its manifest
and `--describe` metadata bind entry state, per-call observations, source
identity, kernel image and capture hashes. Changed and empty RAMFS boots
also pass this session. Four native entry-mask variants (including
`0xdeadbeef`) verify that replay retains arbitrary initial bits until the
first update. Ten corrupted observation variants are rejected without
replacing an existing binary:

```sh
python3 tests/test_live_umask_replay.py
```

A separate KLEE reconstruction check uses the same original syscall body and
production model guards/counters, with two independent semantic process
objects. It makes the entry mask and all six arguments symbolic over every
32-bit pattern. It checks old-value returns and `mask & 0777` against an
independent arithmetic contract, then restores a fresh object from the entry
mask and checks all six recomputed returns/states and lock/access counts.
The completed run has one path, no partial paths and one successful native
replayed test. This bounded proof covers the declared sequential model;
it does not prove kernel locking, concurrency or actual process layouts.
The saved log retains KLEE's module/host target-triple warning.

```sh
python3 tools/verify_umask_checkpoint.py \
  --kernel-root build/kernel_liteos_a \
  --llvm-bin /opt/homebrew/opt/llvm@16/bin \
  --out build/umask-checkpoint-proof
```

`build/live-liteos-umask/umask-verification.json` binds the proof to the live
replay's exact source identity and artifact hash. Standalone metadata keeps
`symbolic_equivalence_verified=false`: this is a separate bounded model
reconstruction proof, rather than a scalar extraction-equivalence claim.

## Freestanding ARMv7 image

`tools/export_freestanding_umask.py` now converts the verified umask capture
into a freestanding target image. It checks capture hashes, source identity
and kernel/user observations, then cross-compiles the exact original syscall
body with the embedded checkpoint, ARM startup, explicit process/lock models
and a RAM validation record. It links with `-ffreestanding -nostdlib -static`
and includes no host library, allocator, formatted output or service call.
There is no guest filesystem, network, host clock, UART or semihost interaction.
The checkpoint contains only unsigned 32-bit scalar values; its semantic
process object is allocated in target RAM, with no captured host pointer.

```sh
python3 tools/export_freestanding_umask.py \
  --capture build/live-liteos-umask --out build/rtl-armv7-umask-new
python3 tools/run_freestanding_armv7.py build/rtl-armv7-umask-new/umask.elf
python3 tools/run_freestanding_armv7.py build/rtl-armv7-umask-new/umask.bin
```

The completed image is in `build/rtl-armv7-umask-final`. Construction sources,
checkpoint JSON and manifest are review sidecars; neither image needs them
at runtime. The raw binary loads at `0x40010000`; ELF load segments provide
their addresses. Both formats start at `_start=0x40010000`.

The provisional target contract is little-endian ARMv7-A A32/Cortex-A7,
one core, a privileged ARM entry with usable CP15 and MMU off, and RAM covering
`0x40000000..0x400fffff`. Startup masks IRQ/FIQ, establishes supervisor mode,
disables MMU/caches, installs local fault vectors, clears BSS and initializes
a 16 KiB stack. It calls the original syscall body directly; target SVC
entry, the actual scheduler and real kernel spinlocks are outside this image's
functional replay contract. Delivery to another RTL model requires matching
its ISA, reset and memory map.

At completion, the image writes a fixed 128-byte little-endian RAM record at
`0x40000000`, publishes status last with memory barriers, and loops locally.
The testbench can observe this memory without providing any guest service:

| Byte offset | Meaning |
| --- | --- |
| 0 | Magic `0x4f535243` |
| 4 | ABI version 1 |
| 8 | Status: 0 uninitialized, 1 running, 2 passed, 3 failed |
| 12 | Error: 0 success; 1..3 model violation; 10..15 prior state; 20..25 result/post-state; 30..35 counts; 255 exception |
| 16 | Completed invocation count |
| 20, 24 | Initial and final process mask |
| 28, 32, 36 | Lock, unlock and process-access counts |
| 40..87 | Six `(raw return, post-call mask)` pairs, each two u32 words |
| 88..127 | Reserved, zero on the normal path |

The verifier supplies only a copied image to QEMU, with semihosting disabled
and serial/monitor output disabled. QMP over pipes controls the external
verification harness and reads target RAM; guest code never calls it and it
supplies no replay input. Both ELF and raw image execution must produce the
same result bytes and match the live capture. A failed target result prevents
publication. The ELF audit rejects undefined symbols, dynamic loader segments,
remaining relocations and `svc`/`bkpt`/`hvc`/`smc` service-trap instructions.

Three regressions validate ordinary and nondefault entry state after deleting
construction inputs, reject incorrect return/post-state expectations in target
execution, and reject patched service traps and dynamic loader segments:

```sh
python3 tests/test_freestanding_umask.py
```

Configure `OSREC_BUILD_FREESTANDING_IMAGE_TESTS=ON` to register the
`freestanding_umask` CTest. The prepared pinned source checkouts, LLVM toolchain
and QEMU are construction/validation requirements. The target image has no
runtime dependency on them. The manifest records their versions, source and
image hashes, memory map, embedded checkpoint and actual RAM observations.
This milestone is functional QEMU TCG validation; no RTL run, cycle timing
claim or cross-architecture port is asserted.

## Freestanding identity images

`tools/export_freestanding_identity.py` packages the seven captured UID/GID/
process-group calls into the same provisional ARMv7-A execution environment.
It checks observation/transcript hashes, the source identity and every decoded
call/event against the live manifest before cross-compilation. Exact
`SysGetUserID`, `SysGetGroupID` and `SysGetProcessGroupID` bodies execute with
four explicit dependency models. The image embeds only scalar call/event data;
no host pointers, descriptors, paths, host runtime or guest I/O are needed.

```sh
python3 tools/export_freestanding_identity.py \
  --capture build/live-liteos-identity-final --out build/rtl-armv7-identity-new
python3 tools/run_freestanding_armv7.py build/rtl-armv7-identity-new/identity.elf
python3 tools/run_freestanding_armv7.py build/rtl-armv7-identity-new/identity.bin
```

The completed artifacts are `build/rtl-armv7-identity/identity.elf` and
`identity.bin`. They use the ARMv7 startup/linker map described above: entry
`0x40010000`, RAM result record `0x40000000`, a 16 KiB stack, masked interrupts
and no MMU. Models consume recorded dependency outcomes in order, checking
invocation, kind and argument before returning an event's result. The original
syscall body recomputes zero-PID substitution. The image checks each raw return
and rejects missing, reordered, mismatched or unused events before publishing
success. It reproduces no actual credential/process-group objects or scheduler.

Result ABI version 2 keeps the same 128-byte record and common
magic/version/status/error/completed-call prefix, so existing umask ABI version
1 images remain supported by the observer:

| Byte offset | Identity ABI version 2 meaning |
| --- | --- |
| 0, 4 | Magic `0x4f535243`, version 2 |
| 8, 12, 16 | Status, error, completed invocations |
| 20, 24 | Consumed and total dependency events |
| 28, 32 | Total calls (7), last invocation (6 on success) |
| 36 | Reserved |
| 40..95 | Seven `(raw return bits, cumulative consumed events)` pairs |
| 96..127 | Reserved |

Status values match version 1. Error values are 1 for missing events, 2 for an
invocation mismatch, 3 for kind/argument mismatch, 4 for an unsupported syscall
number, 5 for unused events, 10..16 for return divergence and 255 for an
exception. Negative raw returns retain their 32-bit two's-complement bits in
RAM; the external observer reports them as signed integers.

The live default returns are `[0,0,1,1,1,-22,1]`, with cumulative consumed-event
counts `[1,2,4,6,7,8,10]`. ELF and raw image execution produce identical RAM
records with semihosting disabled. The manifest binds the complete target
checkpoint/transcript, source and image hashes, memory map and observations.
The image needs none of its construction sidecars at runtime.

`tests/test_freestanding_identity.py` also exercises nondefault UID/GID/PID/
group values after removing construction inputs, rejects nine corrupt
transcript/return cases in actual target execution, rejects hash mismatches
before construction and preserves an existing output directory. The shared
image audit rejects host/dynamic dependencies and service-trap instructions.
`OSREC_BUILD_FREESTANDING_IMAGE_TESTS=ON` registers both `freestanding_umask`
and `freestanding_identity` CTests. These are functional QEMU TCG checks;
actual RTL execution and cycle timing validation remain pending the target
ISA/reset/memory-map contract.

## Freestanding scalar image

`tools/export_freestanding_scalar.py` combines three maximum-priority calls,
three minimum-priority calls and one PID call from one captured kernel image.
It verifies hashes, source locks, exact bodies, constant/dependency headers,
user-mode observations and agreement between decoded calls and manifests.
Captures bound to different kernel images are rejected before construction.
The original three functions are compiled separately with their reviewed
constants and linked with the existing ARMv7 startup and a RAM-only driver.

```sh
python3 tools/export_freestanding_scalar.py \
  --capture build/live-liteos-umask --out build/rtl-armv7-scalar-new
python3 tools/run_freestanding_armv7.py build/rtl-armv7-scalar-new/scalar.elf
python3 tools/run_freestanding_armv7.py build/rtl-armv7-scalar-new/scalar.bin
```

The completed artifacts are `build/rtl-armv7-scalar/scalar.elf` and
`scalar.bin`. Their checkpoint embeds policies `2`, `1`, `0xffffffff` for
each priority query, captured expected results, and the captured process ID.
The six original priority computations have no modeled dependencies.
`SysGetPID` calls an explicit `LOS_GetCurrProcessID` model that reads the
restored unsigned 32-bit PID and increments a counter. The driver requires
zero dependency calls during the six priority queries and exactly one after
the PID call. This does not execute the target SVC dispatcher or scheduler.

The default live returns are `[31,-22,-22,10,-22,-22,1]`. Expected values
are used only for comparison after each original function executes. No host
resource, clock, file, runtime, semihosting, allocation or guest I/O is involved.
The entry and result addresses remain `0x40010000` and `0x40000000`, with
the same provisional privileged A32/Cortex-A7 startup contract.

Result ABI version 3 uses the common 128-byte RAM record:

| Byte offset | Scalar ABI version 3 meaning |
| --- | --- |
| 0, 4 | Magic `0x4f535243`, version 3 |
| 8, 12, 16 | Status, error, completed invocations |
| 20, 24 | Restored PID, PID dependency-call count |
| 28, 32 | Total calls (7), last invocation (6 on success) |
| 36 | Reserved |
| 40..95 | Seven `(raw return bits, syscall number)` pairs |
| 96..127 | Reserved |

Syscall numbers are 159 (maximum), 160 (minimum) and 20 (PID). Status values
match ABI versions 1/2. Error values are 1 for an unsupported query, 10..16
for return divergence, 20..26 for dependency-count divergence and 255 for an
exception. The observer renders priority returns as signed integers and PID
as unsigned, preserving high PID bits. It continues to support the earlier
umask and identity record versions.

ELF and raw binary executions must produce identical result bytes and match
all captured returns and the entry PID before the exporter publishes either
image. Shared static auditing rejects unresolved/dynamic dependencies,
relocations and service traps. The manifest binds all three source identities,
capture-manifest hashes, the shared captured kernel image, checkpoint, target
images and memory observations. Construction sidecars are unnecessary at
runtime.

`tests/test_freestanding_scalar.py` verifies nondefault PID values including
`0xdeadbeef` after deleting construction inputs, detects wrong maximum/minimum
expectations in target execution, and rejects corrupt hashes, PID checkpoints,
source locks and mixed kernel-image captures. CTest now registers
`freestanding_scalar` alongside `freestanding_umask` and
`freestanding_identity`; all three suites pass. Functional QEMU TCG validation
remains separate from actual RTL execution and cycle timing validation.

## Freestanding read-session image

`tools/export_freestanding_read.py` now packages a four-call `SysRead` session
into the same provisional ARMv7-A environment. The completed live-derived
artifact is `build/rtl-armv7-read/read.elf` / `read.bin`:

```sh
python3 tools/export_freestanding_read.py \
  --capture build/live-liteos-umask/capture.json --out build/rtl-armv7-read-new
python3 tools/run_freestanding_armv7.py build/rtl-armv7-read-new/read.elf
python3 tools/run_freestanding_armv7.py build/rtl-armv7-read-new/read.bin
```

The exporter validates the capture against current pinned syscall/model
fingerprints, including entry graph, arguments, transcript and observations.
It checks that the boot checkout's `SysRead` source matches the pinned
reference. It reuses the exact original syscall body, typed object-reference
runtime and sequential-session models. Host printing code is excluded.
Only embedded byte-copy/clear helpers needed by ARM aggregate operations are
linked; they use ordinary target memory, with no allocator or host service.

The supported image schema has four calls, one eight-byte buffer, one semantic
process and at most two semantic file objects. Object IDs and offsets retain
their normalized 64-bit representation; target scalar fields retain declared
32-bit widths. The constructor registers freshly created target objects and
resolves references using their target `sizeof` values. It embeds no captured
host pointer or native struct dump. Descriptor aliases resolve to the same
target file object, preserving shared cursor state. Null descriptor slots,
null/one-past buffer arguments and declared fault paths remain supported.

The initial graph is restored once. Each call executes original `SysRead`,
modeled bounds checks, descriptor mapping, backend read effects and the user
errno/recognition computation. Backend payload/result/errno come from embedded
read events; handles are logical model IDs rather than live host descriptors.
Payload writes and unsigned 32-bit cursor updates are recomputed by the model.
Every generated boundary must match the ordered transcript, which must be
fully consumed. Each call's raw/user return, user/kernel errno, recognition,
all eight buffer bytes and every file cursor are checked before advancing.
Post-call expectations are never used to restore memory or cursor state.

For the live `ABCDE` capture, returns are `[4,1,0,0]`, the final cursor is 5,
and final buffer bytes are `0011414245446677`. Both image formats match and
consume nine events. No source file, capture file, QEMU service, UART, clock,
filesystem or host runtime is consulted by the guest. The target still uses
explicit process/fd/range/VFS models; actual kernel VFS, MMU, scheduling,
interrupts and SVC entry are outside this functional replay scope.

Result ABI version 4 keeps the 128-byte RAM record at `0x40000000`:

| Byte offset | Read ABI version 4 meaning |
| --- | --- |
| 0, 4 | Magic `0x4f535243`, version 4 |
| 8, 12, 16 | Status, error, completed invocations |
| 20, 24 | Call count (4), consumed boundary events |
| 28, 32, 36 | Final kernel errno, user errno, file count (0..2) |
| 40..103 | Four `(raw return, user return, user errno, recognized)` rows, four u32 words each |
| 104, 108 | Final file positions, ordered by object ID; unused slots zero |
| 112..119 | Final eight buffer bytes |
| 120, 124 | Expected total boundary count, reserved |

Signed returns retain two's-complement bits in RAM. Status values match earlier
versions. Error codes are 1 for object reconstruction, 2 for total-event mismatch,
10..13 for per-call transcript divergence, 20..23 for observation divergence
and 255 for an exception. Success is published last with memory barriers.
The observer supports all four result versions and requires complete event
consumption. The image's internal assertions cover full per-call state;
the external RAM record adds final state and per-call user-visible results.

`tests/test_freestanding_read.py` builds synthetic source-locked sessions to
exercise aliased descriptors, cursor wraparound, a one-past-buffer `EFAULT`,
`EINTR` and two separate files. ELF/raw executions match after all construction
inputs are removed. Eight corruptions (payload, entry bytes, descriptor alias,
cursor, event order, missing event, errno and expected memory) fail in actual
target execution without publishing output. Stale source identity is rejected
before construction and an existing output is preserved.

The shared image audit still rejects undefined/dynamic dependencies,
relocations and service traps. The manifest binds the full checkpoint,
syscall/model and target source hashes, ELF/raw hashes and target observations.
`OSREC_BUILD_FREESTANDING_IMAGE_TESTS=ON` registers `freestanding_read` alongside
the other three suites; all four pass. These remain functional QEMU TCG checks,
with actual RTL execution and cycle timing validation pending target details.

## Capture and entry state

Linker `--wrap=SysRead` and `--wrap=read` add capture boundaries while retaining the original function bodies. The pinned `syscall/fs_syscall.c` remains unchanged and is verified against the replay source. The source adapter is `integrations/liteos_qemu/live_capture.c`; `user_init.c` is the embedded user workload.

The adapter validates and snapshots a deliberately bounded scenario: one owning PID, one file, descriptor 3, an eight-byte user buffer and four known calls. It resolves the actual process descriptor to a system descriptor, inspects its live `struct file` cursor, verifies initial kernel errno, and copies initial/returned user bytes using the actual kernel safe-copy API. The live system descriptor is normalized to logical backend handle 17; object IDs 10/20/30 describe the normalized buffer/file/process schema. Pointer addresses are not retained in the standalone executable.

The reviewed normalized entry manifest is `integrations/liteos_qemu/entry.json`. Live values must agree with that manifest before recording is accepted. This is not general kernel object discovery or a complete memory checkpoint. Capture uses one CPU and a private fixture/buffer owned by the init workload; the hook buffer has one writer. It neither records scheduling/IRQ events nor provides generic SMP snapshot consistency.

At each backend read, the hook records exactly its returned bytes, return value, saved errno, invocation and normalized destination. Errno is restored after hook work. The recorder allocates no memory. The framed read stream is emitted after the syscall sequence, with a completion record and a context hash binding the pinned kernel, entry and calls. Diagnostic/transport overhead has not been benchmarked.

## Verification

Kernel observations independently record the raw return, kernel errno, actual file cursor and supervisor/MMU state after each syscall. User observations independently record the raw/user return, user errno, recognition, all eight buffer bytes and CPU mode after each return. Acceptance requires PID 1, user mode `0x10`, supervisor mode `0x13`, and the MMU enabled during the syscall.

The host imports the recorded read stream, executes the pinned syscall body with the existing replay dependency models, and compares every per-call observation against those from the live kernel/user workload. Native replay recomputes range checks, descriptor mapping, syscall branches, buffer effects, cursor updates and user errno processing within that declared model. It does not execute the target VFS/RAMFS, MMU, scheduler or exception dispatcher natively.

The copied native executable runs alone with a minimal environment. It embeds entry state, the dependency transcript and post-call checks. No running QEMU instance, kernel image, source input or trace file is needed during native replay. A successful report is written only after kernel completion, mode/state comparisons, export validation and isolated replay succeed.

The optional direct regression boots with changed data `XYZpqrs` and with an empty file. It checks `[4,2,1,0]` and `[0,0,0,0]` respectively, compares guest/native observations, deletes the source fixture, and reruns the executable:

```sh
python3 tests/test_live_liteos_qemu.py
```

The same regression checks all seven identity observations and a copied standalone
identity executable for both live inputs. `python3 tests/test_live_identity_replay.py`
checks nondefault UID/GID/PID/group dependency values and ten corrupt transcripts
or observations (including changed PID resolution), preserving an existing binary.

Set `OSREC_BUILD_LIVE_LITEOS_QEMU_DEMO=ON` in CMake to register
`live_liteos_qemu`, `live_identity_replay` and `live_umask_replay` after preparing
the dependencies. The two guest boots run sequentially because the test rebuilds the shared managed image.

Build logs are saved under `build/ohos`. Adaptations for the reduced configuration and macOS/LLVM build are stored in `integrations/liteos_qemu/build-files.json`, with original source hashes. They include make directory-rule compatibility, required header paths/declarations, exclusion of unused MTD integration, ARM compiler builtins selection and two assembly mnemonic spelling fixes. Identity root/dependency linker wrappers
are also declared in the reviewed build adaptations. The source copies retain their upstream licenses.

## Artifacts and limits

The output contains `liteos.bin`/`liteos.elf`, `boot.log`, `entry.json`, guest-produced `reads.osrec`, independent kernel/user observation files, imported `capture.json`, standalone `replay`, review sidecars and `report.json`. The report records locked dependencies, source/configuration/image/stream hashes, versions, observed CPU modes and guest/native agreement.

The real kernel runs its scheduler and interrupt machinery during recording. Their reproduction remains unsupported. This demonstration validates one sequential syscall scenario and its user computation under the declared dependency models. It does not establish whole-kernel replay, reproduce drivers/MMIO, certify arbitrary checkpoints or extend the earlier bounded KLEE proof to this live integration. Broader slices require additional state schemas, boundary capture and proof contracts.

For the full product build, the upstream [LiteOS-A QEMU guide](https://github.com/openharmony/device_qemu/blob/master/arm_virt/liteos_a/README.md) uses `hb set`/`hb build` for `qemu_small_system_demo`. This managed kernel build is a focused recording target using its board support.

## AArch64 delivery images

The four freestanding exporters default to AArch64. The live capture remains
from the pinned ARMv7 LiteOS kernel; the extracted syscall bodies and semantic
checkpoint models are rebuilt for AArch64 with 32-bit syscall scalars and
64-bit target pointers. No host capabilities enter the reconstructed state.

For example:

```sh
python3 tools/export_freestanding_read.py --capture build/live-liteos-umask/capture.json --out build/aarch64-read --entry-address 0x40200000 --result-address 0x40180000
python3 tools/run_freestanding_armv7.py build/aarch64-read/read.elf
python3 tools/run_freestanding_armv7.py build/aarch64-read/read.bin --descriptor build/aarch64-read/read.elf
```

The observer's historical filename supports both architectures. It discovers
the ISA, entry, PT_LOAD segments and `osrec_result` address from the ELF. A raw
binary needs its ELF descriptor because raw bytes carry no loading metadata.
For RTL delivery, load PT_LOAD bytes and zero each segment's BSS extent, then
start at the supplied ELF entry in privileged EL1. Startup masks interrupts,
disables the MMU/caches, installs exception vectors and creates its stack.
AArch64 compilation uses strict alignment for execution with the MMU disabled.
The image publishes completion through RAM, without semihosting or guest I/O.

The QEMU functional backend uses Cortex-A53 and its virt RAM map; its generated
DTB occupies the first MiB. The default example addresses avoid that area.
This does not constrain an RTL model that loads the supplied ELF segments.
`tests/test_freestanding_aarch64.py` checks all four result ABIs at two layouts,
ELF/raw equivalence after deleting construction inputs, and rejection of HLT,
invalid entries and dynamic segments. QEMU results do not establish RTL timing.
Older ARMv7 examples above require `--arch armv7` when invoking exporters.

## Parent and task queries

The live workload executes `getppid` (64) and `gettid` (224) twice each in a
forked child of PID 1. Its existing read, priority, identity and umask sequences
still run in PID 1. This pinned non-container LiteOS initialization gives PID 1
no parent object; the child supplies a valid parent edge for the original
`SysGetPPID` body. Fork and scheduling during capture are outside the replay
contract, and are not executed by the exported image.

At each selected syscall entry, the capture adapter takes a scheduler-protected
snapshot of the current PID, parent PID and task ID. It serializes those scalars,
the syscall number, return bits and kernel execution mode. The user workload
separately records the return and user mode. Normalization verifies that all
four entry snapshots agree and that kernel/user returns match. The checkpoint
has three logical objects: current process 1, parent process 2, and task 3.
Their logical IDs are distinct from the captured PID/TID values. No pointer or
host handle is serialized. PID containers must be disabled.

`task-source-lock.json` pins both complete syscall bodies, their source file,
dispatch table and process/task declaration headers. `task_model.h` exposes only
the consumed process/task fields. AArch64 reconstruction creates target-native
pointers for the parent edge and current-object helpers, then executes the exact
pinned bodies against those semantic objects. The image verifies all four
returns, unchanged objects and two accesses to each current-object helper.
This validates the declared field-access model, not the full kernel PCB/TCB
layout, scheduler execution or original instruction timing.

```sh
python3 tools/export_freestanding_task.py --capture build/live-liteos-task-child --out build/aarch64-task
python3 tools/run_freestanding_armv7.py build/aarch64-task/task.elf
```

The `osrec_result` symbol retains the common 32-word, 128-byte result record.
ABI 5 uses the following words (all little-endian uint32):

| Words | Meaning |
| --- | --- |
| 0–4 | Magic 0x4f535243, ABI 5, status, error, completed calls |
| 5–7 | Current PID, parent PID, task ID |
| 8–9 | Current-process and current-task helper access counts |
| 10–12 | Total calls, parent queries, task queries |
| 13 | Reserved zero |
| 14–21 | Four pairs of syscall number and unsigned raw return |
| 22 | Last invocation index |
| 23–31 | Reserved zero |

Status 2/error 0 means success; status 3 means divergence or an exception. The
image terminates in a local branch loop after publishing the result. Entry and
result addresses come from the ELF, as with the other AArch64 exporters. ELF
and raw execution match in QEMU with semihosting disabled. RTL/cycle validation
remains pending. Regression tests exercise full-width unsigned PID/TID values,
construction-input removal, corrupted returns, state drift, mode/result
mismatches, altered source identities and malformed parent/configuration data.

## Effective credential queries

The live PID 1 workload executes `geteuid32` (201) and `getegid32` (202) twice
each after umask and before fork. Their pinned `SysGetEffUserID` and
`SysGetEffGID` bodies read effective credential fields inside scheduler locks.
The capture adapter snapshots current PID, effective UID and effective GID
under a separate scheduler lock at each syscall entry, then records raw return
bits and kernel execution mode. User-mode return observations are recorded
separately and exported after the entire workload.

Normalization requires identical entry fields across the four queries and
matching kernel/user returns. It stores one logical credential object, with
32-bit effective UID/GID fields and logical ID 1. The current PID is a scalar
capture-owner value; no live credential pointer is serialized. Source locks pin
the complete function bodies, syscall source, dispatch and process declaration
headers. This contract requires `LOSCFG_SECURITY_CAPABILITY=y` and user containers
disabled. Unsupported capture configurations are rejected.

The AArch64 image reconstructs the object in target RAM. `OsCurrUserGet` returns
its target-native address only while the lock model is active. The model checks
lock depth and saved-token restoration, while the driver checks one credential
read and one balanced lock/unlock pair per query, unchanged fields, and every
raw return. This is a semantic locking contract; it does not reproduce scheduler
internals, original PCB/credential layout, interrupts or kernel instruction
timing. High-bit results are reported as `raw_bits` to preserve the syscall
register value across signed UID-body and unsigned GID-dispatch conventions.

```sh
python3 tools/liteos_qemu_demo.py --out build/live-credentials-capture
python3 tools/export_freestanding_credentials.py --capture build/live-credentials-capture --out build/aarch64-credentials
python3 tools/run_freestanding_armv7.py build/aarch64-credentials/credentials.elf
```

The image carries all fields, expected returns, dependency models and checks;
it needs no separate checkpoint or host services. Its ELF defines the entry,
load segments and `osrec_result` symbol. ABI 6 uses this 128-byte result record:

| Words | Meaning |
| --- | --- |
| 0–4 | Magic 0x4f535243, ABI 6, status, error, completed calls |
| 5–6 | Effective UID/GID fields |
| 7–10 | Locks, unlocks, credential reads, final lock depth |
| 11–12 | Total calls, captured current PID |
| 13 | Reserved zero |
| 14–21 | Four pairs of syscall number and raw return bits |
| 22 | Last invocation index |
| 23–31 | Reserved zero |

Success requires status 2/error 0, four completed calls, four locks, four unlocks,
four protected credential reads and zero final lock depth. ELF and raw-binary
results match in QEMU without semihosting. Regression cases cover nondefault and
high-bit credential fields, missing construction inputs, corrupted expected
returns, entry-state drift, mode/result mismatches, changed source/configuration
identities and invalid logical references. Additional mutated-body tests verify
that missing locks/unlocks and incorrect restore tokens publish target failures.
RTL execution and cycle timing validation remain pending.

## Process-priority queries

The PID 1 workload executes six `getpriority` (96) calls through the live OHOS
SVC dispatcher: `(which, who)` is `(0,0)`, `(0,1)`, `(0,-1)`, `(1,0)`,
`(-1,0)`, then `(0,0)`. At this pinned configuration the raw returns are
`28, 28, -22, -22, -22, 28`. These are raw LiteOS syscall results, with no
additional libc priority-value conversion.

`SysGetProcessPriority` substitutes the current PID when `who == 0`, then
calls `OsGetProcessPriority`. Capture records only these root dependency
boundaries: invocation index, dependency kind, argument bits and return bits.
Recording is disabled inside the priority lookup helper so its own calls do
not enter the root transcript. The six calls produce four current-PID events
and six priority-lookup events. User-mode argument/return observations are
recorded separately and published after all workload calls finish.

`getpriority-source-lock.json` pins the complete syscall body, source file,
dispatch table and process declaration headers. The checkpoint contains only
32-bit scalar arguments, expected returns and ten ordered dependency outcomes.
It carries no host pointers or live process handles. The image rebuilds the
exact syscall body for AArch64 and supplies embedded scalar boundary models.
It checks invocation/order, both arguments, every return and complete transcript
consumption. It verifies the wrapper's PID-resolution behavior; it does not
replay `OsGetProcessPriority` internals, scheduler state or full process objects.

```sh
python3 tools/liteos_qemu_demo.py --out build/live-getpriority-capture
python3 tools/export_freestanding_getpriority.py --capture build/live-getpriority-capture --out build/aarch64-getpriority
python3 tools/run_freestanding_armv7.py build/aarch64-getpriority/getpriority.elf
```

ELF entry, load segments and result address are discovered from the ELF.
ABI 7 retains the 128-byte `osrec_result` record:

| Words | Meaning |
| --- | --- |
| 0–4 | Magic 0x4f535243, ABI 7, status, error, completed calls |
| 5–8 | Consumed events, event count, call count, last invocation |
| 9–10 | Current-PID queries, priority queries |
| 11–13 | Reserved zero |
| 14–25 | Six pairs of raw return bits and cumulative events consumed |
| 26 | Syscall number 96 |
| 27–31 | Reserved zero |

Success requires status 2/error 0, six completed calls, four PID queries, six
priority queries and consumption of all recorded events. The observer reports
both signed `raw` values and their exact `raw_bits`. ELF and raw binary results
match without guest host services. Tests cover high-bit scalar dependency
values, reconstruction-input removal, changed PID/selector arguments, event
ordering, missing/extra events, incorrect invocation indices and corrupt
source/capture identities. RTL execution and cycle timing remain unvalidated.
