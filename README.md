# OSREC kernel execution recorder

OSREC's end goal is a self-contained executable that reproduces a captured OpenHarmony execution scenario, including selected user/kernel code and relevant scheduling and interrupt interactions. The executable embeds its code closure, initial state, recorded external inputs, replay runtime and validation checks; it requires no original source checkout, separate capture file or live device. The proposed recorder captures the information needed to construct that artifact, while static analysis and KLEE reduce instrumentation and embedded replay data within a declared scenario contract.

Delivery images are intended for RTL/cycle-accurate processor models and must
execute entirely at EL0 without host interaction. Their architectural external
effects are confined to their own RAM, apart from an optional terminal exit.
UART/timer behavior is represented by embedded inputs and RAM state. They must
embed checkpoint data, replay models, startup/runtime code and validation checks. Checkpoints use target ABI
values and relocatable object identities, without live host pointers or
resource handles. The earlier Linux syscall/signal native backends are host validation harnesses;
AArch64 freestanding read-session, umask, identity-query, scalar-query, parent/task-query, effective-credential and process-priority images are now implemented. The supplied ELF defines its entry point and load segments.
The `runtime/el0_flat` backend now resumes a complete captured Linux user/kernel
workload at EL0: original syscall entry/dispatch/return, kernel computation,
page faults and user continuation. Its standalone executable matches 2,272
events, nine embedded timer inputs and 92 RAM-backed UART bytes. Its gateway
preserves every guest GPR and FP/SIMD register; the image makes no host syscall
before terminal exit. See the [current EL0 backend](docs/source-image-flow.md#complete-userkernel-checkpoint).
The exporter also supports an [execution-only production option](docs/el0-runtime-optimization.md#execution-only-production-option)
with `--no-validation`; `--trust-syscall-abi` retains direct user-memory proofs
under the existing return ABI. Validation is enabled by default.
[Grouped DAIF forwarding](docs/el0-runtime-optimization.md#grouped-daif-forwarding)
brings production runtime instructions to 3,516,375 (1.1562 per original kernel
operation), 0.038% below the compact-state image; the 0.20 ceiling remains unmet.
An [opt-in descriptor write tracker](docs/el0-runtime-optimization.md#experimental-descriptor-write-tracking)
reduces scans but regresses total instruction overhead, so it remains disabled by default.
The [simulator-neutral GDB runner](docs/el0-model-runner.md) loads or verifies its
RAM, checks EL0 entry, and inspects the embedded result at completion before exit.
RTL execution and timing validation remain pending. See the
[RTL execution contract](docs/design.md#rtl-and-cycle-accurate-execution-target).

An optional [hardware-memory backend](docs/el0-hardware-memory.md) now uses the
captured QEMU mappings to execute eligible kernel RAM accesses through hardware
page tables without the full-context gateway. Inline shadow-register operations
and indirect branches, native exclusive/prefetch/zeroing paths, inert maintenance,
inline user-memory translation, syscall entry, memory completion and result
observation and UART register buffering reduce gateway entries by about 99.9% on the complete workload. It matches with no hardware exceptions or runtime EL1 services; model initialization
establishes the mappings before entering the EL0 executable.

A [user-binary builder](docs/el0-user-binary.md) also combines a reusable captured-kernel capsule with a supplied static AArch64 ELF. Construction runs the kernel's real `execveat`; delivery starts the new program at its ELF entry and handles its syscalls through captured kernel code, entirely at EL0. The example passes native and QEMU application checks, matches stdout and exit status on Linux, and rebuilds byte-identically from the same inputs. The initial contract admits static non-PIE binaries with immutable executable pages; general scheduling, devices and dynamic loading remain outside it. See the [demo report](docs/el0-native-demo.md) for evidence and limits.

This repository contains host-side capture and replay demonstrations, an optional LLVM analysis planner, and a live LiteOS-A QEMU demo. LiteOS-A is the first kernel target, at revision `4ac7f3aed67000b47bc14d6fe79d63ada708d780`. The demo boots a reduced real kernel on Cortex-A7, captures PID 1 syscalls and exports standalone native replay executables. Scheduling/interrupt reproduction and general kernel-state discovery remain future work.

The LLVM build also includes an [EL0 slice analyzer](docs/el0-analysis.md). It discovers direct-call closures and proven finite callback sets, shows paths to unresolved dependencies, lists memory/state requirements and proposes closures around explicit model boundaries. `--slice-return` finds instruction candidates while retaining control flow and observable effects. It separates architecture/address concerns from replay ordering and does not claim that static candidates are verified executable slices.

The [EL0 exporter](docs/el0-export.md) now transforms a restricted scalar slice, checks return equivalence with KLEE, replays generated tests natively and packages a standalone host executable. It supports LLVM 16 for the installed KLEE toolchain and LLVM 22 for analysis/extraction. The pinned LiteOS-A `LOS_Align` helper runs this way with explicit AArch32 integer widths; pointer/global state and scheduling/interrupt dependencies require further contracts.

The [object-checkpoint prototype](docs/object-checkpoints.md) adds typed initial-state capture and reconstruction for a pointer-bearing completion model. It preserves shared aliases, cyclic links, buffer offsets and a current-task binding, then runs the original computation in a standalone executable. It uses explicit schemas and stable host objects; kernel object discovery and synchronized live capture remain planned.

[Syscall session checkpoints](docs/syscall-checkpoints.md) extend this to the pinned LiteOS-A `SysRead` body. Sequential calls share restored buffer/file/process state, including descriptor aliases, modeled file cursors and errno. Ordered boundary transcripts drive a standalone replay executable. A portable C read hook and host-file adapter supply recorded input bytes; an executable can replay actual file reads after the original file is removed. A bounded KLEE reconstruction check validates the host model; a live LiteOS-A QEMU capture is also implemented below.

The [QEMU end-to-end demo](docs/qemu-demo.md) boots a freestanding ARMv7 guest: user code enters through SVC, the pinned `SysRead` body reads a QEMU semihost file, and the guest records the returned data. It compares guest observations against reconstructed native execution and produces one standalone replay binary. This exercises actual user/supervisor transitions in an isolated program; the live kernel demo below extends it.

The [live LiteOS-A QEMU demo](docs/live-liteos-qemu.md) now boots the actual kernel, including its MMU, scheduler and existing SVC dispatcher. PID 1 reads a real RAMFS file through the original `SysRead`/VFS path. Independent kernel/user observations are compared with native reconstruction before exporting a standalone executable. The replay still models its dependencies; scheduling/IRQ reproduction and general state discovery remain future work.

The same workload also captures three real calls each to `SysSchedGetPriorityMax`
and `SysSchedGetPriorityMin`, plus `SysGetPID`. The priority calls’ [complete EL0 computation](docs/sched-priority-el0.md) replays the captured
policies/results without modeled dependencies. The scalar exporter separately
uses KLEE to check extraction equivalence over all 32-bit policies. PID replay
executes the original body with an explicit captured-process-ID dependency model.

The live workload also captures full-width `getuid32`/`getgid32`, `getpgrp`
and `getpgid` calls, including zero, explicit and invalid PID arguments.
Their original syscall bodies replay against an ordered transcript of actual
kernel dependency outcomes. Invocation, boundary kind, arguments and full
transcript consumption are checked before publishing `identity-replay`.
This models the identity dependencies; it does not reconstruct credential or
process-group kernel objects.

`SysUmask` adds a stateful live session: six SVC calls capture the process's
entry mask, prior-mask returns and post-call masks. Standalone replay restores
the entry mask once and runs the original body, retaining its writes between
calls. Process access and lock operations have explicit sequential models.
A separate bounded KLEE check covers arbitrary 32-bit entry masks and six
arbitrary mask arguments.

The freestanding image embeds the original `SysUmask` body, checkpoint and
models, with no host runtime or semihosting. Its ELF and raw binary produce
identical RAM results in QEMU with guest services disabled. Build it with:

```sh
python3 tools/export_freestanding_umask.py \
  --capture build/live-liteos-umask --out build/rtl-armv7-umask-new
```

The completed artifacts are `build/rtl-armv7-umask-final/umask.elf` and
`umask.bin`. Exporters now default to AArch64; use `--arch armv7` for the
older backend. `--entry-address` and `--result-address` select the linked layout.
ELF loading and result observation derive their addresses from the ELF itself.
QEMU provides functional validation; RTL/cycle timing validation is still pending. See the
[freestanding image contract](docs/live-liteos-qemu.md#freestanding-armv7-image).

The identity session also exports freestanding ELF/raw images. All seven
UID/GID/process-group calls execute their original bodies against embedded,
ordered dependency events, with no host resource handles or services:

```sh
python3 tools/export_freestanding_identity.py \
  --capture build/live-liteos-identity-final --out build/rtl-armv7-identity-new
```

Completed artifacts are in `build/rtl-armv7-identity`; they use the same entry
and result addresses, with result ABI version 2. The target checks every
boundary's invocation, kind and argument and requires full transcript
consumption. See the [identity image contract](docs/live-liteos-qemu.md#freestanding-identity-images).

Priority maximum/minimum and PID captures also export as one freestanding
scalar-query image. It recomputes six priority results and executes `SysGetPID`
against an embedded process-ID model, checking that the dependency runs once:

```sh
python3 tools/export_freestanding_scalar.py \
  --capture build/live-liteos-umask --out build/rtl-armv7-scalar-new
```

Completed ELF/raw artifacts are in `build/rtl-armv7-scalar`, with result ABI
version 3. All three freestanding image suites run under
`OSREC_BUILD_FREESTANDING_IMAGE_TESTS=ON`. See the
[scalar image contract](docs/live-liteos-qemu.md#freestanding-scalar-image).

The captured four-call `SysRead` session now exports as a freestanding image
with target-memory buffer/file/process reconstruction. Read bytes and boundary
outcomes are embedded; descriptor aliases, buffer writes, cursor changes and
errno adaptation execute against explicit models, with no host file or I/O:

```sh
python3 tools/export_freestanding_read.py \
  --capture build/live-liteos-umask/capture.json --out build/rtl-armv7-read-new
```

Completed ELF/raw images are in `build/rtl-armv7-read`, using result ABI 4.
All four image suites pass, including aliasing, wraparound, faults/errors and
corruption checks. See the [read image contract](docs/live-liteos-qemu.md#freestanding-read-session-image).

## Run the prototype

Requires CMake 3.20+, a C11 compiler, Python 3.10+ and Ninja for these commands.

```sh
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
build/record_demo build/capture.osrec 100 500 30 400
python3 tools/export_capsule.py build/capture.osrec build/capsule.c
cc -std=c11 -O2 build/capsule.c -o build/capsule
build/capsule
```

The demo models a budget policy helper with credits, a deadline, a demand and an external clock. It records 180 bytes per invocation and exports a standalone C file containing the original helper, captured state, a clock replay adapter and output checks. The generated executable prints `replay verified` when the replay matches. This verifies functional behavior; it supplies no kernel timing or overhead measurement.

## Run the task and nested interrupt demonstration

```sh
build/record_task_demo build/task.osrec 0 7 5 2
python3 tools/export_task_capsule.py build/task.osrec --inspect
python3 tools/export_task_capsule.py build/task.osrec build/task_capsule.c
cc -std=c11 -O2 build/task_capsule.c -o build/task_capsule
build/task_capsule
```

Task 101 starts on CPU 0 with zero completion credits and a demand of seven. It blocks; another modeled task runs. An outer interrupt observes five credits, a nested interrupt adds two, then the outer handler adds five and wakes the task. Task 101 resumes on modeled CPU 1, consumes seven credits and returns seven.

The 1,184-byte capture has 13 context events. Its exporter checks interrupt parentage, event order, task placement, wait-object generation and completion. Generated replay executes the original completion helper and task continuation, checking intermediate handler effects and final outputs. It does not copy expected memory writes into the reconstructed state. CPU identifiers describe the protocol model; replay does not migrate real host threads or inject hardware interrupts.

The fixed scenario requires the task to block initially, remain blocked after the nested handler, and become ready after the outer handler. Unsupported scenarios are rejected. See [the context protocol](docs/context-protocol.md).

The [AArch64 hardware interrupt replay](docs/async-interrupt-replay.md) adds a single-CPU variant: a real QEMU timer interrupt receives a higher-priority nested GIC interrupt, recomputes completion effects and wakes the blocked continuation. The image records and checks all thirteen context events, with no host services. ELF/raw execution and negative replay checks pass; task scheduling remains a bounded continuation model.

The [live blocking-wait workload](docs/live-wait-replay.md) now captures an actual LiteOS-A `SysNanoSleep`: delay, switch away, timeout deadline, timer IRQ, enqueue/wakeup, switch back and return. A standalone host executable runs eight original syscall/time/scheduler definitions against explicit sequential boundary models and checks all ten observed events. Use `tools/liteos_qemu_demo.py --async-wait` to build, capture and export it.

The [Linux IRQ workflow](docs/linux-irq-replay.md) captures a real AArch64 Linux `nanosleep` with scheduler, timer and IRQ tracepoints, rejects lost or incomplete histories, and exports ELF/raw images that use ten original Linux timer functions and eight scheduler helpers. The original clock-update body now copies realtime, boottime and TAI offsets to their soft bases; a ninth RAM ledger checks propagation with synthetic inputs while timekeeping internals remain modeled. The original low-resolution outer runner surrounds dispatch with checked mode, clock, lock and softirq-deadline boundaries; an eighth RAM ledger verifies that path. The original queue-dispatch body selects the next timer and checks its soft deadline; a seventh RAM ledger verifies its bounded passes. The original callback-run body manages the running marker and callback sequence through checked lock/sequence boundaries. Original enqueue/removal helpers maintain timer state and a projected active mask around a bounded ordered container with an optional synthetic remainder sentinel. A sixth independently read RAM ledger checks its ordering and membership; native background timer contents remain unobserved. Original sleeper construction installs the callback, which executes through hardware-delivered timer exceptions. Original queue wrappers run against a selected-task class model whose boundary states are independently read from RAM. Linux task-state bits and queue/CPU membership are checked separately, including rejection of a repeated wakeup. Optional BTF-backed probes capture native task-state bits, queue/CPU membership and the sleeper link. `--timer-state` also observes inactive timer state and the running-timer pointer at callback entry; `--timer-return` checks that the same base has no running timer by sleep return. `--base-state` also checks the base index and selected active bit, preserving inferred residual occupancy when other timers remain. `--outer-state` also directly checks the CPU base softirq deadline and activation flag at callback entry; initial state remains modeled. `--clock-state` also captures each low-resolution runner timekeeper return, sequence and hard offsets, then uses the selected IRQ outputs in original propagation code; `--clock-offsets` additionally checks propagated soft offsets at callback entry and maps the timekeeper destination pointers to the CPU base using BTF. `--clock-entry` pairs the input sequence and hard offsets with each timekeeper return, reconstructing the selected call entry and comparing observed value changes. The optional exporter flag `--timekeeper-source` also executes the original timekeeper helper for unchanged selected entry/return fields and checks a tenth RAM ledger; provider state, sequence reads and clocksource input remain modeled. `--timekeeper-layout` additionally discovers a unique BTF structure candidate and reports data-symbol lookup capability; it captures no provider values or symbol/type binding. The callback timer and task relationship, plus link clearing by callback return, are directly checked. Independent RAM ledgers must match the captured syscall interval, including these direct observations. Scheduler choices and other tick-handler effects remain explicit models.

## Run the LLVM analysis planner

The optional plugin is validated with LLVM 22.1.7. It uses alias analysis, MemorySSA, dominance and pointer capture analysis to suggest which loads are determined by a preceding complete store to unescaped local memory. It reports direct code dependencies and unresolved effects. It applies no instrumentation or omissions.

```sh
cmake -S . -B build/llvm -G Ninja \
  -DOSREC_BUILD_LLVM_PLANNER=ON \
  -DLLVM_DIR=/opt/homebrew/opt/llvm/lib/cmake/llvm \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++
cmake --build build/llvm
ctest --test-dir build/llvm --output-on-failure
/opt/homebrew/opt/llvm/bin/opt \
  -load-pass-plugin build/llvm/osrec_plan.so \
  '-passes=osrec-plan<my_root>' -disable-output selected.ll \
  2> build/plan.json
```

The build paths above match this workspace's Homebrew installation; use the matching LLVM installation elsewhere. Supply a real function name and its LLVM IR in the last command. Site IDs are bound to the exact module IR hash and planner version. Asynchronous entry roots must be analyzed separately; the plugin does not discover interrupt-to-task relationships.

Loads from arguments, escaped objects, partial writes and uncertain control flow remain observations. Atomic and volatile loads are retained. Inline assembly, indirect calls, external declarations and unmodeled intrinsics are reported for explicit handling. The first omission rule overlaps ordinary compiler optimization; it is a correctness baseline, not evidence of additional savings on optimized kernel code.

## Run the combined user/kernel KLEE scenario

KLEE executes the user application, its read/errno adapter, the actual LiteOS-A `SysRead` body and declared dependency models in one linked LLVM module. Address validation, descriptor mapping and VFS/device behavior are modeled. The seed is synthetic, not a device capture. See [the KLEE integration](docs/klee-liteos.md) for its bounds and replay contract.

```sh
git clone https://github.com/openharmony/kernel_liteos_a.git build/kernel_liteos_a
git -C build/kernel_liteos_a checkout 4ac7f3aed67000b47bc14d6fe79d63ada708d780
python3 tools/klee_liteos.py \
  --kernel-root build/kernel_liteos_a --out build/klee-liteos \
  --llvm-bin /opt/homebrew/opt/llvm@16/bin \
  --klee-include /opt/homebrew/opt/klee/include --run
```

These tool paths match this workspace's KLEE 3.2 / LLVM 16.0.6 installation. Use a compiler with the same LLVM major as your KLEE build. The LLVM 22 planner is a separate toolchain. The runner checks source fingerprints, runs 300 native cases, explores two symbolic modes and natively replays every generated KTest. It saves the linked bitcode, executable, manifest and logs under the output directory.

To enable this integration in CTest, configure with `-DOSREC_BUILD_LITEOS_KLEE_SCENARIO=ON`. Override `OSREC_LITEOS_SOURCE`, `OSREC_KLEE_LLVM_BIN` and `OSREC_KLEE_INCLUDE` for other installations.

## Analyze what must be traced

The implemented KLEE analysis checks two executions with the same checkpoint and independent symbolic I/O environments. Equal proposed traces must imply equal declared outputs and effects. A counterexample prevents an omission; a completed successful check supports it within the model. The final plan also passes a separate replay check that reconstructs an environment from retained observations and reruns the syscall and user code.

```sh
python3 tools/analyze_trace.py \
  --kernel-root build/kernel_liteos_a --out build/trace-analysis \
  --llvm-bin /opt/homebrew/opt/llvm@16/bin \
  --klee-include /opt/homebrew/opt/klee/include
```

For this bounded `SysRead` model, the analysis retains errno and written-byte observations and omits the separate backend return. Returned-byte presence encodes the successful length; losing that metadata invalidates the omission. Five native-confirmed counterexamples show why each retained candidate is individually necessary. The report contains the contract, bounds, selected fields, proofs completed within those bounds and concrete witnesses. See [trace sufficiency and reconstruction](docs/trace-analysis.md).

## Export a standalone scenario executable

```sh
python3 tools/export_sysread.py \
  --plan build/trace-analysis/trace-plan.json \
  --kernel-root build/kernel_liteos_a \
  --compiler /opt/homebrew/opt/llvm@16/bin/clang \
  --case examples/sysread_short_case.json --out build/scenarios/sysread_short
build/scenarios/sysread_short
build/scenarios/sysread_short --describe
```

The executable embeds the checkpoint, reduced trace, original syscall body, user code, models, reconstruction and expected behavior. It runs without construction inputs or tools. The validated target is macOS ARM64 with only the normal macOS system runtime dependency. The example verifies a two-byte short read; its provenance is a synthetic model capture. Export also supports packaging an existing retained capture through `--capture`. See [standalone construction and validation](docs/standalone-export.md).

## Implementation boundaries

- `runtime/recorder.c` provides a caller-owned bounded buffer, explicit little-endian records and sticky failure. Recorder hooks allocate no memory and perform no file I/O. The caller exports only after successful completion.
- `runtime/context.c` tracks a selected task, modeled CPU placement, nested IRQ identities and matching wait generations. Calls and bookkeeping require external serialization. It is not IRQ/SMP-safe recording infrastructure.
- The demonstrations manually place hooks. There is no automatic compiler instrumentation pass yet. The bounded recorder requires one writer, stable storage and no concurrent reader.
- The two exporters support explicit demonstration schemas. They reject incomplete captures and source fingerprint mismatches and verify recomputed outputs. Each source fingerprint covers only its region header; a production build identity must cover compiler, configuration, dependencies and linked image.
- `compiler/Planner.cpp` is analysis only. Its omission suggestions assume compiler-visible memory semantics and require separate kernel effect/ownership validation.
- `integrations/liteos_a/` links a real syscall body to a user application and explicit environment models. It uses 32-bit syscall scalars and host-width pointers, with direct C dispatch replacing architecture entry. It does not execute the target libc, VFS, scheduler, MMU or hardware.
- `tools/analyze_trace.py` refines manually authored boundary observations and verifies transcript-driven replay. It does not yet discover arbitrary memory probes or install instrumentation. Required checkpoint contents and fixed model state are outside its current deletion candidates.
- `tools/export_sysread.py` packages a checked modeled scenario as one executable, binds it to the analyzed source/projection and tests it in isolation before publication. Capture and manifest sidecars support construction and review; the executable ignores them.
- `tests/` exercises buffer boundaries, overflow, encoding, malformed captures, context lifecycle, source mismatch, multiple replay paths, output divergence and conservative analysis decisions.

Validation in this workspace: the original eight CTest suites passed, including the planner, combined KLEE scenario, trace analysis and standalone export. EL0 analysis adds 20 classification/dependency regressions and extraction adds two transformation regressions on LLVM 16 and 22. The LLVM 16/KLEE configuration adds five export regressions, including deliberate mismatch detection and isolated execution. Object reference tests and six typed-checkpoint integration regressions also pass. The callback fixture's original code also passes 96 native input combinations. The original KLEE scenario completes 8 paths with the modeled environment fixed and 9 with modeled I/O outcomes and payload bytes symbolic; all 17 generated tests pass native replay. The native scenario also checks 300 bounded input combinations. Trace analysis completes the full and reduced checks and verifies reduced-trace replay, with five native-confirmed deletion witnesses. Standalone syscall tests cover nine isolated execution paths, capture-only repackaging and six rejection cases. The context tests pass AddressSanitizer and UndefinedBehaviorSanitizer. All three runtime sources compile as freestanding AArch64 objects with `-mgeneral-regs-only`, without unresolved allocator, formatting or I/O symbols. The live LiteOS-A QEMU demo has booted OHOS and captured SVC calls; hardware interrupt replay and kernel overhead measurements remain unvalidated.

See [the design and implementation sequence](docs/design.md) for the broader replay contract. The portable demonstrations, planner, modeled syscall slice, bounded trace analysis, standalone syscall export, verified scalar EL0 extraction and syscall session checkpoint/replay and live LiteOS-A QEMU recording are implemented; real-board capture remains planned.

`getppid` and `gettid` now have a live capture and AArch64 delivery path:

```sh
python3 tools/liteos_qemu_demo.py --out build/live-task-capture
python3 tools/export_freestanding_task.py --capture build/live-task-capture --out build/task-image
python3 tools/run_freestanding_armv7.py build/task-image/task.elf
```

The capture workload forks a child of PID 1 for these queries because this
non-container kernel's PID 1 has no parent link. Fork is capture setup and is
outside the replay contract. The image reconstructs a process, its parent and
a task from logical IDs and scalar fields, then executes the pinned syscall
bodies twice each without guest host services. Result ABI 5 reports four
returns and object-access counts. See [the task replay details](docs/live-liteos-qemu.md#parent-and-task-queries).

Effective UID/GID queries also support live capture and AArch64 delivery:

```sh
python3 tools/export_freestanding_credentials.py --capture build/live-liteos-credentials --out build/credentials-image
python3 tools/run_freestanding_armv7.py build/credentials-image/credentials.elf
```

The live workload captures `geteuid32`/`getegid32` twice each before forking.
The image reconstructs a credential object and executes the pinned syscall
bodies with modeled scheduler locking. It verifies returns, unchanged fields,
protected reads and balanced locking. Capabilities must be enabled and user
containers disabled; no scheduler execution is reproduced. See
[effective credential replay](docs/live-liteos-qemu.md#effective-credential-queries).

`getpriority` also has a live capture and AArch64 delivery path:

```sh
python3 tools/export_freestanding_getpriority.py --capture build/live-liteos-getpriority --out build/getpriority-image
python3 tools/run_freestanding_armv7.py build/getpriority-image/getpriority.elf
```

Six queries exercise current-PID resolution, explicit PID arguments and invalid
selectors/PIDs. The image executes the exact syscall body with embedded,
ordered dependency outcomes. Priority lookup and scheduler internals remain
outside this replay contract. See [process-priority replay](docs/live-liteos-qemu.md#process-priority-queries).

Entry-state field discovery and capture are now automated using the actual
configured Clang AST:

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --out build/live-auto-state
```

The tool generates field plans and snapshot hooks for six roots, then captures
fourteen live entry snapshots with normalized object IDs. Boundary policies
remain explicit, and unsupported effects block hook generation. See
[automated entry-state discovery](docs/entry-state-analysis.md).

Parent/task images can now restore the discovered normalized object graphs:

```sh
python3 tools/export_freestanding_task.py --automated-entry-state \
  --capture build/live-auto-state --out build/rtl-generated-task
```

This path generates target-native object storage, scalar restoration and logical
reference reconstruction for each invocation. Semantic types and dependency
implementations remain reviewed adapters; RTL timing has not been validated.

Effective UID/GID images also accept `--automated-entry-state` through
`tools/export_freestanding_credentials.py`, preserving the reviewed scheduler
lock contract while reconstructing each query's discovered credential field.

Entry-state analysis also supports configured multi-file closure using
`--closure-source` or `--all-sources`, and finite local callback targets. The
live pipeline combines both configured translation units; unresolved targets
and conflicting definitions still block automatic generation.

Explicit `argument_objects` contracts now let configured helper/syscall pointer
arguments supply discovered checkpoint objects. Generated hooks and
reconstruction preserve aliases, cycles and null roots, including bounded
inline-array fields and mixed scalar/pointer argument positions. Host and
standalone AArch64 ELF/raw fixture replay pass. `--argument-entry-state` now
also captures six explicit original process-helper calls on the real current
process under the LiteOS-A scheduler lock. `tools/live_argument_state.py`
exports their generated state as verified standalone AArch64 ELF/raw images.
Const-qualified arguments and pointer edges now retain readonly C views while
sharing normalized object identity with mutable views. The live
`--const-argument-entry-state` profile captures the original process-group-leader
helper's 16-bit status field and exports it through the same standalone pipeline.
`--argument-write-state` adds controlled calls to the original signal-set helper:
generated hooks capture its entry and post-state, and the native field is
restored before scheduler unlock. Standalone replay recomputes the writes from
captured scalar arguments and checks all post-states using the same exporter.
`--argument-write-session` retains writes across six original helper calls in
one locked batch, restores the native field once afterward, and exports replay
with one initialization plus six entry/post-state checks.
Generated reconstruction also supports nested scalar writes through stable
captured pointer paths, with native fixture and standalone AArch64 checks for
the reached object. Writable traversal edges remain blocked.
`--parent-argument-session` adds live two-process coverage: an explicit capture
adapter follows the workload child's real `parentProcess` edge and invokes the
original signal-set helper on PID 1. Generated hooks capture that edge and the
parent's nested scalar write; the native field is restored once after the batch.
Natural call-site selection and arbitrary pointer ranges remain future work. See
[argument-backed discovery](docs/entry-state-analysis.md#argument-backed-object-discovery).

[Whole-kernel coverage surveys](docs/entry-state-analysis.md#whole-kernel-coverage-survey)
inventory existing build objects, recover configured C commands, and classify
every available primary-source function. Per-unit reports retain failures and
state-access blockers; ranked missing calls identify bodies available in other
files. This is a translation-unit baseline for expanding discovery, with no
automatic boundary contracts or whole-kernel completeness claim.
[Automatic cross-file expansion](docs/entry-state-analysis.md#discovered-cross-file-call-closure)
uses that survey to load unique external C bodies for selected roots, with
source-hash checks, translation-unit limits and explicit conflict/failure records.
[Function-reference slices and automatic batches](docs/entry-state-analysis.md#function-reference-slices-and-automatic-batches)
remove unrelated function declarations before merging and can select eligible
active-build roots directly from the survey, with an explicit batch limit.
[Checked batch continuation](docs/entry-state-analysis.md#continuing-and-accounting-for-the-eligible-cohort)
uses a deterministic root offset and combines disjoint batches while retaining
failures and unrequested roots in the coverage report.
[Expansion with additional blockers](docs/entry-state-analysis.md#expanding-roots-with-additional-blockers)
adds a separate cohort for roots with other blockers or unavailable calls when
at least one external C body is uniquely indexed. Remaining blockers and
unrequested roots stay visible.
[Fixed global-array discovery](docs/entry-state-analysis.md#fixed-global-array-storage)
adds bounded global element reads and writes. A configured reanalysis covers
all 2,897 baseline C roots; global capture/replay bindings remain future work.
[Constant array indexes](docs/entry-state-analysis.md#constant-array-indexes)
reuse checked enum/arithmetic proofs for fixed indexes and unsigned mask or
remainder bounds, preserving runtime operand effects.
[Automatic arrays and initializer effects](docs/entry-state-analysis.md#automatic-arrays-and-initializer-effects)
classify proven private array accesses and preserve reads, calls and writes
from partial initializers. Persistent and qualified storage retain blockers.

Proven inline-array ranges now support generated capture/reconstruction:
constant indices and bounded unsigned `%`/`&` expressions are checked against
configured array extents. A reusable readonly AArch64 entry-state runner and
ELF/raw regression cover this path; arbitrary buffer ranges remain blocked.
[Counted-loop discovery](docs/entry-state-analysis.md#counted-loop-index-discovery)
now expands proven loop-counter intervals over inline arrays. Partial writes
retain incoming element values under preservation contracts; pointer extents
and unproved or mutable counters remain blocked.
Count-dependent loops may combine `i < count` with a literal capacity guard
using `&&`; [guarded-loop discovery](docs/entry-state-analysis.md#count-dependent-loops-with-capacity-guards)
retains condition reads/writes and checks that every condition term preserves
the counter before applying that guard to body accesses.
[Arithmetic index proofs](docs/entry-state-analysis.md#arithmetic-over-proven-loop-indices)
also admit nonwrapping 32-bit expressions such as `2 * i + 1` and `6 - 2 * i`.
Each intermediate operation/conversion is checked; strided selections capture
their complete enclosing interval, including gaps between accessed elements.
[Constant loop bounds](docs/entry-state-analysis.md#enum-and-inline-array-count-bounds)
can use portable enum values or matched `sizeof(array) / sizeof(array[0])`
expressions. Generated capture/replay assertions reject a changed array extent.
[Enum operator proofs](docs/entry-state-analysis.md#portable-enum-operator-proofs)
also support checked shifts, bitwise operators and C integer division/remainder
when constructing those bounds.
[Direct constant-expression loop headers](docs/entry-state-analysis.md#direct-constant-expression-loop-headers)
reuse these checked operations in initializers and capacity guards, such as
`i = (2U - 2U)` and `i < ((1U << 4) / 2U)`.
[Inclusive and reversed guards](docs/entry-state-analysis.md#inclusive-and-reversed-capacity-comparisons)
also admit `i <= 7`, `8 > i` and `7 >= i`, with checked conversion to an
exclusive upper limit.

Opt-in `--prune-written-fields` now omits selected reads after full stores that
cover every incoming path, under explicit stable/exclusive/provider-purity
contracts. Reports retain store evidence; writable replay still requires an
effect adapter, and default discovery keeps all reads.
The same proof now supports direct scalar fields of argument-backed objects
when their contracts explicitly promise stable identity, exclusive state and
state-preserving binding. Native fixture and AArch64 replay verify the reduced
entry payload and reject a correct-return implementation that omits the write.
Sequenced comma expressions can also establish store-before-read coverage.
Enclosing unsequenced expressions remain conservative; effectful assignment
targets invalidate earlier facts before right-hand reads are considered.
Conditional (`?:`) and short-circuit (`&&`, `||`) expressions now track
selected/skipped paths separately and retain only shared store facts afterward.
Captured post-state remains mandatory, including preservation when writes skip.
With `--prune-written-fields --preserve-write-state`, capture also retains
eligible incoming scalar values unless a full overwrite is proven at every
exit. This opt-in mode lets independent replay preserve skipped-write values;
the values come from entry snapshots. Native and AArch64 fixtures cover this
case; live policies retain their existing conservative footprints.
Nested scalar preservation also follows captured entry pointer edges. Replay
rejects writable traversal edges, including aliases through another root.
Fixtures verify independent replay and complete-footprint continuous replay.
Preservation's exit-store proof also recognizes direct argument-null guards
with an immediate pure return. A null exit cannot require that absent object's
scalar value; nonnull skipped-write paths still retain their incoming state.

A reusable export path now accepts typed plans, normalized snapshots, reviewed
models/adapters and a sequence of calls without a profile-specific exporter:

```sh
python3 tools/export_entry_state.py --request path/to/request.json --check-only
python3 tools/export_entry_state.py --request path/to/request.json --out build/entry-image
```

It supports mixed roots, additional C translation units, independent or
complete-footprint continuous replay, and portable verified ELF/raw bundles.
Live argument profiles use its shared build/verification backend while retaining
their native provenance checks. See the
[generic export contract](docs/entry-state-analysis.md#request-driven-entry-state-export)
for the request schema and remaining limits.
[Generated typed dispatch](docs/entry-state-analysis.md#generated-typed-replay-dispatch)
now binds object and scalar arguments directly from plans and capture records.
Requests and capture specifications can select it to remove handwritten
invocation routing; dependency models remain explicit. The native shared exporter
supports the same path with `--generated-dispatch`.
[Longer sessions](docs/entry-state-analysis.md#longer-capture-and-replay-sessions)
now support up to 256 calls through a bounded result transcript. Short sessions
retain ABI 8, and capture buffers remain seven calls by default; larger capture
capacity is an explicit specification and build setting.

The capture side now has shared generated call-site wrappers and a bounded
session serializer/importer. Selected sites invoke the original body once and
emit normalized entries, effects, scalar arguments and results without a custom
JSON collector. See [shared call-site capture](docs/entry-state-analysis.md#shared-call-site-capture)
for integration and lifetime/synchronization requirements.
The first live bridge uses `liteos_qemu_demo.py --shared-argument-capture`:
generated wrappers capture six original helper calls under the scheduler lock,
with legacy snapshots and a direct field witness retained for comparison.
`live_shared_capture.py --capture ... --out ...` verifies that native evidence
before exporting through the generic replay path.
The `--shared-mixed-capture` option interleaves an original scalar query with
those six void writes, preserving one object identity and continuous state across
both roots. Replay checks the query's exact value (`3`) and unchanged state.
See [mixed-root live capture](docs/entry-state-analysis.md#mixed-root-live-capture).
The [configured live frontend](docs/entry-state-analysis.md#configured-live-helper-sessions)
now accepts a supplied sequence of reviewed reads/writes through `--shared-session`.
It derives capture capacity and dispatch from that sequence and checks each call
against a direct native field/result witness before standalone replay.

Generated scalar write-effect replay is available for live `SysUmask` captures:

```sh
python3 tools/export_freestanding_umask.py --automated-entry-state \
  --capture build/live-entry-write-effects --out build/rtl-generated-umask-effects
```

Entry bytes and 32-bit arguments are restored; captured exit bytes are used only
for validation. The generated path restores invocations independently and
rejects pointer writes or graph changes. It requires a fresh capture containing
`entry-state-effects.json`.

Continuous generated umask replay is available with `--continuous`. Fresh
captures provide capture-scoped object IDs and an explicit stable-lifetime
contract. Replay restores once, verifies every subsequent entry, and carries
scalar updates between calls. Incompatible graphs, missing identities and
state discontinuities block generation; allocation reuse is not tracked.

Continuous reconstruction also supports direct pointer-field rebinding to null
or already captured objects with stable lifetimes. Generated checks verify
pointer identities, including aliases and cycles. Native fixture capture and
AArch64 ELF/raw tests cover this path. Live bounded `SysSetGroups` capture now
records allocation, pointer replacement and release. A reviewed dynamic adapter
now replays this sequence in self-contained AArch64 ELF/raw images. Nested
pointer writes and generic allocator analysis remain unsupported.

Generation-aware lifetime capture now distinguishes allocations that reuse an
address and records address-free events with snapshot cursors. Fresh live
captures validate this bundle and assign IDs at snapshot time. Scoped OHOS
allocator hooks cover three `SysSetGroups` calls and demonstrate address
reuse with distinct IDs. Target replay models allocation/free and credential
copy for that exact sequence; other captured families retain their explicit
stable-lifetime contracts.

```sh
python3 tools/export_freestanding_setgroups.py --arch aarch64 \
  --capture build/live-setgroups-lists-final \
  --out build/rtl-aarch64-setgroups
```

The new sequence includes a null list, `[0]`, and `[7,9]`. Normalized input bytes
are embedded in target memory; temporary buffers, user copies and all resulting
group fields are verified. Earlier null-list captures remain exportable. Larger
lists, input aliases/offsets, arbitrary partial copy failures and generic allocator analysis
remain outside this reviewed adapter.

Allocation failure outcomes are now captured and replayed, including cleanup
when a temporary list buffer succeeds but credential allocation fails. The live
failure regression injects scoped null allocator results explicitly; it does
not claim reproduction of physical memory pressure.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state \
  --setgroups-allocation-failures --out build/live-setgroups-oom
python3 tools/export_freestanding_setgroups.py --arch aarch64 \
  --capture build/live-setgroups-oom --out build/rtl-aarch64-setgroups-oom
```

User-copy failure replay now covers explicit failures before destination writes.
The null-list call succeeds; `[0]` and `[7,9]` return `-EFAULT`, preserve credentials
and release their temporary buffers. Capture v4 records copy source/destination
IDs, width, result and copied-byte count. Version 5 adds the controlled prefix-copy case below; natural MMU faults
remain outside the reviewed model.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state \
  --setgroups-copy-failures --out build/live-setgroups-copy-faults
python3 tools/export_freestanding_setgroups.py --arch aarch64 \
  --capture build/live-setgroups-copy-faults \
  --out build/rtl-aarch64-setgroups-copy-faults
```

Controlled partial user copies are also supported: the real capture helper copies
half of each nonnull input region, then reports the remaining byte count. The
syscall returns `-EFAULT`; capture and replay verify the copied prefix and unchanged
suffix before freeing the buffer, with credentials preserved. This mode excludes
other fault-injection options and does not reproduce natural translation faults.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state \
  --setgroups-partial-copy-failures --out build/live-setgroups-partial-copy
python3 tools/export_freestanding_setgroups.py --arch aarch64 \
  --capture build/live-setgroups-partial-copy \
  --out build/rtl-aarch64-setgroups-partial-copy
```

`getgroups` adds a reviewed user-output path. An optional live workload runs after
successful `setgroups` and captures a count query, `-EINVAL` for a short buffer,
and a successful copy of `[7,9,0]` into a shared four-word buffer. Replay checks
all output bytes, the untouched fourth word, unchanged credentials and temporary
allocation/free. Initial state and output are restored once; later frames are
assertions. The output-copy failure modes below extend this coverage.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --getgroups \
  --out build/live-getgroups
python3 tools/export_freestanding_getgroups.py --arch aarch64 \
  --capture build/live-getgroups --out build/rtl-aarch64-getgroups
```

`getgroups` also supports controlled output-copy failures. `none` injects failure
before any output writes; `half` copies six bytes of the 12-byte group list and
then fails. Both return `-EFAULT`, preserve credentials, free the temporary buffer,
and retain every output byte beyond the copied prefix. Natural MMU faults remain
outside this reviewed model.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --getgroups \
  --getgroups-copy-outcome half --out build/live-getgroups-partial-output
python3 tools/export_freestanding_getgroups.py --arch aarch64 \
  --capture build/live-getgroups-partial-output \
  --out build/rtl-aarch64-getgroups-partial-output
```

Use `--getgroups-copy-outcome none` for the zero-byte failure case; the default
`success` copies the complete group list.

`getgroups` temporary-allocation failure is also covered. The explicit null
allocation returns `-ENOMEM` under the scheduler lock, then unlocks without
copying or freeing. Capture/replay require unchanged output and credentials,
one failed request, no lifetime events and no copy attempts. This is a scoped
injection, not reproduction of physical memory exhaustion.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --getgroups \
  --getgroups-allocation-failure --out build/live-getgroups-oom
python3 tools/export_freestanding_getgroups.py --arch aarch64 \
  --capture build/live-getgroups-oom --out build/rtl-aarch64-getgroups-oom
```

Allocation-failure injection excludes output-copy failure injection.

`--getgroups-null-output` passes `NULL` to the size-2 call. Original kernel code
returns `-EFAULT` before the short-buffer check, without allocating or copying.
The surrounding count query and successful output call share the same 16-byte
buffer; it is sampled as a witness during the null call and must remain unchanged.
This is a real argument-error path and excludes allocation/copy fault injection.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --getgroups \
  --getgroups-null-output --out build/live-getgroups-null-output
python3 tools/export_freestanding_getgroups.py --arch aarch64 \
  --capture build/live-getgroups-null-output \
  --out build/rtl-aarch64-getgroups-null-output
```

`--getgroups-null-boundaries` captures a nonnull count query, a count query with
`NULL`, and a size-4 call with `NULL`. Returns are 3, 3, `-EFAULT`. No call allocates,
copies or frees; the shared output witness and credentials remain unchanged.
This mode excludes the short-buffer null mode and failure injection.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --getgroups \
  --getgroups-null-boundaries --out build/live-getgroups-null-boundaries
python3 tools/export_freestanding_getgroups.py --arch aarch64 \
  --capture build/live-getgroups-null-boundaries \
  --out build/rtl-aarch64-getgroups-null-boundaries
```

`--getgroups-negative-sizes` captures sizes 0, -1, and `INT32_MIN`. The -1 call
uses the valid output buffer and returns `-EINVAL`; the `INT32_MIN` call uses
`NULL` and returns `-EFAULT` before the size check. Signed values are retained in
JSON and their 32-bit patterns are checked against user observations and replay.
No allocation or copying occurs, and output/credentials remain unchanged. This
profile excludes other argument modes and failure injection.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --getgroups \
  --getgroups-negative-sizes --out build/live-getgroups-negative-sizes
python3 tools/export_freestanding_getgroups.py --arch aarch64 \
  --capture build/live-getgroups-negative-sizes \
  --out build/rtl-aarch64-getgroups-negative-sizes
```

`--getgroups-output-size` sets the final nonnull call's declared capacity from
3 through `INT32_MAX` (default 4). Size 3 is an exact fit for `[7,9,0]`; even the
largest declared capacity allocates/copies only the actual 12-byte group list.
The shared output remains a complete 16-byte object with a checked fourth word.
This option supports the existing allocation/copy-failure modes and excludes
nonnull-capacity changes in the null/negative argument profiles.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --getgroups \
  --getgroups-output-size 3 --out build/live-getgroups-exact-size
python3 tools/export_freestanding_getgroups.py --arch aarch64 \
  --capture build/live-getgroups-exact-size \
  --out build/rtl-aarch64-getgroups-exact-size
```

`--getgroups-output-offset` lets the final nonnull list point 0..4 bytes into the
same 16-byte output object. Capture/replay check all bytes, including untouched
bytes before the pointer and after the copied range. It supports full, zero and
partial output-copy outcomes and allocation failure; null/negative profiles
retain offset 0.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --getgroups \
  --getgroups-output-offset 1 --getgroups-copy-outcome half \
  --out build/live-getgroups-offset-partial
python3 tools/export_freestanding_getgroups.py --arch aarch64 \
  --capture build/live-getgroups-offset-partial \
  --out build/rtl-aarch64-getgroups-offset-partial
```

`--getgroups-group-count 1` captures after the first successful `setgroups`,
before the later calls replace that credential. It runs two count queries and
a final output call; `--getgroups-output-size 1` tests an exact fit. The captured
credential contains only `groups[0]`, allocation/copy width is four bytes, and
half-copy failure writes two bytes. The default count remains 3. Counts 1, 2 and 3
support success and allocation/copy failures, plus null/negative profiles.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --getgroups \
  --getgroups-group-count 1 --getgroups-output-size 1 \
  --getgroups-output-offset 4 --getgroups-copy-outcome half \
  --out build/live-getgroups-single-group
python3 tools/export_freestanding_getgroups.py --arch aarch64 \
  --capture build/live-getgroups-single-group \
  --out build/rtl-aarch64-getgroups-single-group
```

`--getgroups-group-count 2` establishes `[7, 0]` through the final original
`setgroups` call. Its getgroups sequence returns 2, `-EINVAL`, then 2 on success;
allocation/kernel/user copies use eight bytes, and half-copy failure writes four.
The same capture can also be exported through the setgroups exporter.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --getgroups \
  --getgroups-group-count 2 --getgroups-output-size 2 \
  --getgroups-output-offset 4 --getgroups-copy-outcome half \
  --out build/live-getgroups-two-group
python3 tools/export_freestanding_getgroups.py --arch aarch64 \
  --capture build/live-getgroups-two-group \
  --out build/rtl-aarch64-getgroups-two-group
```

`--getgroups-copy-bytes N` injects failure after any prefix of 0 through
`4 * group_count - 1` bytes. This includes prefixes ending inside an integer.
It excludes allocation failures, null/negative profiles and other copy-outcome
options. The capture records the exact bytes written and remaining byte count;
replay checks the full output object and balanced temporary allocation/free.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --getgroups \
  --getgroups-output-size 3 --getgroups-output-offset 1 \
  --getgroups-copy-bytes 5 --out build/live-getgroups-copy-prefix
python3 tools/export_freestanding_getgroups.py --arch aarch64 \
  --capture build/live-getgroups-copy-prefix \
  --out build/rtl-aarch64-getgroups-copy-prefix
```

The null and negative-size profiles also accept `--getgroups-group-count 1`
and `2`. In the one-group null-short profile, the middle size is zero: even
with NULL, it returns 1 as a count query. With two groups the middle size is 1
and NULL returns `-EFAULT` before the short-buffer error. Null-boundary profiles
return the count for both zero-size calls, then `-EFAULT` for the nonzero NULL
call; negative profiles preserve `-EINVAL` for nonnull negative size and
`-EFAULT` for negative size with NULL. The latter two profiles allocate/copy
nothing and preserve the output witness.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --getgroups \
  --getgroups-group-count 1 --getgroups-null-boundaries \
  --out build/live-getgroups-single-null-boundaries
python3 tools/export_freestanding_getgroups.py --arch aarch64 \
  --capture build/live-getgroups-single-null-boundaries \
  --out build/rtl-aarch64-getgroups-single-null-boundaries
```

`getresuid` is also supported with the unchanged `SysGetRealEffSaveUserID` body.
The four-call profile covers success and NULL at each of the three output
positions. It verifies ordered copies, retained writes before failure, untouched
output guards and early termination. A scoped native fixture supplies distinct
real/effective IDs 6001/6002 and restores the native fields outside each captured
call. The pinned kernel returns effective UID as saved UID. This is a reviewed
copy adapter; arbitrary pointer aliases and MMU faults remain unsupported.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --getresuid \
  --out build/live-getresuid
python3 tools/export_freestanding_getresuid.py --arch aarch64 \
  --capture build/live-getresuid --out build/rtl-aarch64-getresuid
```

`--getresuid` excludes `--getgroups` and setgroups fault injections. The image
restores its captured credential and shared output object once, then checks all
four entries/exits. It requires no runtime host interaction.

`getresgid` now uses the shared ordered-copy capture, validator, exporter and
AArch64 adapter with a separate source lock. Its four calls cover success and
NULL at each output position. The scoped native GID fixture is 7001/7002; the
pinned body reports `effGid` as saved GID. Native credentials are restored outside
each captured call. The image executes without runtime host interaction.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --getresgid \
  --out build/live-getresgid
python3 tools/export_freestanding_getresgid.py --arch aarch64 \
  --capture build/live-getresgid --out build/rtl-aarch64-getresgid
```

The UID/GID capture modes exclude each other, `--getgroups` and setgroups fault
injections. Both retain the reviewed nonaliasing output and native NULL-rejection
scope; natural MMU faults and RTL/cycle timing remain unverified.

The UID/GID queries also accept `--credential-output-offsets A,B,C`, with each
byte offset in `0..12` inside the shared 16-byte witness. Repeated offsets alias;
ranges may overlap or be unaligned. Copies execute in source order, so later
successful copies overwrite earlier bytes. NULL still stops the syscall at that
position. For example:

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --getresgid \
  --credential-output-offsets 1,3,5 --out build/live-getresgid-overlap
python3 tools/export_freestanding_getresgid.py --arch aarch64 \
  --capture build/live-getresgid-overlap \
  --out build/rtl-aarch64-getresgid-overlap
```

Nondefault geometry uses capture/manifest version 2, bound to the capture build
configuration. Legacy version 1 retains offsets `0,4,8`. The AArch64 adapter uses
byte stores and checks the entire witness after each call, preserving overlaps
without requiring aligned user pointers. The copy contract remains reviewed;
general user-memory graphs and natural MMU faults are outside its scope.

UID/GID query captures now generate their scalar snapshot fields from configured
Clang analysis. The native harness invokes the generated hook; it no longer
lists the queried fields by hand. A reviewed binding maps `OsCurrUserGet()` to
the current process's user edge, and the ordered-copy adapter remains explicit.
Inspect this construction step with:

```sh
python3 tools/automated_entry_state.py --credential-query getresgid \
  --out build/getresgid-generated-plan
```

New captures include the discovery plan, projected capture plan and generated
hook header. Export independently reanalyzes the pinned configured source and
checks those artifacts before publication, including their source dependencies.
Changed reads, writes or dependencies fail closed. Earlier captures remain
supported and are labeled as using legacy reviewed fields. This automates field
discovery and capture; it does not infer generic user-copy behavior or prove
minimality/completeness of the analysis.

`--credential-ids REAL,EFFECTIVE` configures the scoped UID/GID fixture across
`0..UINT32_MAX`; decimal and hexadecimal values are accepted. Zero, equal IDs
and high-bit values are supported. These are explicitly installed native User
field bit patterns and are restored after each captured call; the fixture does
not claim that credential-changing syscalls established those values.

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --getresgid \
  --credential-ids 0x80000000,0xffffffff --credential-output-offsets 1,3,5 \
  --out build/live-getresgid-full-width
python3 tools/export_freestanding_getresgid.py --arch aarch64 \
  --capture build/live-getresgid-full-width \
  --out build/rtl-aarch64-getresgid-full-width
```

Nondefault IDs use version 3 with explicit output offsets, ID build macros and
Clang-generated fields. Export rejects missing, changed, duplicate or malformed
ID macros even when the configuration hash is updated. Earlier versions retain
their original fixture IDs. The original syscall's signed `int` output locals
preserve the 32-bit patterns on the verified AArch32/AArch64 builds. Replay keeps
the same self-contained runtime and four-call copy contract.


Process-mode `sched_getscheduler` now has a reviewed dependency capture and
self-contained AArch64 exporter:

```sh
python3 tools/liteos_qemu_demo.py --getscheduler --out build/live-getscheduler
python3 tools/export_freestanding_getscheduler.py \
  --capture build/live-getscheduler --out build/rtl-aarch64-getscheduler
```

The four calls use IDs 0, 1, -1 and unused slot 63, all with flag 0. Native
`SysSchedGetScheduler` executes through the existing SVC dispatcher. Export
rebuilds its complete pinned original body with embedded ordered current-PID
and process-scheduler dependency outcomes. Successful lookups write the captured
policy through the actual target local pointer; failures return without a policy
write. Scheduler internals and task mode are outside this contract; reaching task
mode terminates with an error. The manifest supplies ELF entry, load segments,
raw-image load address and the 128-byte ABI 9 RAM result location. ELF/raw results
must match exactly, with no guest I/O or runtime host services. This is functional
QEMU verification; RTL execution and cycle timing remain unverified.

Task-mode `sched_getscheduler` is available as a separate four-call profile:

```sh
python3 tools/liteos_qemu_demo.py --getscheduler-task \
  --out build/live-getscheduler-task
python3 tools/export_freestanding_getscheduler.py \
  --capture build/live-getscheduler-task --out build/rtl-aarch64-getscheduler-task
```

It uses flag -1 with the current task, invalid ID -1, unused slot 127 and foreign
kernel task 0. The actual kernel returns policy 2, EINVAL, EINVAL and EPERM. The
successful indirect callback is captured by forwarding to the original function
through a temporary operations-table binding installed under the syscall's
scheduler lock and restored before unlock. Permission results and policy values come from the real helpers.

The target executes the complete original syscall body with a logical task,
a typed callback and embedded permission/policy outcomes. ABI 10 checks bounds,
lookup identity, permission/callback order and balanced lock ownership, and
publishes every return and dependency cursor to RAM. This profile requires
physical task IDs and the captured task limit of 128; it does not replay a full
TCB, callback internals, task lifecycle, interrupts or scheduler timing. Callback
output replay projects the policy field that the syscall reads. ELF/raw results
match without runtime host services; RTL and cycle timing remain unverified.
Earlier process-mode captures remain supported and retain their original scope.

MMU-off replay images now carry a `target.memory_contract` with physical RAM
ranges, stack bounds, startup BSS clearing and loader zero-fill requirements.
All required RAM must remain accessible for the run. The loader copies each
ELF segment's file bytes and zeroes its memory tail; raw loading uses the same
zero-fill plan and additionally requires the entire raw payload span to be RAM.
The entry ABI requires the MMU to be off (EL1 for AArch64).

Validate against the actual RTL model's RAM map before loading:

```sh
python3 tools/check_image_memory.py \
  --image build/rtl-aarch64-getscheduler-resident-final-verified/getscheduler.elf \
  --binary build/rtl-aarch64-getscheduler-resident-final-verified/getscheduler.bin \
  --ram 0x40000000:0x4000000 --out build/rtl-memory-preflight.json
```

`--ram BASE:BYTES` can be repeated for multiple banks; supply the model's real
ranges. The example describes 64 MiB starting at 0x40000000. Preflight checks
ELF segments, result memory, the whole reserved stack, startup clearing and raw
payload identity/coverage. New linker scripts include aligned BSS padding in the
writable segment. Earlier images remain inspectable, with any legacy startup
padding explicitly added to their RAM requirement. The QEMU runner performs the
same coverage check against its configured 64 MiB before starting a machine.

To verify the loader's actual output, add `--memory-dump BASE:FILE` to the
preflight command for physical bytes captured after loading and zero-fill,
before the first instruction. Repeat it for multiple dumps; adjacent files can
cover a segment. The tool compares file-backed bytes, zero-fill tails (including
result storage and BSS), and raw inter-segment bytes when `--binary` is supplied.
It rejects missing coverage, overlapping dumps and mismatches with their physical
address, and records dump hashes. A map-only check reports
`initial_memory_verified: false`. The caller must supply a snapshot from the
specified phase; a dump alone cannot establish when it was taken.

The QEMU runner can capture and verify that phase automatically:

```sh
python3 tools/run_freestanding_armv7.py \
  build/rtl-aarch64-getscheduler-resident-final-verified/getscheduler.elf \
  --initial-memory-dir build/initial-memory-snapshot
```

The output directory must be new. QEMU starts stopped, saves physical dumps,
verifies initialization, and then executes the image. For a raw image, also
supply `--descriptor IMAGE.elf`. This is external testbench observation with no
guest host services. The same dump checker can inspect RTL loader output.

Generate a portable load bundle for a testbench that accepts addressed RAM files:

```sh
python3 tools/rtl_load_bundle.py prepare \
  --image build/rtl-aarch64-getscheduler-resident-final-verified/getscheduler.elf \
  --binary build/rtl-aarch64-getscheduler-resident-final-verified/getscheduler.bin \
  --ram 0x40000000:0x4000000 --out build/rtl-load-bundle
python3 tools/rtl_load_bundle.py verify build/rtl-load-bundle
python3 tools/run_freestanding_armv7.py --load-bundle build/rtl-load-bundle \
  --initial-memory-dir build/bundle-loaded-memory
```

`load-plan.json` supplies the entry point, physical address/size/hash of each
`bank-NNN.bin`, source hashes, result location and entry requirements. Load all
bank bytes before starting the CPU. The files include zero-filled result/BSS
storage; raw mode also includes raw gap bytes. They cover the required image
ranges rather than the entire declared RAM capacity. All paths are relative to
the bundle directory, so it can move without access to the capture or build tree.
Verification derives the plan again from its packaged ELF and checks bank
contents and hashes. Preparation requires a new directory and leaves no bundle
on failure. Generated-bank verification does not establish actual model memory;
use a model dump for that check. Keep bundle files unchanged during verification
and loading. Bundling does not replace the replay exporter's code/source audit.

Bundle preparation supports both ISAs. The QEMU addressed-bank execution option
currently supports AArch64; ARMv7's legacy RAM-base result placement conflicts
with the `virt` bare-metal device tree. Existing ARMv7 ELF/raw execution remains
available. The bundle introduces no runtime guest services or host fault handling.

Check the actual testbench RAM against the bundle before executing it:

```sh
python3 tools/rtl_load_bundle.py check-loaded build/rtl-load-bundle \
  --ram 0x40000000:0x4000000 \
  --memory-dump 0x40000000:model-ram-before-execution.bin \
  --out build/rtl-loaded-memory.json
```

Supply the model's actual RAM map and dump base addresses; repeat both options
for split banks. The checker first verifies the bundle, then compares every
bank byte, including padding, with the physical dumps. Extra dumped RAM has no
expected-value constraint. This reports `model_initial_memory_verified: true`
when the byte comparison passes. Standalone `snapshot_phase_verified` remains
false: the caller must take the dump at the requested phase. The QEMU bundle
runner performs this exact check while stopped before the first instruction and
records that phase as verified. CPU entry checks are optional; RTL execution is
not verified. No success report is written after a failed comparison.

For AArch64, add `--cpu-state model-cpu-before-execution.json` to `check-loaded`.
The register snapshot uses unsigned JSON integers:

```json
{"format":"osrec-aarch64-entry-state-v1","pc":1075838976,"pstate":965,"sctlr_el1":0}
```

This example describes PC 0x40200000, EL1h with all DAIF masks set and MMU/caches
off. Supply the model's observed register values. The conservative entry profile
requires the ELF entry PC, AArch64 EL1t/EL1h, masked DAIF, clear PSTATE IL/SS,
MMU and caches off, and little-endian EL1 data access. It checks only the listed
fields; architecture extensions and microarchitectural state remain outside its
scope. Initial SP and vector base are set by image startup.

For higher-level checks, use `osrec-aarch64-entry-state-v2` with an
`implementation` object containing boolean `el2_implemented` and
`el3_implemented`, plus `mdscr_el1`. When EL2 is implemented, also supply
`hcr_el2`, `cptr_el2` and `mdcr_el2`; when EL3 is implemented, supply `scr_el3`,
`cptr_el3` and `mdcr_el3`. The stricter baseline profile requires debug control
off, stage 2/routing/injection/traps off, and the appropriate AArch64/non-secure
controls. It allows documented baseline reserved bits and the PMU counter count.
Absent levels need no register values. V1 snapshots retain their earlier scope
with higher-level checks unverified. V2 checks the declared implementation;
standalone files cannot establish that the declaration matches actual hardware.

QEMU can capture both memory and the register snapshot automatically:

```sh
python3 tools/run_freestanding_armv7.py --load-bundle build/rtl-load-bundle \
  --initial-memory-dir build/memory-and-cpu-snapshot --check-entry-state
```

The register observer uses read-only GDB remote packets over local pipes. It
needs no installed GDB client, sends no execution or register-write requests,
and runs before the first QMP `cont`. QEMU snapshots now use v2 and observe actual
EL2/EL3 presence through CPU model properties. The report includes the CPU snapshot hash,
checked fields and observed phase. Standalone snapshots retain an unverified
phase even when all their checked fields pass. This adds no guest host service.

To exercise replay with EL2 and EL3 implemented, add `--boot-from-el3`:

```sh
python3 tools/run_freestanding_armv7.py --load-bundle build/rtl-load-bundle \
  --initial-memory-dir build/el3-boot-snapshot --check-entry-state --boot-from-el3
```

This builds a standalone, stackless guest boot shim at `0x43f00000`, checks that
its reserved page overlaps no replay range or raw payload, and boots from EL3
into nonsecure EL1h. The shim programs the listed baseline controls and transfers
to the supplied ELF entry using `eret`. Its source, disassembly, ELF, raw payload
and hashed load plan are saved under the snapshot directory's `boot/` directory.
For a separate RTL loader, generate the same artifact with
`python3 tools/aarch64_boot.py IMAGE.elf --out NEW_DIRECTORY`; load `boot.bin`
at the plan's address alongside the replay banks and start in the documented
EL3 state at the boot entry.

Boot verification independently re-derives the complete instruction payload
from the reviewed template and ELF entry, checks the plan, and rejects changed
code even if its hash is updated. QEMU compares all 104 boot bytes at reset and
at the replay entry; the unused bytes of the reserved boot page are unconstrained.
To check a separate model's boot dump:

```sh
python3 tools/aarch64_boot.py IMAGE.elf --verify-directory BOOT_DIRECTORY \
  --ram 0x40000000:0x4000000 --memory-dump 0x43f00000:BOOT_DUMP.bin
```

Without `--memory-dump`, this verifies only the generated plan and payload.
Caller-supplied dumps retain an unverified snapshot phase. Load only the verified
raw `boot.bin`; auxiliary source/ELF/disassembly files are for review. Starting
the shim requires AArch64 EL3 reset with EL2/EL3 implemented, EL3 MMU/caches off,
and accessible physical RAM.

The external testbench installs one hardware breakpoint at the replay entry,
continues the boot shim, then removes the breakpoint. It writes no guest memory
or registers. The register observer remains read-only. CPU and replay bank
checks occur before the first replay instruction, after the boot transition;
the report records this phase and the EL3 reset snapshot separately. The guest
needs no debugger or host service to perform the transition or replay. This path
requires the baseline EL2/EL3 configuration and does not prove RTL timing or
extension-specific control compatibility.

A combined portable bundle provides one physical load list for boot and replay:

```sh
python3 tools/rtl_boot_bundle.py prepare \
  --replay-bundle build/rtl-load-bundle --out build/rtl-el3-bundle
python3 tools/rtl_boot_bundle.py verify build/rtl-el3-bundle
python3 tools/run_freestanding_armv7.py --boot-bundle build/rtl-el3-bundle \
  --initial-memory-dir build/portable-boot-snapshot --check-entry-state
```

Its root `load-plan.json` contains relative `loads` filenames, addresses, lengths
and hashes; `entry` is the EL3 boot entry and `replay_entry` is the supplied ELF
entry. Copy every listed load byte to physical RAM and start with the listed
EL3 reset requirements. Nested `replay/` and `boot/` plans bind the banks to the
ELF and the boot code to the reviewed instruction template. The verifier derives
the root plan again and rejects changes to either nested artifact or root fields.
`prepare --boot-address ADDRESS` can relocate the boot shim to another page
inside the supported RAM window; the page must be covered by the declared RAM
and overlap no replay range or raw payload.

The observer loads this bundle without compiling or requiring construction
sources. Its checkpoint report includes the root plan hash. For independent
model snapshots, `rtl_boot_bundle.py check-loaded DIRECTORY --ram BASE:BYTES
--memory-dump BASE:FILE ... --cpu-state STATE.json --out NEW_REPORT.json` checks
all replay banks, the boot payload and optional listed EL1 CPU fields. Include
dumps covering every load. Caller-supplied snapshots retain an unverified phase;
these checks alone do not establish successful execution. The unused boot-page
padding is unconstrained. Moving the bundle does not require changing its plan.

QEMU is the project verification target. Customer model integration can use the
same portable bundles; customer RTL execution is outside our verification work.
The complete QEMU acceptance command is:

```sh
python3 tools/verify_qemu_bundle.py build/rtl-el3-bundle \
  --out build/qemu-verification
```

This also accepts a replay-only bank bundle. It verifies input artifacts, observes
and checks physical memory and CPU entry state, executes the replay, checks its
embedded expectations, and independently rechecks the saved memory dumps. The
new output directory contains `verification.json`, QEMU version, load-plan hash,
CPU/memory evidence, `execution-report.json`, `target-result.bin` and evidence
hashes. Combined bundles include boot checks at reset and replay entry. Execution
uses packaged bytes without compiling. Existing output is never overwritten;
a run failure after output creation records `status: failed` and exits with an
error. A successful report covers QEMU functional behavior and the listed entry
controls; it does not claim every architecture feature or cycle timing.

The practical replay set now includes `clock_gettime` and `clock_getres`.
Native capture forwards both original LiteOS syscall bodies and clock providers,
with five cases per call: realtime, monotonic, invalid clock, NULL output and an
invalid output address. It records eight provider outcomes and six real
user-copy outcomes, and checks all output bytes and errno effects during replay.

```sh
python3 tools/liteos_qemu_demo.py --clocks --out build/live-clocks
python3 tools/export_freestanding_clocks.py --capture build/live-clocks \
  --out build/aarch64-clocks --entry-address 0x40400000 --result-address 0x40380000
python3 tools/rtl_load_bundle.py prepare --image build/aarch64-clocks/clocks.elf \
  --ram 0x40000000:0x4000000 --out build/clocks-load-bundle
python3 tools/verify_qemu_bundle.py build/clocks-load-bundle \
  --out build/clocks-verification
```

The pinned SVC numbers are 263/264, named `clock_gettime32` and
`clock_getres_time32` by its lookup table. Its actual configured OHOS `timespec`
layout is 16 bytes: signed 64-bit seconds, signed 32-bit nanoseconds at offset 8,
and four padding bytes. Capture asserts the native widths; replay preserves
this layout explicitly and checks zero padding. This is the captured OHOS ABI,
not a claim that all architectures use the same syscall ABI. AArch64 replay
supports full nonnegative signed 64-bit seconds; tests include values beyond
32-bit seconds.

Clock images use result ABI 11: ten returns and errno values, eight provider
calls, six copy attempts, 64 successfully copied bytes, fourteen consumed events
and ten checked output states. The native invalid-output case records the real
copy API's failure; replay models that outcome without causing an MMU fault.
Each call starts with a scoped errno-zero fixture. The image needs no live clock
service, filesystem or host service. Clock provider internals, timer interrupts
and elapsed execution timing are outside the replay scope.

Resource-limit queries now use the original `SysUgetrlimit` body (`ugetrlimit`,
SVC number 191). The bounded profile captures six cases: `RLIMIT_NOFILE`,
`RLIMIT_FSIZE`, invalid resource -1, valid resource with NULL output, valid
resource with an invalid output address, and unsupported `RLIMIT_CPU` with NULL
output. The provider runs before the copy API, so unsupported resources return
`-EINVAL` even with NULL output. Native and replay returns are
`0, 0, -EINVAL, -EFAULT, -EFAULT, -EINVAL`.

```sh
python3 tools/liteos_qemu_demo.py --resource-limits --out build/live-rlimit
python3 tools/export_freestanding_rlimit.py --capture build/live-rlimit \
  --out build/aarch64-rlimit --entry-address 0x40400000 --result-address 0x40380000
python3 tools/rtl_load_bundle.py prepare --image build/aarch64-rlimit/rlimit.elf \
  --ram 0x40000000:0x4000000 --out build/rlimit-load-bundle
python3 tools/verify_qemu_bundle.py build/rlimit-load-bundle \
  --out build/rlimit-verification
```

The ABI is two unsigned 64-bit limits (16 bytes), explicitly preserved in
AArch64 replay. Tests include high-bit values and `UINT64_MAX`. Native capture
records actual process-provider outcomes; it does not install limit values.
The reduced native process currently returns zero limits when its limit table
is absent. Replay consumes the recorded provider values, executes the original
syscall's checks and copy, and verifies every output witness. Result ABI 12
reports six provider calls, four copy attempts, 32 successfully copied bytes,
ten consumed events and six verified output states. A scoped errno-zero fixture
is preserved; this kernel body returns errors directly without setting errno.
Provider internals and resource-limit updates are outside this query profile.

The practical families currently covered are:

| Family | Calls |
| --- | --- |
| Input | Captured bounded `read` sessions |
| Identity | `getpid`, `getppid`, `gettid`, UID/GID and effective IDs, process-group queries |
| Process settings | `umask`, `getpriority`, scheduler priority limits, bounded `getrlimit` queries |
| Credentials | Bounded `setgroups`/`getgroups`, `getresuid`, `getresgid` |
| Scheduler queries | Process/task `sched_getscheduler` |
| Time queries | Captured `clock_gettime`, `clock_getres` |
| System identity | Captured `uname`, including input tails and invalid pointers |
| Descriptor lifecycle | Bounded `close` and `dup`, including rollback/free, aliases/reference counts and invalid descriptors |

Each family retains its reviewed source/dependency profile and explicit bounds.

`uname` now uses the original `SysUname` body (SVC 122), with two successful
queries initialized with different byte patterns, NULL, and invalid address 1.
The pinned OHOS structure contains six 65-byte fields (390 bytes). Unlike an
output-only query, this syscall copies the entire caller buffer into a temporary
structure before invoking the identity provider. Capture and replay validate all
390 input bytes, all provider/output bytes, untouched string tails, two adjacent
guard bytes, and the ordered input/provider/output operations. Invalid pointers
return `-EFAULT` at the input copy and never reach the provider.

```sh
python3 tools/liteos_qemu_demo.py --uname --out build/live-uname
python3 tools/export_freestanding_uname.py --capture build/live-uname \
  --out build/aarch64-uname --entry-address 0x40400000 --result-address 0x40380000
python3 tools/rtl_load_bundle.py prepare --image build/aarch64-uname/uname.elf \
  --ram 0x40000000:0x4000000 --out build/uname-load-bundle
python3 tools/verify_qemu_bundle.py build/uname-load-bundle \
  --out build/uname-verification
```

The AArch64 image returns the captured OHOS identity, including the native ARM
machine string and build version; it does not query its execution environment.
The provider boundary consumes recorded bytes, while the original syscall body
performs its input-copy and output-copy control flow. Provider internals and UTS
containers are outside this profile. ABI 13 verifies four calls, two providers, four
input-copy attempts, two output copies, eight dependency events, and 1560 copied
bytes. ELF/raw loading, direct EL1 entry, and EL3-to-EL1 boot are verified on QEMU.
No runtime host services are required.

The optional `--uname-faults` capture extends these four calls with a 195-byte
input-copy prefix followed by failure, provider `-EIO` before writes, output-copy
failure before writes, and a 195-byte output-copy prefix followed by failure:

```sh
python3 tools/liteos_qemu_demo.py --uname-faults --out build/live-uname-faults
python3 tools/export_freestanding_uname.py --capture build/live-uname-faults \
  --out build/aarch64-uname-faults
```

These four extra cases inject scoped dependency outcomes while the real OHOS
syscall body runs. They are marked as injected in capture/image manifests; they
do not reproduce hardware MMU faults or induce a natural provider failure. The
partial input-copy payload contains only the copied prefix, with a zero suffix
for canonical serialization; it does not serialize uninitialized temporary
bytes. Replay copies only that prefix and takes the original error branch. For
partial output failure, replay preserves the unchanged caller suffix and both
guard bytes. The eight-call result ABI 14 verifies five provider calls, eight
input-copy attempts, four output-copy attempts, 17 events and 3120 copied bytes.
The existing four-call ABI 13 remains supported.

Descriptor lifecycle replay now executes the original `SysClose` body (SVC 6).
The workload opens a dedicated file at process descriptor 4 with `O_CLOEXEC`,
then closes it five times: a scoped provider `EIO` before release, a successful
retry, repeated close, descriptor -1, and out-of-range descriptor 1024. The last
three calls return `-EBADF`. Each call starts with a scoped errno-zero fixture.

```sh
python3 tools/liteos_qemu_demo.py --close-lifecycle --out build/live-close
python3 tools/export_freestanding_close.py --capture build/live-close \
  --out build/aarch64-close --entry-address 0x40400000 --result-address 0x40380000
python3 tools/rtl_load_bundle.py prepare --image build/aarch64-close/close.elf \
  --ram 0x40000000:0x4000000 --out build/close-load-bundle
python3 tools/verify_qemu_bundle.py build/close-load-bundle \
  --out build/close-verification
```

Native capture records descriptor association, allocation and close-on-exec
flags before and after each dependency operation and syscall. The failed first
close restores the association and preserves both flags. Successful retry frees
and clears all three fields. Subsequent invalid closes preserve that free state.
Replay independently applies these bounded descriptor transitions, validates
all 15 captured events and five entry/effect witnesses, and checks errno
propagation. ABI 15 requires five detaches, five provider calls, four restoration
attempts, one free, and four errno reads. Tests use different process/system
descriptor numbers and relocated images, ELF/raw banks, and EL1/EL3 starts.

The initial open supplies the captured descriptor fixture; `open` is outside
this replay. The first provider failure is explicitly marked as injected in the
capture and image manifests. Full descriptor tables, locks, vnode/driver close
internals, sockets, standard descriptors and concurrent close are outside the
profile. System-descriptor lifetime is modeled from the captured provider
outcomes; native descriptor-table fields are observed directly. No runtime host
filesystem or services are required.

Descriptor duplication now executes the original `SysDup` body (SVC 41).
The workload opens a dedicated descriptor 4 with `O_CLOEXEC`, then attempts a
scoped allocation failure, duplicates descriptor 4 to 5, duplicates descriptor 5
to 6, and tries descriptors -1 and 1024. Raw returns are `-EMFILE`, 5, 6,
`-EBADF`, `-EBADF`. Unlike `close`, this root returns its errors directly and the
scoped native errno-zero fixture remains unchanged.

```sh
python3 tools/liteos_qemu_demo.py --dup --out build/live-dup
python3 tools/export_freestanding_dup.py --capture build/live-dup \
  --out build/aarch64-dup --entry-address 0x40400000 --result-address 0x40380000
python3 tools/rtl_load_bundle.py prepare --image build/aarch64-dup/dup.elf \
  --ram 0x40000000:0x4000000 --out build/dup-load-bundle
python3 tools/verify_qemu_bundle.py build/dup-load-bundle \
  --out build/dup-verification
```

Native capture observes mappings and allocation/close-on-exec flags for slots
4..6 plus the shared file's reference count before and after each operation and
syscall. Successful duplicates share the same system descriptor; native reference
count increases from 1 to 3. The original retains close-on-exec and both
duplicates have it cleared. The allocation failure changes no fields. Replay
independently applies the bounded lookup/allocation/reference/association effects
and validates all 12 events and five entry/effect witnesses. ABI 16 checks five
lookups, three allocation attempts, two reference increments and two associations,
three allocated aliases, original-only close-on-exec, and final reference count 3.
It preserves the captured `CONFIG_NFILE_DESCRIPTORS` bound (512 in the native
fixture); tests also exercise different bounds and distinct process/system IDs.

The initial open supplies the fixture; its syscall body, full descriptor-table
search, locks, sockets, concurrent updates, arbitrary reference counts and shared
read/write-position behavior remain outside this profile. The first allocation
failure is explicitly identified as injected. ELF/raw images and EL1/EL3 starts
are verified on QEMU, with no runtime host filesystem/services.

This validates declared/loading/startup ranges. It does not prove every dynamic
pointer access, absence of stack overflow, or bus/model correctness. Initial
contents are checked only when dumps are supplied. Resident accessible RAM with MMU disabled
requires no demand-paging or MMU-fault service. Injected user-copy failures remain
logical syscall error tests; they are not hardware MMU faults.

## Shared-state file operations

The `--file-operations` profile now captures and replays a 32-call
create/write/openat/dup2/seek/read/fstat64/stat/close session, including shared
positions, descriptor replacement, cleanup and natural error paths. The
AArch64 ELF and raw images run without host services. QEMU verifies both loading
formats from EL1 and EL3. See [the workflow, commands and bounds](docs/file-operations.md).

The file session now also builds a returning, explicit-context syscall-slice
library for application checkpoint containers. Kernel state persists between
calls, and independent sessions remain isolated. The automated Clang transformation
and declarative kernel-port interface are described under
[callable slices and kernel ports](docs/file-operations.md#callable-slices-for-application-checkpoints).


Application containers can now route saved AArch64 syscall frames through the
same library. The port generates register conventions and syscall argument counts;
the bridge preserves unused registers and updates the computed result and recorded
continuation PC. See [the saved-frame interface and automated QEMU verification](docs/file-operations.md#saved-aarch64-application-frames).
The [live CPU gateway](docs/file-operations.md#live-aarch64-cpu-gateway) now runs
EL0 application code through embedded syscall routes on QEMU, using private
slice stacks and preserving persistent session state.

## Application ELF/checkpoint import

Supplied static AArch64 ELFs can now be paired with a neutral recorded CPU/memory checkpoint and ordered syscall PCs. The importer generates BRK patches, preserves original SVC bytes, embeds initial application memory, and binds multiple executable segments to the returning kernel gateway. The application prepares arguments and consumes returns in EL0; kernel state persists across the sequence. The composed image verifies joint application/kernel restoration in QEMU.

See [the application checkpoint workflow](docs/application-checkpoints.md) for the input schema, automated commands, generated file application, and current bounds.

The [compiled C application workflow](docs/c-application-windows.md) now derives entry, stack, and syscall routes from a linked user ELF and verifies resumable syscall windows in one command. Application CPU/memory and kernel state persist between windows; the practical 32-call file lifecycle is tested with one-call and grouped windows on QEMU.

The [standalone joint-checkpoint workflow](docs/standalone-application-checkpoints.md) saves kernel state and the live application CPU/RAM at an intermediate syscall pause, then resumes only the remaining calls in a fresh QEMU image. The shared field codec checks reviewed state policies and rebuilds context self-references after relocation. The C frontend automates construction and four-mode QEMU verification of both producer and consumer.

The [external kernel-port workflow](docs/external-kernel-ports.md) builds reviewed port bundles outside this repository, pins construction inputs and provides a generic returning-slice proof protocol. A separate 64-bit fixture exercises the complete build and checkpoint chain through the shared infrastructure.

[Byte-preserving source rewriting](docs/external-kernel-ports.md#byte-preserving-source-workflow) now applies Clang offsets to original UTF-8 bytes. Multibyte comments, identifiers and string seeds retain their spelling, while CRLF and BOM inputs keep exact provenance. A QEMU checkpoint regression verifies reconstructed string pointers and cumulative state across fresh images.

[Local enum seed reconstruction](docs/local-static-context-state.md#local-enum-seed-checkpoint-workflow) preserves target-evaluated constants and shadowed scopes for mutable local state, sparse designators and pointer offsets. Generated context names avoid existing declarations and macros. The portable QEMU checkpoint fixture checks persisted array contents, pointer rebinding and cumulative counters across fresh images.

The [Linux kernel preflight](docs/linux-aarch64-slices.md#automated-workflow) checks reviewed profile inputs, syscall ABI, required kernel configuration and optional LLVM/QEMU tools before a new capture. It reports the current 35-profile/39-route inventory and keeps prerequisite checks distinct from native behavioral verification.

[Minimal AArch64 Linux slices](docs/linux-aarch64-slices.md) reuse the gateway, persistent contexts and checkpoint chains. The `minimal` profile supplies 20 calls across ten process/credential/mask syscalls. The `credentials` profile adds original Linux `setresgid` execution: 42 native calls, mutable group credentials, copy-on-write publication and active-slot references preserved through fresh-image resumes. The `fsgid` profile adds original `setfsgid`: 62 calls across twelve roots, filesystem-group changes, silent denial and candidate aborts. The `group-setters` profile adds original `setgid` and `setregid`: 94 calls across fourteen roots, saved-ID rules and aborts after partial candidate updates. The `getgroups` profile adds supplementary queries: 112 calls across fifteen roots, a shared persisted list and native guard-page partial faults. The separate `setgroups` profile adds runtime supplementary-list replacement with effective `CAP_SETGID`: 56 calls across twelve roots, sorted duplicates, empty lists, guarded input faults and persisted list lifetimes. The `setgroups-denied` profile adds 60 calls with observed missing effective `CAP_SETGID`, permission-error precedence and unchanged credential/list pools across resumes. The `capabilities` profile adds original `capset` and commoncap rules: 64 calls across thirteen roots, live capability drop/regain/removal controlling later list updates, five persisted capability sets and abort reference balance. The `capget` profile interleaves 21 application queries: 85 calls across fourteen roots, live serialized capability state, version/NULL/PID ordering, aliased output and partial-copy faults across resumes. The `prctl` profile adds original capability process-control helpers: 92 calls across fifteen routes, bounding drops, ambient raise/lower/clear, securebit locks and keepcaps, with state preserved for later capability/list calls and checkpoint resumes. Its route is restricted to the reviewed commoncap options. The `fsuid` profile adds original `setfsuid` and commoncap filesystem fixups: 84 calls across sixteen routes, silent denial, selective effective-capability drop/regain including bit 32, ambient preservation and locked securebit suppression. Its C witness is generated from the reviewed recipe and argument kinds. The `setresuid` profile adds original real/effective/saved UID transitions: 82 calls across seventeen routes, capability fixups, keepcaps/securebit effects, FSUID repair and persisted typed user/accounting links with balanced ownership. The `uid-setters` profile completes the four scalar UID routes with original `setuid` and `setreuid`: 93 calls across nineteen routes, privileged/unprivileged saved-ID rules and persisted inactive partial edits whose accounting links still identify the old user. The `credential-setters` profile combines all eight scalar UID/GID setters with capabilities and supplementary groups: 98 calls across twenty-three routes, live effective SETGID admission, UID-driven capability changes and preserved scalar/list/accounting state across copies and aborts. The separate `fd-dup` profile adds original `dup`, `dup3` and `close`: 73 calls across thirteen routes, typed shared file references, persistent descriptor bitmaps, close-on-exec flags, fixed-slot replacement, table-full errors and last-reference release across resumes. The `file-io` profile adds original read/write/seek syscall helpers and bounded memory-file callbacks: 118 calls across sixteen routes, persistent contents and size, alias-shared offsets, sparse zero gaps and native partial-copy faults across resumes. The `file-positioned` profile adds original positioned-transfer and truncate helpers: 171 calls across nineteen routes, preserved shared offsets, discarded-tail clearing, zero-filled re-extension and restored typed file/dentry/inode links. The `fd-control` profile adds five reviewed `fcntl` commands with three original descriptor helpers: 233 calls across twenty routes, descriptor-local close-on-exec flags, minimum-fd allocation, shared aliases and reference balance across resumes. Its entry/dispatch boundary is modeled explicitly. The `close-range` profile adds original range-close wrappers/helpers: 267 calls across twenty-one routes, inclusive alias closure, last-reference release, close-on-exec marks on closed bitmap slots and restored 64-bit descriptor state. The `fstat` profile adds original stat wrappers/serialization with reviewed filesystem callbacks: 286 calls across twenty-two routes, a guarded 128-byte output object, persisted inode metadata and page-allocation counts, and an application metadata digest across resumes. Its workload explicitly discards timestamps. The `fchmod` profile adds original wrappers/helpers for ordinary permission bits: 303 calls across twenty-three routes, owner success and non-owner denial, alias-shared inode modes, continued access through existing open descriptors and restored typed mount links. The `fchown` profile adds original ownership wrappers/helpers: 328 calls across twenty-four routes, captured authorization inputs, permitted group changes, denied UID/foreign-group changes, sentinels and ownership shared through aliases and resumes. The `fchown-capable` profile verifies ownership transfer and nonowner reclamation with effective `CAP_CHOWN` only: 330 calls across the same twenty-four routes, denied nonowner chmod, alias-shared UID/GID updates and a persisted capability field through joint resumes. The `file-capabilities` profile combines original `capset` with file operations: 369 calls across twenty-five routes, live CHOWN/FOWNER admission, effective-bit drop/regain, permanent permitted removal and both credential copies preserved with the inode state across resumes. The `file-fsgid` profile adds original filesystem-group changes to that session: 401 calls across twenty-six routes, distinct FSGID/EGID permission checks, silent denial, alias-shared inode groups and both filesystem-GID copies preserved with capability publications across resumes. The `file-fsuid` profile adds original filesystem-user transitions and commoncap fixups: 452 calls across twenty-seven routes, ownership checks against FSUID with unchanged EUID, filesystem capability gain/drop at UID zero, and FSUID/FSGID/capability state preserved together across publications and resumes. The `file-groups` profile adds original supplementary-list updates and queries: 509 calls across twenty-nine routes, live membership controlling inode group changes, capability-gated list replacement, sorted duplicates, empty lists, copy faults and typed list lifetimes retained across joint resumes. The `file-group-setters` profile combines all four scalar GID routes with that session: 568 calls across thirty-two routes, saved-ID rules, partial inactive edits, FSGID repair and mutable group credentials retained through file checks and joint resumes. The `file-status` profile adds reviewed shared F_SETFL/append behavior: 630 calls across thirty-two routes, alias-shared flags, ordinary and positioned append, partial writes and FSUID/FOWNER-sensitive NOATIME admission across resumes. The `file-capget` profile adds original application capability queries to that session: 696 calls across thirty-three routes, live credentials after capset/FSUID changes, ABI-version negotiation, aliased output and guarded partial faults without credential publication. The `file-prctl` profile combines the original commoncap control hook with that session: 767 calls across thirty-four routes, bounding/ambient changes, securebit locks and FSUID fixup suppression carried through later file operations and resumes. The general prctl wrapper is outside its reviewed contract. The `file-credentials` profile adds original scalar UID/accounting paths and combines all thirty-seven reviewed routes: 821 calls with live ID/capability/file effects, balanced user/accounting links, partial inactive aborts and joint resumes. The `file-rlimit` profile adds original `getrlimit` queries: 851 calls across thirty-eight routes, explicit retained NPROC/NOFILE pairs, 64-bit and partial-copy output, error precedence and joint resumes. Its `do_prlimit` dependency is a query-only reviewed model; resource-limit setters remain excluded. The `file-limits` profile extends queries to all sixteen entry-state resource pairs: 924 calls across the same thirty-eight routes, with all 32 limit fields retained through joint resumes. The `file-setrlimit` profile adds original `setrlimit` and `do_prlimit`: 973 calls across thirty-nine routes, live soft/hard updates controlling descriptor admission, denied hard-limit raises and changed signal-owned state preserved through joint resumes. Updates are bounded to STACK, CORE, NOFILE and MEMLOCK; CPU timers remain excluded. One command automates capture, pinned bundle preparation, export and QEMU verification (20, 28 or 32 ELF/raw × EL1/EL3 executions). All profiles use explicit bounded kernel dependency models and self-contained replay images.

The [bounded object-graph codec](docs/context-object-graphs.md) preserves changing typed references inside kernel contexts, including aliases, cycles and pool slot reuse. Struct-array policies and field-local IDs support relocated restore; a synthetic AArch64 fixture verifies successive snapshots in all four QEMU modes.

[Owned buffer references](docs/context-buffer-references.md) extend that codec to typed cursors, aliases and reviewed one-past pointers within persistent arrays. Buffer IDs and byte offsets survive fresh checkpoint images; invalid offsets reject atomically before port callbacks.

[Initialized context state](docs/initialized-context-state.md) automatically reconstructs mutable C scalar, structure, pointer and array seeds, including source-private constants, complete macro invocations, designated elements and links to owned objects. Separate contexts receive independent seeds; checkpoint restore overlays the saved cumulative state.

[Mixed declarations](docs/initialized-context-state.md#mixed-readonly-and-mutable-declarations) retain readonly constants and arrays when mutable pointers from the same statement move into context. A dedicated QEMU checkpoint regression rebuilds canonical pointers to readonly data in each relocated image.

[Function-local static state](docs/local-static-context-state.md) now follows the same ownership and checkpoint path. Declaration identities distinguish shadowed variables; local counters, arrays and aliases retain their updates between returning syscall slices. Readonly local objects referenced by restoration seeds are lifted into private source storage, preserving object identity in both constructors and kernel bodies.

[Private state across source files](docs/private-context-state.md) supports static objects with the same C name. Their context fields and checkpoint values remain distinct, while public `extern` declarations bind to public storage.

[Private functions across source files](docs/private-context-functions.md) now receive separate identities too. Direct calls, forward declarations, source-local macros and context requirements resolve to each file's own helper, including its local static state.

The [supplied-ELF chain workflow](docs/elf-checkpoint-chains.md) imports user-space checkpoint ELFs directly and automates continuation from retained joint checkpoints, using the same verified chain engine as the C frontend.

Resumed application checkpoints now retain completed syscall PC history, allowing separate SVC locations used only before the pause. The C frontend supports named syscall wrappers and automatically resolves the supplied call-site sequence after linking. The multiple-site example and QEMU workflow are described in [standalone application checkpoints](docs/standalone-application-checkpoints.md).

The [checkpoint-chain workflow](docs/checkpoint-chains.md) automates successive application/kernel snapshots across fresh QEMU images. A C application can advance through several absolute syscall ordinals, preserve cumulative kernel state and CPU/RAM, then complete the final suffix. Each stage is verified in all four QEMU load/start modes and linked to its parent checkpoint by identity.

[Live SVC boundaries](docs/svc-boundary-replay.md) connect the full-machine Linux checkpoint to reduced slices. A configurable contract describes the AArch64 `svc #0` registers, vectors and kernel anchor. A reviewed binding maps live kernel objects onto the `file-io` checkpoint schema using the kernel's embedded BTF. The Clang entry-state footprint of each observed root must be covered by that binding. Three real boundaries (`read`, `write`, `close`) are compared on result, user bytes and 95 kernel fields. The comparison found the reviewed transfer model's 47-bit user-address bound (Linux arm64 uses `1 << VA_BITS`); after correcting and rebuilding `file-io`, all three are equivalent. Their footprints are now fully discovered, with no blockers (previously 42, 42 and 12): [path facts, field ranges and descriptor tables](docs/entry-state-analysis.md#path-facts-field-ranges-and-descriptor-tables) cover the descriptor lookup, Spectre masking, null guards and by-value `struct fd`. One declared field range (`max_fds ≤ 64`) is checked on each replayed state. `--all` captures every SVC from resume to power-off. A binding drafter proposes kernel paths from the schema and BTF; it recovers 22 of 23 reviewed `file-io` paths. Multi-call chained replay, user continuation and standalone execution are not yet part of this path.

[Kernel binary replay](docs/kernel-binary-replay.md) replays a captured system call by executing the kernel's own machine code. The image holds every page the live call touched at its physical address, including the kernel's translation tables. A stub at EL2 restores the EL1 state and returns to the user trap instruction, so the CPU takes the SVC and runs the kernel from its vector to the return. All 38 captured Linux 6.10 calls, 253–2,563 kernel instructions each, replay as equivalent: the same instructions, memory accesses, registers and pages as live. 100% of the executed kernel code is authentic. Against the same live traces, the source slices cover 95.3% of the instructions with original code (`tools/kernel_authenticity.py`), up from 7%: the `fd-control` slice runs Linux's own `fcntl` entry and descriptor lookups, and its read, write and truncate paths down through shmem, the page cache and the inode timestamps, with the arm64 `memset.S` on an identity-mapped MMU, every call enters and leaves through Linux's own `entry.S` and system call handlers, and the identifier mapping, user-copy iterators and LSM hook walks are original too.

[KLEE state discovery](docs/klee-state-discovery.md) runs a slice root under KLEE on a captured boundary. The object graph stays concrete; bound scalars, file bytes and user bytes are symbolic. The tool reads per-path dependencies from KLEE's KQuery output. KLEE's STP solver, through `kleaver`, resolves symbolic-index reads, proves outputs unchanged, and decides whether each path leaves the reviewed model domain. Each path's KTest serves as a model, which cuts most solver queries. On the ramfs `read`, `write` and `close` captures, exploration completes with no imprecise reads. The required inputs are 6, 6 and 4 of 30–31 symbolic inputs, and all of them are in the static footprint. Declared Linux input domains (`f_pos ≥ 0`, bounded `f_count`) and the binding's file classes are checked against the live state. With them, every remaining model fault is attributed to a reviewed-model limit: a non-regular file class, or the 64-byte write capacity. Fields the observed graph fixes and binding transients remain static-only. `tools/klee_state_validation.py` replays variants in one QEMU image of the reduced slice. In all three cases, randomizing every unused input leaves outputs at the observed values. Each in-domain KTest reproduces KLEE's outputs on AArch64, and each required input alone changes the outcome. A symbolic argument split into one path per value widens a result from the captured call to every fd in 0–70 or every count in 0–16. Close then needs 6 inputs. Read and write need 10 for a symbolic fd and 7 for a symbolic count. Read with a symbolic count is complete for counts 0–10 only. Every widened set is in the static footprint and replays consistently. Paths KLEE stopped at its time limit count only as prefixes, and such a run reports its required set as a lower bound. A second checkpoint workload adds `umask`, `getpid`, `getuid`, `getresuid`, `dup`, `dup3` and further `lseek`/`close` captures; all 15 boundaries are discovered and replay consistently. Linux descriptor-table invariants (open bitmap equals the installed slots, `next_fd` at most the first free slot), checked against every captured state, keep `dup` from exploding. Where the static footprint is blocked (the fd allocator), discovery observes every field and finds `close_on_exec` beyond the static reads. A third workload adds the remaining identity queries (`getppid`, `geteuid`, `getgid`, `getegid`, `gettid`, `getresgid`), a second `umask`, `-EBADF`/`-EINVAL` paths of `dup`, `dup3`, `close` and `lseek`, and zero-length `read`/`write`: 16 more boundaries, all discovered and consistent; the error paths need no state. Sibling paths that split on one condition and compute the same outputs are merged, so a condition that only chooses between equal results requires nothing (`control_without_effect`); this removes `file_data.size` and `f_pos` from zero-length `read`. `tools/klee_state_batch.py` reruns discovery and validation for every boundary in a manifest and compares each result with the recorded one. The Linux manifest (`integrations/linux_aarch64/file-io/klee-state-batch.json`) lists 35 boundaries in a `quick` and a `long` tier. `-DOSREC_BUILD_KLEE_STATE_BATCH=ON` adds the selected tiers as ctest tests. A fourth workload changes state on the `fd-control` slice: `fcntl` (`F_GETFD`, `F_SETFD`, `F_GETFL`, `F_DUPFD`, `F_DUPFD_CLOEXEC`), `pread64`, `pwrite64` and `ftruncate`. Its binding adds each file's dentry and inode as related objects. It also checks, as a precondition, that `RLIMIT_NOFILE` equals the reviewed model's constant 8; the workload runs at that limit. The `file-io` binding checks it too, and its 35 boundaries were recaptured from checkpoints whose workloads lower the limit before the checkpoint. All 11 positioned-I/O and truncate boundaries replay statically as equivalent. All 21 boundaries are discovered and validate as consistent.

[Source-image flow](docs/source-image-flow.md) extends per-call replay to a captured user program continuing against the kernel's post-boot state. The EL0 mini-OS image runs the kernel's own instructions at EL0, uses linked veneers or the shared architecture emulator for privileged operations, and records named stops. The random fault workload matches all 2,272 native events; optional per-call user-memory hashing also matches all 76,053 sampled pages. The 48-bit lowered layout also passes the random and signal workloads. `runtime/linuxkernel_el0` builds the callable `liblinuxkernel-el0` front end as static/shared libraries, with direct veneer and SVC-context entry; the native arm64 Linux backend now resumes actual user-checkpoint instructions through branch-to-BRK syscall gateways and captured kernel code. Both static/shared variants match all 2,272 random-workload events and all 2,339 signal-workload events, including `rt_sigreturn`, using recorded counter/MMIO inputs. Standalone native checkpoint ELFs embed sparse state, hardware transcripts and full event checks. They use their own startup and direct Linux syscalls, with no libc, CRT, compiler runtime or TLS; both workloads pass with only the executable mounted in a read-only container. Each complete executable is about 55.8 MiB. Dynamic application loading and retained-SVC interception remain open. The flow document contains build and reproduction commands, relocation review and the remaining work.

[Kernel type sources](docs/kernel-type-sources.md) add a DWARF reader beside BTF behind one interface, with 32-bit pointer support, so bindings and typed paths work on kernels built with debug information. A layout correspondence check compiles each binary unit's records under that unit's own compile command and compares sizes and offsets with DWARF. On LiteOS-A, all 214 C units match (28,065 checks); a packed-struct negative control is detected. This checks data layout only, not code.
