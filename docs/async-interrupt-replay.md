# AArch64 task completion with hardware interrupts

The single-CPU task-completion image advances the host continuation demo to actual exception delivery. QEMU's physical timer raises PPI 30 through GICv2. Inside that handler, higher-priority SGI 1 preempts it, applies the nested completion input and returns with `eret`. The timer handler then applies its own input, wakes the selected task and returns. A bounded continuation scheduler switches back to the selected task, which consumes the completion credits and returns.

The replay embeds the original `examples/task_region.h` computation, entry state, device-input values and complete expected capture. Handlers recompute their effects. Target-side `runtime/context.c` and `runtime/recorder.c` record the actual boundaries, including IRQ parentage, interrupted task identity, wait-object generation, switches and return. A byte comparison checks the entire 1,176-byte capture only after completion. Two exception entries and a maximum nesting depth of two are checked independently in the result record. No expected memory effect is assigned to completion state.

## Build and run

Build the host recorder, generate the single-CPU capture, then export:

```sh
cmake --build build/live-syscall-checks --target record_task_demo
build/live-syscall-checks/record_task_demo \
  build/async-task-single.osrec 0 7 5 2 --single-cpu
python3 tools/export_async_task.py \
  --capture build/async-task-single.osrec --out build/async-task-image
```

The output contains `async-task.elf`, `async-task.bin`, the packaged sources, the capture, a 128-byte RAM result and `manifest.json`. Export independently executes ELF and raw payloads and requires identical terminal results before publication. The external QEMU observer also dumps the actual context records from RAM after each run as `target-context-0.osrec` and `target-context-1.osrec`; both must equal the capture independently of the target's success flag. The image runs after its capture and construction sources are removed. The manifest binds source/capture/image hashes, compiler/QEMU versions and observed IRQ/trace results. `--entry-address` and `--result-address` select the linked layout using the existing ELF memory contract.

The existing two-CPU host demo is unchanged by default. Pass `--single-cpu` to obtain the admitted hardware replay recipe; migrated captures reject before compilation.

## Hardware and scheduling contract

The execution target is QEMU `virt-9.2`, Cortex-A53, one CPU, nonsecure EL1h, MMU/caches off, GICv2 distributor at `0x08000000` and CPU interface at `0x08010000`. Entry masks interrupts and initializes VBAR and a 16 KiB stack. Timer PPI 30 has priority `0x80`; SGI 1 has priority `0x20`. Both use the current-EL SP_EL1 IRQ vector. The assembly wrapper preserves all general-purpose registers, ELR_EL1 and SPSR_EL1 at both nesting levels. ELF and raw loading are validated at EL1; EL3 startup is outside this image's contract.

The recorder remains externally serialized. Foreground calls execute with IRQs masked. The outer handler commits its enter/input events before requesting the SGI and unmasking IRQs; the nested handler completes all its records before the outer handler proceeds. This makes the specific bounded nesting recipe safe without changing the general recorder into an IRQ/SMP-safe writer. Other vectors fail, unrecognized interrupts reject, and timer/preemption waits have bounded counter deadlines.

Task identities describe explicit block/switch/wake/return continuation boundaries on one CPU. The background continuation waits for hardware delivery while the selected task is blocked. There are no saved task stacks, kernel scheduler execution, migration, concurrency between CPUs, or live LiteOS-A capture in this milestone. The timer's approximately 1 ms delay triggers an interrupt; captured cycle timing and instruction-position equivalence are not claimed. GIC/timer state is initialized for each execution rather than checkpointed. RTL execution still requires a matching interrupt-controller/timer platform and separate validation.

## Result ABI 27

The existing 128-byte little-endian RAM result uses magic `0x4f535243`, version 27, status 2 for success or 3 for rejection, and an error word. Words 4–14 contain the event count, IRQ count, maximum IRQ depth, nested-completion count, wakeup count, trace byte count, remaining credits (low/high), return value (low/high), and full-trace verification flag. Success requires 13 events, two IRQs, depth two, one nested completion, one wakeup, 1,176 trace bytes and verified capture equality. Publishing terminal status follows a memory barrier.

## Validation

```sh
ctest --test-dir build/live-syscall-checks -j1 --output-on-failure \
  -R '^(async_task|task_capsule|contexts|freestanding_task|freestanding_aarch64)$'
```

The four asynchronous regression cases cover ordinary completion, nonzero entry state, 64-bit saturation, relocated images, execution after deleting capture/sources, ELF/raw equality, unsupported migration, source/parent/wait-generation corruption, a forged intermediate effect, suppressed nested preemption and a missing nested-handler effect. Runtime failures prevent image publication. This is functional QEMU validation; no RTL or cycle measurements have been performed.

The October 19, 2026 validated image is `build/async-task-final-v2`. All four new cases passed against the final implementation. The affected asynchronous, general AArch64 image, task-object image and host task-capsule suites passed together (126.30 seconds); the context protocol C suite also passed. The validation summary and bound evidence hashes are in `build/async-task-validation-20261019.json`. The final image's two independently dumped transcripts equal `build/async-task-single.osrec`, with two actual exception entries, depth two and thirteen matched events.

The [live LiteOS-A blocking-wait milestone](live-wait-replay.md) now captures actual switch/wake/IRQ boundaries and the relevant typed entry state, with a standalone host replay of original wait/timeout code. Porting this hardware path to that captured kernel scenario is the next step and requires its own exception and scheduler contract.
