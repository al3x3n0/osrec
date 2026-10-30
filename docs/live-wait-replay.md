# Live LiteOS-A blocking-wait capture and replay

The `--async-wait` workload executes a real `SysNanoSleep` through the existing user/SVC path in the pinned Cortex-A7 LiteOS-A kernel. PID 1 requests a 20 ms relative sleep with a NULL remaining-time pointer. The original delay scheduler switches to the idle task; timer IRQ 29 expires the wait and enqueues the selected task; the scheduler switches back and the syscall returns zero. The user independently records the return and user CPU mode.

This extends [hardware interrupt replay](async-interrupt-replay.md) with a live kernel reference. The earlier AArch64 image validates actual nested exception delivery against a portable completion model. This workload observes a real kernel scheduler and one timer interrupt, then exports a standalone host replay of original syscall/time/delay/timeout code against explicit scheduling boundaries. Live nested IRQ capture and full kernel scheduler replay are separate future steps.

## Run the workload

```sh
python3 tools/liteos_qemu_demo.py --async-wait \
  --out build/live-wait-new
build/live-wait-new/wait-replay

ctest --test-dir build/live-syscall-checks -j1 --output-on-failure \
  -R '^(live_wait_replay|live_liteos_qemu)$'
```

Use a fresh output directory. The optional workload excludes the other specialized capture flags. Existing default workloads retain their behavior. The accepted kernel revision is `4ac7f3aed67000b47bc14d6fe79d63ada708d780`.

The output includes the captured kernel ELF/raw image, complete boot log, `wait-state.bin`, `wait-events.bin`, `wait-user.bin`, `wait-capture.json`, generated `wait-replay.c` and executable `wait-replay`. The executable embeds its checkpoint and observed inputs and needs no capture file, source checkout or running kernel. It is a host validation harness using libc; it is not a freestanding hardware image.

## Capture boundaries

The admitted recipe has exactly ten events:

| Event | Observation |
| --- | --- |
| Syscall entry | Selected task identity, running state and typed request |
| Delay callback | Relative wait cycles before the original `HPFDelay` |
| Switch away | Previous/new task IDs and selected task's running + delay flags |
| Deadline callback | Original `HPFWaitTimeGet` result and its start-time input |
| IRQ enter | Actual timer IRQ 29, interrupted task and depth one |
| Enqueue | Original scheduler callback's ready state and observed wake clock |
| IRQ exit | Matching interrupt identity/depth |
| Switch back | Selected task after ready-queue removal, before setting running |
| Delay return | Selected task running again, original callback result zero |
| Syscall return | Original `SysNanoSleep` result zero |

The capture checks RR policy and a single CPU. It uses existing task-switch/ISR hooks plus a temporary copy of the selected task's scheduler callback table. Delay, deadline and enqueue wrappers always call their original callbacks. The original table is restored before returning to user code. No callback pointer or native address enters the portable state. Each event append masks interrupts; fixed-buffer exhaustion is sticky and prevents publication. Hooks allocate no memory and print nothing. Data is exported afterward through the report driver.

The admitted switch-away target is idle task ID zero, with its idle status flag. The selected task must be a nonzero user-task identity with the expected running flag. Other switch targets and task classes reject.

Enabling the pinned hook implementation requires a missing LiteIPC header include path and a local Clang diagnostic adaptation for its existing `&*void_pointer` argument macros. Both adaptations are hash-checked in `integrations/liteos_qemu/build-files.json`; they change no scheduler or timeout computation.

## Typed state and observed clocks

`wait-capture.json` names the checkpoint fields and contains the original wire words. The selected task snapshot contains its lifetime-local ID, status, RR policy, prior `waitTime` and `startTime`. The request has zero seconds, 20,000,000 nanoseconds and the native 16-byte AArch32 timespec layout. Tick and clock frequencies are 1,000 Hz and 50 MHz. Twenty ticks therefore become 1,000,000 wait cycles.

Scheduler clocks are explicit recorded inputs: the start time used to form the absolute deadline, the clock observed at enqueue and the selected task's start time after resumption. The decoder requires a consistent deadline, wake at or after expiry, and resumption at or after wake. Replay computes the deadline through the original helper and checks the actual captured states. It does not measure or reproduce the captured elapsed time.

The version-1 state record contains 32 little-endian 32-bit words. Positions 0–10 hold version, selected TID/PID, entry status, running/ready/delay masks, request seconds/nanoseconds/size and tick Hz. Positions 11–14 hold entry wait/start times as low/high pairs. Positions 15–19 hold exit status, raw result, event count, capture failure and final IRQ depth. Positions 20–27 hold exit wait/start times, deadline-base start and deadline, each low/high. Positions 28–31 hold clock Hz, enqueue clock low/high and scheduling policy. Each 40-byte event contains sequence, kind, current TID, subject TID, subject status, IRQ depth, two argument words, CPSR and selected-task status. Kind 9 is the deadline event; kinds 1–8 follow the table's other boundaries. These records are specific to this bounded recipe, not a general task checkpoint format.

## Original computation and explicit models

The exporter pins and preserves eight definitions: `SysNanoSleep`, `nanosleep`, `DoNanoSleep`, `ValidTimeSpec`, `OsNS2Tick`, `HPFDelay`, `HPFWaitTimeGet` and `SchedTimeoutTaskWake`. Source/header and per-definition hashes are in `integrations/liteos_a/wait-source-lock.json`; export checks both the reference checkout and live build tree. Generated code preserves the original licenses and fixed scalar widths.

The host model provides successful user copies, a 20-tick `LOS_TaskDelay` boundary, single-task timeout-queue admission, sequential locks, a ready-queue enqueue adapter and the observed scheduler switch choices. The original delay body sets the delay state. The original deadline body adds its start-time input. The original timeout body clears blocked state and invokes enqueue. Every selected-task status is compared at its matching boundary; expected statuses are not assigned to the task. Scheduler clock inputs are restored only at the reviewed clock boundaries.

Full runqueue priority selection, background task objects, saved native stacks, signal interruption, other requests, SMP, live nested interrupts, concurrent callback-table changes and checkpointing the live GIC/timer are excluded. The capture rejects additional or missing boundaries rather than accepting an unexplained history. This is functional validation, with no RTL or timing equivalence claim.

The next step is to run these original wait/timeout slices against hardware-delivered interrupts in a freestanding replay image, using this live checkpoint and event contract.

## Validation evidence

The accepted October 19, 2026 capture is `build/live-wait-final-v4`. All ten kernel boundaries and the independent user return pass validation. Its generated replay preserves all eight pinned definitions and verifies the selected task's state and the recomputed absolute deadline. The native regression fixture is `tests/fixtures/live-liteos-wait/`, with raw observations, the complete boot log and hashed provenance.

Five new cases cover standalone replay, malformed task/IRQ/status/clock/result observations, source/header tampering, incompatible capture flags and four faulty computation models. The altered delay, deadline, timeout-wakeup and enqueue computations all reject during replay. The existing live-kernel suite also passes both cases, including two real reboots with changed and empty RAMFS inputs and their independent native/freestanding replays. Both CTest suites passed in 226.68 seconds; the final five-case suite also passed after the last admission/provenance checks. The source/image/raw-observation/configuration audit and evidence hashes are recorded in `build/live-wait-validation-20261019.json`.
