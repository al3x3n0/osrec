# Linux timer IRQ capture and freestanding callback replay

This workflow boots real AArch64 Linux, records one blocking `nanosleep` and its scheduler/timer/IRQ boundaries, then exports a standalone AArch64 image. The image receives real emulated GIC timer interrupts and uses nine original Linux timer functions plus eight scheduler helpers. The `hrtimer_wakeup` callback runs inside its exception handler; original sleeper construction and start wrappers run in the foreground. Optional `--task-state` capture records selected native task fields at four scheduler boundaries; `--sleeper-state` also records the sleeper link at four entry/return boundaries. `--timer-state` additionally observes timer state and the clock base's running pointer at callback entry. `--timer-return` additionally checks that the same base's running pointer is null by sleep return. `--base-state` additionally observes the clock-base index, CPU-base identity and active bit at callback entry and sleep return. `--outer-state` also directly observes the CPU base's softirq deadline and activation flag at callback entry. Replay verifies these observations. Scheduler choices, scheduling-class queue operations, accounting, other timer-tick work and syscall boundaries use explicit sequential models.

The selected reference timer functions are from [Linux v6.10 `kernel/time/hrtimer.c`](https://github.com/torvalds/linux/blob/v6.10/kernel/time/hrtimer.c#L1789). It clears the sleeper's task link, wakes that task and returns `HRTIMER_NORESTART`. The wakeup path also uses selected definitions of `__task_state_match`, `ttwu_state_match`, `ttwu_do_wakeup` and `wake_up_process` from [Linux v6.10 `kernel/sched/core.c`](https://github.com/torvalds/linux/blob/v6.10/kernel/sched/core.c#L2115). Four further wrappers—`enqueue_task`, `dequeue_task`, `activate_task` and `deactivate_task`—now run around the selected-task queue model. Their declarations and executable statements are unchanged; internal block comments are omitted from the excerpts. The native kernel used here is `6.10.14-linuxkit`; the workflow records its image/configuration hashes and does not attest that this image was built from the selected v6.10 source checkout.

## Run

Supply an uncompressed ARM64 Linux Image with the required builtin tracing support:

```sh
python3 tools/capture_linux_irq.py \
  --kernel-image /path/to/arm64/Image --out build/linux-irq-native
python3 tools/export_linux_irq.py \
  --capture build/linux-irq-native --out build/linux-irq-image

python3 tools/run_freestanding_armv7.py build/linux-irq-image/linux-irq.elf
```

Add `--task-state` to the capture command to enable native task-field probes; export detects the extra observations automatically. `--timer-state` implies sleeper/task capture and adds one BTF field probe; `--timer-return` also adds a sleep-return probe with BTF-resolved offsets. This additionally requires builtin `KPROBES`, `KPROBE_EVENTS`, `PROBE_EVENTS_BTF_ARGS`, `DEBUG_INFO_BTF` and `BPF_SYSCALL`.

Capture uses a generated libc-free PID 1 and readonly ext2 root, without a host mount, container daemon or guest shell. PID 1 mounts tracefs, configures twelve tracepoints, clears the buffer, enables tracing, requests a 20 ms relative sleep and disables tracing after the return. The initial timer slack must be 50 µs. It then exports the trace, per-CPU loss statistics, event formats and independent user-side result/clock observations before powering the guest off.

The native prerequisite check includes `TRACING`, `FTRACE`, `FTRACE_SYSCALLS`, `EVENT_TRACING`, `DEBUG_FS`, `ARM_ARCH_TIMER` and `KALLSYMS`, in addition to the existing ARM64/root-disk prerequisites. The initial recipe requires non-RT, low-resolution timer delivery (`HIGH_RES_TIMERS` disabled), matching the installed kernel. QEMU uses one Cortex-A53 CPU and `virt-9.2,gic-version=2`. Other kernels/configurations are admitted only when they satisfy these checks and the recorded event contract.

## Observed dependency chain

The decoder identifies the selected timer from its initialization/arming in PID 1 and correlates its opaque ftrace token through cancellation and expiry. It requires `hrtimer_wakeup`, the same timer token, monotonic deadlines, and the complete chain:

```text
nanosleep entry → timer init/start → selected task blocks
arch_timer IRQ enter → selected timer removed/expired
  → task waking → task wakeup → callback exit
IRQ exit → selected task resumes → nanosleep returns zero
```

All trace lines are parsed. CPU/current-task continuity, switch ownership, IRQ enter/exit balance, hardirq context flags and callback boundaries are checked. The callback must expire at or after the recorded hard deadline, within the arch timer IRQ, while the selected task is blocked. Waking/wakeup must identify PID 1 on CPU zero. The deadline/slack values must agree with the admitted request and user clock interval. The buffer's written/retained counts and per-CPU entry count must equal the parsed event count; overrun, commit overrun and dropped-event counters must all be zero.

Additional arch timer IRQs and background task switches within the syscall are retained. Wake events for nonselected tasks remain outside the admitted recipe and reject export. Extra device handlers, multiple timers, live nested interrupts, signal interruption, different syscall results and incomplete histories reject. IRQs before syscall entry are validated as part of the full buffer but lie outside the exported syscall interval. The current recipe requires the return to be the last event in the buffer.

## Replay state and interrupt delivery

The portable transcript replaces the native opaque timer token with wire ID 1 and embeds numeric task IDs and observed clock inputs. Native user pointers and timer tokens do not become replay pointers. The original sleeper constructor creates the typed sleeper → selected-task link and installs its callback pointer. The image reconstructs a projected timer object and Linux task-state bits (`__state`, `saved_state`) with separate `on_rq` and `on_cpu` membership. `TASK_RUNNING` means runnable; CPU membership distinguishes execution from waiting for a scheduler switch. Without sleeper-state capture, the sleeper/timer association is inferred from the admitted construction and trace correlation. Sleeper-state capture directly correlates the sleeper address, callback timer address and selected task link. Trace-only mode also infers task fields. Task-state mode directly observes the selected fields at four entry probes; neither mode snapshots complete native objects or adopts their full struct layouts.

The image consumes the entire syscall interval. For each captured arch timer IRQ it arms the target physical timer and waits for a real exception. The original callback executes only in the expiry IRQ. The original `wake_up_process` wrapper supplies `TASK_NORMAL` to a bounded `try_to_wake_up` model. The original state-match helpers decide whether that mask admits the projected task state. For the captured wake, the model checks that the task is sleeping, off the runqueue and off CPU, and that the callback has cleared the sleeper link. It emits `sched_waking`, calls original activation/enqueue wrappers through a modeled scheduling-class callback, and calls the original `ttwu_do_wakeup`, which sets `TASK_RUNNING` before emitting `sched_wakeup`. The trace hook verifies that state and queue membership. The continuation resumes only after IRQ return and a matching recorded scheduler switch. The recorded blocking switch likewise calls the original deactivation/dequeue wrappers before the CPU-membership model clears `on_cpu`. Other tick-handler effects, Linux locks, preemption, scheduling-class algorithms and CPU selection are modeled. No full `try_to_wake_up` implementation is claimed. The replay builds with the selected helpers' debug-preemption check disabled; it supports no concurrent CPUs or writers.

Before interrupt replay, six additional target probes check running, interruptible, uninterruptible, frozen, excluded-mask and saved-state matching. After the real callback, a second call to the original wakeup wrapper must return zero without adding events or activating the already runnable task again. These probes are synthetic contract checks, not additional native observations; the captured wakeup count and RAM event ledger still contain exactly one wakeup. Exercising the saved-state helper does not add PREEMPT_RT or freezer capture support.

Linux IRQ 11 in the accepted capture is a Linux virtual IRQ number. The standalone backend maps the recorded arch timer events to physical timer PPI 30 on QEMU GICv2. It checks the actual interrupt acknowledgement and preserves general-purpose registers, ELR_EL1 and SPSR_EL1 through the exception wrapper. The supported start is nonsecure EL1h with one CPU, MMU/caches off and a 16 KiB stack. ELF and raw payloads execute independently with semihosting and guest host services disabled. `--entry-address` and `--result-address` select relocated layouts.

Recorded timestamps/deadlines are functional inputs. Target IRQ triggering uses a short bounded timer interval; it does not reproduce the native 20 ms elapsed time, instruction positions or cycle timing. Live GIC/runqueue memory checkpointing, full Linux IRQ/tick handlers, nested IRQs, SMP and RTL validation remain outside this contract.

## Artifacts and result ABI

Native output includes the init ELF, root disk, kernel configuration, complete QEMU log, `trace.txt`, `trace-stats.txt`, `event-formats.json`, `result.json` and a manifest binding their hashes. The exporter checks the artifact set, hashes and equality of parsed observations with the native log before generating an image.

Image output includes `linux-irq.elf`, `linux-irq.bin`, sources, the semantic contract, expected normalized events, both actual RAM event ledgers, expected and actual queue witnesses, terminal RAM result and `manifest.json`. The callback excerpt/function hashes are pinned in `integrations/linux_aarch64/irq-wait/source-identity.json`; scheduler excerpts are pinned in `scheduler-source-identity.json`, with source locations and GPL attribution retained. Both identities and all copied source hashes appear in the image manifest. Export checks source identity, ELF dependencies and absence of external service instructions.

Each normalized event is 32 little-endian bytes: 32-bit kind/current PID, then three 64-bit arguments. Kinds 1–12 are syscall entry, timer init, timer start, scheduler switch, IRQ entry, timer removal, callback entry, task waking, task wakeup, callback exit, IRQ exit and syscall return. Optional kind 13 records a native task-field boundary: argument A is stage 1–4, B is the raw task state, and C packs `on_rq` in the low 32 bits and `on_cpu` in the high 32 bits. `saved_state` must be zero at every admitted boundary. Optional kind 14 records a sleeper boundary: A is stage 1–4, B is timer wire ID 1, and C is the linked task wire ID (1 or null/0). Optional kind 15 records callback-entry timer fields: A is stage 1, B is timer state (0), and C is the running timer wire ID (1). The base pointer is validated as a capture-side identity key and is never serialized as a replay address. Optional kind 16 records the post-sleep running-pointer observation: A is timer wire ID 1, B is base wire ID 1 and C is the running timer wire ID (null/0). Optional kind 17 records base state: A is stage 1 (callback entry) or 2 (sleep return), B is base index 0, and C is the selected base's active bit. Other native active-mask bits remain capture context and are not replayed. Optional kind 18 records the callback-entry softirq snapshot: A is CPU-base wire ID 1, B is its softirq deadline and C is its activation flag. The admitted values are `INT64_MAX` and 0. After each target run the external observer reads the actual ledger from RAM and requires byte equality with the normalized capture, independently of the target's terminal status.

A further 128-byte timer ledger records projected construction/start state at four boundaries. The exporter independently reads it after each image run, in addition to the event and queue ledgers. Its schema is described in the timer-wrapper milestone below. A fourth ledger holds five 32-byte timer-queue model witnesses for the enqueue/removal milestone. A fifth holds seven 32-byte callback-run boundary witnesses. A sixth holds four 32-byte ordered-container witnesses, including any synthetic remainder sentinel. A seventh holds four 32-byte queue-dispatch witnesses. An eighth holds seven 32-byte outer-runner boundary witnesses.

RAM result ABI 29 retains the 128-byte result record and ABI 28 field meanings in words 0–25. Words 26–31 add final `on_rq`, final `on_cpu`, activation count, wrapper attempts, rejected attempts and state-probe count. Success requires values `1, 1, 1, 2, 1, 6`, respectively. The observer still accepts previous ABI 28 images. It reports consumed/expected events, delivered/expected IRQs, callback/wake/resume counts, selected task state, cleared sleeper link, IRQ depth, timer deadlines/expiry input and final phase. Success requires full transcript consumption, one original callback, one wakeup and one resume, matching IRQ counts, a cleared task link and balanced exception context. The ELF/raw results must be identical before publication. The images continue to run after capture, source and manifest files are removed.

## Regression checks

```sh
ctest --test-dir build/live-syscall-checks -j1 --output-on-failure \
  -R '^(linux_irq|async_task|freestanding_aarch64)$'
```

The native regression fixture is `tests/fixtures/linux-aarch64-irq-native/`. Tests cover independently loaded ELF/raw images at two layouts, source/capture removal, timer/task/IRQ/context/clock corruption, trace loss, event-format mismatch, artifact/source tampering, and ninety runtime mutants affecting task-link clearing, task wakeup, callback return, physical timer delivery, task-state masking, saved-state matching/clearing, wrapper mask, runnable-state write activation membership, scheduling-class callbacks, accounting-hook order, activation write order, enqueue flags, dropped state bits, the waking transition omitted native observations, wrong sleeper identity and restoration of a cleared sleeper link, constructor omissions, callback/link installation, start modes, enqueue/removal state, active masks, inactive-removal behavior, running markers, callback invocation, lock/sequence ordering and direct timer observation emission/values. Terminal field corruption and either externally read scheduler-witness ledger being altered also reject.

The accepted October 19, 2026 run is `build/linux-irq-native-final-v1` with images in `build/linux-irq-image-final-v1`. Its complete syscall interval has twenty events and four timer IRQs; one callback wakes and resumes PID 1. Both externally dumped RAM ledgers match all twenty events. The independent native fixture exercises a different eighteen-event, three-IRQ history. All five affected CTest suites passed in 278.43 seconds: twenty-one unittest cases across Linux IRQ, nested task IRQ, general AArch64 images, Linux resource-limit checkpoints and Linux preflight. All four altered callback/delivery models fail during target execution before publication. Hashes of the native input, kernel/configuration, reviewed source, ELF/raw images, RAM ledgers, terminal result and test reports are bound in `build/linux-irq-validation-20261019.json`.

## Scheduler-helper milestone

The scheduler extension reuses the verified twenty-event native capture in `build/linux-irq-native-final-v1`. Its ABI 29 images are in `build/linux-irq-scheduler-final-v1`; the previous ABI 28 images remain historical artifacts. Both ELF/raw RAM ledgers match all twenty events with four physical timer IRQs, one captured wake and one resume. The target also reports one activation, one rejected repeat wake and six state probes. All three affected CTest suites passed in 94.51 seconds: eleven unittest cases, including five Linux IRQ cases and ten rejected runtime mutants. A separate execution of the historical ABI 28 image also passed with the updated observer. Validation and source/artifact hashes are recorded in `build/linux-irq-scheduler-validation-20261019.json`. This remains a trace-derived object reconstruction with modeled activation and scheduling; direct native kernel-state capture is the next separate milestone.

## Queue-wrapper milestone

The next extension adds four pinned original scheduler wrappers in `sched_queue.c`, bringing the scheduler excerpt count to eight functions. `sched_queue_model.c` supplies a queue containing only the selected task, a typed scheduling-class callback table and checked accounting boundaries. Its count is a selected-task projection, not the native CPU's total runnable-task count; background tasks stay in the recorded switch stream. Statistical, pressure, utilization and core-scheduling effects are not reproduced. Migration, unexpected clock updates and incompatible flags fail the bounded model. These choices do not attest the native kernel's configuration or hidden accounting state.

Original deactivation and activation calls replace the earlier direct writes to queue membership. Four additional 32-byte RAM records witness removal marking, class dequeue, class enqueue and final enqueue marking. Each record contains kind, flags, task state, queue membership, CPU membership, selected-task queue count, queued task ID and accounting-hook step. Their expected values come from the declared projection; they are not native memory snapshots. The exporter resolves `osrec_linux_irq_queue` from the ELF, checks its size and independently reads all four records after both ELF and raw execution. Any byte mismatch rejects publication, even when the terminal result and captured-event ledger pass. Terminal ABI 29 remains unchanged.

The extension reuses `build/linux-irq-native-final-v1`; images are in `build/linux-irq-queue-final-v1`. Both captured-event ledgers still match twenty events and four timer IRQs, and both queue-witness ledgers match the four declared boundaries. All six Linux IRQ regression cases passed in 25.03 seconds, including seventeen runtime mutants and corruption of either external queue-witness ledger. The tests also verify both ledgers after relocating the images and removing construction inputs. Validation is recorded in `build/linux-irq-queue-validation-20261019.json`. Native kernel-state capture, original scheduling-class algorithms and full scheduler selection remain future work.

## Direct native task-field milestone

`--task-state` installs four PID-filtered entry probes, using the kernel's BTF argument/field resolution instead of hardcoded native structure offsets. The capture retains their exact definitions, event formats and hit/miss profile alongside the kernel image/configuration hashes. See the kernel documentation for [probe event filtering and profiling](https://www.kernel.org/doc/html/v6.10/trace/kprobetrace.html) and [BTF field access](https://www.kernel.org/doc/html/v6.10/trace/fprobetrace.html#btf-arguments). An unused direct `deactivate_task` entry probe received zero hits in the exploratory build; the admitted recipe instead observes the selected fair-class dequeue callback.

The four observations contain a directly fetched task pointer, PID, `__state`, `saved_state`, `on_rq` and `on_cpu`. The decoder requires PID 1, one consistent native task pointer, zero saved state, the expected sequence and the matching syscall/callback/IRQ context. It admits these states:

| Stage | Native probe | `__state` | `on_rq` | `on_cpu` |
| --- | --- | ---: | ---: | ---: |
| 1 | `dequeue_task_fair` entry | 8193 | 0 | 1 |
| 2 | `wake_up_process` entry | 8193 | 0 | 0 |
| 3 | `activate_task` entry | 512 | 0 | 0 |
| 4 | `wakeup_preempt` entry | 512 | 1 | 0 |

The observed sleep state includes `TASK_FREEZABLE` alongside `TASK_INTERRUPTIBLE`; activation uses `TASK_WAKING`. Replay reconstructs those values and emits each kind-13 record from its corresponding operation. It checks the computed fields against the captured transcript and checks the externally read RAM ledger against all normalized records. The native pointer is only a capture-side identity key and does not become a replay address. Older captures retain the earlier trace-only projection and require no probe support.

These are selected field observations in an instrumented single-CPU run, not a complete task or runqueue checkpoint. In task-state mode the sleeper link is still inferred; the additional mode below observes that link directly. Queue totals, accounting, scheduling-class operations, context switches and final post-wakeup task state still include inferred or modeled state. General freezer, RT and SMP behavior remain unsupported; probe overhead is not timing-equivalent replay. Missing probe support, changed definitions/formats, zero-hit or missed-probe counters, inconsistent fields/pointers and incomplete observation sequences reject.

The final capture is `build/linux-irq-task-state-native-final-v1`, with images in `build/linux-irq-task-state-final-v1`. Its seventeen events include all four direct observations and one timer IRQ; ELF/raw event and queue-witness ledgers match. The independent fixture `tests/fixtures/linux-aarch64-irq-task-state-native/` exercises an eighteen-event history. All eight IRQ regression cases passed in 42.62 seconds, including twenty runtime mutants and both external queue-witness corruption cases. Validation is recorded in `build/linux-irq-task-state-validation-20261019.json`.

## Direct sleeper-link milestone

Capture the sleeper relationship as well as task fields:

```sh
python3 tools/capture_linux_irq.py \
  --kernel-image /path/to/arm64/Image --sleeper-state \
  --out build/linux-irq-sleeper-native
python3 tools/export_linux_irq.py \
  --capture build/linux-irq-sleeper-native --out build/linux-irq-sleeper-image
```

`--sleeper-state` implies `--task-state` and additionally requires builtin `SYSFS`. Before configuring tracefs, PID 1 mounts sysfs, reads the running kernel's BTF (bounded to 8 MiB), resolves the direct `hrtimer_sleeper.timer` and `.task` members, and unmounts sysfs. The reader checks record bounds, member alignment, member types, timer size and zero timer-member offset; unsupported layouts reject. The capture saves the observed layout in `btf-layout.json`, and binds the reader/source and kernel identities. This is an observed layout summary, not an exported complete BTF blob or an independent native build attestation.

The admitted kernel reports a 72-byte sleeper, a timer member at byte zero and a task-pointer field at byte 64. Four more probes use BTF field access or the resolved offset. Return probes cache the original argument pointer and dereference the link on return; the mechanism is documented under [function arguments at kretprobe](https://www.kernel.org/doc/html/v6.10/trace/kprobetrace.html#function-arguments-at-kretprobe). Their explicit maximum active instance count is eight, and all probe miss counters must be zero.

| Stage | Native boundary | Linked task |
| --- | --- | --- |
| 1 | `do_nanosleep` entry | PID 1's captured task pointer |
| 2 | `hrtimer_wakeup` entry | The same task pointer |
| 3 | `hrtimer_wakeup` return | Null; return value zero |
| 4 | `do_nanosleep` return | Null; return value zero |

The callback timer address must equal the sleeper address; the admitted BTF layout places the timer at offset zero. All four observations must identify the same sleeper, and the nonnull links must match the directly captured task pointer. The decoder checks the callback observations inside the expiry IRQ and the sleep observations in PID 1, in the complete recorded order. This directly verifies the relationship used by `container_of` and observes the cleared link by callback return. It does not timestamp the individual clearing instruction.

Replay emits kind-14 records from its typed sleeper object at the corresponding boundaries. Native addresses remain capture-only identity keys; normalized timer/task IDs become reconstructed pointers inside the replay. Both ELF/raw event ledgers must match all observations from independently read RAM. Terminal ABI 29 remains unchanged. Other timer fields, complete object memory, queue totals, scheduler selection, SMP and cycle timing remain outside this checkpoint.

The accepted capture is `build/linux-irq-sleeper-native-final-v1`, with images in `build/linux-irq-sleeper-final-v1`. Both replay formats match twenty-four events, two physical timer IRQs, four task-field observations and four sleeper-link observations. All eleven regression cases passed in 37.98 seconds, including twenty-three runtime mutants, both external queue-witness corruption cases and ten BTF-reader input cases. The independent sleeper fixture has twenty-one events and one IRQ. Validation and artifact hashes are recorded in `build/linux-irq-sleeper-validation-20261019.json`. The regression fixture is `tests/fixtures/linux-aarch64-irq-sleeper-native/`; tests cover all three capture modes, relocated standalone execution, pointer/link/return/layout corruption, runtime mutants and bounded BTF parsing with malformed inputs.

## Original timer-wrapper milestone

Replay now also executes three selected definitions from [Linux v6.10 `kernel/time/hrtimer.c`](https://github.com/torvalds/linux/blob/v6.10/kernel/time/hrtimer.c#L1809): `__hrtimer_init_sleeper`, `hrtimer_init_sleeper` and `hrtimer_sleeper_start_expires`. Their executable statements are unchanged; internal comments are omitted. `timer-source-identity.json` pins the excerpt and source locations alongside the existing callback and scheduler identities.

The sleeper begins with a null task link and callback pointer. The original constructor sets both, and the original start wrapper forwards the timer to a bounded start boundary. The expiry IRQ dispatches through that installed callback pointer and requires the expected original callback. Constructor/start behavior is checked against the admitted initialization/arming events and, where captured, the direct sleeper/task observations. The model supplies the current task pointer only while compiling the original constructor; elsewhere the harness maintains its recorded current-task ID.

The projected boundary uses relative monotonic timers with `CONFIG_PREEMPT_RT` disabled. `debug_init`, `__hrtimer_init` and `hrtimer_start_expires` are checked models, not the full Linux implementations. RT delivery changes, debug-object machinery, clock bases, queue algorithms, cancellation and unrelated tick work remain outside the original-code closure. The retained native configuration has debug objects disabled; this does not attest the exact native source checkout.

Four independently read 32-byte timer witnesses cover the debug boundary, low-level initialization, completed original constructor and start boundary. Fields are kind, projected clock ID, projected mode, callback-pointer match, linked task ID, projected hard-delivery bit, initialization count and start count. These are model-state witnesses, not new native memory snapshots. ELF/raw event, queue and timer ledgers must all match before publication. Queue and timer ledgers are also verified after relocation and removal of construction inputs. Terminal ABI 29 remains unchanged.

The milestone reuses `build/linux-irq-sleeper-native-final-v1`, with new images in `build/linux-irq-timer-closure-final-v1`. Both replay formats still match twenty-four captured events, two physical timer IRQs, four direct task-field observations and four direct sleeper-link observations. All thirteen regression cases passed in 76.61 seconds, including thirty runtime mutants and four external queue/timer-witness corruption cases. Validation and source/artifact hashes are recorded in `build/linux-irq-timer-closure-validation-20261019.json`.

## Original timer enqueue/removal milestone

The exporter now includes the original `enqueue_hrtimer` and `__remove_hrtimer` definitions from [Linux v6.10 `kernel/time/hrtimer.c`](https://github.com/torvalds/linux/blob/v6.10/kernel/time/hrtimer.c#L1012). Their code is pinned in `timer-queue-source-identity.json`. This brings the timer function count to six, alongside eight scheduler helpers.

The original helpers perform timer-state and active-base bookkeeping around checked `timerqueue_add`/`timerqueue_del` boundaries. The container contains only the selected timer in logical base slot zero; it does not implement Linux's red-black tree. The mask and queue contents are a selected-timer projection, not newly captured native fields or a claim that the native base contains no other timers. Clock-base locking, shared queues, migration, restart and event-device reprogramming remain modeled or unsupported. The supported expiry path requests no reprogramming; attempts to enter that boundary reject.

Start now inserts the selected timer through the original enqueue helper. The removal event invokes the original removal helper inside the delivered IRQ before the callback. The target requires one insertion, one deletion, an empty projected queue and cleared projected active mask. It then makes one additional synthetic inactive-removal call, which must return without another deletion or reprogramming. This contract guard adds no native events and is labeled separately in the manifest.

The fourth independently read ledger covers the pre-enqueue state, completed enqueue, pre-removal state, completed removal and inactive-removal guard. Each of its five 32-byte records contains kind, timer state, projected active mask, queued timer ID, add count, delete count, reprogram count and inactive-probe count. The artifact names are `expected-timer-queue.bin` and `target-timer-queue-{0,1}.bin`; the RAM symbol is `osrec_linux_irq_timer_queue`. Any byte mismatch rejects publication. Standalone relocation tests retain and independently verify this ledger after construction inputs are removed. Terminal ABI 29 remains unchanged.

The native capture remains `build/linux-irq-sleeper-native-final-v1`; images are in `build/linux-irq-timer-queue-final-v1`. Both replay formats still match twenty-four captured events, two physical timer IRQs and all eight direct task/sleeper observations. All fourteen regression cases passed in 75.37 seconds, including thirty-eight runtime mutants and six external boundary-witness corruption cases. Validation is recorded in `build/linux-irq-timer-queue-validation-20261019.json`.

## Original callback-run milestone

Replay now invokes the complete selected `__run_hrtimer` definition from [Linux v6.10 `kernel/time/hrtimer.c`](https://github.com/torvalds/linux/blob/v6.10/kernel/time/hrtimer.c#L1537), with internal comments omitted and executable statements unchanged. `timer-run-source-identity.json` pins the definition. The reference timer function count is seven; the scheduler helper count remains eight.

The original body marks the running timer, removes it, invokes the installed callback, handles the restart decision and clears the running marker. The harness no longer manually sequences the selected removal/expiry/callback trace events. Checked debug/trace and lockdep boundaries emit those observations around the original call. All direct task/sleeper observations remain in the independently compared captured-event ledger.

Lock ownership, saved flags, sequence barriers and lockdep calls are explicit single-CPU models. The saved-flags value is a logical token; sequence values count hook calls rather than exposing native seqcount encoding. These hooks do not unmask the physical IRQ or implement Linux spinlocks/concurrent readers. `CONFIG_TIME_LOW_RES` is disabled in this reference projection. The ordered timer container, complete clock-base state, event-device programming and surrounding tick work remain modeled. Only the admitted `HRTIMER_NORESTART` path is supported: attempts to requeue reach an unsupported boundary and reject. The native running marker, lock and sequence memory have not been captured directly.

The fifth ledger, `osrec_linux_irq_callback`, contains seven 32-byte records: entry with the logical lock held, first sequence barrier, unlock after removal, callback completion, lock reacquisition, second sequence barrier and exit with the running marker cleared. Fields are kind, running timer wire ID, timer state, logical lock depth, sequence-barrier count, unlock count, relock count and callback count. It is stored in `expected-callback.bin` and independently read into `target-callback-{0,1}.bin`. Publication requires both images' complete five-ledger comparisons to pass, and standalone relocation tests also read this boundary ledger after construction inputs are removed. Terminal ABI 29 is unchanged.

The inactive-removal and repeated-wakeup probes now run after the original callback-run body and still add no captured events. The original helper retains the logical lock on return, matching its caller contract; the surrounding model releases it. The source runner requires the admitted removal and expiry-entry events to be adjacent in the same delivered IRQ.

The capture remains `build/linux-irq-sleeper-native-final-v1`, with images in `build/linux-irq-run-timer-final-v1`. Both formats match twenty-four native events, two physical timer IRQs and all eight direct task/sleeper observations. All fifteen regression cases passed in 59.80 seconds, including forty-eight runtime mutants and eight external boundary-witness corruption cases. Validation and source/artifact hashes are recorded in `build/linux-irq-run-timer-validation-20261019.json`.

## Direct callback timer-state milestone

```sh
python3 tools/capture_linux_irq.py \
  --kernel-image /path/to/arm64/Image --timer-state \
  --out build/linux-irq-timer-state-native
python3 tools/export_linux_irq.py \
  --capture build/linux-irq-timer-state-native --out build/linux-irq-timer-state-image
```

`--timer-state` implies `--sleeper-state` and `--task-state`. One additional entry probe at `hrtimer_wakeup` fetches the timer argument, `timer->base`, `timer->base->running` and `timer->state`. The kernel resolves the nested member expressions through [BTF argument and field access](https://www.kernel.org/doc/html/v6.10/trace/fprobetrace.html#btf-arguments). Its exact definition, field formats and zero-miss profile are checked and retained with the capture. Older captures retain their previous observation requirements.

The admitted callback snapshot has inactive timer state 0 and a running pointer equal to the selected timer address. The object must match the sleeper/timer identity already observed at sleep entry. The base must be an aligned canonical kernel pointer distinct from the timer. The snapshot occurs inside the selected expiry IRQ, before the sleeper callback-link observation and task wake. Missing, duplicate, reordered or incompatible snapshots reject. Native object, base and running addresses remain capture-only keys.

The reference callback-run body produces the corresponding state before invoking the original callback. Its checked boundary emits kind 15 from the reconstructed timer state and running pointer; both independently read ELF/raw event ledgers must equal the native normalized record. A terminal guard also requires exactly one timer snapshot. The manifest reports `native_timer_fields_verified` and the normalized `native_timer_observations`. The existing five ledgers and terminal ABI 29 are retained.

This observes selected fields at callback entry. It does not directly observe the later native clearing of `base->running`, native lock ownership, seqcount memory, active masks, complete clock bases or concurrent readers. Those remain modeled. The installed kernel has no probeable `__run_hrtimer` symbol, and an exploratory PID-1-filtered `hrtimer_cancel` entry probe did not fire for this sleep. Neither exploratory probe is part of the accepted recipe. The retained source-level runner and native build still have separate identities; no exact native source build attestation or cycle timing equivalence is claimed.

The accepted capture is `build/linux-irq-timer-state-native-final-v1`, with ELF/raw images in `build/linux-irq-timer-state-final-v1`. Both formats match twenty-six captured events, three physical timer IRQs, four task-field observations, four sleeper-link observations and one timer-state snapshot. The regression fixture is `tests/fixtures/linux-aarch64-irq-timer-state-native/`. Validation and source/artifact hashes are recorded in `build/linux-irq-timer-state-validation-20261019.json`.

All seventeen Linux IRQ regression cases passed in 47.88 seconds, including fifty-one runtime mutants, eight external boundary-ledger corruption cases and ten BTF-reader input cases. All four capture modes pass; the timer-state fixture also executes after relocation and removal of construction inputs, with its four boundary ledgers independently read from RAM.

## Native running-pointer return milestone

```sh
python3 tools/capture_linux_irq.py \
  --kernel-image /path/to/arm64/Image --timer-return \
  --out build/linux-irq-timer-return-native
python3 tools/export_linux_irq.py \
  --capture build/linux-irq-timer-return-native --out build/linux-irq-timer-return-image
```

`--timer-return` implies timer-state, sleeper-state and task-state capture. A bounded reader resolves the direct pointer members `hrtimer.base` and `hrtimer_clock_base.running` from the running kernel's BTF. It first validates the existing sleeper layout and all record bounds, then requires unique complete structures, the expected reciprocal pointer types, 64-bit member alignment and offsets within bounded structure sizes. Bitfield pointer members and unsupported type wrappers reject. The accepted kernel reports 64-byte timer/base structures, with the base pointer at byte 48 and running pointer at byte 24. This follows the kernel's [BTF structure and pointer encoding](https://docs.kernel.org/bpf/btf.html).

PID 1 registers an additional `do_nanosleep` return probe with an explicit maximum of eight active instances. The probe caches the original sleeper pointer and reads its timer's base and that base's running pointer at return, using the resolved offsets. The kernel documents this argument-cache mechanism under [function arguments at kretprobe](https://www.kernel.org/doc/html/v6.10/trace/kprobetrace.html#function-arguments-at-kretprobe). The capture retains `timer-layout.json`, exact probe definitions, event formats and zero-miss profiles; the exporter checks them against the native log and manifest.

The return observation must follow the selected task's resumption and sleeper-return observation, outside the IRQ and before syscall completion. It must identify the same sleeper/timer and base as callback entry, return zero and report a null running pointer. Thus the admitted observations show the selected timer as running at callback entry and no running timer on that same base by sleep return. They do not timestamp the clearing instruction or observe the source runner's immediate native return.

Replay emits kind 16 from its reconstructed timer ID and current running pointer after its recorded task resumes. The single modeled base has wire ID 1. The original reference runner has already cleared the running marker; a terminal guard requires exactly one return observation. Both ELF/raw event ledgers must equal the captured normalized observation, in addition to all four existing boundary ledgers. Terminal ABI 29 and older capture modes remain supported. Native addresses remain capture-side identity keys.

The accepted capture is `build/linux-irq-timer-return-native-final-v1`, with images in `build/linux-irq-timer-return-final-v1`. Both formats match twenty-six events and two physical timer IRQs, including four task snapshots, four sleeper links, the callback timer snapshot and the running-pointer return observation. A separately captured regression fixture is retained in `tests/fixtures/linux-aarch64-irq-timer-return-native/`. Validation and source/artifact hashes are recorded in `build/linux-irq-timer-return-validation-20261019.json`. Native lock/sequence memory, active masks, full queues and concurrent readers remain outside the observed state; no exact native source build attestation or cycle timing equivalence is claimed.

All twenty Linux IRQ regression cases passed in 89.20 seconds, including fifty-four runtime mutants, eight external boundary-ledger corruption cases and twenty-five BTF-reader input cases (fifteen for the new return layout). All five capture modes pass, including relocated standalone execution after construction inputs are removed. An initial test-only failure treated NULL as an address that must be absent from ELF; the exclusion check now applies to nonzero native addresses.

## Clock-base state and residual occupancy milestone

```sh
python3 tools/capture_linux_irq.py \
  --kernel-image /path/to/arm64/Image --base-state \
  --out build/linux-irq-base-state-native
python3 tools/export_linux_irq.py \
  --capture build/linux-irq-base-state-native --out build/linux-irq-base-state-image
```

`--base-state` implies all prior field-capture modes. Two extra probes observe the selected timer, its clock base, that base's CPU-base pointer, its index and the CPU base's `active_bases` mask. Callback entry uses BTF field expressions; sleep return uses offsets resolved from the running kernel's BTF. A bounded reader checks direct pointer types, integer/typedef widths, alignment, bounds and unique structures. It rejects bitfield members, cyclic or excessively deep scalar type aliases and incompatible layouts. The accepted kernel reports clock-base CPU-pointer offset 0, index offset 8, and active-mask offset 8 in a 576-byte CPU base. Exact definitions, formats, zero-miss profiles and `base-layout.json` are checked against the native log and manifest.

The decoder requires monotonic base index zero and the same timer, clock-base and CPU-base identities at both boundaries. The callback observation precedes the timer-field and sleeper-link probes inside the selected IRQ. The return observation follows both existing sleep-return probes and precedes syscall completion. The selected active bit must remain stable between these snapshots; changes reject this bounded recipe. The complete 32-bit native mask is retained in `native_base_observations`, while only its selected bit enters the portable kind-17 records. Other bits are context, not verified replay state. Native addresses remain capture-only correlation keys.

The accepted native observations have an inactive selected timer and active bit 1 at both boundaries. This is consistent with another timer remaining on the same base. The reference [Linux timer removal helper](https://github.com/torvalds/linux/blob/v6.10/kernel/time/hrtimer.c#L1027) leaves the bit set when deletion reports a nonempty queue. Replay now represents that case with an explicit opaque residual-occupancy flag alongside its selected timer node. The flag is inferred from the post-removal observations and assumed stable across the replay slice; pre-enqueue occupancy is reconstructed, not directly captured. No background timer objects, counts, ordering or deadlines are reproduced.

The modeled `timerqueue_del` removes the selected node and reports whether the opaque remainder is nonempty. The unchanged original removal helper therefore preserves or clears its projected active bit. Both kind-17 records are emitted from that resulting base state. Initial, post-removal and inactive-removal timer-queue witnesses now carry the residual active bit; their selected-node ID is zero once the selected timer is removed. All five ELF/raw ledgers must match before publication. Older captures retain residual occupancy zero, and terminal ABI 29 remains unchanged. The manifest identifies `native_base_fields_verified`, `background_base_occupancy` and the scope of that reconstruction separately. The foreground dispatcher now also requires each iteration to consume events, so an omitted snapshot fails inside the target instead of stalling until the observer times out.

The accepted capture is `build/linux-irq-base-state-native-final-v1`, with images in `build/linux-irq-base-state-final-v2`. Both formats match thirty events and three physical timer IRQs, including all earlier direct observations and the two base snapshots. The separate regression fixture `tests/fixtures/linux-aarch64-irq-base-state-native/` has twenty-six events and one IRQ. A synthetic contract test also exercises selected bit zero with an unrelated native mask bit set; it is not presented as another native capture. Validation and source/artifact hashes are recorded in `build/linux-irq-base-state-validation-20261019.json`. Full queue algorithms, native lock/sequence memory, concurrent readers, exact native source build attestation and cycle timing equivalence remain outside this milestone.

All twenty-four Linux IRQ regression cases passed in 74.46 seconds, including sixty runtime mutants, eight external boundary-ledger corruption cases and forty-three BTF-reader input cases (eighteen for the new base layout). All six capture modes pass, with relocated standalone execution after construction inputs are removed. The omitted-return-snapshot mutant exposed a foreground dispatch stall; the new progress guard makes it reject in the target.

## Bounded ordered-container milestone

The selected-timer container now uses a checked two-slot ordered array instead of a selected-node pointer and residual boolean. It is a replay model, not Linux's red-black tree implementation. The original timer enqueue/removal and callback-run definitions remain unchanged; the reviewed timer and scheduler function counts remain seven and eight.

When base-state observations imply a nonempty remainder, replay seeds a synthetic sentinel with wire ID 2 and ordering key `UINT64_MAX`. That key is a model ordering choice, not a native timer deadline or a signed Linux `ktime_t`. The sentinel represents occupancy only; it does not identify a native timer or establish the number or ordering of native background timers. The selected timer uses ID 1 and its captured deadline. Its insertion must make it the first entry; removal leaves either the sentinel or an empty container. Older captures seed no sentinel. The inactive-removal guard must leave the remaining container unchanged.

The bounded helpers compute insertion position, first-entry status and post-removal nonemptiness from actual container contents. Equal keys preserve insertion order within this model. Checks reject duplicate pointers or IDs, repeated membership, absent removal, invalid counts, capacity overflow, stale tail slots and incompatible ordering. The original timer removal helper receives the computed nonempty result and preserves or clears its active bit accordingly. This replaces the previous direct return of the inferred residual flag without expanding the native checkpoint.

The new `osrec_linux_irq_ordered` ledger has four 32-byte records: after optional sentinel seeding, selected insertion, selected removal and the inactive-removal guard. Fields are kind, entry count, first ID, second ID, selected membership, sentinel membership, selected insertion count and selected deletion count. Seeding is a synthetic initialization operation and does not increment the selected insertion count. The exporter independently reads the ledger from both images into `target-ordered-{0,1}.bin` and compares it with `expected-ordered.bin`; all six ledgers must match before publication. Standalone relocation tests read all five boundary ledgers after capture, source and manifest removal. Terminal ABI 29 and the native event transcript remain unchanged.

This milestone reuses `build/linux-irq-base-state-native-final-v1`; the new ELF/raw images are in `build/linux-irq-ordered-queue-final-v1`. Both replay thirty events and three physical timer IRQs, including the captured base snapshots. The synthetic empty-remainder test still verifies that unrelated native mask bits are context rather than replayed selected occupancy. Validation and source/artifact hashes are recorded in `build/linux-irq-ordered-queue-validation-20261019.json`. Native full queue contents, balancing, background deadlines, concurrent access, lock/sequence memory, exact source build attestation and cycle timing equivalence remain outside this model.

All twenty-six Linux IRQ regression cases passed in 76.52 seconds, including sixty-eight runtime mutants, ten external boundary-ledger corruption cases and forty-three BTF-reader input cases. Fifteen direct ordered-container cases cover both insertion orders, stable ties, removals, reinsertion and invalid operations. All six capture modes pass, including standalone relocation with the new boundary ledger after construction inputs are removed.

## Original queue-dispatch milestone

Replay now includes the selected complete `__hrtimer_run_queues` definition from [Linux v6.10 `kernel/time/hrtimer.c`](https://github.com/torvalds/linux/blob/v6.10/kernel/time/hrtimer.c#L1606), with internal comments omitted. `timer-driver-source-identity.json` pins the excerpt. The original timer function count is eight; the scheduler helper count remains eight.

The original queue loop now chooses the next node, checks its soft expiry and invokes the original callback runner. The replay boundary supplies one monotonic clock base with offset zero, the bounded ordered container and the captured expiry clock input. Active-base iteration, clock addition and field accessors are checked models. The containing tick/IRQ driver, clock-update machinery and softirq delivery are not included. The captured transcript still selects the admitted expiry IRQ and supplies its time; this is not a prediction of native interrupt timing or all tick decisions.

The residual sentinel is now contained in a typed synthetic timer so the queue loop can use `container_of` safely. Its queue key remains `UINT64_MAX`, while its synthetic soft expiry is `INT64_MAX`. The admitted expiry input must be below that soft expiry; the original queue loop therefore stops on the sentinel after removing the selected timer. Neither sentinel value is an observed native background deadline. General restarts, extra callbacks and native background timer reproduction remain unsupported.

Three additional synthetic passes surround the captured expiry pass: a zero active-mask pass, a pass one unit before the selected soft deadline and a pass after callback completion. They must emit no extra captured events or callbacks. These passes exercise the original queue body under the existing logical lock inside the delivered IRQ; they are not native captured operations. Attempts to enter the modeled softirq wait boundary reject.

The seventh ledger, `osrec_linux_irq_driver`, has four 32-byte records covering those four passes. Fields are kind, callback count, selected membership, first queued ID, projected CPU active mask, queue-peek count, soft-expiry access count and base-visit count. Counts include the synthetic passes and are not native performance counters. The exporter independently reads `target-driver-{0,1}.bin` and compares them with `expected-driver.bin`; all seven ledgers must match before publication. Relocated standalone tests read all six boundary ledgers after construction inputs are removed. Terminal ABI 29 remains unchanged.

The native capture remains `build/linux-irq-base-state-native-final-v1`; images are in `build/linux-irq-queue-driver-final-v1`. Both formats still match thirty events and three physical timer IRQs. A separate host test compiles the same pinned queue body with isolated helper stubs to check soft-deadline equality, times between soft and hard deadlines, active masks, positive/negative base offsets and two due timers. Those extra host cases do not expand the supported native replay recipe. The Linux IRQ CTest limit is now 300 seconds for the expanded mutation/relocation suite; per-image observer limits are unchanged. Validation and source/artifact hashes are recorded in `build/linux-irq-queue-driver-validation-20261019.json`. Native lock/sequence memory, full queue algorithms, exact native source build attestation and cycle timing equivalence remain outside this milestone.

All twenty-eight Linux IRQ regression cases passed in 189.33 seconds, including seventy-seven runtime mutants, twelve external boundary-ledger corruption cases, forty-three BTF-reader inputs and fifteen ordered-container inputs. Ten isolated queue-driver cases pass, and two host mutations detect incorrect deadline equality or use of the hard deadline. All six capture modes pass, including relocated standalone execution with all six boundary ledgers. The first full run reached the previous 180-second suite limit; the successful rerun used the new 300-second limit.

## Original low-resolution outer-runner milestone

Replay now includes the original `hrtimer_run_queues` definition from [Linux v6.10 `kernel/time/hrtimer.c`](https://github.com/torvalds/linux/blob/v6.10/kernel/time/hrtimer.c#L1755), with internal comments omitted. `timer-outer-source-identity.json` pins the excerpt. There are now nine reviewed timer functions and eight scheduler helpers. The outer body performs its mode checks, takes the logical lock, obtains a clock input, evaluates its softirq deadline and invokes the original queue-dispatch body before releasing the lock.

The accepted reference projection has no active high-resolution mode, no one-shot transition, a softirq deadline initialized to `INT64_MAX` and an inactive softirq flag. These mode decisions and softirq fields are modeled inputs, not new native observations. The clock-update boundary injects the captured selected expiry time. Current-CPU lookup and lock/save/restore operations are checked models; saved flags are the logical token 1 and do not expose native DAIF state. Transition and softirq-raise boundaries reject in the standalone image; softirq delivery and actual clock-update internals remain unsupported.

The pre-expiry synthetic queue checks run first under the surrounding logical lock. The model then releases that lock and calls the original outer runner, which owns its lock scope around the captured callback path. After it returns unlocked, the surrounding model reacquires the logical lock for the post-callback and inactive-removal guards. These synthetic operations do not add native events or claim to reproduce surrounding native tick work. The existing seven ledgers retain their meanings.

The eighth ledger, `osrec_linux_irq_outer`, records seven boundaries: CPU lookup, high-resolution guard, tick-mode decision, lock acquisition, clock update, softirq comparison and completed unlock. Each 32-byte record contains kind, logical lock state, clock-update count, tick-check count, softirq-raise count, queue-dispatch count, callback count and softirq-activated flag. Queue-dispatch counts exclude the earlier synthetic passes. The exporter reads `target-outer-{0,1}.bin` independently and compares them with `expected-outer.bin`; all eight ledger pairs must match before publication. Standalone relocation tests read all seven boundary ledgers after construction inputs are removed. Terminal ABI 29 remains unchanged.

The milestone reuses `build/linux-irq-base-state-native-final-v1`, with images in `build/linux-irq-outer-timer-final-v1`. Both replay thirty events and three physical timer IRQs. Eight isolated host cases exercise the same pinned outer body with helper stubs, including early return, one-shot transition, future/equal/past softirq deadlines and preservation of an existing activation flag. Those tests validate source control flow without enabling those branches in native replay. Validation and source/artifact hashes are recorded in `build/linux-irq-outer-timer-validation-20261019.json`. Full tick processing, native clock-update and synchronization memory, exact native source build attestation and cycle timing equivalence remain outside this milestone.

All thirty Linux IRQ regression cases passed in 108.30 seconds, including eighty-seven runtime mutants, fourteen external boundary-ledger corruption cases, forty-three BTF-reader inputs and fifteen ordered-container inputs. Ten isolated queue-driver cases and eight isolated outer-runner cases pass; four host mutations reject across those two source tests. All six capture modes pass, including standalone relocation with all seven boundary ledgers after construction inputs are removed.

## Native callback-entry softirq-state milestone

```sh
python3 tools/capture_linux_irq.py \
  --kernel-image /path/to/arm64/Image --outer-state \
  --out build/linux-irq-outer-state-native
python3 tools/export_linux_irq.py \
  --capture build/linux-irq-outer-state-native --out build/linux-irq-outer-state-image
```

`--outer-state` implies all prior field-capture modes. One additional `hrtimer_wakeup` entry probe reads the timer argument, its CPU-base pointer, `softirq_expires_next` as a signed 64-bit value and `softirq_activated` through [BTF field access](https://www.kernel.org/doc/html/v6.10/trace/fprobetrace.html#btf-arguments). The kernel resolves the activation bitfield; the retained event format exposes its fetched value as `u32`. Exact definitions, formats and zero-miss profiles are checked with the native capture. No hardcoded offset for either new field is used.

The accepted snapshot reports deadline `INT64_MAX` and activation flag 0. These values directly confirm the model's fields at callback entry. This bounded mode rejects other values; it does not admit arbitrary softirq state or enable softirq delivery. The timer must match the earlier sleeper identity, and the CPU-base pointer must agree with the subsequent base probes. The new observation precedes those probes, lies inside the selected expiry IRQ and precedes the wake. Missing, duplicate, reordered, incompatible or falsely attributed observations reject. Native addresses remain capture-only identity keys.

Replay emits kind 18 from its current CPU-base fields at the original callback boundary, after the reference outer body has evaluated its modeled deadline. Both independently read ELF/raw event ledgers must match the native normalized record; a terminal guard requires exactly one snapshot. The existing eight ledger pairs and terminal ABI 29 remain in use. The parser keeps this softirq deadline separate from the selected timer's hard/soft deadlines, and tests assert that distinction explicitly.

The observation does not directly capture outer-runner entry state, the clock-update function's return, tick-mode decisions, lock memory or the softirq raising/delivery history. The initial deadline/flag and clock-update boundary remain modeled; the captured expiry timestamp continues to supply the clock input. Earlier modes retain their previous inferred state and need no additional probes.

The new accepted capture is `build/linux-irq-outer-state-native-final-v1`, with images in `build/linux-irq-outer-state-final-v1`. Both formats match thirty events and three physical timer IRQs, including the new softirq-state snapshot. The independently captured fixture `tests/fixtures/linux-aarch64-irq-outer-state-native/` has twenty-nine events and two IRQs. Validation and source/artifact hashes are recorded in `build/linux-irq-outer-state-validation-20261019.json`. Exact native source build attestation, full queue/tick work, concurrent readers and cycle timing equivalence remain outside this milestone.

All thirty-two Linux IRQ regression cases passed in 100.37 seconds, including ninety runtime mutants, fourteen external boundary-ledger corruption cases, forty-three BTF-reader inputs and fifteen ordered-container inputs. All seven capture modes pass, including standalone relocation with all seven boundary ledgers after construction inputs are removed. Snapshot tests cover field values, identity, ordering, definitions, formats, profile misses, mode provenance and separation of the selected-timer and softirq deadlines.


## Original clock-offset propagation milestone

Replay now executes the original `hrtimer_update_base` definition from [Linux v6.10 `kernel/time/hrtimer.c`](https://github.com/torvalds/linux/blob/v6.10/kernel/time/hrtimer.c#L588). `timer-clock-source-identity.json` pins the complete definition. Ten timer functions and eight scheduler helpers now execute original source. The clock-update body passes the sequence and three hard-base offset addresses to the modeled timekeeper, copies the resulting realtime, boottime and TAI offsets into their corresponding soft bases, and returns the supplied time.

The lower boundary, `ktime_get_update_offsets_now`, still injects the selected captured expiry timestamp. Its sequence value 1 and offsets 11, 22 and 33 are synthetic contract inputs, not native clock state. Soft offsets begin at -11, -22 and -33 so omitted copies cannot pass. Both monotonic offsets remain zero, and only the selected monotonic base participates in dispatch. The additional offset slots do not add native timers, clock-domain replay or timekeeping internals. This milestone reuses the accepted outer-state native capture and adds no probes or native observations.

A ninth independently read ledger, `osrec_linux_irq_clock`, has two 80-byte records: the modeled timekeeper output before the original copies, and completed propagation before the outer deadline comparison. Its ten 64-bit fields are kind, update count, sequence, returned time, three hard offsets and three soft offsets. Kind/count/sequence are unsigned; time and offsets are signed. The exporter compares both images' complete `target-clock-{0,1}.bin` dumps with `expected-clock.bin` before publication. Relocation tests also verify this ledger after removing construction inputs. All nine ledger pairs must match; terminal ABI 29 is unchanged.

Six isolated host cases exercise zero, negative, signed 64-bit extremes and values wider than 32 bits through the same pinned body. Eight new runtime mutants test omitted copies, changed return time, swapped offset pointers, wrong sequence/offset inputs and a missing completion witness. Two host mutants test incorrect propagation and return time. External corruption checks cover both formats of all eight boundary ledgers.

The accepted native capture remains `build/linux-irq-outer-state-native-final-v1`; new images are in `build/linux-irq-clock-update-final-v1`. Both formats replay thirty events and three physical timer IRQs. Validation and source/artifact hashes are in `build/linux-irq-clock-update-validation-20261019.json`. Native timekeeper returns/offsets, outer entry state, tick decisions, synchronization memory, exact native source build attestation and cycle timing equivalence remain unverified. A next capture milestone can investigate the timekeeper boundary without treating the synthetic propagation inputs as native observations.


## Native timekeeper-output milestone

```sh
python3 tools/capture_linux_irq.py \
  --kernel-image /path/to/arm64/Image --clock-state \
  --out build/linux-irq-clock-state-native
python3 tools/export_linux_irq.py \
  --capture build/linux-irq-clock-state-native --out build/linux-irq-clock-state-image
```

`--clock-state` implies all prior field-capture modes. A return probe on `ktime_get_update_offsets_now` saves its four pointer arguments and fetches the sequence, three signed 64-bit offset outputs and signed 64-bit return value. The [Linux v6.10 timekeeping helper](https://github.com/torvalds/linux/blob/v6.10/kernel/time/timekeeping.c#L2151) returns monotonic time and conditionally updates the pointed-to fields. The probe observes their values after the call; it does not establish that every call wrote them. [Kprobe return probes](https://www.kernel.org/doc/html/v6.10/trace/kprobetrace.html) provide the saved arguments and return value. Exact definitions, signed field formats and zero-miss profiles are retained and verified. No new hardcoded kernel layout offsets are used.

The bounded recipe requires exactly one return immediately after each captured timer IRQ entry, attributed to `hrtimer_run_queues`. All four destination addresses must be aligned canonical kernel pointers, distinct, stable across calls and different from other observed object addresses. They remain capture-only identity keys. Values must fit their native widths, returned times must increase and lie within the captured interval, and the selected IRQ return must equal the later `hrtimer_expire_entry` time exactly. Missing, duplicated, reordered, incompatible or falsely attributed observations reject. This correlates the call within a single-CPU IRQ; it does not directly map the four destination pointers onto the BTF CPU-base layout.

Each native return becomes two portable 32-byte records: kind 19 contains time, sequence and timekeeper wire ID 1; kind 20 contains realtime, boottime and TAI offsets as 64-bit two's-complement bit patterns. Thus native and replay event counts differ by one record per timekeeper observation. Native pointers are excluded from the images. The selected IRQ's injected lower boundary writes these observed values into the replay fields, and the original `hrtimer_update_base` body propagates them. Its ninth RAM ledger now verifies native output values and the resulting modeled soft offsets. Initial soft offsets remain synthetic omission guards. Other IRQs retain their timekeeper returns as injected boundary observations without executing the full outer/tick path. Older capture modes retain their existing synthetic sequence and offsets. The IRQ loop now rejects lack of event progress.

The native observation is the lower helper's return and pointed-to outputs. The inline `hrtimer_update_base` return and native soft-offset writes are not separately captured. Timekeeper internals, input sequence, initial soft state, other clock-domain timer dispatch, tick decisions and synchronization memory remain modeled or unobserved. No exact native source build attestation or cycle timing equivalence is claimed.

The accepted final capture is `build/linux-irq-clock-state-native-final-v2`, with images in `build/linux-irq-clock-state-final-v1`. The images match forty-one portable events derived from thirty-seven native events and four physical timer IRQs. All nine independently read ELF/raw RAM ledger pairs match. The independent fixture `tests/fixtures/linux-aarch64-irq-clock-state-native/` has thirty-one native events, thirty-three portable events and two IRQs. The first final-capture attempt retained an unrelated worker wakeup and was correctly rejected by the existing bounded recipe; it produced no replay image. Validation and source/artifact hashes are in `build/linux-irq-clock-state-validation-20261019.json`.

All thirty-seven Linux IRQ regression cases passed in 139.83 seconds. They include 106 runtime mutants, sixteen external boundary-ledger corruptions, all eight capture modes, relocation after construction-input removal and a synthetic signed-boundary projection including `INT64_MIN`. Eight new runtime mutants cover return/offset corruption, incorrect sequence and offset writes, missing counts, missing context emissions and selection of the wrong IRQ's inputs. The test harness initially found an ambiguous mutation selector; the corrected selector passed its targeted check and the full suite. The failed attempt is retained separately from the final passing evidence.


## Native propagated-offset milestone

```sh
python3 tools/capture_linux_irq.py \
  --kernel-image /path/to/arm64/Image --clock-offsets \
  --out build/linux-irq-clock-offsets-native
python3 tools/export_linux_irq.py \
  --capture build/linux-irq-clock-offsets-native --out build/linux-irq-clock-offsets-image
```

`--clock-offsets` implies all prior capture modes. A bounded reader resolves the CPU base's direct eight-element `clock_base` array, its complete element type/size, the element's signed 64-bit `offset` field and the CPU base's unsigned 32-bit `clock_was_set_seq` field from native BTF. It validates all record bounds through the existing layout readers before inspecting members. It rejects duplicate members, bitfields, incompatible integer encodings, cycles or excessive scalar type wrappers, wrong array element/index types/counts, unaligned fields and out-of-structure extents. The native layout has a 576-byte CPU base, eight 64-byte clock bases beginning at byte 64, element offset at byte 56 and sequence at byte 12. These are discovered values, not fixed kernel offsets. Array positions retain the admitted Linux v6.10 hard/soft clock ordering.

One additional `hrtimer_wakeup` entry probe reads the timer identity, CPU-base pointer, sequence and soft realtime/boottime/TAI offsets through the derived layout. Exact definitions, signed field formats, requested mode, retained layout and zero-miss profiles are verified. The snapshot precedes the earlier callback probes inside the selected expiry IRQ. Its sequence and three offsets must equal the selected timekeeper return outputs. Native object and CPU identities must agree with the existing observations. The earlier four timekeeper destination pointers must equal the BTF-derived sequence and hard-offset addresses in this CPU base, and the selected timer's base must be its array element zero. Missing, duplicate, reordered, incompatible, wrongly attributed or falsely mapped observations reject.

Portable event kind 21 carries the three soft offsets as 64-bit two's-complement values. The target emits it from the replay fields populated by the original `hrtimer_update_base` body, before its other callback snapshots, and checks the sequence at the same boundary. All nine independently read ELF/raw RAM ledger pairs still gate publication; the ninth ledger's computed propagation results now have direct native callback-field observations as well as native timekeeper outputs. The terminal ABI remains 29. Older modes retain their earlier requirements.

This observes completed native field values at callback entry. It does not capture the individual native copy instructions, the inline updater's immediate return, initial soft offsets or input sequence. Initial soft fields remain synthetic omission guards. Native timekeeper internals, tick decisions, lock/sequence synchronization memory, full clock-domain dispatch, exact native source build attestation and cycle timing equivalence remain outside the supported projection. Captures with clock observations before the admitted syscall window remain rejected by the bounded recipe.

All forty-one Linux IRQ regression cases passed in 160.68 seconds, including 110 runtime mutants, sixteen external boundary-ledger corruptions and all nine capture modes. The new BTF reader adds twenty-four inputs, bringing the bounded-reader total to sixty-seven. Tests cover layout/type/bounds failures, pointer mapping, callback identity/order, mode provenance, omitted/changed snapshots and signed 64-bit extremes in a synthetic projection. Standalone relocation still checks all eight boundary ledgers after removing construction inputs.

The accepted final capture is `build/linux-irq-clock-offsets-native-final-v4`, with images in `build/linux-irq-clock-offsets-final-v1`. Both formats reproduce thirty-four portable events from thirty-two native events and two physical timer IRQs. The independent fixture has twenty-eight native events, twenty-nine portable events and one IRQ. Three earlier final-capture attempts were rejected for clock observations before the syscall window, events after syscall completion or an unrelated worker wakeup; they produced no accepted replay images. The validation record `build/linux-irq-clock-offsets-validation-20261019.json` retains their rejection details alongside final source/artifact hashes.


## Native timekeeper-entry milestone

```sh
python3 tools/capture_linux_irq.py \
  --kernel-image /path/to/arm64/Image --clock-entry \
  --out build/linux-irq-clock-entry-native
python3 tools/export_linux_irq.py \
  --capture build/linux-irq-clock-entry-native --out build/linux-irq-clock-entry-image
```

`--clock-entry` implies all prior field-capture modes. A new entry probe on `ktime_get_update_offsets_now` reads the same four destination pointers, unsigned 32-bit sequence and signed 64-bit hard offsets as the existing return probe. Each captured timer IRQ must now have exactly one entry/return pair: entry immediately after IRQ entry, then return immediately after helper entry, with matching stable destinations and no intervening captured event. The existing BTF CPU-base mapping also applies to those input pointers. Definitions, signed field formats, zero-miss profiles, mode provenance and value widths are checked. Missing, duplicate, reordered, mismatched or unpaired observations reject.

Portable kind 22 records the input sequence, timekeeper wire ID 1 and zero; kind 23 records the three input offsets as 64-bit two's-complement values. The existing kinds 19/20 retain return values and kind 21 checks native propagated soft fields. Each entry and each return expands to two records, so portable event count exceeds native event count by two per IRQ. Native destination addresses remain capture-only keys.

Replay reconstructs the selected helper's observed entry sequence and hard offsets, replacing the earlier synthetic zero entry state for this mode. The modeled lower boundary checks and emits those actual reconstructed fields, then applies recorded outputs only to fields whose values differ. The original `hrtimer_update_base` body still propagates outputs to soft bases. Non-expiry IRQ pairs remain injected boundary observations. All nine independently read ELF/raw ledger pairs still gate publication, and the terminal ABI remains 29. Older modes retain their previous reconstruction rules.

The contract and image manifest list `changed_fields` for each paired call. This compares observed entry/return values; it does not establish whether the native helper performed stores, retried a sequence read, or took its conditional-update or leap-second branches. The native timekeeper's internal sequence, clocksource and leap state remain unobserved. The helper's [Linux v6.10 implementation](https://github.com/torvalds/linux/blob/v6.10/kernel/time/timekeeping.c#L2163) remains outside the original-code closure. Initial soft offsets remain synthetic omission guards; the inline updater's immediate return, native copy instructions, complete tick/scheduler behavior, synchronization memory, exact native source build attestation and cycle timing equivalence remain unsupported or unverified.

The accepted capture is `build/linux-irq-clock-entry-native-final-v1`, with images in `build/linux-irq-clock-entry-final-v1`: thirty-eight portable events from thirty-four native events and two physical timer IRQs. Its sequence and three hard-offset values are unchanged across both native helper calls. This is a value observation, not proof of absent stores. The independent fixture has thirty-eight native events, forty-four portable events and three IRQs, also with unchanged paired fields. Synthetic cases separately exercise sequence-only changes, mixed changes, unsigned 32-bit maximum sequence and signed 64-bit offset extremes. Validation and source/artifact hashes are in `build/linux-irq-clock-entry-validation-20261019.json`.

All forty-five Linux IRQ regression cases passed in 181.78 seconds, including 121 runtime mutants, sixteen external boundary-ledger corruptions and all ten capture modes. Eleven new runtime mutants cover entry reconstruction, entry-event values/counts, missing selected/contextual snapshots and omitted changed-output applications. Three synthetic transition cases cover sequence-only changes, mixed changes and signed/unsigned limits. All nine ELF/raw ledger pairs match, and standalone relocation verifies all eight boundary ledgers after construction-input removal. Two development captures with events outside the admitted syscall window were rejected and retained separately from accepted evidence.


## Original timekeeper-helper milestone

```sh
python3 tools/export_linux_irq.py \
  --capture build/linux-irq-clock-entry-native-final-v1 \
  --timekeeper-source --out build/linux-irq-timekeeper-source-image
```

The optional exporter flag `--timekeeper-source` executes the complete original `ktime_get_update_offsets_now` definition from [Linux v6.10 `kernel/time/timekeeping.c`](https://github.com/torvalds/linux/blob/v6.10/kernel/time/timekeeping.c#L2163), with internal comments omitted. `timekeeper-source-identity.json` pins the excerpt. A preprocessor alias keeps the original helper separate from the surrounding replay adapter. The source profile executes eleven original timer/timekeeping functions and eight scheduler helpers. Default exports retain their previous ten-function path and nine ledger pairs; this is an export profile, not another native capture mode.

Source replay requires `--clock-entry` observations and unchanged sequence/realtime/boottime/TAI fields across the selected helper call. Missing entry observations or changed selected fields reject before image publication. Other captured IRQ calls remain injected boundary observations; the original helper executes only on the selected expiry call.

The provider is explicitly modeled: its global clock sequence equals the observed entry sequence, its monotonic base is the captured expiry time, its nanosecond increment is zero, its next-leap deadline is `INT64_MAX`, and logical sequence reads take one pass with no retry. These choices are a bounded reconstruction consistent with the observed unchanged fields, not native global-state observations. Provider offsets are deliberately different synthetic guard values (11/22/33, or 12/23/34 when needed to keep them different from the entry fields), so an incorrectly taken update branch cannot silently pass. The source body reads provider state, adds the modeled nanosecond input, evaluates its conditional update/leap paths and completes its retry check. Clocksource conversion and actual Linux sequence/barrier machinery remain outside the original-code closure. Leap correction and retries reject in this standalone profile; isolated host tests exercise those branches separately.

A tenth independently read ledger, `osrec_linux_irq_timekeeper`, has four 80-byte records: sequence-read boundary, nanosecond-provider read, completed retry check and checked source return. Its ten 64-bit fields are kind, sequence-read count, nanosecond-read count, addition count, retry-check count, modeled provider sequence, output sequence, input-offset match mask, returned time and logical lock state. The first three returned-time slots are zero; the final slot contains the actual checked source return. An unchanged offset set has match mask 7. Both image formats' `target-timekeeper-{0,1}.bin` dumps must equal `expected-timekeeper.bin` before publication. Source-enabled standalone relocation verifies all nine boundary ledgers after construction inputs are removed. Terminal ABI 29 remains unchanged.

Eleven isolated host cases use the same pinned body to cover unchanged/updated sequence state, equal/past/future leap deadlines, retry with changed provider state, zero/nonzero nanoseconds, negative base time and 32-bit sequence wrap. Five host mutants test comparison, leap threshold, retry, return and offset-copy errors. Ten new standalone mutants test the selected source path and its provider/witness boundaries. Two additional external-corruption cases verify rejection of altered timekeeper dumps from both image formats. These tests establish reference-source behavior; they do not prove native provider values, stores, retry history or internal branch execution.

This milestone reuses `build/linux-irq-clock-entry-native-final-v1` without new native observations. The source-enabled images are in `build/linux-irq-timekeeper-source-final-v1` and match thirty-eight portable events, thirty-four native events and two physical timer IRQs. Validation and source/artifact hashes are in `build/linux-irq-timekeeper-source-validation-20261019.json`. Native provider state, initial soft fields, exact native source build attestation and cycle timing equivalence remain unverified.

All forty-nine Linux IRQ regression cases passed in 237.55 seconds, including 131 runtime mutants and eighteen external boundary-ledger corruptions. All ten native capture modes retain their default behavior; both default and source-enabled export profiles pass. Source-enabled images pass at entry addresses `0x40200000` and `0x40400000`, with all nine boundary ledgers independently verified after construction-input removal. The new source body also passes eleven isolated host cases and rejects five host mutants. The existing 300-second suite timeout and per-image observer limits are unchanged.


## Timekeeper layout discovery and provider-capture limit

```sh
python3 tools/capture_linux_irq.py \
  --kernel-image /Applications/Docker.app/Contents/Resources/linuxkit/kernel \
  --timekeeper-layout --out build/linux-irq-timekeeper-layout-native
```

`--timekeeper-layout` implies `--clock-entry` and adds native BTF layout discovery to the existing observations. It adds no probes, portable records or RAM ledger. `btf_timekeeper.h` validates the existing timer layouts, resolves unique `timekeeper` and `tk_read_base` types, follows bounded typedef/qualifier chains, and finds a unique anonymous two-member `{seq, timekeeper}` structure. It checks nested sequence-count members, scalar widths/signs, alignment, extent, bitfields, overlap and ambiguity. This is a structural layout candidate: this kernel's BTF does not provide a `tk_core` variable binding, and `symbol_type_binding_attested` remains false. It must not be interpreted as an attested association between that structure and a native address.

The guest reports its candidate through `OSREC_LINUX_IRQ_TIMEKEEPER_LAYOUT`; the capture stores `timekeeper-layout.json` and cross-checks it against the native log and manifest on load. Result flags, mode prerequisites, duplicate/missing layout markers, metadata types and unsafe offsets reject. `timekeeper_data_symbol_lookup_supported` reports whether the captured configuration enables `CONFIG_KALLSYMS_ALL`; a true value would describe configuration support, not establish that a particular data symbol resolves. Exported manifests retain the candidate and its limitations. Both export profiles continue to use the same provider models as before.

For LinuxKit 6.10.14, the candidate is type 3754, size 288, containing timekeeper type 3745, size 280. Candidate offsets relative to the enclosing structure are sequence count 0, clock-was-set sequence 180, monotonic base 48, realtime offset 152, boottime offset 160, TAI offset 168 and next leap 192. These numbers are discovered at capture time; the implementation does not hardcode them.

A development experiment attempted entry/return fetches using `@tk_core+offset`, the data-symbol memory syntax documented by [Linux kprobe tracing](https://www.kernel.org/doc/html/v6.10/trace/kprobetrace.html). The kernel rejected registration with `Invalid probed address or symbol`; the raw failure is retained in `build/linux-irq-timekeeper-boundary-native-dev-v1/qemu.log`. Its configuration has `CONFIG_KALLSYMS_ALL` disabled. No provider snapshot was captured, and the experimental probe is not part of the supported capture tool. The BTF scan and rejected registration do not justify guessing a native address or promoting the replay model to observed state.

The independent fixture has 29 native events, 31 portable events and one IRQ. Tests cover 28 BTF inputs, including a shifted valid enclosing layout, malformed records, typedef cycles, ambiguous candidates, field widths, bitfields, overlap and bounds. Protocol and manifest tests reject changed flags, unsupported bindings, unsafe metadata and configuration-capability mismatches. Both default and source-enabled exports verify all their ELF/raw RAM ledger pairs. The complete Linux IRQ regression results and accepted fresh-capture evidence are recorded in `build/linux-irq-timekeeper-layout-validation-20261020.json`.

The accepted fresh capture is `build/linux-irq-timekeeper-layout-native-final-v3`, with 30 native events, 32 portable events and one physical timer IRQ. Default and source-enabled images are in `build/linux-irq-timekeeper-layout-default-final-v1` and `build/linux-irq-timekeeper-layout-source-final-v1`. The two earlier final attempts were rejected for pre-syscall clock observations and events after syscall completion; their traces remain intact. An initial full-suite run reached its existing 300-second timeout while native capture was also running; its separate timeout log is retained.

Native provider values and symbol/type binding remain unobserved. The next provider-capture step needs a kernel exposing a resolvable data symbol and a defensible symbol/type association, or another independently validated observation mechanism. Layout discovery alone does not validate native sequence reads, clocksource conversion, leap/retry history, internal branches, exact source-build identity or cycle timing.

All 52 Linux IRQ regression tests passed in 215.75 seconds on the separate run, including 131 runtime mutants and eighteen external boundary-ledger corruptions. The 300-second suite timeout is unchanged. Across the existing and new readers, 95 BTF inputs pass their expected acceptance/rejection checks; 28 exercise the timekeeper layout candidate. All eleven capture modes and both export profiles pass their fixture checks.
