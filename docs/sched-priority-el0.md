# A syscall with a complete EL0 computation

`SysSchedGetPriorityMax(int policy)` is implemented in the pinned LiteOS-A
`syscall/process_syscall.c`. Its complete body is:

```c
int SysSchedGetPriorityMax(int policy)
{
    if (policy != LOS_SCHED_RR) {
        return -EINVAL;
    }
    return OS_USER_PROCESS_PRIORITY_LOWEST;
}
```

The reviewed configuration defines `LOS_SCHED_RR` as unsigned `2`, the
lowest user-process priority as `31`, and ARM/Linux-compatible `EINVAL` as
`22`. This syscall queries a limit; it does not change scheduling state.
The source lock binds the revision, source body and scheduler constant
headers. The generated source retains the kernel license and exact function
body, using explicit constant definitions instead of unrelated kernel headers.

The entire computation can run in an ordinary user process. Its only input
is a 32-bit policy argument. There are no callees, pointers, globals,
allocation, locks, external inputs, MMIO, system-register operations or
replay boundaries. The analyzer reports no blockers, state requirements or
model boundaries. The checkpoint is just the argument and expected raw
return: policy `2` returns `31`; every other policy returns `-22`.
No nondeterministic events need recording for this function.

```sh
python3 tools/prepare_priority_el0.py \
  --kernel-root build/kernel_liteos_a \
  --llvm-bin /opt/homebrew/opt/llvm@16/bin \
  --out build/el0/sched-priority-new
python3 tools/export_el0.py build/el0/sched-priority-new/sched_priority.bc \
  --root SysSchedGetPriorityMax --arguments '[2]' \
  --source-identity build/el0/sched-priority-new/source-identity.json \
  --llvm-bin /opt/homebrew/opt/llvm@16/bin \
  --plugin build/el0-llvm16/osrec_el0.so \
  --out build/scenarios/sched_priority_max_new
build/scenarios/sched_priority_max_new
```

The completed artifact `build/scenarios/sched_priority_max` prints
`scenario verified: return=31` and exits with status zero. The exporter also
ran a copied executable alone in an isolated directory. Construction
sidecars are unnecessary at runtime; `--describe` exposes the checkpoint,
source identity and proof metadata.

KLEE compared the reference and extracted LLVM implementations over all
32-bit argument patterns, without assumptions or path pruning. It completed
one path with zero partial paths, and its generated test passed native
differential replay. Optimization expresses the conditional as a select,
so one symbolic path still covers every input. Extraction retained all three
computational IR instructions and removed one debug instruction. This is
a small complete EL0 example, with no substantial slicing reduction.

This is a source-recompiled native macOS ARM64 executable with a synthetic
checkpoint, not a new live-kernel capture or an ARM32 kernel machine-code
replay. The kernel's SVC dispatcher is outside the computation: the extracted
function is called normally at EL0. The proof concerns the prepared reference
and extraction, not arbitrary kernel execution, compiler correctness or
concurrency. Startup and output still use the host system runtime.

## Live LiteOS-A capture

The [live kernel demo](live-liteos-qemu.md) now includes this syscall. PID 1
calls the existing SVC dispatcher with policies `2`, `1` and `-1`; it observes
raw results `31`, `-22` and `-22`. The kernel report driver safely copies
the user observations and exports them over UART. The live source file and
constant headers are checked against the same reviewed lock as the replay.

`build/live-liteos-priority-final/priority-replay` executes the complete
function for all three captured arguments and checks each captured raw result.
It prints `priority session verified: 3 calls` and exits with status zero.
`priority-replay.manifest.json` binds the original kernel image, observation
bytes, source identity and replay executable. Its construction sidecars are
unnecessary at runtime. This artifact uses live observations; the earlier
single-checkpoint scalar artifact above remains synthetic.

The exact prepared bitcode used for this capture was also passed through the
scalar exporter. KLEE completed one path with no partial paths over all
32-bit policy inputs. `priority-verification.json` binds that proof to the
live replay's source identity and records the successful live regression.
The proof establishes reference/extraction equivalence; the live replay
separately checks the three captured kernel returns.

## Minimum priority and process-ID extension

`SysSchedGetPriorityMin` has the same policy check and returns the pinned
`OS_USER_PROCESS_PRIORITY_HIGHEST=10`. Its separate source lock binds the
exact original body and the same scheduler headers. Select it with
`prepare_priority_el0.py --function SysSchedGetPriorityMin`; the existing
maximum-priority invocation remains supported.

The extended live workload captures minimum-priority policies `2`, `1`, `-1`
and checks returns `[10,-22,-22]` in `priority-min-replay`. The completed
artifacts are under `build/live-liteos-more-syscalls`:

```sh
python3 tools/export_el0.py \
  build/live-liteos-more-syscalls/priority-min.sources/sched_priority.bc \
  --root SysSchedGetPriorityMin --arguments '[2]' \
  --source-identity build/live-liteos-more-syscalls/priority-min.sources/source-identity.json \
  --llvm-bin /opt/homebrew/opt/llvm@16/bin \
  --plugin build/el0-llvm16/osrec_el0.so \
  --out build/live-liteos-more-syscalls/priority-min-verified
```

The prepared module from the live capture passed KLEE comparison over every
32-bit policy pattern: one completed path, zero partial paths and one native
replayed test. `priority-min-verification.json` binds this proof to the live
source identity and replay artifact. Changed and empty RAMFS input boots
also pass the read, maximum/minimum priority and PID replay regressions.
Malformed PID/mode observations and an incorrect minimum-priority return
are rejected before a replay binary is published.

`SysGetPID` is also captured through SVC. Its original body calls
`LOS_GetCurrProcessID`; native replay supplies the captured owner ID through
that explicit model. This PID artifact has no symbolic extraction proof.
