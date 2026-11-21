# OpenHarmony kernel capture and executable replay

The end goal is a self-contained executable that reproduces a captured OpenHarmony execution scenario. Its scope includes selected user/kernel code and the relevant scheduling, blocking, wakeup and interrupt interactions. The executable packages the code closure, entry state, ordered external inputs, replay runtime and validation checks. It runs on a declared platform without the original source checkout, a separate capture file, a running source kernel or the original device. Recording and analysis are construction stages for this executable.

The current checkpoint milestone is native execution of restored user code and captured kernel code/state in one self-contained **EL0-only** RTL/model executable for microarchitecture research. All delivered runtime, adapter, user and kernel instructions execute at EL0. Its architectural external effects are confined to its own RAM, apart from an optional terminal exit. Linux arm64 is the test kernel; OpenHarmony remains the broader target. Resume the post-boot checkpoint rather than rerunning Linux boot. UART writes become RAM output/checks, and timer observations come from embedded RAM inputs; delivery requires no physical UART, timer interrupts or other devices.

A full scenario milestone must also export a bounded execution that blocks and resumes with an interrupt-driven completion. Running the exported executable must re-execute the included code and reproduce the scenario contract, including required context relationships, return value and observable memory changes. Measure capture overhead on the source device separately from replay performance. Functional comparisons do not establish cycle fidelity: declare the measured interval, emulation/instrumentation overhead, and model cache/TLB initialization independently.

## RTL and cycle-accurate execution target

The intended delivery artifact is a self-contained image loaded into an RTL or
cycle-accurate processor model. Runtime execution must require no host
interaction. Before the measured interval, the harness provides the ELF's RAM
backing and CPU controls. For flat modeling, user and kernel code share an
address space, and the harness resolves execution addresses with guest
hardware translation disabled. **All delivered code executes at EL0**,
including checkpoint startup, user continuation, linked syscall handling,
architecture adapters and validation. The ELF startup restores the
checkpoint and resumes its saved user PC. Syscall sites transfer control to
linked code within the image at EL0. Captured kernel privilege is logical
state in RAM. Privileged operations and device effects are represented by EL0
software that operates on the image's RAM. The testbench observes completion
before any optional terminal exit.
Host capture, source extraction, compilation, KLEE and artifact inspection
remain construction/validation tools.

The image must embed its code, checkpoint, recorded inputs, reconstruction
runtime, dependency models and validation checks. Startup, stack, writable
memory and completion reporting must follow the selected target's reset and
memory-map contract. Completion can be exposed through a reserved target-memory
status record that the testbench observes. Image execution must require no
host OS, dynamic loader, host C runtime, filesystem, network, environment
variables, host clock, semihosting or host service calls. Any needed formatting,
memory or arithmetic helpers must be included in the image itself.

Checkpoints contain target-defined scalar values, logical object identities and
relocation information. Reconstruction resolves references into the image's
own target memory. Host pointers, live host descriptors, host file paths used
as runtime inputs, and other host capabilities must not become checkpoint
state. Model handles identify embedded replay objects rather than resources
opened on the host. Scalar widths, endianness, errno values and layout rules
must be bound to the target ABI; host capture adapters must normalize or
translate their observations before image construction.

Existing Linux executors are functional validation harnesses, including the
libc-free variant that still uses Linux syscalls and signals. Existing EL1
monitor and QEMU semihost/ABI images also remain development harnesses. The
earlier freestanding AArch64 prototypes implement four-call `SysRead` object-backed
sessions, the `SysUmask` stateful session, UID/GID/process-group identity queries,
scheduler-limit/PID scalar queries, parent/task queries, effective credential queries, and process-priority queries. The supplied ELF defines the entry point
and physical load segments; no fixed entry or result address is part of the RTL
contract. Those earlier prototypes load each PT_LOAD segment, zero its remaining
memory extent, and start at e_entry in privileged EL1 with interrupts masked
and the MMU disabled. Their startup installs a stack and exception vectors;
this historical entry contract does not satisfy the EL0-only delivery goal. The testbench
observes the 128-byte `osrec_result` symbol; ABI versions 1–7 define their
result layouts. Checkpoints and dependency data are embedded, and logical object
references reconstruct into target RAM. The captured LiteOS syscall scalars
remain 32-bit; reconstruction pointers follow the AArch64 ABI. These images
replay captured ARMv7 LiteOS behavior compiled for AArch64; they do not establish
an AArch64 OHOS kernel capture or reproduce the original instruction stream.

ELF/raw functional execution passes in QEMU with guest host services disabled.
RTL execution and timing validation remain pending. The QEMU validation machine
has RAM at 0x40000000–0x43ffffff and reserves its first MiB for a generated DTB;
this is a validation-backend restriction, not the RTL loading contract. Exporter
CLI defaults use entry 0x40200000 and result 0x40180000, with configurable addresses.
Acceptance audits unresolved symbols, relocations, dynamic dependencies and
external service instructions. ARMv7 remains available as a regression backend.

For microarchitectural measurement, start at ELF entry with the model's cache,
TLB and predictor initialization declared, and stop at the completion boundary.
Record the user, captured kernel and adaptation instruction counts for the
measured image, and check the target's exception-level trace across the
interval. The QEMU system validation collects an exception log for this
purpose. Timing equivalence with the original execution requires measurements
on the intended processor model and an assessment of the instruction and
address changes introduced by replay.

## Requirements derived from the executable

| Executable requirement | Framework obligation |
| --- | --- |
| Contains the scenario's executable code | Extract and link the selected user/kernel closure and included asynchronous handlers; resolve every dependency |
| Recreates its starting conditions | Capture and embed required object state, aliases, relocations, lifetimes and supported context state |
| Reproduces its external interactions | Embed device/environment inputs and adapters that verify sites, occurrences, arguments and relevant effects |
| Reproduces required execution relationships | Define the scenario's relevant control/context paths, wait/wakeup causes and interrupt ordering in the contract |
| Executes independently | Package every scenario-specific runtime/model dependency and any required architecture backend; declare the execution platform |
| Detects divergence | Embed expectations for declared behavior and validate recomputed execution, effects and transcript consumption |
| Has a supported, complete construction | Bind code/state/plan to a pinned build and reject missing records or unsupported assumptions |
| Costs little to capture | Use static/KLEE analysis to reduce required observations and implement bounded kernel hooks; measure on-device cost |

The key analysis question is which information must be recorded and embedded so that this executable can reproduce the scenario. A trace file, extracted source file or successful symbolic test is an intermediate artifact. The final acceptance test runs the exported executable without access to construction inputs or the source system.

## Initial scope and decisions

The user selected OHOS, a task/syscall replay scope, and the LiteOS-A repository for combined user/kernel KLEE analysis. The first extracted slice is pinned to revision `4ac7f3aed67000b47bc14d6fe79d63ada708d780`; its `SysRead` source and function hashes are checked before building. The target configuration, compiler and board remain unresolved. The host KLEE scenario abstracts architecture entry and dependencies; it is not a target kernel build. See [the implemented KLEE integration](klee-liteos.md).

A snippet is the self-contained executable defined above. Its replay backend must support the included code's ABI and architecture operations. Portable extracted code can use a linked host runtime for development validation. Delivery images execute entirely at EL0 with an embedded runtime on the declared RTL/cycle-accurate target; privileged semantics and device interactions must be adapted into ordinary instructions and RAM state. A matching kernel harness or emulator can also validate the reconstruction during development. Host replay timing must not be interpreted as kernel execution cost.

The implemented [scalar EL0 exporter](el0-export.md) now handles closed modular integer computation with initialized private stack state. It extracts a root slice, compares return bits against reference IR with KLEE, checks generated cases natively and packages one concrete checkpoint. The pinned LiteOS-A `LOS_Align` helper demonstrates this path with explicit AArch32 scalar widths. General pointer/global state and scheduler/interrupt replay remain outside this initial contract.

The separate [typed object-checkpoint prototype](object-checkpoints.md) captures an exclusively owned host graph and reconstructs fresh objects, aliases, cycles and interior buffer references before running a completion model. Its explicit schema is a state reconstruction baseline. It neither discovers live kernel objects nor proves field omissions with KLEE, and the generic EL0 exporter does not yet accept pointer interfaces.

The [syscall session checkpoint pipeline](syscall-checkpoints.md) applies typed reconstruction to sequential calls through actual pinned `SysRead` code with process/descriptor/buffer/VFS models. It preserves mutable state across calls and verifies complete ordered dependency transcripts plus per-call observations. A separate bounded two-call KLEE reconstruction check passes. The [live LiteOS-A QEMU integration](live-liteos-qemu.md) now boots the real kernel and records reads through its SVC/VFS/RAMFS path, comparing independent kernel/user observations with native replay. General state discovery, field/event minimization and scheduler/IRQ reproduction remain future stages.

The initial replay contract is functional reproduction of the selected task's execution and declared effects across recorded suspension and asynchronous interactions. Instruction-accurate replay and arbitrary concurrent kernel execution are separate milestones. A schedule trace alone does not specify all inter-core memory observations. Reducing capture scope is useful only when the resulting replay contract remains explicit.

## Task replay across scheduling and interrupts

Maintain a capture identity on the task across preemption, blocking, wakeup and CPU migration. Give every execution context a distinct identity: the selected task, included cooperating tasks, hard interrupts and deferred interrupt work. Nested interrupt contexts need parent IDs and depth. Begin and end the logical snippet at named boundaries such as syscall entry and exit, even if its records span several CPUs and many buffer segments.

The exported artifact must contain the runtime needed for its selected replay environment. A matching kernel image or controlled kernel harness provides a development reference; the delivery image must include its required code/state and execute directly on the declared RTL/cycle-accurate target without host service calls. Host execution of extracted components requires explicit ABI and dependency models. Capturing a task's full stack in the middle of an arbitrary instruction stream creates relocation and unwind problems; start at a supported entry boundary and reconstruct execution through included code instead.

Record a dependency transcript with the following event classes. These are planned kernel events; the current demo format does not contain them.

| Event class | Needed replay information |
| --- | --- |
| Task checkpoint | Arguments, relevant kernel objects, user buffers, task and per-CPU state, build identity |
| Context transitions | Task or interrupt identity, CPU, parent context, local sequence, suspension/resumption relation |
| Blocking and wakeup | Wait object and generation, result, waker/completion relation, boundary site and dynamic occurrence |
| IRQ and deferred work | Interrupt source, included handler code or modeled effects, device input, parent and completion relations |
| Shared observations | Site and occurrence, object/generation/offset, observed value, atomic operation and result where needed |
| External effects | Call/write arguments, relevant side effects, device transcript, allocation and lifetime changes |
| Task completion | Return value, user-visible writes, declared kernel state effects, completeness of all linked segments |

Use two explicit treatments for dependencies. Execute handlers and cooperating code that are included in the snippet closure; record their incoming device/environment observations. For dependencies outside the closure, replay modeled effects at validated boundaries and make the reduced scope visible in the manifest. A handler transcript containing only “IRQ entered” cannot replace its writes to a wait queue or completion object.

Do not inject an interrupt at an arbitrary nearby hook and claim exact reproduction. Bind asynchronous effects to validated execution boundaries or reproduce their observed effects through load and interaction transcripts. Exact instruction-position delivery needs architecture/emulator support. Replaying logical observations can preserve a selected task's functional behavior without reproducing physical timing, and the capsule must state that contract.

Synchronization edges can compress the causal log for proven race-free objects. For a lock-protected object, capture the necessary incoming state when ownership is established, preserving the observed acquisition order across included contexts. Lockless reads, competing writers, atomics and DMA require observed values or a stronger concurrency model. Merely logging the scheduler, pinning a CPU or serializing replay does not reproduce SMP races.

Build the first asynchronous example around an existing wait/completion path with clear object ownership. Verify syscall outputs and included handler effects, then add migration, nested interrupts and unsupported concurrency cases. Measure the additional context hooks independently from data capture.

## Capture and replay pipeline

1. Select task/syscall entry and completion boundaries and compute transitive code and state dependencies from the pinned build, including relevant asynchronous contexts. Classify calls, globals, pointer accesses, inline assembly and privileged operations. Reject unresolved dependencies or require an explicit adapter.
2. Emit a region manifest with stable site IDs, build identity, input object layouts, output ranges, allowed external interactions and unsupported effects. Derive IDs from the same optimized module used for instrumentation, with a mapping back to source locations.
3. Instrument the selected region and dependency boundaries. Capture entry state, ordered external observations and exit outputs into preallocated storage. The kernel adapter identifies capture, task, CPU and nesting context.
4. Drain completed captures outside the region. A missing event, overflow, unsupported interaction or inconsistent snapshot marks the entire capsule unusable.
5. Extract code and dependencies offline, construct object/alias restoration and external transcript adapters, and link a self-contained executable embedding the state, transcripts, runtime and expectations. Validate each adapter call's site, occurrence and arguments as well as its returned values.
6. Run the exported executable independently of source checkout, capture files and the source system. Verify the scenario's declared execution relationships and recomputed outputs/effects, and require complete consumption of the embedded transcript.

Ordinary control flow and loads from reconstructed private state are reproduced by execution. Optional path signatures help diagnose divergence; they are not sufficient inputs for replay and must not force execution down a recorded path that the restored state would not select.

## Static analyses that can reduce recording

KLEE provides an offline analysis and test-generation stage alongside static planning. Link selected user code, extracted kernel code and explicit environment adapters into one LLVM module. The implemented bounded `SysRead` analysis executes the same slice with a shared checkpoint and two independent symbolic environments: equal retained traces must imply equal declared outputs and effects. Counterexamples identify insufficient projections; completed checks support omissions within the model. The final plan also passes a decoder check that reruns the original code using only checkpoint and retained observations. See [trace analysis](trace-analysis.md). Solver limits, missing dependencies and unmodeled interleavings restrict every claim to the declared model and bounds. KLEE does not run on the recorder fast path. [KLEE function-testing tutorial](https://klee-se.org/tutorials/testing-function/)

The following are proposed optimizations. Each requires an explicit validity condition; uncertain analysis results must retain observations or reject the region.

| Analysis | Proposed reduction | Required condition |
| --- | --- | --- |
| Call graph and effect summaries | Instrument only the selected dependency closure | Include possible indirect targets and conservative effects for external calls |
| Alias analysis, MemorySSA and dominance | Skip a load capture when a reproduced store determines it | Prove the store executes first and no aliasing or external writer can intervene |
| Read before write and field sensitivity | Snapshot only incoming bytes needed by the region | Include every feasible path, partial write and overlapping alias |
| Escape and ownership analysis | Snapshot an exclusively owned object once | Ownership remains valid throughout the region, including interrupts and DMA |
| Loop and range analysis | Coalesce known input spans and hoist safe capture operations | Stable bounds, valid object lifetime and no change to volatile or atomic semantics |
| Observable output slicing | Avoid capturing internal intermediate values | Preserve code effects and all outputs in the declared replay contract |
| Constant propagation | Reconstruct immutable values from the pinned build | Values cannot change through initialization, configuration or an external writer |

LLVM MemorySSA supplies memory use/definition relationships and an alias-aware clobber walker, which makes it a useful building block. It is an intraprocedural compiler analysis, not a proof of system-wide ownership or concurrency safety; interprocedural effect summaries and target-specific contracts are still required. [LLVM MemorySSA documentation](https://llvm.org/docs/MemorySSA.html)

Place the analysis and instrumentation relative to a pinned optimization pipeline. If later passes clone, inline, reorder or eliminate probes, verify site mappings and semantics again. Mark hooks and the recorder's dependency closure as excluded from instrumentation. Treat instrumentation as an observable effect so the optimizer cannot silently remove it.

Do not promise minimum possible trace size. The practical objective is a smaller sufficient observation set with defensible omission rules and measured capture cost.

## State and external interaction contract

Capture scalar arguments and typed reachable objects using object IDs and byte offsets. Preserve interior pointers, aliases, cycles, alignment, lifetimes and pointer-bearing fields during reconstruction. Track allocation, deallocation and address reuse with generation IDs when those effects are supported. Capture an input buffer at its established stable boundary; copying memory after the function has modified it cannot recover entry state.

Native structure bytes can contain padding or architecture-specific representations. A production manifest must specify ABI, endianness, layout and pointer relocation rules, and compare only defined observable bytes. Unknown pointer provenance, pointer-to-integer assumptions and unbounded object traversal require a fallback or an explicit unsupported result.

External observations include clocks, randomness, MMIO, user memory, DMA changes, per-CPU state, hardware registers and interactions with other tasks. Replay adapters must model relevant writes and side effects as well as return values. A device read can itself have a side effect; never add a second read just to record it. Capture the value of the original access while preserving its width, ordering and barriers.

Do not execute real hardware effects during isolated replay. Represent expected writes and external calls as verified transcript operations. For unknown inline assembly or a call with unknown effects, expand the closure, supply a reviewed model, record the required effects or reject the region.

For mutable shared memory, an entry snapshot is insufficient. Either prove that existing synchronization makes it stable, record each relevant observed load with its dynamic occurrence, or move to a concurrency-aware replay design. Atomics, retries and ordering require separate handling. Added locks or disabled interrupts can alter the execution being captured and must not be presented as transparent recording.

## Kernel runtime and loss handling

The proposed kernel fast path uses preallocated per-CPU buffers, compact numeric site IDs and no heap allocation, formatting, disk I/O or global sequence increment per event. Use timestamps only where the contract needs them; retain local event order and add causal ordering where replay depends on it. Track a region invocation across CPU migration or explicitly constrain supported contexts.

Per-CPU storage does not by itself make logging safe: interrupt writers can nest. Prefer an existing kernel reservation and commit mechanism when available, with explicit task, interrupt and NMI policy. Linux's tracing buffer separates reservation from commitment and handles nested writers; a plain single-producer queue is not a substitute. [Linux ring buffer design](https://docs.kernel.org/trace/ring-buffer-design.html)

Use separate context storage or a tested nesting protocol. Never overwrite unread capsule events. Reserve bounded capacity where possible; otherwise make loss sticky, count rejected captures and export their failure reason outside the fast path. Report export completeness, not just successful buffer writes. Snapshot failures and unsupported effects must invalidate the invocation as reliably as overflow.

For a Linux adapter, evaluate tracepoints and ftrace for discovery, selection and enablement. Dynamic ftrace supports selective function tracing and removes disabled calls through code patching. This is useful infrastructure, but function entry/exit events alone cannot reconstruct memory inputs or external observations. Confirm actual support in the pinned OpenHarmony kernel. [Linux ftrace documentation](https://www.kernel.org/doc/html/latest/trace/ftrace.html)

The current runtime is a bounded linear buffer for one host-side capture. Its context tracker models task switches, IRQ nesting, blocking, wakeup and migration, with external serialization required for every call. It deliberately provides no claim of kernel, IRQ, SMP or concurrent-drain safety.

## Build identity and capsule validation

A production capsule should include format version, kernel source revision, configuration and toolchain hashes, target ABI, linked image build ID, region and site manifest hashes, capture context, object graph, external transcript, expected outputs and completion status. Hashing only a source function is inadequate when macros, headers or compilation options change.

Require the original build identity for faithful replay. Experiments with transformed code should identify both the original and candidate builds and state which equivalence checks apply. They must not silently pass the faithful-replay identity check.

Reject truncated captures, unsupported formats, unknown site IDs, invalid object references, transcript underflow or leftovers and output divergence. Replay with assertions enabled independently of compiler build mode. Functional output agreement is necessary evidence but cannot prove that an incomplete dependency model was sound.

## Evaluation and implementation sequence

Implement these stages in order:

1. **Host capture and replay proof:** implemented demonstrations cover a synchronous helper and a task continuation spanning modeled blocking, nested interrupts and migration. Exported C recomputes included effects and checks the captured transcript. The pinned LiteOS-A `SysRead` model additionally has KLEE trace sufficiency/reconstruction checks and a [standalone executable exporter](standalone-export.md) using their shared replay code.
2. **Task checkpoints and asynchronous replay:** the [single-CPU AArch64 reference](async-interrupt-replay.md) executes timer-driven completion with actual nested GIC exception delivery and checks the full task/IRQ transcript in QEMU. Its scheduler uses explicit continuations. The [live LiteOS-A wait](live-wait-replay.md) captures a blocking `SysNanoSleep` and exports host replay of original wait/timeout code. The [Linux IRQ workflow](linux-irq-replay.md) now captures a real Linux nanosleep's scheduler/timer/IRQ chain and executes ten original timer functions and eight scheduler helpers, with callback delivery through hardware interrupts in standalone ELF/raw images. The outer low-resolution runner, queue-dispatch and callback-run bodies, sleeper construction/start wrappers, timer enqueue/removal bookkeeping, task-state matching, runnable-state writes and activation/deactivation wrappers use original code; timer containers, lock/sequence boundaries, scheduling-class queues, accounting and CPU membership use a bounded model with independent RAM witnesses. Optional BTF-backed probes now directly capture selected task fields at dequeue, wake, activation and preemption boundaries, plus the sleeper link at sleep/callback entry and return. The optional timer-state mode directly observes timer state and the base running pointer at callback entry; the timer-return mode observes that the same base has a null running pointer by sleep return. Base-state capture also observes the index, CPU-base identity and selected active bit at both boundaries. A synthetic sentinel in a two-slot ordered container reconstructs nonempty residual occupancy without reproducing native background timer objects, counts or ordering. A sixth independent RAM ledger verifies modeled ordering and membership. A seventh verifies the original queue-dispatch body at masked, pre-deadline, captured-expiry and post-callback passes; clock inputs and base iteration remain bounded models. An eighth verifies the outer runner's mode checks, logical locking, injected clock update and softirq-deadline comparison; transitions and softirq delivery remain unsupported. Outer-state capture now directly observes the CPU base softirq deadline and activation flag at callback entry; its initial state and tick-mode decision remain modeled. The original clock-update body now propagates realtime, boottime and TAI offsets into their soft bases; a ninth independent RAM ledger verifies before/after fields using injected timekeeper outputs. Clock-state capture now observes the returned time, output sequence and realtime/boottime/TAI offsets on every captured timer IRQ. The selected IRQ outputs feed the original propagation body; other IRQ returns remain injected boundary observations. Older modes retain synthetic offsets, and all modes retain synthetic initial soft offsets. Clock-offsets capture also observes soft realtime/boottime/TAI fields and the sequence at callback entry, checking original propagation results and mapping the timekeeper destination pointers to the same CPU base through BTF. Clock-entry capture also pairs the native helper input sequence and hard offsets with each return, supplies the selected lower-call entry state and records changed fields. This compares observed values without reproducing or attesting the native conditional-update branch. The optional `--timekeeper-source` export profile executes the original timekeeper helper for unchanged selected entry/return fields, using modeled global sequence, clocksource input and retry/leap state. A tenth RAM ledger verifies that selected path; it does not attest the native provider state or native internal branch. Optional timekeeper layout discovery finds a unique anonymous BTF structure candidate and reports data-symbol configuration support, without observing provider values or attesting a symbol/type binding. Initial soft fields and native provider state remain unobserved. Native lock and sequence memory remain unobserved. Scheduling decisions and remaining IRQ/tick work are explicit models; remaining timer/object state is inferred, while the sleeper/callback timer/task relationship can be checked directly. Next, extend captured state and the original scheduling-class closure in separately validated steps.
3. **Compiler selection and manifests:** an optional LLVM 22 planner now emits direct-call closure, load/store sites, blockers and candidates for loads determined by complete stores to unescaped local memory. It applies no instrumentation or omissions. Extend it to task dependency closure and asynchronous entry roots and validate its assumptions against the target kernel.
4. **Analysis-driven capture reduction:** add one omission rule at a time. Compare original and reduced captures over branches, loops, aliasing, malformed inputs and intentionally unsupported effects.
5. **Kernel fast path:** integrate enablement, reservation, context tracking, overflow reporting and export. Test nested interrupts, migration and contention under the supported contract.
6. **Broader task execution:** extend object relocation, handler closure, migration, nested interrupts and shared-memory replay coverage in separately validated steps. Add instruction-accurate interrupt delivery only if required by the replay contract.

Measure uninstrumented, compiled-but-disabled, conservative capture and optimized capture configurations. Report throughput, CPU cycles per completed region, latency distribution, bytes per capture, buffer occupancy, export bandwidth, capture rejection rate and replay divergence rate. Use repeated paired runs and control workload, affinity, frequency policy and instrumentation build; also run end-to-end workloads to observe system effects.

A useful first target is a replay corpus with zero unexplained divergence and explicit rejection of unsupported executions. Set a numeric overhead budget only after measuring the target workloads. Trace traffic is invocation rate multiplied by bytes per invocation: even the 180-byte demo would produce 18 MB/s at 100,000 captures per second, before transport overhead. Use that arithmetic for capacity planning; it is not a measured performance result.

Discovery profiling or sampling may select which invocations to capture. Once an invocation is selected, capture every observation required by its contract; event sampling inside that invocation destroys completeness unless omitted values are reconstructible.

## Automated entry-state analysis

The general pipeline separates three responsibilities. Discovery derives typed
accesses and unresolved dependencies from configured source. Capture frontends
establish source identity, locking/lifetime contracts and native observations.
One request-driven exporter consumes their normalized plans, entries, effects
and call sequence together with a reviewed target model and invocation adapter.
It does not select a kernel-specific profile. The live argument frontend uses
the same image-building and verification backend, retaining its native witness
checks before export.

The exporter validates reconstruction before compilation, supports mixed roots
and extra C translation units, checks return values and state on both ELF/raw
execution, and publishes only after those checks pass. Published requests retain
all supplied inputs and can be rebuilt without the original input directory.
Input hashes establish what was used; native observation provenance remains the
capture frontend's responsibility. A check-only mode reports typed reconstruction
errors without building an image.

An optional typed dispatch declaration removes handwritten invocation routing.
The generator binds object arguments from validated providers and scalar arguments
from their captured slots, then calls the original root with a compile-time check
of its complete function signature. Unexpected routes and session exhaustion
fault explicitly, including when an all-bits return is legitimate. Capture imports
can propagate their site declarations into this path; native shared export can
regenerate original helper bodies from pinned source before generating dispatch.
This automates call glue while retaining explicit dependency implementations,
source provenance checks and state reconstruction contracts.

Further state-model generalization requires typed region/extent contracts for
buffers and heap state, allocator/lifetime transitions, and explicit
synchronization/external-event models. The shared frontends below cover selected
reviewed sites and configurable sequences; arbitrary site selection and external
dependency models remain explicit work. Longer bounded sessions now use ABI 30: a fixed control header and up to 256
route/result records, with exact linker/ELF bounds and complete target verification.
Canonical counted loops now supply proven index intervals for configured inline
arrays. The counter must be fresh, bounded by nonnegative literals and unchanged
within its body; storage extent remains a separate check. These intervals feed
the existing typed snapshot/reconstruction path. Must-store analysis remains
conservative at loop backedges, retaining incoming values for partial writes
under preservation contracts. This does not infer pointer-buffer extents or
prove termination/full overwrite.
Conjunctive conditions can combine a dynamic count with a literal capacity guard.
Every top-level `&&` term must succeed at body entry, and all condition/body terms
are checked for counter mutation or address escape. The tightest admitted literal
guard bounds body indices; other predicates retain ordinary memory-effect
tracking, including effects on a failed final condition. A guard inside an `||`
alternative cannot establish the bound. Direct dynamic condition subscripts
using that loop's counter receive no new proof, and loop backedges still provide
no overwrite guarantee.
Single-counter arithmetic can transform these intervals through 32-bit addition,
subtraction, unary signs and multiplication by a proven constant. An affine
representation retains correlation between repeated reads of the same immutable
counter. Every intermediate operation and implicit conversion must fit its actual
signed/unsigned type without wrapping; explicit casts, unrelated variables and
nonlinear products receive no new proof. Array extent and expansion limits are
checked on the resulting enclosing interval, including gaps in a stride. This
feeds the existing field codec and preservation contracts, without introducing
loop-store guarantees or pointer extents.
Bound resolution also accepts enum constants built from nonwrapping 32-bit
literal/enum arithmetic and structural inline-array `sizeof` count ratios.
Enum declarations are matched by identity, including local/shadowed names.
Array-count proofs require the same integer array member in numerator and
first-element denominator; they infer its configured element count rather than
host byte sizes. Capture and reconstruction emit extent assertions for these
proofs, checking actual array type and length, so a different extent or a pointer
with a coincident byte-size ratio fails compilation. General constant
folding, pointer-size ratios and target-dependent enum initializers remain
outside this subset.
Portable enum evaluation additionally supports division/remainder with C99
truncation toward zero, checked shifts and nonnegative bitwise operands.
Unsigned complement uses exactly 32 bits. Zero divisors, signed `INT_MIN/-1`
or `% -1`, negative/oversized shift counts, negative shift operands and wrapping
left shifts are rejected. Signed negative bitwise expressions remain outside the
portable subset. The same checked evaluator also admits direct constant
expressions in counted-loop initializers and capacity guards, including macros
and resolved enum references. Each expression has a 64-node AST budget, and
every intermediate and implicit conversion must preserve its value within the
actual 32-bit type. Runtime arguments, const variables, calls, side effects,
conditional/comma expressions and explicit casts remain outside this proof.
Bare literal, enum and structural array-count proof shapes remain unchanged;
array-count ratios use their separate extent checks. Runtime affine index
operators retain their existing scope.
Capacity comparisons normalize `i <= bound`, `bound > i` and `bound >= i`
alongside the existing `i < bound` form. Inclusive bounds add one only when the
exclusive limit remains at most `INT32_MAX`, keeping the final counter increment
representable. New `comparison_guards` metadata records the source operator,
counter operand, bound value and exclusive limit. Existing less-than proofs keep
their shape, including structural array-count assertions. This still requires
a fresh ascending counter and an independently bounded storage extent.
Capture capacity remains caller configured, with a seven-call default. Broader
state models still require independent correctness and overhead measurements;
additional local omission proofs do not establish whole-kernel completeness.

Whole-kernel discovery starts with a build-artifact coverage baseline rather
than a selected root list. Existing objects and dependency files establish an
explicit denominator; active module queries recover configured C commands,
including external libraries. Isolated workers survey primary-source function
bodies using same-TU call closure, retaining failed units and root timeouts.
Cross-file definitions are indexed for prioritization but do not silently
resolve calls or supply boundary contracts. Linked symbol names are a separate,
inexact correspondence. Coverage accounting, capture-schema eligibility and
runtime validation remain distinct claims.
Survey-guided call closure now loads unique external C definitions on demand,
verifies source identities and reruns the configured-AST analysis after each
merge. TU-local names and declaration IDs remain isolated. Expansion has explicit
unit/context/time budgets and retains ambiguities, ABI/type conflicts, missing
bodies and resource failures. This extends body availability rather than adding
boundary models; whole-kernel effects and replay eligibility remain separate.
Automatic merges now restrict function declarations to the root's syntactic
reference closure, including callback addresses and referenced global
initializers. All declarations for a retained function still participate in
signature/body checks; all top-level records remain checked. This removes
unrelated function conflicts without claiming a whole-program target or type
slice. Survey-based batch selection interleaves eligible active sources and
retains caller-specified root/unit/context/time limits.
Deterministic root offsets allow disjoint continuation batches. Coverage
aggregation checks input identities, requested/result sets, result hashes and
matching analysis limits, while keeping failed and unrequested roots separate.
It accounts for recorded results and does not promote them to runtime or cache
proofs. Source fingerprints on new scans and missing provenance on older scans
remain visible per batch.
An additional, disjoint cohort selects other blocked roots with at least one
uniquely indexed external C body. Available bodies can expand state discovery
while unrelated blockers and unavailable/ambiguous calls remain explicit.
Requests preserve that baseline evidence, and aggregation requires the matching
cohort denominator. This extends entry-root coverage beyond initially
missing-body-only roots without adding boundary models or weakening checks.
Fixed one-dimensional global arrays now retain their configured storage bound
through a direct array decay, using the existing index proofs and expansion
limits. Discovery records global element reads and writes while preserving
static TU identity and volatile blockers. Pointer aliases, casts, unknown
extents and multidimensional global arrays remain outside this rule. Global
capture/reconstruction bindings are still required before replay acceptance.
Array indexes can also use the existing portable constant-expression evaluator
for enums and arithmetic, including constant unsigned mask/remainder operands.
New index proofs retain intermediate overflow checks and an expression budget;
runtime operand effects and the array's configured storage bound remain checked
separately. This does not infer pointer extents or omit call effects.
Fixed automatic arrays keep a local identity, so proven private element
accesses do not become entry-state fields. Array initializers and index
expressions still contribute effects, including Clang's separate `array_filler`
entries. Function-reference slicing uses the same traversal. Persistent local
arrays, cleanup-managed storage, volatile/atomic accesses and unresolved pointer
provenance remain blocked. Multidimensional types cannot supply a scalar array
bound from their final dimension.

Shared call-site capture now implements part of that frontend boundary.
`entry_capture.py` generates wrappers from selected typed plans and an explicit
site/contract specification. Wrappers capture entry and exit around one original
call, recording scalar arguments and its result. Caller-owned sessions provide
capture-scoped object identities; a callback serializer emits normalized records
without address bytes or host-I/O dependencies. The importer checks the embedded
plan/spec hashes, validates reconstruction and publishes a generic replay request.
It removes per-root JSON collectors for the supported subset without claiming
automatic source rewriting, native binary attestation or dependency-model inference.

Record overflow, reentrancy and snapshot/identity failure invalidate the complete
session. They do not suppress the original call. Incomplete/failed sessions emit
no JSON; transport failure reports failure to the caller. The caller must provide
synchronization and fixed lifetimes, and place the large bounded session in
preallocated storage. Allocation/address reuse and interleaved concurrent owners
remain outside this capture contract. Native fixtures verify mixed roots,
argument objects, void/signed returns and null roots through generic target replay.

The first live integration replaces the direct signal-helper invocation in the
existing controlled PID 1 batch with its generated shared wrapper. Independent
legacy entry/post hooks and direct before/after/restoration witnesses remain
around the same six original calls. The real scheduler lock spans the batch;
the process exit code is restored once before unlock. Shared serialization runs
later from copied snapshots into a bounded buffer. The bridge checks equality
with both observation paths, exact plan/spec binding, native image/log hashes,
pinned helper source, wrapper text and imported replay inputs before export.
Its verification sidecar binds the generic image manifest to this evidence.
The mixed-root option inserts the original signal query after the third write.
Both discovered roots use the same session and process identity; continuous
reconstruction checks all seven entries and exits after one initialization.
The query has a scalar result, with a separate native before/result/after witness;
the six writer calls retain their legacy comparisons. Readonly wrappers reuse
the generated entry hook for their post-state snapshot. This profile fits the
seven-call legacy result layout.

Configured live sessions now accept one through 256 calls to the two reviewed
signal helpers. The sequence determines native scheduling and capture capacity;
replay dispatch is generated from the same validated sites. A direct per-call
RAM/result witness checks every captured entry and post-state. The existing
six-call legacy baseline is separate and remains independently validated.
One scheduler-lock region spans the configured batch, followed by restoration
before unlock. This adds composition and longer live sessions within those
contracts while retaining explicit source, lifetime and synchronization checks.
This generalizes the capture mechanism at a controlled live call site, not
arbitrary site selection, whole-kernel state or scheduler reproduction.

Configured Clang AST analysis now derives conservative field-read/write paths
and direct call closures, using explicit replay boundary policies. It generates
construction-time snapshot hooks for supported object-provider paths and
normalizes their pointers into logical object graphs. The live LiteOS path
checks fourteen generated snapshots against its independent capture adapters.
This removes hand-maintained field lists for the supported roots, while retaining
explicit model/lifetime contracts and blockers for unknown effects. It does not
claim a minimal or complete whole-kernel checkpoint. See
[entry-state analysis](entry-state-analysis.md) for usage and current limits.

Configured entry-state analysis now combines translation units and follows
finite local function-pointer target sets. Static/inline symbols and Clang AST
IDs retain translation-unit identity. A bounded pointer may-alias fixed point
covers loop-carried assignments; nonconverging traversals fail explicitly.
This broadens closure discovery without proving minimality, general pointer
ranges, concurrency semantics or automatic dependency-model selection.

Explicit entry-argument contracts now extend this discovery/capture path to
pointer arguments of configured syscall/helper roots. Discovered fields and
bounded inline arrays use the same normalized object IDs, preserving aliases,
cycles and null roots across argument bindings. Host and standalone AArch64
fixture replay verify reconstruction and scalar writes. A bounded live adapter
now captures six original process-helper invocations on the real current
process under the scheduler lock, then exports standalone AArch64 ELF/raw
images using the discovered argument footprint. Natural kernel call-site
selection, broader argument objects and arbitrary pointer ranges remain
separate work.

The optional full-store omission pass also accepts direct scalar argument
fields under explicit stable-identity, exclusive-state and state-preservation
contracts. Snapshot safety alone grants no omissions. Branch coverage and
interference barriers use the existing conservative proof; nested paths and
helper contexts retain their reads. A native fixture reduces nonnull object
scalar payload from eight bytes to four, while standalone AArch64 replay still
requires the original body to produce the omitted field. This is independent
fixture replay; live policies keep their conservative footprints, and continuous
replay still rejects incomplete entry footprints.

The additional `--preserve-write-state` option requires the omission pass and
retains eligible may-written scalar inputs without an every-exit full-store
proof. Plans record these separately in `preserved_entry_fields`, so they are
not confused with source reads. Capture and reconstruction validate each
projection against a discovered write and all four explicit contract promises:
snapshot safety, stable identity, exclusive state and state-preserving binding.
Independent replay restores these values from entry snapshots and still checks
captured post-state. Early exits and unsupported control flow conservatively
retain values. The skipped-write fixture needs eight scalar bytes per nonnull
entry, including the preserved value; this mode does not claim a reduction for
that fixture or enable stronger live policies.

Preservation also accepts nested scalar paths when every traversal edge is a
captured object pointer read. Source-visible writes to those edges prevent the
projection; reconstruction resolves the path against entry object IDs and
rejects writable edges reached through aliases. The omission proof itself
still covers only direct fields. Native graph fixtures test null edges,
aliases and cycles, while standalone AArch64 images test independent replay
and continuous replay with a complete entry footprint. Continuous replay
keeps its existing identity, lifetime and field-completeness requirements.

For preservation coverage, a narrow argument-null proof now excludes an
immediate pure return under `if (!argument)` or the null `else` arm of
`if (argument)`. The argument must remain its original entry binding: any
assignment to it or taking its address disables this proof. Exclusion applies
only to fields rooted at that argument. Other returns and skipped writes still
need full store coverage. Reports retain guard/return source locations and
excluded-exit counts. Default discovery and read-omission policies are unchanged.

The same pass now follows the C comma operator's operand order when evaluating
that expression directly, including parenthesized/cast forms. It retains reads
inside enclosing unsequenced expressions and never credits a right-hand store
to an assignment-target read that may execute earlier. Effectful target
evaluation clears facts before either operand's reads are observed. Native
comma-expression fixtures and AArch64 ELF/raw images verify the omitted field
is produced by replay; correct returns alone cannot satisfy post-state checks.

Conditional and short-circuit expressions now use separate possible-path states.
Each evaluated branch can use guaranteed preceding stores, while continuation
facts are intersected across both conditional arms or evaluated/skipped logical
operands. Condition reads and assignment-target reads retain their own entry
dependencies. A native fixture recomputes both branch selection and writes in
standalone replay. A separate regression rejects post-state mismatches when a
conditionally skipped write preserves an uncaptured incoming value; read
omission alone does not establish complete writable-state reconstruction.

Const-qualified entry pointers and pointer edges now retain readonly C views
while sharing normalized object identity with mutable views. Replay owns mutable
backing storage; declared const-member storage and writes rooted in const views
are rejected. A second live helper profile captures the original process-group
leader query's 16-bit status field under the real scheduler lock and exports
standalone AArch64 images with independent native value/return checks.

A controlled mutable-argument profile now captures the original signal-set
helper's scalar read/write footprint on the live current process. Entry and
post-state hooks are generated from configured source, and the capture adapter
restores the live field before scheduler unlock. Standalone replay invokes the
original helper with captured scalar arguments and validates its writes against
post-state snapshots. Each invocation restores independently; persistent state
continuity and natural kernel call-site selection remain outside this profile.
The separate continuous-session profile captures six calls in one locked
batch and restores the native field only after the final post-state. Standalone
replay initializes one session object once and checks each entry against the
previous post-state. This establishes bounded scalar-state continuity, without
reproducing scheduling or concurrent kernel observers.

Generated scalar-effect reconstruction now also resolves nested destinations
through captured entry pointer edges. Write permissions apply to the reached
logical object, preserving aliases and cycles; intermediate edges must be
outside the write footprint, including writes through aliasing providers.
Native fixture capture and independent/continuous host replay cover chains and
null paths. Standalone AArch64 ELF/raw replay detects wrong-object and missing
writes at two load addresses. A live two-process profile now analyzes an
explicit capture adapter that follows the workload child's real parent edge
and calls the original signal-set helper on PID 1. Generated hooks capture the
edge and nested scalar write; one locked batch retains updates across six calls
and restores the parent's native field once before unlock. The adapter is
identified separately from the pinned original helper, and native child/parent
IDs must agree with the independent task observations. Natural call-site
selection and nested pointer rebinding remain separate work.
