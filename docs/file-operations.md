# Shared-state file-operation replay

The file profile captures a 32-call session in real ARMv7 LiteOS-A under QEMU,
then rebuilds nine original syscall bodies for a self-contained AArch64 image:
`SysOpen`, `SysOpenat`, `SysWrite`, `SysRead`, `SysLseek64`, `SysFstat64`,
`SysStat`, `SysDup2`, and `SysClose`. The original `GetPath` helper and
`CHECK_ASPACE` macro are preserved. Reviewed dependency models execute the
bounded effects; VFS, allocator, VM and locking internals are not reconstructed.
The separate `--dup` profile still covers `SysDup`, including allocation failure.

```sh
python3 tools/liteos_qemu_demo.py --file-operations --out build/live-files
python3 tools/export_freestanding_files.py --capture build/live-files \
  --out build/aarch64-files --entry-address 0x40400000 --result-address 0x40380000
python3 tools/rtl_load_bundle.py prepare --image build/aarch64-files/files.elf \
  --ram 0x40000000:0x4000000 --out build/files-load-bundle
python3 tools/verify_qemu_bundle.py build/files-load-bundle --out build/files-verification
```

Choose new output directories. ELF entry and segments supply the loading layout;
raw loading uses the corresponding ELF descriptor. Replay uses embedded state
and payloads, without runtime host filesystem interaction or semihosting.
All verification uses QEMU TCG. RTL and cycle timing are customer responsibilities.

## Session

| Phase | Native operations and verified effects |
| --- | --- |
| Create | Open `/dev/shm/osrec-file.bin` read/write with create, truncate and close-on-exec; self-`dup2` preserves it |
| Write and reopen | Write `abcd`; `openat(AT_FDCWD, ...)` creates a second file description with its own position |
| Replace | `dup2(4,5)` closes the second description, references the first, replaces the mapping and clears close-on-exec |
| Shared I/O | Seek through descriptor 5, write `XY`, seek/read through descriptor 4 and obtain `abXY` |
| Metadata | `fstat64` and `stat` copy the pinned native ABI bytes and preserve caller guards |
| Close | Close descriptor 4; descriptor 5 still reports shared position 4; close descriptor 5 releases the last reference |
| Errors | Missing paths, invalid descriptors, null/invalid buffers, invalid path copying, failed metadata copy and zero-length I/O |

Capture records all 192 caller-buffer bytes, raw returns and errno, plus before
and after state for every syscall and each of 94 dependency events. State includes
mapping/allocation/close-on-exec for process slots 4–6, and native reference counts
and 64-bit positions for two file descriptions. Pointers are normalized to
reviewed identities; no live kernel or host pointers enter the checkpoint.
Provider tracing is suppressed inside forwarded providers to keep each modeled
boundary explicit. Entry errno is deliberately initialized to zero for each call.
Selected error paths arise from actual native arguments; this profile injects no
provider errors.

OHOS's pinned `struct stat` is 152 bytes, with an eight-byte file size at offset 48.
These roots copy a 104-byte legacy `struct kstat` prefix. Replay preserves those
native bytes rather than substituting a host or generic AArch64 stat layout.
The file size and copied prefix are checked against independently computed file
content and provider payloads. Other metadata fields remain recorded boundary
outputs rather than synthesized filesystem semantics.

The exporter validates source revision/body/header/provider hashes, capture
hashes, configuration and kernel-image hash when present. The host decoder
checks event order, arguments, errno, descriptor effects, file content, buffer
guards, path allocation and VM-lock balance. Target code recomputes shared-state
I/O and descriptor effects and compares them against embedded observations.
ABI 17 publishes a 128-byte result record; acceptance requires 32 completed calls,
94 consumed events, 32 verified buffers/states, expected return checksum,
`abXY`, seven copy attempts/240 copied bytes and no outstanding references,
paths, descriptor slots or VM locks.

## Verification and bounds

Retained native capture: `build/live-file-operations-native-verified`.
Retained AArch64 ELF/raw image: `build/rtl-aarch64-file-operations-verified`.
Retained ELF/raw × EL1/EL3 bank verification:
`build/file-operations-practical-qemu-verified/verification-matrix.json`.
All four executions reproduce the same result bytes and verify physical memory
banks and CPU entry state. Automated tests also cover a relocated layout,
corrupt captures and deliberately broken reference counts, mappings, file
positions, writes, path release, VM unlocking and user copies. A checked-in
native fixture supports repeatable decoder and replay regression; the live test
recaptures from QEMU rather than trusting that fixture.

This is a complete bounded create/write/reopen/replace/seek/read/stat/close
workflow, not all filesystem syscalls. Its domain is one RAM-file path and one
missing path, two file descriptions, three process slots, an eight-byte file
extent and 192-byte caller witnesses. Directory operations, rename/unlink,
truncate/fsync, permissions, arbitrary paths/sizes/flags, socket/device I/O,
concurrent access and additional provider failures need separate profiles and
models. Native file-mode handling is enabled; PID-container and proc-directory
branches are disabled in this captured configuration.

## Callable slices for application checkpoints

The file profile also exports a returning syscall-slice library. An application
replay container restores its user checkpoint and one corresponding kernel
session, routes each recorded syscall invocation through `osrec_slice_execute`,
applies the returned raw syscall value to the application frame and resumes its
continuation. The session retains descriptor mappings, references, positions and
file contents across calls. Captured before/after states are checks; the runtime
initializes kernel state at session creation or explicit checkpoint restore.

```sh
python3 tools/export_syscall_slices.py \
  --port integrations/liteos_a/files-slice-port.json \
  --capture build/live-file-operations-native-verified \
  --out build/callable-file-slices
```

Publication contains `slices.a`, `slices.elf`, `slices.bin`, reconstruction data,
source snapshots, `context-plan.json`, `slice_layout.h` and a provenance manifest.
The archive contains the slice/runtime objects, excluding the proof driver,
startup and terminal result record. The proof ELF is linked against that same
archive. An application container can link the archive and include
`osrec/syscall_slice.h` plus generated `slice_layout.h`, without including kernel
model types. Compile the slice/runtime with the declared AArch64 general-register
contract. The saved-frame adapter below is included when the port declares an
application register ABI. The CPU gateway below supplies baseline hardware
register restore, private slice stacks and EL0 entry; the application container
supplies checkpoint import and an executable routing plan.

```c
_Alignas(OSREC_SLICE_STATE_ALIGNMENT)
static unsigned char kernel_state[OSREC_SLICE_STATE_BYTES];
static struct osrec_slice_session session;

/* At checkpoint restore: allocate/rebind reconstructed kernel objects once. */
osrec_slice_session_init(&session, &osrec_kernel_adapter,
                        kernel_state, sizeof(kernel_state));

/* At each syscall site: arguments and regions come from the resumed app. */
struct osrec_slice_result result;
osrec_slice_execute(&session, &invocation, &result);
/* On OSREC_SLICE_OK, result.raw is the computed syscall return, including errors. */
```

`invocation` contains a capture ordinal, syscall number, six 64-bit argument
slots and a user-memory view. Each memory region binds a logical object ID and
application virtual address to bytes in target RAM, with read/write permissions.
The memory resolver preserves offsets within each region and rejects overflow,
overlapping regions and duplicate object IDs. Aliased application pointers should
resolve through the same underlying region. The OHOS adapter binds its captured
witness as object 1 and checks input bytes before executing the original root;
it does not seed application memory from expected outputs. Provider writes affect
that mapped application memory directly. Application-side stores between calls
are executed by the application; the proof driver simulates those stores.

The generic execution API distinguishes three cases:

- A syscall succeeds or returns a kernel error: `OSREC_SLICE_OK` and the computed
  raw result; the session advances to its next recorded invocation.
- Arguments, ordinal or mappings differ: `OSREC_SLICE_BAD_INPUT`; no kernel
  execution or persistent state update occurs and the same ordinal can be retried.
- Executed state/effects diverge: `OSREC_SLICE_DIVERGED` with a diagnostic, returning
  through an embedded AArch64 recovery frame. The session is poisoned until
  explicit checkpoint restore. Partial effects are not rolled back automatically.

Same-session recursive entry reports busy. Separate sessions can be entered in
an interleaved sequence with independent state. Concurrent or interrupt-driven
execution has no validated contract yet; the active flag is not an SMP lock.
A restore resets kernel state and transcript progress together. The container
must restore the matching application checkpoint as well.

### Automated construction and kernel ports

`contextify_slice.py` uses Clang AST declaration identities to discover mutable
file-scope state in the prepared code/model closure, generate a context structure,
rebind initializer aliases and thread an explicit context parameter through every
state-dependent direct call. It handles calls in macro definitions, keeps pure
function parameter shapes, and namespaces owned functions as `osrec_kernel_*`.
It does not use a global current-session pointer. The current OHOS closure has
28 owned state objects and 48 context-taking functions. The generated plan records
state types, function signatures, call dependencies, symbol mapping and input
hashes. The target compiler also computes storage size/alignment automatically.

The shared builder consumes a kernel-port descriptor containing the kernel ABI,
argument width, syscall numbers, root symbols and argument kinds. It validates
root coverage and signatures, generates dispatch, compiles the archive/proof image,
audits the image and executes ELF/raw proof images on QEMU before publication.
Manifest identities bind capture, kernel source, port, construction tools,
generated sources, archive and images.

A second AArch64 kernel port supplies the following inputs, through a repository
module or a pinned [external port bundle](external-kernel-ports.md):

1. A descriptor with that kernel's syscall numbering and scalar-width contract.
2. A construction module exposing `prepare(args, sources)`: verify the pinned
   kernel/config/capture identity; prepare original root/helper source, ABI shim,
   reviewed provider models and embedded capture data.
3. An adapter implementing restore, argument/memory binding, returning entry and
   final state verification through the shared `osrec_slice_adapter` contract.
4. A QEMU proof driver and capture-specific expected observations. The shared
   session/memory runtime, AST context transformation, AArch64 recovery frame,
   archive construction and ELF/bank verification can be reused.

The preparation result declares owned sources/headers, adapter/data sources,
required syscall numbers, checkpoint/provenance and expected proof results.
Dependencies outside the selected closure need explicit execution/input/effect
contracts. The existing typed entry-state analysis can prepare object snapshots
for supported dependencies. This context transformation operates on the prepared
closure; it does not synthesize arbitrary kernel dependency models or recover
missing kernel state from user registers alone.

Indirect calls, escaping context-function addresses,
TLS/volatile mutable state, ambiguous public definitions and unsupported declarators or
mutable external state outside the supplied closure reject construction.
[Initialized mutable scalars, structures, pointers and arrays](initialized-context-state.md) and supported
[function-local statics](local-static-context-state.md) are reconstructed in each
context. [Private file-scope objects](private-context-state.md) can share their
names across source files and retain distinct storage. [Private functions](private-context-functions.md)
can also share names while retaining separate call dependencies. Additional configurations and opaque architecture effects require a
reviewed adapter or additional transformation support. Kernel ABI types and
provider semantics remain port-specific.

### Callable-slice verification

ABI 18 verifies two interleaved sessions (64 calls) and a checkpoint restart
(32 calls), for 96 verified returning invocations. It checks every application
buffer, independent contexts, aliases, final references, transcript consumption
and return checksum. Eight rejected inputs leave kernel state unchanged. An
intentional state mismatch returns diagnostic 30, poisons only its own session,
and recovers on explicit restore. Application virtual addresses exceed 32 bits.
A separate synthetic 64-bit closure checks automated macro-call threading,
initializer pointer rebinding and independent sessions without the OHOS profile.
It demonstrates transformation portability rather than validation of another
real kernel.

Native-capture-to-callable-library regression and ELF/raw × EL1/EL3 verification
use QEMU with no runtime host services. The first port still replays captured
ARMv7 LiteOS-A syscall behavior compiled for AArch64; it is not a native AArch64
kernel capture. The saved-frame adapter below prepares application register
results and continuation state. The CPU gateway below executes that return path
on real QEMU registers. [Application checkpoint import](application-checkpoints.md)
and [chained joint snapshots](checkpoint-chains.md) now route supplied user ELFs
through that gateway while preserving kernel state. Recorder-specific Intel
Pinball formats remain outside the neutral ELF/frame/memory import contract.

Retained callable artifacts are in `build/callable-slices-final`:
`slices.a` is the application-linkable library; `sources/slice_layout.h` declares
408 bytes of state aligned to 8 bytes for this port. Retained bank/CPU verification
is in `build/callable-slices-final-qemu-verified/verification-matrix.json`.
The final fresh native-capture and callable-support regressions are recorded in
`build/live-syscall-checks/qemu-callable-slices-final-results.xml`.


### Saved AArch64 application frames

`osrec/aarch64_frame.h` defines an 808-byte loader-owned frame: x0–x30, SP, PC,
PSTATE, v0–v31, FPCR/FPSR and TPIDR_EL0/TPIDRRO_EL0. It is a C memory image
for the little-endian AArch64 container, not an architectural exception-frame
layout or an application-checkpoint file format. SVE/SME and other machine state
remain the checkpoint loader's responsibility.

The port's optional `application_abi` descriptor declares the number register,
six argument registers, result register and `svc-pc-plus-4` continuation rule.
The builder generates `osrec_application_abi` and a sorted syscall/argument-count
table directly from the root recipes. The bridge reads only the argument registers
that a syscall uses. Unused registers retain arbitrary application values and
are not required to contain zero. For this port the container convention uses
x8, x0–x5 and x0, while syscall numbers and scalar types still come from the
captured ARMv7 LiteOS profile. This does not establish a native AArch64 OHOS ABI.

```c
#include "osrec/aarch64_frame.h"

/* frame and app_memory are supplied by the application checkpoint container.
 * frame.pc identifies the original SVC instruction, before it executes. */
struct osrec_aarch64_site site = {
    ordinal, frame.pc, frame.pc + 4, app_memory
};
struct osrec_slice_result result;
uint32_t status = osrec_aarch64_syscall(&session, &osrec_application_abi,
                                      &frame, &site, &result);
/* On OK, frame holds the raw result and continuation PC for the resume hook. */
```

The memory view must include readable bytes for the original four-byte `svc`
and its four-byte continuation instruction, alongside syscall data regions.
The bridge validates the site PC, alignment, overflow, continuation mapping and
little-endian SVC opcode, including nonzero immediates. It does not execute SVC.
It resolves application virtual addresses through the same target-RAM views as
the slice runtime, so those addresses may exceed 32 bits.

After successful kernel execution, including a negative syscall return, only
the declared result register and PC change. All other saved frame bytes remain
unchanged. Rejected input, busy entry, completion, divergence and poison return
without committing frame changes. Divergence can still leave kernel/application
memory effects and requires checkpoint restore, as with the session API. Container
metadata, frames, recipe tables and kernel storage must be isolated from writable
application regions; the bridge rejects such aliases. This is a trusted container
API, not a sandbox for arbitrary metadata pointers.

Build and verify this integration stage with:

```sh
python3 tools/export_syscall_slices.py \
  --capture build/live-file-operations-native-verified \
  --out build/application-file-slices --application-frame
python3 tools/verify_syscall_slices.py \
  --image build/application-file-slices --out build/application-file-slices-qemu
```

The published `slices.a` includes the saved-frame runtime and generated application
ABI. `--application-frame` selects the port's frame proof driver and result ABI 19.
The shared matrix command checks archive/image/source hashes, runs ELF/raw from
EL1/EL3, compares the full terminal result bytes and writes
`verification-matrix.json`. Session-only ports can omit `application_abi` and
continue using the existing API and ABI 18 proof.

ABI 19 checks 96 file calls across two interleaved sessions and a checkpoint
restart, with two register conventions, arbitrary unused argument registers,
full saved-frame preservation, every application buffer and persistent kernel
state. Twenty rejected-input/busy-entry cases preserve the frame and kernel
state. Completion, divergence and poisoned-session cases also preserve the frame.
Two additional synthetic transport calls check positive and negative 64-bit raw
results independently of the OHOS scalar width. Mutation tests corrupt SP,
SIMD bytes, continuation updates, register extraction and site validation; QEMU
rejects each. A fresh native capture runs through this same frame path.

Retained artifacts are in `build/application-frames-final-v2`, with matrix evidence
in `build/application-frames-final-v2-qemu-verified/verification-matrix.json`.
Regression results are in
`build/live-syscall-checks/qemu-application-frame-final-results.xml`.

The saved-frame API operates on a supplied memory image. The CPU gateway below
adds live register entry/return. Importing a Pinball-style checkpoint and deriving
routes/patches for a supplied application ELF remain container integration work.


### Live AArch64 CPU gateway

`osrec/aarch64_gateway.h` adds a returning EL1h container-to-EL0t execution gateway.
It loads the application frame onto the CPU, enters executable application code,
handles recorded syscall sites on a private stack, and restores the resulting
application frame with `eret`. Entry PC can precede the first syscall site.
Kernel state belongs to the same explicit session and is retained between traps.

The executable code uses `brk #0x5353` at each routed syscall site. The corresponding
memory view supplies the original SVC bytes for the existing frame validator.
The embedded vector handler saves all application GPRs, baseline SIMD/FP state,
PSTATE, SP and thread pointers before calling the selected kernel slice. A successful
slice advances PC past the routed site; actual application instructions execute
at that continuation and can consume its computed result. `brk #0x5354` at the
declared exit PC returns to the container after every declared site has completed.
Unexpected app/kernel exceptions return divergence and poison the session.

No SVC, host debugger service, semihosting, host filesystem or external syscall
provider is used at runtime. The instruction audit admits only the port proof's
reviewed BRK addresses and immediates; an unlisted BRK or any SVC/HVC/SMC/HLT/BKPT
rejects construction. The published manifest records the breakpoint contract and
the shared QEMU verifier audits it again before execution.

The gateway takes an application frame, session, register ABI, ordered site list,
executable code span, exit PC, and a dedicated stack of at least 16 KiB. Sites bind
recorded ordinals and original code/data memory views. Writable application regions
and executable code must use their actual physical target addresses in this stage.
The original code view may use a separate immutable byte image at the same logical
code addresses. A mapped writable app-stack region must cover the initial SP.
Gateway/frame storage and slice stacks are isolated from writable app regions.

```c
#include "osrec/aarch64_gateway.h"

_Alignas(16) static unsigned char slice_stack[OSREC_AARCH64_GATEWAY_STACK_MIN];
struct osrec_aarch64_gateway gateway = {
    .abi = OSREC_AARCH64_GATEWAY_ABI,
    .session = &session, .registers = &osrec_application_abi,
    .application = &frame, .sites = sites, .site_count = site_count,
    .executable = executable_region, .exit_pc = exit_pc,
    .stack = slice_stack, .stack_bytes = sizeof(slice_stack)
};
uint32_t status = osrec_aarch64_gateway_run(&gateway);
/* OK: app reached its declared exit. Divergence: restore both app and session. */
```

The current contract is baseline Cortex-A53 AArch64, MMU off, EL1h container,
EL0t application, masked DAIF and one sequential execution per CPU. It is not a
process-isolation mechanism. App PSTATE accepts NZCV and masked DAIF with EL0t
mode. SVE/SME, live MMU contexts, interrupts, signals and concurrent execution
are outside this gateway contract. C kernel/runtime code remains compiled with
`-mgeneral-regs-only`; only the explicit assembly moves FP/SIMD state. The assembly
uses 64-bit lanes to support the existing 8-byte-aligned, 808-byte frame ABI.
Target Clang generates the C/assembly offsets automatically for every build.

The gateway restores the container's stack, VBAR_EL1, TPIDR_EL1, CPACR_EL1,
SP_EL0, ELR_EL1, SPSR_EL1, thread pointers and baseline FP/SIMD state before
returning under the normal C calling convention. CPACR may initially disable FP;
the gateway enables it for frame transfers and restores its original value.
An unexpected EL1 fault preserves the saved application frame, releases the active
entry flag and poisons the session. Partial kernel effects remain until explicit
checkpoint restore. An app fault retains its actual fault-time frame.

```sh
python3 tools/export_syscall_slices.py \
  --capture build/live-file-operations-native-verified \
  --out build/cpu-file-slices --cpu-gateway
python3 tools/verify_syscall_slices.py \
  --image build/cpu-file-slices --out build/cpu-file-slices-qemu
```

`--cpu-gateway` selects proof ABI 20 and includes the gateway in `slices.a`.
The library excludes the proof application and its terminal result driver. A
kernel port's preparation module supplies its reviewed CPU-proof breakpoint
symbols/immediates and proof app assembly, in addition to its existing capture,
root and provider contracts. The gateway, target offset generation, session
runtime, audit and verification matrix are shared across ports.

ABI 20 verifies 96 real file-call round trips across two interleaved sessions and
a restart. It checks every hardware application frame, continuation result store,
application buffer, stack canary, container FP/SIMD state and eight container
control registers. Ten rejected gateway inputs leave frame/kernel state unchanged.
It also checks completion, modeled divergence, poison and checkpoint recovery.
A separate two-call EL0 program starts before its first syscall, prepares a
64-bit argument, feeds the first result into the second call, and retains kernel
state throughout a single gateway entry. This checks 64-bit syscall numbers,
arguments/results and initially disabled FP access. Deliberate app and kernel
instruction faults return through the embedded vectors and recover on restore.

Mutation tests break SIMD lanes, TLS/control restore, LR transport, transcript
advance, active-flag cleanup, fault-frame preservation and the actual app result
store; QEMU rejects each. Legacy image/slice/frame suites and a fresh native
capture-to-CPU-gateway pipeline are also verified.

Retained library/proof artifacts are in `build/cpu-gateway-final-v2`, with ELF/raw
× EL1/EL3 evidence in
`build/cpu-gateway-final-v2-qemu-verified/verification-matrix.json`.
The broad regressions are recorded in
`build/live-syscall-checks/qemu-cpu-gateway-results.xml`; the final CPU entry proof
is recorded in `build/live-syscall-checks/qemu-cpu-gateway-final-entry-results.xml`.
The [application ELF/checkpoint importer](application-checkpoints.md) now generates
site patches, embeds recorded user memory, and composes a separate application ELF
with this library. Its file fixture executes the complete 32-call sequence in EL0,
with repeated routes and two executable segments. Recorder-specific checkpoint
formats still require translation into the neutral input schema.
