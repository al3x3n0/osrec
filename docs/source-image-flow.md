# OSREC source-image flow and remaining work

Nov 11, 2026 · @Alex

## Goal

The primary deliverable is a **self-contained native user-checkpoint executable linked with captured kernel code and state, for RTL/cycle-accurate processor models, with all code executing at EL0**. It embeds the required code, initial memory/register state, external inputs, startup/runtime and acceptance checks. Runtime execution requires no host OS, libc, dynamic loader, filesystem, host signals, host clock or host service calls. A model-specific terminal exit is permitted; a target-memory status record and terminal PC can also report completion. Construction and validation tools may use host services.

The executable owns restoration and execution of its application memory and registers. The captured-kernel backend supplies the kernel's own machine code and persistent post-boot state, with privileged operations handled at the architecture edge. Application and kernel computations execute natively on the modeled CPU. Replay resumes the checkpoint rather than booting Linux again. Linux arm64 is the current test kernel; the broader project target remains captured OpenHarmony scenarios, including relevant scheduling and interrupts when those are admitted.

The delivered executable has no architectural external effects beyond its own RAM and optional terminal exit. UART output becomes a RAM buffer/check, timer observations come from embedded RAM inputs, and kernel privilege/page-table state is software state. Captured UART/timer dependencies are small; they do not require real delivery devices, hardware interrupts, EL1 execution or host calls. Include the observations and effects the scenario needs, and stop on missing inputs or unsupported behavior. The existing sequential workloads need counter reads but do not establish timer-interrupt, idle/wakeup or general device support. Keep startup and verification outside a declared measurement interval; distinguish transformed-code/monitor overhead from original user/kernel timing. Captured architectural state does not supply cache, TLB or other microarchitectural state.

The ordinary arm64 Linux executors and the research EL1 monitor are functional validation harnesses. The monitor uses privileged exception/MMU operations and therefore does not satisfy the EL0-only delivery contract. Delivery needs internal context gateways and EL0 handling of address translation and potentially faulting accesses, with no signal/exception service supplied by a host OS or an EL1 monitor. The checkpoint/library interface remains the entry into the captured kernel computation.

The primary application-to-library entry is a direct branch through a linked syscall veneer. SVC entry remains supported as an alternative backend. Both entries must converge on the same captured kernel dispatcher and user-context return path.

- **Acceptance:** the admitted scenario re-executes captured code and must reproduce its declared observations and effects. Unsupported operations, missing inputs and verification failures stop explicitly. Current workload comparisons do not prove exact replay for arbitrary syscall sequences.
- **Authenticity:** executed instructions are the kernel's own, from our clang-19 build of Linux 6.10. Hand-written equivalents are allowed only at the per-architecture hardware edge (privileged instructions).
- **Test target:** Linux arm64 stands in for the proprietary kernel, which is built with clang and DWARF and boots on QEMU virt.
- **Inputs known in advance:** the program binaries' layouts and their syscalls.

## Current flow

The delivery backend is `runtime/el0_flat`: one native executable embeds user and captured-kernel code, initial RAM/registers, inputs and verification, all executing at EL0. The complete captured workload passes native AArch64 and QEMU application mode; see the [demo report](el0-native-demo.md). Model loading uses the generated `load-plan.json`; RTL execution and cycle validation remain pending.

For a separately supplied static ELF, [the user-binary builder](el0-user-binary.md) takes a reusable libkernel capsule, runs the captured kernel's real `execveat` during construction, and snapshots the new process at its ELF entry. It records a native reference with deterministic RAM inputs, emits native code, expands explicitly missing kernel functions, and validates the resulting standalone executable. The new reference is not an independent live-Linux oracle. The original captured demo retains its live-Linux comparison.

The optional `--linux-baseline` check additionally runs the original ELF on the Linux host and compares program exit status and stdout. It checks program-visible results in fresh host process state; it does not establish per-syscall or kernel-state equality with the capture.

```
libkernel capsule + static user ELF + arguments
              │
              ▼
captured kernel execveat → new process checkpoint
              │
              ▼
native reference and RAM inputs → EL0 code export and link
              │
              ▼
static audit → native validation → QEMU APP → model load plan
```

### Capture and independent reference pipeline

The capture/reference tools below remain construction harnesses. Their default image runs kernel code at EL1 under a small EL2 stub. `--execution el0-minios` runs user and captured kernel code at EL0 with an EL1 monitor handling privileged operations. The arm64 Linux reference harness uses host signals for the architecture edge. These harnesses are separate from the delivered EL0 executable.

```
Kernel build ──▶ Checkpoint ──▶ State dump ──▶ Image build
(clang-19,       (after boot     (RAM + CPU     (text + RAM
 DWARF5)          + setup)        state)         + tables)
                     │                               │
                     ▼                               ▼
                Run native                       Run image
                (live kernel)                    (QEMU, own tables)
                     │                               │
                     └──────────▶  Compare  ◀────────┘
                                (every call + fault)
```

Both runs start from the same checkpoint; the comparison is the acceptance test.

| Step | Tool | Output |
| --- | --- | --- |
| 1. Kernel build | `integrations/linux_aarch64/full-kernel/build.sh` (clang-19, DWARF5, in the build container) | `vmlinux`, `System.map`, `compile_commands.json` |
| 2. Type database | `tools/kernel_dwarf_db.py` (pyelftools, 8 workers, about 9 min) | `dwarf-db.json.gz`: 19,017 types, 93,092 static variables |
| 3. Checkpoint | `tools/build_linux_vm_checkpoint.py --workload examples/linux-vm-checkpoint/init-*.c` | full QEMU machine saved after boot and the program's setup |
| 4. State dump | `tools/kernel_state_dump.py --select <syscall>` | `ram.bin` (all RAM), `state.json` (CPU and system registers, including four probed registers QEMU omits) |
| 5. Image build | `tools/source_image.py build --profile integrations/linux_aarch64/source-image/fd-control.json [--execution el0-minios --dwarf-db …]` | `image.elf`, `manifest.json` |
| 6. Run | `tools/source_image.py run` (the image) and `native` (live kernel) | `calls.json`: every syscall and user exception |
| 7. Compare | `tools/source_image.py compare` | identical count, first difference |

What the image contains (step 5):

- **Code:** the whole persistent kernel text as the live kernel holds it after boot; the profile's boundary functions become traps.
- **Data:** every non-zero RAM page and the zero pages, at the live virtual addresses, under our own page tables; the console UART passed through.
- **Relocation (optional):** RAM moved by Δ, a multiple of 128 MiB (`tools/ram_relocation.py`).
- **Entry:** a stub restores the captured CPU state and resumes the user program at its SVC instruction.

The recorder reads each result from `pt_regs` right after `el0_svc` calls `do_el0_svc`, before any signal frame is set up.

## Results so far

Every compared event matches native Linux: about 100,000 syscalls and user exceptions across the workloads below, apart from one known clock case in the earlier per-call replays.

| Workload | Seeds | Events compared | Identical | Notes |
| --- | --- | --- | --- | --- |
| Random sequence with signals | 4 | 35,013 | all | 690 signals delivered and returned (SIGUSR1/2, SIGSEGV resumed, SIGXFSZ) |
| Random sequence with page faults | 4 | 35,285 | all | 1,969 user page faults; native reported one fault twice, merged |
| Random fd, futex and mmap sequence | 4 | 32,328 | all | buffers prefaulted |
| RAM relocated to 0x80000000 and 0x90000000 | 2 | 2,272 + 11,064 | all | page tables, pfn and phys statics, memblock, resources, swiotlb, sparse sections patched |
| Captured init workload | 1 | 74 | all | ends at the program's own power-off; native PASS line printed |
| Per-call source replays (earlier scheme) | — | 64 calls | 63 | 1,599 function checks identical to a fresh compile; futex wait-timeout diverges on the clock in the binary replay too |

The complete native EL0 demo was merged into `main` at `7ae751a` and pushed. Earlier capture/reference work includes `2459b7f` (image, recorder, workloads, verifier, closure, DWARF database), `125147e` (RAM relocation) and `fc20cbc` (signal delivery).

## Boundaries and limits

A run stops at a declared function boundary from `integrations/linux_aarch64/source-image/fd-control.json` or, in the EL0 runtime, a named architecture boundary from `runtime/el0/el0.h`.

| Boundary | Why it stops |
| --- | --- |
| Idle loop (`default_idle_call`, `arch_cpu_idle`, `cpu_do_idle`…) | nothing runnable; native Linux would wait for an interrupt |
| Error reporting (`_printk`, WARN, list-corruption reports) | reached only on kernel errors or device faults |
| Active audit, seccomp filters, syscall tracing | gated by thread flags before the call |
| EL0 exceptions needing unmodelled state | debug, SVE/SME, compat, MOPS, GCS, asynchronous |
| Power-off (`kernel_power_off`) | the program's own exit; a host exit for now |
| MMIO other than the PL011 UART | unmapped, so an access faults and stops |
| User access to upper-half kernel addresses (EL0 runtime) | separate user/kernel upper page tables preserve the user restriction; a fault stops explicitly |

Known limits:

- **Relocation completeness** rests on a rule (named records, pfn- and phys-typed statics, page tables), not on a full typed walk; two misses were found only by running.
- **Source check:** the full compile audit covers 63,288 distinct function addresses and 96.6% of executable bytes; known relocation fields are masked during comparison. Uncovered ranges remain unverified.
- **Comparison depth:** syscall results and user exceptions, plus optional `--memory` hashes of every EL0-accessible user page after each completed syscall. Kernel state and the exact order of memory writes are not compared.
- **No hardware interrupt replay:** anything that waits for an interrupt ends at the idle boundary. Standalone delivery consumes embedded counter observations; construction can use deterministic counter inputs. These do not establish timer-interrupt support.
- **Single process, single CPU,** QEMU TCG on both sides of the comparison.

## EL0-only native backend

`runtime/el0_flat` is the current delivery work. Its startup, context gateway, software address checks, captured-kernel computation and validation execute at EL0. It has no host service calls before its optional terminal exit, no signals, TLS, libc, exception monitor, privileged bootstrap or physical device accesses. The earlier Linux/EL1 backends remain reference harnesses.

The gateway saves all 31 guest GPRs, NZCV, all 32 SIMD registers, FPCR and FPSR. Actual SP always belongs to a private runtime stack; guest SP is logical RAM state. Generated resume thunks restore the final two scratch registers before a direct branch, so no guest GPR is reserved and captured stack bytes are untouched. Original SP consumers must be lowered before entering this backend. The software walker preserves virtual aliases, observes current captured PTEs, checks inherited AP/XN restrictions and AF, and reports faults before native accesses. It supports checked cross-page transfers when physical and RAM backing are contiguous. Missing backing, faulting/discontiguous split transfers and unsupported code stop explicitly.

The model loads ELF PT_LOAD segments, zeros their memory tails, supplies normal RAM and FP/SIMD at EL0, and starts at ELF e_entry. The image installs its own private stack. The generated load plan identifies the RAM result and completion PC before optional terminal exit. Functional QEMU/native checks do not establish original-kernel cycle equivalence.

Gateway register preservation, nested-entry rejection, transition-budget stops and recovery now run independently of a captured kernel fixture:

```sh
# On AArch64 Linux, including the construction toolchain container:
make -C runtime/el0_flat CC=clang-19 check-gateway
```

The former direct-umask bring-up exporter, driver, fixture checker and counting command have been retired. The complete executor below is the supported application path. Shared ELF admission checks live in `tools/audit_el0_image.py`; current validation uses `tools/check_el0_program.py`.

### Complete user/kernel checkpoint

`tools/export_el0_program.py` and `runtime/el0_flat/program.c` now resume the saved user PC and execute the complete captured random/fault workload. User SVC enters the original captured exception vector, entry code, dispatcher and syscall body. Logical ERET resumes user computation. Software-detected data faults enter the captured kernel fault handlers, which update the same canonical RAM and page tables. Syscall results are computed by these paths; embedded expected events are read for final validation, not to produce results or select branches.

The conservative static closure contains 5,020 kernel functions, the user executable and 1,499 captured address-lowering veneers. This is included code, not a claim that every function executes. A reference translated-code listing broadens function coverage for indirect calls; its branch outcomes and instruction order are not replayed. Unknown runtime targets stop with their original PC. Ordinary arithmetic/SIMD operations execute natively; address, guest-SP and architecture operations use generated adaptations. Exclusive load/store windows, including paired LDXP/STXP, execute without a runtime callback between their load and store.

`build/el0-program-20261110c/checkpoint` passes native EL0 validation in `build/el0-program-validation-20261110d/validation.json`:

- All **2,272** syscall/exception events match the independent reference, including arguments, results and completion state.
- All **nine** ordered timer inputs are consumed; **92 UART bytes** match in RAM.
- Execution reaches the original `kernel_power_off` boundary at `0x80008008eb30`, after **2,261,577** gateway transitions in this run.
- The separate native observer sees exec entry and terminal exit only. The image's first host service is `exit(0)`; no signal handler, libc, runtime file loading, privileged monitor or physical MMIO is used.

The identical ELF also passes QEMU Linux application mode on Cortex-A53: `build/el0-program-qemu-app-20261110a/validation.json`. Guest tracing records only `exit(0)`. Native exclusive-store retries can vary the gateway transition count slightly between runs while leaving the checked computation unchanged. Full-workload instruction counts have not yet been recorded; the historical figures below apply only to the retired umask fixture.

All initial nonzero state and input/validation data are linked into the roughly 92 MiB ELF. Canonical physical RAM has zero-backed storage for the complete captured bank, including initially empty pages that the kernel later allocates. The loader must zero ELF memory tails and provide normal RAM/FP/SIMD at EL0. Observe `flat_full_result` and stop at `flat_completed` before optional terminal exit; `load-plan.json`, generated after successful validation, reports load segments, initialization requirements and symbol addresses.

The current admission requires immutable compiled code. Writes through any physical alias of an included code page stop, and user executable mappings/permissions are checked before entry and after architecture transitions back to user mode. Changed executable mappings, unknown code targets, faulting/discontiguous cross-page transfers and conditional exclusive sequences on read-only memory remain explicit boundaries. The signal workload has not yet been admitted to this backend. This validates transformed functional execution; gateway/address-translation overhead remains part of the delivered instruction stream, and original-kernel cycle equivalence is not established.

Generate with an optional reference coverage listing, then build on arm64 Linux:

```sh
python3 tools/export_el0_program.py \
  --package build/native-application-20261109a \
  --vmlinux build/linux-kernel-clang19-20261108/vmlinux \
  --user-elf build/linux-svc-machine-checkpoint-random-fault-20261108a/init \
  --oracle build/native-application-oracle-20261109b \
  --coverage build/el0-program-reference-code-20261109a.log \
  --out build/my-el0-program
make -C runtime/el0_flat CC=clang-19 IMAGE="$PWD/build/my-el0-program" program observer
python3 tools/check_el0_program.py --image build/my-el0-program \
  --out build/my-el0-program-validation --observer build/el0-flat/flat-observe
python3 tools/check_el0_program.py --image build/my-el0-program \
  --out build/my-el0-program-app-validation --qemu
```

The coverage listing can be reproduced with `check_monitor_checkpoint.py --code-log PATH` against the fixed-input reference monitor. That monitor remains a construction/validation tool and is never linked into the EL0 delivery image. Without a listing, syscall-root closure alone stops on missing indirect targets; `--extra-pc` also admits a whole function and its dependencies. New lowering tests cover scalar/SIMD memory operands, stack operations and exclusive windows. Native negative tests corrupt an expected result and an executable mapping, checking that validation fails while host interaction remains terminal exit only.

### Historical bring-up instruction counts

The retired direct-umask fixture recorded 459,949 instructions for its complete executable, including 303,492 across six execution intervals and 78 original kernel-island instructions. Its five-iteration counter sanity check recorded 20 instructions, including 15 loop instructions. These measurements cover a 60-byte function entered directly; they do not represent user-program continuation, syscall dispatch, the complete checkpoint, CPU cycles or original-kernel timing equivalence.

The frozen report, interval counts and compressed trace remain in `build/el0-flat-app-counts-20261109d/`; the retired tooling is recoverable from commit `bf670da`. Current full-workload dynamic instruction counts and RTL/cycle validation remain pending.

## EL0 runtime progress

**Stage 1: kernel code at EL0 under the mini-OS (QEMU).** Implemented and validated:

- `runtime/el0/el0.h`: trap context, site table, shadow EL1 state, stop reasons and platform interface. Host tests assert the layout shared with assembly and the builder.
- `runtime/el0/emulate.c`: shared privileged-instruction emulation and exception dispatch. Unknown registers, unsupported control changes and unsupported exception-return state stop explicitly. User BRKs cannot invoke the monitor protocol.
- `runtime/el0/minios.c` and `minios.S`: EL1 boot, vectors and context switches. `osrec_stopped` exposes reason, PC, detail and fault address in x0–x3. The recorder reads the saved kernel context for backtraces.
- `tools/source_image_el0.py`: live-text rewriting, ELF instruction/data markers, original-instruction site table, captured shadow state, staged pages, boot parameters, initial GPR/FP state, EL0 kernel mappings and monitor linking.
- `tools/kernel_state_dump.py`: restores its temporary MRS probes before saving RAM. This captures MIDR, MPIDR, DCZID and ID_AA64PFR0 directly. Legacy dumps can recover saved ID values from `cpu_data` through DWARF. `__cpu_logical_map` is insufficient for full MPIDR because it drops architectural bits such as MPIDR.U.

- [x] Host unit tests for `emulate.c`, including exception entry/return and stop cases
- [x] EL0 image builder and monitor link
- [x] Trap choice: `brk #0xf00` sites, `brk #0xf01` boundaries; PAC hints become NOPs
- [x] Generate all monitor boot and state data
- [x] Recorder support for mini-OS stops and shadow ELR/ESR/FAR read through physical memory
- [x] Compare against the saved native random-workload recording

Validation artifacts live under ignored `build/` directories:

| Run | Events | User exceptions | Result |
| --- | --- | --- | --- |
| `source-image-el0-20261108b/run` | 2,272 | 136 | Every event matches the existing native recording |
| `source-image-el0-20261108g/run-memory` | 2,272 | 136 | 2,135 completed calls and all 76,053 sampled user pages match native |
| `source-image-el0-signals-20261108c/run` | 2,339 | 156 | Every event matches native; signal delivery and `rt_sigreturn` execute through the kernel |

Both workloads finish at `kernel_power_off`. These tests establish the listed workloads, not all possible syscall sequences. Clocks, interrupts, multi-process execution and the other declared limits still apply. The EL0 monitor switches upper-half permissions when entering/leaving kernel code; a QEMU negative test confirms that user reads of kernel text stop before observing it. It also stops on changed controls it cannot reproduce and on address translations whose original permissions differ from its EL0 mappings.

**Stage 2: lower the address space.** A host process can map only the lower half, so the kernel's `0xffff…` addresses must move.

- [x] Implement conservative pointer and layout-dependent code lowering in `tools/va_lowering.py`; unresolved operations become named stops
- [x] Keep the original user pages clear by moving the linear map to 32 TiB before lowering; preserve encoded per-CPU offsets, address-keyed hash tables and layout differences
- [x] Validate in QEMU with only TTBR0 mapped, on a Cortex-A53 without LPA2
- [x] Repeat lowered validation on the signal workload: all 2,339 events (156 user exceptions) match native with linked shadow-register veneers enabled

`source-image-el0-lower-20261109e/run` matches all 2,272 native events (136 user exceptions). `source-image-el0-lower-20261109d/run-memory` also matches all 2,272 events and all 2,135 completed-call user-memory snapshots; the later E build adds conservative stops for constants with intermediate consumers. Two negative tests on D confirm that a direct user load and a syscall user-copy using a lowered kernel pointer stop explicitly. The real TTBR1 walk is disabled. The runtime merges captured live user tables with the static kernel mappings, propagates table permission restrictions, and rejects colliding leaves. This is workload validation, not proof that every possible address-bearing value has been found.

**Stage 3: host-process runtime.**

The host library (`liblinuxkernel-el0`) should use linked emulation routines for known instruction sites. A four-byte replacement can branch directly to a nearby, site-specific assembly veneer. Prefer `B` over an unconditional `BL`: the replaced instruction may preserve a live x30, whereas `BL` overwrites it before the callee can save it. The veneer saves the original context, calls the shared emulator, restores the resulting context and branches to the continuation. A direct `BL` is safe only where analysis proves the original x30 dead and the emulated instruction does not need it as an input. Both immediate branches need a target within their ±128 MiB range, so the builder must reserve reachable veneer regions.

The public library contract is **checkpoint calls kernel services**, with application pointers referring to the checkpoint process's actual restored memory:

1. The checkpoint executable initializes a kernel instance from its matching captured kernel-state package and registers its application mappings.
2. At a syscall, the primary path branches directly to a linked application-entry veneer, which captures the application context and calls the library without executing SVC. An existing SVC site can be rewritten to a single B to that veneer. Preserve its original instruction semantics, including a live x30; a source-level API call can instead use the ordinary function ABI.
3. The library enters the captured Linux syscall path at EL0 using that instance's kernel stack and state. Privileged-operation veneers update shadow state or perform supported host mapping actions.
4. A simulated ERET yields the resulting user context to the gateway. The continuation may be the instruction after the original syscall site, a signal handler, a restarted syscall, or a context restored by `rt_sigreturn`.
5. The gateway resumes checkpoint execution. Kernel state, file descriptors and memory-management changes persist across subsequent calls to the same instance.

The ABI must distinguish the Linux syscall result (including negative errno values) from library boundaries, unsupported operations and runtime faults. Expected privilege emulation and supported fault handling must not cause host SIGILL/SIGSEGV termination or call `exit`/`abort` on the checkpoint process. Unsupported cases return a structured diagnostic at the library boundary. A buildable public front end now exists in `runtime/linuxkernel_el0/`, with declarations in `include/osrec/linuxkernel_el0.h`. The native implementation in `runtime/linuxkernel_el0/native.c` now executes captured Linux instructions with signal-based trap delivery and shared physical-memory aliases. Its explicit-context and complete-workload validation and reproduction commands are below. Neither backend substitutes host syscalls for captured Linux services.

There are two distinct veneer layers: the application-entry veneer calls captured Linux services, while the internal privileged-instruction veneers emulate the kernel's EL1 hardware edge. The first public application veneer is an explicit-context function-ABI entry: `lk_el0_veneer(kernel, &user_regs, original_svc_word, &result)`. Its arm64 implementation is exactly one B to `lk_el0_call`; it does not execute SVC. The caller supplies a copied register context whose PC identifies the original syscall site. Whole-application execution now rewrites each admitted user SVC to one B to a nearby BRK veneer. That veneer changes no registers, flags, stack bytes or FP/SIMD state before the host signal frame captures them. The handler normalizes the context using the original SVC address and word, then enters the same captured dispatcher. Logical ERET resumes the returned user continuation directly. Application entry must provide the same logical syscall context as SVC: syscall number/arguments, original instruction identity, saved PC at the original site plus four, flags and other state observable by the kernel. Signal frames and syscall restart must refer to the original application site, not the veneer address. Application-register deadness alone does not justify dropping state that the kernel or a signal frame can observe.

`lk_el0_create` borrows caller-owned shadow state and a matching execution backend; the backend runs from the prepared captured kernel vector until logical ERET yields a user context. The instance and kernel state persist across calls. `lk_el0_svc` accepts a post-SVC register context; it and the mini-OS's real SVC handler use the same `osrec_enter_syscall` normalizer as direct entry. `result.context.x[0]` holds the Linux return value, independently of `result.status`. The context returned by the backend selects the continuation, including signal entry, restart or `rt_sigreturn`; the library does not force return to site+4.

Emulation-core stops are caught with a guarded nonlocal return and reported as named boundaries. Signal masks are restored when a backend reports a stop from its signal handler. Failed calls poison their instance because captured state may already have changed; restore the checkpoint before creating a fresh instance. Concurrent/reentrant calls return BUSY. The native backend now handles SIGTRAP/SIGILL/SIGSEGV/SIGBUS on a private alternate stack, preserves FP/SIMD context and virtualizes the guest TLS registers. The front end alone still cannot recover arbitrary host faults; callers select the native implementation explicitly.

The alternative SVC backend must normalize its exception context into that same dispatcher. The mini-OS already receives SVC through its vectors. Native Linux needs an explicit interception backend: an unhandled SVC would enter the host kernel, not `liblinuxkernel-el0`. Retaining that instruction is therefore supported only with a backend that routes it to the captured kernel. Test both entries for equivalent results, errors, kernel-state changes, signal delivery, syscall restart and `rt_sigreturn`.

This is an instruction-replacement ABI, not the ordinary C calling convention: preserve every register and flag the original instruction preserves, account for SIMD/FP state, and provide a valid save area without corrupting the captured stack or host TLS. Exception entry/return and syscall entry can select a different context or continuation. Calls that save state must not be inserted inside an exclusive load/store sequence without preserving its semantics. The existing BRK mini-OS backend remains the validation baseline.

Minimise each veneer's save set with register/flag liveness and its actual clobber set. `tools/aarch64_liveness.py` provides a conservative local analysis of original instructions: follow direct branches, join both conditional paths and solve loops to a fixed point. W/X aliases share a bit; SP, NZCV, SIMD registers, FPCR and FPSR are tracked separately. Unknown instructions, memory accesses with potential exception observers, indirect transfers and missing code preserve all state. A direct BL kills old x30 but makes no other kernel-assembly ABI assumptions. The initial decoder proves kills for a small whitelist; analysis-budget exhaustion also preserves all state.

`--el0-dispatch branches` now connects this analysis to `tools/source_image_calls.py`. The initial veneers handle selected MRS/MSR shadow fields directly, use no checkpoint stack space and never clobber flags or SIMD. They use a dead/output register for addressing and, if needed, spill one live temporary into a private 16-byte area preceding the shadow. A separate alias exposes that state to EL0 kernel code; the monitor's original mapping retains its privileged permissions, and the user-mode root denies access to both code and state aliases. Sites without a safe address register and operations needing platform actions retain traps. Lowering guards/stops count as state observers during liveness analysis, even when the original instruction would have killed a register. The generated `calls.json` records each site's live, scratch and save sets. The non-lowered random-workload image contains 36,219 veneers: 11,787 save no registers and 24,432 save one. This backend requires single-CPU, non-reentrant execution, as does the current mini-OS. Native arm64 Linux fixtures passed 5,888 register/shadow-state comparisons against a full-GPR/NZCV-save call to the shared C emulator, including DAIF/PAN masks and emulation-counter wraparound.

| Linked-veneer validation | Result |
| --- | --- |
| `source-image-el0-calls-20261109c/run-memory` | All 2,272 events, 2,135 completed-call snapshots and 76,053 user-page hashes match native; reaches `kernel_power_off` |
| `source-image-el0-lower-calls-20261109b/run` | All 2,272 events match native with TTBR1 disabled; reaches `kernel_power_off` |
| `source-image-el0-lower-calls-signals-20261109a/run` | All 2,339 events (156 user exceptions) match native, including signal delivery and `rt_sigreturn`; reaches `kernel_power_off` |
| User-access tests on C | Direct user reads of kernel text, veneer code and the shadow alias stop explicitly |
| User-access tests on `source-image-el0-lower-calls-20261109b` | All four checks pass: kernel text, veneer code, shadow alias and a syscall user-copy using a kernel pointer |

For a fall-through site, preserve old values in `live_after & handler_clobbers & ~instruction_outputs`. Handler inputs must still be captured before clobbering them, and live instruction outputs must still be delivered. An output counts as a kill only when it unconditionally defines the complete tracked register. Context-switch sites require their own continuation analysis. Do not use normal-path deadness to discard state observable by an exception handler.

The library operates on the calling checkpoint's memory and captured kernel instance on common 48-bit arm64 Linux hosts. A separate process may optionally supervise the whole checkpoint; worker execution is not a prerequisite for the direct library-call contract. Signals remain necessary for actual memory faults and unexpected instructions; ordinary emulation sites should not require signal delivery.

- [x] Public `liblinuxkernel-el0` explicit-context ABI, static/shared libraries and linked caller contract fixtures with persistent state across calls
- [x] Bounded native captured-Linux CPU/mapping/fault backend, with independent 22-call QEMU oracle
- [x] Restored static checkpoint application linked to the native backend and transparently resumed; 2,272-event and 2,339-event workloads match
- [x] Single static native ELF with embedded sparse state, hardware transcripts and event/completion checks; no runtime package files
- [x] Single-instruction branches to linked shadow-register emulation veneers, with context-preservation and branch-range validation
- [x] Conservative local register/NZCV liveness analysis and save-mask calculation, with branch, loop, alias and exception-observer tests
- [x] Apply liveness and explicit handler clobber sets when generating shadow-register veneers; compare against the full-save implementation on native arm64 Linux
- [ ] Extend linked veneers to platform actions and context-switch operations
- [x] Native SIGSEGV/SIGBUS/SIGILL and BRK handlers driving the same core (bounded explicit-context validation)
- [x] Structured results and recovery from emulation-core stops at the library boundary
- [x] Primary explicit-context application veneer into `liblinuxkernel-el0`, without SVC
- [x] Transparent raw-register application gateway at rewritten syscall sites (B to BRK capture veneer)
- [x] Alternative SVC-context entry into the same normalizer/dispatcher
- [ ] Native-host SVC interception
- [x] Veneer/SVC contract equivalence tests, including modeled signal/restart/`rt_sigreturn` continuations; actual Linux syscall/signal regression under the mini-OS
- [x] Native process execution through the transparent primary gateway, including captured signal delivery and `rt_sigreturn`
- [ ] Whole-application comparison through a native SVC-instruction interception backend
- [x] Mirror captured user PTE additions, permission changes and unmapping into shared host mappings; validate every guarded user access against the captured tables
- [x] Reserve all current guest VMAs, including unpopulated pages, using DWARF-bound maple-tree layout metadata
- [ ] Dynamic kernel-address mappings beyond the captured layout
- [ ] Signing kept off on PAC hosts, consistent with the unsigned captured return addresses

## Other open items and housekeeping

- [x] Compare user memory after each call: `--memory` on both `run` and `native`. A missing snapshot on one side fails comparison. Different event counts also fail; `compare` returns a nonzero status on a difference.
- [ ] Verify the whole kernel text against a fresh compile of every translation unit. `kernel_source_verify.py --all` recompiles the build database and reports verified executable bytes, unknown relocation types and gaps. All 2,973 database entries (including host tools) recompiled successfully. The report at `build/whole-kernel-source-verification-20261108.json` verifies **19,253,624 / 19,935,924 executable bytes (96.6%)**, spanning 63,288 distinct function addresses. Coverage remains incomplete: 682,300 bytes are in gaps, including 527,208 bytes of NOP padding. Same-named static/weak candidate mismatches remain in the report; every differing same-size candidate has another matching verified extent. A full compile does not automatically mean full text coverage.
- [x] List unexplained RAM-range values by physical page: `kernel_relocation_audit.py`. The retained random-workload state has **553 unexplained aligned values in 165 pages**, after accounting for relocation patches. `build/relocation-review-20261108.json` includes aliases and named object ownership. This is a review inventory, not a completeness proof.
- [x] Document source-image commands, validation and remaining limits here; link from the repository README.

Code sites must be classified by meaning. For example, `perf_reg_validate+0x30` builds the scalar mask `0xffffbffe00000000`; it must not be lowered as a pointer merely because its final instruction materializes `0xffff`. The lowering pass accounts for linear-map arithmetic, encoded offsets and page-table ownership while keeping user mappings disjoint. Only the recorded lowered workloads are established; native host execution now covers the two complete static checkpoint workloads below as well as the explicit-context scenario.

## Native captured-kernel backend

`include/osrec/linuxkernel_el0_native.h` exposes the optional native loader and CPU backend. `lk_el0_native_open` loads a lowered trap-dispatch package into the calling arm64 Linux process. The returned kernel supports the existing `lk_el0_veneer` / `lk_el0_svc` explicit-context entries. For these entries logical ERET returns the resulting user context to the caller. `lk_el0_native_execute` instead resumes actual checkpoint application instructions and continues across captured-kernel returns until a named boundary. The caller supplies changed FP/SIMD state through `lk_el0_native_fp` before each entry.

The physical store is copied into a private memfd; every captured virtual alias uses shared offsets in that store. Kernel mappings retain their original privileged read/write/execute permissions, and application mappings follow the captured user PTEs, including inherited table restrictions. The runtime's physical alias occupies a separate 16 TiB window; instance metadata, stacks and allocated trace buffers use a 256 MiB arena at 24 TiB. A DWARF-bound `vma.bin` descriptor locates the live process maple tree. Its VMA holes are reserved as PROT_NONE and become shared backing mappings only when real captured PTEs appear. This prevents an unrelated host allocation from satisfying a guest access before the kernel has populated its page. Fixed mappings use `MAP_FIXED_NOREPLACE`; replacement is allowed only for a page the instance already owns. A partial mapping failure retains an ownership ledger for cleanup. Guarded user accesses check the captured translation and permissions before executing their original instruction, so an unrelated host mapping cannot satisfy an absent guest PTE. Kernel user-copy faults enter the original kernel exception vectors and fixup paths. The signal-context reader follows the [arm64 FPSIMD/ESR record ABI](https://github.com/torvalds/linux/blob/v6.10/arch/arm64/include/uapi/asm/sigcontext.h).

The package traps guest TPIDR_EL0 operations, keeping host TLS intact. `DC ZVA` uses the captured DCZID block size rather than the host CPU's size. Counter reads stop unless the caller installs an ordered `lk_el0_counter` transcript with `lk_el0_native_counters`; each event checks its instruction PC and register encoding, and the consumption accessor supports rejecting unused inputs. Other emulation-core stops unwind through the backend's cleanup scope before returning a diagnostic and poisoning the kernel instance. Signal masks, alternate stacks and host FP controls are restored. Original process signal dispositions are restored when the native instance closes.

The backend requires arm64 Linux, 4 KiB host pages, the validated 48-bit lowered layout, a static captured kernel mapping layout, and exclusive ownership of the fixed mapping ranges. Only one native instance can be open in a process. Calls, configuration and close must be synchronized by the caller; the runtime owns the four synchronous signal dispositions during the instance lifetime. MMIO requires a PC/address/width/direction-checked ordered transcript: read values are supplied as hardware inputs and original kernel writes must reproduce their recorded values. Missing or mismatched MMIO events, new kernel mapping regions, tagged pointers, unsupported architecture changes and cross-page accesses with uncertain partial-store behavior remain explicit boundaries. Clock inputs, interrupts and scheduling are not synthesized. PAC hints in the captured text are already removed by the image builder. The current application backend admits a static ET_EXEC image with resident initial text. It rejects an ELF interpreter, writable or newly mapped executable pages, and changes to the admitted instruction bytes. The VMA mirror admits at most 2,048 VMAs and a bounded total page count; collisions with host mappings stop before the user continuation executes. Native-host interception of retained SVC instructions, dynamic application loading and further workload coverage remain open.

Build and reproduce on arm64 Linux (the package and QEMU oracle are generated on the existing image-build host):

```sh
python3 tools/source_image_el0.py relink \
  build/source-image-el0-lower-20261109e --out build/my-native-image
python3 tools/source_image_native.py \
  build/my-native-image --out build/my-native-package
python3 tools/linuxkernel_native_oracle.py \
  --image build/my-native-image \
  --package build/my-native-package --out build/my-native-oracle
make -C runtime/linuxkernel_el0 CC=clang-19 AR=llvm-ar-19 check native-run
make -C runtime/linuxkernel_el0 CC=clang-19 AR=llvm-ar-19 \
  PACKAGE="$PWD/build/my-native-package" ORACLE="$PWD/build/my-native-oracle" check-native
build/liblinuxkernel-el0/native-run build/my-native-package
```

The native package contains `native.bin`, sparse `memory.bin` and a provenance manifest. Execution needs neither QEMU, the original dump, vmlinux nor the mini-OS monitor. Packaging still uses vmlinux's instruction/data markers to rewrite the legal-at-EL0 operations whose host behavior differs. The integration oracle injects the same explicit syscall contexts into the validated QEMU image and independently records results, a user page and counter values. The mini-OS now refreshes its merged table copies on logical ERET back into kernel code; a newly allocated user PTE can otherwise be hidden behind a stale merged branch after a kernel user-copy fault. The test compares these results with native execution through both static and shared libraries, then exercises boundary cleanup and rejection of a host page colliding with a new guest mapping. Accepted artifacts are `build/native-kernel-20261109d`, `build/native-oracle-20261109e` and `build/liblinuxkernel-native-20261109a`. Both static and shared native executors match **all 22 QEMU syscall results, the 4,096-byte allocated user page, and all five ordered counter inputs**. The suite additionally checks persistent state, full FP/SIMD preservation, read-only protection, unmapping, structured boundary cleanup, poisoning, missing/mismatched counter inputs and host mapping collision rejection. This is a bounded native-kernel backend test, not whole-application replay.

### Native user checkpoint plus kernel library

The normal execution loop is now: restore the captured user context → run user machine instructions → branch from the original syscall site into its register-free BRK veneer → run captured kernel instructions → emulate logical ERET → resume the selected user continuation. Both user and kernel code execute on the host CPU in one arm64 Linux process; QEMU is used only for the independent oracle. The runtime keeps its host TLS, virtualizes guest TLS operations, and restores complete saved GPR/NZCV/FP state through signal frames. Captured kernel mappings and the physical-store alias become inaccessible while checkpoint user code runs.

`source_image_application.py` checks the static application ELF's instruction bytes against captured RAM and emits `application.bin` plus a DWARF-bound `vma.bin`. Patches are applied to the private instance only when whole-application execution starts. The original syscall PC, immediate, registers and flags reach the kernel normalizer; saved signal frames and restarts refer to that original site. A syscall-result observation hook at the existing pre-signal result point temporarily restores the original BL and executes it at its original address. A return-site trap rearms the observation and likewise restores its original instruction before execution. The observer supplies no syscall results and emulates no ordinary kernel instructions. A bounded caller-owned event array records calls and user exceptions without allocating in signal handlers. The `user-checkpoint` launcher links the kernel library archive; `user-checkpoint-shared` links the shared library. The directory-based launchers retain separate checkpoint memory and hardware-input files for inspection. The embedded delivery variant below links all of these assets and its acceptance checks into one ELF.

| Native workload, both link variants | Events | User exceptions | Counter reads | UART accesses | Result |
| --- | --- | --- | --- | --- | --- |
| Random fd/futex/mmap sequence with page faults | 2,272 | 136 | 9 | 209 | All events match the saved live-Linux and QEMU recordings; reaches `kernel_power_off` |
| Random sequence with signals | 2,339 | 156 | 9 | 209 | All events match, including signal delivery, resumed SIGSEGV and `rt_sigreturn`; reaches `kernel_power_off` |

Every counter and MMIO event must be consumed in order. UART writes reproduce the complete `OSREC_VM_PASS` line, including checksum `c6c0e76815093b61`. That output is recomputed by the running checkpoint application and kernel; only hardware reads are supplied. The two workloads establish their event results and checked UART output, not a proof for arbitrary applications or a comparison of every kernel state byte. The native user-instruction guard test also checks that loading kernel text stops before observing it and that host signal masks/alternate stacks recover. A deliberate host page inside the first future mmap VMA must be rejected at that mmap return, leave the sentinel page unchanged, and survive instance cleanup. Complete event-count comparison also detects hidden demand faults; syscall-return comparison alone would miss them.

Accepted packages are `build/native-application-20261109a` and `build/native-application-signals-20261109a`; QEMU hardware inputs are in `build/native-application-oracle-20261109b` and `build/native-application-signals-oracle-20261109a`. `build/liblinuxkernel-application-20261109a` contains both native launchers. Reports and native event recordings are in `build/native-application-validation-20261109c` and `build/native-application-signals-validation-20261109c`.

Reproduce the first workload (package/oracle generation on the image-build host; compile and execute on arm64 Linux):

```sh
python3 tools/source_image_native.py \
  build/source-image-el0-native-oracle-20261109a \
  --user-elf build/linux-svc-machine-checkpoint-random-fault-20261108a/init \
  --out build/my-user-checkpoint
python3 tools/source_image.py run \
  --image build/source-image-el0-native-oracle-20261109a \
  --native-counters build/my-user-checkpoint --out build/my-user-oracle --limit 3000
make -C runtime/linuxkernel_el0 CC=clang-19 AR=llvm-ar-19 checkpoint
python3 tools/check_native_application.py \
  --package build/my-user-checkpoint --oracle build/my-user-oracle \
  --binaries build/liblinuxkernel-el0 --out build/my-user-validation \
  --live build/source-image-random-fault-20261108a/native/calls.json
```

For automated native integration, set `OSREC_NATIVE_APPLICATION` and `OSREC_NATIVE_APPLICATION_ORACLE`, then run `python3 -m unittest discover -s tests -p test_linuxkernel_application.py`. This builds and exercises both link variants and executes the kernel-access guard test. The QEMU recorder's optional hardware observation is enabled by `--native-counters`; its ordinary recording mode is unchanged.

### Self-contained native executable

`export_native_checkpoint.py` packs an accepted native application package and its matching QEMU hardware recording into linked read-only assets. `lk_el0_native_open_image` restores these assets through the same validated loader used by directory-based execution; its source adapter creates anonymous memfds rather than opening or extracting package files. State and transcripts are copied into private instance storage, so the linked image is never modified. Sorted, nonoverlapping RAM extents preserve zero holes. The 855,662,592-byte logical physical store needs about 54 MiB of stored page data; each complete standalone ELF is about **55.8 MiB**, including the repository runtime, metadata, inputs and checks.

The standalone executable uses **no libc, CRT, compiler runtime or TLS**. It links with `-ffreestanding -nostdlib -static`, enters the repository’s `_start`, and calls arm64 Linux directly with `svc #0`. `standalone.c` implements the bounded host edge: mappings and anonymous memfds, signal installation/masks/alternate stacks, byte operations, allocation and buffered JSON output. `standalone_start.S` supplies the signal-return trampoline and register/stack jump recovery. The kernel signal-frame layouts come from Linux UAPI headers and have compile-time ABI checks. The executor owns one host thread; callable library builds keep their existing thread-local behavior.

The executable links with no ELF interpreter or dynamic dependencies, in a separate host-code window at 96 TiB. A small front-end allocation window at 28 TiB stays separate from captured mappings and the existing runtime metadata arena. Host page size comes from Linux’s initial auxiliary vector and must be 4 KiB. The captured application and kernel retain their established lower address layout. It runs with no arguments and prints a JSON verification result. `--describe` prints its embedded provenance and identity; `--trace OUTPUT.json` optionally writes observations. The runtime requires arm64 Linux with the existing page/layout constraints. Linux still supplies execution, mappings and signal frames; this is the native host deliverable. The bare RTL image remains a separate target.

Acceptance checks are embedded independently of execution. After the captured program reaches its boundary, the launcher compares every declared syscall/exception event with the embedded oracle, checks the exact completion PC and requires full counter/MMIO consumption. Expected results never feed the executed user/kernel code. Consecutive duplicate user-exception observations normalize as in the existing recording comparator. A corrupted expected result fails verification; a corrupted UART output expectation stops at the mismatching access and fails verification. Invalid image descriptors, out-of-range extents, truncated metadata and malformed counter records are rejected, with failure cleanup checked before a subsequent valid image load.

| Executable | Events verified | Counter inputs | MMIO accesses | Independent runtime test |
| --- | --- | --- | --- | --- |
| `build/standalone-checkpoint-20261109a/user-checkpoint` | 2,272, including 136 user exceptions | 9 | 209 | Read-only Alpine root, network disabled, only the executable mounted |
| `build/standalone-signals-checkpoint-20261109a/user-checkpoint` | 2,339, including 156 user exceptions and `rt_sigreturn` | 9 | 209 | Same isolation; no original source, state, oracle files or shared library mounted |

The validation reports are `build/standalone-checkpoint-validation-20261109b/validation.json` and `build/standalone-signals-validation-20261109b/validation.json`. Optional trace validation adds only an output directory mount and compares all events with QEMU. The default run mounts only the ELF. The generated build directory contains `payload.bin`, `image.c`, `image.S`, object files, `user-checkpoint.map` and a provenance manifest for review/rebuild; delivery needs only `user-checkpoint`. `verify_standalone` audits every linker input against the explicit repository object list and checks the ELF entry, absence of undefined symbols and absence of TLS. The link map is used only during build validation. A static ELF without imports alone would not establish that libc is absent.

Generate and build on arm64 Linux:

```sh
python3 tools/export_native_checkpoint.py \
  --package build/native-application-20261109a \
  --oracle build/native-application-oracle-20261109b \
  --out build/my-embedded-checkpoint --build
build/my-embedded-checkpoint/user-checkpoint
build/my-embedded-checkpoint/user-checkpoint --describe
```

Generation can also run on the image-build host; then build in the existing arm64 Linux environment with:

```sh
make -C runtime/linuxkernel_el0 CC=clang-19 AR=llvm-ar-19 \
  IMAGE="$PWD/build/my-embedded-checkpoint" standalone-checkpoint
python3 tools/check_embedded_checkpoint.py \
  --image build/my-embedded-checkpoint --oracle build/native-application-oracle-20261109b \
  --out build/my-embedded-validation
```

Use the canonical `standalone-checkpoint` target; the old embedded-link alias has been retired. `make -C runtime/linuxkernel_el0 CC=clang-19 check-standalone-host` exercises real Linux startup, allocation/syscall error handling, alternate-stack signal delivery and signal-mask-restoring jump recovery without libc.

The isolation validator requires a native arm64 Docker daemon and a local `alpine:3` image. `test_export_native_checkpoint.py` checks deterministic packing, byte-exact sparse reconstruction and malformed-input rejection on any build host. On arm64 Linux, `test_embedded_native_checkpoint.py` uses `OSREC_NATIVE_APPLICATION` and `OSREC_NATIVE_APPLICATION_ORACLE` to build/run a complete libc-free checkpoint, reject a changed embedded expectation, exercise loader failure cleanup, and reject a linker map containing a libc input. The established native runtime limits still apply; embedding does not add dynamic application loading, interrupts or retained-SVC interception.

## Reproducing the EL0 validation

On native arm64 Linux, build and test the public library front end:

```sh
make -C runtime/linuxkernel_el0 CC=clang-19 AR=llvm-ar-19
make -C runtime/linuxkernel_el0 check CC=clang-19 AR=llvm-ar-19
python3 -m unittest discover -s tests -p 'test_linuxkernel_el0.py'
```

The Makefile creates `build/liblinuxkernel-el0/liblinuxkernel-el0.a` and `.so`; `check` links and runs `checkpoint-archive` and `checkpoint-shared`. The linked fixtures use `tests/linuxkernel_el0_host.c`, an architecture/control-flow test backend, **not Linux syscall replacements or a native captured-kernel executor**. Each executable passes 128 paired veneer/SVC calls across persistent state and modeled return/handler/restart/`rt_sigreturn` continuations, plus malformed-input, nested/concurrent-call, missing-platform-action, poisoning and signal-mask recovery checks. The tested arm64 artifacts are in `build/liblinuxkernel-el0-20261110a`; the exported veneer was checked to be a four-byte B instruction. `source-image-el0-library-entry-20261110a/run` confirms all 2,272 native events still match after sharing the entry normalizer with the mini-OS. `source-image-el0-library-signals-20261110a/run` also matches all 2,339 native events, including 156 user exceptions, signal delivery and `rt_sigreturn`.

The tools use the repository's LLVM tools (`/opt/homebrew/opt/llvm@16/bin`) and `qemu-system-aarch64`. Keep the clang-19 kernel build and its DWARF database paired. Existing output directories are rejected.

```sh
python3 tools/source_image.py build --execution el0-minios \
  --dump build/kernel-state-el0-20261108b \
  --vmlinux build/linux-kernel-clang19-20261108/vmlinux \
  --dwarf-db build/linux-kernel-clang19-20261108/dwarf-db.json.gz \
  --profile integrations/linux_aarch64/source-image/fd-control.json \
  --out build/my-el0-image

python3 tools/source_image.py run --image build/my-el0-image \
  --out build/my-el0-run --memory --limit 20000

python3 tools/source_image.py native \
  --checkpoint build/linux-svc-machine-checkpoint-random-fault-20261108a/checkpoint \
  --select number=25 --select x0=3 --select x1=1 \
  --out build/my-native-run --memory --limit 20000

python3 tools/source_image.py compare \
  build/my-native-run/calls.json build/my-el0-run/calls.json

python3 -m unittest discover -s tests -p 'test_el0_runtime.py'
python3 -m unittest discover -s tests -p 'test_aarch64_liveness.py'
python3 -m unittest discover -s tests -p 'test_source_image_calls.py'
python3 -m unittest discover -s tests -p 'test_va_lowering.py'
python3 -m unittest discover -s tests -p 'test_source_image_memory.py'
python3 -m unittest discover -s tests -p 'test_kernel_state_probe.py'

OSREC_EL0_IMAGE=build/my-el0-image python3 -m unittest discover \
  -s tests -p 'test_el0_user_guard.py'
```

The image is self-contained at execution time. `run` additionally uses `manifest.json`, the profile and `vmlinux` for recording and symbol diagnostics. EL0 builds currently require whole text, full state, the original physical RAM placement and 4 KiB page tables. The monitor, tables and staging area live outside captured RAM; QEMU starts this image at EL1 with virtualization disabled. User-memory hashing rejects non-RAM mappings rather than reading MMIO with possible side effects.

Add `--el0-dispatch branches` to the build command to enable linked shadow-register veneers. Add `--lower-kernel 0x200000000000 --va-profile integrations/linux_aarch64/source-image/va-profile-48.json` to exercise the common 48-bit address layout. Rebuild branch images in full when changing the monitor: their linked state aliases depend on its layout, so the monitor-only `relink` command explicitly rejects them. On native arm64 Linux with clang/clang-19, `test_source_image_calls.py` also compiles and executes the 5,888 differential comparisons; other hosts skip that execution check.

Run the relocation inventory separately:

```sh
python3 tools/kernel_relocation_audit.py \
  --dump build/kernel-state-el0-20261108a \
  --vmlinux build/linux-kernel-clang19-20261108/vmlinux \
  --dwarf-db build/linux-kernel-clang19-20261108/dwarf-db.json.gz \
  --out build/relocation-review.json
```

Inside the existing clang-19 container with the pinned source mounted at its original path and the read-only build volume mounted at `/kbuild`:

```sh
python3 /work/tools/kernel_source_verify.py --all --build /kbuild \
  --workers 8 --out /work/build/whole-kernel-source-verification.json
```

The report's `complete`, `verified_bytes` and `gaps` determine coverage. Unknown relocation fields are not counted as verified. The full verifier exits nonzero when coverage is incomplete. It also includes sized assembler code symbols whose ELF type is NOTYPE; the saved full-compile report predates that additional coverage, so 96.6% is a lower bound for the current verifier.

## Local validation artifacts

Build artifacts are local construction and validation outputs, excluded from Git. The captured-workload executable and load plan are retained in `build/el0-program-20261110c`; the supplied-user-ELF executable, Linux baseline and repeat-build comparison are in `build/el0-new-application-20261111b`. Their validation scope is described in the [demo report](el0-native-demo.md).

Consolidation checks use a source-only snapshot in `build/consolidation-20261111/source`, with generated kernel excerpt trees rebuilt from the shared store. Its separate CMake build and regression logs are under `build/consolidation-20261111`. Native and QEMU application checks of the retained supplied-user-ELF executable were also rerun there. These are functional checks; RTL execution and cycle measurements remain pending.

The November 11 consolidation passed all 23 default CTest suites and 529 entry-state regressions. The Linux profile batch passed 134 cases; its four fd-control cases passed on rerun after recapturing the fixture against the current source review. The recapture preserves the prior syscall observations and init binary. Additional EL0 checks passed 36 cases with nine conditional skips, and source/architecture checks passed 47 with one conditional skip. Counts overlap between suites. A fresh AArch64 constructor build is byte-identical to the constructor in `build/libkernel-capsule-20261111b`; both static/shared library contract executables and the standalone-host checks pass. The optional kernel-layout overlay passed header-generation and shell-syntax checks; a complete kernel rebuild with that overlay remains unvalidated.

The subsequent mainline cleanup registers the shared ELF audit and memory/gateway checks in default CTest, bringing it to 25 passing suites. Native validation of the complete 2,272-event workload and its corrupted-result and executable-map negative tests passes after extracting the shared audit. The fixture-independent gateway test also passes on AArch64 Linux and rejects a damaged register restore. Cleanup logs and QEMU validation are under `build/main-cleanup-20261111`.
