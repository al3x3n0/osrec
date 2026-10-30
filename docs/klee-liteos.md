# Combined user/kernel analysis with KLEE

KLEE is an offline execution and test-generation stage. The kernel recorder still captures concrete state and observations with bounded hooks. KLEE can then execute selected user and kernel code together, find alternative paths within an explicit model, and generate concrete cases for native replay. KLEE operates on LLVM bitcode and exposes symbolic input objects through `klee_make_symbolic`. [KLEE function-testing tutorial](https://klee-se.org/tutorials/testing-function/)

```text
Planned device capture                   Implemented offline scenario
----------------------                  ----------------------------
user request                            user application + read/errno adapter
     |                                                   |
syscall entry + checkpoint              pinned LiteOS-A SysRead body
     |                                                   |
selected kernel execution               explicit address / FD / VFS models
     |                                                   |
context + external observations         linked LLVM bitcode
     |                                                   |
completed capture ------ future ------> concrete replay / symbolic exploration
                                                         |
                                                 KTest -> native executable
                                                         |
                                                 output + effect checks
```

The connection from device capture to this scenario is not implemented. Its current seed declares `synthetic model seed; not captured from a running kernel`. Both symbolic modes explore user inputs; neither is an exact replay of a captured syscall invocation.

## Source and execution boundary

The first slice uses [OpenHarmony LiteOS-A](https://github.com/openharmony/kernel_liteos_a) revision `4ac7f3aed67000b47bc14d6fe79d63ada708d780`. `source-lock.json` pins the revision, full `syscall/fs_syscall.c` hash and extracted `SysRead` body hash. The runner preserves the upstream BSD license and source line mapping, and rejects a changed revision or file before extraction.

The original function body executes unchanged, with a compatibility prelude redirecting its external dependencies to named models. This retains its zero-length return, address-check ordering, descriptor translation, backend call and negative errno conversion. The user program calls it through an explicit C read/errno adapter and examines returned data.

| Component | Current treatment |
| --- | --- |
| User application | Executed C program; recognizes a leading `A` in successful reads |
| User syscall wrapper | Executed model of direct dispatch and errno translation; target musl and SVC entry excluded |
| `SysRead` | Extracted, hash-checked kernel function body |
| User-address predicate | One registered eight-byte host buffer; no MMU or target virtual address checks |
| Process descriptor table | User descriptor 3 maps to system descriptor 17; others map to an invalid descriptor |
| VFS/driver read | Four payload bytes, short reads, EBADF, EINTR and EIO; no real VFS or driver execution |
| Scheduler, IRQs, shared memory races | Excluded from this scenario |

Syscall scalar widths are 32 bits; pointers use host width. This is a functional abstraction, not the full ARM ABI. Native execution and KLEE use the same dependency models, so their agreement cannot establish those models' fidelity to a booted kernel.

## Exploration and checks

The request has three symbolic fields: descriptor 0–4, byte count 0–9 and null-buffer selector 0–1. Count 9 deliberately exceeds the modeled eight-byte buffer. The application and kernel slice share the same memory object.

| Mode | User request | Modeled environment |
| --- | --- | --- |
| `fixed` | Symbolic within request bounds | Concrete successful backend and four seed payload bytes |
| `explore` | Symbolic within request bounds | Symbolic success/EINTR/EIO selector and four symbolic payload bytes |

Checks cover return values, errno translation, application recognition, copied bytes, untouched buffer bytes and boundary invocation counts. Zero-length reads must bypass address, descriptor and VFS checks. Invalid addresses must bypass descriptor and VFS calls. These assertions describe this model's supported contract.

The native harness separately enumerates 300 combinations of request fields and backend outcome with the seed payload. KLEE produces representative concrete tests for explored paths, not one test for every possible input value. Every generated test is parsed with bounded KTest framing and replayed through the native combined executable.

The runner uses Z3, disables ordinary external calls, rejects unexpected undefined bitcode symbols, limits each exploration to 30 seconds and 512 MB, and rejects error files, nonzero exits, missing summaries or partially completed paths. KLEE's external-call policy matters because calling host functions can lose the intended symbolic behavior. [KLEE options](https://klee-se.org/docs/options/)

## Reproduce the run

```sh
git clone https://github.com/openharmony/kernel_liteos_a.git build/kernel_liteos_a
git -C build/kernel_liteos_a checkout 4ac7f3aed67000b47bc14d6fe79d63ada708d780
python3 tools/klee_liteos.py \
  --kernel-root build/kernel_liteos_a \
  --out build/klee-liteos \
  --llvm-bin /opt/homebrew/opt/llvm@16/bin \
  --klee-include /opt/homebrew/opt/klee/include --run
```

An existing checkout can be supplied with `--kernel-root`. Omit `--run` to compile the scenario and run native checks without symbolic exploration. `--klee` selects the executable; its LLVM major must match the bitcode compiler. The validated installation is KLEE 3.2 with LLVM 16.0.6. The optional LLVM 22 recorder planner remains a separate pipeline; do not link its bitcode directly into the LLVM 16 module.

Output contains generated source, seed configuration, both linked bitcode modules, the native executable, KLEE directories and logs, plus a manifest recording source/seed/model/runner hashes, tool versions, artifact hashes and completed test counts. Generated outputs and the kernel checkout live under ignored `build/`.

CTest integration is optional:

```sh
cmake -S . -B build/klee-check -G Ninja \
  -DOSREC_BUILD_LITEOS_KLEE_SCENARIO=ON
cmake --build build/klee-check
ctest --test-dir build/klee-check --output-on-failure
```

Override `OSREC_LITEOS_SOURCE`, `OSREC_KLEE_LLVM_BIN` and `OSREC_KLEE_INCLUDE` for different paths. The option also enables trace analysis and standalone export regressions; enabling the LLVM planner and EL0 analysis/extraction with the default object-checkpoint checks yields sixteen test suites. A separate LLVM 16 EL0 build supports [symbolically verified scalar export](el0-export.md).

Validation in this workspace completed 8 fixed-environment paths and 9 exploratory-environment paths, with zero partial paths and all 17 generated tests passing native replay. The original eight suites passed, including bounded trace analysis and standalone export; EL0 analysis and extraction add separate suites. The installed toolchain reports an `arm64-apple-macosx15.0.0` versus `arm64-apple-darwin24.5.0` module/host triple mismatch in saved logs; these runs completed, but a consistent target configuration should be established before expanding the integration. No target-device execution or timing claim follows from these results.

## Extend toward capture and asynchronous execution

First connect a concrete capture to object restoration and an ordered external transcript. In faithful replay, keep captured arguments, payloads and outcomes concrete and verify each interaction's site, occurrence and arguments. In exploratory mode, explicitly mark which user or environment fields may vary; an alternative device outcome describes a different execution.

Then include a bounded blocking syscall path and the relevant wait, wakeup and interrupt code or reviewed effect models. Existing LiteOS-A integration points include `OsArmA32SyscallHandle` in `syscall/los_syscall.c`, `OsTaskSchedule`/`OsSchedResched` in `kernel/base/sched/los_sched.c`, and interrupt handling in `arch/arm/arm/src/los_hwi.c`. These are inspected candidate locations, not installed recorder hooks.

KLEE does not automatically deliver hardware interrupts or reconstruct scheduling. Expose supported event boundaries and bounded event choices, preserve wait-object generations and causal dependencies, and reject unsupported interleavings. Ordinary sequential LLVM execution cannot reproduce arbitrary SMP observations. Include the necessary synchronization/memory model or restrict the contract explicitly.

Avoid using KLEE's POSIX runtime to service the intended LiteOS-A syscall: that runtime supplies a separate environment model rather than executing this kernel's implementation. Link the selected kernel closure and resolve its dependencies explicitly. [KLEE project overview](https://github.com/klee/klee)

For lower recorder overhead, the implemented [trace analysis](trace-analysis.md) checks whether equal retained observations can hide different declared outputs or effects, then verifies replay driven by the selected projection. The current candidate fields are manually specified external-boundary observations; connecting static memory analysis to candidate generation remains planned. An exhausted bounded search supports only the included code, models and interleavings; it does not prove correctness for the whole kernel. Runtime overhead savings still require measurements of real recorder hooks on the selected device.
