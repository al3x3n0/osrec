# OSREC native checkpoint demo

The demo packages a captured AArch64 user program, Linux kernel code and initial state into one standalone executable. It resumes a post-boot checkpoint and reproduces the complete captured workload, providing a functional baseline for processor microarchitecture research.

## User workload

The user program is a small C stress test originally running as Linux PID 1, with direct syscall instructions and no libc. A fixed test sequence is followed by 2,000 seeded random operations. It exercises memfd files, descriptor duplication and flags, ordinary and vectored I/O, file truncation, anonymous mappings, demand-zero page faults, futex operations and error paths. User code also performs buffer manipulation, pseudorandom generation and checksum verification. Futex cases return immediately or use uncontended locks.

## Execution scheme

Startup, user code, captured kernel code, runtime adapters and verification all execute at EL0. The executor restores registers and RAM, then follows the captured syscall entry, dispatch, kernel computation, fault handling and return paths. Ordinary computation runs as native instructions; adapters handle memory addresses, guest stack operations and privileged architectural state.

Kernel objects and page tables live in canonical RAM. UART output is collected in RAM, and timer observations come from embedded inputs. Execution requires no libc, dynamic loader, runtime files, host signal handlers or physical devices. The only host service is optional terminal exit; a processor model can instead stop at the declared completion PC and inspect the RAM result.

## Validation results

The identical executable passes native AArch64 execution and QEMU application mode with Cortex-A53 selected.

| Observation | Result |
| --- | ---: |
| Syscalls | 2,136 across 20 syscall numbers |
| Fault events | 136 |
| Total events matched against the reference | 2,272 |
| Embedded timer inputs consumed | 9 |
| UART output matched | 92 bytes |
| Gateway transitions in the recorded native run | 2,261,577 |

Negative tests reject a corrupted expected result and a changed executable mapping. Gateway transitions are adaptation calls, not executed-instruction counts; native exclusive-store retries can change their number slightly between runs.

## Scope

This demo validates one captured process on one CPU with fixed inputs. Contended scheduling and hardware interrupt replay are outside its scope. Full-workload dynamic instruction counts and RTL or cycle-accurate model validation remain pending.

The [executable](../build/el0-program-20261110c/checkpoint), [model load plan](../build/el0-program-20261110c/load-plan.json), [native validation](../build/el0-program-validation-20261110d/validation.json) and [QEMU validation](../build/el0-program-qemu-app-20261110a/validation.json) are available in the workspace. See [execution details](source-image-flow.md#complete-userkernel-checkpoint) for construction and reproduction commands.

## Separately supplied binary

The [user-binary workflow](el0-user-binary.md) now initializes a different static ELF through the captured kernel's real `execveat`, then builds another standalone EL0 executable. Its example validates arguments and auxv, demand-zero memory and memfd I/O. Native AArch64 and QEMU application mode both pass: 10 syscalls, 5 fault events and 21 UART bytes, ending at the declared `do_exit` entry boundary with user exit status zero. Construction consumes 8 deterministic counter values; this program's execution consumes none.

The latest [executable and load plan](../build/el0-new-application-20261111b/program/), [build report](../build/el0-new-application-20261111b/application.json), [native validation](../build/el0-new-application-20261111b/native-validation-1/validation.json) and [QEMU validation](../build/el0-new-application-20261111b/qemu-validation/validation.json) are available in the workspace. This case compares against native captured-kernel execution with deterministic RAM inputs; the independent live-Linux oracle applies to the original captured workload above.

A subsequent [Linux baseline](../build/el0-new-application-20261111a/linux-baseline/validation.json) runs the unmodified example ELF on AArch64 Linux 6.10.14-linuxkit. Exit status and stdout match captured execution after UART CRLF normalization. This checks program-visible results, without comparing individual syscalls or kernel state. A [repeat-build comparison](../build/el0-new-application-20261111b/reproducibility.json) confirms identical initialized state, reference events/inputs, standalone executable and model load plan from the same capsule assets, ELF, arguments and expected exit. Both builds pass native and QEMU application checks.
