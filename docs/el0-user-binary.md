# Build an EL0 executor from a supplied user binary

`tools/el0_application.py build` combines a reusable libkernel capsule with a separately supplied static AArch64 ELF. The captured kernel runs its real `execveat` path during construction, creating the new address space, stack, arguments and auxiliary vector. The delivered executable starts the user program at its ELF entry point and runs its SVCs through captured kernel code. Startup, user code, kernel computation and adapters all execute at EL0, with RAM as their only required architectural external effect.

## Prepare libkernel once

A capsule contains captured kernel code and post-boot state, a construction helper, typed process-layout offsets and hardware-input settings. Its manifest binds every asset by SHA-256. Create it on a construction host with the existing captured package and its matching kernel build:

```sh
make -C runtime/linuxkernel_el0 CC=clang-19 \
  OUT="$PWD/build/process-loader" prepare-application
python3 -B tools/el0_application.py kernel \
  --package build/native-application-20261109a \
  --vmlinux build/linux-kernel-clang19-20261108/vmlinux \
  --dwarf-db build/linux-kernel-clang19-20261108/dwarf-db.json.gz \
  --constructor build/process-loader/prepare-application \
  --coverage build/el0-program-reference-code-20261109a.log \
  --out build/libkernel
```

The helper requires AArch64 Linux. The public builder runs it in isolated Docker containers; the example toolchain image is `osrec-kbuild-clang19:latest`. Coverage is optional and only broadens the set of complete kernel functions emitted as code.

Preparation records narrowly checked repairs to the captured relocation: scalar argument/bitmap/flag constants retain their original instructions, and a shared page-table directory alias preserves unmoved per-CPU mappings. Different instruction patterns retain their conservative stops. The capsule also declares `do_exit` entry as its terminal boundary, before PID 1 teardown.

## Supply and build a program

```sh
make -C examples/el0-user CC=clang-19
python3 -B tools/el0_application.py build \
  --libkernel build/libkernel \
  --user-elf build/el0-user/program --arg demo \
  --linux-baseline \
  --out build/user-executor
```

The initial admission supports static, non-PIE AArch64 `ET_EXEC` binaries with immutable executable pages, valid sections and AArch64 code/data mapping symbols. PT_LOAD addresses must be below 1 TiB; interpreters, dynamic loading and writable executable segments are rejected. The binary must contain SVC instructions. Scheduling waits, new devices and unsupported instructions stop explicitly.

The builder closes inherited descriptors above stderr, loads the ELF through a memfd and real kernel `execveat`, populates executable pages, then snapshots the new process at entry. Standard descriptors and other process resources come from the template. Arguments use `argv[0]="program"`, repeated `--arg` values and an empty environment.

It records a native captured-kernel reference with deterministic counter values and a RAM PL011 model, checks the expected terminal exit status, and lowers native code. A missing indirect kernel target triggers inclusion of that complete function and another run from initial state, bounded to 12 attempts. Other failures stop. This reference is distinct from the original demo's independent live-Linux oracle.

`--linux-baseline` additionally runs the unmodified ELF using the Linux host's real syscalls, with the same arguments and empty environment. It checks the program exit status and stdout against captured execution; captured UART CRLF becomes LF for comparison with pipe output. The check is optional because the host process's credentials, descriptors, filesystem and other state can differ from the template. It does not compare individual syscalls or kernel state. The helper records exec failures and signal termination separately from program exit status, and the builder stops its baseline container on timeout. This option requires constructor ABI 2; rebuild older capsules with the current helper. Existing ABI 1 capsules continue to build without it.

## Deliver and inspect

The output contains `program/checkpoint`, `program/load-plan.json`, `application.json`, reference events and validation reports. Default validation runs the same executable natively and in QEMU application mode on Cortex-A53. When requested, `linux-baseline/validation.json` records the original ELF's Linux result, kernel version, identity and comparison scope. `--no-validate` still audits the image and emits a load plan, but leaves delivery execution unverified. `--expect-exit` selects a different expected program status.

Delivery embeds state and inputs and uses no libc, loader, runtime files, host signals, host clock or physical UART. Stop at the load plan's completion PC and inspect its RAM result, or allow the optional terminal exit. Construction's `execveat` and host services are outside delivery and its measurement interval.

The [simulator-neutral GDB runner](el0-model-runner.md) loads or verifies those segments, checks EL0 entry, and reads the RAM result at a hardware completion breakpoint before terminal exit.

The example checks argc/argv/auxv, demand-zero memory, a checksum and memfd write/seek/read/close, then prints `OSREC_USER_ELF_PASS` and requests exit(0). It supplies a new ELF rather than resuming the original captured user workload.
