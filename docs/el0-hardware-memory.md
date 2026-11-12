# Hardware-backed kernel memory at EL0

The complete executor has an optional `--hardware-memory` backend. It uses the
captured QEMU kernel mappings to construct EL0-accessible hardware aliases of
canonical RAM. Eligible kernel loads and stores execute natively without
entering the context gateway or walking the captured page tables in software.
Stack-pointer arithmetic also executes inline, including when application code
uses its logical stack. The actual SP remains private to the runtime.

The aliases point to `flat_phys + captured_pa - ram_base`. Multiple virtual
aliases therefore refer to the same physical bytes used by the software path,
kernel page tables, allocator and validation. Physical UART/device addresses
are excluded. Read-only mappings remain read-only; the inline store ranges also
exclude every physical alias of admitted immutable code.

## Execution contract

The processor model establishes the hardware tables before ELF entry. Its
initialization can use privileged operations; the delivered checkpoint does not.
After entry, startup, user instructions, captured kernel computation, adapters
and validation all execute at EL0. Ordinary memory operations use the hardware
MMU after an inline range/mode check, preserving scratch registers and NZCV on
the private stack. Pre/post-index writeback is handled inline. No adaptation is
inserted inside an exclusive window.

This backend retains software handling for changing user mappings, explicit
user-copy accesses, exclusive windows, device inputs and unsupported operations.
The existing workload's demand faults are detected in software and execute the
captured kernel fault path. They do not cause hardware exceptions. Eliminating
those kernel fault computations would change the captured workload.

The hardware run reproduced all 2,272 events, nine counter inputs and 92 UART
bytes with zero hardware exceptions. Its 289,959 gateway entries were down from
approximately 2,261,577 in the software backend, a reduction of about 87%.
The validation artifact is linked below. These are gateway counts, not
instruction or cycle counts; they do not establish a processor timing speedup.

## Build and validate

Export from the existing captured package and independent reference:

```sh
python3 tools/export_el0_program.py \
  --package build/native-application-20261109a \
  --vmlinux build/linux-kernel-clang19-20261108/vmlinux \
  --user-elf build/linux-svc-machine-checkpoint-random-fault-20261108a/init \
  --oracle build/native-application-oracle-20261109b \
  --coverage build/el0-program-reference-code-20261109a.log \
  --hardware-memory --out build/my-hardware-executor

# On the existing AArch64 Linux toolchain host:
make -C runtime/el0_flat CC=clang-19 \
  OUT="$PWD/build/my-hardware-runtime" \
  IMAGE="$PWD/build/my-hardware-executor" program

python3 tools/el0_hardware_model.py prepare \
  --image build/my-hardware-executor --out build/my-hardware-model
python3 tools/el0_hardware_model.py run \
  --image build/my-hardware-executor --prepared build/my-hardware-model \
  --out build/my-hardware-validation
```

The existing LLVM 16 toolchain can also cross-build locally using
`CC='/opt/homebrew/opt/llvm@16/bin/clang --target=aarch64-none-elf'`.
Preparation defaults to the same LLVM directory; `--llvm` selects another one.

Preparation audits the ELF, binds the mapping metadata to the export, constructs
`page-tables.bin`, and writes `hardware-load-plan.json`. The plan specifies normal
RAM extents, ELF initialization, page-table bytes, initial architectural controls,
EL0 entry, completion PC and the RAM result. The current QEMU setup uses 2 GiB
of RAM and 4 KiB pages. It is separate from the older software-memory load plan;
Linux native and QEMU application-mode loaders cannot provide these aliases.

`setup.elf` is a QEMU initialization fixture, not an EL1 execution monitor. It
installs the declared tables and enters the checkpoint once. Every subsequent
exception vector stops rather than services or resumes the computation. The
runner checks EL0 at entry and completion and reads the embedded result before
terminal exit. A removed kernel alias is a negative regression: it must reach
the unexpected-exception stop and fail validation.

Current artifacts:

- [Executor](../build/el0-hardware-memory-20261112b/checkpoint)
- [Model load plan](../build/el0-hardware-model-20261112b/hardware-load-plan.json)
- [Functional validation](../build/el0-hardware-validation-20261112c/validation.json)

The target-independent tests are registered as `el0_hardware` in CTest. Running
the same test module on AArch64 Linux also executes instruction-level checks for
scalar/SIMD memory, register offsets, logical SP, indexed writeback, scratch/flag
preservation and rejection paths. Set `OSREC_EL0_HARDWARE_IMAGE` and
`OSREC_EL0_HARDWARE_PREPARED` to run the complete positive and missing-alias QEMU
checks. Hardware execution on RTL and instruction/cycle measurements remain
unverified.
