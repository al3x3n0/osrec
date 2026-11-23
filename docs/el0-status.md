# EL0 replay status · 2026-11-23

The current IPC result uses the direct transition experiment. The IPC report
includes the original direct-transition benchmark from `26bdf40` on `main`.

The modeling path starts at the user ELF's saved entry, then executes the
captured kernel's syscall code in the same EL0 address space. The harness
installs the user and kernel mappings before entry. Privileged instructions
that the workload needs use EL0 sequences or shadow architectural state.

## Verified runs

- The 640-iteration pipe and eventfd workload completed in QEMU Linux-user
  on Cortex-A53 with **5.09% runtime instruction overhead** at 10 million
  kernel instructions, down from 7.23%. The full run counted
  10,779,406 kernel, 558,981 runtime, and 97,373 application instructions.
  All 8,322 syscall entries, 8,321 returns, and 35 UART operations matched
  the native reference. The ledger recorded zero user faults. The run
  rejected any runtime address translation or mapping refresh. The opt-in
  patch, inputs, and replay command are in the [IPC report](el0-linux-user-ipc.md).
- The Apple Silicon native ELF loader reproduced the original random/fault
  workload's 2,272 events and 92 output bytes. Its whole-kernel IPC smoke
  test matched 16 events and verified the saved user entry against the input
  ELF. The [macOS loader guide](el0-macos.md#native-process-runner) describes the
  loader and the direct-memory build flags.
- The clustered IPC checkpoint ran on AArch64 Linux with 4 KiB pages and
  matched 16 events, 16 UART bytes, and exit status zero. See the
  [user-binary builder](el0-user-binary.md#nonblocking-ipc-on-apple-silicon)
  and [presentation](slides/README.md#detailed-el0-checkpoint-flow).

## Open validation

- The 640-iteration direct-memory run still needs a native macOS capture
  whose relocated addresses, backing, and permissions fit the loader's
  16 KiB host pages. The existing IPC capture requires a different layout.
  The [alias projection command](el0-macos.md#checking-a-capture-for-native-mappings)
  reports which ranges block installation.
- The direct syscall transitions are specific to the captured IPC workload.
  UART MMIO accounted for the 35 remaining `rt_sigreturn` calls in the measured
  window. Timing and microarchitectural validation remain pending. See the
  [model runner](el0-model-runner.md).
- The clustered ELF still needs execution on an Android device.
