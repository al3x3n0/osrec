# Linux ARM replay

For the stateful local-gateway approach using original Linux syscall bodies on AArch64, see [minimal AArch64 Linux syscall slices](linux-aarch64-slices.md). The older ARMv7 replay workflow below runs the captured LiteOS-A scenario through a Linux ABI adapter.

The captured LiteOS-A scenario can be rebuilt as a static ARMv7 Linux EABI5
ELF. It embeds the same checkpoint, transcript and expected observations as
the macOS replay. The original pinned `SysRead` and dependency models are
regenerated after validating the original artifact hash and capture identity.

The Linux runtime supplies startup, write/exit syscalls and the few
string/memory operations used by replay. It has no allocator or dynamic loader.
The unused JSON capture printer is not linked. The `--describe` embedded
metadata interface remains available. Kernel reads still use the recorded
dependency models rather than issuing Linux read syscalls.

Build on the current macOS host:

```sh
python3 tools/linux_arm_replay.py \
  --replay build/live-liteos-final/replay \
  --out build/linux-arm-replay-new --build-only
```

Run the resulting binary on a Linux host with QEMU user mode installed:

```sh
qemu-arm -cpu cortex-a7 ./replay
echo "$?"
qemu-arm -cpu cortex-a7 ./replay --describe
```

Expected normal output is `syscall session verified: 4 calls`, with exit status
zero. No input file or sidecar is required at runtime. The current artifact is
`build/linux-arm-replay/replay`; its build report is in the same directory.

Without `--build-only`, the tool requires `qemu-arm`, runs the copied binary
in an isolated directory, checks all replay observations through its exit
status, and compares `--describe` output with the original metadata. Supply
`--llvm-bin` on hosts with LLVM installed elsewhere.

Current validation: cross-compilation succeeded; ELF headers confirm ARM,
EABI5 and static executable segments; the symbol table has no undefined
symbols. **Execution under `qemu-arm` has not been verified** on this macOS
host: it has only QEMU system emulators, downloads fail DNS resolution, and
access to the Docker daemon socket is denied. The report therefore records
`qemu_verified: false`.

Scheduling and interrupt replay remains outside this scenario's contract.

## Measured execution with the installed QEMU system emulator

The unchanged ELF has now executed successfully under `qemu-system-arm` on a
Cortex-A7, using a limited Linux ABI adapter for `write` and `exit`. This is
user-mode ARM execution with an MMU, but is neither a Linux kernel boot nor a
`qemu-arm` run. The adapter loads the ELF segments at their linked virtual
addresses, supplies the initial argument stack, enters ARM user mode, and
handles its Linux SVC calls. UART supplies output; semihosting terminates the
adapter with the ELF's exit status. No file reads or kernel dependency models
are replaced in the replay binary.

```sh
python3 tools/qemu_linux_abi_replay.py \
  --elf build/linux-arm-replay/replay \
  --out build/linux-arm-qemu-new
```

The verified run is in `build/linux-arm-qemu-count-v2`. It printed
`syscall session verified: 4 calls` and exited with status zero. A separate
`--describe` run matched the original embedded metadata.

The normal replay executed **57,513 ELF instructions**, including **105 in
`SysRead` across four calls**. QEMU TCG used `one-insn-per-tb=on` with
`exec,nochain`, so every logged translation-block execution represents one
instruction. The address filter and ELF executable-segment check exclude
adapter instructions. The raw trace has exactly 57,513 execution records,
and disjoint function totals sum to the same count. This includes startup,
state restoration, models, validation and diagnostics; it does not measure
the live kernel path or recorder overhead.

This `-O0` build spends 47,526 instructions in its byte-loop `memcpy` and
`memset` implementations. The count therefore characterizes this exact
debug artifact, rather than an optimized slice. The report binds the count
to the ELF, adapter and trace hashes. The separate metadata-printing run is
excluded from the normal replay count.
