# Fixed-mapping IPC replay in QEMU Linux-user

The 640-iteration IPC workload completed with **0.3311 runtime instructions per
kernel instruction** at 10 million kernel instructions. The full run dispatched
10,779,406 kernel instructions, 3,579,622 runtime instructions and 97,373
application instructions.

| Replay variant | Runtime instructions per kernel instruction at 10M kernel instructions |
| --- | ---: |
| Mapping refresh and full signal-context copies | 83.8888 |
| Fixed mappings and in-place FPSIMD state | 29.5688 |
| Inline register operations and direct memory accesses | 1.7859 |
| Inline result observer and native sign tests | 0.7696 |
| In-place syscall transitions | **0.3311** |

The prepared capture populates all ELF load segments before execution. The
Linux-user process retains the user and kernel mappings throughout the replay.
The final variant rejects any call to the address translator or mapping
synchronizer during execution. Captured EL1 register operations use EL0
instructions and shadow state. Memory instructions access the installed
addresses directly. The result observer uses the captured syscall's return
slot, and the syscall transitions update the existing signal frame in place.

The experiment assumes a trusted application, fixed mapping permissions, and
the captured kernel's syscall frame layout. It specializes the observed return
site and uses native `DC ZVA` when the capture and emulator agree on
`DCZID_EL0`. Signal delivery remains for syscall entry and return and for UART
MMIO. The final run issued 16,678 `rt_sigreturn` calls during the measured
interval. These were the only host syscall requests observed by the plugin.

## Replay inputs and accounting

- QEMU 10.0.13 with plugins, Linux user mode, AArch64 Cortex-A53.
- Prepared process checkpoint identity
  `7b25fe323102adcad2b01c94d19b6a319f30c997122d5ad97b8058eb51d7a0eb`.
- The interval runs from the user ELF entry at `0x201160` through the
  instruction before `do_exit` at `0x800080059b50`.
- The plugin counts instructions in the original kernel executable ranges as
  kernel instructions, except breakpoint replacements. It counts the user
  executable ranges separately and attributes the remaining instructions,
  including inline veneers outside kernel text, to runtime. Replacing
  breakpoints with executable instructions can increase the kernel count.
  QEMU's own instructions and the host kernel are outside the measurement.

All five replay artifacts matched the native reference byte for byte. This
includes 8,322 syscall entries, 8,321 returns, 35 UART operations, and the
`OSREC_IPC_PASS` console line. The final `exit(0)` reached the expected
boundary. No user fault appeared in the ledger.

| Artifact | SHA-256 |
| --- | --- |
| `calls.json` | `ed4d08c3d4bf5aee5fc46d21722f0371191c826b2df961cf2394f3d37e317e2f` |
| `console.txt` | `e46f7c7d59494106ef0fa175ad7b6212cace7e2afbe9ac7174d8ccd1ccc3fd57` |
| `counters.bin` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `mmio.bin` | `05a8ad0b25de2d61479548bdb60b607d9683da9ccc2f12cc28a11f643e929607` |
| `stdout.json` | `ea585d80665496ac616ecb045284b17463509f5d15c23d67f3962cf8231fb828` |

## Build the experimental reader

Use an isolated checkout and a Linux AArch64 build environment. Build the
standard archive before applying the [experiment patch](../tools/experiments/linux-user-fixed-ipc.patch).
Build the experimental object explicitly so the standard checkpoint preparation
tool can still link to the original backend.

```sh
make -C runtime/linuxkernel_el0 CC=clang-19 OUT=/work/linuxkernel /work/linuxkernel/liblinuxkernel-el0.a
git apply tools/experiments/linux-user-fixed-ipc.patch
clang-19 -O2 -g -fPIC -Wall -Wextra -Werror -mgeneral-regs-only \
  -Iinclude -Iruntime/el0 -Iruntime/linuxkernel_el0 -DOSREC_LOWERED -DOSREC_NATIVE \
  -c runtime/linuxkernel_el0/native.c -o /work/fixed-ipc.o
clang-19 -O2 -mgeneral-regs-only -Iinclude -Iruntime/el0 -Itools \
  -static -Wl,-Ttext-segment=0x600000000000 tools/linuxkernel_prepare_application.c \
  /work/fixed-ipc.o /work/linuxkernel/liblinuxkernel-el0.a -o /work/fixed-ipc-reader
```

The [plugin](../tools/qemu_plugins/linux_user_ipc.c) expects
`/work/kernel-ranges.bin` and `/work/user-ranges.bin`. Each contains
little-endian pairs of 64-bit executable range bounds, using the lowered
capture's kernel addresses and the user ELF addresses. Place the prepared
checkpoint in `/work/prepared` and set `QEMU_INCLUDE` to the directory
containing QEMU 10.0.13's `qemu-plugin.h`.

```sh
clang-19 -O2 -shared -fPIC -Wall -Wextra -Werror -I"$QEMU_INCLUDE" \
  $(pkg-config --cflags --libs glib-2.0) tools/qemu_plugins/linux_user_ipc.c \
  -o /work/linux-user-ipc.so
mkdir -p /work/profile-direct-transitions-ipc
qemu-aarch64 -s 524288 -cpu cortex-a53 -plugin /work/linux-user-ipc.so \
  /work/fixed-ipc-reader record /work/prepared /work/profile-direct-transitions-ipc \
  124338841 1024 0x80008000e000 0x800080059b50 \
  >/work/profile-direct-transitions-ipc/stdout.json
```
