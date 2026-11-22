# Fixed-mapping IPC replay in QEMU Linux-user

The 640-iteration IPC workload completed with **9.70% runtime instruction
overhead** at 10 million kernel instructions, down from 33.11% in the previous
run. The full run dispatched 10,779,406 kernel instructions, 1,055,672 runtime
instructions and 97,373 application instructions.

| Replay variant | Runtime instructions per kernel instruction at 10M kernel instructions |
| --- | ---: |
| Mapping refresh and full signal-context copies | 83.8888 |
| Fixed mappings and in-place FPSIMD state | 29.5688 |
| Inline register operations and direct memory accesses | 1.7859 |
| Inline result observer and native sign tests | 0.7696 |
| In-place signal-frame syscall transitions | 0.3311 |
| Direct syscall transitions and inline shadow-register accesses | **0.0970** |

The prepared capture populates all ELF load segments before execution. The
Linux-user process retains the user and kernel mappings throughout the replay.
The final variant rejects any call to the address translator or mapping
synchronizer during execution. Captured EL1 register operations use EL0
instructions and shadow state. Memory instructions access the installed
addresses directly. The result observer uses the captured syscall's return
slot to complete the event ledger.

The experiment assumes a trusted application, fixed mapping permissions, and
the captured kernel's syscall frame layout. It specializes the observed return
site and uses native `DC ZVA` when the capture and emulator agree on
`DCZID_EL0`. The direct transition patch uses the fixed IPC trace to reserve
`x18` as a pointer to replay state and preserves the guest register value at
its traced uses. Syscall gateways branch to the captured EL0 vector. The
return stub restores user state and branches through the matching gateway.
The measured interval included 35 `rt_sigreturn` calls for UART MMIO, down
from 16,678. These were the only host syscall requests observed by the plugin.

## Replay inputs and accounting

- QEMU 10.0.13 with plugins, Linux user mode, AArch64 Cortex-A53.
- Prepared process checkpoint identity
  `7b25fe323102adcad2b01c94d19b6a319f30c997122d5ad97b8058eb51d7a0eb`.
- The interval runs from the user ELF entry at `0x201160` through the
  instruction before `do_exit` at `0x800080059b50`.
- The plugin counts instructions in the original kernel executable ranges as
  kernel instructions, except breakpoint replacements. It counts the user
  executable ranges separately and attributes the remaining instructions,
  including inline veneers outside kernel text, to runtime. It charges the
  lowered return instruction at `0x80008001217c` to runtime in both variants.
  QEMU's own instructions and the host kernel are outside the measurement.

The direct run matched all five recorded replay artifacts byte for byte. This
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
tool can still link to the original backend. The
[direct transition patch](../tools/experiments/linux-user-ipc-direct-transitions.patch)
layers on top of that patch. Its register and vector assumptions are specific
to the prepared capture below.

```sh
make -C runtime/linuxkernel_el0 CC=clang-19 OUT=/work/linuxkernel /work/linuxkernel/liblinuxkernel-el0.a
git apply tools/experiments/linux-user-fixed-ipc.patch

build_ipc_reader() {
  clang-19 -O2 -g -std=c11 -fPIC -fno-builtin -Wall -Wextra -Werror \
    -mgeneral-regs-only -mbranch-protection=none \
    -Iinclude -Iruntime/el0 -Iruntime/linuxkernel_el0 -DOSREC_LOWERED -DOSREC_NATIVE \
    -c runtime/linuxkernel_el0/native.c -o "/work/$1.o"
  clang-19 -O2 -mgeneral-regs-only -Iinclude -Itools -Iruntime/el0 \
    -static -Wl,-Ttext-segment=0x600000000000 tools/linuxkernel_prepare_application.c \
    "/work/$1.o" /work/linuxkernel/liblinuxkernel-el0.a -o "/work/$1"
}

build_ipc_reader fixed-ipc-reader
git apply tools/experiments/linux-user-ipc-direct-transitions.patch
build_ipc_reader direct-ipc-reader
```

The [plugin](../tools/qemu_plugins/linux_user_ipc.c) expects
`/work/kernel-ranges.bin` and `/work/user-ranges.bin`. Each contains
little-endian pairs of 64-bit executable range bounds, using the lowered
capture's kernel addresses and the user ELF addresses. Place the prepared
checkpoint in `/work/prepared` and verify its inputs before running the
direct reader. Set `QEMU_INCLUDE` to the directory containing QEMU 10.0.13's
`qemu-plugin.h`.

```sh
set -e
sha256sum -c - <<'EOF'
48439bb5d55dccc0c8961c3e799bbd6a57a7111f3215aa8d1a61f2542509b99c  /work/prepared/application.bin
a65c916c9c0a4155e514ba22b67cb53575fc8dae354451357b9aeee09ddfb9ea  /work/prepared/native.bin
707b7a591dda95e3db92bb6fb6c379f33a08948208d8e8e1a9e7961171984fc3  /work/prepared/memory.bin
31915f7517ec0863387c7360d22ed4a347024e5caa6a9a64ef8985fa9110b6b2  /work/prepared/vma.bin
EOF

clang-19 -O2 -shared -fPIC -Wall -Wextra -Werror -I"$QEMU_INCLUDE" \
  $(pkg-config --cflags --libs glib-2.0) tools/qemu_plugins/linux_user_ipc.c \
  -o /work/linux-user-ipc.so

for variant in fixed direct; do
  report="/work/profile-$variant-ipc"
  mkdir -p "$report"
  qemu-aarch64 -s 524288 -cpu cortex-a53 -plugin "/work/linux-user-ipc.so,out=$report" \
    "/work/$variant-ipc-reader" record /work/prepared "$report" \
    124338841 1024 0x80008000e000 0x800080059b50 >"$report/stdout.json"
done

for artifact in calls.json console.txt counters.bin mmio.bin stdout.json; do
  cmp "/work/profile-fixed-ipc/$artifact" "/work/profile-direct-ipc/$artifact"
done
```
