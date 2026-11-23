# Fixed-mapping IPC replay in QEMU Linux-user

The 640-iteration IPC workload completed with **3.62% runtime instruction
overhead** at 10 million kernel instructions in a two-pass build. The checked
reader measured 4.32%. Both ran in QEMU Linux-user on Cortex-A53 and executed
10,779,406 kernel and 97,373 application instructions across the full replay.

| Replay variant | Runtime instructions per kernel instruction at 10M kernel instructions |
| --- | ---: |
| Mapping refresh and full signal-context copies | 83.8888 |
| Fixed mappings and in-place FPSIMD state | 29.5688 |
| Inline register operations and direct memory accesses | 1.7859 |
| Inline result observer and native sign tests | 0.7696 |
| In-place signal-frame syscall transitions | 0.3311 |
| Direct syscall transitions and inline shadow-register accesses (`26bdf40`) | 0.0970 |
| Direct gateways and syscall event recording in the return stub | 0.0769 |
| SSBS-aware syscall return check | 0.0723 |
| Direct DAIF register writes with masked reads | 0.0669 |
| Single-store DAIF updates for the full mask and I/F (`7d096e0`) | 0.0509 |
| Deferred result initialization and direct DAIF store at entry | 0.0494 |
| Pending event and guest mode encoded together | 0.0478 |
| Paired stack and gateway load and direct UART frame updates | 0.0470 |
| Paired load of live and expected return addresses | 0.0463 |
| Direct return using an untagged pending-event pointer | 0.0455 |
| Paired stack and syscall state transfers | 0.0432 |
| Two-pass execution-only ELF | **0.0362** |

The prepared capture populates all ELF load segments before execution. The
Linux-user process retains the user and kernel mappings throughout the replay.
The checked reader rejects any call to the address translator or mapping
synchronizer during execution. Captured EL1 register operations use EL0
instructions and shadow state. Memory instructions access the installed
addresses directly. Each syscall site branches to its own gateway. A bounded
cursor feeds the event ledger, and the return stub writes the restored result
from `x0` into the pending event. The runner accounts for the direct
transitions after execution using the cursor and the pending event.
The direct return initializes the result fields. The runtime also initializes
an incomplete record at a replay stop or before resuming user execution
after an emulated return. The C emulator records guest mode with the event
cursor and pending pointer. Its mode remains valid while both pointers match.
After a direct transition changes either pointer, a pending event indicates
kernel mode and a cleared pointer indicates user mode.

The experiment assumes a trusted application, fixed mapping permissions, and
the captured kernel's syscall frame layout. It specializes the observed return
site and uses native `DC ZVA` when the capture and emulator agree on
`DCZID_EL0`. The direct transition patch uses the fixed IPC trace to reserve
`x18` as a pointer to replay state and preserves the guest register value at
its traced uses. Syscall gateways branch to the captured EL0 vector. The
return stub restores user state and branches through the matching gateway.
The measured interval included 35 `rt_sigreturn` calls for UART MMIO, down
from 16,678. These were the only host syscall requests observed by the plugin.

The return stub selects an instruction sequence for the captured user SSBS
bit. It checks the common return state after masking NZCV and normalizing
SSBS. When DAIF or PAN is set, the stub uses the full status check and
restores both fields.

DAIF register writes store their operand directly. Register reads mask
the result, and the runtime normalizes DAIF before C emulation and at the
execution boundary. The replay places its state so bits 9:6 of the existing
`x18` pointer supply the full DAIF mask. A byte store sets or clears I and
F while preserving D and A. These changes save 213,836 runtime instructions
in the 10-million prefix and 230,406 across the full replay. The kernel and
application counts match the previous reader in both intervals.

Deferred result initialization, the DAIF store at entry, and the packed
pending event and guest mode save 30,880 runtime instructions in the
10-million prefix and 32,623 across the full replay. Entry uses the mask in
`x18` when its address bits match. The fallback uses an immediate for the
mask.

The return stub loads the user stack pointer and gateway address as a pair.
That saves 7,719 runtime instructions in the prefix and 8,321 across the
full replay. The UART handler updates the interrupted signal frame in place
after validating the access. That saves another 4,403 instructions in the
full replay. All 35 UART accesses occur after the prefix.

The return check also loads the live ELR and expected user PC as a pair.
The runtime transfers ELR and SPSR between the assembly stubs and the C
emulator at signal boundaries. This saves 7,719 runtime instructions in the
prefix and 8,251 across the full replay.

Keeping the pending pointer untagged removes one instruction from the
direct return. That saves a further 7,719 runtime instructions in the prefix
and 8,286 across the full replay.

Syscall entry saves the user stack pointer and DAIF as a pair and loads the
kernel stack pointer with the precomputed SVC syndrome. Return saves the
kernel stack pointer and clears the pending event in one store pair. These
changes save another 23,159 runtime instructions in the prefix and 24,895
across the full replay. Signal handling transfers the live fields into
the existing checkpoint shadow layout for C emulation.

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
boundary. No user fault appeared in the ledger. The shadow entry and emulation
counters matched the prior reader. A trace buffer limited to one event stopped
at the second syscall and preserved the first result and both guard records.
Additional replay checks matched the prior reader with SSBS clear and with
DAIF and PAN set in the saved return status. Injecting an SSBS mismatch or a
reserved status bit stopped the replay before the first return.
The packed-mode variant matched the reference diagnostics for injected user
faults before and after a direct syscall return. With every return routed
through the signal handler, the replay kept the same ledger and preserved
the incomplete result fields in a prefilled caller buffer. That stress
run executed 3.4% more runtime instructions than the previous reader.
The direct UART frame path preserved terminal registers and FPSIMD state.
An unsupported UART instruction and exhaustion of the MMIO ledger preserved
the previous reader's diagnostics and terminal state.
The ELR and SPSR value traces matched. Injected return address and status
mismatches reached the same guard instruction and produced matching fault
reports. The untagged-pointer variant matched an injected user fault after
an emulated kernel instruction and direct syscall return. Its forced
C-emulation run matched the ledger and used 0.6% fewer runtime instructions
than the paired-address variant.
The paired stack transfers matched the stack-pointer, DAIF, PAN, ESR, ELR,
and SPSR traces. Tests also covered the DAIF immediate fallback, prefilled
trace buffers, and faults after a signal interrupted kernel execution.
Forcing every return through C emulation used 1.0% more runtime instructions
than the untagged-pointer variant and produced the same replay artifacts.

The DAIF audit matched all 63,399 observed mask changes and 8,340 guest reads.
Additional checks matched the reference after injecting bits outside DAIF and
after forcing D and A set across partial updates. The emitter also passed
with a state pointer that selected the fallback for setting the mask.

The syscall entry and return stubs in the checked reader, including their
gateways and the lowered ERET, account for 424,400 runtime instructions,
or 89.9% of the full run.

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

## Build the execution-only ELF

Use the direct reader run above as the collection pass. The exporter checks
the starting checkpoint and the five recorded artifacts against the pinned
SHA-256 values and an independent reference. It links the sparse starting RAM,
application and kernel metadata, and ordered device inputs into one statically
linked AArch64 Linux ELF. The replay uses a single transition word to track
guest mode and omits syscall ledger writes. Its runtime still checks return
PC and status, fixed mappings, each UART access against the transcript, and
successful completion at `do_exit(0)`.

In the isolated checkout with both reader patches applied, apply the
[production patch](../tools/experiments/linux-user-ipc-production.patch).
Set `IPC_ORACLE` to the independent reference directory and use fresh build
output paths.

```sh
git apply tools/experiments/linux-user-ipc-production.patch
OUT=/work/ipc-production-runtime python3 tools/export_native_checkpoint.py \
  --package /work/prepared --oracle "$IPC_ORACLE" \
  --ipc-profile /work/profile-direct-ipc --out /work/ipc-production --build

mkdir -p /work/profile-production-ipc /work/ipc-empty
cd /work/ipc-empty
qemu-aarch64 -s 524288 -cpu cortex-a53 \
  -plugin /work/linux-user-ipc.so,out=/work/profile-production-ipc \
  /work/ipc-production/user-checkpoint >/work/profile-production-ipc/console.txt
cmp /work/profile-direct-ipc/console.txt /work/profile-production-ipc/console.txt
```

The resulting ELF is 58,288,624 bytes and the linker audit confirmed it has
its own startup, zero undefined symbols, and no libc, compiler runtime, or TLS.
It completed from an empty working directory with the same console output.
External instrumentation found identical hit counts at all 9,456 measured
kernel and user instruction addresses and identical general registers, stack
pointer, and NZCV at `do_exit`. The exporter rejected a modified transcript.
Changing an embedded UART write also made the ELF stop with a nonzero status
before printing any console output.

| Measurement | Checked reader | Execution-only ELF |
| --- | ---: | ---: |
| Runtime instructions through 10M kernel instructions | 431,827 | 362,348 |
| Runtime instruction overhead through 10M kernel instructions | 4.32% | 3.62% |
| Runtime instructions over the full replay | 472,202 | 395,982 |
| UART accesses over the full replay | 35 | 35 |

The execution-only ELF used 16.1% fewer runtime instructions in the prefix
and across the full replay. UART emulation still accounted for all 35
`rt_sigreturn` calls during the measured interval. The instruction window
excludes checkpoint setup and final output. The ELF targets the pinned
capture and Linux host ABI.
