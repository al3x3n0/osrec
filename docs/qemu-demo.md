# Freestanding QEMU capture to standalone native replay

For actual kernel boot and live capture through its SVC/VFS path, use the [live LiteOS-A QEMU demo](live-liteos-qemu.md). This document describes the earlier isolated harness.

`tools/qemu_sysread_demo.py` cross-compiles and boots a freestanding ARMv7 guest, records reads in that guest, and exports a native executable that reproduces the captured scenario. The validated platform is QEMU 9.2.3, machine `virt-9.2`, Cortex-A7, one CPU, TCG, 64 MiB RAM. Cross-compilation uses LLVM 16 clang/lld; the native replay uses the system C compiler on macOS ARM64.

The guest executes the pinned LiteOS-A `SysRead` function. It is a small capture harness, not a boot of the complete OpenHarmony kernel. Process state, descriptor slots, range checks and logical file cursors follow the existing explicit session model. Real ARM user/supervisor modes and SVC exception entry/return are exercised. The MMU is off, interrupts are masked, and no scheduler runs. Consequently, memory protection, context switching, interrupt interleavings, OHOS exception dispatch and the target VFS/drivers are outside this demo.

```text
QEMU ARM guest                              Native executable

initialize typed entry objects              rebuild fresh entry objects
             |                                           |
enter ARM user mode                         user errno adapter
             |                                           |
user read -> SVC exception                   original LiteOS-A SysRead
             |                                           |
original LiteOS-A SysRead                    recorded backend outcome
             |                                           |
QEMU semihost file read                      buffer writes + cursor update
             |                                           |
record returned bytes/result/errno           check return/errno/memory/cursor
             |
return to user mode
             |
save stream + per-call observations
             |
import -> compare guest/host state -> export executable
```

## Run

QEMU and clang with an ARM bare-metal target and lld must already be installed. The example uses the existing pinned kernel checkout and a file with a ten-byte prefix. Run from the repository root:

```sh
python3 -c "from pathlib import Path; Path('build/read-fixture.bin').write_bytes(b'0123456789ABCDE')"
python3 tools/qemu_sysread_demo.py \
  --kernel-root build/kernel_liteos_a \
  --input build/read-fixture.bin \
  --out build/qemu-sysread-demo
build/qemu-sysread-demo/replay
```

Choose an empty output directory. Override `--clang`, `--qemu` or `--compiler` for other tool paths. The default clang path is the matching Homebrew LLVM 16 installation. `--entry` accepts an entry/call manifest; this guest requires both descriptors 3/4 to alias exactly one file object. Calls retain the existing 1..8 invocation, eight-byte buffer and bounded argument contract.

The original input is copied into a temporary directory as `input.bin`. Startup opens it read-only through QEMU semihosting and seeks to the checkpoint's initial cursor. Each reached read goes through the actual `SysRead` body and into a semihost backend; the recorder hook immediately stores the result, saved errno and exact returned bytes. The guest maintains a logical cursor consistent with regular-file reads. This is a host-backed file exposed through QEMU, not a UART or sensor. Semihosting is enabled only for this repository-built guest. Its file paths are fixed, and QEMU runs with its temporary directory as the working directory.

The first read returns `ABCD`, the second `E`, the third EOF. The fourth syscall has count zero and never enters the backend. The observed raw/user returns are `[4,1,0,0]`, cursor positions `[14,15,15,15]`, errno remains zero, and final buffer bytes are `00 11 41 42 45 44 66 77`.

## What is verified

The guest checks supervisor mode during startup and backend calls, validates each SVC's arguments against the manifest, and checks user mode after every returned syscall. SVC entry preserves user registers; the user adapter performs errno translation and subsequent buffer processing. Typed entry objects are generated from the reviewed manifest and remain alive across all calls. They are not discovered from a running OS.

The host importer binds the read stream to the pinned kernel, normalized entry and call sequence. It reruns the syscall with the recorded backend outcomes and compares its observations against the guest's independently saved observations after every invocation. Comparisons cover raw/user returns, user/kernel errno, recognition, all eight buffer bytes and the shared file cursor. Exported replay checks the complete ordered boundary transcript and those observations.

Finally, the runner deletes its staged input, copies only the replay executable to another directory, and runs it with a minimal environment. No trace, input or metadata file is needed at runtime. `report.json` is written only after every comparison and isolated replay succeeds. A failed startup retains the built guest/source bundle for inspection without a successful report.

The optional regression varies the external file bytes and also tests EOF, invalid ranges, invalid descriptors and a zero-length call. Its guest/native comparisons ensure the results are not tied to the example payload. Enable it with:

```sh
cmake -S . -B build/qemu-tests -DOSREC_BUILD_QEMU_DEMO=ON
cmake --build build/qemu-tests
ctest --test-dir build/qemu-tests --output-on-failure -R '^qemu_sysread$'
```

The existing bounded two-call KLEE check applies to the session reconstruction core. It does not certify this assembly startup, SVC handler, semihost adapter or arbitrary guest sessions.

## Artifacts

| Artifact | Purpose |
| --- | --- |
| `guest.elf`, `guest.sources/` | Bootable guest and reviewed source bundle, including original kernel license |
| `reads.osrec` | Guest-produced framed read observations |
| `guest-observations.bin` | Six little-endian u32 words and eight buffer bytes per invocation |
| `entry.json`, `capture.json` | Entry manifest and imported session capture |
| `qemu.log` | Guest completion output |
| `replay` | Self-contained native executable |
| `replay.manifest.json`, `replay.sources/` | Native export review material |
| `report.json` | Versions, guest/source/stream hashes, comparison status and replay result |

Actual LiteOS-A kernel boot and live RAMFS capture are now implemented in the linked live demo. The complete OHOS product build remains a separate integration target. The official [LiteOS-A QEMU guide](https://github.com/openharmony/device_qemu/blob/master/arm_virt/liteos_a/README.md) builds `qemu_small_system_demo` through the OpenHarmony product build. That requires the product, board and dependency repositories plus its build environment; the live demo adds a separate managed dependency tree while preserving the original pinned recorder checkout. The live adapter validates a bounded entry schema and the actual dispatch/VFS path. General kernel state extraction and scheduling/interrupt reproduction remain future work.
