# Importing an application ELF and checkpoint

The application importer connects a supplied AArch64 ELF and saved user state to the returning kernel-slice library. The application runs at EL0 in QEMU. Its declared SVC instructions are replaced with embedded BRKs; the container handles those exceptions locally, executes the selected kernel slice, and resumes at the original SVC PC plus four. Application instructions prepare arguments, consume returns, and update user memory between calls. Kernel state persists until an explicit checkpoint restore.

The importer uses the ELF entry point and PT_LOAD segments. It does not need section tables, symbols, fixed application addresses, or a disassembler to identify the recorded call order. The checkpoint supplies that order explicitly. Repeated visits to the same PC produce one physical patch and multiple ordered route entries.

The customer checkpoint is a user-space ELF containing application code and data at a concrete execution point. The neutral metadata format is `osrec-aarch64-application-checkpoint-v1`; it describes CPU initialization and ordered syscall boundaries where the ELF alone does not supply them. For verification, the C frontend compiles a user application into that ELF and derives its stack, entry, syscall site, and exit boundary automatically.

```json
{
  "format": "osrec-aarch64-application-checkpoint-v1",
  "elf_sha256": "SHA256 of the exact supplied ELF",
  "frame": {
    "pc": "0x41000000",
    "sp": "0x41030000",
    "pstate": "0x3c0",
    "tpidr_el0": "0x1234567890"
  },
  "calls": [
    {"pc": "0x41010000"},
    {"pc": "0x41010000"}
  ],
  "exit": {"pc": "0x410000fc", "original": "1f2003d5"},
  "snapshots": [{"address": "0x41020000", "data": "2a00000000000000"}],
  "extra_memory": [{"address": "0x4102f000", "bytes": 4096, "permissions": 3}],
  "objects": [{"address": "0x41020000", "bytes": 192, "id": 1}],
  "assertions": [{"address": "0x410200c0", "data": "2000000000000000"}]
}
```

The addresses above illustrate the schema; they must match the supplied ELF and checkpoint. Integers accept JSON numbers or hexadecimal strings. `frame.pc` defaults to the ELF entry, PSTATE defaults to masked EL0t, and unspecified GPR, SIMD, FP, and thread-pointer fields default to zero. Supply `x` as 31 values and `v` as 32 `[low64, high64]` pairs when those states are recorded. FPCR and FPSR are 32-bit values. SP must be 16-byte aligned with mapped writable space below it.

`snapshots` overlay recorded bytes on file contents and zero-filled BSS or extra memory. Code snapshots are rejected: executable bytes must match the supplied ELF. Extra memory describes checkpoint-owned stack or heap ranges outside PT_LOAD. Permissions are read=1 and read/write=3. Named `objects` partition existing memory ranges and assign IDs required by the kernel adapter; the OHOS file adapter requires the 192-byte caller witness at ID 1. Other ranges receive unique IDs automatically. Optional `assertions` compare final application memory against expected bytes after execution.

A resumed checkpoint can also carry `completed_calls`, an ordered list of `{ "pc": address }` records for the completed prefix. Its length must equal `first_ordinal` and is bounded to 65,536. These PCs receive the same local route patch but have no entries in the active dispatch table. They preserve executable bytes when a SVC location occurs only before the pause. Repeated PCs shared by prefix and suffix produce one physical patch. An unexpected visit to a completed-only PC diverges before entering the kernel slice.

The input lists syscall PCs, while syscall numbers and arguments come from the live application registers according to the selected port's register ABI. The exit boundary is an explicitly declared instruction with four expected original bytes, written in byte order. The example uses an AArch64 NOP. It is replaced by the local exit BRK. Selecting the exit boundary is part of the recording contract.

## Automated workflow

For intermediate checkpoints and automatic continuation in fresh images, use the [supplied-ELF chain workflow](elf-checkpoint-chains.md). It combines import, composition, joint export and four-mode verification in one command, and can resume an existing joint checkpoint without recompiling the application.

First export the selected kernel port. This existing command produces the returning archive and its independent proof image:

```sh
python3 tools/export_syscall_slices.py \
  --capture tests/fixtures/files-native \
  --out build/my-kernel-slices --cpu-gateway
```

Import the customer's application and neutral checkpoint, then compose and verify them:

```sh
python3 tools/import_application_checkpoint.py \
  --elf application.elf --checkpoint application-checkpoint.json \
  --out build/my-application-routes \
  --ram 0x40000000:0x4000000 \
  --reserved 0x40000000:0x1000000 \
  --reserved 0x43f00000:0x10000

python3 tools/export_application_replay.py \
  --slices build/my-kernel-slices \
  --application build/my-application-routes \
  --out build/my-application-replay

python3 tools/verify_syscall_slices.py \
  --image build/my-application-replay \
  --out build/my-application-qemu-verified
```

Output directories must be new. The reserved ranges above keep application memory separate from the default container and QEMU EL3 boot area. Composition also checks actual linked container segments and startup clearing ranges for overlap before running QEMU.

The route package contains the original ELF, patched ELF, input checkpoint, complete initial memory payloads, generated C/header, and a hash-bound route plan. The original executable bytes remain available to the saved-frame validator. Composition embeds payloads in the self-contained image: the guest loader copies RAM bytes and restores CPU state without reading files or calling host services. Gateway ABI 2 supports multiple disjoint executable spans; existing single-span source initializers still work when rebuilt against the new header and archive.

The composed proof restores the application and kernel, executes the full sequence, checks kernel completion and application assertions, and repeats after an explicit joint restore. Result ABI 21 records the routed calls, initial-memory checks, completed sessions, executable segments, unique patches, and private-stack guards. The verification matrix compares the complete 128-byte result across ELF/raw loading and EL1/EL3 starts. It also verifies pinned route artifacts and reconstructs routing metadata and generated C from the supplied ELF/checkpoint.

## Reproducible file application

`tools/build_file_application_fixture.py` generates a separate application ELF for the captured 32-call OHOS file lifecycle. This fixture executes buffer preparation and return/output checks in EL0, calls a repeated SVC site in a second executable segment, and consumes a recorded BSS snapshot. It also witnesses SIMD and thread-pointer transport through application stores.

```sh
python3 tools/build_file_application_fixture.py \
  --slices build/my-kernel-slices --out build/my-file-application
```

Use its `application.elf` and `checkpoint.json` as the importer inputs above. The fixture uses the syscall numbers declared by this kernel port, which come from the captured ARMv7 LiteOS ABI. AArch64 execution does not automatically change those numbers to Linux AArch64 syscall numbers.

`tests/test_application_import.py` removes the fixture's ELF section table before importing it, exercises malformed inputs and repeated routes, verifies four QEMU modes, and rejects missing application restoration, missing snapshots, invalid executable spans, a damaged EL0 return store, and modified published artifacts. `freestanding_application_import` is registered with CTest.

## Current boundaries

The importer supports bounded static, little-endian AArch64 ET_EXEC images with readable, nonoverlapping identity-mapped PT_LOAD segments and at most 16 MiB of initial application memory. Writable executable segments, dynamic loaders, relocation at import time, executable snapshots, overlapping file ranges, and unreviewed service/trap instruction candidates are rejected. The conservative executable-word scan can reject literal data that resembles an instruction; it does not establish arbitrary control-flow reachability.

The current container uses Cortex-A53, MMU and caches off (or, for a library built with `target_mmu`, the [identity map](linux-aarch64-slices.md#mmu-on-harness) with caches off), masked interrupts, EL1h to EL0t execution, and sequential sessions. It provides no application isolation, SMP, SVE/SME, scheduler, or native process-address-space reconstruction. Ordinary composition starts a fresh kernel session at ordinal zero and verifies the complete sequence expected by the selected kernel adapter. Joint-checkpoint composition can restore a saved intermediate ordinal and execute the suffix. It can divide that sequence into resumable execution windows while retaining the application and kernel state. Windows run within one resident image; the [standalone joint-checkpoint workflow](standalone-application-checkpoints.md) also saves the reviewed kernel fields and application frame/RAM for restoration in a fresh image.

The ELF/checkpoint infrastructure is independent of the OHOS syscall implementation. Kernel adapters still define supported arguments, object identities, dependency models, and completion expectations. The current OHOS library runs original captured ARMv7 LiteOS kernel C recompiled for AArch64 with pinned 32-bit kernel scalars and reviewed boundary models. This does not yet import an arbitrary native AArch64 kernel checkpoint or general VFS/MMU/scheduler state.

## Retained verification

The composed package is in `build/application-import-final-v2/image`, including the imported application, returning archive, generated loader, kernel source closure, and pinned kernel build manifest. Its four-mode evidence is in `build/application-import-final-v2/qemu-verified/verification-matrix.json`. Each execution completes 64 calls: the 32-call persistent sequence followed by a joint application/kernel checkpoint restore and another 32 calls. It verifies three initial memory segments, two executable spans, one recorded snapshot, four final application-memory assertions, and two private-stack guards. There are two embedded application BRK patches and no external service instructions.

The input kernel proof and generated application sources are retained in `build/application-import-final-v1/kernel` and `build/application-import-final-v1/fixture`. All six regression suites, including fresh native capture, passed in 78.22 seconds; evidence is recorded in `build/live-syscall-checks/qemu-application-import-final-results.xml`. Package provenance checks are additionally covered by `build/live-syscall-checks/qemu-application-import-package-results.xml`.
