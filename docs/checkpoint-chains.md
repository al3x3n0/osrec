# Chaining application/kernel checkpoints

A saved joint checkpoint can now produce another intermediate checkpoint. Each stage loads the saved kernel state and application CPU/RAM into a fresh self-contained QEMU image, executes only its interval, and stops before the next SVC. The next checkpoint retains the full completed syscall PC history and advances the absolute kernel ordinal. A final consumer executes the remaining suffix and checks complete kernel and application results.

The [supplied-ELF workflow](elf-checkpoint-chains.md) runs this engine directly from a customer's ELF/neutral metadata or from an existing joint checkpoint. The C frontend below shares the same stage construction and offline verification.

The practical OHOS file profile remains the original ARMv7 LiteOS-A C recompiled for AArch64 with captured 32-bit kernel scalars and reviewed boundary models. Chaining adds persistence across images; it does not broaden syscall argument coverage, discover arbitrary kernel heaps, or migrate state between different kernel/capture constructions.

## One-command C workflow

Use a current checkpoint-capable kernel archive. The two-site fixture exercises a prefix-only SVC as well as repeated visits to the suffix SVC:

```sh
python3 tools/export_syscall_slices.py \
  --capture tests/fixtures/files-native --out build/my-chain-kernel
python3 tools/build_c_file_application_fixture.py \
  --slices build/my-chain-kernel --prefix-calls 5 --out build/my-chain-app
python3 tools/run_c_application_checkpoint_chain.py \
  --slices build/my-chain-kernel \
  --source build/my-chain-app/application.c --spec build/my-chain-app/spec.json \
  --pause-ordinals 5,16,31 --out build/my-checkpoint-chain
```

Pause ordinals are absolute counts of completed calls. They must strictly increase, remain inside the selected syscall sequence, and contain at most 64 intermediate checkpoints. The workflow compiles/imports the application once, then builds one producer/advancer for each requested pause and a final consumer. It alternates container addresses to verify reference rebinding while leaving application addresses fixed.

Each image receives ELF/raw execution checks and all four QEMU ELF/raw × EL1/EL3 load/start checks. Intermediate resumed stages and the final consumer restart twice from their input checkpoint. The report distinguishes logical calls in each interval from the additional proof executions. No guest host services are enabled; QMP observes stopped-machine memory externally.

Output includes:

- `compiled/` and `routes/`: the supplied C application and its imported ELF package.
- `stage-N/image/`, `stage-N/qemu/`, `stage-N/checkpoint/`: an image, verification evidence and its exported joint checkpoint.
- `finish/image/` and `finish/qemu/`: final suffix execution and verification.
- `workflow.json`: ordered intervals, generations, parent identities, per-stage observations and artifact hashes.

The final image embeds all required payloads and does not need earlier stage files to execute. Checkpoint generation metadata retains the immediate parent's manifest; ancestor payloads are not recursively duplicated. The complete workflow retains all stages for independent lineage checking.

Offline verification of the retained package checks stage ordering, parent identities, checkpoint generations, pinned kernel/application/image/source bytes, and recorded QEMU evidence:

```sh
python3 tools/run_c_application_checkpoint_chain.py --verify build/my-checkpoint-chain
```

## Advance an existing checkpoint

The composer accepts `--resume-checkpoint` and `--pause-ordinal` together. This selects an intermediate resumed stage rather than final suffix execution:

```sh
python3 tools/export_application_replay.py \
  --slices build/my-chain-kernel \
  --resume-checkpoint build/my-checkpoint-chain/stage-0/checkpoint \
  --pause-ordinal 16 --entry-address 0x40800000 --out build/my-advanced-image
python3 tools/verify_syscall_slices.py \
  --image build/my-advanced-image --out build/my-advanced-qemu
python3 tools/application_pause.py \
  --producer build/my-advanced-image --out build/my-next-checkpoint
```

The new pause must exceed the saved ordinal and precede sequence completion. The input checkpoint must retain complete syscall PC history; older checkpoints without that history remain usable for final suffix execution. The container must relocate relative to the input checkpoint's producer. The builder checks these conditions before target execution.

The target loads the input portable kernel record, restores its live application frame and memory, executes `new_ordinal - saved_ordinal` calls, and saves a new portable record. Result ABI 25 verifies loaded/saved checkpoints, interval call counts, stack guards, captured frame, and relocated context. The exporter appends newly completed PCs to the prior history; completed-only PCs stay patched without entering the active route table.

New joint manifests record `checkpoint_start_ordinal`, `generation`, and `input_checkpoint_manifest_sha256`. `parent-checkpoint-manifest.json` pins the immediate parent. Loading checks parent ordinal, generation, kernel/capture identity and schema consistency, in addition to existing record, frame and application checks. Legacy single-stage manifests remain readable.

## Verification

The retained example is `build/c-checkpoint-chain-final-v2`. It advances through 0 → 5 → 16 → 31 → 32, with logical interval counts 5, 11, 15 and 1. Its proof execution counts are 5, 22, 30 and 2 because resumed stages restart twice. All four QEMU modes pass for every image; final kernel completion and five application memory assertions pass on both final restarts.

`freestanding_application_checkpoint_chain` verifies those intervals, nonzero SIMD/FP state, preserved complete syscall history, parent generations and final completion. It rejects backward/repeated/out-of-range ordinals, altered lineage, damaged image payloads, and target mutations that omit checkpoint loading or erase state before saving. The existing import, window and standalone checkpoint suites continue to cover single-stage operation.

The four affected CTest suites passed in 181.96 seconds. Their retained report is `build/live-syscall-checks/qemu-checkpoint-chain-results.xml`. Offline verification of `build/c-checkpoint-chain-final-v2` also passed.
