# Chains from supplied user ELFs and joint checkpoints

`tools/run_application_checkpoint_chain.py` imports a supplied user-space ELF and neutral checkpoint metadata, executes selected syscall intervals, exports joint application/kernel checkpoints, and verifies every image in QEMU. It can also continue an existing joint checkpoint or run its final suffix directly. The C frontend uses the same stage engine and verifier.

## Start with the customer's ELF

Use an existing checkpoint-capable kernel slice archive and the [neutral application metadata](application-checkpoints.md):

```sh
python3 tools/run_application_checkpoint_chain.py \
  --slices build/my-kernel-slices \
  --elf application.elf --checkpoint application-checkpoint.json \
  --pause-ordinals 5,16,31 --out build/my-elf-chain
```

The ELF contains application code/data at the recording point. Its entry and PT_LOAD segments are authoritative; section tables, symbols, C sources and an application build manifest are unnecessary. The metadata supplies saved CPU state, stack/memory overlays, ordered SVC PCs, the exit boundary, object identities and optional final memory assertions. Syscall numbers and arguments come from live application registers using the kernel port's register ABI.

The tool copies exact input bytes into `inputs/`, imports them into `routes/`, then constructs `stage-N/image`, `stage-N/qemu`, `stage-N/checkpoint` and `finish/`. Each image embeds its application memory/frame, kernel archive and required portable kernel record. Guest execution uses no host services. QMP observes stopped memory externally.

Pause ordinals are absolute completed-call counts, strictly increasing inside the captured kernel sequence. A root ELF chain must describe the complete selected sequence beginning at kernel ordinal zero. This means the archive's captured initial kernel state, not necessarily application process startup. Application memory alone cannot reconstruct an arbitrary later kernel state. Nonzero starting ordinals require a matching joint checkpoint.

The tool validates ELF/metadata identities, route count, starting ordinal and pause ranges before creating its output or executing target code. Existing static AArch64 ELF, conservative instruction audit, identity mapping and bounded-memory restrictions apply. The container still uses the current Cortex-A53/QEMU 64 MiB RAM profile; importer `--ram` and `--reserved` options can constrain accepted input mappings, while composition checks actual container overlap.

## Continue a saved joint checkpoint

```sh
python3 tools/run_application_checkpoint_chain.py \
  --slices build/my-kernel-slices \
  --resume-checkpoint build/my-elf-chain/stage-0/checkpoint \
  --pause-ordinals 16,31 --out build/my-continued-chain
```

The input checkpoint's saved ordinal determines the starting point. New pauses must exceed it. The tool copies the entire input checkpoint into `initial-checkpoint/`, preserves its exact manifest identity, and continues checkpoint generations and parent links. It restores saved kernel state and live application CPU/RAM, executes only each remaining interval, and alternates container addresses so each restore exercises context-reference rebinding.

The output is independent of the original input checkpoint directory. It contains the required initial checkpoint, routes and subsequent stages. No C application compilation occurs. The kernel archive/capture identity and codec schema must match the saved record; migration between different kernel/capture identities is unsupported.

Advancing to another intermediate checkpoint requires complete completed-SVC history. Existing legacy snapshots without that history can still finish their suffix. To finish a checkpoint without exporting another intermediate one, omit pause ordinals:

```sh
python3 tools/run_application_checkpoint_chain.py \
  --slices build/my-kernel-slices \
  --resume-checkpoint build/my-continued-chain/stage-1/checkpoint \
  --out build/my-final-suffix
```

Every resumed interval and final suffix executes twice from its input snapshot. Root production executes once. The report distinguishes logical interval lengths from these additional proof executions. Final execution checks kernel completion and application memory assertions.

## Verification and retained evidence

All stages receive ELF/raw execution checks and the four QEMU ELF/raw × EL1/EL3 matrix checks. Offline verification reconstructs input routes, checks retained input and kernel identities, validates absolute intervals and cumulative generations, and verifies pinned image/source bytes and recorded QEMU evidence:

```sh
python3 tools/run_application_checkpoint_chain.py --verify build/my-elf-chain
python3 tools/run_application_checkpoint_chain.py --verify build/my-continued-chain
```

The generic report format is `osrec-application-joint-checkpoint-chain-v1`. It records `input_mode`, `first_ordinal`, `initial_checkpoint_manifest_sha256`, pauses, remaining logical calls and all stage identities. Existing `osrec-c-joint-checkpoint-chain-v1` reports remain readable through the shared verifier. Both new frontends record `chain_construction_sha256` for the shared engine.

`freestanding_elf_checkpoint_chain` removes the ELF section table and deletes source/build artifacts before starting the chain. It checks the six-call 64-bit fixture at 0 → 2 → 4 → 5 → 6, continuation at 2 → 4 → 5 → 6, and a final-only suffix at 4 → 6. It verifies relocated state, generation continuity and exact interval counts, rejects invalid pauses and later user-only ordinals, and verifies retained outputs after deleting their original inputs. Changed starting ordinals and damaged saved kernel records reject offline verification.

The practical 32-call OHOS file example uses a sectionless supplied ELF in `build/customer-elf-fixture-v1`, with its complete root chain in `build/customer-elf-chain-v1`. It retains the existing ARMv7 LiteOS-A capture recompiled for AArch64 with pinned 32-bit scalars and reviewed dependency models; it is not a native AArch64 kernel capture.

`build/customer-elf-resume-v1` continues its ordinal-5 snapshot through 16 → 31 → 32, preserving generations 2 and 3 and executing 27 logical remaining calls. `build/customer-elf-finish-v1` finishes the ordinal-31 snapshot directly. `build/customer-legacy-finish-v1` verifies final-only restoration of an older ordinal-5 snapshot without generation metadata or completed-call history. All retained images passed the four QEMU modes, and their offline chain verification passed.

The existing C-chain and external-port CTest suites passed in 108.69 seconds (`build/live-syscall-checks/qemu-elf-chain-results.xml`). The new supplied-ELF suite passed separately in 52.47 seconds (`build/live-syscall-checks/qemu-elf-chain-import-results.xml`).
