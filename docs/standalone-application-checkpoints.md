# Standalone joint application/kernel checkpoints

A paused syscall sequence can now be exported and resumed in a fresh QEMU machine. The producer runs a prefix of the application, stops immediately before the next SVC, and publishes a quiescent kernel record. The external QEMU testbench observes that record, the live EL0 CPU frame, and every application memory segment while the CPU is stopped. The guest uses no host service. A consumer image embeds the resulting checkpoint, restores it at startup, and executes only the suffix.

The first concrete backend remains the bounded OHOS file profile: original ARMv7 LiteOS-A C recompiled for AArch64 with captured 32-bit kernel scalars and reviewed boundary models. This adds checkpoint persistence and relocation; it does not add native AArch64 kernel capture or unrestricted VFS, MMU, scheduler, or object-graph reconstruction.

## Automated C workflow

Build a current checkpoint-capable kernel archive, then compile and exercise the practical file application:

```sh
python3 tools/export_syscall_slices.py \
  --capture tests/fixtures/files-native --out build/my-checkpoint-kernel
python3 tools/build_c_file_application_fixture.py \
  --slices build/my-checkpoint-kernel --out build/my-checkpoint-app
python3 tools/run_c_application_checkpoint.py \
  --slices build/my-checkpoint-kernel \
  --source build/my-checkpoint-app/application.c \
  --spec build/my-checkpoint-app/spec.json \
  --pause-ordinal 5 --out build/my-joint-checkpoint
```

The last command compiles C, derives ELF routes, builds a producer, verifies its result and exact checkpoint bytes in all four QEMU ELF/raw × EL1/EL3 modes, freezes the joint checkpoint, links a consumer at a different address, and verifies that consumer in all four modes. The consumer restores the same checkpoint twice to prove deterministic restart. A pause ordinal counts completed calls and must be strictly between zero and the full call count.

`checkpoint/` contains `kernel.bin`, the neutral saved application checkpoint, its imported ELF/memory package, and a manifest pinning all artifacts and the selected kernel construction. `consumer/` includes that complete checkpoint plus the archive, construction sources, ELF and raw image. It runs without the producer or construction files. The workflow report pins stage manifests, source inputs, and verification evidence.

Existing imported ELF packages can use the separate stages:

```sh
python3 tools/export_application_replay.py \
  --slices build/my-checkpoint-kernel --application build/my-routes \
  --pause-ordinal 5 --out build/my-producer
python3 tools/verify_syscall_slices.py \
  --image build/my-producer --out build/my-producer-qemu
python3 tools/application_pause.py \
  --producer build/my-producer --out build/my-snapshot
python3 tools/export_application_replay.py \
  --slices build/my-checkpoint-kernel --resume-checkpoint build/my-snapshot \
  --entry-address 0x40600000 --out build/my-consumer
python3 tools/verify_syscall_slices.py \
  --image build/my-consumer --out build/my-consumer-qemu
```

## What is saved and restored

The application snapshot includes all 31 GPRs, SP, the next SVC PC, PSTATE, 32 SIMD registers, FPCR/FPSR and both EL0 TLS registers. Non-executable application memory is overlaid on the original user ELF, including the live application stack inside the syscall wrapper. Executable bytes must match the reviewed patched producer image; the importer reconstructs them from the original ELF and route patches. Object IDs and final memory assertions are retained. The remaining route list begins at the saved kernel ordinal.

The kernel codec uses a reviewed field policy, checked against target Clang declarations and offsets. Every context field must be classified. Persistent leaves are integer scalars or byte/integer arrays. Structures require member policies; fixed arrays can use element policies. Pointer fields require explicit treatment: fixed context self-references, [bounded references to owned objects](context-object-graphs.md), [typed references into owned buffers](context-buffer-references.md), or excluded invocation scratch. Unknown fields, changed types, missing nested policies and persistent raw pointers fail construction.

For the file profile, the payload is 208 bytes. It retains descriptor mappings, reference counts, positions, file content, dependency cursor, verified-call count, return hash and model counters. The 64-byte header carries format, length, construction/schema identity, ordinal and an integrity checksum. The codec excludes application pointers, argument scratch and saved kernel setjmp registers. Restore initializes a fresh context, overlays persistent fields, and rebinds `process.vmSpace` to the destination context's `space`.

Shared save/load APIs reject busy or poisoned sessions, overlapping record/state storage, malformed headers, wrong schemas, bad checksums and invalid port state. Port checks validate the saved ordinal against the dependency cursor, file-state witness and return hash. A rejected load leaves the existing session and kernel state untouched. Loading a valid record does not execute earlier syscall bodies.

Other AArch64 kernel ports can supply a field policy and quiescent validation callback through their construction adapter. Its `prepare()` result names a generated-source-relative `checkpoint_policy` JSON file with format `osrec-slice-checkpoint-schema-v1` and a `fields` map; each field declares its exact target type and `persist`, `transient`, `members`, `elements`, `self_reference`, `context_reference`, or `context_buffer_reference` policy. The port adapter supplies `uint32_t osrec_kernel_checkpoint_check(const void *state, uint64_t next)`, returning zero only for valid quiescent state. The builder generates and archives the codec automatically. Target layout discovery, field codec generation, record handling, ELF import, composition and QEMU verification are shared. General heap graphs, external references, concurrent capture and migration between different kernel/capture identities still need additional contracts. Checkpoints currently bind to the same archive and reviewed captured sequence. The exporter retains the completed syscall PC history as `completed_calls`, separately from the remaining active routes. Both sets are checked against original SVC bytes and patched locally. Prefix-only locations are supported; the gateway rejects an unexpected visit to one before entering any kernel callback. Every executable SVC candidate must still be covered by the recorded prefix or suffix. This retains the conservative service-instruction audit.

## Verification

The regression suite `freestanding_application_checkpoints` covers pauses after calls 1, 5 and 31, each with four producer modes and four fresh consumer modes. It checks relocated contexts, suffix-only execution, live frame/RAM restoration, complete kernel/application results and repeated restart. The snapshot test sets nonzero values in all 32 SIMD registers and FPCR/FPSR, then checks their exact saved values and imported restoration metadata. Target rejection tests corrupt checksums, schema, ordinal, dependency cursor and verified-call count, including corruptions with recomputed checksums, then verify no state mutation. Mutations that skip checkpoint loading or reset restored kernel state fail. Host tests reject altered artifacts, mismatched kernel identity, incomplete field policies and persistent pointers.

The original one-site example is `build/c-standalone-checkpoint-final-v3`: five prefix calls, followed by 27 suffix calls per consumer restart, with no guest host services. QEMU validates functional execution; customer RTL/cycle-accurate integration remains outside this verification workflow.

All eight relevant regression suites passed in 180.57 seconds, including fresh native capture; evidence is `build/live-syscall-checks/qemu-standalone-checkpoint-results.xml`. The strengthened full-SIMD snapshot suite also passed in 21.40 seconds, recorded in `build/live-syscall-checks/qemu-checkpoint-simd-results.xml`.

## Multiple syscall locations

The C frontend supports an explicit `call_sites` list in the spec. Each entry names the wrapper used for that dynamic call. The default interface is `osrec_app_syscall(number,a0,a1,a2,a3,a4,a5)`; a name such as `prefix` generates `osrec_app_syscall_prefix(...)`. All use the selected port register convention and preserve the C caller's callee-saved registers. Symbol resolution generates concrete PCs after linking.

```sh
python3 tools/build_c_file_application_fixture.py \
  --slices build/pause-checkpoint-kernel-v1 --prefix-calls 5 \
  --out build/my-multiple-site-app
python3 tools/run_c_application_checkpoint.py \
  --slices build/pause-checkpoint-kernel-v1 \
  --source build/my-multiple-site-app/application.c \
  --spec build/my-multiple-site-app/spec.json \
  --pause-ordinal 5 --out build/my-multiple-site-checkpoint
```

The retained example is `build/c-multiple-svc-checkpoint-v2`. Its producer executes five calls at a distinct prefix SVC; the consumer starts at the default SVC and executes 27 remaining calls per restore. Both images contain three reviewed patches: the two SVC locations and terminal exit. All four QEMU modes pass for each image. The application code bytes match across the producer and consumer snapshots.

The checkpoint tests now use this two-site C application at pauses 1, 5 and 31. A target test deliberately resumes at the completed-only prefix PC, requires divergence with zero kernel entries and an unchanged ordinal/context, then reloads the checkpoint and completes normally. Import tests reject missing or malformed history, non-SVC PCs and altered route metadata. Named wrappers without a default site and alternate register conventions are also tested. The boot audit reads instruction lines, so a directory name containing `svc` does not create a false service-instruction rejection.

All four affected suites passed in 163.01 seconds: AArch64 image/boot, application import, resident windows and standalone checkpoints. Evidence is `build/live-syscall-checks/qemu-multiple-svc-results.xml`. The focused importer/checkpoint run also passed, recorded in `build/live-syscall-checks/qemu-multiple-svc-focused.xml`.

The [checkpoint-chain workflow](checkpoint-chains.md) now restores an intermediate snapshot, executes another interval, and exports the next snapshot in a fresh image. It preserves cumulative syscall PC history and verifies parent identities and checkpoint generations.

The [external kernel-port workflow](external-kernel-ports.md) supplies construction modules and proofs from pinned bundles outside the repository. Its separate 64-bit fixture exercises this same checkpoint chain with an alternate register convention and a relocated context self-reference.
