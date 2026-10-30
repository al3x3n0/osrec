# Relocatable references into owned buffers

The shared AArch64 checkpoint codec supports typed pointers into persistent scalar arrays owned by the kernel context. Cursors, aliases and reviewed end pointers are saved as a field-local buffer ID plus a byte offset. A fresh image restores them into its own context, retaining both array contents and the pointer positions reached by earlier syscall slices.

## Policy

Use `context_buffer_reference` for a pointer whose permitted targets are completely classified persistent integer or byte arrays:

```json
{
  "type": "uint32_t *",
  "policy": "context_buffer_reference",
  "targets": ["buffers[0].words", "buffers[1].words"],
  "nullable": true,
  "allow_one_past": true
}
```

The [complete fixture policy](../tests/fixtures/context-buffer-port/checkpoint-policy.json) expands two owned `Buffer` structures and persists each `uint32_t words[4]` array. The cursor and end fields allow one-past pointers; the alias field permits only actual elements. Both flags default to false and require Boolean values.

Target Clang checks the exact field types, array extents, layout and pointer/element compatibility. Targets must be nonempty persistent scalar arrays. Structures, transient storage, incompatible element types and paths outside the context reject construction. The same expansion and payload bounds as the [object-graph codec](context-object-graphs.md) apply.

A pointer must identify one target unambiguously. Construction rejects overlapping allowed target address ranges, including the shared address where one array ends and a second array immediately begins when one-past pointers are allowed. The fixture places a classified guard field after each array to separate these ranges. Ports can instead restrict a pointer's target list or disable end-pointer support.

## Save, validate and restore

Each field occupies 16 payload bytes: a little-endian 64-bit ID followed by a little-endian 64-bit byte offset. IDs 1 through N identify that field's ordered targets. Null has the unique representation `(0, 0)`. Reordering targets changes the schema identity; different fields may use different orders and still alias the same buffer element.

For a target of N elements of size S, ordinary offsets are `0, S, …, (N-1)*S`. Enabling `allow_one_past` also permits `N*S`. Save rejects foreign pointers, offsets outside the declared array domain, and pointers between elements before the port validation callback or any record write. It uses bounded integer address differences to classify pointers, rather than subtracting unrelated C pointers.

Load checks every ID, offset, null representation and end policy before decode or port callbacks. A valid payload is restored into a temporary context, with links reconstructed using typed array indices, and passed to `osrec_kernel_checkpoint_check(state, next)`. Only successful validation updates the destination context and ordinal. The callback remains responsible for boundary consistency, object lifetimes and whether a saved end pointer may be used by the next slice. One-past pointers support comparison and cursor bounds; they cannot be dereferenced.

Array contents persist independently from cursor positions. This policy does not capture arbitrary heap allocations, user memory pointers, pointers into structures or physical addresses. The real OHOS port remains the reviewed LiteOS-A file profile; the following proof fixture is synthetic.

## Automated QEMU workflow

```sh
python3 tools/export_syscall_slices.py \
  --capture tests/fixtures/context-buffer-port \
  --port tests/fixtures/context-buffer-port/port.json \
  --out build/my-context-buffer-kernel
python3 tools/verify_syscall_slices.py \
  --image build/my-context-buffer-kernel --out build/my-context-buffer-kernel-qemu
python3 tools/run_c_application_checkpoint_chain.py \
  --slices build/my-context-buffer-kernel \
  --source tests/fixtures/context-buffer-port/application.c \
  --spec tests/fixtures/context-buffer-port/spec.json \
  --pause-ordinals 1,2,4,5 --out build/my-context-buffer-chain
python3 tools/run_c_application_checkpoint_chain.py --verify build/my-context-buffer-chain
```

The six-call C application selects an interior cursor and alias, advances the cursor while retaining the alias, switches buffers, reaches the final element, advances to a one-past pointer and clears the pointers to null. It checks all returns and guarded user output. The current fixture also has two [private counters with the same name](private-context-state.md) in different source files, retaining values `next` and `3*next`. Kernel state occupies 96 target bytes; the portable record is 184 bytes including the 64-byte header. Nonzero array seeds and aliased pointers into the second buffer are reconstructed through [automatic array restoration](initialized-context-state.md).

Retained examples are `build/context-buffer-kernel-v1`, `build/context-buffer-kernel-qemu-v1` and `build/context-buffer-chain-v1`. Kernel and all five chain images pass ELF/raw × EL1/EL3 verification, for 24 retained matrix executions. Resumed intervals restore twice at changed kernel context addresses; guest execution uses no runtime host services.

The seeded version is retained in `build/initialized-context-kernel-final-v1`, `build/initialized-context-kernel-qemu-final-v1` and `build/initialized-context-chain-final-v1`, with the same layout and record size. The original v1 examples retain the earlier zero-initialized port and its exact construction identities.

The local-static version's call counter is a [function-local static](local-static-context-state.md), owned and persisted as `osrec_local_BufferStep_calls_0`. Its retained kernel and chain are `build/local-static-kernel-final-v2`, `build/local-static-kernel-qemu-final-v2` and `build/local-static-chain-final-v2`. They pass the same 24-mode verification with an 80-byte context and 168-byte record, under their pinned construction and schema identities. The current fixture retains that counter and adds the two private counters; it uses a new schema identity.

The private-state version is retained in `build/private-state-kernel-final-v1`, `build/private-state-kernel-qemu-final-v1` and `build/private-state-chain-final-v1`. All 24 matrix executions and offline chain verification passed with the 96-byte context and 184-byte record. The checkpoint test verifies both private counters at each pause, alongside the local counter, buffer contents and pointer positions.

The current fixture accesses those counters through [same-named private Tick helpers](private-context-functions.md) in each source. Current retained builds are `build/private-function-kernel-final-v1`, `build/private-function-kernel-qemu-final-v1` and `build/private-function-chain-final-v1`. Their 24 matrix executions and offline chain verification passed, preserving the 96-byte/184-byte layout under updated construction and schema identities.

The CTest suite `freestanding_context_buffer_checkpoint` checks exact saved IDs, offsets and buffer contents. Target probes mutate records with recomputed checksums and check atomic rejection, callback counts, foreign pointers, element alignment, end-pointer policy, nonnullable pointers, canonical nulls and independent target ordering. A successful save after relocation must reproduce the original record exactly.

All four affected CTest suites passed in 92.82 seconds: buffer references, object graphs, external ports and OHOS application checkpoints. Evidence is `build/live-syscall-checks/qemu-context-buffer-results.xml`. The earlier 272-byte file, 80-byte external-port and 160-byte object-graph codec schemas remain unchanged.
