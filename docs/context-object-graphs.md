# Bounded context-owned object graphs

The shared AArch64 kernel checkpoint codec can save changing typed links between objects inside an explicit kernel context. It supports aliases, cycles, null links and reuse of fixed pool slots. Kernel code updates those objects during each syscall slice; saving at a quiescent boundary retains their scalar state and link identities. A fresh image restores the links to its own context addresses before the next syscall runs.

This is a construction policy for reviewed context-owned pools. It does not discover or capture arbitrary heap allocations, external kernel objects, physical addresses or concurrent mutations. Interior pointers into owned scalar arrays use the separate [buffer-reference policy](context-buffer-references.md). The real OHOS backend remains the bounded ARMv7 LiteOS-A file profile recompiled for AArch64. The object-graph fixture below is synthetic and adds no real-kernel capture coverage.

## Policy

Every context field requires an exact target C type and a policy. `members` classifies structures; `elements` expands a fixed array and applies its `element` policy recursively. `context_reference` declares an ordered list of permitted context paths and an explicit nullability rule. For example, a `Node *head` selecting one of three owned nodes uses:

```json
{
  "type": "Node *",
  "policy": "context_reference",
  "targets": ["nodes[0]", "nodes[1]", "nodes[2]"],
  "nullable": true
}
```

The [complete fixture policy](../tests/fixtures/context-graph-port/checkpoint-policy.json) classifies `Node nodes[3]` using `elements`, with member policies for value, allocation state, generation and the changing `next` pointer. Allocation state and generations remain port-owned scalar fields; the codec does not infer lifetimes or reference counts.

Target Clang supplies actual field offsets, sizes and pointee compatibility. Construction rejects missing classifications, changed types, union or bitfield members, raw persistent pointers, malformed or duplicate targets, targets outside the reviewed context, transient targets and incompatible pointee types. Arrays allow at most 256 elements per dimension, reference lists at most 256 targets, expansion at most 8,192 classified paths and 4,096 leaves, and payloads at most 65,536 bytes. These are codec construction bounds; the port must also fit the target stack and memory budget.

## Wire identities and restore

Each changing pointer occupies eight little-endian bytes in the payload. Zero represents null; IDs 1 through N select the ordered targets for that field. Nullability defaults to false when omitted. IDs are field-local. Reordering a field's target list changes its schema identity. No runtime addresses or context padding are serialized.

Saving first checks that every pointer is null when allowed or exactly equal to one of its own context's declared targets. Foreign-context and interior pointers reject before the port callback or any record write. The port's `osrec_kernel_checkpoint_check(state, next)` then validates object lifetime, topology, counters and consistency with the reviewed execution boundary.

Loading validates the header, schema, checksum, ordinal and all reference IDs before calling port code. It decodes into a temporary context and checks that complete state. Only a successful validation initializes and overlays the destination context, rebinds every link to a destination object and installs the saved ordinal. Aliases and cycles follow from selecting the same owned objects; no pointer traversal is needed. Rejected loads leave the destination context and session untouched. The quiescent validation callback must itself avoid side effects outside the temporary state.

## Reproduce the QEMU proof

```sh
python3 tools/export_syscall_slices.py \
  --capture tests/fixtures/context-graph-port \
  --port tests/fixtures/context-graph-port/port.json \
  --out build/my-context-graph-kernel
python3 tools/verify_syscall_slices.py \
  --image build/my-context-graph-kernel --out build/my-context-graph-kernel-qemu
python3 tools/run_c_application_checkpoint_chain.py \
  --slices build/my-context-graph-kernel \
  --source tests/fixtures/context-graph-port/application.c \
  --spec tests/fixtures/context-graph-port/spec.json \
  --pause-ordinals 1,2,4,5 --out build/my-context-graph-chain
python3 tools/run_c_application_checkpoint_chain.py --verify build/my-context-graph-chain
```

The six-call fixture allocates one node with aliased head/tail, adds a second node forming a cycle, changes a 64-bit value, releases the first node, reuses its slot with an incremented generation and rotates the cycle. Its context is 96 bytes; the portable record is 160 bytes including the 64-byte header. Pauses at 1, 2, 4 and 5 cover aliases, cycles, release and reuse. Every producer and consumer runs in fresh QEMU machines in ELF/raw × EL1/EL3 modes; resumed intervals execute twice and kernel contexts move between images. All guest state and execution remain self-contained, without runtime host services.

Retained examples are `build/context-graph-kernel-v1`, `build/context-graph-kernel-qemu-v1` and `build/context-graph-chain-v1`. The CTest regression `freestanding_context_graph_checkpoint` also recomputes checksums after corrupting IDs or generations, verifies rejection without state mutation, counts port callbacks to prove malformed IDs never reach them, checks nonnullable zero rejection, and rejects foreign/interior pointers without touching the output record.

The three affected CTest suites passed in 49.78 seconds: context graphs, external ports and existing OHOS application checkpoints. Evidence is `build/live-syscall-checks/qemu-context-graph-results.xml`. The kernel and all five chain images passed ELF/raw × EL1/EL3 verification, giving 24 retained matrix executions.
