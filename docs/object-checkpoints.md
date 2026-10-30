# Preparing initial state for an extracted execution

The object-checkpoint prototype captures an entry state from an exclusively owned host object graph and packages an executable that reconstructs it in a new process. It exercises the state preparation needed by future EL0 kernel slices: scalar fields, object identity, aliases, cyclic references, interior buffer pointers and an explicit current-task binding. The computation is a portable completion model, not LiteOS-A scheduler code. No live OHOS capture or concurrent checkpoint protocol is implemented.

```text
at function entry                         in the executable

current_task --> task #4                  create objects #1..#4
                  |                      restore scalar fields and bytes
       wait ------+--> completion #1     reconnect object references
       alias -----+       | next         bind current_task
                          v                       |
                      completion #2               v
                          | next           run original computation
                          +----> #1        check return, credits, buffer

       cursor --> buffer #3 + 2
       view   --> buffer #3 + 4
```

## Run capture and export

The default build includes the object reference runtime, capture fixture and integration tests:

```sh
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
build/record_object_demo build/object-checkpoint.json
python3 tools/export_object_checkpoint.py build/object-checkpoint.json \
  --out build/scenarios/object_checkpoint
build/scenarios/object_checkpoint
build/scenarios/object_checkpoint --describe
```

Before execution, completion #1 has five credits, completion #2 has three, and the buffer contains eight `a5` bytes. Demand is seven. Capture serializes this initial state before running the original computation; afterward it records the observed return, both credit counts and the complete buffer. Replay consumes five credits from #1 and two from #2, returns seven, and reproduces both buffer writes. Expected effects are used for checking after execution, not for restoring the starting state.

Optional arguments vary the initial credits and demand:

```sh
build/record_object_demo build/another-checkpoint.json 0 5 3
```

## Capture and reconstruction contracts

`include/osrec/checkpoint.h` and `runtime/checkpoint.c` provide a bounded caller-owned object table. Register live, disjoint objects with an ID, schema, base and size. `osrec_object_reference` translates a known pointer into `{object, offset}` while checking its required access extent and schema. Null maps to `{0,0}`. Unknown pointers, overlapping registrations, duplicate IDs, insufficient capacity and invalid extents invalidate the table. Capture callers still own synchronization, object discovery, pointer-field identification and lifetime stability.

The JSON format stores typed scalar fields and byte buffers. Struct padding and raw pointer values are excluded. Typed struct references target object bases; byte-buffer references support interior offsets with explicit extents. A root map names `current_task`. The source SHA256 binds the field declarations and computation to the captured schema. The generic graph validator accepts aliases and cycles, checks every reference, and requires all objects to be reachable from the declared roots. It bounds object count and total buffer storage.

The exporter accepts a specific completion contract: two distinct completion objects linked in a cycle, one task whose two completion references alias, and one eight-byte buffer with two related views. It verifies the contract and observed-effect shapes before generating C. Replay creates all objects first, restores scalar fields and bytes, registers their fresh addresses, then resolves references using `osrec_object_resolve`. Allocation order and numeric object IDs do not affect reconstruction.

Fieldwise reconstruction adapts this fixture's pointer layouts to the host compiler. It is not an automatic adapter for arbitrary kernel structs, pointer-to-integer arithmetic, embedded subobjects or architecture-specific layouts. Such code needs a reviewed schema/layout transformation or a matching target execution backend.

The generated executable embeds its full checkpoint and provenance. It calls the original computation and checks return bits, both completion counters and all eight buffer bytes. It is compiled without optimization/LTO to keep reconstruction and computation explicit in this prototype. Export audits system dependencies and executes a copied binary in an otherwise empty directory with a minimal environment. Its `.c` and `.manifest.json` sidecars and the capture file are unnecessary at runtime. A failed reconstruction/result check prevents replacement of an existing executable.

## Validation and remaining work

The C reference tests check relocation to different storage, shared aliases, nulls, wrong schemas, overlapping ranges, invalid offsets/extents, unknown objects, capacity and sticky failure. Six integration regressions check entry versus final state, standalone isolated execution, remapped/reordered object IDs, malformed graph rejection, wrong expectations preserving an existing artifact, and zero/large initial states. The reference tests and generated replay also pass AddressSanitizer/UndefinedBehaviorSanitizer. The reference runtime compiles as freestanding AArch64 code without unresolved symbols.

This prototype uses explicit object registrations and a hand-written schema. JSON and formatted I/O are review tools, not a proposed low-overhead kernel fast path. Kernel integration should generate bounded serializers from reviewed type information and static dependencies, use a compact capture format, and establish a coherent checkpoint boundary across relevant writers and lifetimes. Locks, DMA and MMIO cannot be captured by simply traversing this table.

KLEE has not certified this object-checkpoint contract or minimized its fields; embedded metadata says so. The next analysis step is to vary omitted initial fields independently, require equal retained checkpoint/transcript to imply equal declared observations, and validate a decoder that reconstructs a representative state. The [scalar EL0 exporter](el0-export.md) remains restricted to scalar arguments/private stack; it does not yet consume these pointer-bearing checkpoints.

The separate [syscall checkpoint pipeline](syscall-checkpoints.md) now reconstructs typed process/file/buffer state for sequential calls through the pinned LiteOS-A `SysRead` body. It has its own explicit models and bounded KLEE reconstruction check; the completion-model checkpoint contract described here remains unchanged.
