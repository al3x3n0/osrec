# Finding kernel code that can be extracted for EL0 replay

The analyzer identifies function closures and instruction slices that are candidates for execution in a host user process. Kernel provenance does not make an ordinary computation privileged: arithmetic, branches and access to suitable process-owned memory can run at EL0. The relevant distinction is between those computations and dependencies on hardware, privileged architectural state, address mappings, other execution contexts and external inputs.

`compiler/El0Analyzer.cpp` supports LLVM 16 and 22. `tools/analyze_el0.py` follows direct calls and proven finite callback sets from a selected root, records obstacles and state requirements, and reports a candidate closure for each included function. `--slice-return` adds a backward instruction slice of the root's return values and observable effects. Analysis alone does not transform code or declare a kernel binary safe to execute at EL0. The separate [EL0 exporter](el0-export.md) extracts, verifies and packages a restricted scalar subset.

## Build and inspect a slice

The existing LLVM 22 planner build option builds both plugins. The EL0 plugin can also be built independently with LLVM 16, matching the installed KLEE toolchain. Compiler, `opt`, bitcode linker and plugin must use the same LLVM major.

```sh
cmake -S . -B build/llvm -G Ninja \
  -DOSREC_BUILD_LLVM_PLANNER=ON \
  -DLLVM_DIR=/opt/homebrew/opt/llvm/lib/cmake/llvm \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++
cmake --build build/llvm
mkdir -p build/el0
/opt/homebrew/opt/llvm/bin/clang -O1 -fno-inline -g -fno-builtin -emit-llvm -c \
  examples/el0_slice.c -o build/el0/example.bc
python3 tools/analyze_el0.py build/el0/example.bc \
  --root el0_scenario --opt /opt/homebrew/opt/llvm/bin/opt \
  --plugin build/llvm/osrec_el0.so --out build/el0/example-unmodeled.json
python3 tools/analyze_el0.py build/el0/example.bc \
  --root el0_scenario --opt /opt/homebrew/opt/llvm/bin/opt \
  --plugin build/llvm/osrec_el0.so --boundaries examples/el0_boundaries.json \
  --out build/el0/example-modeled.json
ctest --test-dir build/llvm --output-on-failure -R '^(planner|el0_analysis)$'
```

The example has an unresolved clock dependency. Without a boundary it requires review. With the proposed transcript-backed clock boundary, `el0_scenario` and `transform` form a candidate with models. The analyzer records the model description and its incoming call sites; it does not implement or validate that model. `transform` alone is a computation candidate.

To see callback resolution and instruction candidates in actual C code:

```sh
/opt/homebrew/opt/llvm/bin/clang -O0 -g -fno-builtin -emit-llvm -c \
  examples/el0_callback_slice.c -o build/el0/callback.bc
python3 tools/analyze_el0.py build/el0/callback.bc \
  --root callback_scenario --slice-return \
  --opt /opt/homebrew/opt/llvm/bin/opt --plugin build/llvm/osrec_el0.so \
  --out build/el0/callback-slice.json
```

With the validated LLVM 22 toolchain, this example resolves both `add_seven` and `triple`, includes their bodies, and retains 13 of the root's 19 instructions. Six instructions are omission candidates, including the unused private computation. Both callback implementations are included regardless of which one a particular capture selects. The report proposes a smaller instruction set; it does not publish a rewritten executable.

```text
el0_scenario(result_pointer)
    |
    +-- kernel_clock()   unresolved input -> proposed recorded-input model
    |
    +-- transform()      ordinary computation candidate
    |
    +-- *result = value  valid writable memory / checkpoint requirement
```

For a larger analysis, compile all available callees into compatible bitcode and link them with `llvm-link`. Keep debug information and avoid inlining when source-level call boundaries matter. Missing bodies remain external dependencies. Analyze the target configuration's IR before substituting dependencies; a report over already modeled code describes that modeled code and cannot establish properties of the omitted kernel implementations.

## Report and classifications

The report contains input/IR fingerprints, target triple and data layout, included functions, static call edges, one shortest direct-call path to each function, site-specific blockers, memory requirements, recursion back edges and candidate subclosures. Debug locations are included where available. Memory accesses include origin, read/write direction, volatility, atomicity, address space, global/TLS identity and size information where available. Global addresses require binding even when code only returns an address without dereferencing it. The same instruction can yield multiple memory requirements, for example a copy's source and destination.

| Classification | Meaning |
| --- | --- |
| `computation_candidate` | No reported dependencies or memory requirements in this function closure. Well-defined inputs, ABI and code generation still require validation. |
| `candidate_with_state` | No unresolved obstacles, but memory, pointer or recursion contracts remain. |
| `candidate_with_models` | Proposed named model boundaries cut dependencies; state requirements may also remain. |
| `requires_review` | At least one operation or dependency remains unclassified. This does not imply it is a privileged instruction. |

Review domains separate architecture/address review, ordering review, environment-state review and dependency/runtime review. Inline assembly is always opaque in this version, even if its instructions could run at EL0. Integer-derived addresses, non-default address spaces, architecture entry attributes and unusual calling conventions require review. Volatile access may represent MMIO or ordinary shared memory; the analyzer does not guess which. TLS may be host TLS or kernel per-CPU state, requiring an explicit mapping.

Atomic operations can execute at EL0 on appropriate hardware. They are nevertheless unresolved for deterministic replay until the required ordering and competing contexts are accounted for. Similarly, a critical section may contain ordinary computation but depend on another task, interrupt or DMA writer. Removing a lock without understanding that dependence can change the scenario.

Ordinary `memcpy`, `memmove` and `memset` intrinsics are described as memory effects. Volatile variants and special address spaces still require review. Integer `umax`, `umin`, `smax` and `smin` are classified as portable computations. Other intrinsics remain unclassified, including cycle counters and target-specific operations. Function aliases are resolved for call traversal. No functions are ignored merely because their names resemble recorder hooks.

## Callback target sets

The resolver handles direct function/alias values, finite `select` and PHI alternatives, loads at constant offsets from immutable globals/tables with definitive initializers, and loads from private stack memory whose nearest clobber is a dominating complete store of a known function pointer. Stack resolution uses alias, capture, dominance and MemorySSA analyses. Callback data paths and target bindings remain state requirements.

Every target of a complete set is analyzed; one eligible target cannot hide another target's privileged operation. Proposed model boundaries can replace individual targets, and unmatched targets retain their code closures. If any alternative is unknown, the site stays unresolved while known alternatives are still reported and analyzed.

Mutable registrations, replaceable/external initializers, volatile or atomic pointer loads, dynamic table indices and cyclic target expressions remain unresolved. Resolution has a bounded work budget and falls back to incomplete on exhaustion. It does not enumerate address-taken functions and assume that enumeration is exhaustive. Captured callback identities could refine a specific scenario later, but would need runtime checks and a declared scenario bound.

## Instruction slices

`--slice-return` builds a dependency graph for the root function and follows SSA operands and possible preceding memory definitions backward. MemorySSA PHIs include alternatives from predecessor blocks; alias/mod-ref analysis can exclude irrelevant stores. The walk continues past partial writes and through earlier definitions, so a partial store cannot hide bytes from an earlier store. An opaque call's possible reads keep relevant private writes, while proven inaccessible private objects can be excluded.

The criterion includes all returns, all control-flow terminators, calls other than debug/lifetime markers, externally visible or unclassified writes, volatile/atomic accesses and other side effects. Keeping the full CFG and its condition operands avoids proposing branch or loop removal based only on a value dependence. Ordinary stores to unescaped private allocations become candidates for omission only when no retained operation depends on them. Memory-copy intrinsics are conservatively retained as calls.

The report contains mandatory seeds, kept instructions, omitted candidates, SSA/memory dependence edges and the resulting candidate closure. The whole-function report remains available beside it. Callee bodies are retained whole, and global bindings/pointer interfaces are conservatively reported at function granularity. This is not a minimal slice or an arbitrary-observation slicing interface. The report itself provides neither a transformation nor an equivalence certificate.

## Proposed model boundaries

A strict manifest names functions to replace and records why and how:

```json
{
  "format": "osrec-el0-boundaries-v1",
  "boundaries": {
    "kernel_clock": {
      "reason": "clock input comes from the captured scenario",
      "implementation": "proposed transcript-backed clock model"
    }
  }
}
```

Boundaries can cut a declared function or a defined function whose implementation should be excluded. Root, unknown symbols and intrinsic boundaries are rejected. Unused boundaries are reported. A boundary is a construction proposal: the final model must reproduce relevant return values, memory effects, errors, callbacks and ordering. Its implementation and reconstruction behavior need separate checks, such as the existing bounded KLEE trace analysis. The manifest hash records the exact proposals used to form the closure.

## Limits and next stages

Static call paths are possible compiler-visible paths, not captured call stacks. Every IR block is inspected without proving branch feasibility. Callback sites with incomplete target sets remain unresolved; the analyzer does not silently choose a target. Recursion is recorded without infinite stack expansion. Scheduling and interrupt handlers are separate roots and are not automatically added.

Every report explicitly sets `native_execution_verified` and `replay_equivalence_verified` to false. Absence of a reported obstacle does not prove initialized memory, pointer validity, defined arithmetic, termination, stack bounds, ownership, lack of hidden writers, equivalent struct layouts, or safe backend-generated instructions. Recompilation for another architecture requires an explicit ABI/layout contract. Executing original target machine code requires its own instruction and relocation checks.

The extraction pass recomputes dependencies from the input IR, deletes the omitted instructions without introducing undef/poison replacements, preserves the CFG, keeps reachable callee bodies and verifies the resulting module. The exporter checks a closed scalar contract, compares reference and extracted return values with KLEE, replays generated tests natively and packages a concrete checkpoint. Pointer/global state, models and asynchronous scenarios need additional contracts before this generic exporter can accept them. Scenario-specific callback identities and finer interprocedural slicing remain future work.

The existing host-adapted LiteOS-A scenario is a concrete test input. Linking its `SysRead`, user application and models reveals six included functions and ordinary memory requirements. That result describes the explicitly modeled scenario; full VFS, scheduler, driver and architecture code are outside that module.

Validation includes 20 analysis regressions on LLVM 16 and 22, two extraction regressions with native reference/slice comparisons, and five LLVM 16/KLEE export regressions. These cover callback completeness, unsafe alternatives, aliasing, partial writes, MemorySSA merges, retained effects, portable min/max, rejected state/undefinedness contracts, isolated execution, source-identity binding and detection of deliberately changed return values. The callback fixture's original code also passes 96 native input combinations.

The IR interpretation follows the [LLVM language reference](https://llvm.org/docs/LangRef.html); dependency analysis uses [MemorySSA](https://llvm.org/docs/MemorySSA.html) and [alias/mod-ref analysis](https://llvm.org/docs/AliasAnalysis.html). Plugin registration follows the [new pass manager documentation](https://llvm.org/docs/WritingAnLLVMNewPMPass.html).
