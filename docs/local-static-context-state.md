# Function-local static kernel state

The shared Clang transformer automatically moves supported mutable function-local statics into the kernel context. Each declaration receives its own field, so repeated calls use cumulative state and independent sessions remain isolated. Ordinary automatic locals remain stack variables; immutable nonpointer const statics remain read-only source objects.

For example:

```c
uint64_t BufferStep(uint64_t operation, void *output)
{
    static uint64_t calls = 0;
    uint64_t result = 0;
    /* Update buffers and produce the return value. */
    ++calls;
    return result;
}
```

The generated field is `osrec_local_BufferStep_calls_0`. All references to that declaration become `ctx->osrec_local_BufferStep_calls_0`, and the function receives a context parameter. Callers receive context parameters through the existing direct-call dependency analysis.

## Ownership and reconstruction

Fields use `osrec_local_<function>_<declaration>_<ordinal>`, with an ordinal among mutable statics in that function's AST traversal order. Two functions with a variable named `state`, or two nested scopes in one function with that spelling, receive different fields. Declaration IDs determine reference rewriting. A collision with supplied file-scope state rejects construction.

For a [qualified private function](private-context-functions.md), `<function>` is its distinct dependency key. A `calls` static inside `osrec_private_0_Step` therefore becomes `osrec_local_osrec_private_0_Step_calls_0`. The plan's function mapping retains its original source and declaration name.

`context-plan.json` retains a `local_state` list with each generated field's name, source, function, original declaration spelling and exact target type. Initialized local statics also appear in `state_initializers`, identifying their restoration helpers; initialized arrays additionally appear in `array_initializers`. Ports use the generated field names in their ordinary field policies and validation callbacks. Renaming declarations or changing their order can change these names and therefore the construction/schema identity.

Zero initialization is part of the context-wide reset. Initialized scalars, arrays and pointers are reconstructed by source-local helpers placed before the containing function. Helpers create typed seeds and copy their bytes into the corresponding fields. Owned-state references in seeds bind to the destination context, including links into another local static's array. File-private constants available before the function remain usable. Seed initialization happens during session restore or checkpoint reconstruction; calls retain their preceding updates.

[Mixed declarations](initialized-context-state.md#mixed-readonly-and-mutable-declarations) can keep a readonly local constant beside a mutable pointer. If the pointer's initializer references that constant, the transformer lifts the constant into private source storage before the containing function. Both the function and its restoration helper then reference the same object. Constants that no restoration seed needs remain inside their original function.

For example:

```c
uint64_t Step(uint64_t amount)
{
    static const uint64_t seed = 13, *alias = &seed;
    static uint64_t total = seed;
    total += amount;
    return total + *alias;
}
```

`alias` and `total` become context fields. The readonly `seed` becomes a uniquely named `static const` definition before `Step`, followed by the two restoration helpers. Declaration-ID rewriting binds `&seed` in the function and the pointer constructor to that one definition. The scalar constructor still evaluates the seed in source scope. Readonly arrays, including strings and implicit zero elements, follow the same rule.

The transformer recursively lifts readonly local dependencies of those seeds. It distinguishes same-named constants in different functions, translation units and nested blocks. Unlifted readonly siblings in a removed declaration are retained, with their references updated if another sibling was lifted. Body references in owned macro definitions can be rewritten when that token has one declaration binding; a macro token resolving to different objects in different scopes rejects construction. `lifted_constants` records each lifted object's original declaration, source path, function key, target type, source offset and generated private symbol. These objects receive no context fields or checkpoint wire entries.

No session or checkpoint wire ABI changes are needed. Every generated field still needs a reviewed persistence, reference or transient policy. On load, fresh seed reconstruction precedes the saved-state overlay and reference rebinding. A persisted local counter therefore resumes at its recorded value rather than at its C initializer.

## Verification and workflow

The [buffer-reference workflow](context-buffer-references.md#automated-qemu-workflow) now uses a function-local static call counter. Its returning proof checks two interleaved contexts and a reset. Its C application advances through 0 → 1 → 2 → 4 → 5 → 6 in fresh images; the checkpoint test reads the saved counter at every pause and checks it equals the absolute syscall ordinal. Each image runs as ELF/raw from EL1/EL3, and resumed intervals load twice at different context addresses.

The fixture subsequently added [same-named private counters across two source files](private-context-state.md). The current context is 96 bytes and its record 184 bytes; the earlier retained local-static builds below keep their original 80-byte/168-byte layout and identities.

The callable-slice QEMU regression separately exercises initialized local counters, a sparse local array, an alias into that array, source-private constants, same-named statics in different functions and a shadowed declaration in a nested block. It verifies interleaved cumulative effects, isolation and reset. A mutation that resets a counter on each call fails the target proof.

Retained builds are `build/local-static-kernel-final-v2`, `build/local-static-kernel-qemu-final-v2` and `build/local-static-chain-final-v2`. Kernel plus five chain images passed all four QEMU modes, for 24 retained matrix executions. Offline chain verification passed. The saved local counters are exactly 1, 2, 4 and 5; the context remains 80 bytes and the record 168 bytes. The fixture's renamed field and changed pinned inputs give it a new schema identity.

Five affected CTest suites passed in 94.30 seconds: callable slices, buffer references, object graphs, external ports and OHOS application checkpoints. Evidence is `build/live-syscall-checks/qemu-local-static-results.xml`. After strengthening attribute rejection, all six callable tests passed in 19.81 seconds; the final log is `build/live-syscall-checks/local-static-callable-final.log`.

## Local readonly seed checkpoint workflow

The callable regression also checks readonly local scalars, sparse and zero-initialized arrays, a string containing delimiter/comment characters, a dependent readonly seed and same-named constants across functions, source files and nested blocks. It verifies address identity, scalar reconstruction, cumulative updates, interleaved session isolation and reset. Replacing an address comparison with a different shadowed seed makes the QEMU proof fail. Unsupported type, scope, attribute, mutable-pointee, macro-body and symbol-collision cases reject before changing either source or header files.

`tests/test_mixed_declaration_checkpoint.py` now includes a function-local variant. Its source-owned `SeedReferenceCheck` contains a readonly `private_seed` and a mutable `seed_ref` in one declaration. The shared transformation lifts the seed and generates `osrec_local_SeedReferenceCheck_seed_ref_0` for the pointer. Source boundary validation compares that pointer with the lifted object's address before calls and at each checkpoint boundary. The reviewed pointer always has that canonical target, so its policy is transient; reconstruction supplies each destination image's address. Ledger values and call counts remain persisted. Pointers whose target changes within readonly image data still require a portable reference contract.

The context is 32 bytes and the checkpoint record 80 bytes. Returning sessions interleave and reset, and the compiled C application advances through 0 → 2 → 4 → 5 → 6 in fresh images. Each resumed interval restores twice into different contexts. ELF/raw × EL1/EL3 verification checks the actual guest observations. Saved ledger value/call pairs remain `(8589934601, 2)`, `(4294967313, 4)` and `(12884901908, 5)`. A reviewed null pointer seed fails the target proof before publication. The regression deletes the original port bundle and then verifies the retained inputs and chain offline.

Create and pin the portable fixture variant, then use the ordinary export and checkpoint pipeline:

```sh
PYTHONPATH=tests python3 - <<'PY'
from pathlib import Path
from test_mixed_declaration_checkpoint import prepare_fixture
prepare_fixture(Path('build/my-local-readonly-port'), local=True)
PY
python3 tools/export_syscall_slices.py \
  --capture build/my-local-readonly-port \
  --port build/my-local-readonly-port/port.json --out build/my-local-readonly-kernel
python3 tools/verify_syscall_slices.py \
  --image build/my-local-readonly-kernel --out build/my-local-readonly-kernel-qemu
python3 tools/run_c_application_checkpoint_chain.py \
  --slices build/my-local-readonly-kernel \
  --source build/my-local-readonly-port/application.c \
  --spec build/my-local-readonly-port/spec.json \
  --pause-ordinals 2,4,5 --out build/my-local-readonly-chain
python3 tools/run_c_application_checkpoint_chain.py --verify build/my-local-readonly-chain
```

Retained inputs are `build/local-readonly-port-final-v1`. Outputs are `build/local-readonly-kernel-final-v1`, `build/local-readonly-kernel-qemu-final-v1` and `build/local-readonly-chain-final-v1`. Kernel plus four chain stages passed all four QEMU modes, for 20 retained matrix executions. Offline verification passed, construction hashes identify the tools used for that build, and guest host services remain disabled. The lifted seed addresses in the three producer images are `0x404071f8`, `0x406071f8` and `0x404071a8`; each boundary check accepts the reconstructed destination address.

Six affected CTest suites passed serially in 449.00 seconds: callable slices, OHOS application checkpoints, external ports, object graphs, buffer references and both mixed-declaration checkpoint variants. After adding the ambiguous-macro guard, the complete callable suite was rerun; all 11 tests passed in 56.25 seconds. Evidence is `build/live-syscall-checks/qemu-local-readonly-results.xml` and `qemu-local-readonly-callable-final-results.xml`. `local-readonly-validation.json` records the final passing suites and report hashes; `local-readonly-retained-evidence.json` records the retained construction hashes, saved ledger pairs and seed addresses. The focused final binding/identity test also passed in 4.62 seconds.

## Local enum seed checkpoint workflow

Mutable local seeds can now use ordinary function-local enum constants, including sparse array designators, macro arguments and pointer offsets:

```c
uint64_t Provider(uint64_t delta)
{
    enum {WIDTH = 3, INDEX = 1, SEED = 0x100000007UL};
    static uint64_t words[WIDTH] = {[INDEX] = SEED};
    static uint64_t *word = &words[INDEX];
    return *word += delta;
}
```

The restoration helper recreates the visible enum groups in nested scopes. Clang evaluates their explicit initializers for AArch64; the helper retains each evaluated initializer's integer type and keeps implicit enumerators implicit, preserving the group's target type deduction. Enum declarations in the original function remain available to ordinary execution. Declaration identities select the constants, and block and `for` scopes distinguish shadowed names. Designators omitted from Clang's expression AST also receive the visible enum scopes. These declarations add no context fields or checkpoint wire entries.

The optional `initializer_enums` plan entries identify the owned field, restoration helper and ordered lexical scopes. Each enum group records its original tag, relative source path, byte offset and enumerators. `initializer_value` and `initializer_type` describe the evaluated explicit initializer before the enum group's final conversions; `type` describes the resulting enumerator. Implicit enumerators are marked separately.

Generated context parameters and reconstruction temporaries avoid existing declaration and macro names. Macro names come from Clang preprocessing, including supplied headers. The optional `context_parameters` mapping records functions whose parameter differs from the default `ctx`; original parameter names and readonly constants keep their bindings. This changes generated spelling without changing the runtime ABI.

`tests/test_local_enum_checkpoint.py` supplies a pinned portable fixture with an enum-seeded three-word array, a pointer into its second word and a local call counter. The array and counter persist; the pointer uses the existing buffer-reference codec. Source-owned validation checks these against the ledger at every boundary. The context is 64 bytes and its checkpoint record 128 bytes. The original portable fixture remains 24/80 bytes.

```sh
PYTHONPATH=tests python3 - <<'PY'
from pathlib import Path
from test_local_enum_checkpoint import prepare_fixture
prepare_fixture(Path('build/my-local-enum-port'))
PY
python3 tools/export_syscall_slices.py \
  --capture build/my-local-enum-port \
  --port build/my-local-enum-port/port.json --out build/my-local-enum-kernel
python3 tools/verify_syscall_slices.py \
  --image build/my-local-enum-kernel --out build/my-local-enum-kernel-qemu
python3 tools/run_c_application_checkpoint_chain.py \
  --slices build/my-local-enum-kernel \
  --source build/my-local-enum-port/application.c \
  --spec build/my-local-enum-port/spec.json \
  --pause-ordinals 2,4,5 --out build/my-local-enum-chain
python3 tools/run_c_application_checkpoint_chain.py --verify build/my-local-enum-chain
```

The focused regressions check nested enum shadowing, `for` scopes, sparse macro designators, stringification, full-width signed and unsigned values, generated-name collisions, interleaved sessions and reset. A changed seed fails target validation before publication. The checkpoint regression advances through 0 → 2 → 4 → 5 → 6, loads each resumed interval twice into different contexts and verifies the raw saved array, pointer ID/offset and local counter. It also deletes the original fixture before verifying the retained inputs and chain offline.

Retained inputs are `build/local-enum-port-final-v1`; outputs are `build/local-enum-kernel-final-v1`, `build/local-enum-kernel-qemu-final-v1` and `build/local-enum-chain-final-v1`. Kernel plus four chain stages passed ELF/raw × EL1/EL3, for 20 retained matrix executions. Offline verification and construction/input hash checks passed; guest host services remain disabled. At saved ordinals 2, 4 and 5, the second array word equals the ledger value, the local counter equals the ordinal, and the pointer record is buffer ID 1/byte offset 8. The other two words remain zero.

Eight affected CTest suites passed serially on the finished tools in 463.18 seconds: callable slices, OHOS application checkpoints, external ports, object graphs, buffer references, mixed declarations, source bytes and local enums. The enum suite contains four tests, including macros supplied by a model header. Evidence is `build/live-syscall-checks/qemu-local-enum-final-results.xml`, `local-enum-validation.json` and `local-enum-retained-evidence.json`. The latter records raw saved state, source byte offsets, enum snapshots and construction identities.

## Bounds

Context field types must be available from the supplied model headers. Function-local typedefs and tags, including enum field types, casts or `sizeof` in moved initializers, reject construction. Enum attributes, fixed underlying types and initializer integer types wider than 64 bits require preparation. Lifted readonly seeds that themselves depend on local enums remain unsupported. Automatic variables still require preparation. Constant macros must be available before the containing function; moving a seed cannot depend on a macro defined inside that function. Object attributes such as explicit alignment or a section assignment require an adapter, so moving a declaration cannot silently discard them. Static scalar and aggregate initializers must meet the same owned-expression and reference rules as file-scope state. Function addresses, anonymous compound-literal objects, TLS and volatile state require explicit contracts. Lifted readonly initializers cannot refer to context-owned mutable state. Rewriting dependent constant references requires their spelling inside the owned initializer expression; unsupported macro-body spellings and generated-symbol conflicts reject before source mutation. Reconstruction temporaries must fit the target stack budget.

This extends the reviewed static-storage closure. It does not infer arbitrary heap graphs, indirect callback contracts or concurrent initialization. The fixture remains synthetic AArch64 evidence; the real OHOS port remains the reviewed LiteOS-A file profile. All guest execution is self-contained.
