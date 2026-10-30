# Automatic restoration of initialized kernel state

The shared Clang context transformer supports initialized mutable file-scope scalars, structures, pointers and arrays. Kernel ports can retain C scalar-array, structure-array, pointer-array, string and multidimensional-array initializers, including sparse designated elements. Each independent kernel session reconstructs those values in its own context. Pointers to owned objects or array elements are rebound to that context before execution. All initializer expressions stay in their original source scope, so private enums, constant macros and readonly constants remain available.

For example, a reviewed port can supply ordinary C declarations:

```c
static Buffer buffers[2] = {
    [0] = {.words = {[0] = 0x13579bdf, [3] = 0x2468ace0}},
    [1] = {.words = {0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00}}
};
static uint32_t *cursor = &buffers[1].words[1];
```

The transformer moves `buffers` and `cursor` into `osrec_kernel_context`, threads that context through dependent kernel functions, and generates a restoration helper for the array. The helper constructs a typed seed, with owned-state references rewritten to destination fields, and copies it into the destination array. A prototype and helper call are included in the generated restoration path. Helpers are placed beside the original declarations so private enums and constant macros remain available in their original source scope. The context plan retains an `array_initializers` list naming each array, its exact target type and its generated function.

Scalar, structure and pointer seeds now use the same source-local reconstruction:

```c
enum {PRIVATE_LOW = 7};
#define PRIVATE_HIGH UINT64_C(0x100000000)
static const uint64_t private_seed = PRIVATE_HIGH + PRIVATE_LOW;
static Ledger ledger = {.value = private_seed, .calls = 0};
static Ledger *alias = &ledger;
```

`ledger` and `alias` become context fields, while `private_seed` stays readonly in its source. Their helpers construct `Ledger` and `Ledger *` seeds beside the original declarations, replacing `&ledger` with the destination context's address. The generated context header contains types, helper prototypes and restoration calls; it no longer needs the private initializer expressions. `value_initializers` records each initialized non-array file-scope field's name, type, source and helper function. The existing array and local-static report keys retain their meaning.

Clang expansion locations identify the original initializer's start. A delimiter scan retains its complete C expression, including arguments to function-like constant macros and commas or semicolons inside nested initializers, strings or comments. AST declaration IDs still decide which references bind to owned state. An owned object passed as a macro argument can be rewritten when its spelling is inside the source expression; a macro body spelling an owned object outside that expression still requires explicit source expansion or an adapter. Multi-declarator statements produce one source replacement containing every required helper.

Clang represents sparse designated array elements in `array_filler`, separately from ordinary `inner` AST children. Shared traversal includes both branches, so references in array initializers and sparse local arrays participate in ownership analysis, rewriting and function-address checks. Repeated semantic entries at the same source location produce one rewrite.

## Session and checkpoint behavior

Session initialization and explicit session reset reconstruct the original seeds, including implicit zero elements, aliases and cycles. They do not share mutable seed storage between contexts. A checkpoint load first reconstructs a fresh temporary context, then overlays saved persistent fields and rebinds recorded references. After validation it restores the destination in the same way. Thus default seeds initialize scratch or omitted transient fields, while saved persistent values and pointer positions retain all earlier syscall effects.

No checkpoint wire ABI change is required. Ports still classify every field with a reviewed [object](context-object-graphs.md) or [buffer-reference](context-buffer-references.md) policy and supply quiescent validation. Kernel records remain pinned to their archive and capture identities. Changing a port's initial state creates a new construction identity; this feature does not migrate existing records to a different kernel construction.

## Verification

The context-buffer fixture now starts with nonzero designated array contents and aliased pointers into its second buffer. Its returning-slice proof interleaves two contexts, verifies every boundary against captured values, restores one context and executes the sequence again. Its C application then advances through 0 → 1 → 2 → 4 → 5 → 6 in fresh checkpoint images, restoring each resumed interval twice.

Use the [buffer workflow commands](context-buffer-references.md) to rebuild the current fixture. Retained seeded artifacts are `build/initialized-context-kernel-final-v1`, `build/initialized-context-kernel-qemu-final-v1` and `build/initialized-context-chain-final-v1`. Kernel and all five chain images pass ELF/raw × EL1/EL3 QEMU verification, for 24 retained matrix executions. The earlier v1 artifacts retain their original zero-initialized fixture and pinned inputs.

The callable-slice regression adds a separate QEMU target with seeded cyclic structure links, pointers to array members, sparse pointer arrays, an inferred-length string containing a semicolon, a multidimensional array and source-private constants and a sparse local array referencing a public object from another translation unit. It checks initial values, interleaved updates, context isolation and reset. Removing a generated restoration helper makes the target proof fail. External declarations are distinguished from definitions: mutable references must resolve to owned storage, and an external declaration cannot bind to another source file's private static object. Construction tests reject function addresses in mutable state initializers, external mutable state and owned references whose macro spelling lies outside the initializer expression.

## Scalar and structure verification

The callable-slice regression also builds two nested, same-named source files with different private enums and function-like constant macros. It reconstructs full-width scalar seeds, a designated structure with an embedded array, an alias passed as a macro argument, a self-link, a pointer to a readonly source constant and a string containing delimiter/comment characters. It checks interleaved cumulative updates, isolation and explicit reset on QEMU. Removing either a scalar or a structure helper makes the target proof fail. Additional construction cases reject external mutable scalar references, out-of-expression owned macro spellings and restoration-helper name conflicts.

The portable external fixture now initializes its ledger structure from a file-private readonly constant built from a private macro and enum. Its alias is reconstructed against each destination ledger. The flat and nested-source port regressions both run the six-call application through 0 → 2 → 4 → 5 → 6, preserving saved ledger state after seed reconstruction. The context layout remains 24 bytes, and the checkpoint record remains 80 bytes; construction identities change with the source and generated helpers.

Retained images use `build/initialized-values-kernel-final-v1`, `build/initialized-values-kernel-qemu-final-v1` and `build/initialized-values-chain-final-v1`. Reproduce them with new output directories:

```sh
python3 tools/export_syscall_slices.py \
  --capture tests/fixtures/portable-slice-port \
  --port tests/fixtures/portable-slice-port/port.json --out build/my-initialized-values-kernel
python3 tools/verify_syscall_slices.py \
  --image build/my-initialized-values-kernel --out build/my-initialized-values-kernel-qemu
python3 tools/run_c_application_checkpoint_chain.py \
  --slices build/my-initialized-values-kernel \
  --source tests/fixtures/portable-slice-port/application.c \
  --spec tests/fixtures/portable-slice-port/spec.json \
  --pause-ordinals 2,4,5 --out build/my-initialized-values-chain
python3 tools/run_c_application_checkpoint_chain.py --verify build/my-initialized-values-chain
```

The retained kernel matrix and four chain stages passed 20 QEMU executions across ELF/raw and EL1/EL3. Offline chain verification passed, and retained construction hashes identify the tools used for that build. Saved `(ledger.value, ledger.calls)` pairs are `(8589934601, 2)`, `(4294967313, 4)` and `(12884901908, 5)`. Guest host services remain disabled throughout.

All seven affected CTest suites passed in 298.92 seconds: callable slices (now nine tests), external ports, object graphs, buffer references, application checkpoints, application frames and the CPU gateway. Evidence is `build/live-syscall-checks/qemu-value-initialization-results.xml`. The focused scalar/array/local-static/initializer-rejection checks passed in 8.92 seconds, in `build/live-syscall-checks/value-initialization-focused-final.log`.

## Mixed readonly and mutable declarations

A single declaration can define both readonly objects and mutable pointers:

```c
static const uint64_t seed = 13, bias = 7, *alias = &seed;
static const uint64_t zeros[2], *zero_alias = &zeros[1];
```

The transformer retains `seed`, `bias` and `zeros` as ordinary readonly definitions in their original source scope. It moves `alias` and `zero_alias` into context fields and reconstructs them against the retained image data. Retained definitions appear before the generated helpers replacing that statement. Readonly objects receive neither context fields nor wire entries. Initialized and implicitly zero-initialized readonly arrays retain their values.

The same ownership rule applies inside functions. For example, `static const uint64_t local_bias=5, *alias=&file_seed;` retains `local_bias` inside the function and gives `alias` a generated local-state field. Its initializer can reference the preceding file-scope constant `file_seed`. If an initializer references a readonly function-local object, that object and its readonly dependencies are now [lifted into private source storage](local-static-context-state.md#ownership-and-reconstruction), preserving identity in the function and the restoration helper. Mutable seeds can also use [ordinary block-local enum constants](local-static-context-state.md#local-enum-seed-checkpoint-workflow), reconstructed with their target values and lexical scopes. Function-local field types and lifted readonly seeds depending on those enums still require preparation.

The optional `retained_declarations` plan list records each retained definition's original declaration name, relative source path, exact type and original source byte offset. Function-local entries also identify the owning function, including qualified private-function keys. Source identities and offsets describe the prepared input, before rewriting. [Byte-preserving rewriting](external-kernel-ports.md#byte-preserving-source-workflow) keeps UTF-8 literals intact and hashes the original source bytes, including CRLF and an optional BOM.

This support covers ordinary declaration types available in source/model headers. Mixed declarations with inline type definitions, complex type prefixes, object attributes or TLS require explicit source preparation or an adapter. A readonly initializer referring to context-owned mutable state is rejected: its address cannot be shared unchanged between sessions. Anonymous objects and function references in retained initializers also require explicit contracts. These rejected cases fail before rewriting files.

The callable test checks retained file-scope scalars, a zero-initialized array and a function-local constant, together with interleaved mutable pointer/counter updates, context isolation and reset. Changing a retained seed causes the QEMU target proof to fail. Separate construction cases check rejection without partial source mutation.

`tests/test_mixed_declaration_checkpoint.py` creates a pinned external port variant with a readonly seed and a mutable `seed_ref` in one declaration. The source closure's `SeedReferenceCheck` verifies the reference against the image-local seed before calls and at checkpoint boundaries. The pointer is transient in this reviewed profile: it always has that canonical target, so reconstruction supplies the new image's address. Ledger values and call counts remain persisted. This does not add a wire encoding for arbitrary changing pointers into readonly image data.

Its context occupies 32 bytes and its portable record remains 80 bytes. The original external fixture remains 24/80 bytes. The new regression interleaves returning sessions, advances through 0 → 2 → 4 → 5 → 6, verifies each saved ledger state, rejects a reviewed null reference seed on target, deletes the original bundle and verifies retained inputs and the chain offline.

Retained inputs are `build/mixed-declaration-port-final-v1`; outputs use `build/mixed-declaration-kernel-final-v1`, `build/mixed-declaration-kernel-qemu-final-v1` and `build/mixed-declaration-chain-final-v1`. Rebuild into new directories:

```sh
python3 tools/export_syscall_slices.py \
  --capture build/mixed-declaration-port-final-v1 \
  --port build/mixed-declaration-port-final-v1/port.json --out build/my-mixed-declaration-kernel
python3 tools/verify_syscall_slices.py \
  --image build/my-mixed-declaration-kernel --out build/my-mixed-declaration-kernel-qemu
python3 tools/run_c_application_checkpoint_chain.py \
  --slices build/my-mixed-declaration-kernel \
  --source build/mixed-declaration-port-final-v1/application.c \
  --spec build/mixed-declaration-port-final-v1/spec.json \
  --pause-ordinals 2,4,5 --out build/my-mixed-declaration-chain
python3 tools/run_c_application_checkpoint_chain.py --verify build/my-mixed-declaration-chain
```

The retained kernel and all four chain stages passed ELF/raw × EL1/EL3 verification, for 20 matrix executions. Offline verification passed. The readonly seed addresses in the three producer images are `0x404071f8`, `0x406071f8` and `0x404071a8`; the source boundary check accepts the reference rebuilt for each image. Saved ledger value/call pairs remain `(8589934601, 2)`, `(4294967313, 4)` and `(12884901908, 5)`. Construction hashes identify the tools used for that build. Guest execution uses no host services.

Eight affected regression suites passed across the initial run and serial retries: callable slices (now ten tests), external ports, object graphs, buffer references, application checkpoints, application frames, the CPU gateway and the new mixed-declaration checkpoint suite. The initial parallel run passed six suites and hit the existing 180/240-second limits for callable/external suites. Serial retries passed in 63.80 and 105.63 seconds. Both attempts are retained in `build/live-syscall-checks/qemu-mixed-declaration-results.xml` and `qemu-mixed-declaration-retry-results.xml`; `mixed-declarations-validation.json` records the eight final passing results and hashes of both reports. Focused declaration and checkpoint tests also passed in 3.55 and 44.81 seconds.

## Remaining constraints

The existing bounded-closure requirements remain: indirect calls, TLS and volatile state need explicit adapters. Supported [function-local statics](local-static-context-state.md) now receive independent context fields. Types used in context declarations must be available from owned model headers. Initializer spelling and owned-state reference spelling must lie in the owned source expression; macro-expanded owned references outside that expression require an adapter or explicit source expansion. Constant macros inside an ordinary initializer are supported. Function addresses in mutable initializers require a separate callback contract. Anonymous compound-literal objects also require an adapter: moving their initializer into a restoration helper can shorten the lifetime of an object reached through a saved pointer.

Each restoration helper uses a typed temporary seed. Ports must fit reconstruction within their target stack and memory budgets, and must keep padding outside the persisted-state contract. Readonly constants and string literals keep their original lifetime; pointers into readonly image data still need an explicit checkpoint policy if stored in context fields. This reconstructs reviewed static pools and tables; it does not discover arbitrary heap objects or reproduce concurrent initialization. Guest execution remains self-contained, without runtime host services.

Five affected CTest suites passed in 66.30 seconds: callable slices, buffer references, object graphs, external ports and OHOS application checkpoints. Evidence is `build/live-syscall-checks/qemu-array-initialization-final-results.xml`. The final strengthened callable suite, including anonymous-object rejection, also passed in 21.58 seconds; its log is `build/live-syscall-checks/initialized-callable-final.log`.
