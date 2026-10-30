# Private functions across C source files

The shared Clang transformer supports same-named static function definitions in different supplied C translation units. Each private helper retains its own calls, context requirements and local static storage. A public function under the same spelling keeps its existing root name and binds public declarations from other sources.

The buffer fixture now has a private `Tick` in each of `kernel.c` and `provider.c`:

```c
/* kernel.c */
static uint64_t Tick(void) { return ++visits; }

/* provider.c */
static uint64_t Tick(void) { visits += 3; return visits; }
uint64_t ProviderTick(void) { return Tick(); }
```

The transformed spellings are `osrec_kernel_osrec_private_0_Tick` and `osrec_kernel_osrec_private_1_Tick`. Both receive context parameters, and each accesses its source's separately owned `visits` field. Their static linkage remains private; the compiler can still inline them. Ports expose public syscall roots or wrappers for dispatch.

## Declaration identities and dependencies

The transformer collects definitions and declarations before building the call graph. Unique function names keep their existing dependency keys and transformed spellings. Colliding private definitions use `osrec_private_<source-index>_<declaration>`, with the source index taken from the adapter's ordered `sources` list. Public definitions keep their original key.

Each translation unit maps Clang declaration IDs to its own private definition or to a supplied public definition. This includes forward declarations, direct calls and block-scope external declarations. An unresolved declaration cannot bind to another source's private function. Duplicate public definitions, repeated definitions in one source and generated-key collisions reject construction.

Context requirements propagate through these distinct dependency keys. If one source's `Tally` is pure and another source's `Tally` changes owned state, the first keeps its original arguments while the second receives a context argument. The same binding map drives renaming and function-address escape checks.

Source-local macros can invoke the private helpers and receive the proper name and context rewrite. All rewrites remain tied to their original spelling location. One shared header declaration or macro cannot be rewritten into two different private names: conflicting shared spellings reject rather than selecting one file's implementation. Put such prototypes and macros in their respective source files, or supply a reviewed adapter/expanded closure.

## Generated plan and state policy

`context-plan.json` adds a `private_functions` list when qualification is needed. Each entry gives the function key, source, original declaration name and transformed symbol spelling. `symbols`, `signatures`, `function_dependencies`, `context_functions` and `pure_functions` use the corresponding function keys.

[Local static fields](local-static-context-state.md) use that key too. For example, a `calls` static inside `osrec_private_0_Step` becomes `osrec_local_osrec_private_0_Step_calls_0`. Its `local_state.function` points to the qualified key, and ports classify its generated field through the existing checkpoint policy. Changing source order can change qualified keys and construction/schema identities.

## QEMU verification

The callable regression uses two files with private `Step` and `Tally` helpers, a third with a public `Step`, and an entry function with a block-scope external `Step` declaration. The private steps own separate counters and same-named local statics. One tally is pure; the other increments local persistent state. The proof checks dependency keys, private/public binding, initial values, cumulative effects, interleaved session isolation and reset. Replacing a private call with the public implementation has a valid signature but fails the target proof.

Construction tests reject duplicate public functions, unresolved external references to private helpers, escaping context-function addresses, shared header prototypes that require incompatible names and generated-key collisions.

The [buffer-reference workflow](context-buffer-references.md#automated-qemu-workflow) advances a six-call C application through 0 → 1 → 2 → 4 → 5 → 6 in fresh images. The two private ticks update the independently persisted counters to N and 3N at ordinal N. The existing local call counter, buffer contents and cursor positions also survive each restore. The layout stays 96 bytes and the record stays 184 bytes; changed pinned source/closure identities produce a new schema identity.

Retained builds are `build/private-function-kernel-final-v1`, `build/private-function-kernel-qemu-final-v1` and `build/private-function-chain-final-v1`. Kernel plus all five chain images passed ELF/raw × EL1/EL3, for 24 matrix executions. Offline chain verification passed. Saved `(kernel visits, provider visits, local calls)` values remain `(1,3,1)`, `(2,6,2)`, `(4,12,4)` and `(5,15,5)`.

All five affected CTest suites passed in 143.65 seconds: callable slices (eight tests), buffer checkpoints, object graphs, external ports and OHOS application checkpoints. Evidence is `build/live-syscall-checks/qemu-private-function-results.xml`.

## Bounds

The call contract remains direct-call C. Indirect dispatch and escaping context-function addresses need explicit callback contracts. Mutable initializer function addresses, shared private header bodies, TLS, volatile state, unsupported local types and arbitrary heap graphs retain their existing restrictions. This qualification does not infer missing dependency models or kernel state from user registers.

Unique-name ports retain their function keys and context layouts. Session, frame, gateway and checkpoint wire ABIs are unchanged. This fixture is synthetic AArch64 evidence; the real OHOS port remains the reviewed LiteOS-A file profile. Guest execution uses no runtime host interaction.
