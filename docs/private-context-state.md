# Private state across C source files

The shared Clang context transformer supports mutable file-scope static objects with the same spelling in different supplied C translation units. Such definitions receive independent context fields. Public definitions retain their original field name, and an `extern` declaration resolves to the public object when its source file has no private definition of that name.

For example, the buffer fixture now contains:

```c
/* kernel.c */
static uint64_t visits;
/* Each BufferStep increments this by one. */

/* provider.c */
static uint64_t visits;
uint64_t ProviderTick(void)
{
    return Tick(); /* provider.c's private Tick increments visits by three. */
}
```

The resulting fields are `osrec_private_0_visits` and `osrec_private_1_visits`, both persisted independently. At syscall ordinal N, the port validates values N and 3N. Returning slices retain both values between calls; fresh checkpoint images restore both before their next slice.

## Declaration binding

The builder first collects definitions across the supplied sources. Unique file-scope names keep their existing context field names. Only colliding private definitions are qualified as `osrec_private_<source-index>_<declaration>`, using the zero-based order in the adapter's `sources` list. A public object that shares the spelling with private objects retains its original name.

References are rewritten by Clang declaration ID within each translation unit. Top-level and block-scope `extern` declarations join to their source's private definition when C linkage permits it, or to a supplied public definition. They never fall back to another translation unit's private storage. Duplicate public definitions, repeated owned definitions within one source and generated-name collisions reject construction. Incompatible declaration types reject before transformation. An incomplete first array extent can bind to a supplied complete array definition.

Pointer and aggregate initializers use the same binding map. Thus two files can each own `words` and `alias = &words[1]`; each alias is reconstructed against that file's separate destination array. Context threading through direct calls remains unchanged.

Immutable nonpointer const definitions remain source objects. A private constant in one file is not rebound to a mutable object with the same spelling in another file. Qualification considers the mutable definitions being moved into the context; source-private read-only definitions keep their own C identity.

`context-plan.json` adds a `private_state` list only when qualification is needed. Entries record the generated field name, source, original declaration spelling and target type. `owned_state` and initializer reports use the actual generated field names. Ports use those names in their reviewed checkpoint policies and quiescent validation callbacks. Changing source order can change qualified names and the construction/schema identity.

## QEMU verification

The callable-slice regression uses four C files: two with private counters, arrays and aliases under matching spellings; a third with a public counter under the same spelling; and an entry function with a block-scope `extern` declaration. It checks initial seeds, cumulative updates, separate contexts, alias targets, public binding, a private constant sharing a mutable object's name and reset on QEMU. A mutation that binds one file's counter to another file's storage fails the target proof. Construction tests reject duplicate public storage, unresolved references to private storage and incompatible public declaration types. The initialized-array QEMU regression also binds an incomplete external array declaration to its complete owned definition.

The [buffer-reference workflow](context-buffer-references.md#automated-qemu-workflow) also runs a six-call C application through 0 → 1 → 2 → 4 → 5 → 6 in fresh checkpoint images. Tests read both private counters and the existing function-local call counter from every saved record. The strengthened fixture has a 96-byte target context and a 184-byte portable record; its added fields and pinned source changes create a new schema identity. Earlier retained buffer builds retain their original schemas and sizes.

Retained builds are `build/private-state-kernel-final-v1`, `build/private-state-kernel-qemu-final-v1` and `build/private-state-chain-final-v1`. Kernel plus all five chain images passed ELF/raw × EL1/EL3, for 24 matrix executions. Offline chain verification passed. Saved `(kernel visits, provider visits, local calls)` values are `(1,3,1)`, `(2,6,2)`, `(4,12,4)` and `(5,15,5)`.

The object-graph, external-port and OHOS application-checkpoint regression suites passed in `build/live-syscall-checks/qemu-private-state-results.xml`. After correcting the negative probe's old fixed record-size assumption and strengthening immutable-name binding, the final callable suite (seven tests) and buffer-checkpoint suite passed in 42.29 seconds. Their evidence is `build/live-syscall-checks/qemu-private-state-final-results.xml`. The probe now derives the replacement size from the generated codec and checks that it replaced exactly one embedded record.

## Bounds

[Same-named private functions](private-context-functions.md) are now supported through separate declaration identities and dependency keys. Duplicate public function definitions still reject. Existing context type, initializer, TLS, volatile, indirect-call and state-policy restrictions still apply. Declaration-type comparison uses Clang's reported desugared type where available and otherwise requires matching spelling; additional equivalent spellings can require a reviewed model normalization.

The session and checkpoint wire ABIs are unchanged. Unique-name ports retain their context layouts and naming. The fixture provides synthetic AArch64 evidence; the real OHOS port remains the reviewed LiteOS-A file profile. Guest execution contains no runtime host interaction.
