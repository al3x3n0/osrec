# Build-time PC index

The latest [runtime optimization](el0-runtime-optimization.md),
[immutable-page bitmap](el0-page-bitmap.md) and call specialization reduce
runtime instructions further to **4,465,783 (1.4684:1)**. Kernel indirect
entries and direct thunks use 32-byte frames; user frames retain 64 bytes.
The index implementation and preceding
measurement below remain the baseline for that change.

The pretranslated-memory exporter now embeds a read-only two-level PC index in
the ELF. Indirect branch cache misses and runtime context resumes use it instead
of searching the original-PC table. The existing user/kernel domain checks,
native-stack admission and missing-target diagnostics remain active.

Each domain has a base, a power-of-two span and an array of page pointers. Each
occupied 4 KiB source-code page has 1,024 entries containing the direct-branch
and full-context resume addresses. Empty pages and instruction holes contain
zero. The index includes explicit coverage-boundary thunks, so these retain
their original diagnostic behavior. It is derived from the admitted instruction
closure and direct branch destinations, without a recorded target sequence.

The inline lookup checks alignment and the full 64-bit target range before
indexing. It saves only X16/X17, uses flag-free instructions and leaves NZCV
unchanged. BR, BLR and RET retain original-PC semantics; BLR updates X30 only
after a successful resolution. The per-site live-target cache still handles
repeated targets. Kernel and user inline lookups use separate indices.

## Measured result

Image: [checkpoint](../build/el0-indexed-20261114a/checkpoint), SHA-256
`46aa74d27499b1d6227304d9edbc273660c41b158f548a33c2313f226e15955d`.
QEMU 9.2.3 TCG Cortex-A53, one vCPU, `PROFILE=1`. Counts are dynamic
instructions, not cycles.

| Execution-interval metric | Pretranslated memory | Indexed control |
| --- | ---: | ---: |
| Runtime/adaptation instructions | 17,086,418 | **12,011,626** |
| Indirect adapters | 5,957,790 | **1,634,765** |
| Runtime `target()` instructions | 1,513,929 | **762,162** |
| Original kernel operation visits | 3,041,214 | 3,041,214 |
| Native kernel payload | 2,817,620 | 2,817,620 |
| Native application payload | 131,951 | 131,951 |
| Total instructions | 20,035,989 | **14,961,197** |
| Runtime / original kernel operations | 5.6183:1 | **3.9496:1** |

This removes **5,074,792 runtime instructions (29.70%)**. Whole-ELF execution
is 15,102,856 instructions, including 141,659 startup/final-validation
instructions. All **2,272 events**, **nine ordered counter inputs** and **92 UART
bytes** match, with 4,664 gateways, zero hardware exceptions, no EL1 runtime
service and no host calls before completion. RAM and hardware tables remain
embedded; no external page-table file is loaded.

The index occupies 23,347,264 read-only bytes: 1,415 populated kernel pages and
two user pages, plus roots and descriptors. The complete ELF grows from
135,942,328 to 159,023,152 bytes. This exchanges ELF/RAM space for fewer executed
instructions; cache/cycle effects have not been measured.

The **0.20:1 ceiling** and **0.10:1 target** remain unmet. The largest remaining
costs are checked memory adapters (4,893,604), runtime functions (3,186,338),
indirect adapters (1,634,765) and system adapters (1,266,570). Explicit user-copy
stores are prominent remaining memory sites; they still require live mapping,
permission and fault behavior.

- [Counts](../build/el0-indexed-profile-20261114a/counts.json)
- [Budget assessment](../build/el0-indexed-profile-20261114a/budget.json)
- [Measured workload validation](../build/el0-indexed-measurement-20261114a/validation.json)
- [Loaded code/data identity](../build/el0-indexed-profile-20261114a/profile-plan.json)
- [Remaining hotspots](../build/el0-indexed-profile-20261114a/hotspots.json)
- [Embedded memory report](../build/el0-indexed-20261114a/pretranslated-elf.json)

## Verification and reproduction

The indirect-branch fixture executes 29,376 cases across the preceding and new
lookup paths. It checks changing targets, zero initialization, holes, alignment,
unsigned bounds, high kernel PCs, scratch-register aliases, links, every NZCV
combination and all GPR/SP preservation. A full-image audit compares all 467,872
context entries with the original PC table and checks holes and read-only table
placement. Corrupt-table/guard-metadata rejection and descriptor-mismatch stops
also pass on this image.

Use the [pretranslated-memory build commands](el0-pretranslated-memory.md#build-and-verify);
new exports select the index automatically and record `pc_lookup_backend` as
`page-index` in the manifest. Existing exports retain their generated backend.
When rebuilding an annotated pretranslated image for profiling, finalize that
copy with `PRETRANSLATE=1` too, before running the identity/map check.

```sh
OSREC_EL0_INDEXED_IMAGE=build/el0-indexed-20261114a \
  python3 -m unittest discover -s tests -p test_el0_indirect_cache.py -v
OSREC_EL0_PRETRANSLATED_IMAGE=build/el0-indexed-20261114a PYTHONPATH=tests \
  python3 -m unittest test_el0_pretranslate.PretranslatedImage -v
```
