# Embedded immutable-page bitmap

The latest [runtime optimization](el0-runtime-optimization.md) keeps the store adapter and
bitmap unchanged while reducing runtime/adaptation to
**6,177,120 (2.0311:1)**. The measurements below remain the bitmap baseline.

Pretranslated exports replace the user-store adapter's linear scan of immutable
physical spans with a read-only bitmap embedded in the ELF. The measured image
has 219 protected spans covering 1,137 pages. Each user-copy store previously
could traverse most of that list before writing ordinary RAM.

Construction sets one bit for every canonical RAM page intersecting an
immutable span. The adapter checks that the translated physical access lies
inside canonical RAM before indexing by its RAM-relative page number. A set
bit takes the existing checked fallback before the store. Single-page admission
already excludes accesses crossing a page boundary. All physical aliases share
the same protection bit. Partial immutable spans conservatively protect their
whole page here; the fallback retains byte-range handling.

Only the immutable-write check changes. Captured tables are still read live;
root/geometry, parent restrictions, AF, permissions, backing, alignment,
writeback and fault handling retain their existing checks. The **26,113-byte**
bitmap requires no startup construction or separate runtime file. The model
verifies its compiled bits against the protected spans and bound metadata and
rejects any writable ELF load page covering it. Earlier exports retain their
generated span-scan backend.

## Measured result

Image: [checkpoint](../build/el0-page-bitmap-20261114a/checkpoint), SHA-256
`4a7d3f221537a2ff349a602e51f2a3343c2a4a0d96cd7e38541657cffbd1bdf4`.
QEMU 9.2.3 TCG Cortex-A53, one vCPU, `PROFILE=1`. These are instruction counts,
not processor cycles.

| Execution-interval metric | Call-tree baseline | Page bitmap |
| --- | ---: | ---: |
| Runtime/adaptation instructions | 11,742,027 | **8,107,172** |
| Memory adapter instructions | 4,893,604 | **1,258,749** |
| Native kernel payload | 2,830,860 | 2,830,860 |
| Original kernel operation visits | 3,041,214 | 3,041,214 |
| Native application payload | 131,951 | 131,951 |
| Total instructions | 14,704,838 | **11,069,983** |
| Runtime / original kernel operations | 3.8610:1 | **2.6658:1** |

This removes **3,634,855 runtime instructions (30.96%)** and **74.28%** of the
memory-adapter cost. Whole-ELF execution is 11,211,642 instructions;
startup/final validation remains 141,659. The ELF grows by only 6,120 bytes to
159,189,888 bytes because adapter code also shrinks. Cache/cycle effects remain
unmeasured.

All **2,272 events**, **nine ordered counter inputs** and **92 UART bytes**
match, with 4,664 gateways, zero hardware exceptions, no EL1 runtime service
and no host calls before completion. RAM and hardware tables remain embedded,
with no external page-table image loaded.

The **0.20:1 ceiling** and **0.10:1 target** remain unmet. Runtime functions now
dominate at 3,186,338 instructions, followed by indirect adapters (1,409,909),
system adapters (1,261,547) and memory adapters (1,258,749).

- [Counts](../build/el0-page-bitmap-profile-20261114a/counts.json)
- [Full validation](../build/el0-page-bitmap-measurement-20261114a/validation.json)
- [Loaded code/data identity](../build/el0-page-bitmap-profile-20261114a/profile-plan.json)
- [Hotspots](../build/el0-page-bitmap-profile-20261114a/hotspots.json)
- [Budget assessment](../build/el0-page-bitmap-profile-20261114a/budget.json)
- [ELF initialization](../build/el0-page-bitmap-20261114a/pretranslated-elf.json)

## Verification and reproduction

The differential QEMU fixture runs both implementations across scalar, pair,
SIMD, signed-register-offset and writeback cases; three translation geometries;
two changed-mapping passes; and 28 fault/permission/alias modes. It checks
registers, NZCV, memory and logical SP. First/last protected RAM pages and
out-of-RAM destinations are included. Construction tests cover partial pages,
overlaps, final partial RAM pages and rejected out-of-range spans. Full-image
negative checks reject corrupted bits, writable loads and missing metadata,
in addition to the preceding table/descriptor corruption checks.

New pretranslated exports enable this automatically; use the existing
[build commands](el0-pretranslated-memory.md#build-and-verify).

```sh
python3 -m unittest discover -s tests -p test_el0_user_memory.py -v
OSREC_EL0_PRETRANSLATED_IMAGE=build/el0-page-bitmap-20261114a PYTHONPATH=tests \
  python3 -m unittest \
    test_el0_pretranslate.PretranslatedImage.test_corrupted_tables_and_guard_metadata_are_rejected \
    test_el0_pretranslate.PretranslatedImage.test_bitmap_cannot_be_writable_or_unbound_from_metadata -v
```
