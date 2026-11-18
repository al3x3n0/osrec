# Runtime hot-path optimization

The latest grouped-system pass forwards DAIF values into immediately following
updates. It measures **3,516,375 runtime instructions (1.1562:1)**, **0.038% below**
the compact-state image, with identical state and source execution frequencies.
See the [current pass](#grouped-daif-forwarding).

The last profiled validation-enabled image removes repeated return-validation branches, paired
field loads and memory-walk address setup, with optional **`LTO=1`**. It retains
all **2,136 syscall gateways** and reduces runtime/adaptation instructions to
**4,465,783 (1.4684:1)**, a further **1.92%** reduction. Every original PC's
measured execution frequency remains identical. Live PTE, permission,
context-admission and fault checks remain in force.
Syscall entry remains a required runtime context switch. The preceding
[generated user returns](el0-inline-return.md), [inline system inputs](el0-system-inputs.md)
and dispatcher measurements remain below or in their linked reports.

## Execution-only production option

Export with **`--no-validation`** to remove the syscall/fault event ledger,
result-observation hook, expected event/UART data, final workload-result
comparisons, saved entry-context copies and return-context comparisons.
Validation remains enabled when the option is omitted. The generated
`runtime-config.h` selects matching C and assembly at build time; there is no
per-event mode branch. Use **`PROFILE=0`** to omit optional guest profiling too.

Two execution-only contracts are available:

| Export options | User-memory behavior |
| --- | --- |
| `--no-validation` | Live address translation; disables 43 direct user-memory sites whose proofs relied on return-context checks |
| `--no-validation --trust-syscall-abi` | Retains those direct sites under the existing syscall/fault return ABI, without checking it on every return |

The trusted contract assumes syscall returns preserve X1–X30 and SP and advance
the saved PC by four. Fault returns preserve all GPRs, SP and PC. These are the
same conditions checked by the validation-enabled backend. Use that backend
to establish the scenario contract before selecting the trusted production
option. The flag requires `--no-validation`; it does not enable result checking.

Both modes retain architectural emulation, input consumption, UART output,
live translation/permission/fault handling, immutable-code protection,
pretranslated binding guards, target resolution and unsupported-operation
stops. Native user resumes check that their stack frame fits a writable,
non-immutable admitted alias. This replaces saved-SP equality as an execution
requirement. The linker/model admission still checks construction metadata.
The oracle remains a construction input for code coverage and external inputs;
its expected event and UART outputs are absent from production images.

Build a new execution-only image with the trusted contract:

```sh
python3 tools/export_el0_program.py \
  --package build/native-application-20261109a \
  --vmlinux build/linux-kernel-clang19-20261108/vmlinux \
  --user-elf build/linux-svc-machine-checkpoint-random-fault-20261108a/init \
  --oracle build/native-application-oracle-20261109b \
  --coverage build/el0-program-reference-code-20261109a.log \
  --hardware-memory --pretranslated-memory \
  --no-validation --trust-syscall-abi --out build/el0-production-new
make -C runtime/el0_flat \
  'CC=/opt/homebrew/opt/llvm@16/bin/clang --target=aarch64-none-elf' \
  IMAGE="$(pwd)/build/el0-production-new" \
  OUT="$(pwd)/build/el0-production-runtime-new" \
  PROFILE=0 LTO=1 PRETRANSLATE=1
```

Omit `--trust-syscall-abi` for the live-translation variant. Use a fresh `OUT`
when changing mode, compiler or profiling/LTO options; the build rejects mixed
runtime objects. Existing exports without a configuration header retain their
validation-enabled behavior.

Production status 1 means execution reached the declared terminal boundary.
It does not mean results matched an oracle. Model and instruction reports carry
`runtime_validation: false` and `verification_scope: "execution-completion"`;
the trusted contract is also recorded in the manifest/model reports. The event
and expected counts are zero. Actual UART output is retained in runtime RAM and
the host model saves it separately after execution.

The initial trusted production image measures **4,116,488 runtime instructions
(1.3536:1)**, **7.82% below** the preceding checked/profiled image. This compares
validation removal plus `PROFILE=0`; it does not isolate validation alone.

| Measured configuration | Runtime instructions | Interval total | Whole ELF |
| --- | ---: | ---: | ---: |
| Checked, `PROFILE=1` | 4,465,783 | 7,435,760 | 7,577,710 |
| Execution-only, live user translation, `PROFILE=0` | 5,718,553 | 8,690,665 | 8,693,311 |
| Execution-only, trusted ABI, `PROFILE=0` | **4,116,488** | **7,088,600** | **7,091,246** |

The trusted configuration removes **347,160 actual interval instructions** and
**486,464 whole-ELF instructions (6.42%)**. Startup/final work falls from 141,950
to **2,646** instructions. Its runtime count falls by 349,295: removing the
observation hook also exposes 2,135 executions of the original branch as native
kernel payload, so that accounting reduction exceeds actual instruction removal
by 2,135. The source-PC frequency audit still matches all **29,917 PCs /
3,182,392 visits**. The non-trusting option is slower because the 43 direct user
sites become live software walks; it is measured separately rather than counted
as a speed improvement.

Both initial production variants complete the scenario at EL0 with nine counter inputs,
92 UART bytes, 2,381 gateways and zero hardware exceptions, runtime EL1 services
or host calls before completion. The host compares the production UART bytes
with the checked image; production itself performs no expected-output check.
The default build's entire result and gateway/memory/system profiles remain
identical to the preceding image. Return fixtures test both modes, including
changed saved state, live descriptors and stack admission. Production image
checks prove that the ledger and context helpers are absent, bind the mode to
the ELF, reject an invalid return stack before native access and verify the full
467,872-entry PC index. Linked branch, memory and system-group audits pass.

Initial [production ELF](../build/el0-production-20261117c/checkpoint):
**156,419,360 bytes**, SHA-256
`18f92609af7457f32d67a45eefe7c4a9110e3f1e6ebfb89ebe1caf4c78399562`.
Matching runtime objects/model are `build/el0-production-runtime-20261117c` and
`build/el0-production-model-20261117c`. The **0.20:1 ceiling** remains unmet;
these are QEMU instruction counts, not cycle measurements.

- [Production counts](../build/el0-production-profile-20261117c/counts.json)
- [Comparison, contracts and unchanged inputs](../build/el0-production-profile-20261117c/comparison.json)
- [Execution-completion report](../build/el0-production-measurement-20261117c/validation.json)
- [Actual UART output](../build/el0-production-measurement-20261117c/uart.bin)
- [Original-PC frequencies](../build/el0-production-profile-20261117c/source-visits.json)
- [Hotspots](../build/el0-production-profile-20261117c/hotspots.json)
- [Production image checks](../build/el0-production-full-checks-20261117c.log)
- [Option and return tests](../build/el0-production-option-tests-20261117c.log)
- [Broader regression tests](../build/el0-production-regression-tests-20261117b.log)
- [Default validation-enabled execution](../build/el0-validation-default-execution-20261117b/validation.json)

## Experimental descriptor write tracking

`--track-pretranslated-writes` requires `--pretranslated-memory` and is opt-in.
It caches descriptor validation only after covering the writes that could
invalidate it. The current checkpoint has 11 checked descriptors on seven
writable physical pages; an invalidation hook in C alone would miss the
original native kernel stores.

The exporter retains checked adapters for all decoded stores, including SP
writeback, exclusive windows and DC ZVA. Watched pages are excluded from native
write ranges and page-cache admission, included in the inline write-exclusion
bitmap, and mapped read-only through every guest alias. Canonical runtime RAM
remains writable. The C write-admission hook marks the cache dirty before any
write to a watched page, including partial and crossing writes. Unrelated
entries on the same page conservatively invalidate too. Native scratch/stack
accesses to protected pages still stop at the native-fault boundary.

The cache starts dirty. A successful descriptor scan clears it; clean returns
skip only that scan. Live root/TCR, destination, PSTATE and stack checks remain.
TTBR0 writes invalidate it, and changed TCR writes retain the existing
unsupported-operation policy. Records, masks, counts and expected bindings are
linked read-only and bound by model admission. A dirty failed scan keeps the
existing fallback and diagnostic. No user translation, permission result or
fault result is cached, and no EL1 write-fault handler is added.

Checked store payloads and their post-store captures use the private runtime
stack. This is necessary for SP writeback: capturing on the old guest SP after
a push can overwrite the newly stored pair before writeback is committed.
The final resume installs the updated guest SP. A real gateway fixture verifies
the pushed pair survives both captures and the native resume.

The ordinary export options remain unchanged; append the tracking flag and use
fresh image/runtime directories to reproduce the experiment. The default still
uses the selected production image and repeated live descriptor checks.

**Measured outcome: correct, but not selected as an optimization.** Descriptor
scans fall by **96.74%**, but intercepting general stores costs much more than
the scans saved. SP writeback stores in particular need private slow-path
payloads and a second context transition. The new guards also reduce call-tree
specialization opportunities.

| Production interval metric | Selected default | Write tracking |
| --- | ---: | ---: |
| Full inline descriptor scans | 2,271 | **74** |
| Hot ERET site instructions | 365,631 | **214,408** |
| Runtime/adaptation instructions | 3,516,375 | **50,533,674** |
| Runtime / original kernel operations | 1.1562:1 | **16.6163:1** |
| Context gateways | 245 | **76,551** |
| Total interval instructions | 6,488,487 | **53,499,593** |

The ERET site saves **151,223 instructions**, but total runtime grows by
**47,017,299 instructions (14.37 times the baseline runtime)**. Generated memory
adapters cost 18,774,205 instructions and C/gateway functions 28,227,648. Whole-ELF
execution is 53,502,315 instructions; outside-interval work remains 2,722.
These are instruction counts, not cycle measurements. A profitable version
needs static exclusion proofs or cheaper store handling, especially for stack
writes, before it can replace the default.

The checked image matches all **2,272 events**, nine counter inputs and 92 UART
bytes. Production and checked terminal guest contexts and UART output match
the preceding images byte for byte. Architectural shadow fields and the entry
counter also match. The diagnostic `emulated` counter rises from 95,259 to
106,662: exactly the **11,403 original DC ZVA visits** now routed through tracked
system adapters. No counter update is discarded to improve the result.
All **29,917 original PCs / 3,182,392 visits** keep their exact frequencies.
Both modes report zero hardware exceptions, runtime EL1 services and host calls
before completion.

Validation includes the actual C write hook over partial/cross-page writes,
bitmap fast returns, TTBR changes and descriptor mutation/recovery; generated
clean/dirty returns; the private-stack gateway fixture; and a complete audit
that original and cloned native stores cannot bypass the checked adapters.
Model admission rejects missing watched pages, an initially clean cache,
write-range/bitmap holes and writable validation records. The surrounding
53-test suite passes 40 tests, with 13 optional integrations skipped. Linked
control, memory and system-group audits pass.

Experimental [ELF](../build/el0-tracked-20261117b/checkpoint): **176,548,440 bytes**,
SHA-256 `2cdde187f9c1df97e82675449abf5749bdfdf0ff30da05d64cc2e2aedfa4672e`.

- [Counts](../build/el0-tracked-profile-20261117b/counts.json)
- [Comparison and state/counter explanation](../build/el0-tracked-profile-20261117b/comparison.json)
- [Descriptor-cache execution counts](../build/el0-tracked-profile-20261117b/descriptor-cache.json)
- [Checked execution](../build/el0-tracked-checked-execution-20261117b/validation.json)
- [Exact source-PC frequency audit](../build/el0-tracked-profile-20261117b/source-visits.json)

## Grouped DAIF forwarding

Within existing system groups, a DAIF read or update now supplies its value to
an immediately following DAIF set/clear operation. The generated update omits
the redundant shadow load and uses the preceding read destination or scratch
value as its first input. All stores, source-PC markers and counter increments
remain. Forwarding stops at any other operation, including a register overwrite;
no group boundary, branch, guest memory access or runtime callback is crossed.
This uses the existing single-vCPU, non-reentrant execution contract.

The image removes **417 static loads**, executed **1,332 times** in the measured
workload. Runtime instructions fall from **3,517,707 to 3,516,375 (0.038%)** and
the ratio from **1.1567:1 to 1.1562:1**. System-adapter instructions fall from
1,162,970 to **1,161,638**; other runtime categories are unchanged. Interval total
is **6,488,487**, whole-ELF total **6,491,209**, and outside-interval work remains
2,722 instructions. This is a modest instruction-count gain, not a cycle result;
the 0.20:1 ceiling remains unmet.

The expanded fixture checks **2,935 groups / 375,680 sequential-emulator
comparisons**, including every destination register, all immediate masks,
set/clear chains, intervening overwrites, arbitrary shadow bits, counter
wraparound, NZCV/SIMD preservation and header page ends. The focused and
surrounding suites pass **17 tests**, with two optional image tests skipped.
Linked control, memory and system-group audits pass.

The checked workload still matches all **2,272 events**, nine counter inputs
and 92 UART bytes; its full result and gateway/memory/system profiles match the
preceding image. Production retains 245 gateways. Its terminal guest context,
shadow header and UART output are byte-identical to both the checked image and
the preceding production image. Twenty-one construction files remain identical.
All **29,917 original PCs / 3,182,392 visits** retain their execution frequencies;
all 6,619 specialized return branches, 20,406 dynamic direct returns and every
indirect-resume frequency match the baseline.

Selected [ELF](../build/el0-daif-forward-20261117a/checkpoint): **156,337,888 bytes**,
1,664 bytes smaller, SHA-256
`f8b389dbe7baf19bd833701cebc4e6d0cba576ec0d1faf8d287820b1a4a7fb4c`.
Use the same export/build options with fresh output directories.

- [Counts](../build/el0-daif-forward-profile-20261117a/counts.json)
- [Comparison and terminal state](../build/el0-daif-forward-profile-20261117a/comparison.json)
- [Hotspots](../build/el0-daif-forward-profile-20261117a/hotspots.json)
- [Checked execution](../build/el0-daif-forward-checked-execution-20261117a/validation.json)
- [Source-PC frequency audit](../build/el0-daif-forward-profile-20261117a/source-visits.json)

## Compact system/state adapters

The generated ERET-to-user path now preserves the shadow-state base in X17
through the specialized descriptor checks, using the dead count register X16
for each expected value. The generic count-mismatch loop still reconstructs
the base; an empty table preserves it. Each live descriptor pointer, mask and
expected value is still read, with immediate rejection before the next record.

Root and TCR comparisons share a conditional compare and rejection branch.
Both expected values are bounded internal reads. After all admission checks,
paired stores commit adjacent DAIF/PAN fields and mode/emulated-counter fields.
The same counter increment, including wraparound, is preserved. These changes
remove **five instructions per successful return**. PAN system-register writes
also use one UBFX instead of LSR plus AND; the measured workload does not execute
that write, so it contributes no claimed dynamic saving.

| Execution-interval metric | Indexed-walker baseline | Compact adapters |
| --- | ---: | ---: |
| Hot ERET path per successful return | 166 | **161** |
| Hot ERET site, 2,271 successful returns | 376,986 | **365,631** |
| System adapters | 1,174,325 | **1,162,970** |
| All runtime/adaptation instructions | 3,529,062 | **3,517,707** |
| Runtime / original kernel operations | 1.1604:1 | **1.1567:1** |
| Total interval instructions | 6,501,174 | **6,489,819** |

The reduction is **11,355 instructions (0.32% of runtime)**. Whole-ELF execution
falls to **6,492,541**, with the same 2,722 instructions outside the interval.
All other runtime categories are unchanged. These are instruction counts, not
cycle measurements; the **0.20:1 ceiling remains unmet**.

The focused suite passes **21 tests**, with two optional full-image tests
skipped. It includes 48,000 grouped-system comparisons, all PAN register operands,
shadow-header page ends, descriptor-count changes, early rejection and live
return-context checks against the shared emulator. A simultaneous root/TCR
mismatch case supplements the existing independent mismatch cases.

The checked workload still matches **2,272 events**, nine counter inputs and
92 UART bytes; its full result and gateway/memory/system profiles are unchanged.
Production retains **245 gateways**. Final guest context, shadow header and UART
output match both the checked image and preceding production image byte for byte.
Both images report zero hardware exceptions, runtime EL1 services and host calls
before completion. Twenty-one construction files remain identical; only generated
adapter assembly changes. The linked control, memory and system-group audits pass.
All **29,917 original PCs / 3,182,392 visits** retain their execution frequencies;
all 6,619 specialized return branches, 20,406 dynamic direct returns and every
indirect-resume frequency match the baseline.

Selected [ELF](../build/el0-state-compact-20261117b/checkpoint): **156,339,552 bytes**
(unchanged file size), SHA-256
`ac8f17aa763a576ba3de81bc64c1dc4be3a7387bb6e5967a91ba284e2c8c0929`.
Use the same export/build options with fresh output directories.

- [Counts](../build/el0-state-compact-profile-20261117b/counts.json)
- [Comparison and terminal state](../build/el0-state-compact-profile-20261117b/comparison.json)
- [Hotspots](../build/el0-state-compact-profile-20261117b/hotspots.json)
- [Checked execution](../build/el0-state-compact-checked-execution-20261117b/validation.json)
- [Source-PC frequency audit](../build/el0-state-compact-profile-20261117b/source-visits.json)

## Ordered kernel-map lookup

The shared software walker now uses an ordered index for the linked immutable
kernel mapping table. Before entering the measured workload, it checks that
all **33 mappings** have nonzero, non-overflowing extents in sorted,
non-overlapping order. Each lookup still checks the live array pointer and
count. A mismatch retains the original first-matching-entry scan; mutable,
unsorted, overlapping, empty and overflowing tables receive no index.

A single unsigned envelope test excludes addresses outside the table's overall
VA range. Addresses inside it use binary search, followed by the original
exact-span, access-size, permission and physical-backing checks. A hole still
uses the live TTBR0 walk. No user translation or physical RAM binding is cached.
Static kernel-mapping precedence, live PTE/AF/AP/XN handling, split-access
behavior and fault diagnostics remain unchanged.

| Execution-interval metric | Adapter-fold baseline | Indexed walker |
| --- | ---: | ---: |
| Shared `page` walker | 88,053 | **43,986** |
| All runtime functions | 199,901 | **155,834** |
| All runtime/adaptation instructions | 3,573,129 | **3,529,062** |
| Runtime / original kernel operations | 1.1749:1 | **1.1604:1** |
| Total instructions | 6,545,241 | **6,501,174** |

The **44,067-instruction reduction (1.23%)** is entirely in the shared walker;
every generated adapter category is unchanged. Whole-ELF execution falls by
**43,991 instructions** to **6,503,896**. Work outside the measured interval
increases by a net 76 instructions, from 2,646 to **2,722**, including startup
admission and startup translations. The **0.20:1 ceiling** remains unmet.
These are QEMU instruction counts, not cycle measurements.

The host fixture performs **85,440 comparisons** with the original linear
lookup, including every map boundary, holes, all VA bits, zero/large/split
accesses, all access modes, AF/AP/XN errors, physical aliases, missing RAM,
TCR changes, live count changes and a changed mutable table while the immutable
index is warm. Invalid index candidates preserve overlap order. Focused tests,
the broader memory/runtime suite and the complete **467,872-entry** PC-index
check pass; optional platform/image integrations remain skipped as recorded
in the logs.

The full validation-enabled workload still matches **2,272 events**, nine
counter inputs, 92 UART bytes and 2,381 gateways. Its entire result and gateway,
memory and system profiles match the preceding checked image. Production
retains 245 gateways. Its final **792-byte guest context, 104-byte shadow header
and 92 UART bytes** match both the checked image and the previous production
image. Both variants have zero hardware exceptions, runtime EL1 services and
host calls before completion.

All **29,917 original PCs / 3,182,392 visits** retain their execution frequencies.
All **6,619** specialized return branches, **20,406** dynamic direct returns and
every indirect-resume frequency match. Twenty-two construction files, including
the generated assembly/C, initial RAM/state, manifest and hardware metadata,
are byte-identical. The generated assembly objects are reused in isolated output
directories; the annotated ELF still passes exact loaded code/data identity.
The linked branch/fallthrough, memory and system-group audits pass after relink.

Selected [ELF](../build/el0-walker-index-20261117a/checkpoint): **156,339,552 bytes**,
2,112 bytes larger, SHA-256
`22274f61a5f496cfc94136084c429fe174d4bac1da8b9242635c467f5c162d52`.
Matching objects/model are `build/el0-walker-index-runtime-20261117a` and
`build/el0-walker-index-model-20261117a`. The existing export/build commands
reproduce the pass with fresh output directories; no new option is needed.

- [Counts](../build/el0-walker-index-profile-20261117a/counts.json)
- [Comparison, unchanged inputs and terminal state](../build/el0-walker-index-profile-20261117a/comparison.json)
- [Measured execution-completion report](../build/el0-walker-index-measurement-20261117a/validation.json)
- [Checked workload and profiles](../build/el0-walker-index-checked-execution-20261117a/validation.json)
- [Original-PC frequencies](../build/el0-walker-index-profile-20261117a/source-visits.json)
- [Specialized returns](../build/el0-walker-index-profile-20261117a/direct-returns.json)
- [Resume frequencies](../build/el0-walker-index-profile-20261117a/indirect-frames.json)
- [Loaded code/data identity](../build/el0-walker-index-profile-20261117a/profile-plan.json)
- [Hotspots](../build/el0-walker-index-profile-20261117a/hotspots.json)
- [Budget](../build/el0-walker-index-profile-20261117a/budget.json)
- [Focused checks](../build/el0-walker-index-unit-tests-20261117a.log)
- [Warm-binding checks](../build/el0-walker-index-binding-tests-20261117a.log)
- [Regression checks](../build/el0-walker-index-regressions-20261117a.log)
- [Full PC-index check](../build/el0-walker-index-pc-index-20261117a.log)

## Removing redundant adapter instructions

The execution-only image now measures **3,573,129 runtime/adaptation
instructions (1.1749 per original kernel operation)**, down from 3,737,666
(1.2290:1): **164,537 instructions / 4.40%**. This pass retains every live guard,
all shadow counters, the syscall/fault ABI and the previous production options
(`--no-validation --trust-syscall-abi`, `PROFILE=0 LTO=1`).

| Removed sequence | Dynamic instructions saved |
| --- | ---: |
| Branch to the next instruction after non-rejecting system helpers | 49,859 |
| Repeated base/page additions in generic shadow-field accesses | 59,706 |
| Temporary offset spills and index-slot arithmetic in indirect lookup | 50,565 |
| Separate index-slot extraction/shift in user returns | 2,271 |
| Separate index-slot extraction/shift in syscall entry | 2,136 |
| **Total** | **164,537** |

Non-rejecting system helpers fall through when the next original PC is the
next emitted instruction. Resume thunks occupy a separate section; gaps still
branch to their coverage boundary. The linked audit verifies all **4,213**
removed static branches against captured source words, helper size, adjacent
compiler-emitted labels and the final scratch-frame restoration. Helpers with
rejection paths retain their explicit control flow.

Generic shadow-register helpers relocate the actual page of each known byte,
value and emulation counter. They retain known-bit checks, operand exclusions,
ordered updates and side-effect-free fallback. This removes three address
instructions per successful operation, without assuming the entire shadow
object or even its header occupies one page.

After alignment and bounds checks, PC indices use the aligned original target's
low 12 bits shifted left twice to address a 16-byte slot. `UBFIZ` combines the
previous extraction and shift. Ordinary indirect operands remain live until
lookup finishes; X16/X17 operands are read from their original spill. This
removes the temporary offset store/reload while retaining full target equality,
cache-empty handling, page/slot holes, domain bounds, link-register updates,
flags and both frame conventions. Index construction rejects non-page-aligned
bases explicitly. User return and syscall indices combine their extraction and
shift in the same way.

| Execution-interval category | Native syscall baseline | Current |
| --- | ---: | ---: |
| System adapters | 1,286,161 | **1,174,325** |
| Indirect adapters | 908,605 | **858,040** |
| Syscall adapters | 183,696 | **181,560** |
| All runtime/adaptation | 3,737,666 | **3,573,129** |
| Total instructions | 6,709,778 | **6,545,241** |

Every other adapter category is unchanged. Native kernel/application counts
remain **2,840,161 / 131,951**; all **29,917 original PCs / 3,182,392 visits** have
identical frequencies. All **6,619** specialized return branches and **20,406**
dynamic direct returns match. Every indirect-resume target retains its execution
frequency. Whole-ELF execution is **6,547,887 instructions**, with an unchanged
2,646 outside the measured interval. The **0.20:1 ceiling** remains unmet;
these are QEMU instruction counts, not cycles.

The full validation-enabled export also passes: **2,272 events, nine counter
inputs, 92 UART bytes and 2,381 gateways**. Its entire result and gateway,
memory and system profiles match the previous checked image byte for byte.
Production retains 245 gateways. Its final **792-byte guest context, 104-byte
shadow header (including counters) and 92 UART bytes** match both the previous
production image and the new checked image. Both variants have zero hardware
exceptions, runtime EL1 services and host calls before completion.

The expanded differential fixtures exercise all indirect source registers,
BR/BLR/RET, both frame conventions, empty/hit caches and slots immediately
before/after a page boundary, including slot 1023. Shadow-register fixtures now
cover three header placements (offsets 0, 3968 and 4088), generic known-bit/value
pages, scratch aliases, unknown reads, counter wraparound and rejection without
mutation. Focused and broader regression checks pass; the full image checks
and linked branch/memory/system-group audits are recorded below. Nineteen
construction files, including the manifest and hardware mapping metadata, are
byte-identical to the previous production image.

Selected [ELF](../build/el0-adapter-fold-20261117a/checkpoint): **156,337,440 bytes**,
124,160 bytes smaller, SHA-256
`bd4c23f5ca6537157ab179be5a9c1cff496be640cd776681fc265a8d2c76577b`.
Matching objects/model are `build/el0-adapter-fold-runtime-20261117a` and
`build/el0-adapter-fold-model-20261117a`. The existing export/build commands
reproduce the pass with fresh output directories; no new option is needed.

- [Counts](../build/el0-adapter-fold-profile-20261117a/counts.json)
- [Comparison, sequence savings and unchanged inputs](../build/el0-adapter-fold-profile-20261117a/comparison.json)
- [Measured execution-completion report](../build/el0-adapter-fold-measurement-20261117a/validation.json)
- [Checked workload and profiles](../build/el0-adapter-fold-checked-execution-20261117a/validation.json)
- [Original-PC frequencies](../build/el0-adapter-fold-profile-20261117a/source-visits.json)
- [Specialized returns](../build/el0-adapter-fold-profile-20261117a/direct-returns.json)
- [Resume frequencies](../build/el0-adapter-fold-profile-20261117a/indirect-frames.json)
- [Loaded code/data identity](../build/el0-adapter-fold-profile-20261117a/profile-plan.json)
- [Linked branches and adapter fallthroughs](../build/el0-adapter-fold-20261117a/control-compiled.json)
- [Hotspots](../build/el0-adapter-fold-profile-20261117a/hotspots.json)
- [Budget](../build/el0-adapter-fold-profile-20261117a/budget.json)
- [Focused checks](../build/el0-adapter-fold-unit-tests-20261117a.log)
- [Extended indirect-boundary checks](../build/el0-adapter-fold-indirect-boundaries-20261117a.log)
- [Regression checks](../build/el0-adapter-fold-regressions-20261117a.log)
- [Full-image checks](../build/el0-adapter-fold-full-checks-20261117a.log)

## Native syscall entry in execution-only images

Execution-only pretranslated exports now inline plain SVC entry at **108 static
sites**. Every executed SVC still enters the original captured kernel vector;
its syscall dispatch, memory accesses and return path execute normally. The
adapter replaces the full SIMD/GPR gateway with a private 80-byte scratch
frame and the existing compact kernel-resume convention. Validation-enabled
exports retain their event ledger, saved contexts and syscall gateways.

Before committing, the adapter checks live user mode and PSTATE, aligned kernel
SP with 64 bytes of headroom in an immutable writable interval, and the live
VBAR-derived vector against the complete kernel PC index. Missing, unaligned,
out-of-domain and unsupported inputs restore GPRs, SP and NZCV and enter the
original C gateway, preserving its diagnostics. No recorded sequence selects
the syscall target. Admission binds the stack interval and all source SVC words
to the ELF and construction metadata.

All six scratch GPRs move to private RAM before writing a kernel-stack frame.
This handles physical aliases between user and kernel stacks, including spills
that overlap at different offsets. The architectural transition retains FAR,
PAN, PSTATE and SIMD/FP state, updates ESR/ELR/SPSR and logical stacks, applies
the entry mask and increments the entry counter with its existing wraparound.
The final version pairs the NZCV/user-SP spill and load, and the adjacent
ELR/SPSR commit: three instructions are removed per successful inline SVC.
Every possible rejection precedes the architectural commit.

The preceding resolver-only pass also replaces separate scalar-equality
branches with bounded CMP/CCMP chains, retaining live mapping, RAM and stack
checks. It saves 16,050 instructions independently of the syscall adapter.

| Execution-only configuration (`PROFILE=0 LTO=1`, trusted ABI) | Runtime instructions | Interval total | Gateways |
| --- | ---: | ---: | ---: |
| Initial production image | 4,116,488 | 7,088,600 | 2,381 |
| Resolver comparison chains | 4,100,438 | 7,072,550 | 2,381 |
| Inline native syscall entry | 3,744,074 | 6,716,186 | 245 |
| Paired syscall context accesses | **3,737,666** | **6,709,778** | **245** |

The final image removes **378,822 instructions (9.20% of runtime)** from the
initial production image, with identical native kernel/application counts of
**2,840,161 / 131,951**. The inline entry accounts for 362,772 of that reduction,
including **6,408** from the three paired accesses across 2,136 SVC executions.
All 2,136 enter the kernel directly; the remaining gateways are 195 memory,
49 system and one completion boundary. Whole-ELF execution is **6,712,424**
instructions, including the unchanged 2,646 outside the measured interval.
The runtime/original-kernel ratio is **1.2290:1**; the **0.20:1 ceiling** and
**0.10:1 target** remain unmet. These are QEMU instruction counts, not cycles.

The syscall fixture performs **294,912 full-context comparisons** against the
shared emulator, covering both SVC immediates, every NZCV value, PSTATE and mode
rejections, vector holes/alignment/bounds, kernel-stack bounds/alignment,
counter wraparound, SIMD/FP state and six user/kernel stack placements.
The broader suite passes 48 checks, with nine optional integrations skipped.
All six selected full-image checks pass: invalid return stack, production-mode
binding, native syscall metadata mutations, bad kernel SP/cross-domain vector,
stack-mode metadata mismatch and the full **467,872-entry** PC-index/frame audit.
The validation-enabled image still matches all **2,272 events**, nine counter
inputs and 92 UART bytes with its 2,381 gateways.

Host-side comparison finds the final **792-byte guest context, 104-byte shadow
header and 92 UART bytes identical** between the production and checked images.
This evidence is collected after completion; no expected values or comparisons
are added to production execution. Hardware exceptions, runtime EL1 services
and host calls before completion remain zero. Seventeen construction files,
including initial RAM, state, input counters and previous optimization proofs,
are byte-identical to the initial production export.

The linked branch, memory and system-group audits also pass. Every original
PC's frequency matches: **29,917 PCs / 3,182,392 visits**. All **6,619** specialized
return branches retain their continuations and **20,406** dynamic executions.
Existing indirect-resume frequencies match; direct kernel-vector resumes add
the 2,136 inline entries previously handled by full-context gateways.

Selected [ELF](../build/el0-native-svc-20261117b/checkpoint): **156,461,600 bytes**,
42,240 bytes larger than the initial production image, SHA-256
`0b5e5464d5a12397b03c4295966076b0476f03592cd949df5039858f59102879`.
Matching objects/model are `build/el0-native-svc-runtime-20261117b` and
`build/el0-native-svc-model-20261117b`. Reproduce with the execution-only export
and build commands above; new pretranslated exports select native syscall entry
automatically when a writable kernel-stack interval is available.

- [Counts](../build/el0-native-svc-profile-20261117b/counts.json)
- [Comparison and terminal-state/input identity](../build/el0-native-svc-profile-20261117b/comparison.json)
- [Measured execution-completion report](../build/el0-native-svc-measurement-20261117c/validation.json)
- [Checked workload and terminal state](../build/el0-checked-regression-execution-20261117b/validation.json)
- [Original-PC frequencies](../build/el0-native-svc-profile-20261117b/source-visits.json)
- [Specialized returns](../build/el0-native-svc-profile-20261117b/direct-returns.json)
- [Resume frequencies](../build/el0-native-svc-profile-20261117b/indirect-frames.json)
- [Loaded code/data identity](../build/el0-native-svc-profile-20261117b/profile-plan.json)
- [Hotspots](../build/el0-native-svc-profile-20261117b/hotspots.json)
- [Budget](../build/el0-native-svc-profile-20261117b/budget.json)
- [Full-image checks](../build/el0-native-svc-full-checks-20261117b.log)
- [Regression checks](../build/el0-native-svc-regressions-20261117b.log)

## Return validation and live memory walks

| Execution-interval metric | Previous combined pass | Current pass |
| --- | ---: | ---: |
| System adapters | 1,443,132 | **1,406,796** |
| Memory adapters | 706,615 | **655,400** |
| All runtime/adaptation instructions | 4,553,334 | **4,465,783** |
| Total instructions | 7,523,311 | **7,435,760** |
| Runtime / original kernel operations | 1.4972:1 | **1.4684:1** |

Generated user returns compare X1–X30 in one CMP/CCMP chain, with a single
rejection branch. A failed comparison keeps Z clear through the remaining
comparisons. Expected-register loads are bounded internal-state reads; no
context commit occurs before rejection. X0 retains its syscall-specific check.
All registers are still compared, including spilled scratch registers.

The return also loads the live translation root/TCR and saved SP/PC as adjacent
pairs. Across **2,271 successful returns**, removing fourteen intermediate
branches and two separate loads saves **36,336 instructions**: 31,794 branches,
2,271 TCR loads and 2,271 PC loads. SP alignment/headroom, saved PC advancement,
SPSR, live descriptor and destination-index checks remain active.

Live user-memory helpers load root/TCR together and retain the fresh root in
their unused frame slot at offset 56. They establish the canonical RAM base
once, reuse it for each table read and the final data address, and check parent
AP restrictions at each table instead of accumulating them in another register.
Block descriptors branch to their leaf checks before table-only AP tests.
The immutable bitmap uses a separate work register; the legacy span scanner
restores the RAM base after using that register as its cursor.

These changes save **51,215 memory-adapter instructions** in aggregate. Each
access still reads live PTEs and checks physical bounds before dereferencing
them. The root is retained only within one access. Earlier parent-permission
rejections restore the original inputs and enter the shared C walker, which
preserves diagnostic precedence when a later PTE is also invalid. AF, leaf AP,
write protection, immutable aliases, address exclusions and fallback remain.

All six focused CTest modules pass. The return fixture performs **473,088
context comparisons**, covering each GPR bit, all NZCV values, syscall/fault
returns and descriptor-count hints. The memory fixture exercises **12,288
cases**, including combined parent-permission/PTE failures, both immutable-page
backends, grouped accesses, three walk geometries and both exclusion backends.
All twelve malformed-image checks and the full **467,872-entry** PC-index/frame
audit pass. Linked audits verify **70,127** shortened conditional branches,
**6,619** specialized returns, memory elision and all system groups.

All **29,917 executed original PCs / 3,182,392 visits** retain their exact
execution frequencies. Dynamic specialized returns remain 20,406. Native
kernel/application counts remain **2,838,026 / 131,951**. Nineteen construction
inputs/proofs and the manifest are byte-identical. Results and gateway, memory
and system profiles match: 2,272 events, 2,381 gateways, nine counter inputs,
92 UART bytes and 185 faults. Hardware exceptions, runtime EL1 services and
host calls before completion remain zero.

Whole-ELF execution is **7,577,710 instructions**, including 141,950 outside the
measurement interval. The delivered
[ELF](../build/el0-next-slices-20261117a/checkpoint) is **156,605,944 bytes**,
54,912 bytes smaller, SHA-256
`1f08c5418985bf5d2e164bcf05d628dc69f381c1fc8457890918616c84a31352`.
The **0.20:1 ceiling** and **0.10:1 target** remain unmet. QEMU 9.2.3 TCG
Cortex-A53, one vCPU, `PROFILE=1 LTO=1`; these are instruction counts, not cycles.

- [Counts](../build/el0-next-slices-profile-20261117a/counts.json)
- [Comparison and input identity](../build/el0-next-slices-profile-20261117a/comparison.json)
- [Measured validation](../build/el0-next-slices-measurement-20261117a/validation.json)
- [Original-PC frequencies](../build/el0-next-slices-profile-20261117a/source-visits.json)
- [Direct-return audit](../build/el0-next-slices-profile-20261117a/direct-returns.json)
- [Indirect-frame audit](../build/el0-next-slices-profile-20261117a/indirect-frames.json)
- [Loaded code/data identity](../build/el0-next-slices-profile-20261117a/profile-plan.json)
- [Hotspots](../build/el0-next-slices-profile-20261117a/hotspots.json)
- [Budget](../build/el0-next-slices-profile-20261117a/budget.json)
- [Focused checks](../build/el0-next-slices-checks-20261117a.log)
- [Malformed-image checks and PC-index audit](../build/el0-next-slices-negatives-20261117a.log)

Matching model: `build/el0-next-slices-model-20261117a`. The unchanged C runtime
objects are reused from `build/el0-multi-slice-objects-20261116a`.

### Historical build cleanup

The November 17 cleanup removed **176 generated assembly, object and linker-map
intermediates / 21.58 GiB logical size** from superseded EL0 images. Current and
comparison-baseline images, their annotated assembly and runtime objects remain.
Historical executables, construction inputs and measurement reports are retained;
historical audits needing deleted assembly require restoring/rebuilding those
intermediates. The [cleanup manifest](../build/old-build-cleanup-20261117a.json)
lists every removed file. Repository source files were excluded.

## Combined removal of six runtime sequences

| Execution-interval metric | User-exclusion lookup | Combined pass |
| --- | ---: | ---: |
| System adapters | 1,495,346 | **1,443,132** |
| Indirect adapters | 974,228 | **908,605** |
| Resume thunks | 230,742 | **165,119** |
| Observation | 78,995 | **74,725** |
| Syscall entry stubs | 38,448 | **36,312** |
| Memory adapters | 706,810 | **706,615** |
| All runtime/adaptation instructions | 4,743,396 | **4,553,334** |
| Total instructions | 7,713,373 | **7,523,311** |
| Runtime / original kernel operations | 1.5597:1 | **1.4972:1** |

The six removed sequences account for the entire **190,062-instruction saving
(4.01%)**, without counting the same instruction in more than one slice:

| Removed instruction sequence | Dynamic instructions saved |
| --- | ---: |
| Separate kernel indirect-entry SP adjustment | 65,623 |
| Separate kernel indirect-resume SP adjustment | 65,623 |
| Repeated system-operation scaffolding | 44,002 |
| Repeated header-address ADD in copied system operations | 8,163 |
| Duplicate observation load/address setup | 4,270 |
| Separate native gateway-entry SP adjustment | 2,381 |

**Kernel indirect frames** now use a 32-byte frame with X16/X17 saved at offset
zero and the lookup temporary at offset 16. A pre-indexed STP combines stack
allocation and spilling; a post-indexed LDP combines restoration and release.
Guarded dispatch, index lookup, cache probes and all kernel direct resume thunks
use the same layout. Full 64-bit live-target equality, index bounds/alignment,
empty-cache checks and slow fallback remain. User indirect frames and generated
ERET-to-user returns retain their 64-byte convention; the existing kernel-stack
admission contract remains in force.

The complete PC-index audit verifies all **466,477 kernel** and **1,395 user**
direct thunks, including the appropriate frame instructions and destination
equality with the full-context resume. Each original target's dynamic direct
resume frequency is unchanged: **65,623 kernel** and **4,148 user** resumes.
Kernel entry and return each save one instruction. Static kernel thunk size
falls by four bytes per entry.

**Adjacent system operations** share one scratch pair, one shadow-page base,
one emulation-counter increment and one continuation branch. The planner admits
only consecutive operations already supported by the aligned-header inline
backend, up to eight at a time. It excludes platform actions, metadata-sensitive
operations, branches, context edges and guest accesses. Scratch selection
excludes every operand/destination register in the group; individual operations
still execute in order. All original PC entries remain available, including
entries into a suffix of a longer group.

These operations cannot observe the emulation counter or fail halfway through
under the backend's admitted internal-memory contract, so adding the group
length once preserves the original unsigned wraparound result. A marker NOP
represents a no-effect operation when needed for distinct source accounting;
these operations remain adaptation work. The profiler adds each original source
visit and attributes no native payload to grouped emulation. Code/data in the
annotated ELF are identical to the delivered ELF.

There are **512 static group entries over 1,009 distinct source operations**.
The workload executes **6,237 groups / 12,523 system operations**, eliminating
6,286 repetitions of seven setup/counter/cleanup/branch instructions:
**44,002 instructions**. Copied system operations also use the existing checked
page-relative header backend, eliminating **8,163** address ADDs. The 49 system
gateway entries each save one native-capture instruction, completing the
**52,214-instruction** reduction in the system category. The linked group audit
checks captured words, scratch exclusions, counter increments, field accesses,
spills, distinct ordered source labels and continuations for every group.

**Observation** loads its two-word internal pending record with LDP and clears
the pending pointer with a page-relative STR. Guest source-address bounds,
alignment checks, event fields and fallback are retained. This removes two
instructions per **2,135** recorded results, saving **4,270** instructions. The
paired load is also tested with the pending record beginning at page offset
4088, across a page boundary.

**Native gateway capture** combines its 32-byte stack decrement and X0/X1 spill
into a pre-indexed STP. Frame contents, original-SP recording, private-handler
stack switching, GPR/SIMD/FP capture and diagnostic behavior remain unchanged.
The compiled macro shrinks from 72 to **68 bytes**. All **2,381** gateway entries
save one instruction: 2,136 syscall, 195 memory, 49 system and one final boundary.
These gateway savings are distributed among their existing adapter categories.

All ten focused CTest modules pass. Extended indirect and dispatch fixtures
exercise both frame conventions, all target/source aliases, hits/misses, holes,
zero targets, links, bounds, flags and SP restoration. The new system-group
fixture passes **48,000 full-context comparisons** against sequential execution
by the shared emulator, covering 375 groups, all GPR operands, dependent shadow
updates, counter wraparound, all NZCV values, SIMD/FP state and both header page
placements. Profiler tests preserve each grouped source visit. The complete
PC-index/frame audit and all twelve malformed-image admission/context/fault
checks pass. All **70,125** shortened conditionals and **6,619** specialized
return branches pass their linked audits; dynamic direct returns remain 20,406.

A separate histogram audit compares every original source PC's execution
frequency, combining copied, grouped and original entries. All **29,917 executed
source PCs / 3,182,392 visits** match exactly, including 3,041,214 kernel visits.
Native kernel/application counts remain **2,838,026 / 131,951**. This frequency
audit is post-execution evidence; it does not supply execution paths or results.

Eighteen construction inputs/proofs are byte-identical, including initial RAM,
state, mappings, hardware metadata, prior memory/dispatch/call proofs and the
user-exclusion lookup. The manifest adds only the 32-byte kernel indirect-frame
description. The entire result and gateway, memory and system profiles match:
**2,272 events**, nine counter inputs, 92 UART bytes, 185 faults, five memory
post-operations and 2,381 gateways. Hardware exceptions, runtime EL1 services
and host calls before completion remain zero.

Whole-ELF execution falls to **7,665,261 instructions**, retaining 141,950
startup/final-validation instructions. The delivered
[ELF](../build/el0-multi-slice-20261116a/checkpoint) is **156,660,856 bytes**,
**2,053,896 bytes smaller**, SHA-256
`ae8dd6f3bc11c57e942298f3450a665ea83212cf44b7596e23d00a2ae386022f`.
The **0.20:1 ceiling** and **0.10:1 target** remain unmet. QEMU 9.2.3 TCG
Cortex-A53, one vCPU, `PROFILE=1 LTO=1`; cycle/cache effects remain unmeasured.
This pass completed on November 17; artifact names retain the November 16 export
date.

- [Counts](../build/el0-multi-slice-profile-20261116a/counts.json)
- [Measured validation](../build/el0-multi-slice-measurement-20261116a/validation.json)
- [Comparison, six slices and input identity](../build/el0-multi-slice-profile-20261116a/comparison.json)
- [All original-PC frequencies](../build/el0-multi-slice-profile-20261116a/source-visits.json)
- [Direct-frame and frequency audit](../build/el0-multi-slice-profile-20261116a/indirect-frames.json)
- [System group construction](../build/el0-multi-slice-20261116a/system-groups.json)
- [Linked system-group audit](../build/el0-multi-slice-20261116a/system-groups-compiled.json)
- [Linked conditional audit](../build/el0-multi-slice-20261116a/control-compiled.json)
- [Linked memory audit](../build/el0-multi-slice-20261116a/memory-compiled.json)
- [Linked return audit](../build/el0-multi-slice-profile-20261116a/direct-returns.json)
- [Loaded code/data identity](../build/el0-multi-slice-profile-20261116a/profile-plan.json)
- [Hotspots](../build/el0-multi-slice-profile-20261116a/hotspots.json)
- [Budget](../build/el0-multi-slice-profile-20261116a/budget.json)
- [Focused checks](../build/el0-multi-slice-checks-20261116a.log)
- [Full PC-index/frame audit](../build/el0-multi-slice-index-audit-20261116a.log)
- [Negative checks](../build/el0-multi-slice-negatives-20261116a.log)

Build a fresh [pretranslated export](el0-pretranslated-memory.md#build-and-verify)
with `PROFILE=1 LTO=1 PRETRANSLATE=1`. Matching runtime objects and model are
`build/el0-multi-slice-objects-20261116a` and
`build/el0-multi-slice-model-20261116a`. Focused fixture and linked group audit:

```sh
python3 -m unittest discover -s tests -p test_el0_system_groups.py -v
python3 tools/el0_system_groups.py --image build/el0-multi-slice-20261116a \
  --annotated build/el0-multi-slice-annotated-20261116a
```

## Static user-address exclusion lookup

| Execution-interval metric | Memory elision | Exclusion lookup |
| --- | ---: | ---: |
| Memory adapters | 841,399 | **706,810** |
| All runtime/adaptation instructions | 4,877,985 | **4,743,396** |
| Native kernel instructions | 2,838,026 | 2,838,026 |
| Native application instructions | 131,951 | 131,951 |
| Total instructions | 7,847,962 | **7,713,373** |
| Runtime / original kernel operations | 1.6040:1 | **1.5597:1** |

The software translation contract gives fixed kernel/device mappings precedence
over TTBR0. User-memory adapters therefore scanned a sorted exclusion list
before every live page-table walk, including ranges without RAM backing or
usable access permissions. High user-stack addresses could examine nearly all
18 ranges. Those mappings are construction-time constants in this backend.

The exporter now embeds **512 read-only entries / 8,192 bytes**. Each entry covers
a 2^39-byte address bucket and stores a base plus a tagged bounding length.
After the existing TCR and address-size guards, the full admitted address selects
one entry. Empty buckets pass in six instructions. An unsigned base subtraction
and length comparison admit addresses outside a nonempty envelope in nine.
An untagged exact interval rejects addresses inside it immediately. Tagged
envelopes, which may contain holes, retain the original range scan. Rounding an
even mixed length up by one can cause extra fallback at its end, never admission
inside a fixed mapping; odd-length intervals also conservatively use fallback.

For this image there are **507 empty**, **four exact** and **one mixed** bucket.
The lookup uses all static mappings, including UART/device and non-readable
entries. It does not inspect or cache any user PTE or translation result. The
existing walk, parent/leaf permission checks, AF checks, physical bounds,
immutable-page protection and per-access fallback remain unchanged.

A read-only mode flag binds the lookup to hardware metadata. Model admission
checks its geometry and hash, verifies read-only LOAD/section permissions, and
reconstructs the entire table and the old exclusion list from the ELF's actual
kernel-map pointer/count and map bytes. A changed table, exclusion range, map
binding or missing metadata is rejected before execution. Older images and
exports without pretranslation keep their original path.

The histogram independently counts entries to all **1,053** generated scan
loops using the linked input-section base and the fixed-width assembly layout.
The preceding image executed **21,552 range-scan iterations across 61 sites**.
The new workload executes **zero**; the generic loops remain available for
other admitted addresses in mixed buckets. The saving is **134,589 runtime
instructions (2.76%)**, entirely in memory adapters (**16.00%** of that category).
Every other adapter category, native payload count and source-visit count is
unchanged. All **70,125** shortened conditionals and all **6,619** specialized
return branches pass their linked audits; dynamic direct returns remain 20,406.

All seven focused CTest modules pass. The native lookup fixture passes
**810,112 full-context comparisons** against an independent C linear scan,
covering every bucket, all NZCV values, scratch/address aliases, exact endpoints,
holes, odd lengths, overlapping/unsorted spans, empty/full maps, addresses above
48 bits and randomized addresses. The memory fixture now compares both paths
over **10,752 cases**, retaining live PTE changes, permissions, block mappings,
page crossings, grouped loads, writeback and SIMD checks. Its timeout increases
from 30 to 60 seconds for the doubled fixture. Construction tests cover binding,
read-only permissions, geometry and hashes. Twelve malformed full images retain
lookup/admission, GPR, PC, SP, domain and descriptor diagnostics; the complete
original-PC index audit passes.

Fifteen payload/proof inputs are byte-identical, including all initial RAM/state,
mappings and the prior memory/call specialization proofs. Hardware metadata
changes only to declare the new lookup; `state.S` adds only its ROM bytes and
mode flag. The manifest changes only to bind the hardware metadata hash.
The complete result and gateway, memory and system profiles match: **2,272
events**, nine counter inputs, 92 UART bytes, 185 faults, five memory
post-operations and 2,381 gateways. Hardware exceptions, runtime EL1 services
and host calls before completion remain zero. Loaded code/data match the
annotated image used for provenance.

Whole-ELF execution falls to **7,855,323 instructions**, retaining 141,950
startup/final-validation instructions. The delivered
[ELF](../build/el0-user-exclusion-20261116a/checkpoint) is **158,714,752 bytes**,
50,416 bytes larger, SHA-256
`14a4e979bafef314286e5b3c7593b7aa1cca021accd5c680d84b6ef85641fcd6`.
The **0.20:1 ceiling** and **0.10:1 target** remain unmet. QEMU 9.2.3 TCG
Cortex-A53, one vCPU, `PROFILE=1 LTO=1`; cycle/cache effects remain unmeasured.

- [Counts](../build/el0-user-exclusion-profile-20261116a/counts.json)
- [Measured validation](../build/el0-user-exclusion-measurement-20261116a/validation.json)
- [Comparison and input identity](../build/el0-user-exclusion-profile-20261116a/comparison.json)
- [Dynamic range-scan audit](../build/el0-user-exclusion-profile-20261116a/exclusion-scans.json)
- [Lookup bytes](../build/el0-user-exclusion-20261116a/user-exclusion-buckets.bin)
- [Linked conditional audit](../build/el0-user-exclusion-20261116a/control-compiled.json)
- [Linked memory audit](../build/el0-user-exclusion-20261116a/memory-compiled.json)
- [Linked return audit](../build/el0-user-exclusion-profile-20261116a/direct-returns.json)
- [Loaded code/data identity](../build/el0-user-exclusion-profile-20261116a/profile-plan.json)
- [Hotspots](../build/el0-user-exclusion-profile-20261116a/hotspots.json)
- [Budget](../build/el0-user-exclusion-profile-20261116a/budget.json)
- [Focused checks](../build/el0-user-exclusion-checks-final-20261116a.log)
- [Negative checks](../build/el0-user-exclusion-negatives-20261116a.log)

Build a fresh [pretranslated export](el0-pretranslated-memory.md#build-and-verify)
with `PROFILE=1 LTO=1 PRETRANSLATE=1`. Matching runtime objects and model are
`build/el0-memory-elision-objects-20261116a` and
`build/el0-user-exclusion-model-20261116a`. Focused fixture:

```sh
python3 -m unittest discover -s tests -p test_el0_user_exclusion.py -v
```

## Eliminating redundant memory checks

| Execution-interval metric | Folded arithmetic | Memory elision |
| --- | ---: | ---: |
| Memory adapters | 1,170,161 | **841,399** |
| Native-control adaptation | 347,326 | **347,314** |
| All runtime/adaptation instructions | 5,206,759 | **4,877,985** |
| Native kernel instructions | 2,838,026 | 2,838,026 |
| Native application instructions | 131,951 | 131,951 |
| Total instructions | 8,176,736 | **7,847,962** |
| Runtime / original kernel operations | 1.7121:1 | **1.6040:1** |

**Immutable literals:** construction resolves 650 PC-relative literal loads
inside admitted read ranges, proves their physical bytes belong to protected
code pages, and emits the same load against a local read-only literal pool.
Only the architectural literal displacement changes. The following branch
skips the pool and selects the original continuation; no scratch frame, bounds
scan or context gateway executes. A linked audit checks every instruction,
literal byte and continuation against the captured package. All runtime checks
at these loads are eliminated. Their remaining **2,082** attributed instructions
are continuation branches; the loads remain native payload. This saves
**143,658** instructions from the preceding 145,740-instruction category.

**Fixed kernel pages:** 2,097 single LDAR/STLR-family sites can retain admission
to one page of the immutable kernel read/write ranges. A miss executes the
existing alignment, mode, range and permission checks before recording the
page. A hit compares the full 64-bit `VA | 4095` tag, rechecks live mode and
alignment, restores X16/X17 and executes the original acquire/release word.
It does not save NZCV or rescan the ranges. The nonzero tag prevents an empty
cache from admitting page zero. All endpoints are page aligned, and aligned
single accesses cannot cross a page, so successful admission covers every
eligible offset in the same page. Read and write caches are per source site.
No user translation, page-table value or fault outcome is cached.

The ELF carries a read-only cache-mode flag bound to hardware metadata. Model
admission verifies that flag and both read-only range tables, including their
sentinels and page-aligned endpoints, against the metadata. Changed pages,
misalignment, user mode and cache misses retain the original fallback. These
sites save **130,172 instructions**, falling from 249,984 to **119,812**.

**Adjacent user loads:** 15 groups contain two consecutive loads from the same
unchanged base at contiguous offsets. One fresh live translation and permission
check admits the complete single-page range. The original loads still execute
in order, with no intervening store, branch, pointer write or context edge.
Failed group admission restores the entry state and runs the original
per-instruction paths, preserving page crossings and partial-fault behavior.
All original entry points remain available, including each group's second load.
The linked audit verifies all 30 native words and address increments. Explicit
user-access adaptation falls from 644,664 to **589,732**, saving **54,932**.

Memory adapters therefore save **328,762 instructions (28.10%)**. Smaller text
permits six additional short conditionals; native-control work falls by another
12 instructions. Every other adapter category is unchanged. The total saving
is **328,774 (6.31%)**. All **70,125** shortened conditional edges pass the
linked condition/register/bit/target audit. All 6,619 specialized return branches
still select their exact continuations, with unchanged 20,406 dynamic direct
returns and 3,041,214 original kernel operation visits.

The remaining memory attribution is:

| Source | Runtime instructions |
| --- | ---: |
| Explicit user copies with live translation | 589,732 |
| Unproven application accesses, including demand mappings | 109,191 |
| Aligned kernel admission, misses and hit guards | 119,812 |
| Other kernel adaptations, including device handling | 20,582 |
| Literal-pool continuation branches; no memory checks | 2,082 |

This does **not** eliminate all checked memory. Demand-created mappings and
the workload's 185 faults still run through the captured kernel. Removing their
guards without a stronger proof or changing the backend's fault contract would
lose required behavior. No mappings or fault outcomes are replay-selected.

All nine focused CTest modules pass. The native fixture covers **200**
acquire/release variants and **63** literal variants in **74,976 full-context
comparisons**, including all NZCV values, cache hits, page changes, permission
rejections, mode changes, register/SP aliases, XZR and SIMD literal widths.
The expanded user-memory fixture checks **5,376 cases**, including 336 grouped
cases across live PTE changes, permissions, block mappings and page crossings.
Proof and profiler tests cover captured-site metadata, unsafe grouping rejection,
literal-pool layout and native-payload attribution. Eight malformed full images
retain range/mode, GPR, PC, SP, domain and descriptor diagnostics; the complete
original-PC index audit passes.

Fourteen payload and construction-proof inputs are byte-identical. Hardware
metadata changes only to declare fixed-page caches; `state.S` adds only the
read-only mode flag. The manifest changes only to bind the new metadata hash.
The entire result and gateway, memory and system profiles match: **2,272 events**,
nine counter inputs, 92 UART bytes, 185 faults, five memory post-operations and
2,381 gateways. Hardware exceptions, runtime EL1 services and host calls before
completion remain zero. Loaded code/data match the annotated profile image.

Whole-ELF execution is **7,989,912 instructions**, retaining 141,950 startup/final
validation instructions. The delivered
[ELF](../build/el0-memory-groups-20261116b/checkpoint) is **158,664,336 bytes**,
63,744 bytes larger, SHA-256
`1acfcfb8ee51bc320e6784cbf7dcd45e3308c33d5de5a24632971833c90dfc68`.
The **0.20:1 ceiling** and **0.10:1 target** remain unmet. QEMU 9.2.3 TCG
Cortex-A53, one vCPU, `PROFILE=1 LTO=1`; cycle/cache effects remain unmeasured.

- [Counts](../build/el0-memory-groups-profile-20261116b/counts.json)
- [Measured validation](../build/el0-memory-groups-measurement-20261116b/validation.json)
- [Comparison and input identity](../build/el0-memory-groups-profile-20261116b/comparison.json)
- [Memory breakdown](../build/el0-memory-groups-profile-20261116b/memory-breakdown.json)
- [Construction proofs](../build/el0-memory-groups-20261116b/memory-elision.json)
- [Linked memory audit](../build/el0-memory-groups-20261116b/memory-compiled.json)
- [Linked conditional audit](../build/el0-memory-groups-20261116b/control-compiled.json)
- [Linked return audit](../build/el0-memory-groups-profile-20261116b/direct-returns.json)
- [Loaded code/data identity](../build/el0-memory-groups-profile-20261116b/profile-plan.json)
- [Hotspots](../build/el0-memory-groups-profile-20261116b/hotspots.json)
- [Budget](../build/el0-memory-groups-profile-20261116b/budget.json)
- [Focused checks](../build/el0-memory-elision-checks-20261116a.log)
- [Updated grouping/provenance checks](../build/el0-memory-groups-checks-20261116b.log)
- [Negative checks](../build/el0-memory-groups-negatives-20261116b.log)

Build a fresh [pretranslated export](el0-pretranslated-memory.md#build-and-verify)
with `PROFILE=1 LTO=1 PRETRANSLATE=1`. Matching runtime objects and model are
`build/el0-memory-elision-objects-20261116a` and
`build/el0-memory-groups-model-20261116b`. Focused fixture and linked audit:

```sh
python3 -m unittest discover -s tests -p test_el0_memory_elision.py -v
python3 tools/el0_memory_elision.py --image build/el0-memory-groups-20261116b \
  --annotated build/el0-memory-groups-annotated-20261116b
```

## Folded address arithmetic

| Execution-interval metric | Return-reaching copies | Folded arithmetic |
| --- | ---: | ---: |
| Checked memory adapters | 1,231,711 | **1,170,161** |
| Indirect adapters | 989,324 | **974,228** |
| Native-control adaptation | 350,034 | **347,326** |
| All runtime/adaptation instructions | 5,286,113 | **5,206,759** |
| Native kernel instructions | 2,838,026 | 2,838,026 |
| Total instructions | 8,256,090 | **8,176,736** |
| Runtime / original kernel operations | 1.7382:1 | **1.7121:1** |

Wide constants now choose the shorter MOVZ/MOVN construction and start in the
first required 16-bit lane, including shifted initial instructions. MOVK fills
only the remaining differing lanes. This applies to inline adapters and
original-PC constants. The profiler recognizes MOVN-based call links while
continuing to count their setup as adaptation work.

Memory and UART address calculations now use flag-free ADD/SUB immediates,
including the shifted-immediate form, and fold register extension/shift into
ADD when encodable. A zero-register index needs no addition. Larger offsets
retain the wide-constant fallback. Post-index writeback uses the same helpers;
modular 64-bit arithmetic, source/destination aliases and NZCV are preserved.

Every user-translation page-table and data backing check remains live. For a
physical RAM base **B = 2^k** and RAM length **L <= B**, the generated check
replaces constant construction plus subtraction with **PA XOR B**. Within the
admitted range this equals **PA - B**. If PA's B bit is clear, XOR sets it,
making the candidate offset at least B and larger than L minus the access
size. If that bit is set, higher bits are unchanged; only offsets within the
same original range pass the unsigned bound. Other RAM geometries retain
subtraction. Each bound is checked before its associated dereference; page-table
loads, permissions, access flags and immutable-page checks remain unchanged.

The measured saving is **79,354 instructions (1.50%)**: **61,550** in checked
memory, **15,096** in indirect adapters and **2,708** in native control. Every
other adapter category is unchanged. Original kernel visits remain 3,041,214,
native application instructions remain 131,951, and all **20,406** dynamic
specialized returns remain. The linked return audit checks all 6,619 copied
return branches and their exact continuations. Reduced assembly size allows
one more conditional to use its short form; all **70,119** shortened branches
pass the linked condition/register/bit/target audit.

An executable fixture checks **972 probes / 155,520 full-context comparisons**
against independent C arithmetic: all 16 NZCV values, every constant destination
including XZR, positive/negative offsets, wraparound, register aliases, extended
indices and shift boundaries. Bounds cases include exact access endpoints,
high addresses and seven RAM geometries, with subtraction fallbacks exercised.
The existing memory and UART tests retain live translation, permission, failure,
writeback and state-preservation coverage. All **11 focused CTest modules** pass;
five corrupted full images retain their GPR, PC, kernel-SP, domain and descriptor
diagnostics, and the complete original-PC index audit passes.

Fifteen construction inputs and proofs, including all payload/state data,
manifest, mapping metadata and call-specialization proof, are byte-identical.
The entire result and gateway, memory and system profiles match the preceding
image: **2,272 events**, nine counter inputs, 92 UART bytes, 185 recorded faults,
five memory post-operations and 2,381 gateways. Hardware exceptions, runtime
EL1 services and host calls before completion remain zero. The annotated image
has identical loaded code/data to the measured delivery image.

Whole-ELF execution falls to **8,318,686 instructions**, retaining 141,950
startup/final-validation instructions. The delivered
[ELF](../build/el0-address-fold-20261116a/checkpoint) is **158,600,592 bytes**,
76,280 bytes smaller, SHA-256
`3e27952d3ed6e97510fb2747cda108e60aca22f23a589711f284140ffc4e39b5`.
The **0.20:1 ceiling** and **0.10:1 target** remain unmet. QEMU 9.2.3 TCG
Cortex-A53, one vCPU, `PROFILE=1 LTO=1`; cycle/cache effects remain unmeasured.

- [Counts](../build/el0-address-fold-profile-20261116a/counts.json)
- [Measured validation](../build/el0-address-fold-measurement-20261116a/validation.json)
- [Comparison](../build/el0-address-fold-profile-20261116a/comparison.json)
- [Input/proof identity](../build/el0-address-fold-20261116a/address-fold-audit.json)
- [Linked conditional audit](../build/el0-address-fold-20261116a/control-compiled.json)
- [Linked return audit](../build/el0-address-fold-profile-20261116a/direct-returns.json)
- [Loaded code/data identity](../build/el0-address-fold-profile-20261116a/profile-plan.json)
- [Hotspots](../build/el0-address-fold-profile-20261116a/hotspots.json)
- [Budget](../build/el0-address-fold-profile-20261116a/budget.json)
- [Existing focused checks](../build/el0-address-fold-tests-20261116a.log)
- [Arithmetic/provenance checks](../build/el0-address-fold-new-tests-20261116a.log)
- [Negative checks](../build/el0-address-fold-negatives-20261116a.log)

Build a fresh [pretranslated export](el0-pretranslated-memory.md#build-and-verify)
with `PROFILE=1 LTO=1 PRETRANSLATE=1`. Matching runtime objects and model are
`build/el0-address-fold-objects-20261116a` and
`build/el0-address-fold-model-20261116a`. Focused fixture:

```sh
python3 -m unittest discover -s tests -p test_el0_arithmetic.py -v
```

## Return-reaching partial copies

| Execution-interval metric | Compact control | Pruned 64-word bodies | Pruned 128-word bodies |
| --- | ---: | ---: | ---: |
| Copied source instructions, static | 99,997 | 73,094 | **97,243** |
| Specialized root call sites, static | 3,348 | 3,425 | **3,440** |
| All runtime/adaptation instructions | 5,309,843 | 5,304,830 | **5,286,113** |
| Native kernel instructions | 2,836,998 | 2,837,274 | **2,838,026** |
| Total instructions | 8,278,792 | 8,274,055 | **8,256,090** |
| Runtime / original kernel operations | 1.7460:1 | 1.7443:1 | **1.7382:1** |

The partial-call analysis now computes reverse reachability from its copied
RET X30 instructions. Nodes that cannot reach any such return are omitted;
execution rejoins original code before their first instruction. Loops with a
copied-return edge remain, while components with no copied return are removed.
All original conditional outcomes remain possible. No execution counts,
recorded targets or branch outcomes select a copy or an execution path.

The production search examines at most **512 instructions** in each function
and retains at most **128** per partial copy. If the expanded useful graph is
too large, it falls back to a scan bounded by that retained-body limit. The
**100,000-instruction total copy budget is unchanged**. Existing closed copies
keep priority; remaining partial bodies are ranked by size, then source PC.
Calls, LR writes/restores, context gateways and atomic groups remain proof
boundaries. Partial proofs still cannot summarize a callee for a parent.

The final export retains every preceding root copy and adds **92**, with
**1,930 partial root copies** and the unchanged 178 nested copies. Its 97,243
copied source instructions are 2,754 fewer than the baseline. An independent
audit verifies all 468 selected partial-function graphs: every retained node
can reach a copied return, every original-code exit agrees with the graph,
and every earlier return site in retained functions remains. Closed calls and
their proofs are identical. Thirteen state, payload, mapping, dispatch and
immutable-bitmap inputs are byte-identical.

The 64-word variant saves **5,013 runtime instructions (0.09%)**. The delivered
128-word variant saves **23,730 (0.45%)** against compact control. Histogram
savings are **19,983 indirect-adapter instructions**, **3,084 resume-thunk
instructions** and **663 native-control instructions**; every other category
is unchanged. Direct returns increase from **19,378 to 20,406**. A linked audit
checks all **6,619** specialized return branches and their exact continuations;
the histogram confirms **1,028 additional direct returns**. These account for
the higher native-kernel payload count. Original kernel visits remain 3,041,214.

Whole-ELF instructions fall to **8,398,040**, retaining 141,950 startup/final
validation instructions. Native application instructions remain 131,951.
The **0.20:1 ceiling** and **0.10:1 target** remain unmet. QEMU 9.2.3 TCG
Cortex-A53, one vCPU, `PROFILE=1 LTO=1`; cycle/cache effects remain unmeasured.

All **24 call-analysis and execution tests** pass, including return-reaching
loops, discarded components, search/copy limits, deterministic allocation and
independent total-budget enforcement. Executable tests cover **240 partial-copy
combinations** across fast returns, slow calls, tail exits, budget exits,
shared stack frames and bodies longer than 64 instructions, plus the nested
frame/alias fixture. All three focused CTest checks pass. Five corrupted full
images retain the GPR, PC, kernel-SP, domain and descriptor diagnostics; the
complete original-PC index audit passes. The linked control audit verifies all
70,118 shortened conditional branches.

The entire result and gateway, memory and system profiles match the preceding
image: **2,272 events**, nine counter inputs, 92 UART bytes, 185 recorded faults,
five memory post-operations and 2,381 gateways. Hardware exceptions, runtime
EL1 services and host calls before completion remain zero. RAM and tables remain
embedded in the ELF.

Delivered [ELF](../build/el0-return-wide-20261116a/checkpoint), SHA-256
`bd19d3670526231257a6dc2e3bfad6beb4c3583965f979a6339c5c0a7388a7d2`.
It is 158,676,872 bytes, **24,208 bytes smaller** than compact control.

- [Counts](../build/el0-return-wide-profile-20261116a/counts.json)
- [Full measured validation](../build/el0-return-wide-measurement-20261116a/validation.json)
- [Comparison and input identity](../build/el0-return-wide-profile-20261116a/comparison.json)
- [Copy proof audit](../build/el0-return-wide-20261116a/call-proof-audit.json)
- [Direct-return counts and linked continuations](../build/el0-return-wide-profile-20261116a/direct-returns.json)
- [Construction proofs](../build/el0-return-wide-20261116a/call-specialization.json)
- [Linked conditional audit](../build/el0-return-wide-20261116a/control-compiled.json)
- [Loaded code/data identity](../build/el0-return-wide-profile-20261116a/profile-plan.json)
- [Hotspots](../build/el0-return-wide-profile-20261116a/hotspots.json)
- [Budget](../build/el0-return-wide-profile-20261116a/budget.json)
- [Negative checks](../build/el0-return-wide-negatives-20261116a.log)

Build a fresh [pretranslated export](el0-pretranslated-memory.md#build-and-verify)
with `PROFILE=1 LTO=1 PRETRANSLATE=1`. Matching runtime objects and model are
`build/el0-return-wide-objects-20261116a` and
`build/el0-return-wide-model-20261116a`. Focused fixture:

```sh
python3 -m unittest discover -s tests -p test_el0_call_analysis.py -v
```

## Compact control lowering

| Execution-interval metric | Paired spill writeback | Compact control |
| --- | ---: | ---: |
| Native-control adaptation | 604,638 | **350,697** |
| Observation adapters | 81,130 | **78,995** |
| All runtime/adaptation instructions | 5,565,919 | **5,309,843** |
| Total instructions | 8,534,868 | **8,278,792** |
| Runtime / original kernel operations | 1.8302:1 | **1.7460:1** |

Original-PC constants now start with MOVZ and omit zero-valued MOVK lanes.
Every resulting 64-bit value is unchanged, including the original continuation
written to X30 before a transformed BL. Across 56,718 static constant sequences,
this removes **31,775 instructions**. No recorded targets or branch outcomes
select a constant or conditional edge.

The pretranslated exporter also computes the fixed-width layout of its main
assembly section. Gateway sizes come from the actual macro definitions; tests
compare those sizes with assembled expansions. Unknown layout directives,
conditional macro code and nested macro expansion are rejected. Only word
alignment is admitted in the main section.

The range pass recognizes the existing inverse-condition/long-B lowering and
shortens an edge only when its original target is in the same section and its
distance already fits the signed architectural range. Removing instructions
can only shrink these distances. A second layout pass verifies that bound.
Of **70,295** candidate conditional edges, **69,824** become one native branch;
**471** retain their long form. All source labels and original-PC index entries
remain available, including private call-copy continuations and coverage stops.

An independent linked-code audit verifies **every shortened instruction** against
compiler-emitted source/target offsets and the original condition, register,
test bit and displacement. The main section contains the predicted 7,938,216
bytes. A semantic normalization audit matches the entire preceding assembly
after accounting for wide-immediate values and conditional forms. The manifest,
state, mappings, call and dispatch proofs and fourteen construction inputs are
byte-identical.

The executable fixture passes **39,840 cases**, covering conditions, both
register widths, zero-register operands, test-bit boundaries, all NZCV values,
one- through four-instruction constants, every writable destination GPR and
complete context preservation. Planner tests cover both signed range endpoints,
out-of-range and unresolved edges, repeated relaxation and unsupported growth.
Profiler tests retain original-operation provenance for compact branches and
links while excluding adapter guards from native payload. All four focused
CTest checks pass. Five corrupted full images retain the GPR, PC, kernel-SP,
domain and descriptor diagnostics; the complete original-PC index audit passes.

The histogram attributes **253,941 saved instructions** to native-control
adaptation, a **42.00%** reduction in that category, and another **2,135** to the
observation hook's compact link constant. Every other adapter category is
unchanged. The combined saving is **256,076 instructions (4.60%)**.
Whole-ELF instructions fall to **8,420,742**, retaining 141,950 startup/final
validation instructions. Native kernel/application counts remain
2,836,998/131,951, with 3,041,214 original kernel visits. The **0.20:1 ceiling**
and **0.10:1 target** remain unmet. QEMU 9.2.3 TCG Cortex-A53, one vCPU,
`PROFILE=1 LTO=1`; cycle/cache effects remain unmeasured.

The entire result and gateway, memory and system profiles match the preceding
image: **2,272 events**, nine counter inputs, 92 UART bytes, 185 recorded faults,
five memory post-operations and 2,381 gateways. Hardware exceptions, runtime
EL1 services and host calls before completion remain zero. RAM and tables remain
embedded in the ELF.

Delivered [ELF](../build/el0-compact-control-20261115a/checkpoint), SHA-256
`b727d267ff52780a7f7d1fb88413968f6329cc8ca34a1db4afcebc50d19247ac`.
It is 158,701,080 bytes, **406,392 bytes smaller** than the preceding image.

- [Counts](../build/el0-compact-control-profile-20261115a/counts.json)
- [Full measured validation](../build/el0-compact-control-measurement-20261115a/validation.json)
- [Comparison and input identity](../build/el0-compact-control-profile-20261115a/comparison.json)
- [Static range proofs](../build/el0-compact-control-20261115a/control-lowering.json)
- [Linked instruction audit](../build/el0-compact-control-20261115a/control-compiled.json)
- [Semantic assembly comparison](../build/el0-compact-control-20261115a/control-comparison.json)
- [Loaded code/data identity](../build/el0-compact-control-profile-20261115a/profile-plan.json)
- [Hotspots](../build/el0-compact-control-profile-20261115a/hotspots.json)
- [Budget](../build/el0-compact-control-profile-20261115a/budget.json)
- [Negative checks](../build/el0-compact-control-negatives-20261115a.log)

Build a fresh [pretranslated export](el0-pretranslated-memory.md#build-and-verify)
with `PROFILE=1 LTO=1 PRETRANSLATE=1`. Matching runtime objects and model are
`build/el0-compact-control-objects-20261115a` and
`build/el0-compact-control-model-20261115a`. Checks and the linked audit:

```sh
PYTHONPATH=tests python3 -m unittest test_el0_control test_el0_instruction_profile -v
python3 tools/el0_control.py --image build/el0-compact-control-20261115a \
  --annotated build/el0-compact-control-annotated-20261115a
```

## Paired spill writeback

| Execution-interval metric | Page-relative caches | Paired spill writeback |
| --- | ---: | ---: |
| System adapters | 1,683,544 | **1,495,346** |
| Memory adapters | 1,258,749 | **1,231,711** |
| Observation adapters | 85,400 | **81,130** |
| All runtime/adaptation instructions | 5,785,425 | **5,565,919** |
| Total instructions | 8,754,374 | **8,534,868** |
| Runtime / original kernel operations | 1.9023:1 | **1.8302:1** |

Inline helpers now reserve their scratch frame with a pre-indexed paired store
and release it with a post-indexed paired load. Each replaces two instructions
with one while retaining the same frame size, saved-register slots, memory
addresses and NZCV. The change covers primary and generic shadow operations,
counter inputs, checked memory, exclusive-window guards, memory completion,
UART buffering, observation, logical stack operations and lowered branches.
Generated user returns also use the combined entry spill. Context gateways,
indirect resume frames and all admission checks retain their existing layouts.

A streaming normalization audit verifies that the new generated assembly is
exactly the preceding assembly after **16,428 entry-spill** and **27,878
restore** substitutions. It permits only adjacent SP arithmetic and paired
loads/stores with the same offsets and effects. All other assembly, the manifest
and fourteen construction inputs are byte-identical, including the call proofs,
dispatch records, mappings and immutable bitmap.

The histogram attributes all **219,506 saved instructions (3.79%)** to system
adapters (**188,198**), memory (**27,038**) and observation (**4,270**). Every
other category is unchanged. Whole-ELF instructions fall to **8,676,818**, with
unchanged startup/final validation cost of 141,950. Native kernel/application
counts remain 2,836,998/131,951, with 3,041,214 original kernel visits. The
**0.20:1 ceiling** and **0.10:1 target** remain unmet. QEMU 9.2.3 TCG Cortex-A53,
one vCPU, `PROFILE=1 LTO=1`; cycle/cache effects remain unmeasured.

All ten affected CTest checks pass. The expanded primary-shadow fixture passes
**249,856 cases** against the shared emulator, covering all 32 register
encodings, both address backends, all NZCV values, counter wrap, logical modes,
and headers at both ends of a page. The other executable fixtures cover checked
memory and faults, exclusive exits, logical/native SP, writeback, UART,
observation, counters, generic registers, call copies and generated returns.
Five corrupted full images retain the GPR, PC, kernel-SP, domain and descriptor
diagnostics; the complete original-PC index audit passes.

The entire result and gateway, memory and system profiles match the preceding
image: **2,272 events**, nine counter inputs, 92 UART bytes, 185 recorded faults,
five memory post-operations and 2,381 gateways. Hardware exceptions, runtime
EL1 services and host calls before completion remain zero. RAM and tables remain
embedded in the ELF.

Delivered [ELF](../build/el0-paired-spill-20261115a/checkpoint), SHA-256
`01f5b2583641203110e029c1164307b5a38ecb8a484b1afe8c79b94ff95fef9f`.
It is 159,107,472 bytes, **177,280 bytes smaller** than the preceding image.

- [Counts](../build/el0-paired-spill-profile-20261115a/counts.json)
- [Full measured validation](../build/el0-paired-spill-measurement-20261115a/validation.json)
- [Comparison and input identity](../build/el0-paired-spill-profile-20261115a/comparison.json)
- [Exact assembly substitution audit](../build/el0-paired-spill-20261115a/assembly-comparison.json)
- [Loaded code/data identity](../build/el0-paired-spill-profile-20261115a/profile-plan.json)
- [Hotspots](../build/el0-paired-spill-profile-20261115a/hotspots.json)
- [Budget](../build/el0-paired-spill-profile-20261115a/budget.json)
- [Negative checks](../build/el0-paired-spill-negatives-20261115a.log)

Build a fresh [pretranslated export](el0-pretranslated-memory.md#build-and-verify)
with `PROFILE=1 LTO=1 PRETRANSLATE=1`. Matching runtime objects and model are
`build/el0-paired-spill-objects-20261115a` and
`build/el0-paired-spill-model-20261115a`. Primary-shadow fixture:

```sh
python3 -m unittest discover -s tests -p test_el0_system_header.py -v
```

## Page-relative indirect caches

| Execution-interval metric | Descriptor checks | Page-relative caches |
| --- | ---: | ---: |
| Indirect adapters | 1,260,581 | **1,009,307** |
| All runtime/adaptation instructions | 6,036,699 | **5,785,425** |
| Total instructions | 9,005,648 | **8,754,374** |
| Runtime / original kernel operations | 1.9850:1 | **1.9023:1** |

Each indirect cache already has two 64-bit words aligned to 16 bytes. The new
probe retains the page base after loading the original-PC key, compares the
complete live target without a scratch copy, and loads the native target through
a low-12-bit relocation on that same page. This removes three instructions from
ordinary cache hits. When X16 or X17 holds the target, the comparison instead
uses its original stack spill and rebuilds the page base after a hit, saving
one instruction. The nonzero native-target guard remains in place, including
when a zero key matches an empty cache. NZCV is untouched.

Indexed cache fills now store the native address and original target directly
through the page base. Ordinary targets remain in their original register;
X16/X17 targets are recovered from the entry spill and the native address is
reloaded from its just-written cache word. This eliminates the temporary key
and native-address spills. Cache publication still writes the native address
before the key. The binary-search backend shares the new hit probe and retains
its existing fill. All caches continue to be filled only from their admitted
original-PC tables; live target changes take the existing resolver.

The histogram attributes the entire **251,274-instruction saving (4.16%)** to
indirect adapters, a **19.93%** reduction in that category. Every other adapter
category is unchanged. Whole-ELF instructions fall to **8,896,324**, retaining
141,950 startup/final-validation instructions. Native kernel/application counts
remain 2,836,998/131,951, with 3,041,214 original kernel visits. The **0.20:1
ceiling** and **0.10:1 target** remain unmet. QEMU 9.2.3 TCG Cortex-A53, one
vCPU, `PROFILE=1 LTO=1`; cycle/cache effects remain unmeasured.

The executable fixture passes **313,344 cases** across both lookup backends,
all 32 target-register encodings, BR/BLR/RET, every NZCV value, warm hits, changing
and invalid targets, and matching keys with empty native words. Every cache is
placed at either offset 0 or 4080 of a page; linked symbols verify both extremes.
The fixture checks every GPR, SP and NZCV, link updates and cache side effects.
All four focused CTest checks pass. Five corrupted full images retain the GPR,
PC, kernel-SP, domain and descriptor diagnostics; the complete original-PC index
audit passes.

A streaming assembly comparison finds changes only in the **7,157 indirect
adapter blocks**. The manifest, state, mappings, call and dispatch proofs,
immutable bitmap, generated C and embedded inputs are byte-identical to the
preceding export. The entire result and gateway, memory and system profiles
match: **2,272 events**, nine counter inputs, 92 UART bytes, 185 recorded faults,
five memory post-operations and 2,381 gateways. Hardware exceptions, runtime
EL1 services and host calls before completion remain zero. RAM and tables stay
embedded in the ELF.

Delivered [ELF](../build/el0-indirect-page-20261115a/checkpoint), SHA-256
`42011f8a97cac7226bce979ee6a983e793f472b17da7790709388792da9592d8`.
It is 159,284,752 bytes, **229,000 bytes smaller** than the preceding image.

- [Counts](../build/el0-indirect-page-profile-20261115a/counts.json)
- [Full measured validation](../build/el0-indirect-page-measurement-20261115a/validation.json)
- [Comparison and input identity](../build/el0-indirect-page-profile-20261115a/comparison.json)
- [Assembly comparison](../build/el0-indirect-page-20261115a/assembly-comparison.json)
- [Loaded code/data identity](../build/el0-indirect-page-profile-20261115a/profile-plan.json)
- [Hotspots](../build/el0-indirect-page-profile-20261115a/hotspots.json)
- [Budget](../build/el0-indirect-page-profile-20261115a/budget.json)
- [Negative checks](../build/el0-indirect-page-negatives-20261115a.log)

Build a fresh [pretranslated export](el0-pretranslated-memory.md#build-and-verify)
with `PROFILE=1 LTO=1 PRETRANSLATE=1`. Matching runtime objects and model are
`build/el0-indirect-page-objects-20261115a` and
`build/el0-indirect-page-model-20261115a`. Focused fixture:

```sh
python3 -m unittest discover -s tests -p test_el0_indirect_cache.py -v
```

## Descriptor checks and guarded table dispatch

| Execution-interval metric | Partial leaf returns | Guarded dispatch only | Descriptor specialization |
| --- | ---: | ---: | ---: |
| System adapters | 1,781,197 | 1,781,197 | **1,683,544** |
| Indirect adapters | 1,303,349 | **1,260,581** | **1,260,581** |
| All runtime/adaptation instructions | 6,177,120 | 6,134,352 | **6,036,699** |
| Total instructions | 9,146,069 | 9,103,301 | **9,005,648** |
| Runtime / original kernel operations | 2.0311:1 | 2.0171:1 | **1.9850:1** |

The export supplies the descriptor count to the generated user-return path.
Counts from zero through 32 receive straight-line checks, guarded by equality
with the live count. A different count uses the generic loop; larger tables
also keep that loop. Every descriptor still loads its live pointer, mask and
expected value and checks the live descriptor in the original order. There
is no cached validity result or recorded branch selection. All rejection paths
restore the original context before the existing ERET gateway.

The generic loop now post-increments each record pointer and tests the count
at the back edge. On the admitted eleven-record path, unrolling removes
**43 instructions per successful return**, or **97,653** across 2,271 returns.
This is a **1.59%** reduction relative to the guarded-dispatch-only baseline.
The executable return fixture covers **473,088** complete context cases across
seven count hints. Another **255,493** descriptor-only executions cover all
live counts 0–33, every bit under varying masks, early rejection and invalid
pointers immediately beyond the live table.

The existing guarded-dispatch emitter recognizes one site at
`0x800080028358`, loading `sys_call_table` through a masked index hint. It uses
463 immutable pointer/native-target records. Each fast branch checks the full
live pointer against its record; out-of-range hints, changed pointers and
unadmitted targets retain the checked original-PC resolver. This saves another
**42,768 instructions**. An executable fixture passes **64,000** combinations
of BR/BLR, index and target register aliases, NZCV, pointer changes, empty native
entries, bounds and high index bits. Model preparation validates the immutable
records against the admitted domain's PC table after the existing header and
bitmap checks, preserving their diagnostic order.

The intermediate measurement restores only the preceding descriptor loop in
the new export. Removing its dispatch prefix and records leaves assembly
byte-identical to the partial-return image. Payloads, initial state, mapping
metadata, call proofs and immutable bitmap are unchanged. The entire result
and gateway, memory and system profiles match: **2,272 events**, nine counter
inputs, 92 UART bytes, 185 recorded faults and five memory post-operations.
There are **2,381 gateways**, including the unchanged 2,136 syscalls and 49
residual ERETs. Hardware exceptions, runtime EL1 services and host calls before
completion remain zero. Five corrupted full images retain the GPR, PC,
kernel-SP, domain and descriptor diagnostics; the full PC-index audit passes.

Whole-ELF instructions fall to **9,147,598**, with unchanged startup/final
validation cost of 141,950. Native kernel/application counts remain
2,836,998/131,951, with 3,041,214 original kernel visits. The **0.20:1 ceiling**
and **0.10:1 target** remain unmet. QEMU 9.2.3 TCG Cortex-A53, one vCPU,
`PROFILE=1 LTO=1`; cycle/cache effects remain unmeasured.

Delivered [ELF](../build/el0-return-descriptors-20261115a/checkpoint), SHA-256
`d32de5c54dae4c2068f581c2b1ce825fe87bd4bc51785956b679053b8167e837`.
It is 159,513,752 bytes, **8,200 bytes larger** than the partial-return image.

- [Counts](../build/el0-return-descriptors-profile-20261115a/counts.json)
- [Full measured validation](../build/el0-return-descriptors-measurement-20261115a/validation.json)
- [Separate savings and input identity](../build/el0-return-descriptors-profile-20261115a/comparison.json)
- [Loaded code/data identity](../build/el0-return-descriptors-profile-20261115a/profile-plan.json)
- [Hotspots](../build/el0-return-descriptors-profile-20261115a/hotspots.json)
- [Budget](../build/el0-return-descriptors-profile-20261115a/budget.json)
- [Guarded-dispatch-only counts](../build/el0-dispatch-baseline-profile-20261115a/counts.json)

Build a fresh [pretranslated export](el0-pretranslated-memory.md#build-and-verify)
with `PROFILE=1 LTO=1 PRETRANSLATE=1`. Matching runtime objects and prepared model
are `build/el0-return-descriptors-objects-20261115a` and
`build/el0-return-descriptors-model-20261115a`. Focused checks:

```sh
PYTHONPATH=tests python3 -m unittest test_el0_return test_el0_dispatch -v
```

## Partial leaf returns

| Execution-interval metric | Shadow-header image | Partial leaf returns |
| --- | ---: | ---: |
| Directly branched returns | 13,240 | **19,378** |
| Syscall / all gateways | 2,136 / 2,381 | **2,136 / 2,381** |
| Indirect adapters | 1,409,909 | **1,303,349** |
| Resume thunks | 252,240 | **233,826** |
| Native-control adaptation | 600,789 | 604,638 |
| All runtime functions | 871,495 | 871,495 |
| All runtime/adaptation instructions | 6,298,245 | **6,177,120** |
| Native kernel instructions | 2,830,860 | 2,836,998 |
| Total instructions | 9,261,056 | **9,146,069** |
| Runtime / original kernel operations | 2.0710:1 | **2.0311:1** |

The raw histograms confirm **6,138 more direct returns**. Indirect adapter
instructions decrease by **106,560 (7.56%)**, and their three-instruction resume
thunks lose another **18,414**. Rejoining original code and entering copies adds
3,849 native-control adaptation instructions. All other adapter categories are
unchanged, yielding a net **121,125 runtime instruction reduction (1.92%)**.
The direct return branches themselves contribute 6,138 more native kernel
instructions; original kernel visits remain **3,041,214**. Total instructions
fall by **114,987**, including a whole-ELF count of **9,288,019** and unchanged
startup/final-validation cost of 141,950. The **0.20:1 ceiling** and **0.10:1
target** remain unmet. QEMU 9.2.3 TCG Cortex-A53, one vCPU,
`PROFILE=1 LTO=1`; cycle/cache effects remain unmeasured.

The full result and gateway, memory and system profiles match the preceding
image exactly: **2,272 events**, nine counter inputs, 92 UART bytes, 185 recorded
faults, five memory post-operations and 49 residual ERET gateways. Hardware
exceptions, runtime EL1 services and host calls before completion remain zero.
RAM and page tables remain embedded in the ELF.

Delivered [ELF](../build/el0-partial-return-20261115a/checkpoint), SHA-256
`b326df287b465ab891f619993b27f27287a9e9230cee37b0d196877b98d1eccc`.
It is 159,505,552 bytes, **346,240 bytes larger** than the shadow-header image.

- [Counts](../build/el0-partial-return-profile-20261115a/counts.json)
- [Measured workload validation](../build/el0-partial-return-measurement-20261115a/validation.json)
- [Direct-return histogram audit](../build/el0-partial-return-profile-20261115a/direct-returns.json)
- [Construction proofs and original-code exits](../build/el0-partial-return-20261115a/call-specialization.json)
- [Loaded code/data identity](../build/el0-partial-return-profile-20261115a/profile-plan.json)
- [Hotspots](../build/el0-partial-return-profile-20261115a/hotspots.json)
- [Budget assessment](../build/el0-partial-return-profile-20261115a/budget.json)

The call analysis now copies proven leaf prefixes of larger functions. Every
copied instruction preserves the incoming X30; copied `RET X30` instructions
branch directly to the original caller's continuation. Only a direct BL enters
each private copy, and original function entries and context targets remain
available. No recorded targets or branch outcomes select an execution path.

An unproven path branches back to the original instruction before executing it.
This includes calls, X30 writes/restores, context gateways, exclusive groups and
instructions outside the 64-instruction prefix budget. Conditional edges and
budget-limited fallthroughs explicitly rejoin original code when their targets
are outside the copy. Partial proofs cannot summarize callees for a parent;
the existing closed-frame and nested-call rules remain separate.

The observation hook's original BL can also enter a proven callee copy. All
observation checks remain ahead of that call. This removes a return adapter
without bypassing the observation hook or its ordering.

The export retains every preceding copy and continuation, and adds **1,838
partial call copies across 444 functions**, plus the observation-hook call.
There are now **3,348 root copies and 178 nested copies**, totaling **99,997
source instructions** within the existing 100,000-instruction copy budget.
The version-3 proof records which functions are partial and every original-code
exit. Payloads, initial state, mapping metadata, embedded state source and
immutable-page bitmap are byte-identical to the shadow-header image.

Nineteen analysis/execution tests pass. The new executable fixture exercises
**144 combinations** of NZCV and input values through fast returns, a slow call
after a copied stack save, an external tail edge and a fallthrough cut by the
copy budget. It checks results, X30, SP and X29. The complete original-PC index
audit preserves all 467,872 context targets; five corrupted full images retain
their GPR, PC, kernel-SP, domain and descriptor diagnostics.

```sh
python3 -m unittest discover -s tests -p test_el0_call_analysis.py -v
```

Fresh export and object directories are required. Build with
`PROFILE=1 LTO=1 PRETRANSLATE=1` using the
[pretranslated-memory commands](el0-pretranslated-memory.md#build-and-verify).
Matching object/model directories are
`build/el0-partial-return-objects-20261115a` and
`build/el0-partial-return-model-20261115a`.

## Page-relative shadow-header access

| Execution-interval metric | Paired return checks | Shadow-header access |
| --- | ---: | ---: |
| Syscall gateways | 2,136 | **2,136** |
| All gateways | 2,381 | **2,381** |
| System adapters | 1,858,097 | **1,781,197** |
| All runtime functions | 871,495 | 871,495 |
| All runtime/adaptation instructions | 6,375,145 | **6,298,245** |
| Total instructions | 9,337,956 | **9,261,056** |
| Runtime / original kernel operations | 2.0963:1 | **2.0710:1** |

The measured saving is **76,900 instructions (1.21%)**, entirely in system
adapters; every other adapter category is unchanged. Whole-ELF instructions
fall to **9,403,006**, with unchanged startup/final validation cost of 141,950.
Native kernel/application counts remain 2,830,860/131,951, with 3,041,214
original kernel visits. The **0.20:1 ceiling** and **0.10:1 target** remain unmet.
QEMU 9.2.3 TCG Cortex-A53, one vCPU, `PROFILE=1 LTO=1`; these are instruction
counts, not cycle/cache measurements.

The entire result and gateway, memory and system profiles match the preceding
image: 2,272 events, nine ordered counter inputs, 92 UART bytes, 185 recorded
faults and five memory post-operations. Hardware exceptions, runtime EL1
services and host calls before completion remain zero. RAM and tables remain
embedded. Payloads, initial state, mapping bindings and construction proofs are
byte-identical; mapping metadata gains only the shadow-header alignment.

Delivered [ELF](../build/el0-shadow-header-20261115a/checkpoint), SHA-256
`ea055504c47a1dc5a1639a39290d6345a1e9ea3f343a417eabaca213acbdc816`.
It is 159,159,312 bytes, **23,104 bytes smaller** than the paired-return image.

- [Counts](../build/el0-shadow-header-profile-20261115a/counts.json)
- [Measured workload validation](../build/el0-shadow-header-measurement-20261115a/validation.json)
- [Loaded code/data identity](../build/el0-shadow-header-profile-20261115a/profile-plan.json)
- [Hotspots](../build/el0-shadow-header-profile-20261115a/hotspots.json)
- [Budget assessment](../build/el0-shadow-header-profile-20261115a/budget.json)

Hardware-memory exports align `flat_shadow` to 128 bytes and access its small
primary header with `ADRP` plus load/store low-12-bit relocations. This removes
the separate address-building `ADD` from each admitted primary system adapter.
The emulation counter remains updated. Fields outside the aligned header keep
the existing handler path. The base-address generator remains available for
older fixtures and software exports.

DAIFSet/DAIFClr now combine each contiguous run of selected interrupt-mask bits
into one logical immediate. All mask values retain the shared emulator's
behavior, including zero masks. Admission, logical mode and maintenance rules
are unchanged; platform actions still use the existing runtime handlers.

The export declares this addressing contract in its manifest, hardware metadata
and read-only ELF flag. Model preparation checks agreement, actual header
alignment, the `flat_program.shadow` binding and flag page permissions before
execution. Earlier exports without this contract retain their base backend.

The executable differential fixture passes **77,056 cases** against the shared
emulator: both address backends, all admitted primary operations, register
aliases including XZR, all NZCV combinations, counter wrap, logical modes and
header placements at the beginning and end of a page. It also checks SP, a
SIMD sentinel, FPSR and FPCR. Four corrupted images reject misalignment, a
different shadow pointer, a writable contract flag and metadata downgrade.
Five full-image failures retain the GPR, PC, kernel-SP, cross-domain and page
descriptor diagnostics without a hardware service.

Run the focused fixture with:

```sh
python3 -m unittest discover -s tests -p test_el0_system_header.py -v
OSREC_EL0_SHADOW_HEADER_IMAGE=build/el0-shadow-header-20261115a \
  PYTHONPATH=tests python3 -m unittest test_el0_system_header.FullImage -v
```

Fresh export and object directories are required. Build the image with
`PROFILE=1 LTO=1 PRETRANSLATE=1`; runtime-only relinking cannot change generated
system adapters in an older export. Matching object/model directories are
`build/el0-shadow-header-objects-20261115a` and
`build/el0-shadow-header-model-20261115a`.

## Paired return-register checks

Generated user-return validation now checks R1–R30 in pairs: one paired load,
one compare, one conditional compare and one failure branch per pair. The
conditional compare keeps Z clear when the first register differs, so either
mismatch reaches the existing fallback. Scratch-register operands are still
loaded from their saved stack slots. X0 retains its separate syscall/fault rule.
All SP, PC, PSTATE, descriptor and target checks remain unchanged.

This removes 30 instructions from every successful user return, without changing
the scratch frame, guest SIMD/FP state, commit order or failure diagnostics. A
failure still restores the original context and enters the shared runtime's
ordered diagnostic scan. Every GPR remains checked at full 64-bit width.

| Execution-interval metric | LTO runtime | Paired return checks |
| --- | ---: | ---: |
| Syscall gateways | 2,136 | **2,136** |
| All gateways | 2,381 | **2,381** |
| System adapters | 1,926,227 | **1,858,097** |
| All runtime functions | 871,495 | 871,495 |
| All runtime/adaptation instructions | 6,443,275 | **6,375,145** |
| Total instructions | 9,406,086 | **9,337,956** |
| Runtime / original kernel operations | 2.1187:1 | **2.0963:1** |

The saving is exactly **68,130 instructions (1.06%)**: 30 instructions on each
of 2,271 successful user returns. All other adapter categories are unchanged.
Whole-ELF instructions fall to **9,479,906**, with unchanged startup/final
validation cost of 141,950. Native kernel/application counts remain
2,830,860/131,951, with 3,041,214 original kernel visits. The **0.20:1 ceiling**
and **0.10:1 target** remain unmet. QEMU 9.2.3 TCG Cortex-A53, one vCPU,
`PROFILE=1 LTO=1`; these are instructions, not cycle/cache measurements.

The entire result and every gateway, memory and system profile match the prior
LTO image: 2,272 events, nine ordered counter inputs, 92 UART bytes, 185 recorded
faults and five memory post-operations. Hardware exceptions, runtime EL1 services
and host calls before completion remain zero. RAM and tables remain embedded.
Payloads, initial state, mappings and construction proofs are byte-identical;
generated assembly changes only for the paired return checks.

All 67,584 differential cases pass against the shared emulator, including every
bit of every GPR, scratch aliases, both syscall/fault X0 rules, all NZCV
combinations and rejection before user-stack writes. Five corrupted full images
retain the GPR, PC, kernel-SP, domain and descriptor diagnostics. Profiler and
code/data-identity checks pass too.

Delivered [ELF](../build/el0-paired-return-20261115a/checkpoint), SHA-256
`93aace52b99cf59ea4fe2dda103dca5e0057526924c14e4614e70ee0f6dbb14d`.
It is 159,182,416 bytes, 232 bytes smaller than the baseline.

- [Counts](../build/el0-paired-return-profile-20261115a/counts.json)
- [Measured workload validation](../build/el0-paired-return-measurement-20261115a/validation.json)
- [Loaded code/data identity](../build/el0-paired-return-profile-20261115a/profile-plan.json)
- [Hotspots](../build/el0-paired-return-profile-20261115a/hotspots.json)
- [Budget assessment](../build/el0-paired-return-profile-20261115a/budget.json)

A fresh [pretranslated export](el0-pretranslated-memory.md#build-and-verify) is
required to obtain the new generated checks. Build it with
`PROFILE=1 LTO=1 PRETRANSLATE=1` and fresh object directories. A runtime-only rebuild of an old
export retains that export's older return code. Matching objects/model are
`build/el0-paired-return-objects-20261115a` and
`build/el0-paired-return-model-20261115a`. Run the return contract fixture with:

```sh
python3 -m unittest discover -s tests -p test_el0_return.py -v
```

## Link-time optimization

The standalone Makefile supports opt-in Clang/LLD link-time optimization with
`LTO=1`. C runtime modules and generated C data objects are compiled as bitcode,
allowing shared entry helpers to inline and simplify across module boundaries.
The `flat_*` model/debug ABI is retained explicitly at link time, including
constant metadata that the optimizer can fold out of C references. `flat_run`
remains a non-inlined execution boundary for identical-window measurement.
The default build remains non-LTO.

Syscall entry still captures the full GPR, SIMD and FP context, uses the private
runtime stack, records events and snapshots, validates entry/targets/stacks and
counts every gateway. Kernel/user generated assembly, initial payloads, mapping
metadata and analysis proofs are unchanged. The ELF's C code/data placement and
resolved hardware-table bytes change; RAM and tables remain embedded.

| Execution-interval metric | Cached resolver | LTO runtime |
| --- | ---: | ---: |
| Syscall gateways | 2,136 | **2,136** |
| All gateways | 2,381 | **2,381** |
| Syscall handler plus its shared entry function | 226,416 | **202,920** |
| All runtime functions | 899,851 | **871,495** |
| All runtime/adaptation instructions | 6,471,631 | **6,443,275** |
| Total instructions | 9,434,442 | **9,406,086** |
| Runtime / original kernel operations | 2.1280:1 | **2.1187:1** |

The syscall row includes the former separate `osrec_enter_syscall` cost;
that function is now inlined into `step_syscall`. Its combined cost falls
**10.38%**. Total runtime decreases by **28,356 instructions (0.44%)**, with all
generated adapter counts unchanged. Whole-ELF instructions decrease by 28,400
to **9,548,036**; startup/final validation decreases by 44 to 141,950.
Native kernel/application instructions remain 2,830,860/131,951, with 3,041,214
original kernel visits. The **0.20:1 ceiling** and **0.10:1 target** remain unmet.
QEMU 9.2.3 TCG Cortex-A53, one vCPU, `PROFILE=1`; these are instruction counts,
not cycle/cache measurements.

The entire result and all gateway, memory and system profiles match the
preceding image: 2,272 events, nine ordered counter inputs, 92 UART bytes,
185 recorded faults and five memory post-operations. Hardware exceptions,
runtime EL1 services and host calls before completion remain zero. Five
corrupted images retain the GPR, PC, SP, domain and descriptor diagnostics.
Shared-emulator, context/cache and profiler tests pass.

Hotspot attribution now uses the generated text and resume input-section
extents. LTO can place C functions after the resume section; those functions
must still count as runtime functions. A regression fixture tests both section
orders. The measured totals and budget calculation are independent of this
attribution correction.

Delivered [ELF](../build/el0-entry-lto-20261115a/checkpoint), SHA-256
`9452b6c2798e59c09934046bec832c50bcd8a833e4d92fdfecf502862267ea03`.
It is 159,182,648 bytes, 15,616 bytes smaller than the baseline.

- [Counts](../build/el0-entry-lto-profile-20261115a/counts.json)
- [Measured workload validation](../build/el0-entry-lto-measurement-20261115a/validation.json)
- [Loaded code/data identity](../build/el0-entry-lto-profile-20261115a/profile-plan.json)
- [Hotspots](../build/el0-entry-lto-profile-20261115a/hotspots.json)
- [Budget assessment](../build/el0-entry-lto-profile-20261115a/budget.json)

Use fresh runtime and image directories when changing LTO modes. Rebuild the
generated C objects too; reusing native `image.o`/`text.o` would make a partial
LTO build. Retain `LTO=1` when linking the annotated profiling copy with the
same runtime objects. For example:

```sh
python3 - <<'PY'
from pathlib import Path
import shutil
source=Path('build/el0-entry-target-20261115a')
out=Path('build/my-entry-lto'); out.mkdir()
skip={'image.o','text.o','checkpoint','checkpoint.map','pretranslated-elf.json'}
for file in source.iterdir():
    if file.is_file() and file.name not in skip:
        shutil.copy2(file,out/file.name)
PY
make -C runtime/el0_flat \
  'CC=/opt/homebrew/opt/llvm@16/bin/clang --target=aarch64-none-elf' \
  PROFILE=1 LTO=1 PRETRANSLATE=1 \
  OUT="$PWD/build/my-entry-lto-objects" IMAGE="$PWD/build/my-entry-lto" program
```

The delivered runtime objects are `build/el0-entry-lto-objects-20261115a`, and
the prepared model is `build/el0-entry-lto-model-20261115a`. Apply the existing
failure tests with their image variables set to `build/el0-entry-lto-20261115a`.

## Entry resolver

Successful context targets from the linked read-only PC index are cached by
full original PC, logical mode, native-stack setting, domain-range count and
PC-index count. A hit still checks the live kernel SP and the admitted mapping
identity/count and physical RAM bounds. Changed inputs take the full resolver,
retaining domain, stack, immutable-write and missing-target diagnostics in their
original order. Mutable legacy PC tables are never cached. Changing the live
exception vector selects a new lookup; no recorded target sequence is used.

The hot wrapper is a leaf function; the original resolver is outlined into
`target_slow`. Stack-admission checking stays inline. Empty register constraints
retain aggregate base pointers for compact generated loads; these constraints
emit no instructions and do not bypass any checks. Context capture, the private
runtime stack, syscall validation, snapshots, profiling and all gateway counts
remain unchanged. Generated assembly, payloads, mappings and analysis proofs
match the preceding export byte for byte.

| Execution-interval metric | Previous syscall runtime | Cached entry resolver |
| --- | ---: | ---: |
| Syscall gateways | 2,136 | **2,136** |
| All gateways | 2,381 | **2,381** |
| Target resolution, including all helpers | 258,462 | **168,050** |
| All runtime functions | 990,263 | **899,851** |
| All runtime/adaptation instructions | 6,562,043 | **6,471,631** |
| Total instructions | 9,524,854 | **9,434,442** |
| Runtime / original kernel operations | 2.1577:1 | **2.1280:1** |

The target row includes both `target` (146,125) and `target_slow` (21,925),
including cache misses and fills. Target-resolution work decreases **34.98%**.
The total saving is **90,412 runtime instructions (1.38%)**. All generated
adapter counts remain unchanged. Native kernel/application instruction counts
remain 2,830,860/131,951, with 3,041,214 original kernel visits. Whole-ELF
instructions fall to **9,576,436**; startup/final validation remains 141,994.
The **0.20:1 ceiling** and **0.10:1 target** remain unmet. QEMU 9.2.3 TCG
Cortex-A53, one vCPU, `PROFILE=1`; these are instruction counts, not cycles.

The full result and every gateway, memory and system profiling record match the
baseline: 2,272 events, nine ordered counter inputs, 92 UART bytes, 185 recorded
faults and five memory post-operations. Hardware exceptions, runtime EL1
services and host calls before completion remain zero. RAM and hardware tables
remain embedded, without an external table loaded.

The host test executes the actual resolver with a warmed cache against an
independent linear-scan reference. It covers all SP bits, mode/domain changes,
PC holes/alignment/bounds, native-stack and table-count changes, RAM bounds,
immutable overlaps, mutable mapping permissions, mutable legacy targets and a
null shadow in logical-stack resolution. Mapping/context, shared-emulator,
syscall and profiler checks pass. Two corrupted full images retain the `0x104`
kernel-SP and `0x103` cross-domain stops without native-access exceptions.
Non-profiled runtime syntax checking also passes.

Delivered [ELF](../build/el0-entry-target-20261115a/checkpoint), SHA-256
`b2c9a21df296500fa9399cae898692b49dc622e58a9b5eea68adc32cb0c486ce`.
The ELF grows by 1,208 bytes to 159,198,264 bytes.

- [Counts](../build/el0-entry-target-profile-20261115a/counts.json)
- [Measured workload validation](../build/el0-entry-target-measurement-20261115a/validation.json)
- [Loaded code/data identity](../build/el0-entry-target-profile-20261115a/profile-plan.json)
- [Hotspots](../build/el0-entry-target-profile-20261115a/hotspots.json)
- [Budget assessment](../build/el0-entry-target-profile-20261115a/budget.json)

Use the runtime-only rebuild procedure below, starting from
`build/el0-syscall-runtime-20261115a`. Matching runtime objects are in
`build/el0-entry-target-objects-20261115a`; the final prepared model is
`build/el0-entry-target-model-20261115b`. Run:

```sh
python3 -m unittest discover -s tests -p test_el0_runtime_hot.py -v
OSREC_EL0_NATIVE_STACK_IMAGE=build/el0-entry-target-20261115a PYTHONPATH=tests \
  python3 -m unittest test_el0_native_stack.NativeStackImage.test_bad_sp_and_cross_domain_vector_stop_before_native_access -v
```

## Syscall entry

The shared emulator now has one inline implementation of validated user entry,
used by both syscall entry and general user exceptions. The syscall API retains
all null-pointer, mode, PC, PSTATE, opcode and entry-form checks. Once validated,
it reaches that implementation directly without calling the generic exception
function or repeating PSTATE validation. The compiled syscall routine is now
frameless. The generic exception API still validates user PSTATE before any
mutation and retains same-level abort normalization.

The runtime records syscall arguments using a fixed 48-byte builtin copy,
allowing the compiler to use paired loads/stores. Context capture and restore,
private runtime-stack execution, snapshot recording, event capacity checks,
kernel-stack admission, target lookup and gateway/profiling accounting remain
active. Syscall FAR remains captured guest state. Generated assembly, payloads,
mapping metadata and analysis proofs are byte-identical to the preceding export.

| Execution-interval metric | Generated user-return baseline | Optimized syscall runtime |
| --- | ---: | ---: |
| Syscall gateways | 2,136 | **2,136** |
| All gateways | 2,381 | **2,381** |
| `step_syscall` instructions | 147,384 | **136,704** |
| Shared syscall + general exception-entry functions | 152,983 | **94,582** |
| All runtime functions | 1,059,344 | **990,263** |
| All runtime/adaptation instructions | 6,631,124 | **6,562,043** |
| Total instructions | 9,593,935 | **9,524,854** |
| Runtime / original kernel operations | 2.1804:1 | **2.1577:1** |

The shared-entry row includes general fault entry as well as syscall entry.
All generated adapter counts are unchanged. The net reduction is **69,081
instructions (1.04%)**, entirely in runtime functions. Native kernel/application
counts remain 2,830,860/131,951, with 3,041,214 original kernel visits. Whole-ELF
execution falls to 9,666,848 instructions; startup/final validation remains
141,994. The **0.20:1 ceiling** and **0.10:1 target** remain unmet. These are
dynamic instruction counts from QEMU 9.2.3 TCG Cortex-A53, one vCPU, `PROFILE=1`;
cycle/cache effects remain unmeasured.

All 2,272 events, nine ordered counter inputs and 92 UART bytes match. The entire
result structure and gateway, memory and system profiling records are identical
to the baseline, including 185 recorded faults and five memory post-operations.
Hardware exceptions, runtime EL1 services and host calls before completion remain
zero. RAM and hardware tables remain embedded, with no external table loaded.

Delivered [ELF](../build/el0-syscall-runtime-20261115a/checkpoint), SHA-256
`bd44264bcfe7367d0a1fbe37c66273e1f519d791296beffd530b9abf750ad7a1`.
The ELF is 159,197,056 bytes, 24 bytes smaller than the baseline.

- [Counts](../build/el0-syscall-runtime-profile-20261115a/counts.json)
- [Measured workload validation](../build/el0-syscall-runtime-measurement-20261115a/validation.json)
- [Loaded code/data identity](../build/el0-syscall-runtime-profile-20261115a/profile-plan.json)
- [Hotspots](../build/el0-syscall-runtime-profile-20261115a/hotspots.json)
- [Budget assessment](../build/el0-syscall-runtime-profile-20261115a/budget.json)

The host contract test covers 40,320 combinations of opcode, PC boundary,
PSTATE, logical mode and both entry forms, plus null-pointer checks. Rejections
preserve the context and shadow header; accepted entries retain FAR, PAN, all
GPRs and PSTATE while applying the expected stack/vector/ESR transition and
entry-count wrap. Invalid general user-exception PSTATE still stops before
mutating state. The executable syscall, context, user-return and profiler tests
pass; non-profiled runtime sources also pass syntax checking. The shared-core
contract test is registered with CTest as `el0_runtime`.

Reproduce using the runtime-only rebuild procedure below, starting from
`build/el0-user-return-20261114a`, with fresh output directories. The matching
runtime objects are in `build/el0-syscall-runtime-objects-20261115a`. Finalize
the annotated profiling copy with `PRETRANSLATE=1` before checking loaded
code/data identity.

```sh
python3 -m unittest discover -s tests -p test_el0_runtime.py -v
python3 -m unittest discover -s tests -p test_el0_syscall.py -v
```

## Dispatcher specialization

The dispatcher now tail-calls separate system-operation, syscall and general
handlers. The memory implementation is outlined into its own handler, and
operand decoding occurs only on paths that need it. The top-level `step`
has no stack frame; the syscall handler uses 48 bytes instead of the preceding
general handler's 192 bytes. Post-operation restore, fault, UART and exclusive
behavior remain unchanged.

System profiling caches the last matching `(word, metadata)` row. Key misses
use the original first-match/first-empty search. The overflow bucket is never
treated as a cached source key. Counter wrap and reset behavior retain the
original layout and row order; a cache must be cleared when its table is reset.
Profiling remains enabled, with unchanged gateway, memory and system records.

| Execution-interval metric | Previous runtime | Specialized dispatcher |
| --- | ---: | ---: |
| Dispatcher plus profiling helpers | 837,493 | **718,995** |
| All runtime functions | 2,420,875 | **2,302,377** |
| All runtime/adaptation instructions | 7,341,709 | **7,223,211** |
| Total instructions | 10,304,520 | **10,186,022** |
| Runtime / original kernel operations | 2.4141:1 | **2.3751:1** |

The dispatcher row includes every new handler and the cold profiling lookup;
it is not just the smaller top-level `step`. It decreases **14.15%**. All runtime
functions decrease **4.89%**, and total runtime/adaptation decreases by
**118,498 instructions (1.61%)**. Kernel/application native payload counts and
the 3,041,214 original kernel visits remain unchanged.

Whole-ELF instructions fall to **10,328,016**; startup/final validation remains
141,994. The ELF grows by 2,664 bytes to 159,194,904 bytes. All 2,272 events,
nine counter inputs and 92 UART bytes match, with the same 4,664 gateways,
185 recorded faults and five memory post-operations. Hardware exceptions,
EL1 runtime services and host calls before completion remain zero. The
**0.20:1 ceiling** and **0.10:1 target** remain unmet. These are instruction
counts, not cycle or cache measurements.

Delivered [ELF](../build/el0-runtime-dispatch-20261114b/checkpoint), SHA-256
`3e8ba9dbfda451602217f65e52e3686262d900374fedf06492b2ce22467175cb`.

- [Counts](../build/el0-runtime-dispatch-profile-20261114b/counts.json)
- [Full measurement validation](../build/el0-runtime-dispatch-measurement-20261114b/validation.json)
- [Loaded code/data identity](../build/el0-runtime-dispatch-profile-20261114b/profile-plan.json)
- [Hotspots](../build/el0-runtime-dispatch-profile-20261114b/hotspots.json)
- [Budget assessment](../build/el0-runtime-dispatch-profile-20261114b/budget.json)

A host counter-table oracle checks repeated/alternating keys, identical words
with different metadata, exact row order, capacity overflow, a real sentinel
key, counter wrap and reset. Full-image GPR, PC, descriptor, SP and cross-domain
corruptions still produce their original diagnostics without hardware faults.
The existing runtime context, shared emulator, memory and profiler checks pass.
Both profiled and non-profiled runtime configurations compile. Reproduction
uses the runtime-only rebuild procedure below.

## Previous runtime pass

This pass changes runtime code while reusing the preceding ELF export's
generated kernel/user assembly, payloads and mapping metadata byte for byte.
Gateway counts and source-operation visits remain unchanged.

## Changes

- **User-context copy and comparison:** caller-saved integer SIMD copies the
  31 GPRs, SP and PC into the admission snapshot. The return comparison checks
  GPRs and SP together, masking only X0 for syscall returns. PC is checked
  separately. A mismatch takes the original scalar diagnostic scan, preserving
  the first failing register and `0x106`/`0x107` stop details. PSTATE is outside
  these helpers' copied/compared fields, as before. Helpers run after full guest
  SIMD capture, use only caller-saved SIMD registers, and preserve NZCV, FPSR
  and FPCR. Their memory is normal RAM under the existing model mappings.
- **Kernel-stack admission:** the linked read-only `flat_maps` table is checked
  once for ordered, nonempty, nonoverlapping ranges without address wrap. New
  stack positions use a mapping hint or binary search. A completed admission
  can be reused for the exact same SP while table identity/count and physical
  RAM base/size match. It is recorded only after range, permission, physical
  backing and immutable-write checks pass. The domain/mode check still runs
  before this path. Mutable/replaced tables and invalid index geometry retain
  the original first-eligible scan, including overlap order.
- **Runtime write protection:** successful bitmap tests replace repeated
  protected-span searches for ordinary RAM writes and stack admission. A set
  bit still takes the exact byte-range search, preserving partial-page
  semantics. Missing bitmaps, changed RAM bounds and larger transfers retain
  that search too.
- **Word reads:** fixed-size builtin copies produce native little-endian
  64-bit reads for captured PTEs and observed results, preserving unaligned
  access support in normal RAM.
- **ERET:** the shared emulator checks its hot return opcode before general
  system-register decoding. It calls the same exception-return implementation
  and retains all SPSR/mode checks and emulation counters.

## Measured result

Delivered [ELF](../build/el0-runtime-fast-20261114b/checkpoint), SHA-256
`ffe4843b9e5f1f1b7207450524694583db92ccb05bbc2db6db2115fc750c3213`.
QEMU 9.2.3 TCG Cortex-A53, one vCPU, `PROFILE=1`. These are dynamic instruction
executions, not processor cycles.

| Execution-interval metric | Bitmap baseline | Optimized runtime |
| --- | ---: | ---: |
| Runtime functions, including new helpers | 3,186,338 | **2,420,875** |
| All runtime/adaptation instructions | 8,107,172 | **7,341,709** |
| Native kernel payload | 2,830,860 | 2,830,860 |
| Native application payload | 131,951 | 131,951 |
| Original kernel operation visits | 3,041,214 | 3,041,214 |
| Total instructions | 11,069,983 | **10,304,520** |
| Runtime / original kernel operations | 2.6658:1 | **2.4141:1** |

Runtime functions decrease **24.02%**; total runtime/adaptation decreases
**765,463 instructions (9.44%)**. Every generated adapter category retains its
preceding count. The remaining runtime function costs include `step` (837,493),
`target` (521,653), context capture/restore and dispatch. The new context
comparison/copy helpers account for 117,956 and 43,168 instructions respectively.

Whole-ELF execution decreases from 11,211,642 to **10,446,514** instructions.
Startup/final validation grows by 335 instructions, from 141,659 to 141,994;
the execution-interval improvement is therefore also a whole-image reduction.
The ELF grows by 2,352 bytes to 159,192,240 bytes. Cache/cycle effects remain
unmeasured.

All **2,272 events**, **nine ordered counter inputs** and **92 UART bytes**
match, with the same **4,664 gateways**, zero hardware exceptions, no EL1
runtime service and no host calls before completion. RAM and page tables remain
embedded, without an external page-table image loaded. The **0.20:1 ceiling**
and **0.10:1 target** remain unmet.

- [Counts](../build/el0-runtime-fast-profile-20261114b/counts.json)
- [Full measurement validation](../build/el0-runtime-fast-measurement-20261114b/validation.json)
- [Loaded code/data identity](../build/el0-runtime-fast-profile-20261114b/profile-plan.json)
- [Hotspots](../build/el0-runtime-fast-profile-20261114b/hotspots.json)
- [Budget assessment](../build/el0-runtime-fast-profile-20261114b/budget.json)

## Verification and reproduction

The context fixture checks both 8- and 16-byte-aligned contexts, copy boundaries
and 17,408 single-bit mutations, including allowed syscall X0 changes and
independently checked SP. It verifies unchanged NZCV, FPSR and FPCR. Mapping
tests compare the ordered/hinted lookup with the original scan over 77,824 SP
values and check cache invalidation, RAM bounds, overlap order and live mutable
permissions. The fixture uses the same normal RAM type as the delivered image.

Full-image corruptions retain the expected `0x106` register, `0x107` PC,
`0x105` descriptor, `0x104` SP and `0x103` cross-domain diagnostics, with zero
hardware exceptions. Shared ERET contracts, native-stack/SIMD preservation,
software/live user translation and profiler checks also pass.

Rebuild an existing export into a fresh directory with fresh runtime objects;
no new exporter analysis is required:

```sh
cp -R build/el0-page-bitmap-20261114a build/my-runtime-image
make -C runtime/el0_flat \
  'CC=/opt/homebrew/opt/llvm@16/bin/clang --target=aarch64-none-elf' \
  PROFILE=1 PRETRANSLATE=1 OUT="$PWD/build/my-runtime-objects" \
  IMAGE="$PWD/build/my-runtime-image" program
python3 -m unittest discover -s tests -p test_el0_runtime_hot.py -v
OSREC_EL0_RUNTIME_FAST_IMAGE=build/my-runtime-image PYTHONPATH=tests \
  python3 -m unittest test_el0_runtime_hot.RuntimeImageDiagnostics -v
```
