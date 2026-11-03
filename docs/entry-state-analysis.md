# Automated entry-state discovery and capture

The entry-state tool uses Clang's typed AST from the actual configured kernel
translation units. It discovers memory reads, writes, pointer edges, aliases,
function arguments and direct call paths. Field lists are not supplied by the
user. A separate boundary policy specifies which dependencies are reconstructed
objects, recorded scalar outcomes, ordering models or memory models.

## Whole-kernel coverage survey

Survey the existing configured build before selecting new capture roots:

```sh
python3 tools/discover_kernel_state.py --liteos-tree build/ohos \
  --out output/kernel-state-survey --jobs 2
```

The output directory must be new. `objects.json` accounts for every existing
`out/obj/**/*.o`, including assembly and failed source provenance. Dependency
files identify the source; active Make modules and their `LOCAL_OBJS` identify
the owning build rule, including libraries outside their source directories.
Recovery uses `make -n` with the real configuration. It does not rebuild the
kernel. `module-ownership.json` retains module-query failures, and recovered
commands are saved in `compile_commands.json`.

The generic `--compile-commands PATH` mode surveys a supplied compilation
database. Each source runs in a separate worker, with a default 180-second unit
timeout, one-second root timeout and 100-context analysis cap. These are resource
limits, not proofs: timed-out or failed functions remain failed. Assembly,
command failures, parse failures and roots not reached before a unit failure
stay visible. Parsed function inventories are checkpointed before root analysis.
`Analyzer.fresh()` shares immutable AST indexes while isolating each root's
reads, writes, aliases, providers, ranges and call counters.

`units/*.json` retains source/header hashes, compiler identity, the primary-source
function inventory, read/write paths, blocker counts and up to three examples
per blocker kind. Header bodies are available to local call closure but are not
counted again as primary-source roots. Candidates are reported separately from
plans accepted by capture-schema generation. Neither status establishes native
capture/replay correctness, termination, minimality or completeness.

`report.json` ranks blockers and unresolved calls by affected roots. A call whose
external body appears elsewhere is marked `cross_translation_unit_body_available`;
it remains unresolved in this baseline. No models or argument contracts are
invented. Build objects may include stale or unlinked files, and the report says
so. Linked text symbols from the current ELF provide an additional denominator;
their source correspondence uses names only, not verified link provenance.
Duplicate static names, assembly and linker elimination prevent treating those
matches as exact coverage. Other configurations and architectures are outside
the current survey.

The 2026-10-21 baseline in `build/whole-kernel-discovery-v2` accounts for 640
existing objects: 623 C and 17 assembly units. All 623 C commands were recovered;
622 units parsed and were surveyed. Active module ownership covers 638 objects,
including 621 C units, all of which parsed. The two unowned existing objects are
the hook and MTD shell-command objects. The hook source fails parsing because
its internal include path is absent while `LOSCFG_KERNEL_HOOK` is disabled; that
failure is retained rather than repaired with invented compiler flags.

The survey records 2,897 primary-source function bodies: 2,437 blocked, 409
candidates and 51 root timeouts. Of the candidates, 233 pass capture-schema
generation; none receive new runtime validation from this survey. Unavailable
call bodies affect 2,010 roots, and 861 unresolved callee names have external
definitions elsewhere in the inventory. The largest such gaps include
`LOS_LkPrint`, `__errno_location`, `LOS_MemFree` and `memset_s`. Cross-file closure
is the next major implementation gap; these functions are not automatically
replaced by transcripts or assumed pure. The current ELF has 1,427 text symbols,
which are tracked separately from C-body coverage.

Six focused tests and four targeted CTest suites pass. The validation manifest
`build/whole-kernel-discovery-validation-20261021.json` checks all object,
source, dependency and unit-report hashes, and records the coverage limits.

### Current analyzer refresh, 2026-10-22

`build/whole-kernel-current-20261022` reruns all 623 frozen compile commands
with the current analyzer and the same two workers, 100-context cap, one-second
root budget and 180-second unit budget. All 640 object/dependency-file hashes,
the frozen ELF, and 960 source/header dependencies match before and after the
scan. No kernel rebuild, source repair or boundary model is introduced.

The matching primary-source inventories contain the same 2,897 C roots:

| Same-TU classification | Original baseline | Current analyzer |
| --- | ---: | ---: |
| Candidate | 409 | 416 |
| Blocked | 2,437 | 2,427 |
| Root timeout | 51 | 54 |

Eight blocked roots become candidates: `OsSetMainTaskProcess`,
`OsVmPhysAreaSizeAdjust`, `OsInactiveListIsLow`, the four `OsMoveToActive*` /
`OsMoveToInactive*` helpers, and `__tandf`. Conversely, `__year_to_secs` is now
blocked on unresolved pointer origins. Three formerly blocked roots time out;
failure transitions are not semantic improvements. All 51 previous timeouts
remain timeouts. The same `los_hook.c` parse failure remains, reporting missing
`los_hook_types_parse.h`, and 17 assembly objects remain unanalyzed.

There are 234 entry-schema candidates, versus 233 previously. This does not
establish complete write/effect capture or replay. Among roots completed by both
engines, 648 have changed read/write path sets. Unsupported-construct blockers
affect 16 roots rather than 588, while unresolved-origin blockers affect 1,182
rather than 980; improved syntax support does not remove origin requirements.

`build/whole-kernel-current-20261022-validation/report.json` records the complete
status transition matrix, changes, remaining failures and verified engine.
`verification.json` binds the reports, units and saved analyzer sources. The raw
scan uses `--compile-commands`, so its object count is zero; separately verified
copies of the frozen object and ownership inventories supply the build context
and active-module filter.

Fresh cross-file request lists contain 417 missing-body-only roots and 1,470
mixed-blocker roots. Their selection uses the current survey and the pinned
active-module ownership. Earlier cross-file results and the 2,897-root combined
accounting remain historical; they are not imported as fresh closure results.
The next stage is to run these versioned requests with the current engine.

## Discovered cross-file call closure

Expand calls using the verified survey's external-definition index:

```sh
python3 tools/discover_call_closure.py --survey output/kernel-state-survey \
  --roots roots.json --out output/discovered-closures \
  --max-translation-units 4 --root-timeout 60 --jobs 2
```

`roots.json` is an array of objects with `source` (the absolute source path from
the survey) and `root` (its original function name). The output directory must
be new. The tool verifies the compilation database, unit reports and recorded
source/header hashes before using the index. Each expansion freshly parses the
selected source and checks its identity. It merges configured ASTs with namespaced
declaration IDs, static functions and globals, then reruns analysis. Only missing
named call bodies with one indexed external definition select another file.
Transitive calls are discovered from the expanded plan, rather than assumed
from function names or replaced by transcripts.

The default limits are four translation units, 100 call contexts and 60 seconds
per root. Conflicting declarations/records, ambiguous external definitions,
changed inputs, unavailable bodies and resource limits remain explicit failures
or blockers. Target/compiler identities and relevant ABI options must agree;
repeated flags are normalized with last-option precedence. Function-reference
slicing now removes unrelated functions before checking compatibility; all
top-level records remain and existing record checks still apply. Weak-symbol precedence,
assembly bodies, arbitrary buffer extents and whole-program alias proofs remain
outside the loader.

Each root report retains the final valid plan, source identities, per-round
missing bodies and access paths, and every load/conflict/limit event. If a later
merge fails, the previous blocked plan is retained. A timed-out worker keeps its
last checkpoint and has status `failed`. Candidate and capture-schema statuses
retain their earlier meanings: they are not native capture/replay approval or
proof of complete state. No boundary models or object contracts are invented.

The initial 2026-10-21 trial in `build/call-closure-discovery-v2` selects up to four
roots per source group from the baseline's roots having only missing-body
blockers and unique available definitions. It covers 29 roots in eight groups.
Twenty reach a valid expanded plan, resolving 25 initial root/callee gaps.
The final statuses are two candidates, 26 blocked and one 30-second timeout.
The candidates are capture initialization (`osrec_capture_init`) and procfs name
comparison (`EntryMatch`); this does not establish a newly replayable kernel
syscall. Further calls, memory effects, type conflicts and unit limits remain
visible, rather than being suppressed to increase candidate counts.

Six focused tests cover transitive expansion, static identity, ambiguous/missing
bodies, unit limits, type/ABI conflicts, changed survey dependencies and generated
native capture through helper files. Explicit fixture object contracts enable
eight native calls in both replay modes, two addresses and portable rebuilds.
Six fixture images plus CLI export pass; twelve standalone ELF/raw runs and four
EL3 memory/CPU entry checks pass. Two helper-body mutations fail state verification
despite correct returns. Five targeted CTest suites pass. Evidence is retained in
`build/call-closure-validation-20261021.json`; these fixtures do not add native
validation to the 29 real-kernel plans.

### Function-reference slices and automatic batches

Automatic closure now passes its namespaced root to
`merge_translation_units(units, roots=[root])`. Before conflict checks, the merge
computes a syntactic closure over function references and referenced global
initializers. This retains direct callees, addresses used as callbacks, all
statically visible callback alternatives, and function references reached through
global initializer chains. Functions referenced only by unused globals do not
enter the slice. This is a reference graph, not a claim that all indirect targets
or global writes have been resolved.

Every declaration and body for a retained function name participates in the
existing signature and duplicate-definition checks. Referenced conflicts remain
blocked. All top-level nonfunction declarations remain, including records;
unrelated record conflicts still block the merge. Function-local scopes and
declaration IDs retain their TU namespaces. `program.function_slice` records the
roots, retained names and removed declaration count. The existing unsliced
`merge_translation_units(units)` API keeps its prior behavior; automatic closure
also accepts `slice_functions=False` for comparison.

Configured Clang JSON ASTs are copied and namespaced in one pass, with a
separate cloning memo for each translation unit. Merged AST storage is
independent of the parsed input trees, including nested dictionaries and lists.

To select a bounded batch directly from a verified survey:

```sh
python3 tools/discover_call_closure.py --survey output/kernel-state-survey \
  --all-eligible --max-roots 128 --out output/closure-batch \
  --max-translation-units 4 --root-timeout 10 --jobs 2
```

Eligible roots have only missing-body blockers, with one indexed external source
for every missing callee. If object/module ownership files are available, only
sources owned by active modules are selected. Roots are sorted within source
groups and interleaved across groups. `--max-roots` limits this sequence; without
it, all eligible roots are requested. The batch report records the eligible
count, group counts, active-module filter and selection-input hashes. This does
not replace the full coverage denominator: roots with other blocker classes and
inactive objects remain in the original survey.

The fixture tests include conflicting unused prototypes in separately compiled
files, plus referenced conflicts, duplicate bodies, finite callbacks, global
initializer references and record conflicts. Sliced and unsliced plans match
when the original merge is valid. The cross-file fixture retains explicit object
contracts and verifies entry/post-state through native capture and standalone
replay; this does not validate real-kernel candidates at runtime.

The 2026-10-21 validation in `build/function-slice-original29-v1` reruns the
original 29 roots with the same unit/context/time limits. Valid expanded plans
increase from 20 to 27, initial root/callee gaps resolved from 25 to 32, and
merge-conflict stops fall from ten to two. Final statuses are three candidates,
25 blocked and one timeout. `InitRebootHook` is the additional candidate after
its unrelated `dprintf` declarations are excluded; it is not newly validated
for native capture or replay.

Automatic selection finds 507 eligible active-source roots. The bounded run in
`build/function-slice-coverage128-v1` requests 128 across 12 groups, with a
four-unit limit and ten seconds per root. It finishes with 19 candidates, 99
blocked and ten timeouts. Among completed roots, 113 reach valid expanded plans
and resolve 130 initial root/callee gaps. Nine timed-out roots have expanded
checkpoints; those remain failures and are excluded from the completed-plan
totals. The remaining eligible roots have not been covered by this batch.

All ten focused tests and five targeted CTest suites pass. Two native fixture
captures produce six accepted images plus one CLI export. Twelve standalone
ELF/raw runs, four EL3 memory/CPU entry checks and both state-error mutations
pass their checks. Seven prior exports retain identical raw images and results.
`build/function-slice-validation-20261021.json` records source/artifact hashes,
selection and limits. Neither broader root selection nor function slicing
establishes whole-kernel completeness or a performance result.

### Continuing and accounting for the eligible cohort

The automatic sequence supports a zero-based offset, so completed roots need
not be requested again:

```sh
python3 tools/discover_call_closure.py --survey output/kernel-state-survey \
  --all-eligible --start-root 128 --out output/closure-remainder \
  --max-translation-units 4 --root-timeout 10 --jobs 2
```

Without `--max-roots`, this requests the remainder of the verified sequence.
Negative or out-of-range offsets fail explicitly. A changed survey or selection
ordering cannot silently reuse an old offset when results are combined, because
aggregation checks every automatic batch against the current verified sequence:

```sh
python3 tools/discover_call_closure.py --survey output/kernel-state-survey \
  --aggregate-batches output/closure-batch output/closure-remainder \
  --out output/closure-coverage
```

Aggregation validates survey/database identity, requested/result sets, root
report hashes, source identities and matching unit/context/time limits. It
rejects overlaps, missing results, altered automatic selections and roots
outside the eligible cohort. An interrupted batch without a final report is
not a completed input. Failed roots remain requested failures; only roots never
requested are counted as unrequested. Partial aggregations retain that list.
These are checks on recorded results, not cache admission or fresh analysis.

New scan reports fingerprint the discovery/analysis source files and record
whether those files remained unchanged through the batch. Aggregation preserves
this provenance for each input, including absent fingerprints on older reports.
It does not assert uniform implementation provenance for historical batches.
Its `recorded_results_only` scope and false runtime/completeness flags remain
explicit. Covering this cohort does not cover roots with other initial blocker
classes, assembly, other configurations or all linked kernel state.

The 2026-10-21 accounting in `build/eligible-closure-all507-v1` combines the
first 128 roots with `build/eligible-closure-remaining379-v1`, using four units,
100 call contexts and ten seconds per root. All 507 eligible roots are requested
exactly once, with none left unrequested. Results are 46 candidates, 405 blocked
and 56 timeouts. Among completed roots, 423 reach valid expanded plans and resolve
734 initial root/callee gaps. Failed checkpoints remain outside those totals.
Thirty candidates pass capture-schema generation; no native kernel validation
is added by this accounting run.

The full baseline still contains 2,897 primary-source roots; 2,390 roots outside
this eligibility rule are not revisited here. Completed-plan blockers most often
include unresolved memory (315 roots), unavailable bodies (304), architecture or
ordering effects (257), and dynamic extents (240). These counts overlap because
one plan can have several blocker classes. `build/eligible-closure-triage-20261021.json`
retains the detailed ranking and remaining callee definitions for the next step.

Six targeted CTest suites and five focused accounting tests pass, including the
existing ten closure tests with native fixture replay. The prior engine source
is matched to its recorded hash, and its analysis definitions and worker dispatch
match the continuation engine. New batch source fingerprints remain stable;
the older batch's absent fingerprint fields remain absent in the aggregate.
`build/eligible-closure-validation-20261021.json` records the input/result hashes,
engine comparison, coverage limits and validation. This completes the eligible
cohort's recorded coverage, while whole-kernel state discovery remains incomplete.

### Expanding roots with additional blockers

`--all-mixed` selects a separate cohort from the verified survey: blocked roots
outside `--all-eligible` that have at least one unresolved callee with a unique
indexed external C definition. Other architecture, memory, pointer, recursion or
call blockers can remain. Roots with only unavailable/ambiguous bodies and roots
whose analysis failed are not selected. Active-module filtering and deterministic
source-group interleaving use the same inventory as the original cohort.

Requests record available, unavailable and ambiguous callees and the baseline
blocker classes. Loading an available body does not supply a model for any other
dependency. Source/ABI/type checks, function-reference slicing, unit/context/time
limits and failure checkpoints remain unchanged. Selection uses the frozen
survey's classifications, so later analyzer improvements do not silently change
the continuation order.

```sh
python3 tools/discover_call_closure.py --survey build/whole-kernel-discovery-v2 \
  --all-mixed --max-roots 64 --max-translation-units 4 --max-contexts 100 \
  --root-timeout 10 --jobs 2 --out build/mixed-closure64-v1
python3 tools/discover_call_closure.py --survey build/whole-kernel-discovery-v2 \
  --aggregate-batches build/mixed-closure64-v1 --coverage-cohort mixed \
  --out build/mixed-closure-coverage64-v1
```

Continuation uses the next saved `--start-root` offset with the same survey and
limits. Aggregation
requires an explicit mixed-cohort denominator and rejects automatic batches
from the other cohort. Failed and unrequested roots remain separate. The mixed
summary uses `mixed_roots`; the original eligible summary and historical
aggregation retain their existing representation.

The frozen baseline identifies 1,381 mixed roots in 12 groups, disjoint from the
507 initially missing-body-only roots. Another 1,009 baseline primary roots are
outside both selections. Those roots, parse failures, assembly and other
configurations remain outside these cross-file cohorts; no completeness or
runtime claim follows from their selection.

The first batch in `build/mixed-closure64-v1` requests 64 roots across all 12
groups. Thirty-five complete as blocked plans and 29 time out. All 35 completed
plans expand to additional translation units; 40 initially missing callees
remain observed and now resolve to configured C bodies. No candidate or capture
schema is promoted. The mixed coverage report retains 1,317 unrequested roots.

Completed plans record 52 additional read-path and 49 write-path occurrences
relative to their first single-unit plans. These are conservative symbolic
records, including unresolved/null forms, and do not establish capturable state.
The validation report separates paths containing explicit unknown markers and
does not treat removed paths as omission proofs. Remaining blockers include
unavailable calls (24 completed roots), unresolved memory (22), dynamic extents
(19), and architecture/ordering effects (18); counts overlap.

Six targeted CTest suites pass, including five mixed-cohort tests, the five
legacy accounting tests and the existing ten closure tests with native fixture
replay. `build/mixed-closure-validation-20261021.json` verifies source/result
hashes, disjoint selection, coverage, ABI compatibility and body-gap counts.
The former 507-root selection and aggregate match the prior tool's output
exactly; body-discovery and identity-check definitions are unchanged. This batch
adds no runtime kernel validation or boundary models, and failed expansion
checkpoints are excluded from completed-plan totals.

`build/mixed-closure-next64-v1` continues at offset 64 with the same engine and
limits. Its 64 roots produce 61 completed blocked plans and three timeouts; all
61 completed plans expand, resolving 95 additional initial root/callee gaps.
They record 260 additional read-path and 286 write-path occurrences, with
explicit unknown markers kept separate from potentially useful symbolic paths.
No candidate or capture schema is promoted.

`build/mixed-closure-coverage128-v1` checks both disjoint batches: 128 requested
roots, 96 completed blocked plans, 32 timeouts and 1,253 unrequested roots. Across
completed plans, 135 initial root/callee gaps now resolve to configured bodies.
The continuation validator checks complete compiler/source/header identities,
ABI compatibility, engine fingerprints, result hashes and the saved request
sequence. Earlier regression evidence is reused because the analysis engine and
test configuration are unchanged; tests are not rerun for this data-only batch.
`build/mixed-closure-continuation128-validation-20261021.json` records this
accounting. The next continuation offset is 128. Runtime validation and
whole-kernel completeness remain unproved.

The third batch, `build/mixed-closure-third64-v1`, continues at offset 128.
Twenty plans complete as blocked and 44 time out. All 20 completed plans expand,
resolving 20 further initial root/callee gaps. No candidates or capture schemas
are promoted. `build/mixed-closure-coverage192-v1` now accounts for 192 roots:
116 completed blocked plans, 76 timeouts and 1,189 unrequested roots. Completed
plans cumulatively resolve 155 initial root/callee gaps. Timeout checkpoints
remain excluded from these expansion totals.

`build/validate_mixed_continuation.py` accepts the prior validation, new batch,
cumulative coverage and output paths. It verifies the full predecessor artifact
chain, unchanged analysis fingerprints, exact continuation order and preservation
of the earlier batches. Each output keeps an immutable copy of the validator.
Checks against the earlier 128-root report reproduce its coverage and metrics;
an attempted repeated batch is rejected before output. The recorded checks are
in `build/mixed-closure-generic-validator-checks.json`. The 192-root validation
is `build/mixed-closure-continuation192-validation-20261021.json`.

The fourth batch starts at offset 192. Its original output,
`build/mixed-closure-fourth64-v1`, contains nine completed blocked plans,
49 timeouts and six explicit disk-write failures. Removing 604,316,566 bytes of
abandoned generated Clang temporary files allowed those six failures to be
retried with the same analysis limits; all six completed as blocked. Original
results, retry results, logs and hashes are preserved. The accepted batch,
`build/mixed-closure-fourth64-recovered-v1`, replaces only those six failures
and retains the other 58 results unchanged. It contains 15 completed blocked
plans and 49 timeouts. Twelve completed plans expand, resolving 23 additional
initial root/callee gaps. No candidate or capture schema is promoted.

`build/mixed-closure-coverage256-v1` accounts for 256 of the 1,381 mixed roots:
131 completed blocked plans, 125 timeouts and 1,125 unrequested roots. Across
completed plans, 128 expand and 178 initial root/callee gaps now resolve to
configured bodies. Failed checkpoints remain excluded from these totals.
A diagnostic of the preceding 192 roots records valid plan checkpoints for
66 of their 76 timeouts, including expanded checkpoints for 18; ten have no
valid checkpoint. These checkpoints do not establish where a timeout occurred.

The continuation validator also independently checks the six recorded retries,
preserved originals, unchanged limits and 58 untouched results. Its updated
parity and repeated-batch rejection checks are recorded in
`build/mixed-closure-generic-validator-checks-v2.json`; earlier checks remain
preserved. Current validation is
`build/mixed-closure-continuation256-validation-20261021.json`, and the next
offset for that validation is 256. The analyzer and test configuration are unchanged, so earlier
regression evidence is reused. Whole-kernel completeness and runtime validation
remain unproved.

The fifth batch, `build/mixed-closure-fifth64-v1`, starts at offset 256. All
64 roots complete as blocked plans, with no timeouts or worker errors. Of these,
63 plans expand and resolve 142 additional initial root/callee gaps. Two roots,
`__stdio_write` and `fprintf`, retain their last valid blocked plan after a later
merge rejects incompatible configured `_IO_FILE` record definitions; this does
not establish a complete closure. The plans record 641 additional read-path
and 1,057 write-path occurrences, including explicitly marked unknown paths.
No candidate or capture schema is promoted.

`build/mixed-closure-coverage320-v1` accounts for 320 mixed roots: 195 completed
blocked plans, 125 timeouts and 1,061 unrequested roots. Across completed plans,
191 expand and 320 initial root/callee gaps now resolve to configured bodies.
The 320-root validation is
`build/mixed-closure-continuation320-validation-20261021.json`. The engine remains
unchanged and existing regression evidence is reused.

Separate diagnostic reruns select the first earlier timeout with no saved plan,
one saved plan and an expanded saved plan. All three finish within ten seconds
when run sequentially, and their blocked results do not replace accepted
coverage. Instrumented phase timings show merging consumes approximately
1.9–5.7 seconds per probe, versus 0.017–0.022 seconds for root analysis. This
small sample identifies merging as a useful next profiling target; it does not
establish the cause of historical timeouts or a performance benchmark. The
script, phase traces, results, prior-result hashes and unchanged engine hashes
are preserved under
`build/mixed-closure-fifth64-v1/diagnostics/timeout-phase-probes-v1`.

The sixth batch, `build/mixed-closure-sixth64-v1`, starts at offset 320 and
records 57 completed blocked plans and seven timeouts, with no other worker
errors. Of the completed plans, 51 expand and resolve 122 additional initial
root/callee gaps. They record 269 additional read-path and 340 write-path
occurrences, including explicitly marked unknown paths. Eleven roots retain
their last valid blocked plan after a later merge rejects incompatible
configured declarations or record layouts. No candidate or capture schema is
promoted, and failed checkpoints remain excluded from completed-plan totals.

`build/mixed-closure-coverage384-v1` accounts for 384 mixed roots: 252 completed
blocked plans, 132 timeouts and 997 unrequested roots. Across completed plans,
242 expand and 442 initial root/callee gaps now resolve to configured bodies.
The 384-root validation is
`build/mixed-closure-continuation384-validation-20261021.json`.
The engine and test configuration remain unchanged, so earlier regression
evidence is reused. Whole-kernel completeness and runtime validation remain
unproved.

Separate `cProfile` reruns of the same three diagnostic roots record eight
completed merge calls. Full-AST `deepcopy` and the subsequent `namespace` walk
account for approximately 99.2% of their aggregate profiled merge time. This
descriptive sample includes substantial profiler overhead and uses a separate
60-second worker cap; it supplies neither accepted coverage nor a speedup claim.
All three results remain blocked. One result matches the earlier diagnostic
exactly; two differ only in entry-read order. Independent verification checks
entry-read multiplicities and every access field, with every other result field
matching exactly, plus configured source identities and artifact hashes.
The profiles, raw results and verification are preserved under
`build/mixed-closure-sixth64-v1/diagnostics/merge-profile-probes-v1`.
The next performance target is reducing repeated full-AST copying and
namespacing while preserving input immutability, identifier isolation, reference
closure and all configured record checks. No production optimization is applied
by these diagnostic runs.

The seventh batch, `build/mixed-closure-seventh64-v1`, starts at offset 384 and
records 33 completed blocked plans and 31 timeouts, with no other worker errors.
Thirty completed plans expand and resolve 75 additional initial root/callee gaps.
They record 122 additional read-path and 115 write-path occurrences, including
explicitly marked unknown paths. Three roots retain their last valid blocked
plan after later merges reject incompatible configured declarations or record
layouts. No candidate or capture schema is promoted, and failed checkpoints
remain excluded from completed-plan totals.

`build/mixed-closure-coverage448-v1` accounts for 448 mixed roots: 285 completed
blocked plans, 163 timeouts and 933 unrequested roots. Across completed plans,
272 expand and 517 initial root/callee gaps now resolve to configured bodies.
The 448-root validation is
`build/mixed-closure-continuation448-validation-20261021.json`.
Production engine fingerprints and test configuration remain unchanged;
the existing production regression evidence is reused. Whole-kernel completeness
and runtime validation remain unproved.

An isolated merge prototype combines AST copying and translation-unit
namespacing in one pass over JSON dict/list/scalar values. The remaining merge
code, including function-reference selection and configured compatibility
checks, is byte-for-byte unchanged. Paired evaluation uses identical fresh AST
objects for three earlier diagnostic roots and a known `fprintf` record
conflict, alternating implementation order. Ten successful merge outputs match
exactly, including metadata; one rejected merge matches the `_IO_FILE` conflict
error. Input hashes remain unchanged after every invocation. Eight existing
program tests and three selected reference-slicing tests pass with the candidate
loaded in process; CLI subprocess checks in the program suite still use the
production engine.

The selected eleven merge calls total approximately 36.57 seconds with the
reference and 19.96 seconds with the candidate, a reference/candidate ratio of
1.83. This is a small diagnostic sample, not a whole-kernel performance or
equivalence guarantee. At this stage the prototype required JSON AST values and
remained isolated from production discovery and accepted coverage. Its source, reference
snapshot, paired comparisons, test logs and independent provenance/accounting
verification are preserved under
`build/mixed-closure-seventh64-v1/diagnostics/merge-clone-prototype-v1`.

The eighth batch, `build/mixed-closure-eighth64-v1`, starts at offset 448 and
records 59 completed blocked plans and five timeouts, with no other worker
errors. Fifty-four completed plans expand and resolve 132 additional initial
root/callee gaps. They record 235 additional read-path and 80 write-path
occurrences, including explicitly marked unknown paths. Six roots retain their
last valid blocked plan after later merges reject incompatible configured
declarations or record layouts. No candidate or capture schema is promoted.

`build/mixed-closure-coverage512-v1` accounts for 512 mixed roots: 344 completed
blocked plans, 168 timeouts and 869 unrequested roots. Across completed plans,
326 expand and 649 initial root/callee gaps now resolve to configured bodies.
`build/mixed-closure-continuation512-validation-20261021.json` seals this result
under the original engine, before the merge optimization. Failed checkpoints
remain excluded from completed-plan totals. Whole-kernel completeness and
runtime validation remain unproved.

The evaluated single-pass clone/namespacing implementation is now the production
merge engine. The exact evaluated candidate replaces only the per-translation-unit
copy/namespacing block; all other analysis modules remain unchanged. New tests
check that mutating merged nested storage cannot mutate parsed inputs, and that
reusing one parsed tree for two translation units keeps IDs and static references
distinct. All six production regression suites pass, comprising 41 cases,
including native capture/replay checks. Three fresh production worker probes
also match the earlier diagnostic results when ignoring only entry-read order.

`build/merge-clone-engine-v1/report.json` records the transition after the first
512 roots. It preserves both engines, original and updated program tests,
regression logs, exact-sample evidence and the complete historical validation
chain. Earlier timeouts are retained. The JSON-AST input contract, configured
record checks, function-reference closure, ABI checks and analysis budgets remain
explicit; the sampled equivalence checks do not prove whole-kernel equivalence.

`build/validate_mixed_continuation_v2.py` requires `--engine-transition` pointing
to that report. It verifies archived engine hashes and all historical artifacts,
requires the original engine before offset 512 and the optimized engine from
offset 512, and records per-engine root totals. Its 512-root migration report,
`build/mixed-closure-continuation512-optimized-validation-20261021.json`, exactly
reproduces the sealed original coverage, completed-plan metrics and limits.
Parity and rejection of repeated batches, unknown engine fingerprints and an
incorrect transition offset are recorded under
`build/mixed-closure-ninth64-v1/diagnostics/transition-validator-checks-v1`.

The ninth batch, `build/mixed-closure-ninth64-v1`, starts at offset 512 under the
optimized engine. All 64 roots complete as blocked plans, with no timeouts or
worker errors. Fifty-five completed plans expand and resolve 140 additional
initial root/callee gaps. They record 345 additional read-path and 298 write-path
occurrences, including explicitly marked unknown paths. Nine roots retain their
last valid blocked plan after a later configured merge conflict. No candidate
or capture schema is promoted. This batch uses different roots from earlier
batches and does not establish a whole-kernel performance improvement.

`build/mixed-closure-coverage576-v1` accounts for 576 mixed roots: 408 completed
blocked plans, 168 timeouts and 805 unrequested roots. Across completed plans,
381 expand and 789 initial root/callee gaps now resolve to configured bodies.
The 576-root validation is
`build/mixed-closure-continuation576-validation-20261021.json`, with 512 roots
attributed to the original engine and 64 to the optimized engine. Failed
checkpoints remain excluded from completed-plan totals;
whole-kernel completeness and runtime validation remain unproved.

The remaining mixed-cohort pass continues under the same optimized engine and
four-unit, 100-context, ten-second budgets, with two workers. Each disjoint batch
is aggregated and validated before the next batch starts. The remaining 805
roots produce 410 completed blocked plans and 395 timeouts, resolving 1,156
additional initial root/callee gaps among completed plans:

| Root offsets, inclusive | Blocked | Timeouts | Resolved initial root/callee gaps |
| --- | ---: | ---: | ---: |
| 576–639 | 37 | 27 | 79 |
| 640–703 | 40 | 24 | 105 |
| 704–767 | 37 | 27 | 109 |
| 768–831 | 49 | 15 | 159 |
| 832–895 | 53 | 11 | 164 |
| 896–959 | 36 | 28 | 89 |
| 960–1023 | 43 | 21 | 79 |
| 1024–1087 | 14 | 50 | 22 |
| 1088–1151 | 27 | 37 | 69 |
| 1152–1215 | 25 | 39 | 72 |
| 1216–1279 | 3 | 61 | 8 |
| 1280–1343 | 11 | 53 | 45 |
| 1344–1380 | 35 | 2 | 156 |

`build/mixed-closure-coverage1381-v1` now accounts for every mixed-cohort root:
1,381 requested, 818 completed blocked plans, 563 timeouts and zero unrequested
roots. There are no analysis candidates or accepted capture schemas in this
cohort. Across completed plans, 762 expand and 1,945 initial root/callee gaps now
resolve to configured bodies. Additional symbolic path occurrences total 9,312
reads and 4,279 writes, including 1,207 reads and 1,824 writes with explicit
unknown markers; these counts are not accepted replay state. Failed expansion
checkpoints remain excluded from the completed-plan totals.

Current validation is
`build/mixed-closure-continuation1381-validation-20261021.json`. It retains 512
roots attributed to the original engine and 869 to the optimized engine, with
the full predecessor artifact chain and compiler/source/header identities
checked. The completion driver, per-batch logs and progress records are archived
under `build/mixed-closure-offset1344-v1/diagnostics/cohort-completion`. Production
code and test configuration are unchanged during this pass; the six-suite,
41-case engine-transition regression evidence is reused. The requested cohort
is exhausted, but timeouts, remaining blockers and resource limits still prevent
a complete whole-kernel state or runtime claim.

`build/whole-kernel-closure-accounting-v1/report.json` reconciles all 2,897
recorded primary C roots: the 507 historical missing-body-only closure roots,
the 1,381 mixed closure roots, and 1,009 roots retaining their baseline results.
The resulting recorded statuses are 1,772 blocked, 670 failed and 455 analysis
candidates. These combine historical engine versions and baseline evidence;
they are not a fresh whole-kernel reanalysis. Missing historical engine
fingerprints remain explicitly missing. The 17 assembly objects and the one
unparsed C unit remain outside analyzed C-root coverage.

The accounting separately flags candidates with explicit unknown paths. The
retained baseline candidate `__year_to_secs` contains `*(unresolved:alias)` and
already has a rejected capture schema. Its recorded candidate label is retained
for provenance and does not establish resolved state or replay eligibility.
The accounting verifier checks the root partition, evidence hashes, status
totals, engine attribution and retained failures. Remaining work includes the
563 mixed-cohort timeouts and unresolved body, memory-origin, dynamic-extent
and architecture blockers; this pass introduces no boundary models or native
kernel replay promotions.

### GNU statement expressions and expression-result aliases

The analyzer now supports scalar and pointer results from GNU statement
expressions, `({ statements; value; })`. It visits the complete compound body
for may-effects and resolves the final expression with a separate local alias
environment, using the existing bounded flow-insensitive alias closure. Clang
declaration IDs preserve nested and shadowed scopes. Comma expressions return
their right operand's aliases, and simple assignment expressions return their
assigned value's aliases; both operands' effects remain visited. This follows
the [GNU statement-expression value rule](https://gcc.gnu.org/onlinedocs/gcc/Statement-Exprs.html).

That validation retained blockers for assembly, atomics, jumps and varargs.
Statement expressions with cleanup attributes, nonautomatic local storage,
variably modified types, or aggregate/array results also remain blocked because
their implicit effects or storage semantics need additional analysis. The
structured must-store pass treats statement expressions as impure and does not
derive guaranteed exit overwrites from them: a nested early return can bypass
later stores. This may preserve extra entry state.

Memory accesses now check unknown origins beneath dereference wrappers. Paths
such as `*(null)` and `*(unresolved:alias)` produce origin blockers instead of
being retained as resolved reads or writes. The check distinguishes actual
origin positions from valid fields, globals or providers named `null`.

The validation in `build/c-constructs-validation-20261021.json` records 17 passed
regression suites comprising 91 cases. New coverage includes nested statement
expressions, shadowed locals, comma/assignment results, finite callback targets,
native snapshot capture, rejection of implicit effects, and early-return
preservation. Existing capture/replay and range-analysis regressions also pass.
Seven selected configured kernel roots are analyzed by both engines on identical
ASTs and source/header/compiler identities. Four roots lose six unsupported
construct occurrences in total. `HalClockGetCycles` loses its statement-expression
blocker while retaining its architecture blocker; goto sites in
`FindSuitableStack` remained unsupported in that comparison. All seven sample
plans remained blocked and none gained a capture schema. Removed symbolic access paths contain
explicit null or unresolved markers.

The fresh `__year_to_secs` sample is now blocked on unresolved pointer origins;
its historical baseline candidate label remains in the immutable accounting
report. `build/c-constructs-v1` preserves both engines, tests, plans and identity
evidence. The 1,381-root cohort and 2,897-root accounting above remain historical
results; this feature validation does not reanalyze the whole kernel, replace
earlier timeouts, add boundary models or promote native kernel replay.

### Direct goto and labeled exits

Direct `goto` now participates in the configured-AST may-access closure. The
analyzer checks that each target label belongs to the available function body,
visits every syntactic statement (including skipped statements and statements
after returns), and retains the bounded flow-insensitive pointer alias closure.
Forward exits, backward jumps, helper functions, and jumps out of statement
expressions use this same conservative union. No reachability, iteration count,
termination, or execution-order proof follows from that union.

Functions containing labels or jumps receive no structured must-store read
omissions or guaranteed exit-store omissions. Eligible written fields therefore
retain their entry-state preservation requirements. Counted-loop range proofs
continue rejecting labels and jumps in the loop condition/body. Label IDs and
direct jump target IDs are namespaced together when combining translation units.

Computed goto and label-address expressions remain unsupported. A function
with a direct jump also remains blocked if it contains cleanup attributes,
nonautomatic local storage, or variably modified types: the jump extension does
not model their implicit lifetime, storage, or bound-evaluation effects.

`build/direct-goto-validation-20261021.json` records the regression and paired
kernel validation, with both engines preserved under `build/direct-goto-v1`.
The seven configured kernel samples retain identical read/write paths between
engines. `FindSuitableStack` loses its three direct-goto blockers, while its
remaining memory, address, architecture, and external-call blockers persist.
All seven sample plans remain blocked. The earlier whole-kernel cohort counts
and replay acceptance scope remain unchanged.

### Unsigned counters with any start

A canonical counted loop needs a known start, except for an `unsigned int`
counter whose start reads a variable:

```c
for(unsigned i=(unsigned)length;i<64;++i)ctx->file_data.bytes[i]=0;
```

The counter is never negative. A start at or above the limit runs no
iteration, and below a limit of at most 2^31, `++` cannot wrap. So inside the
body `i` lies in `[0, limit)`. The proof records the start as
`unsigned_counter_any_start`. A signed counter with an unknown start stays
blocked. Constant starts keep the constant rules, so a start that wraps or
narrows, such as `0xffffffffU+1U` or `(unsigned char)256`, is still rejected.

Merged translation units compare function declarations by type, not by spelling.
Typedef names are expanded per unit. A `bool` that no typedef names is `_Bool`,
because Clang prints C's `_Bool` either way. Different types still reject the
merge.

### Fixed multidimensional arrays

Configured fixed arrays now support nested subscripts on inline members,
top-level globals, and private automatic storage. Each subscript must retain an
actual Clang array decay and independently prove its own dimension's bound.
The first extent of `unsigned values[2][4]` is two, not four; a valid inner
extent cannot justify an invalid outer index. Pointer-to-array variables,
pointer casts, incomplete arrays and unproved variable bounds still block
discovery. Nested selections are capped before Cartesian expansion by the
configured range limit, including the selected base paths.

Constant indices, unsigned masks/remainders, typedef array shapes, and existing
counted-loop proofs compose across dimensions. Private automatic arrays retain
their local storage identity while all initializer effects are visited. Global
paths remain discovery-only because snapshot generation still requires explicit
object-provider or argument bindings. Qualifier checks follow nested subscripts
back to their original member, retaining const, volatile and atomic restrictions.

Bound scalar cells use paths such as `state()->values[1][3]` through capture,
snapshot validation and reconstruction. The existing explicit isolation
contracts govern typed-store omissions and partial-write entry preservation.
No pointer, aggregate, concurrency or lifetime restriction is relaxed.

`build/multidimensional-arrays-validation-20261021.json` records 18 passed suites
and 101 tests. The new matrix fixture captures native calls, replays independent
and continuous sessions at two AArch64 load addresses, and rejects a missing
entry cell and an omitted target store. Ten same-AST kernel comparisons retain
the same read/write paths and blocker counts. In particular, the dynamic indices
in `OsGetHwiFormCnt` and `GetMonthDayFromString`, and the local static storage in
`OsArchFlagsToStr`, remain unresolved. All ten sample plans remain blocked;
whole-kernel discovery counts and native kernel replay acceptance are unchanged.

### Compile-time generic and choice expressions

The analyzer now follows Clang's selected association for C11 `_Generic` and
its folded condition for GNU `__builtin_choose_expr`. These constructs preserve
the selected expression's lvalue or pointer result. Loads, assignments,
compound updates, callback targets, helper return aliases and supported constant
index expressions therefore use the selected operand's actual storage path.
The controlling expression and discarded alternatives contribute no runtime
effects or pointer assignments. This follows the generic-selection rules in
[C11 draft N1570, section 6.5.1.1](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf)
and the [GNU choice-expression rules](https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html).

This also fixes missed reads: previously, a load through a selected lvalue could
produce an empty candidate footprint. Two isolated same-AST fixture comparisons
now retain `current()->value` for those loads. Three further fixtures resolve
selected writes and pointer results, and exclude calls in unevaluated operands.
The previous and current engines run in separate interpreters with their own
archived helper modules; compressed AST inputs and engine hashes are retained.

Missing or ambiguous selection metadata blocks export. Selected unknown calls,
null origins, assembly and other unsupported effects retain their blockers.
Functions using selections conservatively exclude implicit cleanup,
nonautomatic local storage and variably modified types in evaluated code;
discarded alternatives do not trigger those exclusions. A selected statement
expression with an early return still prevents exit-store guarantees. Structural
definition/reference indexing remains conservative and can retain unused bodies.
No runtime branch feasibility, arbitrary type compatibility or VLA evaluation
model is inferred by this extension.

`build/compile-time-selection-validation-20261021.json` records the final tests,
isolated engine comparisons and native-to-AArch64 fixture replay. Ten configured
kernel comparisons retain their prior read/write paths and blocker counts; all
remain blocked. Whole-kernel counts and native kernel replay acceptance are
unchanged. Earlier focused and pre-hardening runs are retained as diagnostics;
the validation report identifies the accepted final artifacts.

### Fixed global-array storage

The initial global-array extension resolved one-dimensional fixed arrays when the configured
Clang AST contains an actual array-to-pointer decay of a top-level declaration.
Reads and writes use element paths such as `global:values[3]`; merged programs
retain the existing translation-unit names for static globals. Constant indexes,
unsigned masks/remainders and certified counted-loop intervals use the same
bounds and expansion-limit checks as member arrays. Record elements can supply
field paths, and volatile accesses retain their blocker.

Pointer parameters, pointer aliases, pointer casts, incomplete arrays, static local
arrays and multidimensional global arrays did not acquire storage bounds from
that initial rule. A discovered global path also does not supply an object-provider
binding: capture of these reads or post-state fields is rejected by the current
provider-only snapshot generator. Discovery candidates and entry-only schema
acceptance remain separate from complete effect capture and replay eligibility.

The configured reanalysis in `build/global-array-kernel-survey-v1` uses the same
623 compilation commands and matches all 2,897 primary roots and 960 source/header
hashes from the frozen baseline. It retains 622 parsed units and one parse
failure. Results are 412 analysis candidates, 2,431 blocked roots and 54 timeouts;
51 timeouts persist from the baseline and three formerly blocked roots time out
in this run. Failures remain unknown.

Among the 2,843 roots completed by both runs, 21 gain 115 read-path entries and
212 write-path entries, with no previously discovered paths removed. These
totals include capture instrumentation as well as kernel and library sources.
Newly resolved kernel state includes `g_mainTask[0].processCB`, two fields of
`g_physArea[0]`, and entries in the syscall dispatch tables. Three roots lose
their last analysis blocker: `OsSetMainTaskProcess`, `OsVmPhysAreaSizeAdjust`,
and the library helper `__tandf`. Their global state still lacks replay bindings;
an empty entry schema for a write-only root is not effect-capture acceptance.
Nine targeted regression suites pass, including four global-array cases and
existing native fixture replay tests. The validation report
`build/global-array-discovery-validation-20261021.json` records input/artifact
hashes, paired-completed comparisons and old/new engine checks on identical
fresh configured ASTs. This reanalysis keeps the earlier cross-file cohort
reports separate and does not reanalyze the baseline's 17 assembly objects.

### Constant array indexes

Configured fixed arrays also admit indexes expressed as enum constants or pure
portable `int`/`unsigned int` arithmetic. This reuses the loop-bound constant
evaluator: every intermediate operation and implicit conversion must fit its
32-bit type, division follows C99 truncation, and shifts and bitwise operations
retain the existing portability restrictions. Constant evaluation has a 64-node
budget. Explicit casts, mutable or `const` variables, assignments, comma and
conditional expressions do not become constant proofs.

Unsigned remainder and mask intervals can use these constant expressions as
their right operand. The runtime left operand retains its reads, writes and
call blockers. Each new range records its constant value, type and proof kind;
ordinary array extent and range-expansion checks still apply. Previously
accepted literal indexes and intervals retain their existing representation.
This rule supplies an index bound, leaving pointer origins, object contracts,
storage extents and capture/replay requirements unchanged.

The same-command reanalysis in `build/constant-index-kernel-survey-v1` matches
all 2,897 primary roots and 960 source/header hashes from the prior global-array
scan. It reports 417 analysis candidates, 2,420 blocked roots and 60 timeouts,
with the existing source parse failure retained. All 54 prior root timeouts
persist; six formerly blocked roots time out in this run and remain unknown.

Among 2,837 roots completed by both runs, 21 gain 184 read-path entries and
159 write-path entries, without removing previously discovered paths. Additions
include page-list state, console and task fields, syscall argument-table slots,
and library lookup-table elements. Five page-list helpers clear their last
analysis blocker, but none gains snapshot-schema acceptance. Capture and replay
bindings remain required.

Some new intervals still exceed the configured element-expansion limit
(32 roots) or the array extent (two roots). In particular, a queue-ID mask gives
an interval larger than the configured queue table; this is not proof of an
out-of-bounds execution. These plans retain blockers. Twelve targeted CTest
suites pass, including five focused index tests with native capture and
AArch64 ELF/raw replay. `build/constant-index-discovery-validation-20261021.json`
records hashes, paired-completed comparisons and old/new engine checks on
identical fresh configured ASTs. Earlier closure-cohort results and the 17
assembly objects are not reanalyzed by this scan.

### Automatic arrays and initializer effects

Fixed one-dimensional automatic arrays now keep a local storage identity through
a direct array decay. Proven element reads and writes stay within the current
invocation rather than becoming incoming snapshot fields. Initializers and index
expressions still contribute their external reads, writes and calls. Constant,
mask/remainder and counted-loop bounds use the existing extent and expansion
checks. Pointer aliases and parameters do not borrow an array's extent.

Static local, thread-local, register, cleanup-managed and unbounded arrays remain
outside this rule. Volatile and atomic accesses retain blockers, including
qualifiers hidden behind typedefs and volatile members of local record arrays.
Pointer elements or pointer members whose origins are unresolved also retain
their blockers. This does not prove initialization, escape safety or arbitrary
local pointer provenance.

Clang's `InitListExpr.array_filler` entries are now traversed alongside ordinary
children. This preserves effects from partially filled array initializers and
retains their referenced functions during call-closure slicing. The default
implicit initializer contributes no external state. A separate type check
restricted that implementation to one dimension: a member array such as
`unsigned values[2][4]` cannot incorrectly use its final dimension as its outer
bound. Multidimensional arrays remained unsupported in that validation.

The accepted configured reanalysis is `build/automatic-array-kernel-survey-v2`.
It matches all 2,897 primary roots and 960 source/header hashes from the previous
scan: 417 analysis candidates, 2,426 blocked roots and 54 timeouts, plus the
existing source parse failure. Among 2,837 roots completed by both runs, 18 have
fewer memory blockers: 87 dynamic-extent and 87 unresolved-memory blocker entries
are removed. These include private buffers in syscall adapters, timezone code,
floating-point parsing, trigonometric helpers and stdio. Other blockers remain
for all 18 roots. No new external-state paths, callees, candidates or snapshot
schemas are claimed. Six prior timeouts complete as blocked plans in this run;
this timing variation does not establish an analysis or runtime speedup.

Seventeen targeted CTest suites pass, including seven focused tests with native
capture and AArch64 ELF/raw replay using private scratch arrays. Partial
initializer reads and calls, function-reference slicing, hidden qualifiers,
local/global name separation and the multidimensional extent guard are covered.
The validation report `build/automatic-array-discovery-validation-20261021.json`
records isolated old/new engine checks on identical fresh ASTs. All seven prior
analysis modules are preserved, and the analyses run in separate processes so
each uses its corresponding traversal and imported helpers.
The earlier `automatic-array-kernel-survey-v1` is explicitly preliminary and not
accepted, because subsequent tests exposed typedef-hidden volatile/atomic and
volatile-record-member cases. Existing assembly and cross-file cohort reports
remain separate.

### Constant hook lists, jumps and loop counters (2026-10-31)

The Linux `fd-control` slice now runs original kernel code for:
- the LSM hook walks;
- the descriptor bit search;
- `alloc_fd`'s retry loop;
- the uid/gid extent search.

Each needed one more proof.

**Constant address graphs** (`entry_state_const_graph.py`). A const global defined
once with an initializer cannot change at run time. When one of its pointer
members is initialized with an address constant (`&G.m[i]`, possibly converted),
a function or a null pointer, a load of that member yields exactly that value.
A walk over such a table therefore resolves to the table's own elements. Reads
of its members carry `defined_const_initializer_leaf` evidence (object, path,
type, initializer and its hash). `fixed_global_read` validates that evidence and
removes those reads from the entry state, as it does for numeric constants.
Paths into const objects are spelled canonically: `->` after an object of
record type is that record's member.

**`container_of`.** `(char *)p - offsetof(T, m)` resolves to an object when
every value of `p` is the address of member `m` of an object whose declared
record type is `T`. Clang's JSON dump omits an `OffsetOfExpr`'s designator.
`entry_state_offsetof.py` reads it from the configured compiler's own libclang
and attaches it by source position and order. An `offsetof` that cannot be
matched stays unannotated and keeps its `pointer_arithmetic` blocker, as does a
`container_of` on a mutable pointer or with a mismatched member or record. Each
resolution is listed under `container_proofs`.

**Loop conditions as facts.** In a `for` loop's body and increment, the loop
condition holds when nothing between its evaluation and the use stores its
variables. The whole body counts for the increment, since `continue` reaches
it. A pointer assigned in the loop initializer is never read uninitialized
inside the loop.

**Definite assignment across jumps.** A local is initialized at a use when a
plain assignment precedes it in an enclosing block. Each label on the way back
is reached by falling through or by a `goto`, and every such `goto` must itself
follow an assignment; a `goto` reached again through the same label adds no
new entry path. A case label inherits the definitions that precede its
`switch`. `label: x = v;` reaches later uses even when the label is a retry
target.

**Intervals over several assignments.** When a local has no unique reaching
definition, its interval is the union of the values of all its assignments,
each evaluated where it is assigned. Assignments that read the variable itself
(`i++`) must map that union back into itself, assuming it holds before them,
or the union is not used. A guard such as `(idx + 1) * 64 >= sz` is solved for
`idx` when no intermediate value can wrap. An update whose guards contradict
the assumed interval never runs. Comparisons whose operand intervals decide
them fold to 0 or 1, and a conditional with a decided condition takes one arm.
The interval depth limit rose from 6 to 12 and the node budget from 512 to 8192.

**Smaller changes.**
- `p->m` through a bounded pointer to a record element is member `m` of that
  element.
- A structured definite-initialization proof now also accepts null alongside
  bounded array pointers.
- The per-access element limit counts each array separately; the alias limit
  bounds how many arrays.

On the `fd-control` slice, the footprint blockers changed as follows:
- **`fcntl`:** 36 to 6. The remaining three accesses index the close-on-exec
  bitmap with the raw syscall `fd`, whose bound follows only from `fdget`
  having succeeded. They predate this change.
- **`ftruncate`:** 309 to 292, the count of the slice before the new code. It
  needs `--max-alias-paths 1024`, because the uid map's 5 extents multiply the
  64 descriptor slots. All remaining blockers are in shmem, folio and xarray
  code.
- **`pread64`:** about 50 new blockers remain in the user-copy chain. The copy
  reads the kernel buffer at `kaddr + offset + progress`, which needs a
  relational bound on the offset and the file size.

`tests/test_entry_state_hook_lists.py` covers the hook walk and its rejected
variants, the goto retry, the inductive counter and its unguarded variants, and
`switch` dominance.

Some loops that the older tests required to stay blocked are now proven:
- Loops outside the induction certificates now have path-fact bounds: wide
  or cast bounds, `i+0U`, `(count*0U+7U)>=i`, `i+=2`, a counter declared
  before its loop, wrapped constant starts that equal 0, and nested `i+j`.
- Indexes that leave the array (`i*i`, `i<<1`, `(unsigned)i+1U`) now report
  `array_bounds` instead of an unproven extent.
- Zero-trip loops (a bound of 0, or `i>=7` from 0) keep may-accesses inside
  the array.

Each changed case was checked against C's semantics. The affine-index,
constant-expression, comparison, constant-bound, enum-operator, guarded-loop
and loop tests now assert these results.

### Derived pointers, checked spans and decided branches (2026-11-02)

The original Linux user-copy chain (`copy_page_to_iter`, `_copy_to_iter`,
`iterate_and_advance`, `copy_to_user_iter`, `raw_copy_to_user`) needed three
more rules.

**Derived pointers.** `p + n` or `p - n` where `n`'s bound cannot be proven no
longer blocks where it is formed. It yields a `derived-pointer` value that
records the array or object `p` points into. `p++`, `p--`, `p += n` and
`p -= n` on a local pointer produce the same value; `++p` evaluates to it and
`p++` to the previous value.

Every use that could touch memory still blocks:
- a dereference (`dynamic_extent`: "dereference of a derived pointer");
- a store into non-automatic memory or an aggregate initializer;
- a return from the root;
- a boundary argument other than a checked span.

Comparisons and differences of derived pointers access no memory; a difference
is an integer of unknown value. A value loaded through a derived pointer is
unresolved. An offset that is proven stays with the bounded-pointer rules, so
a proven out-of-bounds formation such as `a - 1` still reports
`pointer_arithmetic`. Bounded pointers through a record element now resolve
`p->m` to that element's member.

**Checked spans.** A `memory_model` boundary may list `spans`:
`{pointer, length, access, objects}`. Such a span is a contract that the model
fails at run time unless `[pointer, pointer + length)` lies inside one of the
listed objects. Each value of the pointer argument then selects as follows:
- **Derived from, or pointing into, a listed array:** the whole array is read
  or written.
- **Known origin that isn't listed:** the call never completes, so the value
  contributes nothing.
- **Unknown origin:** blocks unless every listed object is already reached.

Each use is recorded in `checked_span_proofs`. In the `fd-control` slice:
- `__arch_copy_to_user` lists `file_data.bytes` and the zero page's bytes.
- `__arch_copy_from_user` lists `file_data.bytes` only.
- `page_span` in `models.c` now fails on any pointer outside the listed
  objects. Before, it checked only spans that started inside them.

**Decided branches.** An `if` or `?:` whose condition the interval evaluator
decides in the current call context visits only the taken arm. When that arm
always leaves the block, the statements after it are skipped too, unless a
label or case can enter them. Each decision is listed in
`decided_branch_proofs` with its evidence.

To decide `iter_is_ubuf(iter)`, the evaluator gained:
- **Integer fields of automatic records:** the union of every write is
  recorded. That includes a whole-object store such as
  `*i = (struct iov_iter){.iter_type = ITER_UBUF, ...}`. Increments, compound
  updates and escapes to unanalyzed code make the field unknown. A read uses
  the union only where a write dominates it, as for pointer fields.
- **Pointer context:** the evaluator reads such fields through the pointer
  values of the current call, and carries pointer arguments into callees.
- **Operators and types:** `__builtin_expect` is transparent. `!` and
  decidable comparisons fold. Enumerated types evaluate in a range that holds
  both `int` and `unsigned int`.

A lone `static const` object with no initializer is a tentative definition:
zero-filled and immutable, so its elements carry constant evidence.

On the `fd-control` slice:

| Call | Blockers before | Blockers after |
|---|---|---|
| `pread64` | 232 | 180 |
| `pwrite64` | timed out at 1 h | 174 |
| `fcntl` | 6 | 6 |

The user-copy chain has no blockers left. The remaining ones are in folio,
xarray and shmem code: error pointers, tagged xarray entries, and the
`XAS_RESTART`/NULL states of `xa_node`, which the flow-insensitive
automatic-record store merges. Some are also the 500-context limit.

`tests/test_entry_state_checked_spans.py` covers:
- checked spans: selected, rejected and unknown origins, writes, and contract
  validation;
- blocked uses of derived pointers;
- decided branches, including the cases that must stay undecided.

Tests that expected pointer mutations or unproven formations to block at the
formation now assert where the derived value blocks instead: in the local
effects, GNU conditional, kernel idiom, pointer arithmetic and hook-list tests.
A zero step (`p += 0`) is proven.

### Flow-sensitive values and path correlations (2026-11-03)

The page cache (`filemap_get_entry`, `xas_load`, `shmem_get_folio_gfp`,
`__mark_inode_dirty`) keeps state in stack objects whose values change along a
path. Two examples are `XA_STATE`'s `xa_node` (`XAS_RESTART`, then NULL or a
node) and a folio returned through `&folio`. A union over every write cannot
separate these states. The analyzer now follows them in visit order.

**Pointer values.** An integer converted to a pointer is a value, not an
object: `const-address:N` for a constant, `error-pointer` for the ERR_PTR
range. The interval evaluator gives each pointer an integer view: null is 0;
objects lie in `[4096, top-4097]`, aligned as a `pointer_values` contract
says; error pointers lie in the top 4095 values. Through these views it decides
`&` masks, `==`/`!=` with constants, `!`, `&&`/`||` and `xa_is_node`-style
tag tests.

**Flow state.** These values are tracked along the visited path:
- fields of automatic records;
- pointer locals whose address escapes (each a one-field object);
- integer locals.

The state is kept as follows:
- **Branches:** each arm starts from the condition's refined state, and the
  arms join.
- **Labels:** a label joins the states of the gotos that reach it.
- **Loops:** a loop drops what its body can carry across iterations.
- **Calls:** a call joins its callee's return states. A call with several
  possible targets joins one state per target.
- **Unknown keys:** a key with no flow value falls back to the union of every
  write.

`analyze()` repeats whole-root passes, up to 10 optimistic and then up to 5
conservative. Each optimistic pass carries the previous pass's unreachable
regions, goto states and stack-object writes. A converged result solves the
analysis equations. Without convergence the root is analyzed again with nothing
carried, and failing that it reports `analysis_limit`.

While a callee's aliases are resolved out of order, flow values stay visible
for every field the callee and its callees never store. A store through a
non-member lvalue, or an unknown callee, hides them all. Before this, any
callee that wrote memory, such as a model setting `ctx->model_fault`, hid them
all.

**Return partitions.** A call's return states are also kept split by the sign
of the returned value: negative, zero (null), or positive (non-null). The split
applies to:
- `if (f(...))` or `if (!f(...))` directly;
- a local assigned from the call, at a later test against zero: truth,
  `==`/`!=`, `<`, `<=`, `>`, `>=`, either way round;
- `return v` or `return f(...)`, which pass the split to the caller.

A test also narrows the local's own split, so `if (ret) return ret;` returns
only the non-zero states. `if (status < 0) break;` in `generic_perform_write`
keeps the success states of `write_begin`, where the page is stored.

A split applies to a key only while the flow still holds the very value
object the call produced. Any later store makes a new object. An
`XAS_BOUNDS` from `xas_start` only comes with a NULL entry, so the
`folio != xas_reload(&xas)` reached after `if (!folio) goto out` no longer
sees it.

**Correlated stores.** A pointer local `p` is proven non-null at a read when
all of these hold:
- `p` starts null, and one statement stores it, unconditionally in the arm of
  an earlier `if (C)`;
- the read has the same guard `C` with the same truth;
- `C` reads only unescaped locals that nothing stores in between;
- the earlier `if` precedes the read's statement in one block, with no label
  or case between them.

For example, `__mark_inode_dirty`'s `wb` is proven non-null under its second
`if (!was_dirty)`. Each use is listed in `null_guard_proofs` as
`correlated_store_guard`.

**Value splits.** At a condition over an escaped pointer local, each value
class is tried alone: null, the error range, each constant address, and
objects. A class is dropped from the arm when the condition is decided against
it. `IS_ERR(folio)` keeps only error pointers in its true arm and only objects
in its false arm.

**Data models.** The portable evaluator treats `long` as at least 32 bits, so
a 64-bit pointer view does not fit it. When an integer view of a pointer leaves
a value undecided, the evaluator repeats it under ILP32 and under LP64. Each
run uses that model's exact `long` width, modular conversion to unsigned types,
and that pointer width. It keeps the hull of the two results, which holds on
both targets. `(uintptr_t)p >= (uintptr_t)-MAX_ERRNO` is false for an object
address under both. A comparison that only one model decides stays undecided.

**Pointer equality.** `==`/`!=` with an array-element pointer is admitted when
the result is address-independent:
- one side is a constant (null, constant address, error range, function);
- both sides are the same path;
- both sides are storage the replay does not rebuild (automatic objects or
  named globals).

Two reconstructed objects compare alike only if the replay preserves their
identity. A profile states that with a `pointer_identity` contract (`reason`,
`implementation`). `fd-control` declares it: its replay binds every pointer to
the pool or class object recorded in the live state. Each comparison is listed
in `pointer_comparison_proofs` with its `identity`.

**Element-address stores.** Storing `&array[k]` of a non-automatic array is
storing an ordinary object address when every `k` is in range. Examples are
`xa_head = &ctx->folio_pool[0]` and `p->head = &p->items[n % 2]`. A later load
carries no array provenance, so arithmetic on it stays unproven. One-past and
automatic arrays still block. Each store is listed in `pointer_store_proofs`.

**User addresses.** A `user_addresses` contract names root parameters that hold
user-space addresses (`function`, `parameter`, `reason`, `validated_by`).
`fd-control` names `buf` of `pread64` and `pwrite64`. Such a parameter's value
is `user:NAME`: the exact address the caller passed, never a kernel object.
- `u + n`, `u - n`, `p++`/`p += n` keep the user value.
- `u - v` between user values is an integer.
- `(unsigned long)u` with integer arithmetic (`PAGE_ALIGN`) and a cast back
  keeps it too, as long as no operand carries a kernel pointer.
- A user value has no integer view, so it decides no condition, and it may be
  null.
- Kernel code dereferencing it blocks ("user address dereferenced outside a
  user-memory boundary"). Only boundaries may touch user memory.

Each use is listed in `user_address_proofs`. `fault_in_readable`'s page
stepping and `uaddr - start` need this.

**Boundary writes into locals.** A memory-model boundary whose declared
`writes` argument is the address of the caller's own volatile scalar local
writes live automatic storage, which is no kernel state. Other scalar locals
keep their scalar-address `memory_ranges`. `linux_get_user_byte`, the model
behind `unsafe_get_user`, is now such a boundary (`writes: [2]`).

**Discarded volatile scalars.** A volatile automatic scalar qualifies when each
of its uses is one of:
- a store;
- a read whose value is discarded (`(void)c`);
- its address as a declared boundary write argument.

Its value, even an indeterminate one, never reaches a computation, whatever
jumps the function has. Each one is listed in `local_volatile_storage_proofs`
as `discarded_volatile_scalar`. `fault_in_readable`'s `volatile char c`
qualifies.

**Loop-body objects.** An object declared in a loop body starts a new lifetime
on every iteration, with or without an initializer, so its flow values are not
carried across iterations. A `for`-init declaration runs once and is carried.
Before, `generic_perform_write`'s `struct page *page` lost every stored value
inside the loop.

**Null-replacing stores.** A read of `p` is non-null when, earlier in its block,
`if (!p) p = E;` stores a non-null `E` unconditionally and nothing stores `p`
or enters the block in between. `balance_dirty_pages_ratelimited`'s `wb` uses
this. Each use is listed in `null_guard_proofs` as `null_replaced_before_use`.

**Escaped pointer steps.** `p++` or `p += n` on an escaped pointer local
updates its stored value. In a loop, or in a function with labels, the value
becomes unresolved. Before, the stored value kept the pointer's first element.

**Budgets.** `entry_state.py --max-contexts` sets the call-context budget.
`reduced_boundary_replay.py` passes 4000 contexts and 1024 alias paths.

On the `fd-control` slice:

| Call | Before (2026-11-02) | After |
|---|---|---|
| `pread64` | 180 | 0 |
| `pwrite64` | 174 | 0 |
| `fcntl` | 6 | 6 |
| `ftruncate` | 292 | 360 |

ftruncate's stack-object values do not converge in 5 passes (`analysis_limit`).
Its count is the conservative fallback's: `shmem_undo_range` and the folio
batch loops of truncation.

Both footprints pass the reduced replay's blocker check (observations
`observe-pread` and `observe-pwrite`). Both then stop at the binding check:
discovered reads that `live-binding.json` does not supply. pread64 has 46 and
pwrite64 has 48:
- inode timestamps, ids, state, lock and version;
- `user_ns` id maps;
- superblock flags and time limits;
- `tk_core`, the clock read for timestamps;
- the ops classes (`fop_pool`, `aops_pool`, `iop_pool`, `super_ops`);
- mount flags;
- the inode's writeback structure;
- for pwrite64, also the dirty-throttling state (`bdp_ratelimits`,
  `ratelimit_pages`, `task.nr_dirtied`).

The timestamp update (`touch_atime`, `file_update_time`,
`inode_update_time`, `__mark_inode_dirty`) and the page cache reach them.

fcntl's six are the raw-descriptor `close_on_exec` bitmap index.

`tests/test_entry_state_flow.py` covers the following, each with the cases
that must stay blocked:
- return partitions;
- field-aware callee regions;
- correlated stores;
- value splits under both data models;
- element-address stores;
- escaped pointer steps;
- several callback targets;
- user addresses, boundary writes into locals and discarded volatile
  scalars;
- sign tests on returned values, loop-body objects and null-replacing
  stores.

Updated expectations now assert the more precise result:
- `goto` dead code, conditions false on loop entry, and a guard decided on a
  null-only pointer are pruned;
- address-independent comparisons are admitted;
- reconstructed-object comparisons need the identity contract.

## Run the live pipeline

The prepared LiteOS demo supports generated snapshot instrumentation:

```sh
python3 tools/liteos_qemu_demo.py --automated-entry-state --out build/live-auto-state
```

The pipeline recovers compiler arguments from module-level `make -n`, parses
the real process syscall and VFS translation units, and generates six plans
and a capture header. It builds those hooks into the live kernel. Fourteen entry
snapshots are collected: six umask, four effective credential and four parent/task
queries. Existing capture/replay validations continue to run. Output includes:

- `entry-state-plan.json`: discovered fields, types, call paths, writes,
  boundary contracts, blockers, compiler flags and source/header hashes.
- `entry-state-capture.h`: generated typed snapshot hooks.
- `entry-state-snapshots.json`: live normalized object graphs and scalar values.
- `report.json`: kernel/image and capture provenance, plus existing validations.

The process-priority plan has no object fields because both of its dependencies
are explicitly cut at recorded scalar boundaries. Those existing boundary
wrappers still record their argument/results; the new generator handles object
field snapshots, not automatic implementation of arbitrary dependency models.

The generated hooks run inside the capture adapter's real scheduler locks.
They call stable current-object providers, copy discovered scalar fields, and
register discovered pointer edges. Hooks are construction-time instrumentation,
not delivery-image code. Parent/task AArch64 images can reconstruct these
snapshots directly using the option below, with no runtime host interaction.

## Analyze another C root

For a source present in a Clang compilation database:

```sh
python3 tools/entry_state.py \
  --compile-commands build/entry-state/process_commands.json \
  --source build/ohos/kernel/liteos_a/syscall/process_syscall.c \
  --root SysGetPPID \
  --boundaries integrations/liteos_a/entry-state-boundaries.json \
  --out build/entry-state/ppid-plan.json \
  --capture-header build/entry-state/ppid-capture.h
```

`--root` may be repeated. Omit `--capture-header` to inspect an analysis with
unresolved effects. Clang compilation must succeed; the tool does not substitute
stubs for missing kernel types or configuration headers. `prepare_entry_state.py`
can recover a command from the managed LiteOS tree, and `automated_entry_state.py`
can generate the current six-root bundle without booting:

```sh
python3 tools/prepare_entry_state.py --out build/entry-state/process_commands.json
python3 tools/automated_entry_state.py --out build/entry-state/generated
```

## What the analysis reports

For example, the original non-container `SysGetPPID` body produces:

| Discovered path | Role |
| --- | --- |
| `OsCurrProcessGet()->parentProcess` | Pointer edge |
| `OsCurrProcessGet()->parentProcess->processID` | Scalar read |

The generator binds the current process, registers the parent as another logical
object, then captures its PID. A null edge becomes object ID zero; guarded
snapshot code skips dereferencing it. Aliases and cycles reuse the same ID.
`SysGetTid` yields `taskID`; credential getters yield `effUserID` and `effGid`.
`SysUmask` yields a read and a write of `umask`.

Analysis follows direct calls with pointer-argument bindings and local aliases.
It retains both runtime branch arms and loop bodies. Preprocessor branches are
selected by the real compiler arguments; changes in configuration or headers
are recorded in the analysis identity. Reads after writes remain candidates:
this is a conservative may-access footprint, not a proof of the smallest entry
checkpoint or of read-before-write dominance.

Object-provider boundaries require an explicit `snapshot_safe: true` contract.
The caller must establish the required locking/lifetime context. Scalar
transcript boundaries cannot silently accept pointer arguments; such arguments
require a memory-effect model. Reviewed boundaries stop transitive analysis,
so changing the boundary policy changes the required state.

## Normalization and limits

`runtime/entry_snapshot.c` maintains a temporary address-to-ID table. Serialized
records contain only object IDs, type names, root bindings, scalar bytes and
reference IDs. The temporary address table must never be dumped as a checkpoint.
Pointer fields are recorded as edges, never copied as scalar bytes. Storage is
bounded; overflow and conflicting duplicate fields fail the snapshot. Null
references and repeated references preserve their identity. Capture metadata
uses little-endian ARMv7 scalar bytes; it is not an AArch64 memory-layout dump.

The supported hook-generation subset is nonvolatile scalar fields and pointer
edges along plain current-object-provider paths. Unproven dynamic array ranges, unresolved
pointer origins/callback targets, recursion, architecture operations, integer-address
conversions, unsupported control constructs and unmodeled external effects
produce blockers. Global paths need additional binding support before hooks can
be generated. Argument-backed objects support explicit entry bindings, as
described below; arbitrary pointer ranges remain unsupported. Bitfields,
aggregate copies, function pointers and pointer-to-pointer projections also
require an adapter. A blocked plan cannot silently produce a snapshot header.

This is an automated analysis-and-capture foundation, not a whole-kernel alias
proof, a universal checkpoint generator, or an automatic replacement for
boundary-model design. Reports deliberately set `minimality_proven` and
`completeness_proven` to false. General replay generation, path-sensitive
read-before-write analysis and scheduling/interrupt reconstruction remain
separate work. Configured direct-call closure now supports multiple translation
units, as described below.

Tests cover compiler configuration changes, local aliases, direct callees,
conditional field reads, read/write overlap, unknown callbacks and ranges,
generated hook compilation/execution, null/self references, conflicting
snapshots and rejection of serialized pointer bytes. A live-kernel test compares
all fourteen generated snapshots with independent existing capture observations
and verifies an AArch64 delivery image from that same run.

## Path facts, field ranges and descriptor tables

`tools/entry_state_values.py` closes the analysis gaps found on the live Linux
`read`/`write`/`close` boundaries (see [SVC boundaries](svc-boundary-replay.md)).
Six mechanisms are involved; each runs only after the analyzer's narrower
certificates have failed.

| Mechanism | Linux idiom it covers |
| --- | --- |
| Path facts and integer intervals | `if (fd >= fdt->max_fds) return NULL; … fdt->fd[fd]` |
| Declared field ranges | `max_fds` bounded by the slice's 64 inline slots |
| Pointer-element arrays | `fdentry = fdt->fd + i; file = *fdentry` |
| Index-mask idiom | `array_index_mask_nospec` and `(void *)(mask & (unsigned long)file)` |
| Null guards | `if (!file) return …; file->f_count` |
| By-value records | `struct fd f = fdget_pos(fd); … f.file->f_pos` |

**Path facts.** A fact is a condition that holds at a node because a structured
guard dominates it. The guard can be:

- the taken arm of an `if`, `&&`, `||` or `?:`;
- an earlier `if` in the same block whose arm always leaves the block (`return`,
  `break`, `continue` or `goto`).

A fact is kept only if all of these hold:

- no variable it mentions is stored from the guard's start to the use, including
  stores inside the guard itself;
- a loop between the guard and the use widens that region to the whole block
  statement;
- no mentioned variable's address is taken, and none is volatile;
- no label or `case` can enter the region.

Loop conditions are not facts; induction variables keep the existing loop
certificates. A guard may compare a variable or a pure expression over variables
(`if (start + copied >= 64) break;`). Memory reads in a guard contribute only
their declared range or their type range, which hold at every point in time.

**Integer intervals.** Intervals use LP64 ranges for unknown values and the
narrowest supported range to decide whether arithmetic or a conversion can wrap.
A variable takes its value from its unique reaching assignment, or from its
caller's argument interval if it is an unassigned parameter. Calls with
available bodies are evaluated through their return expressions; for example,
`array_index_nospec(idx, size)` returns `idx < size ? idx : 0`.

These cases are rejected rather than bounded:

- volatile or escaped locals;
- locals that may be read before initialization;
- a constant mask that would hide such a read.

Pure constant expressions stay with the portable constant folder. Intervals wider
than the element limit are not reported, so unproven indexes still show
`dynamic_extent`.

**Field ranges.** A boundary policy may declare `state_ranges`, such as
`struct fdtable.max_fds` in `[0, 64]`. Each entry needs a reason and a
`validated_by` check on live state. The plan lists the ranges a proof used in
`state_range_assumptions`. `tools/reduced_boundary_replay.py` checks each one
against the captured pre- and post-state and refuses the replay on a violation.

**Pointers.**

- *Pointer-element arrays.* Inline arrays of object pointers now form bounded
  pointers, and loads through them yield the slot paths
  (`…->fdt->fd[3]->f_count`).
- *Index mask.* `(T *)(mask & (uintptr)p)` is the operand `p` or null. This holds
  when `mask` is defined by a body returning `c ? ~0 : 0` of the same unsigned
  type. `x & mask` with `mask = f(x, n)` and `f` returning `x < n ? ~0 : 0` is
  below `n` or zero. Any other integer-to-pointer conversion still blocks;
  pointer-to-integer conversions no longer do, because they access no memory.
- *Null guards.* A dominating guard removes the `null` alternative from that read
  of a pointer variable or a tracked record field. `__builtin_expect`
  (`likely`/`unlikely`) is recognized as a branch hint returning its first operand.
- *Uninitialized declarations.* A local pointer whose every read has a unique
  reaching assignment no longer keeps its uninitialized-declaration origin, even
  in loops with `continue`.
- *By-value records.* The pointer fields of automatic records and by-value
  parameters are tracked as values: compound-literal returns, struct assignment
  and argument passing. Tracking stops if the record's address escapes. A plain
  dereference may mix array elements with ordinary object paths.

**External memory.** A `memory_model` boundary with `"result":
"external_memory"` returns memory outside kernel entry state, such as the replay
runtime's admitted user objects. Accesses through it are listed in
`external_memory_accesses`, not in entry reads or blockers.

**Results on the corrected `file-io` slice.** The capacity guard
`if(start+copied>=64)break;` was added to the 20 transfer models, because the
read bound depends on two variables and intervals cannot express it.

| Root | Blockers before | Blockers after | Proofs used |
| --- | --- | --- | --- |
| `linux_read`, `linux_write` | 42 each | 0 | 17 null guards, 1 masked pointer, 8 index proofs |
| `linux_close` | 12 | 0 | 2 null guards, 3 index proofs |

Each root uses one declared range, `max_fds ≤ 64`. Discovered reads cover:

- `current → files → fdt → max_fds`;
- all 64 descriptor slots with `f_count`, `f_mode`, `f_pos` and `object_id`;
- `file_data`, the open-descriptor bitmaps and `next_fd`.

User bytes appear only as external memory. Tests are in
`tests/test_entry_state_path_facts.py`.

Some existing tests encoded limitations that are now proven, and their
expectations were changed. Wide constants such as `5ULL+0ULL` and the
non-canonical loops stay blocked.

- `(index++,5)` and `index ? 5 : 5` now prove index 5.
- A comparison result is now bounded to `[0, 1]`.
- A loop-condition access to the right of its own `&&` bound is now proven.
- Pointer fields of non-escaping local records now resolve.
- `__builtin_expect` is no longer external.

## Generated replay reconstruction

Parent/task delivery now supports the normalized snapshot path:

```sh
python3 tools/export_freestanding_task.py \
  --automated-entry-state \
  --capture build/live-automated-entry-state-final \
  --out build/rtl-aarch64-generated-state
```

`tools/reconstruct_entry_state.py` emits storage inferred from provider return
and field expression types, scalar byte restoration, reference assignments and
provider bindings. Object IDs are local to an invocation. Aliases, cycles and
null references are preserved; captured addresses are never emitted. Extra
fields/objects, blocked plans and unsupported storage are rejected. Generated
static assertions check scalar widths against the target types. The exporter
checks capture hashes, boundary policy and analysis source/header hashes before
building, auditing and executing both ELF and raw images.

The parent/task runner restores each invocation independently and checks that
its captured fields remain unchanged after the syscall. This is replay of
individual entry states, not proof of object continuity across invocations.
The current process ID is outside the discovered footprint and is therefore
not restored; result ABI 5 word 5 is zero in this mode. Parent and task IDs are
checked against the independently recorded syscall returns.

Semantic type definitions, selected syscall bodies, dependency implementations
and the call runner remain reviewed adapters. The normalized frames directly
supply replay state for this family; universal syscall export, write-effect
validation and scheduling reconstruction remain future work. Execution checks
use QEMU TCG and do not establish RTL timing equivalence.

Effective credential queries support the same generated reconstruction:

```sh
python3 tools/export_freestanding_credentials.py \
  --automated-entry-state \
  --capture build/live-automated-entry-state-final \
  --out build/rtl-aarch64-generated-credentials
```

Each frame restores only its discovered effective UID or GID field. The reviewed
scheduler-lock model enforces credential access inside a lock, the saved-token
unlock contract, balanced operations and zero terminal lock depth. Result ABI 6
word 12 is zero because the process ID is not part of this footprint. Words 5/6
report the last UID/GID returns, allowing frames with different entry values.
The parent/task and credential exporters share provenance and schema validation.
Tests also exercise nonzero/high-bit values, changing per-invocation state and
missing locks, missing unlocks and invalid unlock tokens. These fault tests are
synthetic; the live root-process capture has effective UID/GID zero.


## Multi-file closure and finite callbacks

The analyzer can follow configured bodies across source files in a compilation
database:

```sh
python3 tools/entry_state.py --compile-commands compile_commands.json \
  --source kernel/syscall.c --root SysExample \
  --closure-source kernel/helper.c \
  --boundaries integrations/liteos_a/entry-state-boundaries.json \
  --out build/example-plan.json --capture-header build/example-capture.h
```

Use `--all-sources` to load every source listed in the database instead of
selecting closure files. The default limit is 100 translation units; exceeding
it fails explicitly, and `--max-translation-units` can change the limit. Each
source retains its own compiler flags and dependency hashes. Reports include
all source identities and translation-unit locations for discovered effects.
The live six-root pipeline now analyzes its two configured source files together.

AST declaration IDs are namespaced by translation unit. Static functions,
static globals and inline function bodies retain local identities; external
functions resolve by linkage name. Provider/ordering policies continue to use
the original function names and cut through local inline implementations.
Conflicting named record layouts, function declarations, multiple external
bodies and compiler targets fail closed. This check is intentionally strict:
equivalent declarations using different typedef spellings may need explicit
normalization before they can be combined. This is not a complete C linker or
ABI compatibility proof. Only supplied compilation-database sources are loaded;
missing bodies still require source coverage or a boundary model.

Finite callback targets can now be followed through local function-pointer
initializers, conservative assignments, conditional expressions and function
parameters. Every possible resolved target is visited, including targets in
another source file. Unknown parameter targets, global callback tables, nullable
callbacks, and unresolved target mixtures remain blockers. No runtime address
lookup or speculative target guessing is used.

These extensions remove the single-translation-unit restriction and some
callback blockers. Dynamic heap/buffer ranges, general alias analysis, read-before-write
proofs and automatic dependency-model design remain unresolved limits.


Pointer aliases now use a flow-insensitive may-alias fixed point before effect
traversal, including assignments that feed a later loop iteration. This keeps
all possible local callback targets and object paths, at the cost of retaining
aliases that are overwritten before use. The pass is bounded to 32 iterations;
a nonconverging linked traversal fails with an `alias_limit` blocker. Unresolved
and null origins are retained rather than discarded from target sets. This is
still not general heap/offset analysis or a read-before-write proof.

## Argument-backed object discovery

Root helper/syscall pointer arguments can now supply objects to the same typed
discovery, snapshot and reconstruction pipeline. The boundary policy can include
an `argument_objects` section alongside its existing `boundaries` section:

```json
{
  "format": "osrec-entry-state-boundaries-v1",
  "boundaries": {},
  "argument_objects": {
    "query": {
      "left": {
        "kind": "object_argument",
        "reason": "caller holds the object stable for the snapshot",
        "implementation": "entry hook under the caller's lifetime and lock contract",
        "snapshot_safe": true
      }
    }
  }
}
```

For `unsigned query(Node *left) { return left->next->value; }`, analysis binds
`left` at entry and discovers the `next` edge and `value` scalar itself. Plans
name this logical root `osrec_argument_left()` and retain its argument name,
position, configured type and safety contract in `object_providers`. This is
a synthetic binding name, not a function invoked in the native kernel.
The policy file's existing hash also covers argument contracts.

The generated hook accepts the bound pointers after the snapshot parameter:
`osrec_snapshot_query(&snapshot, left)`. With multiple argument objects,
parameters follow the root function's declaration order, omitting scalar and
unbound arguments. Ordinary provider calls keep their existing behavior. Call
the hook while the stated lifetime and locking conditions hold. A non-null
argument must denote a valid object of the configured type; the tool does not
validate arbitrary user pointers or make concurrent reads atomic.

Argument bindings propagate through local aliases and configured callees,
including other translation units. Existing bounded inline-array discovery
works on these objects. Multiple argument roots can alias or form cyclic
graphs; null bindings use ID zero. Pointer arguments and pointer fields are
serialized only as logical object references, never address bytes.

`reconstruction_header(..., scalar_arguments=True)` restores argument objects
and exposes their pointers as `osrec_bound_osrec_argument_left`, for example.
The reviewed call adapter passes those pointers to the original root. Scalar
arguments remain in the frame's `arguments` list, in declaration order with
bound pointers omitted. `osrec_argument(invocation, argument)` keeps the
original C argument position, so a scalar between two pointers retains index
1. Pointer-only roots do not require `scalar_arguments=True`. Existing captured
post-state validation also works for direct scalar writes to argument objects.

Missing safety contracts, unknown parameter names, conflicting reserved binding
names and tampered binding metadata reject. Hook generation remains restricted
to plain, nonvolatile fields and checked pointer paths. Const-qualified object
views now support readonly footprints; writes rooted in those views and fields
declared with const storage are rejected. Volatile object pointer parameters,
pointer-to-pointer arguments, callbacks, aggregate values
and arbitrary buffer extents need additional adapters. No general heap traversal,
whole-kernel completeness is established by this extension. A bounded live
helper capture now uses this binding path under the scheduler lock, as below.

Run `python3 tests/test_entry_state_arguments.py` with the prepared LLVM 16 and
QEMU tools, or enable `OSREC_BUILD_FREESTANDING_IMAGE_TESTS` and run CTest's
`entry_state_arguments` suite. Its configured C fixtures exercise native
snapshot capture, host reconstruction, aliases, cycles, null roots, bounded
arrays, mixed scalar/pointer positions, cross-file closure and scalar writes.
Standalone AArch64 ELF and raw images replay five captured invocations after
the capture executable and source are removed; changing an unselected captured
field is rejected. These are fixture captures, not new live-kernel observations.

### Live process-helper argument capture

```sh
python3 tools/liteos_qemu_demo.py --argument-entry-state \
  --out build/live-argument-state
python3 tools/live_argument_state.py --capture build/live-argument-state \
  --out build/rtl-argument-state
```

`--argument-entry-state` implies automated entry-state capture and currently
requires the default live workload. It adds six explicit calls to the original
`OsProcessExitCodeSignalIsSet(LosProcessCB *processCB)` inline helper, one before
each selected PID 1 `SysUmask` call. The capture adapter holds the actual
scheduler lock, supplies the real current process pointer, takes the generated
snapshot, reads `exitCode` independently and executes the original helper.
These are adapter-requested helper invocations; they are not evidence that the
unmodified syscall naturally invokes this helper.

The new, separate `entry-argument-boundaries.json` policy specifies the entry
binding and safety contract. Its hash is retained in the generated plan without
changing the existing provider-boundary policy. Configured analysis discovers
the single `exitCode` read from the actual helper body. The snapshot hook uses
the kernel's real `LosProcessCB` type and field access; no copied kernel memory
layout or recorded pointer bytes are used. Existing provider snapshots and
syscall replay checks continue to run.

The seven-root plan and generated header are retained in `entry-state-plan.json`
and `entry-state-capture.h`. The snapshot bundle has its existing fourteen entry
frames plus six helper frames, with capture route ID 65536. That ID denotes a
helper in the capture adapter, not an OHOS syscall number. Six independent
little-endian `{invocation, exitCode, helper_return}` records form the 72-byte
`argument-entry-kernel.bin` witness. Both the normalized frames and binary
witness must match their retained native-log markers; lifetimes, source/header
hashes, policy hashes and the original helper excerpt are checked on export.

The exporter reconstructs each invocation independently and runs the pinned
original helper body in standalone AArch64 ELF/raw images. Its semantic model
contains only the discovered 32-bit `exitCode` field and explicitly retains the
ARMv7 32-bit `BOOL` return ABI. Captured field values supply the computation;
recorded returns are used only as checks. The existing result ABI 8 verifies
six returns and six readonly states. The image embeds all reconstruction data
and requires no capture file, source tree, host service or original device.
Replay does not reproduce the scheduler lock or concurrent process mutation.

`tests/test_live_argument_state.py` boots a fresh kernel capture, checks ELF/raw
execution at two entry addresses, and repeats execution after removing the
capture and generated construction sources. It rejects changed results and
changes to a captured high bit that leaves the return unchanged. Witness,
schema, policy, lifetime identity and provenance corruptions also reject,
including a rehashed snapshot/witness pair inconsistent with the native log.
The native current process has `exitCode=0` in this workload. Separate synthetic
cases execute the same pinned original body on zero, nonzero, mask-boundary and
high-bit values; those values are not presented as native observations.

This adds one live argument-backed object footprint. Automatic selection of
natural kernel call sites, broader object/range discovery,
concurrency reproduction and RTL/cycle timing validation
remain separate work.

The accepted October 20 capture is `build/live-argument-entry-final-v1`.
Images are retained in `build/rtl-argument-entry-final-v1` and
`build/rtl-argument-entry-relocated-final-v1`, with entry addresses `0x40200000`
and `0x40400000`. Both ELF/raw pairs verify all six calls and readonly states.
All fifteen related CTest suites passed, including the three new live argument
tests and the existing live entry-state capture suite. Source/artifact hashes,
native zero-valued observations, synthetic nonzero cases and corruption-check
results are recorded in `build/live-argument-entry-validation-20261020.json`.

### Const-qualified kernel object arguments

```sh
python3 tools/liteos_qemu_demo.py --const-argument-entry-state \
  --out build/live-const-argument-state
python3 tools/live_argument_state.py --capture build/live-const-argument-state \
  --out build/rtl-const-argument-state
```

Const pointer arguments and const pointer edges now use the same generated
object snapshots. The C bindings retain their pointee qualifiers, while object
identity uses the underlying unqualified type, so const and mutable views can
alias the same logical object. Reconstruction creates mutable owned backing
objects through C's conditional-expression type conversion; only the outer
object qualifier is removed. Declared member qualifiers remain intact. Actual
const scalar/array members and const pointer storage are rejected rather than
restored through cast-away qualifiers. A compiler-checked aggregate assignment
also rejects const subobjects omitted from the captured footprint before the
backing object can be cleared. Volatile storage remains unsupported.

Pointer restoration checks the underlying pointed-to types and allows const
qualification conversions, preserving type rejection for unrelated objects.
Generated public const bindings reject mutation in C. Writes rooted in const
bindings, including explicit cast-away-const writes found by analysis, block
generation. This is a conservative readonly subset: const views can contain
mutable pointer members in C, but writes through those members still require
a separate mutable binding/contract for this pipeline. A parameter's top-level
pointer const does not freeze the internal replay binding slot between frames.
Qualifiers inherited through pointee typedefs are resolved within their source
translation unit and made explicit in the argument binding type.

The new live profile captures six explicit calls to the pinned original
`OsProcessIsPGroupLeader(const LosProcessCB *processCB)` helper, under the actual
scheduler lock. Configured analysis discovers its 16-bit `processStatus` field.
The separate `entry-const-argument-boundaries.json` policy preserves the earlier
exit-code profile's policy hash. `entry-const-argument-source-lock.json` pins the
helper, type header and `OS_PROCESS_FLAG_GROUP_LEADER` value. Both capture
profiles remain available and are mutually exclusive in one run.

This profile uses helper route 65537 and the existing 72-byte kernel witness:
the 16-bit observed status is zero-extended into each record's 32-bit value
word, while normalized snapshots retain exactly two field bytes. The exporter
selects the profile from capture metadata, checks the native log and provenance,
and runs the original helper using a two-byte semantic field model. Source and
runtime checks preserve the captured ARMv7 `BOOL` return ABI. Standalone delivery
continues to use result ABI 8, with no host services or captured pointers.

Core tests cover aliases between const and mutable roots, const pointer edges,
cycles, null references, compile-time readonly enforcement, mismatched pointee
types and declared const-member rejection. They also replay a const object graph
in AArch64 ELF/raw images. Live tests check two load addresses, source/capture
removal, seven schema/profile/width corruption cases, and result/state mutations.
Synthetic status values separately exercise absent/present group-leader flags,
unrelated flags, combined flags and the 16-bit maximum. Natural call-site
selection, arbitrary pointer ranges and concurrency reproduction remain outside
this milestone; RTL timing is unverified.

The accepted October 20 const capture is `build/live-const-argument-final-v1`:
all six native status values are `0x0800`, with helper return 1. ELF/raw pairs
in `build/rtl-const-argument-final-v1` and
`build/rtl-const-argument-relocated-final-v1` verify six calls and readonly states
at entry addresses `0x40200000` and `0x40400000`. All seventeen related CTest
suites passed; eleven focused core suites and final const-specific checks also
passed after the additional type guards. The earlier exit-code capture still
exports through the updated pipeline. Evidence and source/artifact hashes are
in `build/const-argument-validation-20261020.json`.

### Captured argument-backed scalar writes

```sh
python3 tools/liteos_qemu_demo.py --argument-write-state \
  --out build/live-argument-write-state
python3 tools/live_argument_state.py --capture build/live-argument-write-state \
  --out build/rtl-argument-write-state
```

The write profile executes the pinned original
`OsProcessExitCodeSignalSet(LosProcessCB *processCB, UINT32 signal)` helper on
the real PID 1 process. Configured analysis discovers both the read and write
of `exitCode`. Generated entry and effect hooks capture that field before and
after the original helper, with the pointer argument normalized as an object
binding and the scalar `signal` retained at its original argument position 1.
`entry-write-argument-boundaries.json` supplies the explicit lifetime/locking
contract; its separate hash preserves both earlier read-only profiles.

These are controlled adapter invocations, not naturally selected syscall call
sites. Each call runs while the actual scheduler lock is held. The adapter
saves the native field, captures entry state, executes the original helper,
captures post-state, and restores the saved field before releasing the lock.
The native scenario uses signals `0`, `1`, `127`, `128`, `0x80000001` and
`0xffffffff`. Restoration is a capture intervention, separate from the helper's
write effect. It is recorded and checked rather than treated as part of the
original helper or hidden from the capture contract.

This profile uses helper route 65538. Six entry frames join the existing
fourteen entry snapshots, and six helper post-state frames join the existing
six umask effects. `argument-entry-kernel.bin` contains six little-endian
`{invocation, signal, before, after, restored}` records, totaling 120 bytes.
Normalized fields, scalar arguments, object/lifetime identity, direct native
witnesses, restoration values and the retained native log must agree. Each
`after` must equal `before | (signal & 0x7f)`, and each restored value must equal
its own entry value. Entry/post ordering and exact discovered footprints are
checked before export; rehashing mismatched files cannot bypass the log check.

Standalone replay restores each entry state independently, passes its captured
scalar argument to the original helper, and checks the resulting field against
captured post-state. Expected writes are never applied to replay storage. The
original helper returns `VOID`: result ABI 8 uses zero solely as the replay
adapter's completion marker, while its write-effect checks validate all six
post-states. The replay does not restore the live process or reproduce scheduler
locking; it owns isolated reconstructed objects with no host services.

Tests execute the same pinned body with synthetic nonzero entry fields to check
preservation of unrelated bits. Live tests verify two image load addresses,
ELF/raw execution after capture/build-source removal, schema and provenance
corruption rejection, and runtime rejection of omitted writes, a wrong scalar
argument index and an extra write outside the helper's mask. The live workload
has entry values zero; nonzero entry values in the reference tests are synthetic.
This profile covers direct scalar argument-object writes restored independently
for replay. The continuous variant below retains those writes across a bounded
helper session. Pointer rebinding, arbitrary heap/range capture and natural
call-site selection need additional independently validated capture contracts.

The accepted October 20 capture is `build/live-argument-write-final-v1`.
Its six native entry values are zero, post-values are `0, 1, 127, 0, 1, 127`,
and all six restoration observations are zero. Images in
`build/rtl-argument-write-final-v1` and
`build/rtl-argument-write-relocated-final-v1` verify all six writes at entry
addresses `0x40200000` and `0x40400000`, in both ELF and raw form. All eighteen
related CTest suites passed, including the three new write-profile tests.
Both previously retained read-only captures still export successfully. Native
witnesses, synthetic nonzero-entry cases, corruption checks and source/artifact
hashes are recorded in `build/argument-write-validation-20261020.json`.

### Continuous argument-backed helper sessions

```sh
python3 tools/liteos_qemu_demo.py --argument-write-session \
  --out build/live-argument-session
python3 tools/live_argument_state.py --capture build/live-argument-session \
  --out build/rtl-argument-session
```

The session profile calls the same original `OsProcessExitCodeSignalSet` helper
six times in one scheduler-lock region before the first selected PID 1 umask
call. It retains the helper's field writes between invocations. After the last
post-state snapshot, the capture adapter restores the live process's original
field once, before scheduler unlock. Thus the captured continuity spans one
explicit helper batch; mutations do not escape into the surrounding workload.

Signals `1`, `2`, `128`, `4`, `0x80000008` and `16` exercise accumulation and
masking without saturating the low bits early. A zero entry field produces
post-states `1, 3, 3, 7, 15, 31`. `entry-session-argument-boundaries.json`
specifies the locked lifetime contract, while the original helper's existing
write-profile source lock remains unchanged. The capture report explicitly
admits helper route 65539 into its stable-lifetime scope and records a
single-lock, restoration-after-batch session contract. This ID is a capture
adapter route, not an OHOS syscall number.

Six `{invocation, signal, before, after}` records occupy the first 96 bytes of
`argument-entry-kernel.bin`. Three trailing words record the session's initial,
final and restored native values, for a total of 108 bytes. No per-call restore
is inferred or fabricated. Every call must satisfy the original helper's
masked-OR relation, every next entry must equal its preceding post-state, and
the object graph, captured field schema and capture-scoped identity must remain
stable. The trailing final value must match the last post-state, and the native
restored value must match the session entry. The retained native log and all
existing source, policy, snapshot and lifetime provenance checks still apply.

Export selects continuous replay from the capture profile. Generated restoration
initializes one session object once; the original helper then mutates that same
object through all six calls. The runner checks six entry states and six
post-states, with the original scalar argument position 1 retained. Result ABI
8 reports `states_restored=1`, `entry_states_checked=6` and `states_verified=6`.
The exporter rejects an image reporting the wrong continuity mode. Zero remains
only the adapter completion marker for the original `VOID` helper. Replay
finishes with the final session state; the native restoration intervention is
not replayed as an original helper effect.

Tests cover a synthetic high-bit initial field, local object-ID renumbering with
stable capture-scoped identity, locally correct calls separated by a hidden
state discontinuity, missing lifetime/session contracts and changed boundary
witnesses. Runtime mutants reset state between calls, omit the write, use the
wrong scalar argument index, attempt repeated initialization, or corrupt state
before the next entry check. Live ELF/raw replay runs at two load addresses and
again after removing capture files and generated construction sources.

This validates continuity of the discovered scalar footprint during one locked
helper batch. It does not reproduce scheduling, concurrent observers, object
allocation/rebinding, arbitrary cross-syscall sessions or RTL timing.

Accepted evidence is retained in `build/live-argument-session-final-v1`: native
entries `0, 1, 3, 3, 7, 15`, posts `1, 3, 3, 7, 15, 31`, and session boundary
`{initial: 0, final: 31, restored: 0}`. ELF/raw images in
`build/rtl-argument-session-final-v1` and
`build/rtl-argument-session-relocated-final-v1` passed at load addresses
`0x40200000` and `0x40400000`. All 19 regression suites passed, and the earlier
read, const-read and independent-write captures still exported successfully.
`build/argument-session-validation-20261020.json` records the checks, retained
artifacts and source hashes.

### Live nested writes through the parent-process edge

```sh
python3 tools/liteos_qemu_demo.py --parent-argument-session \
  --out build/live-parent-argument
python3 tools/live_argument_state.py --capture build/live-parent-argument \
  --out build/rtl-parent-argument
```

The `parent-exit-signal-session` profile captures a real two-process graph. Its
root is the explicitly labeled `OsrecParentExitSignalSet` capture adapter in
`integrations/liteos_qemu/parent_argument_adapter.h`, rather than an original
kernel function. The adapter follows `processCB->parentProcess` and invokes
the pinned original `OsProcessExitCodeSignalSet` helper. Configured Clang analysis
visits both bodies and discovers the parent pointer read, nested `exitCode` read
and nested scalar write. This is a controlled call site, not automatic selection
of a natural kernel helper invocation.

PID 1 has no parent in this workload. Capture therefore runs before the child's
first `getppid`, while the wrapper already holds the real scheduler lock. Native
checks require a distinct, allocated parent and record the child's process ID
and its PID 1 parent. Six original helper calls use the session signals above,
retaining the parent's changes until the last generated post-state snapshot.
The native adapter then restores the parent's initial `exitCode` once, checks
the parent edge and process ID, and unlocks. No mutation escapes the batch into
the surrounding syscall workload.

`entry-parent-argument-boundaries.json` admits the child and parent's locked
lifetimes. Snapshots contain two logical objects, the root's `parentProcess`
edge and the parent's four-byte `exitCode`; pointer addresses are never
serialized. The entry state's edge determines the permitted write owner.
Null/self parent edges, changes to the edge, wrong field owners, extra state,
changed object types/identities and writes to traversal edges fail validation.
The generic nested-write reconstructor checks continuity and initializes two
session objects once. Every incoming edge/value and outgoing edge/value is
compared; snapshots never perform the helper's writes or rebind the edge.

The binary witness has 116 bytes: six `{invocation, signal, before, after}`
records followed by `{initial, final, restored, child_pid, parent_pid}`. Export
requires both the single-lock session contract and a separate parent contract
with capture site `child-first-getppid`. Its two native process IDs must also
match every row of the independent task witness. The report retains the pinned
original helper identity plus the capture adapter's path/hash. The configured
AST dependency hashes also cover that adapter. Rehashing the helper witness and
its native log cannot silently replace the independent task's process IDs.

`tests/test_live_parent_argument.py` covers a high-bit synthetic entry,
renumbered local object IDs with stable session identities, invalid graphs and
boundaries, hidden inter-call changes, missing lifetime/parent contracts and
adapter provenance. Live AArch64 ELF/raw images run at two load addresses and
again after deleting capture files and generated construction sources. Target
mutants select the wrong process, omit the original helper's write or corrupt
the parent edge; each fails post-state validation. The original helper returns
`VOID`; zero remains only the replay adapter's completion marker. Scheduling,
concurrent observers, dynamic lifetimes, arbitrary heap/range capture and RTL
timing remain outside this profile.

Accepted evidence is retained in `build/live-parent-argument-final-v1`: child
PID 3 and parent PID 1, native entries `0, 1, 3, 3, 7, 15`, posts
`1, 3, 3, 7, 15, 31`, and boundary `{initial: 0, final: 31, restored: 0}`.
ELF/raw images in `build/rtl-parent-argument-final-v1` and
`build/rtl-parent-argument-relocated-final-v1` passed at `0x40200000` and
`0x40400000`, each reporting one initialization and six entry/post checks.
All 21 regression suites passed. All four earlier retained argument profiles
also exported successfully. `build/parent-argument-validation-20261020.json`
records the checks, source identities and retained artifact hashes.

## Proven inline-array index ranges

Configured inline-array fields can now be captured and reconstructed by element.
The analyzer derives the storage extent from Clang's array type and accepts
constant indices or unsigned index expressions with provable intervals, such as
`index % 8U` and `index & 15U`. It checks that the interval fits the actual array.
Plain unchecked indices remain blockers: a fixed storage extent does not itself
prove an index is in bounds. Pointer variables, pointer casts and signed modulo
also remain blocked. Integer casts are not stripped when proving an index,
because truncation or sign conversion can change its value.

Plans include `memory_ranges` with the configured extent, selected index bounds,
element type and evidence location. Each selected element has its own field
path, for example `current()->values[3]`, and snapshot field name `values[3]`.
Hooks capture scalar bytes or supported pointer edges by element; reconstruction
uses target field expressions and verifies scalar widths. It never copies an
array's pointer representation as scalar data. The default range expansion limit
is 64 elements and can be changed using `--max-range-elements`; capture-runtime
object/field/value capacities still apply independently. Aggregate elements and
complex array projections remain outside the generation subset.

### Counted-loop index discovery

Discovery now proves index intervals for a narrow canonical `for` form:

```c
void paint(State *state, unsigned count, unsigned value) {
    for (unsigned i = 0; i < 8; ++i) {
        if (i >= count) break;
        state->values[i] = value + i;
    }
}
```

The counter must be a fresh local `int` or `unsigned int` declaration without
an explicit storage class. Initialization and exclusive upper limit are
nonnegative integer literals no greater than `INT32_MAX`, with a nonempty
interval. A literal guard is a direct `<` comparison and the increment is prefix
or postfix `++`. The body cannot assign, increment or take an address expression
containing the counter. Labels, cases, jumps and assembly invalidate this proof.
Counter declarations are matched by identity, so nested and shadowed counters
cannot borrow one another's bounds. `break`, `continue` and early returns can
reduce the visited set without widening the interval.

Direct counter subscripts, with parentheses/lvalue conversion, use this proof;
the arithmetic extension below separately checks supported index expressions.
Explicit casts, unguarded dynamic limits, nonunit steps,
descending loops and reused counters remain outside it. Existing constant and
unsigned mask/modulo proofs remain available independently. Value-preserving
implicit 32-bit conversions at the loop initializer/condition are accepted only
within the nonnegative literal interval. No explicit or narrowing cast becomes
a bound. This proves an index range, not termination or a full overwrite.

The configured inline-array extent and range-expansion limit are still checked
separately. A proven loop interval cannot lend an extent to a pointer or casted
buffer. Each selected element uses the existing typed field/edge codec; plans
record `index_proof` in `memory_ranges`, including the declaration name, literal
interval, increment and loop location. Ordinary local integer increments do not
become incoming object-memory reads; global and object-field increments retain
their existing read/write tracking.

Loop backedges remain conservative in must-store analysis. Reads in the loop
stay captured. With `--prune-written-fields --preserve-write-state` and the
existing strong binding contracts, possibly written scalar elements also retain
their incoming values. In the example, `count == 0` writes nothing and
`count == 3` changes only the first three elements, so all eight initial values
remain available for restoration and verification. The loop proof does not
silently turn this partial writer into a guaranteed overwrite.

`tests/test_entry_state_loops.py` covers signed/unsigned, partial, nested and
shadowed loops, and rejects unsafe or unproved induction forms. Its native
fixture captures eight alternating partial writes and full-array sums through
generated wrappers. Both independent and continuous sessions export ELF/raw
pairs at two addresses and rebuild from portable requests after original inputs
are removed. A missing entry element rejects reconstruction. Omitting an element
store or modifying the tail during a correct-return query fails target state
verification. Accepted bundles are in `build/loop-discovery-final-v2`; evidence
is recorded in `build/loop-discovery-validation-20261020.json`.

The 2026-10-20 validation passed all 36 selected regression suites on the first
run, including fresh live LiteOS argument/shared/configured captures. Six loop
fixture images and one CLI export passed; the fixture images also passed 12
standalone ELF/raw executions and four EL3 memory/CPU entry checks. Fifteen
existing exports reproduced identical raw images and results. These checks
validate the admitted loop subset and existing capture paths; arbitrary pointer
extents, general loop induction and whole-kernel completeness remain unproved.

### Count-dependent loops with capacity guards

The loop proof also admits a dynamic count when a literal capacity comparison
is an unconditional conjunct at body entry:

```c
for (unsigned i = 0; i < count && i < 8; ++i)
    state->values[i] = value + i;
```

Either conjunct order is accepted. Nested `&&` expressions are flattened; when
several literal guards constrain the same declaration, the tightest limit is
used. A guard hidden inside `||`, a conditional or a comma expression cannot
supply the bound. Additional predicates can contain such expressions when a
separate unconditional literal conjunct already establishes the capacity.
`count` itself needs no inferred upper bound: it may be zero or `UINT32_MAX`.
The configured inline-array extent and element-expansion cap are checked after
proving the counter interval, independently of the dynamic predicate.

The complete condition and body are scanned for counter writes, increments and
address escape. This prevents `i < 8 && (i = count)` from changing the counter
after the capacity test succeeds. The same restriction applies before the guard
and to nested expressions. A fresh counter declaration, nonnegative literal
initial value, nonoverflowing unit increment and literal upper limit retain the
existing requirements. Only body subscripts receive that counter's proof. A
direct dynamic subscript using this loop's counter in its condition remains
blocked, even after a short-circuit capacity test; existing constant/mask index
proofs remain available there.

Other condition memory accesses keep ordinary read/write tracking. In particular,
`state->values[7]++ && i < 8 && i < count` changes the tail even when `count == 0`,
and again when a later capacity test fails. Those changes are captured and
verified; a loop condition is not treated as a pure test. Plans add a `condition`
record to `index_proof` for conjunctions, recording the number of terms and
literal guards, counter immutability and possible zero iterations. Plain counted
loops retain their existing proof shape. No new loop-store dominance or runtime
footprint reduction is inferred: a zero/partial write retains incoming elements
under the same strong preservation contracts.

`tests/test_entry_state_guarded_loops.py` tests seven accepted condition forms,
23 rejected guard forms, body mutations/escapes/casts, indexed condition accesses
and the expansion limit. Native generated capture covers both independent and
continuous sessions, two replay addresses and portable rebuilds after input
cleanup. Counts of zero, three, `UINT32_MAX` and eight exercise the capacity
guard; a query limit read from the captured tail changes the observed prefix.
A separate native session checks condition writes on failed guards. Missing
incoming fields reject reconstruction, while omitted tail stores and correct
returns with wrong state fail target verification. Accepted artifacts are in
`build/guarded-loop-discovery-final-v3`; the validation record is
`build/guarded-loop-discovery-validation-20261020.json`.

The 2026-10-20 guarded-loop validation passed all 37 selected regression suites
on the first CTest run. Three retained native fixture captures produced seven
accepted images; a separate CLI export adds an eighth. Fourteen standalone
ELF/raw executions and six EL3 memory/CPU entry checks passed. Twenty-two prior
exports reproduced identical raw images and results, and freshly analyzed plain
counted-loop plans matched the previous plans after ignoring list order. These
results cover the admitted capacity-guard form; dynamic pointer extents and
arbitrary loop induction remain outside the proof.

### Arithmetic over proven loop indices

An admitted counter interval can now prove a single-counter affine body index:

```c
for (unsigned i = 0; i < count && i < 4; ++i)
    state->values[2U * i] = value + i;

for (unsigned i = 0; i < 4; ++i)
    result += state->values[6U - 2U * i];
```

Supported operations are `+`, `-`, unary signs and multiplication when at least
one operand is a proven constant. The proof retains `a * i + b`, so repeated
reads of the same immutable declaration remain correlated: `(i + i) - i` has
the original interval, and `i - i + 3` is constant. A factor such as `i - i + 2`
can itself prove a constant. Unrelated variables, multiple counters, nonlinear
products, division and shifts receive no new proof. Existing unsigned mask and
modulo rules remain independently available.

Each intermediate result must fit its actual Clang `int` or `unsigned int` type.
Implicit 32-bit integer conversions are accepted only when the whole input
interval preserves its value; narrowing, wider arithmetic and explicit casts
remain outside this proof. Signed overflow and unsigned wrap are rejected even
when a subsequent operation would cancel them mathematically. Negative signed
intermediates can be valid if their type permits them, but the final array range
must be nonnegative and inside the configured storage extent. Analysis is bounded
to 64 AST nodes per candidate index and fails closed beyond that limit.

Arithmetic plans add an `arithmetic` record to `index_proof`, with the coefficient,
offset, resulting bounds and checked operation/conversion bounds. Bare counters
retain their prior proof shape. These proofs apply only within the already
certified loop body: they do not establish dynamic pointer extents, prove the
loop condition's indexed accesses, or constrain other scalar arguments.

Selection remains a conservative enclosing interval. Both example indices select
`values[0]` through `values[6]` for capture, although execution touches only the
four even indices. Gaps at indices 1, 3 and 5 retain incoming values under the
existing strong preservation contracts and count toward the expansion cap.
`values[7]` lies outside this projected footprint. This provides neither an exact
sparse footprint nor a guaranteed overwrite; must-store analysis remains
conservative at loop backedges.

`tests/test_entry_state_affine_indices.py` covers 12 accepted arithmetic forms,
21 rejected overflow/wrap/cast/operator forms, and rejection of unbounded loops,
indexed conditions, casted storage, multiple counters and expansion-limit
violations. Generated native capture covers zero, partial and capacity-limited
writes, reverse queries, independent/continuous sessions, two image addresses
and portable rebuilds after original input cleanup. A missing incoming gap field
rejects reconstruction. Omitting a selected store or changing a gap during a
correct-return query fails target state verification. Accepted artifacts are in
`build/affine-index-discovery-final-v2`; evidence is recorded in
`build/affine-index-discovery-validation-20261020.json`.

The 2026-10-20 arithmetic validation passed all 29 targeted CTest suites on the
first run, covering core entry-state analysis/capture/replay and fresh configured
LiteOS capture. A final four-test focused run also passed after adding the
negative signed-to-unsigned conversion case; implementation and image fixtures
were unchanged. Two retained native captures produced six accepted images,
with a seventh from CLI export. Twelve standalone ELF/raw runs and four EL3
memory/CPU entry checks passed. Thirty prior exports reproduced identical raw
images and results; fresh canonical, guarded and condition-writing loop plans
matched their baselines after ignoring list order. The proof remains confined
to admitted single-counter arithmetic and configured inline-array storage.

### Enum and inline-array count bounds

Loop initializers and capacity guards may now use enum constants resolved from
their declaration identities. Explicit enum initializers admit 32-bit integer
literals, references to already resolved enumerators, parentheses, unary signs,
addition, subtraction and multiplication. Every intermediate result and implicit
conversion must fit its actual `int`/`unsigned int` type, and computed values are
checked against Clang `ConstantExpr` values. Implicit enumerators advance from
the previous admitted value; an unsupported initializer prevents that chain from
being inferred until a new explicit value is resolved. Local and shadowed enums
cannot borrow values from namesakes. Final loop bounds remain nonnegative and
no greater than `INT32_MAX`.

This is a deliberately portable constant subset. Explicit casts, wrapping
arithmetic, wider integer expressions, `sizeof` enum initializers and
ordinary `const` variables remain outside it. Checked shifts and other operators
are added by the extension below. Enum values do not add runtime
memory reads. Each initializer proof is bounded to 64 AST nodes.

A guard can also derive a count structurally from a fixed integer array member:

```c
for (unsigned i = 0;
     i < sizeof(state->values) / sizeof(state->values[0]);
     ++i)
    result += state->values[i];
```

The numerator must be an inline `int`/`unsigned int` array member, and the
denominator must be `sizeof` its matching member's literal element zero.
Both `->` and `.` member forms are supported. The count comes from the configured
array type, independently of native pointer/`size_t` byte widths. The associated
implicit counter conversion for a `sizeof` comparison is admitted only for that
structural proof and the existing nonnegative 32-bit counter interval. This does
not admit arbitrary wide literals or general wide arithmetic.

Plans record `constant_bounds` in `index_proof`, including enum value provenance
and array owner/member/count metadata. Every admitted array-count proof emits a
`_Static_assert` in both capture and reconstruction headers, checking that the
member is an array with the expected length through Clang type compatibility.
A model whose member has changed length fails with `loop array extent differs`, even if all selected
scalar fields would still have compatible widths. Neither generating snapshots
nor exporting replay silently reuses a count from a different model layout.

Constant bounds compose with conjunctive count guards and the existing arithmetic
index proof. Array extents and expansion caps remain separate checks; condition
mutation/address escape, casted storage and unproved indexed conditions retain
their existing blockers. Partial writes retain incoming values under the same
preservation contracts, without gaining any loop overwrite guarantee.

`tests/test_entry_state_constant_bounds.py` covers eight admitted forms, 15
rejected enum/count forms, mutation/cast rejection and the expansion cap. Native
capture tests local enum bounds, structural array counts, zero/partial/full writes,
independent and continuous replay at two addresses, and portable rebuilds after
original input cleanup. Changing the array from eight to sixteen elements fails
both capture and replay compilation. A pointer model also rejects when its byte
size ratio coincides with the expected array count. Accepted artifacts are in
`build/constant-bound-discovery-final-v3`; evidence is recorded in
`build/constant-bound-discovery-validation-20261020.json`.

The 2026-10-20 constant-bound validation passed all 30 targeted suites after
rerunning one existing counted-loop suite whose native reference Clang compile
hit its 60-second deadline. A focused extent-check method also passed on rerun
after a separate native compile timeout. The initial logs are retained; the cause
of those timeouts was not established. Final extent tests reject both a larger
array and a pointer with a coincident byte-size ratio. Two retained native
captures produced six accepted images, with a seventh from CLI export. Twelve
standalone ELF/raw runs and four EL3 memory/CPU entry checks passed with the final
array-type assertion. Thirty-seven prior exports reproduced identical raw images
and results, and fresh prior loop plans matched their baselines after ignoring
list order. This covers the admitted constant-bound subset, without inferring
dynamic pointer extents or arbitrary compile-time expressions.

### Portable enum operator proofs

Enum bounds can now use additional portable 32-bit integer operations:

```c
enum { BEGIN = 0U & 7U, CAPACITY = (1U << 4) / 2U };
for (unsigned i = BEGIN; i < count && i < CAPACITY; ++i)
    state->values[i] = value + i;
```

Division and remainder follow C99 truncation toward zero, including negative
operands: `-17 / 2` is `-8`, and `-17 % 3` is `-2`. A zero divisor is rejected.
Both division and remainder also reject the signed `INT_MIN`/`-1` pair, even when
the mathematical remainder would be zero. Every child expression and result
still fits its actual `int` or `unsigned int` type; later operations cannot hide
an earlier overflow or wrap.

Left and right shifts require nonnegative left operands and counts from 0 to 31.
Left shifts must fit the result type without discarding bits. This admits
`(1U << 31) >> 28` while rejecting a signed shift into an unrepresentable value,
unsigned left-shift wrap and negative signed right shifts. Binary `&`, `|` and
`^` require nonnegative operands. Unary `~` is admitted only for `unsigned int`
and complements exactly 32 bits; signed complement remains outside this portable
subset. Width-changing casts and wider integer arithmetic retain their blockers.

The operations compose with existing portable enum arithmetic and implicit enum
chains, retain declaration-identity scoping, and share the 64-node initializer
budget and Clang `ConstantExpr` cross-check. Final loop capacities still lie in
the nonnegative `INT32_MAX` interval. These changes concern enum constants;
runtime affine indices do not gain division, shifting or bitwise operations
through this extension. Existing mask/modulo index proofs remain independent.

`tests/test_entry_state_enum_operators.py` exercises 16 accepted expressions and
an implicit-enum chain, plus 21 rejected expressions. Its evidence distinguishes
expressions rejected by Clang before an AST is usable from configured-AST
rejections. Native capture uses shifted/divided writer capacity and a complemented,
shifted query capacity, with zero/partial/full writes. Both replay modes run at
two addresses and rebuild from portable requests after original input cleanup.
A narrowed capacity and a query that changes the tail despite returning the
correct sum fail state verification. Accepted artifacts are in
`build/enum-operator-discovery-final-v2`; evidence is recorded in
`build/enum-operator-discovery-validation-20261021.json`.

The 2026-10-21 operator validation passed all 31 targeted CTest suites on the
first run, including fresh configured LiteOS capture. The four focused tests
passed, with two rejected expressions stopped by Clang and 19 by configured-AST
analysis. Two native captures produced six accepted images, with a seventh from
CLI export. Twelve standalone ELF/raw executions and four EL3 memory/CPU entry
checks passed. Forty-four prior exports reproduced identical raw images and
results, and fresh prior loop plans matched their baselines after ignoring list
order. These results cover the admitted enum operators and existing loop proof;
arbitrary constant expressions and dynamic pointer extents remain outside it.

### Direct constant-expression loop headers

Counted-loop initializers and capacity guards also accept direct expressions
from the portable 32-bit constant subset above. For example,
`for (unsigned i = (2U - 2U); i < ((1U << 4) / 2U); ++i)` proves the same
interval as a literal capacity of eight. Macro expansions and arithmetic using
resolved enum declarations are supported, including shadowed enum names.
Nonzero initializers narrow the interval, and conjunctive capacity guards select
the smallest proven limit.

The shared evaluator checks every operation and implicit conversion against its
actual signed/unsigned type, with a 64-node budget per expression. Clang
`ConstantExpr` values are cross-checked when present. Proof metadata records
`kind: integer_constant_expression`, the resulting `value`,
`evaluation: portable_nonwrapping_32bit_constant_expression` and
`ast_node_limit: 64`. Bare literal, enum and matched array-count proofs retain
their previous shapes. Structural `sizeof` ratios use the existing separate
array-type/extent proof rather than general `sizeof` folding.

The existing fresh counter, nonnegative bounds through `INT32_MAX`, nonempty
interval, unit increment and counter-preservation requirements still apply.
Runtime variables remain blocked even in `count * 0U + 8U`; const variables,
calls, conditional/comma expressions, assignments, increments, explicit casts,
wider types, wrapping intermediates and invalid shifts/division gain no proof.
The counter must still appear directly in its comparison. This extension does
not add runtime arithmetic index operators or discover pointer extents.

`tests/test_entry_state_constant_expressions.py` covers 16 accepted operator
expressions, four enum/macro/conjunction contexts and two nonzero initializers.
It rejects 30 invalid or nonconstant expressions, eight additional loop/header
forms and an insufficient range expansion cap. Native fixtures capture zero,
partial and full writes in both replay modes, run at two addresses, and rebuild
after removing original inputs. Wrong capacity and tail mutation fail post-state
verification despite correct return values. Accepted artifacts are retained in
`build/direct-bound-discovery-final-v2`; validation evidence is recorded in
`build/direct-bound-discovery-validation-20261021.json`.

The 2026-10-21 direct-expression validation passed all 32 targeted CTest suites
on the first run, including fresh configured LiteOS capture, plus four focused
tests. All 30 invalid-expression cases were rejected by configured-AST analysis.
Two native fixture captures produced six accepted images; CLI export produced
a seventh. Twelve standalone ELF/raw executions and four EL3 memory/CPU entry
checks passed. Fifty-one prior exports reproduced identical raw images and
results, and fresh prior plans matched after ignoring list order. These results
cover the admitted constant-expression headers, without establishing arbitrary
loop support or whole-kernel completeness.

### Inclusive and reversed capacity comparisons

The counted-loop proof accepts `i <= bound`, `bound > i` and `bound >= i`
alongside `i < bound`. The comparison must refer directly to the fresh counter.
Literal, enum, checked constant-expression and structural array-count bounds use
the same resolution and extent assertions as before. Conjunctions can combine
these forms with runtime guards, such as `count > i && 7 >= i`; the constant
guard bounds body accesses, while condition effects remain part of discovery.

Inclusive comparisons normalize to `exclusive_limit = bound + 1`, checked
against the nonnegative `INT32_MAX` domain before admission. This also keeps the
final unit increment representable. For example, a signed counter ending at
`2147483646` is admissible, but `i <= 2147483647` receives no proof. Bounds still
need to fit the actual array and expansion cap. Descending counters, unbounded
runtime comparisons, disjunctive bypasses, counter mutation/escape and indexed
condition accesses remain outside this extension.

New `comparison_guards` records carry `operator`, `counter_operand`,
`bound_value`, `inclusive` and `exclusive_limit`. Original constant-bound
evidence is retained separately, including array-type and length assertions.
Existing `i < bound` proof formats are unchanged.

`tests/test_entry_state_comparisons.py` covers 12 comparison/context forms and
two signed/unsigned boundary cases, plus 14 rejected comparisons and five
additional unsafe loop forms. Native fixtures use reversed inclusive guards
for zero, partial and full writes, then replay both modes at two addresses and
rebuild from portable requests after removing original inputs. A narrowed
capacity and a query that mutates the array tail fail post-state verification
despite correct return values. Accepted artifacts are retained in
`build/comparison-discovery-final-v2`; evidence is recorded in
`build/comparison-discovery-validation-20261021.json`.

The 2026-10-21 comparison validation passed all 33 targeted CTest suites on the
first run, including fresh configured LiteOS capture, plus four focused tests.
Two native fixture captures produced six accepted images; CLI export produced
a seventh. Twelve standalone ELF/raw executions and four EL3 memory/CPU entry
checks passed. Fifty-eight prior exports reproduced identical raw images and
results, and fresh prior plans matched after ignoring list order. These results
cover the admitted ascending-loop comparison forms, without establishing
arbitrary loop support or whole-kernel completeness.

`integrations/rtl_aarch64/entry_state_replay.c` provides a reusable readonly
entry-state runner through an explicit type/call adapter. Its RAM result ABI 8
has magic/version/status/error/completed at words 0–4, call count at 5, restored
states at 6, unchanged-state checks at 7, last invocation at 8, and up to seven
(number, raw return bits) pairs at words 10–23. Other words are reserved and zero.
The runner restores each independent invocation, checks its return and verifies
that all captured state remains unchanged. Writes need captured post-states or a separate effect adapter.

The bounded-range test captures typed array fields with construction-time host
instrumentation, removes that capture executable, then audits and executes both
AArch64 ELF and raw images with guest host services disabled. It also injects a
write to an unused captured element and verifies target failure. These are C
fixtures, not a new live OHOS array syscall capture or RTL timing validation.
Dynamic heap/buffer ranges and pointer arithmetic still need memory contracts.

## Conservative read-before-write pruning

`tools/entry_state.py --prune-written-fields` enables a structured must-store
pass after ordinary may-access discovery. Default discovery retains all reads.
The opt-in pass omits selected reads from `entry_reads` only when a full typed
store covers every incoming path to that read. It records omitted observations
in `dominated_reads`, with their covering store locations and omission reason.
Writes remain in `state_writes`; reports still set minimality and completeness
proof flags to false.

This pass requires the provider policy or root `argument_objects` contract to
explicitly declare all of:

```json
{
  "stable_identity": true,
  "exclusive_state": true,
  "preserves_entry_state": true
}
```

These are adapter contracts: repeated provider calls identify the same object,
its captured state is isolated from external writers, and provider calls do not
mutate that state. The analyzer does not infer locking, lifetime or concurrency
proofs. Existing live policies do not claim these stronger contracts, so they
continue to retain their incoming fields.

Argument bindings now support the same direct-field proof. Their three stronger
promises come from the named argument's explicit contract; `snapshot_safe`
alone does not authorize omissions. The bound pointer identifies the same
isolated object for the invocation. A pointer assignment or intervening write
clears facts, and a nonconverging pointer-alias pass keeps the plan blocked.
The pass still retains nested pointer paths and helper-context reads.

The supported proof subset is a direct scalar provider field or a constant
indexed array element, with a unique resolved destination and matching store/
load types. Both arms of a conditional can establish coverage; early-return
arms are excluded from later incoming paths. Aliases with the same logical path
can share a proof. Any intervening write clears older facts to avoid assuming
unproven nonoverlap. Calls other than contracted providers clear facts, including
reviewed transcript/ordering boundaries. Unsequenced expressions with effects,
loops/backedges, switches, jumps, ambiguous destinations, bitfields, partial
writes, pointer fields and deeper pointer projections do not earn omissions.
Helper contexts retain their incoming reads; there is no interprocedural
must-store summary yet.

Tests exercise branch coverage, early returns, retained incoming source fields,
read-before-store occurrences, aliases, partial writes, unchecked interference
and missing provider contracts. A generated hook omits the overwritten field
while preserving the object binding, and a native construction-time fixture
checks the body against ten different initial values. Writable replay still
requires an effect adapter: the reconstruction generator rejects these plans without a captured post-state or
a separate effect adapter, even when the incoming snapshot has no scalar fields.

`tests/test_entry_state_argument_dominance.py` compares generated full/reduced
hooks around a native C fixture with five nonnull calls and a null root. Each
nonnull reduced entry captures only four scalar bytes (`other`) rather than
eight (`value` plus `other`); the scalar input argument and object metadata are
unchanged. This is a 50% reduction in this fixture's object scalar payload,
not a measurement of whole-capture size or kernel overhead. The replayed body
must produce the omitted `value`; post-state snapshots only compare its result.
Host replay verifies the omitted field starts at zero, while AArch64 ELF/raw
images execute six independent calls at two load addresses. A target mutant
computes the correct return without writing and fails the post-state check.
Continuous replay rejects the incomplete entry footprint. Branch/alias
barriers and twelve missing/invalid contract cases keep
the earlier proof limits explicit. No live policy enables this stronger pruning.

Run `python3 tests/test_entry_state_argument_dominance.py --out build/argument-dominance`
to retain a fresh pair of images with plans and normalized full/reduced captures.
Accepted images and captures are retained in `build/argument-dominance-final-v1`
at load addresses `0x40200000` and `0x40400000`. All 22 regression suites passed,
and all five earlier retained argument profiles still exported successfully.
`build/argument-dominance-validation-20261020.json` records the payload counts,
standalone checks and source/artifact hashes.

### Sequenced comma-expression stores

The opt-in omission pass now evaluates an isolated C comma operator from left
to right. For `return (left->value = input ^ left->other, left->value);`, a full
typed store covers the following load under the same explicit identity,
isolation and state-preservation contracts. Parentheses, casts and nested comma
operators retain that sequencing. Both callable provider roots and argument
bindings use the rule; no new policy promises are inferred.

This applies when the comma operator is the expression currently evaluated.
An enclosing addition or call argument list with effects remains conservative:
the pass observes nested reads without creating new store facts. Conditional
stores on only one path, compound/partial writes, intervening stores
and boundary calls still prevent coverage where appropriate. This is not a
general C sequencing or interprocedural dataflow proof.

Assignment operands need separate treatment because their evaluation order is
not fixed. If evaluating the target may have effects, all prior facts are
cleared before observing either operand. A sequenced store in the right operand
also cannot cover a target-side load that might have occurred earlier. For
`left->array[left->value & 3U] = (left->value = 4, left->value)`, the right-hand
comma's load can be omitted, while the target index's incoming `value` load
remains captured. This also fixes retention for an earlier store followed by
an assignment whose target provider lacks a state-preservation contract.

`tests/test_entry_state_sequence_dominance.py` covers fourteen expression cases,
the two-sided assignment-index case and a contracted-provider comma case.
Generated full/reduced hooks capture a native C fixture with five nonnull calls
and one null call. Its object scalar payload is eight versus four bytes per
nonnull entry; scalar arguments and metadata are unchanged. Independent host
and AArch64 replay produce the omitted field from the comma-expression body.
An omitted-write mutant returns the correct value but fails post-state
validation. Live policies remain conservative, and pruned entry footprints
still require independent replay.

Run `python3 tests/test_entry_state_sequence_dominance.py --out build/sequence-dominance`
to retain a fresh pair of ELF/raw images and normalized captures.
Accepted evidence is retained in `build/sequence-dominance-final-v1` at
`0x40200000` and `0x40400000`. All 23 regression suites passed, and all five
earlier retained argument profiles still exported successfully. The retained
images also passed after removal of their temporary construction directory.
`build/sequence-dominance-validation-20261020.json` records these checks,
payload measurements and source/artifact hashes.


### Conditional and short-circuit paths

The opt-in proof now follows the guaranteed evaluation order of standard C
`condition ? then_expression : else_expression`, `&&` and `||` when evaluating
those expressions directly. The condition/left operand is evaluated first.
Each conditional arm starts with the same resulting facts; facts that continue
afterward must be shared by both arms. Logical right operands can use left-side
facts, but continuation facts must also hold when the right operand is skipped.
No constant-condition folding or truth-sensitive inference is performed.
Shared source-store locations are deduplicated when paths join, so repeatedly
merging inherited facts does not duplicate evidence exponentially. A configured
fixture with 40 short-circuit joins and 40 structured-if joins retains one
covering-store witness.

For `return input ? (left->value=4,left->value) : (left->value=5,left->value);`,
both selected-arm loads are covered. In
`return (input ? (left->value=4) : 0,left->value);`, the final load still needs
incoming state because one path skips the store. Likewise, a load used by the
condition is observed before branch stores; it cannot borrow their values.
The existing assignment-operand safeguards, interference barriers, strong
binding contracts and direct-scalar restriction remain in force. Enclosing
unsequenced expressions, loops, helper contexts and GNU omitted-middle `?:`
remain conservative.

`tests/test_entry_state_conditional_dominance.py` checks 21 expression cases,
including nested choices, both-arm/one-arm merges, short-circuit skip paths,
condition reads, assignment-index reads and effectful targets. A generated
native fixture chooses branches using captured `input` and `other` bits, then
writes `value` in either nonnull branch. Full/reduced hooks record five nonnull
calls and a null call. Object scalar payload remains eight versus four bytes
per nonnull entry; scalar arguments and metadata are unchanged. Standalone
replay recomputes the condition and writes instead of consuming captured branch
decisions. Wrong branch selection and omitted writes fail target checks.

A read omission does not prove a field is written on every invocation. A
separate native fixture skips a write on some calls, preserving a nonzero
incoming value that is absent from the reduced read footprint. Independent
zero-initialized replay must then fail the captured post-state check. The
regression verifies both such mismatches; it does not fill missing inputs from
expected outputs or relax preservation checks. Writable replay still needs
reproducible complete post-state, and pruned footprints still require
independent replay. Live policies do not enable these stronger omissions.

Run `python3 tests/test_entry_state_conditional_dominance.py --out build/conditional-dominance`
to retain a fresh pair of ELF/raw images and full/reduced normalized captures.
Accepted images and captures are retained in `build/conditional-dominance-final-v1`
at `0x40200000` and `0x40400000`. All 24 regression suites passed; the four
overwrite-proof suites passed again after evidence deduplication. All five
earlier retained argument profiles still exported successfully, and the images
also passed after removal of their temporary construction directory.
`build/conditional-dominance-validation-20261020.json` records these checks,
preservation failures, payload counts and source/artifact hashes.

### Incoming values preserved by skipped writes

`--prune-written-fields --preserve-write-state` adds eligible incoming scalar
values that replay needs when a write may skip. This is separate from source
read discovery: `entry_reads` remains the pruned read footprint, while
`preserved_entry_fields` records retained write inputs with their source-write
metadata and the reason that an every-exit overwrite was not proven.

The structured proof intersects full typed store facts at every return and
normal fallthrough. Both conditional arms must establish the same store.
Early returns can prevent an unconditional proof;
unsupported loops, switches and jumps disable exit-store guarantees. Calls and
other interfering effects clear facts. A later write can clear an earlier
store fact even for a different field, retaining extra input conservatively.
There is no general truth-sensitive or interprocedural store proof. Direct
argument-null guards have the narrow coverage rule described below.

Direct scalar fields and supported indexed scalar elements qualify.
Their object contract must explicitly set `snapshot_safe`, `stable_identity`,
`exclusive_state` and `preserves_entry_state` to true. The generated hook and
reconstruction reject projections that do not match a discovered write or
these contracts. Pointer writes and arbitrary buffers do not gain this
preservation support. Nested scalar paths have additional requirements
described below. Existing read-only pruning behavior is
unchanged, and live capture policies do not enable the new option.

`tests/test_entry_state_write_preservation.py` covers nine source patterns,
void fallthrough, projection tampering, missing input and invalid option
combinations. Its native fixture skips writes for two nonzero incoming values
that read-only pruning cannot independently replay. With preservation enabled,
five nonnull entries contain `other` plus incoming `value`: eight scalar bytes
each, matching the full footprint for this fixture. A sixth entry has a null
root. Replay receives these inputs only from entry snapshots; captured outputs
remain checks. Zeroing a skipped value or corrupting its captured input fails
the standalone post-state check even when the return value is correct.

Run `python3 tests/test_entry_state_write_preservation.py --out build/write-preservation`
to retain captures and ELF/raw images at `0x40200000` and `0x40400000`.
Accepted captures and images are in `build/write-preservation-final-v3`.
Both image pairs also passed after their temporary construction directory was
removed. All 25 regression suites passed, including fresh live captures; all
five earlier argument profiles re-exported successfully with unchanged
footprints. `build/write-preservation-validation-20261020.json` records the
checks, payload costs, conservative limits and source/artifact hashes.

### Direct argument-null exits in overwrite coverage

Preservation mode recognizes `if (!argument) return ...;` and the null `else`
arm of `if (argument)`. Parentheses and implicit conversions are allowed; the
null arm must be a single immediate pure return, optionally inside braces.
The tested declaration must be a configured root argument whose entry binding
is unchanged. Any assignment to that parameter or taking its address anywhere
in the function disables the rule. Aliases, explicit casts, comparisons,
compound predicates, multi-statement null arms and effectful returns retain
the existing conservative behavior.

A proven null exit is excluded only from overwrite coverage for that argument's
fields. It cannot exempt another argument's fields, even if the bindings can
alias on other calls. Every remaining exit must still establish the full typed
store. This rule changes preservation input selection only: default may-read
discovery, read omission and nested-store proof limits are unchanged.
`write_state_preservation.null_guard_exit_proofs` records the root and guard/
return locations. Guaranteed store evidence records `excluded_null_exits` when
this rule applies. Unsupported control flow still disables exit guarantees.

`tests/test_entry_state_null_guard.py` checks 15 guard/control patterns and a
second-root counterexample. Its native fixture fully overwrites `value` after
a null guard. With preservation enabled, five nonnull entries capture only
four scalar bytes (`other`) instead of eight; the sixth null entry has no
scalar fields. All six post-states still require replay to perform the store.
Two relocated standalone AArch64 ELF/raw image pairs verify the reduced
footprint. An implementation that returns the right result while omitting the
store fails its first post-state check. Live policies remain conservative.

Run `python3 tests/test_entry_state_null_guard.py --out build/null-guard`
to retain normalized captures, source evidence, images and fault observations.
Accepted artifacts are in `build/null-guard-final-v2`. Both image pairs passed
again after removal of their temporary construction directory. All 27
regression suites passed, including fresh live captures, and all five retained
argument profiles re-exported successfully. The proof evidence, payload counts
and source/artifact hashes are recorded in
`build/null-guard-validation-20261020.json`.

### Nested incoming scalar preservation

The same opt-in mode now preserves incoming scalar fields reached through
object-pointer paths. Every prefix must already be a captured nonvolatile
object-pointer read, and no source-visible write may target a prefix. The
root contract's snapshot-safety, stable-identity, exclusive-state and
state-preserving-binding promises apply to the reachable objects for the
complete call. There is no new nested store-omission proof: eligible nested
write inputs are conservatively retained even for unconditional stores.

Capture records logical object IDs, pointer edges and incoming scalar bytes.
Reconstruction uses only entry edges to resolve the destination. Its existing
write checks reject traversal edges that alias a writable field under another
root, even if the captured entry and exit pointer values are identical.
Projection validation also rejects missing or malformed edge reads, weakened
contracts, pointer-valued preservation fields and paths absent from the
discovered write footprint. Pointer mutation and arbitrary buffers retain
their existing restrictions.

`tests/test_entry_state_nested_preservation.py` captures four calls that
conditionally assign through `current()->next->next`. A distinct third object
starts with value 41; entry/post values are `[41,41,2,2]` and `[41,2,2,4]`.
The scalar is never read by the source body. Default discovery omits it;
preservation captures it before each call. The same fixture covers aliases,
cycles, null edges and argument-backed nested capture. Independent replay
restores four entries. With complete entry state and capture-scoped identities,
continuous replay restores once and checks all four entries and exits.

Standalone ELF/raw images at `0x40200000` and `0x40400000` cover both modes.
Zeroing a skipped value, omitting a selected write and writing the wrong owner
fail post-state checks despite correct return values. This remains a native C
fixture; live kernel policies do not enable preservation or stronger omissions.
Run `python3 tests/test_entry_state_nested_preservation.py --out build/nested-preservation`
to retain the captures, image pairs and fault observations.
Accepted artifacts are in `build/nested-preservation-final-v2`. All four
image pairs passed again after removal of their temporary construction
directory. All 26 regression suites passed, including fresh live captures;
the five previously retained argument profiles also re-exported successfully.
`build/nested-preservation-validation-20261020.json` records the evidence,
payload cost, scope limits and source/artifact hashes.

## Request-driven entry-state export

`tools/export_entry_state.py` provides one exporter for the supported typed
state subset. It consumes existing discovery reports and normalized captures;
no function name, field list or kernel profile is hard-coded in this path.
A request chooses a plan per invocation and supplies reviewed target-native
types and an adapter implementing `uint32_t osrec_invoke(uint32_t number)`.

```json
{
  "format": "osrec-entry-replay-request-v1",
  "mode": "continuous",
  "plan": "plan.json",
  "entries": "entries.json",
  "post_states": "posts.json",
  "model_header": "model.h",
  "adapter_header": "adapter.h",
  "files": {"functions.c": "functions.c"},
  "translation_units": ["functions.c"],
  "calls": [
    {"root": "update", "number": 101, "raw_bits": 99},
    {"root": "query", "number": 102, "raw_bits": 140}
  ]
}
```

Paths resolve relative to the request. `plan` is an
`osrec-entry-state-plan-v1` report. Entry/post files can be snapshot arrays or
the existing `osrec-live-entry-state-v1` / `osrec-live-entry-effects-v1`
bundles. Calls and snapshots have the same order and count. Each root must
select a unique plan; each route selects one root. Captured route tags must
agree, and paired entry/post invocation tags must match. `number` is an
unsigned 32-bit adapter route; it need not be an OS syscall number. Return
values use unsigned 32-bit `raw_bits`, including a reviewed completion marker
for void adapters. Post-state is required for writable plans.

The model header declares semantic types and interfaces; the adapter binds
providers and invokes the selected body using reconstructed arguments. Extra
headers/sources can be listed in `files`, using distinct flat names. Only
declared `.c` files in `translation_units` compile as separate units. Generated
headers, startup and linker files are reserved. Models and adapters remain
explicit review inputs; this tool does not infer kernel dependency models or
attest that supplied function bodies match native capture source.

```sh
python3 tools/export_entry_state.py --request request.json --check-only
python3 tools/export_entry_state.py --request request.json --out build/replay
```

Preflight selects plans and runs the existing typed reconstruction checks.
It rejects unsupported storage/effects, missing inputs and incomplete continuous
state. JSON diagnostics identify input, call, reconstruction or build/verification
failures. Check-only validates reconstruction; it performs no compilation or
target execution. Export compiles a static AArch64 image, audits dependencies,
relocations and service traps, executes ELF and raw images, and verifies every
return and state check before publishing a new output directory. Failed builds
or replay leave the output unpublished.

The bundle includes `request.json`, retained `inputs`, generated `sources`,
`entry-state.elf`, `entry-state.bin`, a result record and a hashed manifest.
Its request can rebuild independently of the original input paths. Both the
original and portable requests are retained and hashed. Generic
export records `native_capture_attested: false`: capture frontends still own
native source/witness verification. The existing live argument exporter retains
those checks and now shares `entry_state_image.py` for construction and target
verification. The generic exporter does not weaken reconstruction contracts.

Current target support is AArch64. Sessions of one through seven calls retain
ABI 8; eight through 256 calls use the bounded ABI 30 transcript described below.
Continuous mode still requires complete field footprints, capture-scoped
identities and supported graph/lifetime behavior. General buffers, arbitrary
pointer mutation, concurrency and external-event reproduction require additional
models. This is a reusable path through the supported subset, not a claim of
whole-kernel state completeness.

`tests/test_entry_state_export.py` captures interleaved writer/reader roots on a
shared graph, including a skipped nested write. Separate function translation
units replay at two load addresses in independent and continuous modes. The
published request rebuilds after the original input directory is deleted.
Diagnostics and rejection tests cover mismatched captures, unavailable effects,
missing fields, reserved filenames, unsupported call counts and invalid roots.
Correct returns with a missing store and invalid C source both prevent publication.
Run it with `--out build/general-export` to retain the four bundles and faults.
Accepted mixed-root bundles are in `build/general-export-final-v3`; their four
image pairs passed again after the temporary construction directory was removed.
All 28 regression suites passed, including fresh live captures. The three
generic-export test cases passed again after request-hash retention was added.
All five retained live argument profiles exported through both the shared
backend and generic requests. Their raw images and result records match the
previous profile exports byte-for-byte. Generic live requests are retained in
`build/general-export-live-requests-v1`, and the final generic live bundles use
the `build/rtl-*-generic-request-v2` paths.
`build/general-export-validation-20261020.json` records the hashes and checks.

### Generated typed replay dispatch

A replay request can now declare invocation routing instead of supplying a
handwritten `osrec_invoke` implementation:

```json
"dispatch": {
  "format": "osrec-entry-dispatch-v1",
  "sites": [
    {"root": "update", "number": 101, "return_kind": "u32"},
    {"root": "query", "number": 102, "return_kind": "u32"}
  ]
}
```

With this field, `adapter_header` supplies original function bodies or declarations
and explicit dependency/provider implementations. It must leave `osrec_invoke`
to the generator. Separate original C translation units remain supported.
Each route/root declaration is unique and must agree with the captured calls.
Only roots actually called emit dispatch code, so unused declared sites need
no reconstruction bindings in the image.

The generator obtains object-pointer arguments from the plan's validated root
bindings and 32-bit integer arguments from the captured invocation/argument
slots. It preserves argument order, nulls, aliases and const pointee types.
Signed arguments and returns retain their target 32-bit representation; void
calls produce zero completion markers. Each invocation calls its original root
once. Compilation checks the complete original function-pointer type against
the plan's parameter types and declared return kind, plus scalar widths and
signed conversion behavior. Unsupported parameter types or unbound pointers
reject; there is no fallback to guessed argument values or pointer addresses.

Routing is checked against the expected invocation, including session exhaustion.
An invalid route or extra call invokes `replay_fault`; a legitimate
`UINT32_MAX` return cannot serve as an error sentinel. Generated dispatch does
not initialize or repair state: the existing independent/continuous reconstruction
and post-state checks retain that responsibility.

Capture specifications opt in with `"replay_dispatch": "generated"`; import
propagates the site's routing declarations into the generic request. Existing
specifications and requests retain their reviewed adapter behavior. Check-only
validates dispatch structure and bindings after reconstruction, with errors at
stage `dispatch`; original function ABI checks require compilation. Published
requests retain the dispatch declaration and original adapter inputs, so they
regenerate dispatch when rebuilt. The manifest hashes generated dispatch and
the complete compiled adapter source separately from supplied input hashes.

The native shared frontend also supports:

```sh
python3 tools/live_shared_capture.py --capture build/live-mixed-final-v1/capture \
  --generated-dispatch --out build/generated-live-replay
```

It performs all existing native capture/source/witness/request checks, then
obtains the original helper bodies directly from pinned source and generates
routing from the validated capture sites. Its sidecar binds both that generated
dispatch hash and the generic image manifest to the native evidence. This works
for the six-write session and seven-call mixed session without their handwritten
invocation adapters. Dependency models, source attestation, fixed lifetimes,
synchronization and the configured session bound remain explicit frontend contracts.

`tests/test_entry_state_dispatch.py` exercises both replay modes, two load
addresses, portable rebuilds after original inputs are deleted, signed limits,
void calls, multiple const/mutable pointer arguments, aliases and nulls. It
rejects malformed dispatch declarations and incompatible return/parameter ABIs,
and tests invalid-route/exhaustion faults with a valid all-bits result.
`tests/test_live_generated_dispatch.py` verifies native-backed exports at both
addresses with unchanged result records, and catches incorrect query returns
and unexpected stores through the generated path. Accepted bundles are in
`build/generated-dispatch-final-v3` and
`build/generated-dispatch-native-final-v4`; evidence is recorded in
`build/generated-dispatch-validation-20261020.json`.
All 33 regression suites passed, including fresh shared and mixed kernel captures.
The final five dispatch cases and native export case passed again after fixing
a route-parameter/root-name collision. Twenty-four standalone executions passed
for the retained bundles after construction cleanup, and seven earlier profile
exports retained byte-identical raw images/results. The native-backed CLI and
check-only path passed; malformed dispatch produced a `dispatch` diagnostic.

### Longer capture and replay sessions

The generic path supports up to 256 calls. It chooses ABI 8 for one through
seven calls, preserving the short-session result layout, and ABI 30 for eight
through 256 calls. Existing requests need no format change. Capture specifications
opt in to a larger caller-owned session with, for example:

```json
"max_calls": 33,
"replay_dispatch": "generated"
```

Compile every translation unit that uses `entry_capture.h`, including both
capture runtime files, with the same `-DOSREC_CAPTURE_CALLS=33` configuration.
The generated wrapper asserts that its configured capacity equals the explicit
specification. The default remains seven; merely updating the tools does not
allocate a larger buffer in the live kernel. Capacity must be an integer from
one through 256, and import rejects records beyond the specification's bound.
The caller still owns preallocated storage, object lifetimes and synchronization.
Snapshot and object-identity capacities are unchanged. Session storage grows
with its configured capacity; this is not a measured overhead result.

ABI 30 retains a 128-byte control header and appends one eight-byte
`(route, raw result)` record per configured replay call. The result symbol is
exactly `128 + 8 * call_count` bytes, at most 2176 bytes. No guest pointer selects
the transcript location. Header words 10 through 13 declare capacity, eight-byte
stride, fixed offset 128 and transcript version 1. Existing entry-state counters
and mode flags retain their header positions. Reserved words must be zero.
The result transcript contains actual recomputed results; expected results
remain separate in the checkpoint.

The linker asserts the exact expected result extent. ELF inspection requires
the complete result symbol to fit a writable segment. The observer first reads
the control header, stops the guest at terminal status, and validates its count,
layout, flags and progress against the ELF-derived result size before reading
the bounded transcript. It rejects a changed/incomplete read. Legacy ABIs still
require a 128-byte result symbol. ELF/raw comparison includes all result bytes,
and verification checks every call and state, not just the first seven.

Long-session divergence codes have separate ranges: `0x10000 + invocation` for
return mismatch, `0x20000 + invocation` for post-state mismatch, and
`0x30000 + invocation` for entry-state mismatch. Invocation numbers are zero
based. Short-session error codes are unchanged. Continuous replay still restores
once; independent replay restores each invocation.

`tests/test_entry_state_long_session.py` captures 33 original mixed-root helper
calls through generated wrappers, imports them, and replays both modes at two
addresses. Portable requests rebuild after original inputs are deleted. Late
faults at invocation 25 distinguish an incorrect return from an unexpected store.
A separate 256-call scalar capture reaches the supported maximum. Tests reject
invalid capacities, capacity/compiler mismatch, overflow, over-limit import and
requests, malformed headers and incompatible result extents. Overflow invalidates
recording while the original function still runs.

Accepted bundles are in `build/long-session-final-v4`. This extends general
capture/import/replay infrastructure; the original fixed LiteOS call-site
profiles still select their existing six- or seven-call batches. The
[configured live frontend](#configured-live-helper-sessions) extends the same
infrastructure to supplied sequences. Natural call-site selection, dynamic
object lifetimes and concurrent capture remain separate work.
Evidence is recorded in `build/long-session-validation-20261020.json`.
All 39 selected suites have passing final results. The initial broad run had
three timeouts (`freestanding_task`, `live_entry_state`, `live_argument_state`);
all three passed separately without implementation changes. Both runs are
retained, and the cause of the timeouts is not established. The final six focused
long-session cases passed. Fourteen standalone ELF/raw executions plus four EL3
executions with complete loaded-memory/CPU-entry checks passed after construction.
Eleven earlier short-session exports retained byte-identical raw images/results.

## Shared call-site capture

`tools/entry_capture.py` connects selected call sites to the request-driven
exporter. It generates wrappers from an existing typed plan report and a capture
specification. This integrates at caller-selected sites; it does not rewrite an
arbitrary kernel or choose call sites automatically.

```json
{
  "format": "osrec-entry-capture-spec-v1",
  "mode": "continuous",
  "contract": {
    "fixed_lifetimes": true,
    "exclusive_capture": true,
    "reason": "The selected objects remain live across this session",
    "implementation": "Caller holds the required synchronization"
  },
  "sites": [
    {"root": "update", "number": 101, "return_kind": "u32"},
    {"root": "query", "number": 102, "return_kind": "u32"}
  ],
  "model_header": "model.h",
  "adapter_header": "adapter.h",
  "files": {"bodies.c": "bodies.c"},
  "translation_units": ["bodies.c"]
}
```

```sh
python3 tools/entry_capture.py generate --plan plan.json --spec capture-spec.json --out capture.h
```

Include the generated header after the original types/function declarations.
Link `runtime/entry_capture.c` and `runtime/entry_snapshot.c`. Allocate the
session outside the kernel stack, for example as caller-owned static storage:

```c
static struct osrec_capture_session session;
osrec_capture_init(&session);
unsigned result = osrec_capture_update(&session, input);
/* Additional selected calls under the caller's lifetime/synchronization contract. */
int ok = osrec_capture_json(&session, OSREC_CAPTURE_PLAN_SHA256,
                           OSREC_CAPTURE_SPEC_SHA256, write_bytes, context);
```

`write_bytes(context, data, bytes)` returns nonzero only when it accepts the
entire chunk. The caller owns transport buffering and completion handling.
The transport callback must not capture into or reset the same session.
The runtime does not allocate memory, take locks or perform host I/O. Serialization
can run after capture under a caller-appropriate output contract; it uses copied
field/argument bytes and recorded logical IDs, not live object dereferences.
Metadata string storage must remain valid through serialization.

Each wrapper evaluates its supplied C arguments through ordinary function-call
semantics and invokes the original body once. It snapshots the discovered entry
footprint, records unbound 32-bit scalar arguments, calls the original function,
then snapshots the read/write effect footprint. Object-pointer arguments need
the existing explicit root-object contracts; arbitrary pointers remain blocked.
`u32`, `i32` and `void` return kinds have compile-time ABI checks. Signed results
retain their 32-bit representation; void calls use a zero completion marker.
The wrapper returns the original function result and preserves its side effects
even when recording fails.

Snapshots use the selected plan's entry reads and preservation projections.
Discovery options and their stronger contracts still matter: this frontend does
not silently expand or prove completeness of an incomplete write-only footprint.
The generic replay verifier still checks all captured post-state effects.

Sessions have one owner, seven calls by default, sixteen scalar argument slots per
call and the existing snapshot/object-identity bounds. The caller guarantees
fixed object lifetimes, no address reuse, and the synchronization promised by
the selected plans/specification. Mixed roots are supported. A nested capture,
overflow or snapshot/identity failure invalidates the session; serialization
rejects failed, empty or active sessions before output. Transport failure returns
failure and the caller must discard incomplete output. Reinitializing starts a
new session. This is a bounded reference collector, with no measured low-overhead
or concurrent-capture claim.

After extracting a complete JSON session through the chosen transport:

```sh
python3 tools/entry_capture.py import --plan plan.json --spec capture-spec.json \
  --capture capture.json --out build/captured-request
python3 tools/export_entry_state.py --request build/captured-request/request.json \
  --out build/captured-image
```

Import requires the exact plan/spec hashes embedded in the generated wrapper,
registered root/route pairs, sequential invocation IDs, matching entry/post
arguments and supported typed reconstruction. It retains the raw session, plans,
specification, reviewed replay inputs and hashes. Failed import publishes no
request. Import verifies input binding and reconstruction, not native kernel
source/binary identity; `native_source_attested` remains false. Image construction
and execution are separate checks performed by the generic exporter.

`tests/test_entry_capture.py` runs generated native wrappers, serializes through
the shared runtime, imports the sessions and exports standalone images. Mixed
writer/reader sites replay at two addresses in independent and continuous modes.
A second fixture covers object arguments, signed/void results and a null root.
Tests check capacity/reentrancy behavior, callback failure, ABI mismatches and
tampered plan/spec/record bindings. Run with `--out build/shared-capture` to retain
the generated headers, native capture projects, imported requests and images.
The base runtime/wrappers are validated here with native C fixtures and
freestanding target compilation. The first live integration follows below.
Accepted artifacts are in `build/shared-capture-final-v3`, including four mixed-root
ELF/raw pairs and one argument/void/signed pair. All five pairs passed again after
the temporary construction directory was removed. All 29 regression suites
passed; the four capture cases also passed after generator naming safeguards
were added. The public generate/import/export CLI path passed, and all five
retained live argument profiles still exported successfully. The freestanding
AArch64 runtime object has only the existing snapshot identity/init helpers as
undefined dependencies. `build/shared-capture-validation-20261020.json` records
these checks, source hashes and artifact hashes.

### Live kernel integration of shared wrappers

```sh
python3 tools/liteos_qemu_demo.py --shared-argument-capture --out build/live-shared
python3 tools/live_shared_capture.py --capture build/live-shared --out build/shared-replay
```

This opt-in profile selects the existing locked current-process signal-helper
session. It generates a wrapper for the original
`OsProcessExitCodeSignalSet(LosProcessCB *, UINT32)` from the discovered plan,
compiles the shared runtime into the pinned LiteOS-A build, and replaces the
direct helper invocation with that wrapper. It uses a `void` result contract
and zero completion markers. The existing legacy snapshots and direct RAM
before/after observations surround the same calls; the helper is not invoked
again to produce a second comparison trace.

All six calls run on the real PID 1 process inside one scheduler-lock region.
Signals `[1,2,128,4,0x80000008,16]` produce entry values `[0,1,3,3,7,15]` and
exit values `[1,3,3,7,15,31]`. The direct witness records initial/final/restored
values `(0,31,0)`. The real field is restored once before unlock. Shared records
remain snapshots of the helper session before that capture-adapter restoration.
The wrapper's session lives in static storage. Later report generation serializes
the copied records into a 16 KiB buffer and emits one `OSREC_SHARED_CAPTURE`
JSON line through bounded console chunks.

The host compares shared entries/effects with both legacy snapshots and the
direct field witness. Object session-ID namespaces are separate, so equality
comparison ignores their numeric labels and the legacy lifetime cursor while
still validating each namespace's stable identities. Plan/spec hashes must
match the exact generated inputs. Import publishes `shared-request/request.json`.
The native capture retains `shared-capture.json`, specification, generated
wrapper, runtime source/header, reviewed replay model/adapter and a verification
report alongside the legacy observations, boot log and actual kernel images.

`live_shared_capture.py` reloads the native source/capture checks before image
construction. It validates the retained kernel binary/ELF hashes, log binding,
helper source identity, shared/legacy/direct-witness equality, generated wrapper
and exact imported plan/model/adapter/call sequence. Imported request hashes must
also agree. It then delegates to generic export and adds
`native-capture-verification.json`, tying native source/witness and capture
hashes to the generic image manifest. The generic manifest retains its own
scope: it does not independently attest native capture provenance.

Continuous standalone replay initializes once, checks all six entries and exits,
and ends at 31. It does not reproduce kernel scheduling or execute the capture
adapter's restoration. `tests/test_live_shared_capture.py` boots a fresh kernel,
exports at two load addresses, checks corrupt capture/request/native files, and
rejects an omitted helper store despite correct zero result markers. It also
tests independent witness/legacy mismatches and duplicate/missing log records.
The test runs only with the live LiteOS QEMU regression option enabled.

This remains a controlled helper call site, single CPU, fixed process lifetime
and bounded session. Other roots, natural call-site selection, dynamic regions,
allocator transitions and concurrency require further integration/contracts.
Accepted evidence is in `build/live-shared-final-v2`: a fresh native capture,
two relocated ELF/raw pairs and an omitted-write fault observation. Both image
pairs passed again after their temporary construction directory was removed.
The native-backed CLI export also passed. All 30 regression suites passed,
including a second fresh shared-wrapper kernel run, and all five retained
argument profiles still exported with unchanged raw images/results.
`build/live-shared-validation-20261020.json` records the native/image hash chain,
scope limits and source/artifact hashes.

### Mixed-root live capture

```sh
python3 tools/liteos_qemu_demo.py --shared-mixed-capture --out build/live-mixed
python3 tools/live_shared_capture.py --capture build/live-mixed --out build/mixed-replay
```

This option inserts the original `OsProcessExitCodeSignalIsSet(LosProcessCB *)`
after the third signal write. Its source and argument boundary policy are pinned
separately. Both roots are discovered in the same plan and captured through
generated wrappers into one session. The original six writer calls retain their
legacy entry/effect comparisons and direct field witness. The query adds a
separate native witness `(wire position, before, raw result, after) = (3,3,3,3)`.
Its return is the low seven bits, so booleanizing `3` to `1` is incorrect.

The seven calls have entry values `[0,1,3,3,3,7,15]`, exit values
`[1,3,3,3,7,15,31]`, and raw results `[0,0,0,3,0,0,0]`. The query is readonly;
its post-state snapshot reuses its generated entry hook. Full continuous
reconstruction verifies stable object identity and state across both roots.
All calls remain inside the same scheduler-lock region, with the original field
restored once from `31` to `0` before unlock. This profile fits the seven-call
ABI 8 capacity; longer sessions use the separate bounded transcript ABI. It does not add arbitrary call-site discovery, dynamic object
lifetimes, concurrency or scheduling reproduction.

The native bridge validates the query's retained source identity, policy hash,
wrapper, log record, direct witness and imported request before generic export.
The verification sidecar binds both helper identities and witnesses to the image
manifest. `tests/test_live_shared_mixed.py` checks malformed ordering, routes,
results, identities and witnesses, then boots a fresh kernel and exports at two
addresses. Runtime mutations prove that both a booleanized query result and an
unexpected query store fail replay verification, even when the other property
is correct. Accepted capture and relocated images are retained in
`build/live-mixed-final-v1`; validation is recorded in
`build/live-mixed-validation-20261020.json`.
All 31 regression suites passed, including a second fresh mixed-root kernel
capture. Both relocated ELF/raw pairs passed standalone execution after temporary
construction files were removed. The native-backed CLI passed, and the five
retained argument profiles plus the earlier single-root shared capture reexported
with byte-identical raw images and result records.

### Configured live helper sessions

The live frontend now accepts a supplied sequence instead of requiring a new
hardcoded workload for each composition:

```sh
python3 tools/liteos_qemu_demo.py \
  --shared-session integrations/liteos_qemu/shared-session-example.json \
  --out build/live-configured
python3 tools/live_shared_capture.py --capture build/live-configured \
  --out build/configured-replay
```

Its input has format `osrec-live-helper-session-v1`:

```json
{
  "format": "osrec-live-helper-session-v1",
  "calls": [
    {"root": "OsProcessExitCodeSignalSet", "arguments": {"signal": 2}},
    {"root": "OsProcessExitCodeSignalIsSet", "arguments": {}}
  ]
}
```

Admission accepts one through 256 calls to these two reviewed original helpers.
Signal values are unsigned 32-bit integers; readers take no scalar arguments.
The kernel supplies the real PID 1 process binding. Call count determines both
the generated schedule and preallocated capture capacity, with a matching wrapper
assertion. Both roots are discovered under their existing pinned source/type and
argument-boundary contracts. The generated capture specification adds an explicit
fixed-lifetime/exclusive-session contract for the full configured batch. Replay
uses generated typed dispatch automatically; short sessions select ABI 8 and
long sessions select ABI 30.

The existing six-write legacy baseline still runs and restores its field first.
It is a separate set of original calls, excluded from the configured session.
The same existing scheduler-lock region then spans the entire configured batch.
Each generated wrapper invokes its original helper once. Independent RAM reads
surround that call, recording `(position, route, signal, before, raw, after)`.
The witness header records `(PID, count, initial, final, restored)`. The kernel
restores the initial field once after the configured batch and before unlock.
No second execution is used to produce a comparison trace for these calls.

Shared records serialize afterward from copied snapshots into a bounded buffer.
`shared-session-kernel.bin` retains the direct witness; `shared-session.json`,
`shared-session-schedule.h` and `shared-session-sources.json` retain the workload,
compiled schedule and both pinned helper identities. Validation checks every
entry/post field and scalar argument against the independent witness, original
helper semantics, sequence and restoration boundary. Full continuous reconstruction
checks identity and state across both roots. The earlier six-call baseline keeps
its separate legacy snapshot/witness validation.

Reload verifies the kernel images, native log and witness, source/model/schedule,
wrapper text, capture hashes and exact imported request before generic export.
The image sidecar binds these checks and the generated dispatcher to the generic
manifest. Its scope distinguishes the separate baseline from the configured
calls. Native provenance remains a frontend responsibility.

`tests/test_live_configured_capture.py` boots fresh kernels for the supplied
33-call example, a single read, and a 256-read maximum session. The example has
sixteen writes and seventeen queries, reaching `127` and restoring `0`; its two
relocated image pairs check all 33 entries and exits after one initialization.
The single read exercises ABI 8 with an unused declared writer site. The maximum
session exercises native capacity/transport and the 2176-byte ABI 30 result.
Negative cases cover workload admission, witness fields, arguments, identities,
source/schedule files, policy/hash binding, and late target faults at invocation 25.
Accepted artifacts are in `build/live-configured-final-v2`; evidence is recorded
in `build/live-configured-validation-20261020.json`.
All 35 selected suites have passing final results. Two existing native-reference
compile steps exceeded their 60-second deadlines in the initial run; their
isolated methods and complete suites passed with the same interpreter and no
implementation changes. Both runs are retained; the timeout cause is not established.
The five focused configured cases passed, including fresh kernels at capacities
1, 33 and 256. Eight retained ELF/raw executions and four EL3 executions with
loaded-memory/CPU-entry checks passed after construction. Eleven earlier exports
retained byte-identical raw images and result records. The native-backed CLI and
portable check-only request also passed.

This generalizes composition within the two reviewed helper contracts. It remains
a controlled, single-CPU, fixed-lifetime experiment under explicit locking;
arbitrary roots, automatic site selection, allocator transitions and scheduling
reproduction are outside this frontend. Capture latency and overhead are unmeasured.

## Captured scalar write effects

The live pipeline now emits `entry-state-effects.json`: six `SysUmask` exit
snapshots generated from the union of its discovered reads and writes, sampled
under the scheduler lock. Entry snapshots also record the syscall's 32-bit mask
argument. The report hashes the effect bundle alongside entry snapshots, plans
and hooks. Serialization still contains logical IDs and scalar bytes only.

Build the generated writable AArch64 image with:

```sh
python3 tools/export_freestanding_umask.py --automated-entry-state \
  --capture build/live-entry-write-effects \
  --out build/rtl-aarch64-generated-umask-effects
```

`reconstruction_header(..., post_states=..., scalar_arguments=True)` restores
entry fields and captured 32-bit integer arguments, then emits
`osrec_state_matches` checks for the captured post-state. Expected output bytes
are used only in checks, never in restoration. This supports a field omitted by
must-store pruning: its object is still allocated, but the replayed body must
produce the expected value. Readonly plans keep their unchanged-state checker.

The independent writable subset includes scalar provider fields, supported indexed
scalar elements and nested scalar fields reached through stable captured pointer
edges. Exit roots, object IDs/types and the field footprint must agree
with the entry graph; extra/missing fields and width changes fail. Fields outside
the write footprint must retain their entry bytes. Pointer writes,
bitfields, volatile fields, aggregate writes and object graph
changes require a separate adapter. Independently normalized exit graphs are
used here for scalar updates on the same provider objects; this does not prove
allocation/lifetime continuity. Continuous replay also supports restricted
pointer rebinding, as described below.

Nested scalar destinations are resolved against the entry snapshot's logical
object IDs. For `current()->next->next->value += step`, write permission applies
to the reached object's `value`, including when aliases or cycles lead back to
a root object. Null paths grant no field-write permission. Intermediate edges
must be captured at entry and must not themselves appear in the resolved write
footprint, even through another provider alias or a write that leaves the edge
unchanged. This prevents transient pointer changes from making the actual write
destination ambiguous. Nested pointer writes remain unsupported.

`tests/test_entry_state_nested_effects.py` captures a native C fixture through
generated hooks, then checks independent and continuous host reconstruction for
chains, aliases, cycles and null paths. Continuous AArch64 ELF/raw replay checks
four entry/post pairs at two load addresses. Wrong-object and omitted-write
mutants fail despite matching return values. A write-only nested field works in
independent replay; continuous replay rejects its incomplete entry footprint.
Run `python3 tests/test_entry_state_nested_effects.py --out build/nested-effects`
to retain a fresh pair of images and their normalized capture manifests.
This is fixture coverage, not a
live-kernel nested-write capture. Retained images and normalized snapshots are
in `build/nested-effects-final-v1`; validation is recorded in
`build/nested-effects-validation-20261020.json`. All 20 entry-state regression
suites passed, including the earlier live capture profiles. The final pointer
and nested-effect suites also passed after adding the write-only fixture.

Result ABI 8 word 7 now reports verified states and word 9 records write-effect
mode (1 for captured post-state, 0 for readonly). The observer reports
`states_verified` in both modes and `unchanged_states` only for readonly mode.
The generic runner restores every invocation independently by default. The older umask
export path still reproduces a sequential session; the default generated effect path
does not establish continuity between invocations. Continuous mode is described
below.

Tests check unchanged fields, missing effects, graph/schema disagreement,
argument widths and high-bit arguments, omitted incoming fields and rejection
of unsupported writes. Live tests compare generated exit masks with independent
kernel observations, execute the AArch64 ELF/raw images and inject an incorrect
exit mask while preserving recorded hashes: target validation must fail before
publishing an image. RTL timing and general memory-effect inference remain
unvalidated.


## Continuous sessions

Generated `SysUmask` replay can now preserve state across calls:

```sh
python3 tools/export_freestanding_umask.py --automated-entry-state --continuous \
  --capture build/live-entry-state-continuity-final \
  --out build/rtl-aarch64-continuous-umask
```

Fresh captures attach a `session_id` to each object at snapshot time using one
transient lifetime table for the capture. Addresses remain construction-time data and are
never serialized. Frame-local `id` values still name field owners and edge
references; equal frame-local IDs do not imply cross-frame identity. Continuous
replay uses the separate capture-scoped IDs to allocate one set of target-native
objects. A frame may renumber its local IDs while retaining its session IDs.

Continuous generation requires a fixed object set, root bindings, field widths and
complete field footprint for the selected sequence. Each captured post-state
must equal the next captured entry after canonicalizing references to session
IDs. Discontinuities, missing/duplicate session identities, object-set changes and
incomplete footprints fail before image publication. A field omitted from the
first entry cannot silently be initialized using a later captured value; such
pruned footprints currently require independent replay or a separate adapter.

Only invocation zero is restored. Every invocation checks its incoming state
with `osrec_entry_matches` before executing, then checks returns and captured
exit fields. Later entries and all exits are comparisons, never assignments.
`osrec_restore` rejects later invocation indices in continuous mode without
changing storage or bindings. This preserves updates made by the replayed code
and detects unexpected changes between calls.

The capture report includes an explicit stable-lifetime scope for the PID 1
process during its six umask calls in the configured workload. The loader
requires that contract for continuous export. The transient identity table does
not track allocation generations or detect reuse of a freed address: other
lifetimes require an adapter contract or allocation-event capture. This is
captured state continuity, not a scheduler/interrupt or physical-lifetime
proof. Allocation/free events and changes to the object set remain blocked.

Direct provider pointer fields may now be rebound in continuous mode to null or
another object already present in the initial captured footprint. Typed plans
must identify the field as a write of a single object pointer; nested pointer
writes, pointer-to-pointer and function-pointer fields remain unsupported.
Entry/post pairs must retain the same local-to-session identity mapping. All
unwritten edges are checked for equality, and generated C checks target pointer
types at compilation. Post-state edges are comparisons only: captured outputs
are never used to perform the rebinding on behalf of the replayed function.

The pointer-effect test analyzes a C fixture, captures its native execution using
generated hooks and the snapshot runtime, then executes four calls in AArch64
ELF/raw images. It covers rebinding, null, aliases and cycles, plus a wrong-target
fault where both objects have equal scalar values and the return remains correct.
It rejects new objects, changed identities, provider rebinding and unwritten edge
changes. This establishes functional fixture coverage. Live `SysSetGroups`
allocation and pointer-replacement capture is available with a reviewed dynamic
replay adapter described below.

Result ABI 8 word 24 marks continuous mode and word 25 counts incoming-state
checks. Continuous success requires one restoration, all incoming-state checks
and all exit checks; independent mode still requires one restoration per call.
The manifest records the selected mode and whether continuity was reproduced.
Both ELF and raw images execute with guest host services disabled. Tests verify
renumbered local IDs, one shared object allocation, invalid later restoration,
discontinuities, missing identity/lifetime contracts and target failure when a
field is changed between calls. RTL timing remains unvalidated.

## Allocation generation capture

`runtime/object_lifetime.c` records existing-object, allocation and release
events without exporting addresses. It reuses bounded tracking slots but never
reuses logical IDs: allocation at an address whose previous object was released
gets a new ID, even if the type and bytes are unchanged. Snapshots store their
IDs and event cursor immediately, so later report serialization cannot relabel
an earlier snapshot using a newer allocation at the same address.

The hook API requires serialized calls and complete allocator/free coverage in
its declared scope. Seed existing objects with `osrec_lifetime_observe`, seal the
initial object set, and use `osrec_lifetime_allocate` / `osrec_lifetime_release`
for subsequent events. Null allocation results and `free(NULL)` add no event.
Duplicate allocation, unknown release/reference, ID exhaustion, more than 32
simultaneously live objects, or more than 128 events invalidate the recorder.
The contract covers base addresses; interior references and realloc require
additional adapters. No heap allocation or I/O occurs inside these hooks.

Fresh live captures publish hashed `entry-state-lifetimes.json` and include a
`lifetime_cursor` in each entry/post snapshot. The host validates event order,
non-reused IDs, and whether each snapshot identity was live at its cursor. The
export loader validates that bundle before reconstruction. The current live
workload records existing objects and scoped `SysSetGroups` allocation/free
events. It reports `allocation_reuse_tracking: true` with syscall scope `[206]`;
other syscall lifetimes still require their explicit contracts. Legacy captures
without the bundle retain their
explicit stable-lifetime contract.

### Live credential replacement capture

The capability build executes three `SysSetGroups` calls through the real user
SVC ABI before forking the task-query child: a null list, `[0]`, and `[7,9]`.
Reviewed capture hooks sample the process-to-user edge, five credential scalars
and every declared group element under the scheduler
lock. Linker wrappers record successful `LOS_MemAlloc` and `LOS_MemFree` calls
reached by the selected PID during each syscall; unexpected allocation size,
pool, execution mode or outcome/event count aborts capture. Other allocator
activity is outside this scope.

`setgroups-capture.json` v5 records each entry/exit, normalized input regions,
raw result, source/type hashes and whether an allocation reused a retired base
address. The host checks the temporary list allocation/copy path when present,
credential allocation size, release ordering, the new process edge, unchanged
copied credential fields, all group values and continuity across calls. User
observations independently confirm every success/error return in user mode. This reviewed
footprint is explicit; generic Clang discovery does not yet model the allocator
and copy closure.

The new credential IDs advance 2→3→5→7, with temporary input buffers 4 and 6.
Earlier credential-query snapshots retain ID 2 after it has been
freed, and their cursor proves it was live when sampled. Captures contain no
object addresses. Tests reject retired references, changed allocation sizes,
copy mismatches, incorrect edges, incomplete footprints and reordered events,
then verify the existing self-contained AArch64 exports.

The generic fixed-object reconstructor still rejects this changing object set.
The capture records `dynamic_object_replay: false` because capture itself does
not establish target replay; the exporter below performs and records that check.
Lists above two elements, arbitrary partial copy failures, realloc/interior references and
general allocator coverage remain outside this capture contract. Version 1
null-list captures remain accepted by the exporter.

### Self-contained dynamic credential replay

```sh
python3 tools/export_freestanding_setgroups.py --arch aarch64 \
  --capture build/live-setgroups-lists-final \
  --out build/rtl-aarch64-setgroups
```

The exporter verifies source locks, captured source/type/configuration hashes,
the kernel image and boot log, independent user returns, and the lifetime/effect
contract. It extracts the original `SysSetGroups` and `SetGroups` bodies without
rewriting their statements. A reviewed model preserves the 24-byte `User` scalar
layout with target-native process/user pointers. Capability success, current
object providers, scheduler locking and copy/allocation dependencies are modeled.
This does not reproduce the full kernel ABI, scheduler or allocator algorithm.

Only the first incoming credential bytes are restored. The bounded allocator
uses eight static 32-byte slots and captured allocation IDs/reuse decisions to
produce target-native pointers. Release retires the current slot generation;
reusing that slot assigns a new logical ID. A checked byte-copy implementation
copies the replayed old object and group payload, and the original body computes the new group
fields and process pointer. Captured exits supply assertions only. Every entry
and exit checks the live generation, scalar fields and every group element; allocation/free/copy order,
one remaining live credential, balanced locks and permission-call counts are
also checked. Later entry states never overwrite target memory.

Normalized input IDs occupy a separate argument-object namespace and identify
distinct complete regions of four or eight bytes at offset zero. The exporter
embeds those bytes; initial restoration constructs all argument objects once.
The original syscall receives pointers into these target-native regions. The
user-copy model checks pointer identity, length and destination allocation, then
copies actual target bytes. Every entry/exit also verifies that input regions
remain unchanged. No later invocation restores an input or output field.

Result ABI 8 word 26 value 3 identifies legacy allocation-outcome replay; value 4 also records user-copy outcomes. Word 20 counts user-copy failures. Words 21 and 22
count allocation attempts and failures. Word 23
counts user-copy attempts, including failures (this extension requires three calls, so word 23 does not
overlap the call records). Words 27–29 count allocations,
releases and copies, word 30 counts live credentials, and word 31 counts address
reuse. The new three-call sequence requires five allocations, five releases,
five kernel copies, two user copies and one remaining live credential. The final
group array is `[7,9,0]`. The observer checks consistent counts; the target also
checks the exact per-call transcript and bounds for trailing group payloads.
Both ELF and raw images are audited and run with guest services disabled before
publication. Their RAM result records must match byte for byte.

Target fault tests reject wrong copied fields, omitted release, releasing the
new object, reusing an old logical ID, corrupting an input group and omitting a
temporary buffer release. A separate controlled target fixture
uses nonzero credentials and detects a copy stub even when it increments the
copy counter and returns success. Rehashed malformed allocation transcripts
fail before publication. These checks cover this reviewed syscall adapter;
generic allocator/copy code analysis, larger lists, input aliases/nonzero
offsets, arbitrary partial copy failures, general heap operations and RTL/cycle timing
remain unvalidated.

### Allocation failure outcomes

Failed allocation attempts carry request size, ID zero and `reuse: false` in a
separate per-call `allocation_attempts` transcript. They create no lifetime event
and consume no logical identity. Successful attempts must agree with allocation
events; all requests must match the expected order and sizes. The target allocator
consumes these outcomes and returns null at the original allocation boundary,
letting the unchanged syscall/helper bodies execute their failure branches.

The live regression explicitly injects three scoped failures from PID 1:

| Call | Outcomes | Cleanup | Result |
| --- | --- | --- | --- |
| Null list | 24-byte credential request returns null | None | `-ENOMEM` |
| `[0]` | 4-byte temporary request returns null | None | `-ENOMEM` |
| `[7,9]` | 8-byte temporary allocation succeeds; 32-byte credential request returns null | Release temporary object | `-ENOMEM` |

All three calls preserve the original credential ID and every captured field.
Target results show four attempts, three failures, one successful allocation and
release, one user copy, zero kernel copies, and one live credential. Entry/exit
checks still run around every call; only initial state and input regions are
restored. The observer checks these counts against success/error results, while
the target verifies the exact attempt/event transcript.

`--setgroups-allocation-failures` requires automated capture. The capture records
`fault_injected: true`, saves the compile-time configuration and its hash, and
compares the kernel return with the independently observed user return. Export
verifies that provenance and carries the injection label into its manifest.
These are real OHOS syscall executions under controlled allocator outcomes,
not evidence of actual memory exhaustion or allocator timing equivalence.
Natural null results can be represented by the same outcome schema, but this
live failure validation uses injection.

Tests reject changed failure-state fields, mismatched allocation outcomes and
missing cleanup before export. Target faults detect skipped temporary release,
an incorrect success return and mutation of credentials on failure. Missing or
changed injection configuration blocks publication. Successful version 1/2
captures remain supported alongside version 3 outcomes.


### User-copy failure outcomes

Capture version 4 additionally records `user_copy_attempts` on both entry/exit
frames. The reviewed wrapper checks the original user pointer and the newly
allocated temporary destination ID, records source-region ID, destination ID,
size, primitive result and copied-byte count, and forwards ordinary copies.
Input sampling occurs before the scoped syscall begins, so it is not included
in this transcript. The new `--setgroups-copy-failures` option requires automated
capture and excludes allocation-failure injection. It returns the requested
copy length before writing any destination bytes. Original `SysSetGroups`
then maps the nonzero primitive result to `-EFAULT` and frees the temporary list.
Version 4 rejects natural and partial user-copy faults; version 5 adds the controlled partial-copy case below;
MMU permission, translation, exception and timing behavior are not reproduced.

The injected sequence returns `0`, `-EFAULT`, `-EFAULT`: call 0 replaces the
credential normally, while calls 1/2 allocate and release only their temporary
buffers. Each failed call retains the incoming credential ID and all fields.
The capture validates exact copy metadata and the successful prefix of
allocation attempts, forbidding credential allocation after copy failure.
Compile-time injection configuration, its hash and independently observed user
returns must agree before export. Earlier v1–v3 captures remain supported.

The AArch64 adapter consumes the captured result at the original copy call,
validates target-native pointer/length/destination bounds, and returns before
writing on injected failure. Later snapshots remain assertions, with one initial
restore. ABI 8 kind 4 uses word 20 for copy failures and word 23 for copy attempts;
words 21/22 retain allocation attempt/failure counts. This sequence produces three
allocations, three releases, no allocation failures, one kernel header copy, two
user-copy attempts/failures and one live credential. These words are reserved
for the reviewed three-call extension and do not overlap its call records.

Tests reject wrong copy source/destination IDs, results, partial-write claims,
missing copy attempts, impossible allocation outcomes, changed credentials,
missing release events and inconsistent injection provenance. Target fault
images detect skipped temporary cleanup, incorrect success return, credential
mutation on failure and a copy model that returns success after a recorded
failure. ELF and raw-image results must match before publication. This remains
a reviewed SysSetGroups dependency model; generic allocator/copy analysis and
RTL/cycle timing validation remain pending.


### Controlled partial user copies

`--setgroups-partial-copy-failures` requires automated capture and excludes the
other fault-injection options. The scoped wrapper calls the real user-copy helper
for half the requested bytes, checks that it succeeded, then returns the number
of remaining bytes. The locked ARM user-copy header declares the primitive result
as bytes not copied. Original `SysSetGroups` maps the nonzero result to `-EFAULT`,
releases its temporary buffer and preserves its incoming credentials.

Capture v5 records `partial_copy_fault_injected`, the copied prefix in
`destination_data`, `bytes_copied` and `suffix_unchanged: true`. The wrapper saves
pre-copy destination bytes, checks copied bytes against the separately sampled
input, and checks the uncopied suffix against its pre-copy bytes. Both checks run
again immediately before release. Raw addresses and uninitialized suffix contents
are not exported. The host validates exact metadata, prefix bytes, the selected
injection mode, input widths, credential continuity and allocation/release events.
The compile-time partial-copy macro must agree with capture and report provenance.

The target model copies the recorded prefix from target-native input memory and
returns the remaining count. It saves its own pre-copy destination bytes and
checks prefix/suffix preservation before retiring the temporary object. Thus it
checks the byte effects even though the syscall subsequently frees that buffer.
No captured output is restored. Earlier v1–v4 captures remain exportable.

Result ABI 8 word 26 value 5 identifies copy byte-effect verification. Word 19
counts copied user bytes; word 20 counts failed user-copy attempts; word 23 counts
all user-copy attempts. This extension is restricted to three calls, avoiding
call-record overlap. The injected sequence copies two bytes from `[0]` and four
bytes from `[7,9]`: total six user bytes, two failed copies, three allocations and
three releases, one kernel header copy and one live credential. ELF and raw
execution must agree before publication.

The regression extends capture rejection tests with wrong byte counts, remaining
counts, prefix data, suffix-preservation claims and injection mode. Target faults
detect an omitted prefix copy, a corrupted copied byte, and a write beyond the
recorded prefix, in addition to wrong return, state mutation and skipped cleanup.
The new coverage is a controlled half-prefix copy in the reviewed SysSetGroups
adapter. Arbitrary fault positions, natural MMU faults, general copy/allocator
analysis and RTL/cycle timing remain outside this milestone.


### SysGetGroups and shared user-output objects

`--getgroups` requires automated capture and successful preceding `setgroups`
calls; it excludes the existing setgroups fault-injection modes. Three real
user SVC calls run with the credential groups `[7,9,0]`: size 0 returns the count
3, size 2 returns `-EINVAL`, and size 4 returns 3 after copying 12 bytes. Every
call uses the same complete 16-byte output object, initialized with distinct
sentinel words. Count and short-buffer paths leave the whole object unchanged;
the successful copy leaves the fourth word unchanged. Independent user-mode
observations contain return values, execution mode and the entire output object.

The reviewed capture samples credentials and output bytes before/after each
call. Scoped allocator hooks register the final call's 12-byte temporary
allocation and release, including its new logical generation ID and captured
reuse flag. The output-copy wrapper checks source ID, destination pointer and
copy width and requires success. `getgroups-capture.json` v1 records a separate
argument-object ID for the shared region, exact copy metadata, lifetime events
and source/type hashes. The host validates unchanged credentials, output
continuity, copied prefix, preserved suffix and event ordering. Raw addresses
are not exported. The kernel capability configuration and construction header,
boot log, kernel image and independent user observations are checked by export.

A separate source lock pins unchanged `GetGroups` and `SysGetGroups` bodies and
relevant headers. The target adapter restores one stable credential and one
shared output array initially, models a bounded temporary region, scheduler
locks, current-user/process providers, kernel copying and user copying, then
runs the original syscall bodies. Later entry and exit frames only assert state.
The temporary source bytes are checked before free, and complete output bytes
are checked after every call. Allocator reuse eligibility is modeled from the
captured flag; prior native allocator address history is not reconstructed.

Result ABI 8 word 26 value 6 denotes bounded user-output replay. Words 17/18
count scheduler locks/unlocks, word 19 counts user bytes, word 21 counts
allocation attempts, word 23 counts user copies, and words 27–31 retain dynamic
object statistics. The observer requires three calls with returns 3, `-EINVAL`,
3, three balanced locks, one allocation/release/kernel copy/user copy, 12 user
bytes and one remaining live credential. This extension requires three calls
so its extra counters do not overlap the call records. ELF and raw-image RAM
records must agree before publication; their entry/load segments are recorded
for model loaders. Guest I/O, semihosting and runtime host services are absent.

Regression tests reject malformed captured returns, copied/guard bytes, output
identity or state continuity, changed credentials, allocation/copy metadata and
missing release events. Target faults detect a user-copy stub even when it
reports the correct count, corrupted output, an overwritten guard word, skipped
cleanup, credential mutation and an incorrect return. A rehashed corrupt output
capture is rejected before publication. The initial contract requires
three credential groups, one complete aligned output region, and successful
allocation/output copy; the output failure extension follows below. Null-output and other argument errors, allocation and
output-copy failures, arbitrary counts/aliases/offsets, generic allocator/copy
analysis and RTL/cycle timing remain outside this milestone. Capture remains
ARMv7 LiteOS-A; syscall C bodies rebuild for AArch64 under the declared models.


### SysGetGroups output-copy failures

Capture v2 records `copy_outcome` as `success`, `none`, or `half`. The latter two
are explicit scoped injections: `none` returns 12 bytes not copied before any
write, while `half` invokes the real output-copy helper for six bytes and then
returns the six remaining bytes. Query and short-buffer calls keep their prior
returns and output state. The final syscall maps either nonzero primitive result
to `-EFAULT`, frees its temporary buffer and leaves credentials unchanged. This
models controlled dependency outcomes, not natural MMU faults or exception timing.

Full before/after output snapshots make partial writes observable. In `half`,
output becomes `[7,0x55660009,0x99aabbcc,0xddeeff00]` from the four sentinel words:
six copied bytes include only the low two bytes of the second group value. The
remaining ten bytes must match incoming output. The host validates that exact
prefix/suffix, primitive remaining/copy counts, return, credential continuity and
allocation/release events. The construction macros, their hash, capture mode,
report mode and independent user-mode observations must agree before export.
Earlier v1 successful captures remain exportable.

The target's user-copy dependency copies the recorded byte count from its actual
temporary buffer and returns the captured remaining count. Original `GetGroups`
executes its error branch and cleanup. State/output are initialized once; later
frames only assert them. Result ABI 8 kind 7 extends kind 6 with word 20 counting
failed output-copy attempts. Word 19 counts actual copied bytes (0, 6, or 12).
The observer checks one failed copy against `-EFAULT`, balanced allocation/free,
three balanced locks and the appropriate copied-byte count. ELF/raw RAM results
must match before publication, with no guest I/O or runtime host interaction.

Regression tests cover zero and partial output failures, incorrect copied or
untouched bytes, mismatched primitive counts, changed credentials, missing
cleanup, changed mode and rehashed injection configuration. Target faults detect
skipped cleanup, a false successful primitive return, mutation of credentials,
copying the whole buffer despite a recorded partial/zero failure, and a partial
copy stub that increments its counters without writing. The next section adds allocation failures. Null-output cases, arbitrary group counts/offsets/aliases, natural MMU faults,
generic allocator/copy analysis and RTL/cycle timing remain outside this adapter.


### SysGetGroups allocation failure

`--getgroups-allocation-failure` requires the getgroups workload and excludes
output-copy failure injection. The wrapper records a 12-byte attempt before
returning null to original `GetGroups`. Its existing null branch unlocks and
returns `-ENOMEM`; neither copying nor freeing is reached. The preceding count
query and short-buffer call retain their returns 3 and `-EINVAL`.

Capture v3 adds the boolean `allocation_fault_injected`. A failed request has
ID 0 and `reuse: false`; it registers no object and emits no lifetime event.
Before/after output and credential fields must be identical, copy attempts must
be empty, and the lifetime cursor must remain unchanged. The validator now also
requires each call's cursor advance to equal its exact expected event count,
rejecting backward cursors even when an empty event slice could hide them.
Earlier v1/v2 success and output-copy failure captures remain supported.

The construction macro, saved configuration hash, capture/report flag and
independent user return must agree before export. The target allocator consumes
the failed attempt under the scheduler lock, increments failure counts and
returns null without activating temporary storage. Original syscall code then
executes the unlock/error branch. Only initial credentials/output are restored;
every subsequent entry/exit remains an assertion. Result ABI 8 kind 8 extends
kind 7 with allocation outcomes: words 21/22 count attempts/failures, while the
output/copy/lifetime counters retain their prior meaning. This trace requires
one attempt/failure, zero allocations/releases/kernel copies/user copies/user
bytes, three balanced locks and one live credential. ELF/raw RAM results must
match before publication, with no runtime host services or guest I/O.

Regression tests reject fabricated allocation IDs or reuse, unexpected copies,
output/credential changes, backward cursors and a false injection flag. Target
fault images detect skipped failure-path unlock, incorrect success return,
credential/output mutation and an attempted free after a null allocation.
Rehashed configuration that omits injection blocks publication. This validates
explicit allocator outcomes, not actual memory pressure or allocator timing.
The following extension adds a null-output argument case. Additional argument cases, broader counts/aliases/offsets,
generic allocator/copy analysis, natural MMU faults and RTL/cycle timing remain
outside this milestone.

### SysGetGroups null output and error precedence

`--getgroups-null-output` replaces the size-2 call's list pointer with `NULL`.
The unchanged `GetGroups` body checks null before checking insufficient size,
so the three user SVC returns are 3, `-EFAULT`, 3. The middle call performs no
allocation, kernel/user copy or free, leaves credentials unchanged, and balances
its scheduler lock. This is an actual argument-error branch, with no injected
dependency failure; the mode excludes allocation and output-copy fault injection.

Capture v4 adds `null_output_case` and an explicit `output_region` identity for
the shared 16-byte witness. The middle call's `arguments.list` is JSON null.
Capture samples the buffer established by the first count call even when it is
not passed to the middle syscall. Independent user observations check all its
bytes after every call. Validation requires the witness identity to match both
nonnull arguments, unchanged middle-call bytes/credentials, empty allocation,
copy and lifetime events, and continuity into the final successful output call.
Earlier v1–v3 captures remain supported.

The saved construction macro, configuration hash, capture/report mode and user
observations must agree before export. A per-call null flag supplies a real null
pointer to original AArch64 syscall code; the output witness is restored only
once and later frames are assertions. Result ABI 8 kind 9 identifies this
three-call sequence and retains kind 8's counters. Its two nonnull calls include
one successful allocation/release/kernel copy/user copy totaling 12 user bytes;
the null call contributes only a balanced lock. Its `-EFAULT` is not counted as
a failed user copy. ELF/raw RAM results must agree before publication, with no
guest I/O or runtime host interaction.

Regression tests reject a substituted nonnull pointer, different witness,
`-EINVAL` in place of `-EFAULT`, changed output/credentials, unexpected allocation
or copy, incompatible modes and rehashed configuration missing the null macro.
Target fault images detect wrong pointer reconstruction, reversed error
precedence, skipped unlock, credential/witness mutation and unexpected allocation.
This extension covers the size-2 null case with three stable credential
groups; the following extension adds null count queries and size-4 rejection.
Other sizes/group counts/offsets/aliases, generic
dependency analysis, natural MMU faults and RTL/cycle timing remain outside it.

### SysGetGroups null count and sufficient-size rejection

`--getgroups-null-boundaries` runs sizes 0, 0, 4 with the first list pointing to
the shared 16-byte witness and both later lists null. The original syscall checks
size zero before list validity, so the null count query returns 3. With size 4,
the null pointer returns `-EFAULT` before any allocation or copy. The sequence
returns 3, 3, `-EFAULT`, preserves every witness byte and credential field, emits
no allocation/release event and balances three scheduler locks. It uses actual
argument branches and excludes both the short-null profile and fault injection.

Capture v5 introduces `null_output_profile`: `none`, `short`, or `boundaries`.
The retained `null_output_case` boolean must agree with that profile. The validator
checks exact sizes, null/nonnull argument identities, returns, unchanged witness
and credentials, state continuity, empty dependency records and unchanged
lifetime cursors. Saved construction macros, capture/report profile and
independent user observations must agree before export. Older v1–v4 captures
remain supported.

The target checkpoint distinguishes an absent allocation from an attempted null
allocation. The adapter rejects any allocation outside the captured attempt,
including the final null-list call; it supplies real null pointers to unchanged
syscall bodies. Result ABI 8 kind 10 denotes this sequence, with all allocation,
release, copy, failure and reuse counters zero, one live credential, and three
balanced locks. A null argument's `-EFAULT` does not count as a failed user copy.
ELF/raw RAM results must match before publication, without runtime host services.

Regression tests reject wrong count returns, sizes, pointers, witness/profile,
output/credential changes, unexpected dependency records and backward cursors.
Target fault images detect rejecting a null count query, skipping its unlock,
skipping the positive-size null unlock, wrong pointer reconstruction, unexpected
allocation and mutated credentials/witness bytes. Rehashed construction metadata
missing the boundary macro blocks publication. The reviewed contract still
requires three stable groups and a complete shared witness; arbitrary sizes,
group counts/aliases/offsets, natural MMU faults, generic dependency analysis and
RTL/cycle timing remain outside it.

### SysGetGroups signed sizes

`--getgroups-negative-sizes` runs sizes 0, -1, `INT32_MIN` with the first two
lists pointing to the shared witness and the last list null. Original syscall
code returns 3, `-EINVAL`, `-EFAULT`: a negative size with a valid list takes the
signed short-buffer branch, while a null list is rejected before the signed size
check. Every credential field and witness byte remains unchanged. No allocation,
release or copy occurs, and all three scheduler locks are balanced. The profile
excludes other argument modes and injected dependency failures.

Capture v6 adds `negative-sizes` to `null_output_profile`, because the last call
tests null precedence at the signed lower boundary. Sizes are signed JSON
integers, not unsigned aliases. User observations and checkpoint constants carry
the corresponding 32-bit patterns (`0xffffffff` and `0x80000000`); export masks
only after semantic validation and the original AArch64 C body receives signed
`int` arguments. Construction macros, capture/report profile, independent user
bytes, untouched state and empty lifetime/dependency records must agree. Capture
versions v1–v5 remain supported.

Result ABI 8 kind 11 denotes this exact three-call sequence. The observer requires
returns 3, `-EINVAL`, `-EFAULT`, three balanced locks, one live credential and zero
allocation/release/copy/failure/reuse counters. Null-argument rejection is not a
failed user-copy attempt. ELF and raw-image RAM results must agree before
publication; the image has no guest I/O or runtime host services.

Regression tests reject unsigned aliases, values outside the declared profile,
wrong null reconstruction/precedence, inconsistent profiles, changed output or
credentials, unexpected dependency records and backward lifetime cursors. Target
fault images detect unsigned size comparison, lost sign bits, substituted
nonnull pointers, skipped short/null unlocks and mutated credentials/output.
Rehashed configuration missing the negative-size macro blocks publication.
This is a reviewed three-group profile, not arbitrary argument exploration;
other sizes/group counts/aliases/offsets, natural MMU faults, generic dependency
analysis and RTL/cycle timing remain outside the current adapter.

### SysGetGroups exact fit and declared capacity

`--getgroups-output-size` generalizes the final nonnull output call's declared
capacity to integers 3..`INT32_MAX`, with default 4. The credentials still contain
three groups and the actual output witness remains a complete 16-byte object.
Original `GetGroups` accepts size 3, because its rejection compares size strictly
less than the group count. A larger declared capacity, including `INT32_MAX`,
still requests and copies only `groupCount * sizeof(int)` (12 bytes), leaving
the fourth word intact. This option supports allocation/output-copy injection;
changed capacity excludes the existing null/negative argument profiles.

Capture v7 adds `output_size`. The host validates its integer type and signed
positive bounds, exact final argument, fixed actual region width, 12-byte
allocation/copy metadata, copied prefix and untouched suffix. The saved numeric
construction macro, capture/report value and independent user observations must
agree. Older v1–v6 captures retain their declared capacity 4. All target counters,
continuous restore-once behavior and result ABI 8 kind 8 remain unchanged.
The AArch64 adapter consumes the captured size in unchanged syscall bodies;
ELF/raw RAM results must agree before publication with no runtime host services.

Tests capture success at size 3 and `INT32_MAX`, reject off-by-one size mismatches,
unsigned/out-of-range capacity, boolean values, oversized allocation/copy records
and overwritten guard bytes. Target faults detect rejecting an exact fit and
using declared capacity instead of actual group count for allocation. Rehashed
construction metadata with a different capacity blocks export. The exact-fit
case also exercises allocation failure and zero/partial output-copy failures.
This removes the fixed capacity-4 restriction for the final nonnull call; other
argument sequences, group counts, aliases/offsets, natural MMU faults, generic
dependency analysis and RTL/cycle timing remain outside the reviewed adapter.

### SysGetGroups interior output pointers

`--getgroups-output-offset` generalizes the final nonnull output pointer to byte
offsets 0..4 inside the complete 16-byte witness. Earlier calls keep the base
pointer, establishing object identity and incoming state. The actual 12-byte
group copy fits the object at every allowed offset. Capture samples the whole
object before/after each call and checks the real copy destination against base
plus offset; it supports success, zero/half-copy injection and allocation failure.
Nonzero offsets exclude the existing null/negative argument profiles.

Capture v8 adds `output_offset`. The final list reference has the same logical
object ID, the recorded offset and `bytes = 16 - offset`; `output_region` still
describes the complete base witness. Copy outcomes also record `destination_offset`.
The host validates type/range, reference span, object identity, copied group bytes,
unchanged prefix before the pointer and unchanged suffix after the written range.
The output ID must be disjoint from kernel object and lifetime IDs; unsupported
cross-object aliases are rejected.
Saved numeric construction macro, capture/report value and independent user
observations must agree. Capture v1–v7 retains base-pointer semantics and remains
supported. Offset 1 partial failure copies six bytes into positions 1..6 and
leaves positions 0 and 7..15 unchanged.

The target checkpoint carries each call's offset. Reconstruction restores the
shared base array once, while invocation supplies base plus offset to unchanged
syscall bodies. The byte-copy dependency validates that destination and performs
actual writes from its temporary source. Later entry/exit frames assert all
16 bytes; logical identities and lifetime counters retain their prior meaning.
Result ABI 8 kinds and counters are unchanged. ELF/raw RAM results must agree
before publication, with no guest I/O or runtime host services.

Tests capture successful output at offsets 1 and 4, shifted zero/partial failures
and allocation failure at offset 4. They reject offset/range/span/identity or copy
metadata mismatches and altered output bytes. Target fault images detect ignoring
the pointer offset, writing at the base while reporting a correct copy count,
and corrupting the prefix guard. Rehashed construction metadata with a different
offset blocks publication. This supports one shared output object with bounded
interior references; arbitrary aliases/object graphs, larger offsets/group counts,
natural MMU faults, generic dependency analysis and RTL/cycle timing remain outside
the current adapter.

### SysGetGroups captured group count

`--getgroups-group-count` supports 1, 2 or 3, with default 3. The one-group workload
executes its three getgroups calls immediately after the first successful
setgroups, while its `[0]` credential is live; the remaining setgroups calls run
afterward. The three-group workload retains its placement after the final
setgroups. The two-group workload supplies `[7, 0]` to the final setgroups call, so the
primary gid is already present and the credential retains two groups. Its
credential allocation is 28 bytes rather than the three-group case's 32 bytes.
Original syscall bodies execute in every case. Snapshot identities
and lifetime cursors preserve the earlier credential generation even after the
later workload replaces/frees it.

The middle call declares `group_count - 1`. For count 1 this is size zero and
returns another count query; there is no positive nonnull buffer smaller than
one group. The final call accepts declared capacity `group_count..INT32_MAX` and
the existing offsets 0..4. One-group success returns 1, 1, 1; copy and allocation
failures replace only the last return with `-EFAULT` or `-ENOMEM`. Two-group
success returns 2, `-EINVAL`, 2; its failure outcomes likewise affect only the
final call. Capture v12 additionally supports null/negative argument modes for
one- and two-group credentials, as described below.

Capture v9 adds `group_count` for counts 1 and 3; v10 extends it to count 2.
Credential validation reads `groupNumber`, checks
the declared count and requires exactly five header scalars plus that many group
fields. Allocation/copy metadata and lifetime sizes use `4 * group_count`, and
half-copy outcomes use half that width. Before/after output remains 16 bytes,
with copied bytes and both guards asserted. The saved count macro, capture/report
count and independent user observations must agree. Older v1–v8 retain count 3,
and v9 still rejects count 2.

The AArch64 checkpoint emits captured count/byte-width constants. The adapter
restores/checks only the captured credential fields and validates every
allocation, kernel copy, user copy and temporary-buffer release using that width.
Result ABI 8 kind 12 denotes a one-group trace: four-byte allocation/copy width,
zero/two/four user bytes according to outcome. Kind 13 denotes two groups:
eight-byte allocation/copy width and zero/four/eight user bytes. Both use three
balanced locks, initial state restored once and three entry/exit assertions. Null allocation has no
allocation/release/copy effects. ELF/raw RAM results must agree before publication
without guest I/O or runtime host services.

Tests cover one- and two-group success, zero/half-copy failure and allocation failure at
an interior pointer with exact declared capacity matching the captured group count. The two-group
case also verifies standalone ELF/raw replay of the original setgroups sequence. They reject count mismatch,
three-group dependency widths, duplicate credential fields, unexpected copies,
altered output and rehashed construction with the wrong count. Target faults
detect a hard-coded three-group width, wrong count return and a copy stub that
reports progress without writing. Arbitrary group values/argument
sequences/aliases, larger offsets, generic dependency analysis, natural MMU
faults and RTL/cycle timing remain outside the current reviewed adapter.


### SysGetGroups selected byte-prefix failure

`--getgroups-copy-bytes N` selects a failure after any prefix in
`0..4 * group_count - 1`, for counts 1, 2 and 3. The native wrapper copies that
prefix using the real user-copy API, then returns the remaining byte count to
the unchanged syscall. A zero prefix makes no user-copy API call and leaves the
output unchanged. This is explicit fault injection; it does not reproduce an
MMU fault. Allocation failures, null/negative profiles and the old copy-outcome
selector are excluded.

Capture v11 exclusively represents this profile as `copy_outcome: partial` and
an integer `copy_bytes`. Validation requires that count to be below the actual
list width, checks the exact copied prefix, preserves the whole 16-byte witness,
and validates temporary-buffer lifetime and cleanup. Previous formats keep their
success/none/half semantics and reject prefix metadata. Saved macro, report and
capture prefix must agree, even when a changed configuration is rehashed.

AArch64 replay uses the captured remaining count without requiring field-aligned
writes. Result ABI 8 kinds 14, 15 and 16 identify prefix traces for counts 1, 2 and
3. The observer checks a failed copy and a prefix below the corresponding width;
export additionally requires its byte counter to match the capture exactly.
Entry/exit assertions check every output byte. ELF/raw results must match before
publication, with runtime host interaction disabled.

Tests cover one-byte, seven-byte, nine-byte and zero-byte prefixes across all
three counts, at offset 1 and exact declared capacity. They reject out-of-range,
boolean and missing prefix counts, legacy format claims, inconsistent remaining
counts, guard changes and rehashed configuration disagreement. Target faults
reject a copy stub and a helper that writes the full list despite reporting a
partial failure. Arbitrary argument sequences, group values, aliases, generic
allocation/copy analysis and RTL/cycle timing remain outside this adapter.

Output assertions compare memory values. An extra write that stores the same
value is not independently observed as a memory transaction; dependency checks
validate the reviewed helper call and its declared width. Bus-level write traces
would require model-side observation. The over-copy fault test uses a prefix
whose untouched suffix differs from the source, so the violation is observable.


### SysGetGroups argument profiles for all captured counts

Null-short, null-boundary and negative-size profiles now support every reviewed
count (1, 2 and 3). Capture v12 extends the argument profiles specifically to
counts 1 and 2; older versions retain their three-group profile restrictions.
Default capacity remains 4 and offset remains 0 for these profiles; allocation
and copy-failure injection remain excluded.

The null-short sizes are `0, group_count - 1, 4`. The first and final pointers
are nonnull, while the middle is NULL. With count 1 the middle is size zero and
returns 1, so all three returns are 1. With count 2 it is size 1 and returns
`-EFAULT` before considering buffer size: returns 2, `-EFAULT`, 2. Only the
final call allocates, copies and frees a temporary of `4 * group_count` bytes.

Null-boundary profiles use sizes 0, 0, 4 and pointers nonnull, NULL, NULL. Both
count queries return the captured count; the last returns `-EFAULT`. Negative
profiles use 0, -1, `INT32_MIN` and nonnull, nonnull, NULL pointers. Returns are
captured count, `-EINVAL`, `-EFAULT`. Neither profile allocates/copies/frees any
object, and both preserve the full output witness through all calls. Original
syscall bodies execute without modifications.

Result ABI 8 kinds 17/18 identify null-short counts 1/2, 19/20 null-boundary
counts 1/2, and 21/22 negative-size counts 1/2. The observer derives the count
and checks return order, balanced locks, continuous entry/exit assertions and
profile-specific effects. ELF/raw results agree before publication, without
runtime host interaction.

Live tests cover all six new combinations and preserve the existing three-group
regressions. Corrupted count, signed argument, output, raw return, allocation
metadata and legacy-format claims are rejected. Target faults detect NULL taking
precedence over a zero-size query, short-buffer checks taking precedence over
NULL, and output mutation in an otherwise no-write call. Larger offsets, general
argument sequences and object aliases, generic dependency analysis, natural MMU
faults, transaction-level memory tracing and RTL/cycle timing remain outside the
reviewed adapter.


### Ordered multi-output credential query: getresuid

The pinned `SysGetRealEffSaveUserID` acquires the scheduler lock, reads
`User.userID` once and `User.effUserID` twice, then unlocks before copying three
local integers to user outputs. This source uses effective UID as saved UID.
Each copy is four bytes and returns immediately with `-EFAULT` on nonzero
remaining bytes. Earlier successful copies are retained; later copies are not
attempted. The capture records the original syscall, not an emulated kernel body.

`--getresuid` selects four calls: all outputs valid, then NULL in positions
0, 1 and 2. Nonnull outputs refer to offsets 0, 4 and 8 of one shared 16-byte
witness. The fixture assigns distinct real/effective IDs 6001/6002 before entry
capture and restores native credentials after exit capture, under scheduler lock.
This setup is explicitly recorded, rather than claimed as state established by
credential-changing syscalls. The selected calls themselves never change those
fields. The remaining four output bytes are guards, and the whole witness remains
continuous across the selected calls. Setup and restoration outside their
boundaries are not replayed.

The reviewed footprint is two four-byte scalars and the current-process user
edge. No raw addresses are serialized; capture-scoped lifetime IDs bind the same
User generation throughout. There are no allocation/free effects. This footprint
and copy contract are reviewed against the pinned source body. Configured Clang
analysis independently finds `OsCurrUserGet()->userID` once and
`OsCurrUserGet()->effUserID` twice, and reports three unmodeled external
`LOS_ArchCopyToUser` dependencies. The adapter supplies those explicit models;
generic code analysis does not infer their ordered copy behavior.

Native valid copies use the real user-copy API. NULL calls are rejected by its
address-range check, returning four remaining bytes without writes; these are
native NULL rejections, not injected copy-prefix failures. Capture validation
checks argument geometry, IDs disjoint from kernel objects, exact scalar widths,
credential/output continuity, copy order and values, early termination, unchanged
lifetimes, raw returns and independent user observations. Hashes bind kernel
image, boot log, configuration, transcript, source and type header. A rehashed
configuration missing the capture macro is rejected before publication.

The AArch64 adapter restores the credential and witness once and executes the
original body for all four calls. Dependency checks enforce lock/unlock order,
three User accesses per call, expected output position, source value and width.
Result ABI 8 kind 23 uses words 27–31 for copy attempts, bytes written, locks,
unlocks and User accesses. Expected totals are nine attempts, 24 bytes, four
locks/unlocks and twelve User accesses; four entry/exit assertions accompany
returns 0, `-EFAULT`, `-EFAULT`, `-EFAULT`. This kind has no dynamic allocator
counters. ELF/raw RAM results must agree with runtime host services disabled.

Tests corrupt saved-value selection, copy ordering, copies after failure,
returns, guards, fields, pointer aliases/types, lifetime cursor and allocation
metadata. Target faults select the wrong saved field, continue after positive
copy failure, falsely return success, omit unlock, skip actual writes, alter the
guard or swap output pointers. Arbitrary UID values, aliasing or overlapping
outputs, partial-copy MMU faults, user containers, credential-changing syscall
setup, generic dependency synthesis, transaction-level memory tracing and
RTL/cycle timing remain outside this reviewed profile.

### Shared ordered credential outputs: getresgid

The original `SysGetRealEffSaveGroupID` is source locked separately from the UID
query. ARMv7 capture dispatches `getresgid32` (211); the AArch64 image rebuilds
that original C body, rather than claiming a native AArch64 capture or Linux
syscall ABI. It reads `User.gid` once and `User.effGid` twice under scheduler lock.
The saved GID in this pinned implementation is effective GID.

The reviewed profile follows the same four-call sequence and 16-byte witness as
getresuid, using distinct scoped GIDs 7001/7002. Capture restores native gid and
effGid after each exit snapshot. It records three, one, two and three copy
attempts, with native NULL rejection returning four remaining bytes and the
syscall returning `-EFAULT`. Earlier writes remain visible; later copies stop.
The normalized output ID is capture local and must remain disjoint from kernel
objects and lifetime IDs.

Native capture, validation, checkpoint generation, publication and the target
copy adapter share the UID/GID machinery. Profiles select field names, fixture,
source lock, syscall number and result kind explicitly. Configuration checks
reject the other capture mode; validation rejects wrong syscall numbers and
boolean pointer fields even when only a nested frame is corrupted. This reuse
is a reviewed implementation of two known dependency contracts; it does not
make external user-copy analysis generic.

Result ABI 8 kind 24 identifies getresgid; kind 23 continues to identify
getresuid. Both use words 27–31 for nine copy attempts, 24 copied bytes, four
locks, four unlocks and twelve credential accesses, with no allocator counters.
The target restores the two scalars, user edge and output witness once, then
asserts four entries and exits. Publication requires static ELF audit and exact
ELF/raw RAM-result agreement under QEMU with guest host services disabled.
Tests corrupt capture state and compile seven faulty target variants, including
wrong saved-field selection, continuation after a positive copy failure,
missing unlock, omitted writes and pointer swapping. Arbitrary credentials,
output aliases/overlaps, natural MMU faults, user containers, full native layouts,
transaction-level write tracing and RTL/cycle timing remain outside this profile.

### UID/GID aliases, overlaps and unaligned outputs

The shared credential-output path now supports three independently selected byte
offsets in `0..12` within its 16-byte output witness. The offsets are stable
throughout the four-call sequence. A range is four bytes; repeated offsets alias,
and distinct ranges can partially overlap. This removes the previous separate,
aligned-output restriction for this bounded witness. All-valid success followed
by NULL at positions 0, 1 and 2, the scoped fixtures and original syscall bodies
remain the same.

The native workload initializes its witness and offsets in accessible user
storage and passes each address through the real SVC dispatcher. Capture derives
the witness base from the first valid output and its configured offset, then
checks every argument and every user-copy destination against that geometry.
The native copy API performs all nonnull writes, including unaligned writes.
NULL failures use its actual range check. Before/after snapshots retain all 16
bytes, so successful prefixes, overlaps, untouched bytes and continuity are
checked without assuming that the fourth word is always a guard.

Version 2 stores `output_offsets` explicitly and requires three integer offsets
within bounds, different from the default `0,4,8`. The capture configuration
records each offset as a macro. Export checks those macros against the validated
bundle, including when a changed configuration is rehashed. Version 1 retains
its original geometry and cannot contain version-2 metadata; old captures without
the macros remain valid. Geometry is shared by the call arguments, entry/exit
snapshots, copy-effect validation and embedded target checkpoint.

Replay uses ordered volatile byte stores for each four-byte copy. An unaligned
user destination is never dereferenced as a 32-bit scalar in the adapter. Later
copies overwrite earlier bytes in the same object, and a NULL failure preserves
only the successful prefix. Every entry and exit compares the entire witness.
Copy-byte totals count all successful stores, including repeated writes to the
same address; they are not a count of unique changed bytes. ABI 8 kinds 23/24
and the nine-attempt/24-byte totals remain unchanged.

Live regression profiles cover complete UID aliasing, reversed high offsets,
GID real/saved aliasing, overlapping unaligned ranges `1,3,5` and complete aliasing
at the last valid offset 12. Corrupt geometry, legacy/version claims, pointer
arguments, output/continuity and copies after NULL are rejected. Target variants
with reversed byte order, omitted stores, discarded geometry and continued
copies after NULL fail. The default UID/GID target fault suites remain in place.
ELF/raw execution must agree with runtime host services disabled. Offsets outside
the witness, arbitrary argument sequences or credentials, partial-copy faults,
generic dependency synthesis, transaction-level tracing and RTL/cycle timing
remain outside the reviewed model.

### Clang-generated UID/GID query capture fields

Selecting `--getresuid` or `--getresgid` now adds that original syscall to the
configured multi-translation-unit analysis. Clang discovers the real field once
and the effective field twice through `OsCurrUserGet()`. The discovered query
must have its three pointer arguments, no state writes or unknown memory ranges,
exactly the reviewed provider/copy/lock dependencies and no analysis blockers.
Unexpected fields or dependencies prevent generation.

`LOS_ArchCopyToUser` is an explicit `memory_model` boundary for this selection.
It permits field-hook generation while the existing native copy checks, capture
validator and target adapter enforce the bounded output contract. Without that
model, the generic analyzer reports three external-dependency blockers. This
extension does not infer copy semantics or make unknown effects safe.

The model declares `reads: [1]`: the copy reads its source argument. Each
source is `&realUserID` (or its siblings), an automatic scalar that the analyzer
tracks as a one-element bounded pointer. Two analyzer rules let it through:

- An implicit conversion of a bounded pointer to `void *` (with any qualifiers)
  keeps its origin. Offsets on the `void *` view (GNU byte arithmetic) and casts
  back to a typed pointer are still rejected.
- A boundary may receive a bounded pointer only at an argument it declares in
  `reads` or `writes`. That access is checked against the pointer's extent and
  lifetime; any other bounded argument remains a `boundary_memory_effect`
  blocker.

The plan then lists three one-element ranges over the locals. The capture bridge
requires exactly three distinct ones, and drops them from the capture plan
because locals are not entry state. Before these rules, the scalar-address
support made each `&local` a bounded pointer, and the query was rejected with
"credential query discovered footprint differs".

The discovery plan retains the original current-User provider. A separate
capture plan projects it through the reviewed binding
`OsCurrUserGet() == OsCurrProcessGet()->user`, adds that user edge and preserves
all discovered scalar reads. The standard hook generator emits one edge and two
scalar snapshots, deduplicating repeated effective-field reads. The native
harness calls the generated hook under its existing capture lock, replacing its
handwritten field list. Scalar widths come from `sizeof` in the configured type.
This binding is explicitly modeled; its equivalence is not proven by analysis.

The capture's construction macro, bundle generation marker and report flag must
agree. Existing version-1/2 geometry and snapshot formats remain unchanged.
The plan records both original discovery and projected capture plans, plus the
additional copy boundary. The report hashes the plan and hook header. Export
also regenerates them from the verified source and current matching configuration
with controlled compiler arguments, checking the selected plans, hook text,
source/header dependency hashes, compiler identity and boundary policy. It never
executes compiler arguments supplied by a capture. A forged plan or modified
hook still fails after its hashes are updated; removing the generation claim
while its construction macro remains set also fails.

Published artifacts include the verified construction plan and hook header.
Their manifest distinguishes generated fields with independent reanalysis from
legacy reviewed-field captures. Reconstruction still uses the reviewed target
User model and copy/scheduler adapters. Unit checks exercise required boundary
models, extra/missing reads, writes, unknown dependencies and translation-unit
namespaces; live checks retain ordered-copy target faults and reject rehashed
plan/header changes. The analysis remains conservative and bounded, with no
proof of completeness or minimality, no generic dependency synthesis and no
RTL/cycle timing claim.

### Configurable full-width credential fixtures

The shared UID/GID capture accepts `--credential-ids REAL,EFFECTIVE`, with each
value in `0..UINT32_MAX`. The fixture still changes only the two selected User
fields under the capture setup lock and restores them outside each selected
syscall. Arbitrary values are supported as captured bit patterns, including zero,
equal IDs, bit 31 set and `0xffffffff`. These fixtures do not claim natural
credential transitions or that every bit pattern can be established through a
credential-changing syscall.

Custom values use version 3. The bundle records the real/effective fixture and
three output offsets explicitly, including default offsets when selected.
Its generated-field marker is required. The capture header records both IDs as
canonical unsigned decimal C constants and records all three offsets. Native
copy checks compare the full unsigned source patterns, and all output bytes
continue through the real safe-copy API. Export binds both ID macros to fixture
metadata; missing, changed, duplicated or malformed definitions fail before
publication, even if the configuration hash is updated. Versions 1/2 remain
restricted to their historical default IDs; changing only their fixture metadata
cannot broaden those formats. Explicit default IDs retain versions 1/2.

The original bodies assign unsigned User fields into signed `int` locals before
copying four bytes. Native AArch32 capture and the AArch64 rebuild preserve the
full 32-bit representation with the configured Clang toolchain. This is verified
bit-pattern behavior for those builds, not a portable C claim for arbitrary
integer ABIs. Target checkpoint constants use `UINT32_C`, reconstruction restores
32-bit User fields, and copy checks compare unsigned source values before ordered
byte stores. High-bit IDs never become signed JSON fixture values or syscall
return codes. Saved UID/GID continues to use the effective field in the pinned
source.

Live profiles cover zero/equal UID values, maximum real UID with zero effective
UID and output aliasing, high-bit/maximum GIDs with unaligned overlap, and equal
nonzero GIDs aliased at offset 12. Validation rejects booleans, signed/out-of-range
or string IDs, mismatched fields, false scope, format downgrades, default values
misclaimed as version 3 and absent generation markers. Existing distinct-ID
profiles retain their field-selection fault checks; equal values alone cannot
distinguish selection of two fields containing the same bits. Each image must
pass source reanalysis, static audit, continuous entry/exit assertions and exact
ELF/raw RAM-result comparison without runtime host services. Additional target checks rejected clearing the real ID high bit and truncating
the saved ID to 16 bits, each at the source-value check (error 105). The four-call
argument sequence, bounded witness, explicit copy/provider models and lack of
natural MMU or RTL/cycle timing validation remain unchanged.


### Process-mode scheduler policy queries

`--getscheduler` adds four actual `SysSchedGetScheduler(id, 0)` calls before fork:
current-process alias 0, explicit PID 1, invalid -1, and unused process slot 63.
The reviewed profile expects two policy successes, EINVAL and ESRCH. It records
five ordered dependency events: one current-PID result and four
`LOS_GetProcessScheduler` outcomes. Nested dependency internals are suppressed
from this root-boundary transcript. Error events carry no policy value (canonical
zero with `policy_written=0`); capture never reads the syscall's uninitialized
policy local on failure. The helper implementation is source-pinned alongside
the original syscall and lookup table to bind that output contract.

The exporter validates independent user arguments, user mode, dependency order,
PID resolution, success/output flags, error outcomes and returns. It checks
source and captured kernel/observation hashes before compiling the complete
original body. The target boundary validates the nonnull policy pointer and NULL optional
parameter, consumes the expected event, writes successful policies,
and returns failures without writing. ABI 9 reports dependency consumption,
PID/scheduler calls, policy writes and every raw return. Unsupported task mode
traps explicitly; task types are placeholders for that unreachable branch.

This adds a reviewed syscall profile, not generic scheduler-object reconstruction
or automated inference of pointer-output dependencies. The checkpoint embeds
observed outcomes; no full process table, scheduler callbacks, locks, interrupt
behavior or physical memory/MMU behavior is reconstructed. Tests exercise
malformed/truncated/extra observations and target faults in PID resolution,
lookup arguments, policy writes/returns, task selection and omitted lookups.


The new live scheduler regression passed: native and AArch64 returns were
`2, 2, -22, -3`, successful policy writes totaled two, and dependency cursors
advanced `2, 3, 4, 5`. ELF and raw-image RAM results matched byte for byte. Ten
malformed-capture cases were rejected. Six target faults were detected: missing
PID resolution, wrong lookup ID, returning helper status instead of policy,
incorrect policy write, task-mode selection and omitted lookup execution.


The existing generated-snapshot and partial-copy regression cases also passed
individually (199 seconds combined). The aggregate entry-state invocation hit its
old 360-second timeout without an assertion report; its CTest budget is now 900
seconds. The full aggregate has not been rerun with the new budget.

### Task-mode scheduler policy queries

`--getscheduler-task` selects the negative-flag branch of the same pinned
`SysSchedGetScheduler` body. The user obtains its task ID through the existing
SVC gettid path before the read capture begins. Four later calls use that ID,
-1, unused physical task slot 127, and foreign kernel task 0, with flag -1.
The capture requires physical task IDs (PID containers are rejected) and asserts
the native task limit is 128. Its eight records contain four immutable task-limit
samples, three real permission results, and one forwarded callback outcome.
The invalid-ID call reaches neither lookup, lock, permission nor callback; both
permission failures unlock and return the negated positive error code.

A wrapped real permission helper installs a copied operations table only after
successful permission checking, while the original syscall holds its scheduler
lock. The copied table preserves every operation except `schedParamGet`; that
entry forwards to the saved original callback, records its return and 16-bit
policy output, and immediately restores the task's original table pointer.
The syscall wrapper also checks that no temporary binding survives its return.
No permission result or policy value is replaced; the only task mutation is
this scoped callback binding. Kernel addresses and
function pointers are not serialized. Task/callback types, task bounds and
permission implementation are pinned alongside the original syscall source.

The AArch64 model binds a logical task identity to a typed
`unsigned int (*)(const LosTaskCB *, SchedParam *)` callback. It checks the
original body's zero-initialized parameter fields, injects the captured policy
output through that pointer, and validates bounds/lookup/lock/permission/callback/
unlock order. Saved lock tokens and balanced ownership are checked; native
spinlocks, IRQ state and scheduler behavior are not reproduced. Only the policy
field is replayed because it is the callback output consumed by the syscall;
unread priority/time-slice/deadline fields are outside the dependency model.
The process dependencies terminate explicitly if this task profile reaches them.

Capture format v2 selects task mode explicitly and requires canonical build
markers. The exporter independently validates the binary user rows and event
transcript, source identity, kernel and observation hashes. JSON comparisons
preserve types, rejecting boolean aliases for integer fields. Existing format v1
process captures retain their original source lock, type model and ABI 9.
Task images use ABI 10 with four bounds checks, three task lookups, three permission
checks, one callback, three matched locks/unlocks and zero final lock depth.
Their dependency cursors are 3, 4, 6 and 8. This is a reviewed capture/replay
adapter; generic analysis does not infer the indirect callback's behavior.


The live task test passed with raw returns `2, -22, -22, -1`; all eight records
were consumed, and ELF/raw RAM results matched exactly. Thirteen malformed
binary-capture cases, a boolean-alias manifest case and five invalid configuration
cases were rejected. Nine target faults were detected: permission-error sign,
bypassed permission helper, skipped callback, wrong callback policy, missing
unlock, wrong task pointer, accidental process mode, duplicate lock, and stubbed
syscall execution. The existing process-mode live capture/export and its faults
also passed with the new permission wrapper present.

### Resident physical memory contract

All freestanding exporters now include `target.memory_contract`, derived from
ELF PT_LOAD segments and the replay startup symbols. It records required resident
physical ranges, ELF loader zero-fill tails, the 16 KiB stack, startup BSS clearing,
the raw payload span and explicit MMU-off entry assumptions. New startup code
exports `__stack_bottom`; earlier repository images use their established 16 KiB
stack reservation below `__stack_top`. Bounds, instruction/stack alignment and
writable stack/result placement are validated while describing the image.

The prior linker script aligned `__bss_end` outside the output section, so startup
could clear a few bytes after PT_LOAD's declared memory size. Both AArch64 and
ARMv7 scripts now put BSS start/end symbols and end alignment inside the section.
This also accounts for input objects requiring higher BSS alignment. Existing
images retain support when the extra clearing is only the known alignment tail;
the tail is included in their required RAM instead of silently omitted. Clearing
that exceeds the writable segment plus alignment padding is rejected.

`tools/check_image_memory.py --image IMAGE --ram BASE:BYTES` validates these
ranges against supplied physical RAM banks. Adjacent banks can jointly cover a
range; even a one-byte hole fails. With `--binary`, it also verifies raw length and
each file-backed segment's bytes against the ELF, then checks the entire raw
loading span (including inter-segment gaps) is writable RAM. The physical map
supplied to this tool is an assertion that the model allows the required fetches,
reads and writes throughout execution. Preflight cannot test the model itself.
ELF loading must copy file bytes and zero `p_memsz - p_filesz`; a raw loader must
apply that zero-fill plan as well. Startup independently clears BSS, but this does
not replace initialization of NOLOAD result storage or other loader tails.

The QEMU RAM-result runner checks coverage against its existing 64 MiB RAM map
before launching QEMU, and validates a raw image against its ELF descriptor before
execution. This adds no guest I/O, host fault handler or runtime checkpoint service.
Its optional `--initial-memory-dir NEW_DIRECTORY` saves physical RAM before the
first instruction and checks it before continuing the CPU. The directory contains
bank dumps and `memory-preflight.json`, including hashes and the QEMU snapshot
backend. This option requires an ELF or a raw image with its ELF descriptor.

Standalone preflight accepts repeated `--memory-dump BASE:FILE` arguments for
model/testbench snapshots taken after loading and zero-fill, before execution.
Verification streams comparisons across adjacent dump files, rejects overlapping
files and missing initialization coverage, and locates mismatches by physical
address. ELF file-backed bytes and all loader zero-fill tails must match. Raw
loading additionally checks gap bytes supplied by the raw payload, with ELF
zero-fill taking precedence wherever a tail overlaps that payload. Unspecified
ELF gaps and legacy startup padding have no initial-content requirement; the
startup later clears its padding. Dump files themselves must lie within the
declared RAM. Their unrelated bytes are hashed, without constraining their value.
Reports with dumps use `osrec-image-memory-preflight-v2` and explicitly record
`initial_memory_verified`; map-only reports retain v1 and report it as false.
The standalone caller asserts the snapshot phase; the checker cannot infer it
from the bytes. Files must remain unchanged during checking.

Hardware translation/permission/access-flag faults are outside the current
MMU-off execution contract. Null/bounded user-copy error outcomes remain explicit
logical models, even though the physical image RAM is resident.

Memory tests cover both ISAs, high-alignment objects and odd BSS tails, legacy
padding/stack-symbol compatibility, adjacent RAM banks, missing NOLOAD storage,
one-byte holes, invalid numeric ranges, raw extent/content corruption, malformed
ELFs and rejection outside QEMU RAM before any machine starts. Eight existing
AArch64 ELF/raw executions across two relocated layouts also passed. The rebuilt
task scheduler image retains returns `2, -22, -22, -1`, exact ELF/raw RAM equality,
verified artifact hashes and zero startup padding outside load segments.
Loader-content tests also cover both ISAs, ELF/raw loading from initially dirty
RAM, split dumps, comparisons larger than 64 KiB, dirty zero-fill, wrong physical
bases, missing/overlapping dumps, CLI rejection without writing a success report,
and explicit map-only status. QEMU initial snapshots and successful subsequent
execution are checked for eight AArch64 images across the two relocated layouts.

This is a conservative memory provisioning contract, not a proof of all dynamic
accesses or stack depth. It neither reconstructs native page tables/TLB state nor
claims hardware bus behavior, RTL execution or timing equivalence.

Portable RTL initialization is provided by `tools/rtl_load_bundle.py prepare`.
It accepts the same ELF, optional raw binary and physical RAM map, with a new
output directory. The bundle stores its source ELF/raw files and a relative-path
`load-plan.json`: entry point, endianness, result range, entry requirements,
memory contract, source hashes, and addressed/hash-checked bank files. The bank
ranges merge required resident intervals (and the raw payload interval in raw
mode), so unrelated RAM capacity need not be emitted. Bank creation uses streamed
source copies and sparse zero extents; it includes ELF loader tails and harmless
zeros for legacy startup padding. Every byte of every bank must be loaded before
execution; sparse holes represent zero bytes, not optional writes into dirty RAM.

`verify DIRECTORY` derives the plan from the packaged ELF, validates raw identity,
checks initialized bank contents and recomputes all hashes. It rejects changed
entry/address/path/hash metadata, integer/bool aliases, bank truncation/extension,
corrupted initialized bytes and altered source files. Bundle relocation requires
no original capture/build paths. Hashes provide consistency checks, not signing
or source authentication. Generated inputs explicitly report
`model_initial_memory_verified: false` and `rtl_execution_verified: false`.
Actual testbench memory is checked separately with pre-execution dump verification.

The RAM-result runner's `--load-bundle DIRECTORY` option loads the addressed
files directly into QEMU and sets the ELF entry without using ELF/raw image
loading for those RAM contents. With `--initial-memory-dir`, it observes and
verifies the resulting physical memory before execution, including raw gaps.
This path is currently AArch64-only. ARMv7 initialization bundles can still be
prepared/verified; the legacy ARMv7 layout at 0x40000000 conflicts with QEMU's
bare-metal DTB placement ([QEMU virt boot documentation](https://www.qemu.org/docs/master/system/arm/virt.html)).
Tests exercise ELF/raw bundles for both ISAs, portable paths, independent plan
derivation, corruption rejection and no overwrite. Eight relocated AArch64
images execute from both ELF-derived and raw-derived banks with matching results
and verified pre-execution dumps. The task-scheduler bank bundle also retains
`2, -22, -22, -1` without guest host services.

`rtl_load_bundle.py check-loaded DIRECTORY --ram BASE:BYTES --memory-dump BASE:FILE`
checks actual testbench dumps against a verified bundle. Unlike the ELF-only
memory check, it constrains every bank byte, including ELF gaps/legacy startup
padding emitted in the bundle. It accepts adjacent split dump files, verifies
the actual supplied RAM map, rejects missing coverage/overlap/changed bytes, and
reports the exact physical mismatch address. Unrelated dump bytes are hashed
without constraining their values. Optional `--out` requires a new report file
and is written only after successful verification.

The report `osrec-rtl-loaded-bundle-verification-v1` links the load-plan hash and
source hashes to the compared physical ranges and dump hashes. It separates
`bank_files_verified`, `model_initial_memory_verified`,
`snapshot_phase_verified`, `cpu_entry_state_verified` and
`rtl_execution_verified`. A standalone caller asserts that dumps were captured
after loading all banks and before the first instruction; this cannot be inferred
from file contents, so snapshot phase remains unverified. The QEMU bank runner
now invokes this exact comparison before its first `cont`, verifies that phase
through its control sequence, and leaves CPU register claims false unless the
optional entry check is requested; RTL claims remain false. Both ISA
tests include a corrupted legacy padding byte accepted by the weaker ELF-only
initialization check and rejected by the full bank check. AArch64 execution tests
assert full bank-byte coverage and stopped-phase evidence for both bundle modes.

AArch64 entry snapshots are checked by `tools/aarch64_entry_state.py`, used by
`check-loaded --cpu-state FILE` and the QEMU runner's `--check-entry-state`.
The external snapshot format `osrec-aarch64-entry-state-v1` contains unsigned
integer `pc` (64 bits), `pstate` (32 bits) and `sctlr_el1` (64 bits). Missing fields,
booleans, negative/overflowing values and incorrect snapshot formats are rejected.
The conservative profile `osrec-aarch64-mmu-off-entry-v1` checks:

- PC equals the ELF entry.
- PSTATE.M selects AArch64 EL1t or EL1h; all DAIF masks are set.
- PSTATE.IL and SS are clear.
- SCTLR_EL1.M, C, I and EE are clear: MMU/caches disabled and little-endian EL1 data.

These checks include stricter provisioning conditions than the older sparse
EL1/MMU-off bundle metadata. They do not change existing images or require exact
values for unrelated register bits. Startup initializes its selected SP and VBAR;
those initial values and general-purpose registers are not checked. Register field
definitions are grounded in [Arm's register documentation](https://documentation-service.arm.com/static/5e7b6b167158f500bd5bf124)
and [QEMU's Arm state definitions](https://github.com/qemu/qemu/blob/master/target/arm/cpu.h).
The profile does not establish higher-EL trap configuration, pending external
events, ISA extensions, cache/TLB contents, complete architectural state or timing.
`cpu_entry_state_verified` means only the report's listed fields passed.

The QEMU observer uses local FIFO channels and a minimal read-only GDB remote
protocol client. It discovers register indices/widths through target XML and maps
QEMU Cortex-A53's `SCTLR` alias to SCTLR_EL1. It validates checksums, packet escapes
and repeats, bounded XML transfers, and required register presence/width. It
never downloads code, writes registers, steps, continues or detaches. This needs
no GDB installation or TCP/Unix socket listener. QMP confirms the CPU is stopped
before and after observation, before any `cont`. Raw snapshots and hashes are
saved beside memory dumps. The control sequence verifies the snapshot phase in
QEMU; caller-supplied files cannot establish their capture phase.

Loaded bundle reports with CPU evidence use `osrec-rtl-loaded-bundle-verification-v2`
and include `cpu_entry_verification`, the state-file hash and bounded-check scope.
Without CPU evidence, reports remain v1 with CPU verification false. Tests reject
wrong PC/EL/execution state, unmasked exceptions, illegal/step state, enabled
MMU/cache/big-endian data, malformed values, unavailable/duplicate registers and
forbidden debugger writes/control packets. Both ELF/raw bank variants of eight
relocated AArch64 images pass memory and CPU checks before successful execution.

Higher-level baseline controls are covered by
`osrec-aarch64-entry-state-v2` / `osrec-aarch64-mmu-off-entry-v2`. V1 snapshots and
their existing register checks remain supported, with higher-level verification
false. V2 adds an explicit `implementation` object containing boolean
`el2_implemented` and `el3_implemented`; these cannot be inferred from absent
debugger registers. All v2 snapshots require `mdscr_el1`. Implemented levels
require their control registers as unsigned 64-bit values:

| Condition | Required register | Accepted baseline constraint |
| --- | --- | --- |
| Always | MDSCR_EL1 | Zero |
| EL2 implemented | HCR_EL2 | RW only (`0x80000000`); other bits zero |
| EL2 implemented | CPTR_EL2 | Only bits in `0x33ff` may be set (baseline RES1 positions) |
| EL2 implemented | MDCR_EL2 | Only HPMN bits 4:0 may be set |
| EL3 implemented | SCR_EL3 | NS/RW set; optional FW/AW; all other bits zero |
| EL3 implemented | CPTR_EL3, MDCR_EL3 | Zero |

These are conservative provisioning constraints. They cover baseline
virtualization, routing, injected exceptions, feature/system-register traps and
debug controls; they do not establish extension-specific fine-grained traps or
full architecture-feature compatibility. The CPTR reserved-bit allowance follows
[Arm's baseline register layout](https://documentation-service.arm.com/static/5e906b9fc8052b1608760b6b).
When a level is declared absent, its registers are omitted; supplied values for
that level are rejected as contradictory. Missing required controls, incorrect
types, enabled traps/stage 2/debug state and unsupported control values fail.

The QEMU observer identifies CPU 0 through `query-cpus-fast`, observes `has_el2`
and `has_el3` through QOM, and conditionally discovers/reads registers from XML.
These CPU properties govern actual implemented levels
([QEMU Arm CPU realization](https://github.com/qemu/qemu/blob/v9.2.0/target/arm/cpu.c)).
The report records the QOM path/backend and sets `implementation_presence_observed`
true. Standalone files instead contain caller declarations and retain that flag
false; their physical provenance is not established by validation. A successful
v2 report sets `higher_el_trap_configuration_verified` true only for the listed
baseline controls/absence declarations, while architecture-feature verification
remains false. The same memory snapshot and before-first-`cont` phase apply.

All eight relocated AArch64 bank executions now verify v2 evidence with EL2/EL3
observed absent and debug control clear. A separate stopped QEMU model with both
levels present exercises real register discovery/capture and rejection of EL3h
reset as an EL1 entry. Unit fixtures cover valid conservative combinations of
implemented levels and corruption of each control/presence field. The optional `--boot-from-el3` path now also executes both bank variants of
these eight images with EL2 and EL3 implemented. A generated stackless shim at
`0x43f00000` configures the conservative controls, disables the listed EL1
MMU/cache/endian bits and enters nonsecure EL1h through `eret`. Its page must
not overlap any replay range or raw payload. Sources, disassembly, ELF, binary
and a hashed load plan are persisted for separate model loading.

A separate external breakpoint controller installs/removes one hardware
breakpoint at the ELF entry and continues only the boot transition. It uses
execution-control packets; the register reader still accepts only reads. Neither
writes guest registers or memory. The reset snapshot confirms EL3h and the boot
entry; the replay snapshot confirms EL1h and the supplied ELF entry. Reports say
before the first replay instruction after boot, rather than before any machine
instruction. Every replay bank byte is compared again at this checkpoint. The
boot bytes have a separate exact comparison at reset and at the replay entry.
Each comparison checks all 104 bytes against a verified payload; reserved boot
page padding is unconstrained. The boot verifier independently re-derives the
reviewed instruction template and ELF-entry MOV immediates, rejects mutated code
or plan fields, and never follows plan-supplied filenames. The optional standalone
physical dump check requires RAM coverage of the complete reserved page, accepts
split contiguous dumps, and retains an unverified capture phase. Tests reject
mutated instructions, manifest paths/control values, wrong entry bindings,
missing dump coverage, and changed first/last physical payload bytes.

The scheduler bundle also passes this path with results `2, -22, -22, -1`.
Replay runs at EL1 under implemented/configured EL2/EL3, without runtime guest
host services. This is QEMU functional evidence, not RTL/cycle validation, full
architectural-state verification, or natural MMU fault replay.


Combined boot/replay artifacts use `osrec-rtl-el3-boot-bundle-v1`. The root plan
lists relative physical loads, the EL3 boot entry, ELF replay entry, result
address, declared RAM and reset requirements. Fixed nested paths `replay/` and
`boot/` are independently verified before deriving and comparing the root plan;
no unverified manifest filename is used to select inputs. Preparation validates
boot-page coverage and collision before creating output, never overwrites an
existing bundle, and removes new partial output on failure.

The QEMU `--boot-bundle` path loads packaged bytes with no runtime compiler use.
Tests remove the original replay bundle and auxiliary boot build files, execute
all eight relocated images in ELF/raw bank modes, and exercise two boot-page
addresses. Both boot snapshots and complete replay-bank checks must pass before
the same functional result is accepted. Independent combined dump checks include
optional EL1 CPU checks, retain an unverified phase, and reject root plan/path
mutations, changed boot/bank bytes, missing dumps and physical-byte mismatches.
The loader plan describes generated artifacts and does not itself verify model
state or RTL execution.


Project acceptance uses QEMU; customer RTL execution is outside this verification
workflow. `verify_qemu_bundle.py` handles replay-only and combined EL3 bundles,
checks their artifacts before launch, requires observed checkpoint phases and
successful replay results, and independently rechecks persisted dumps and listed
CPU fields. It saves QEMU version, bundle plan hash, raw result, execution report,
memory/CPU evidence and evidence hashes under one new directory. Failures after
directory creation are recorded as failed and propagate to a nonzero command
exit. Tests exercise both bundle types, output collision rejection and failed
acceptance without a successful result artifact. These functional checks do not
expand the bounded analysis or architecture-feature verification scope.


Practical clock queries use a reviewed boundary profile for `SysClockGettime` and
`SysClockGetres`. Source locks cover the pinned syscall source, lookup table,
clock provider source and native libc ABI headers. The unchanged root bodies
consume recorded clock-provider results and errno, then execute their actual
branching and safe-copy calls through a bounded copy model. These roots require
no discovered process-object field restoration; provider internals remain
outside this profile.

Native capture makes ten SVC calls (two successful clock IDs, invalid ID, NULL
output and invalid output per root), forwarding all provider and user-copy calls.
It resets errno to zero outside each body and restores it after recording the
result. Fourteen events include eight provider calls and six copy attempts.
Every successful and failed output witness is checked. The configured ABI is a
16-byte struct with signed 64-bit seconds, 32-bit nanoseconds at offset 8 and
four padding bytes; capture and AArch64 replay assert its layout. Replay uses
ABI 11, verifies all call outputs and errno, and requires exact event consumption.

Tests reject capture sizes, call identities/modes, event order, copy sizes,
padding, hash/config changes and Boolean substitutions. Full-width timestamp
fixtures and two image layouts pass ELF/raw bank loading with direct EL1 and
EL3 boot on QEMU. Target corruption tests force dependency, errno, copy-data and
output-state divergence. A separate live regression performs actual native
capture and verifies both bank modes and boot paths. Runtime replay consumes
captured values with no clock/host service and does not reproduce timer timing
or the native invalid-pointer hardware fault mechanism.


Resource-limit queries use a reviewed `SysUgetrlimit` profile, locked to the
original misc syscall body, provider source, lookup table and libc limit ABI.
The capture makes six native SVC calls: file-descriptor/file-size limits, invalid
resource, valid resource with NULL/invalid output, and unsupported CPU resource
with NULL output. All six provider calls and four real safe-copy attempts are
forwarded and recorded. The last call verifies provider-error precedence over
NULL output; the original body performs no preliminary pointer rejection.

The model preserves two unsigned 64-bit limits and all 16 output bytes. It
consumes recorded getrlimit values and implements the bounded copy outcomes;
provider internals/process limit objects are outside this boundary profile.
Capture uses a scoped zero errno fixture and restores prior errno after each
body. Unlike the clock wrappers, the native resource-limit body returns negative
errors directly without setting errno. ABI 12 verifies six outputs/returns,
six providers, four copies, 32 copied bytes and ten consumed events.

Native capture and QEMU replay pass both ELF/raw bank variants and EL1/EL3 starts.
Synthetic ABI tests separately cover high-bit limits and UINT64_MAX at two
relocated layouts. Validators reject call/mode/result identity, event ordering,
copy-size/payload, hashes, configuration and Boolean substitutions. Target tests
force dependency-kind, 64-bit reconstruction, source-copy and output-state
corruption. Source and construction inputs can be removed before execution.


The practical `uname` profile binds the pinned `SysUname` body, native provider
source, SVC lookup, and OHOS `utsname` header. Its entry dependency includes all
390 caller bytes, since OHOS copies them before updating six 65-byte identity
fields. Two different initial patterns expose preserved string tails; two guard
bytes verify the output-copy extent. NULL and address 1 fail the real native
input copy before the provider. Eight ordered events record four input attempts,
two provider outputs and two output copies. The AArch64 image checks the entire
input/provider/output data path and four caller witnesses. It retains the
captured native identity rather than generating AArch64 or host identity strings.
The base profile excludes UTS containers and injected failures; it models
dependency API outcomes rather than the native
MMU fault mechanism or provider internals. Tests reject malformed capture
extents/order/mode/padding, mismatched output/guard bytes, hashes, manifest
checkpoints and capture flags; deliberate target changes fail in QEMU. Functional
acceptance covers relocated ELF/raw banks and direct EL1/EL3-to-EL1 starts, with
physical-memory and CPU-entry checks and runtime host services disabled.


`--uname-faults` adds four explicitly injected boundary outcomes: 195 bytes copied
from the caller then input failure, provider `-EIO` without writes, zero-write
output failure, and 195 bytes copied to the caller then output failure. The
original native `SysUname` body takes each branch. Capture omits uninitialized
input-copy suffix bytes, encoding zero in the unused payload suffix. Native
instrumentation checks that the partial input operation preserves the remaining
temporary bytes. Replay writes only the recorded prefix, and input failure
prevents any provider invocation. Provider failure preserves the temporary and
skips output copying. Output failure preserves the caller suffix and guards.
The extended ABI 14 checks eight calls, five providers, eight input attempts,
four output attempts, 17 events and 3120 copied bytes; ABI 13 remains compatible.
Capture and image manifests explicitly identify fault injection, and export
rejects mismatched provenance or capture flags. Target mutations that over-copy,
suppress provider errors or suppress input errors fail on QEMU. These controlled
API outcomes do not reproduce fault-handler/MMU internals or natural provider
failure conditions. UTS containers and arbitrary partial-copy extents remain
outside the reviewed profile.


The practical `close` profile source-binds `SysClose`, process descriptor
operations and table layout, the SVC lookup, native close-provider entry source,
and OHOS errno macro. Entry state covers descriptor 4's association, allocation
bit and close-on-exec bit, with a captured system descriptor supplied by a
preceding native `open(O_CLOEXEC)`. Fifteen events observe native detachment,
close-provider results, restoration attempts and free effects for five SVC calls.
One scoped EIO provider failure occurs before release: the original syscall
restores the association and propagates errno while preserving both flags. Real
native retry succeeds and clears association/allocation/cloexec. Repeated close,
negative and out-of-range descriptors propagate EBADF while leaving free state
unchanged. Source `get_errno()` expands to a native errno read; errno/result
witnesses validate its propagation rather than inventing a native callback event.
AArch64 replay applies independently reviewed bounded descriptor transitions
and a modeled system-descriptor lifetime, checking every event and entry/effect
witness. ABI 15 additionally requires four errno reads, five detach/provider
calls, four restoration attempts and one free. The first close failure is marked
as injected, and initial open, full tables/locking, provider internals, sockets,
standard descriptors and concurrent close are outside scope. Tests reject
capture field/state/order/hash/config/provenance corruption and make target
rollback, free/cloexec, errno or lifetime mutations fail. Functional QEMU
acceptance covers distinct process/system descriptor numbers, relocated ELF/raw
banks and EL1/EL3-to-EL1 entry with no runtime host filesystem/services.


The practical `dup` profile binds the original `SysDup`, process descriptor
operations/table layout, SVC lookup, native file-reference implementation and
file layout. Capture records three normalized slots (4..6: mapping, allocation,
close-on-exec) and the shared native file reference count. A dedicated native
open supplies descriptor 4 with close-on-exec and reference count 1. Five calls
exercise scoped allocation failure with no effects, two successful duplicates
(including duplication of the first duplicate), and negative/out-of-range
process IDs. Twelve ordered events observe five lookups, three allocation
attempts, two native file-reference increments and two associations. Each native
syscall also records its descriptor limit and complete entry/effect witness.
The AArch64 image independently applies reviewed bounded transitions, preserves
the shared system descriptor, observes references 1..3, and keeps close-on-exec
only on the original. Direct raw error returns leave the errno-zero fixture
unchanged. ABI 16 checks final association/allocation/cloexec/reference fields
and all counters. Tests use distinct process/system IDs and descriptor bounds,
relocated ELF/raw banks and EL1/EL3 starts; capture corruption and target reference,
allocation, alias and flag mutations fail. Allocation injection is explicitly
marked and checked during export. Initial open, full allocator/table internals,
locking/concurrency, socket/system-descriptor upper-bound rejection, arbitrary
reference counts and shared read/write-position semantics are outside the
reviewed profile. Runtime host filesystem/services are absent.
