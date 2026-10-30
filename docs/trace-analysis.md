# Choosing sufficient observations with KLEE

OSREC uses KLEE offline to check whether a proposed trace determines the declared execution slice. Instead of replacing an omitted observation with an arbitrary default and testing a few runs, the implemented analysis executes the same slice twice, with a shared checkpoint and independent symbolic environment inputs.

The end goal is a self-contained executable reproducing the captured scenario. KLEE therefore analyzes which recorded information must be embedded in that executable, and whether its reconstruction runtime can drive the included code. The behavior contract must include the execution/context relationships required by the selected scenario as well as outputs and effects. The current `SysRead` checker covers a bounded sequential functional contract, and [standalone export](standalone-export.md) now packages that scenario as one executable. Extending the contract to scheduling and interrupts remains integration work.

```text
                     same checkpoint
                      /           \
          symbolic environment A   symbolic environment B
                     |             |
              execute slice A   execute slice B
                     |             |
               proposed trace   proposed trace
                      \           /
                 equal retained observations?
                             |
                 different outputs or effects?
                      /                \
                    yes                 no, complete bounded search
                     |                           |
          counterexample: retain field     omission supported
                                                 |
                                      trace-driven replay check
```

For fixed code and checkpoint `C`, environment inputs `E`, trace projection `T` and declared contract `O`, the required property is:

```text
T(C, E1) == T(C, E2)  =>  O(C, E1) == O(C, E2)
```

KLEE searches for a pair violating this implication. A native-confirmed violating pair establishes that the proposed trace is insufficient. No violation supports the property only if exploration completes without unresolved errors, within the stated code, models and bounds. Partial exploration is `unknown`, never evidence for deleting a field.

This property establishes that retained observations determine the contract. A separate decoder check establishes that our replay adapter can actually reconstruct and execute the slice using those observations. It receives only the checkpoint and a projected trace whose omitted values and presence bits have been erased. It reconstructs a representative modeled environment, reruns the real syscall and application code, and checks the contract and reconstructed trace. It does not restore expected output memory as a substitute for executing the code.

## Implemented LiteOS-A example

The source-pinned `SysRead` slice and environment boundaries are described in [the KLEE integration](klee-liteos.md). The shared checkpoint contains descriptor 0–4, request size 0–9 and null-buffer selector 0–1; the eight-byte user buffer initially contains `0xa5`. Address validation and descriptor mapping are fixed models. Independently symbolic environments choose success/EINTR/EIO, a successful-read limit 0–4 and four payload bytes. Variable successful-read length is included specifically to avoid assuming a full read.

The declared contract compares user return, errno, recognition flag, all eight user-buffer bytes and address/descriptor/read/errno boundary invocation counts. It is functional replay with dependency-call shape, not instruction-accurate execution or every internal branch in the environment models.

Six manually identified boundary observations are candidates:

| Observation | Encoding |
| --- | --- |
| `read.result` | Presence when the backend executes, plus signed result |
| `errno.value` | Presence when `get_errno` executes, plus errno |
| `read.payload[0..3]` | For each retained byte, presence when written and its value |

Field presence is real trace information. For this encoding, retained byte presence determines the written length. Losing that metadata invalidates the return omission. A production format could encode a contiguous span and its length instead; that would be a different trace projection requiring its own check.

The runner starts with all six fields, greedily proposes one deletion at a time and retains a deletion only after a completed sufficiency check. It validates a witness for every remaining field against the final plan with that field removed, then checks transcript-driven replay for the final plan. This yields an inclusion-minimal set for these candidates: no retained field can be individually deleted. It does not claim a globally cheapest encoding or minimum kernel trace size.

## Observed result

The selected mask is 62: retain errno-event presence/value and the presence/value of bytes actually written; omit the separate backend return. On a successful read, byte presence reconstructs the count. On a backend failure, errno presence/value reconstructs the modeled failure. Fixed checkpoint models determine zero-length handling, address faults and invalid descriptors. An executed backend can return zero without an errno event or payload entries.

KLEE found and native execution confirmed five deletion counterexamples. For example, with descriptor 3, request size 8 and a valid buffer:

```text
execution A: backend EINTR -> user return -1, errno 4
execution B: backend EIO  -> user return -1, errno 5

omit errno: both traces have no returned bytes, yet user errno differs
```

For the last payload byte, two successful four-byte reads with payloads `40000000` and `40000002` collide when byte 3 is omitted, but produce different user-buffer contents. Other witnesses distinguish different short-read lengths when the observation carrying a needed presence bit is removed.

In the validated LLVM 16/KLEE 3.2 run, the full and reduced plans each completed 45 paths and native-replayed 45 generated tests. The separate reduced-plan decoder check completed 11 paths and native-replayed 11 tests. Every accepted check had zero partial paths. Five counterexamples established individual necessity of the retained candidates.

These counts describe the declared model. They are not real kernel coverage, device timing or a measured overhead reduction. The analysis currently identifies observations; it does not install probes in LiteOS-A or emit a production capture format.

## Run and inspect

```sh
python3 tools/analyze_trace.py \
  --kernel-root build/kernel_liteos_a --out build/trace-analysis \
  --llvm-bin /opt/homebrew/opt/llvm@16/bin \
  --klee-include /opt/homebrew/opt/klee/include
```

Use `--klee` for a different KLEE executable and `--max-time` to change the per-check time budget (default 60 seconds). The runner uses Z3 without a forked solver and a subprocess timeout; timeout or incomplete exploration cannot certify an omission. A deliberately restricted one-second run rejected the full plan as uncertified. A repeat with 20 seconds retained the return observation when that deletion's search timed out; the default budget was increased without changing the bounds. Analysis bitcode is compiled with `-O1` and vectorization disabled to reduce incidental harness branching. The earlier scenario remains an independent `-O0` check. Toolchain and address-model limitations from the integration apply here as well.

`trace-plan.json` records bounds, contract, selected fields, compilation/solver settings, source and tool hashes, module hashes, completed checks, unknown results and native-confirmed witnesses. KLEE directories contain error files and concrete KTests. The paired native executable accepts a mask, common request and two environments; the runner natively checks accepted-plan generated tests and replays each insufficiency witness.

Enable `OSREC_BUILD_LITEOS_KLEE_SCENARIO` in CMake to run the original combined scenario, trace-analysis regression and standalone export checks. With the LLVM planner, EL0 analysis/extraction and default object-checkpoint checks enabled there are sixteen CTest suites. The separate LLVM 16 EL0 build can enable KLEE scalar export checks with `OSREC_BUILD_EL0_EXPORT_TESTS`. The trace-analysis regression requires the derived return omission, retained-field counterexamples and successful transcript-driven replay; it does not require fixed path counts across toolchain changes.

## Extend the analysis to kernel capture

1. Generate candidate observation sites from the pinned code closure and static effect/alias summaries. Current candidates are manually authored and are not yet imported from the LLVM planner. Keep uncertain memory, indirect calls and architecture effects explicit.
2. Vary uncaptured incoming state independently between the two executions, including user-memory bytes, mutable descriptor state, shared objects and external observations. A value fixed in both executions cannot be shown necessary by this test. Treat checkpoint contents as candidates too when snapshot reduction becomes supported.
3. Represent observation ordering, dynamic occurrences, object generations and selected event presence in the actual proposed trace format. Check arguments and side effects of transcript operations, not just return values.
4. Add bounded scheduling and interrupt choices to both executions, together with relevant handler/cooperating code or reviewed effect models. Same recorded events with different task outputs or handler effects must be a counterexample. Hardware delivery and arbitrary SMP races require an explicit model; ordinary sequential KLEE execution does not supply it.
5. Analyze guarded omissions so an observation is recorded only on paths where reconstruction needs it. Recheck the whole policy; a field necessary on one path need not be recorded on all paths.
6. Bind a supported plan to the exact optimized module, ABI, models, bounds and instrumentation sites. Invalid or unsupported executions retain a conservative trace or reject the capture. KLEE supports finding omissions offline; actual recorder overhead must be measured on the target device.

KLEE's assumptions constrain the symbolic input domain, so the report must make each bound visible. Equality of the two traces is tested as an implication rather than an assumption: unequal pairs finish normally, preserving a useful zero-partial-path completion check. [KLEE intrinsics](https://klee-se.org/docs/intrinsics/)
