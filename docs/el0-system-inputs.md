# Inline system inputs

The newer [generated user-return paths](el0-inline-return.md) reduce gateways
further to 2,381. The [optimized syscall runtime](el0-runtime-optimization.md)
retains that count and reduces runtime/adaptation to **4,465,783 (1.4684:1)**.
The input-path measurement below remains the preceding baseline.

Ordered counter reads and TPIDRRO_EL0 writes now execute in generated code,
removing **12 dynamic runtime gateway entries** from the captured workload.
The delivered ELF is [checkpoint](../build/el0-system-inputs-20261114a/checkpoint),
SHA-256 `6d512d11dc80840e08b44776adfe264c5bcf9e4845281f1e935a478c1f294647`.

## Behavior

`counter_path` admits only unlowered CNTVCT_EL0/CNTPCT_EL0 reads. It checks the
live input cursor against the table length, then the next input's source PC and
register key. Success consumes that input, writes the destination unless it is
XZR, and increments the shadow emulation count. The input sequence remains
embedded data; it does not select control flow. No host timer is read.

A mismatch restores every scratch register and NZCV, leaves the input cursor
and shadow state untouched, and falls through to the existing gateway. The
shared emulator then produces the original unsupported-input diagnostic.
Bounds are checked before dereferencing the input table. Both inline and
fallback paths reject a cursor at or beyond the input count.

TPIDRRO_EL0 writes update shadow state and set the known bit even when no
initial value was captured, matching the shared emulator. The flat backend's
platform callback is empty; its virtual thread register is never host TLS.
Reads retain their known-bit check and fall back when unknown. Metadata for
lowered operations retains the existing gateway.

These paths preserve all unrelated GPRs, native SP, NZCV and SIMD state. They
apply to new hardware-memory exports; old generated assembly still works with
the shared runtime. The C header asserts the counter-table offsets and stride
used by the generated assembly.

## Measurement

QEMU 9.2.3 TCG Cortex-A53, one vCPU, `PROFILE=1`. Counts include the new inline
checks and unchanged guest profiling. These are dynamic instructions, not cycles.

| Execution-interval metric | Specialized dispatcher | Inline system inputs |
| --- | ---: | ---: |
| Runtime gateways | 4,664 | **4,652** |
| System gateways | 2,332 | **2,320** |
| Runtime functions | 2,302,377 | **2,296,535** |
| All runtime/adaptation instructions | 7,223,211 | **7,217,459** |
| Native kernel instructions | 2,830,860 | 2,830,860 |
| Native application instructions | 131,951 | 131,951 |
| Original kernel operation visits | 3,041,214 | 3,041,214 |
| Total instructions | 10,186,022 | **10,180,270** |
| Runtime / original kernel operations | 2.3751:1 | **2.3732:1** |

Runtime falls by **5,752 instructions (0.0796%)**. Inline system adapters grow
by 198 instructions while runtime functions and resume thunks shrink; the net
improvement includes all these costs. Whole-ELF execution falls to 10,322,264
instructions, with unchanged 141,994 startup/final-validation instructions.
The ELF grows by 592 bytes to 159,195,496 bytes. The **0.20:1 ceiling** and
**0.10:1 target** remain unmet.

All 2,272 events, nine ordered counter inputs and 92 UART bytes match. The
185 recorded faults and five memory post-operations retain identical memory
profiling. Hardware exceptions, runtime EL1 services and host calls before
completion remain zero. RAM and page tables remain embedded. Payloads,
mapping metadata, initial state and call-specialization proofs match the
preceding export byte for byte; generated assembly changes for the new paths.

The remaining gateways comprise 2,136 syscall entries, 2,320 ERET operations,
195 memory pre/post operations and one final boundary. System profiling now
contains only ERET; removed counter/thread operations still increment the
shadow emulation count. This profiling table describes actual gateway entries.

- [Counts](../build/el0-system-inputs-profile-20261114a/counts.json)
- [Measured workload validation](../build/el0-system-inputs-measurement-20261114a/validation.json)
- [Loaded code/data identity](../build/el0-system-inputs-profile-20261114a/profile-plan.json)
- [Hotspots](../build/el0-system-inputs-profile-20261114a/hotspots.json)
- [Budget assessment](../build/el0-system-inputs-profile-20261114a/budget.json)

## Verification and reproduction

The executable fixture runs 6,272 cases covering both counter keys, input PC/key
mismatches, exhausted and out-of-range cursors, a null table on rejected reads,
emulation-count wrap, known/unknown thread state, scratch/destination aliases,
XZR, X30, all NZCV combinations, native SP and SIMD preservation. Thread state
is compared with the shared emulator. Three corrupted full images independently
verify PC mismatch, key mismatch and empty-input diagnostics, with no hardware
exception or runtime EL1 service. Runtime/context and instruction-profiler tests
also pass; the runtime compiles without guest profiling too.

Use the [pretranslated-memory export/build procedure](el0-pretranslated-memory.md#build-and-verify)
with fresh directories. Then run:

```sh
python3 -m unittest discover -s tests -p test_el0_system_inputs.py -v
OSREC_EL0_SYSTEM_INPUTS_IMAGE=build/el0-system-inputs-20261114a PYTHONPATH=tests \
  python3 -m unittest test_el0_system_inputs.FullImage -v
```

The [instruction profiler](el0-instruction-profile.md#reproduce) uses the matching
runtime object directory `build/el0-system-inputs-objects-20261114a`. Finalize the
annotated copy with `PRETRANSLATE=1` before checking loaded code/data identity.
