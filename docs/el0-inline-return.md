# Generated user returns

The newer [combined runtime optimizations](el0-runtime-optimization.md), with LTO, retain all
2,136 syscall gateways and reduce runtime/adaptation instructions further to
**4,465,783 (1.4684:1)**. The latest return comparison chain and paired field
loads save another 36,336 instructions while retaining every context check.
The user-return measurement below is an earlier baseline.

Checked ERET-to-user paths now run in generated assembly, removing **2,271
runtime gateway entries (48.82%)** and **586,335 runtime/adaptation instructions
(8.12%)** from the preceding image. ERET remains emulated at EL0.

Delivered [ELF](../build/el0-user-return-20261114a/checkpoint), SHA-256
`a7ecfe686142fd22f4f940080a8a6331ab8e8169b5c3712e3aa0d90a57c24393`.

## Transition

The pretranslated exporter emits a path at each of the two original ERET
sites. It admits a kernel-to-user return only after checking:

- SPSR selects EL0t and contains only the shared emulator's admitted bits.
- A syscall/fault entry context has been recorded.
- The captured translation root, TCR and every descriptor check still match.
- The live destination is aligned and has an entry in the immutable user PC
  index, using the full 64-bit address range.
- Every required GPR, user SP and return PC matches the recorded context.
  Syscall returns may change X0 and advance PC by four; fault returns may not.

Only six scratch GPRs and NZCV are saved on the native kernel stack. All checks
precede architectural-state updates and writes to the user stack. A successful
path increments the shadow emulation count, restores DAIF/PAN and user NZCV,
records the kernel SP, clears the saved-context validity flag, selects the user
SP and branches through the existing direct resume thunk. SSBS is retained in
the control block's logical PSTATE field. SIMD registers, FPSR and FPCR stay
live and unchanged; there is no C call or 800-byte context capture/restore.

The scratch frame uses 64 bytes below kernel SP, as the existing indirect
adapters do. The user resume thunk writes/restores X16/X17 in the same 32-byte
headroom already used by native capture. Kernel and user stacks remain under
the pretranslated backend's native-stack admission contract.

Any failed check restores the original GPRs, SP and NZCV and falls into the
original ERET gateway. Shadow state and the recorded user context are unchanged
before fallback. The shared emulator and runtime admission retain their exact
diagnostic order and stop details. Returns to kernel code, absent snapshots,
lowered metadata and exports without the pretranslated user index retain the
general path. Existing generated exports remain supported by the runtime.

## Measurement

QEMU 9.2.3 TCG Cortex-A53, one vCPU, `PROFILE=1`. Counts include all new inline
checks and guest profiling; these are instructions, not cycles.

| Execution-interval metric | Inline system inputs | Generated user returns |
| --- | ---: | ---: |
| Runtime gateways | 4,652 | **2,381** |
| System gateways | 2,320 | **49** |
| Runtime functions | 2,296,535 | **1,059,344** |
| System adapters | 1,261,745 | 1,926,227 |
| Resume thunks | 265,866 | 252,240 |
| All runtime/adaptation instructions | 7,217,459 | **6,631,124** |
| Native kernel instructions | 2,830,860 | 2,830,860 |
| Native application instructions | 131,951 | 131,951 |
| Original kernel operation visits | 3,041,214 | 3,041,214 |
| Total instructions | 10,180,270 | **9,593,935** |
| Runtime / original kernel operations | 2.3732:1 | **2.1804:1** |

The net reduction includes increased generated-system-adapter work, rather than
counting only removed C instructions. Whole-ELF instructions fall to 9,735,929;
startup/final validation remains 141,994. The ELF grows by 1,584 bytes to
159,197,080 bytes. The **0.20:1 ceiling** and **0.10:1 target** remain unmet.

All **2,272 events**, **nine ordered counter inputs** and **92 UART bytes** match,
with identical memory profiling: 185 recorded faults and five memory
post-operations. Hardware exceptions, runtime EL1 services and host calls before
completion remain zero. RAM and page tables remain embedded. Captured payloads,
initial state, mappings and call-specialization proofs match the preceding
export byte for byte; generated assembly and runtime context storage change.

Remaining gateways are **2,136 syscall entries**, **49 residual ERET entries**,
**195 memory pre/post operations** and **one final boundary**. The system profile
counts actual remaining gateway entries; inline returns still increment the
shadow emulation counter. Syscall entry is now the largest gateway group.
The largest instruction categories are system adapters (1,926,227), indirect
adapters (1,409,909), memory adapters (1,258,749) and runtime functions (1,059,344).

- [Counts](../build/el0-user-return-profile-20261114a/counts.json)
- [Measured workload validation](../build/el0-user-return-measurement-20261114a/validation.json)
- [Loaded code/data identity](../build/el0-user-return-profile-20261114a/profile-plan.json)
- [Hotspots](../build/el0-user-return-profile-20261114a/hotspots.json)
- [Budget assessment](../build/el0-user-return-profile-20261114a/budget.json)

## Verification and reproduction

The differential fixture executes 67,584 cases against the shared ERET emulator.
It covers every bit of every GPR including scratch aliases and X30, syscall/fault X0 rules,
native SP, return PC, all NZCV combinations, each SPSR bit, DAIF/PAN/SSBS,
emulation-count wrap, root/TCR changes, masked descriptor changes, absent
snapshots, missing PC pages/slots, alignment and address bounds. It checks
unchanged user-stack bytes on rejection and verifies SIMD/FP state preservation.

Five corrupted full-image runs retain the original GPR (`0x106`), PC (`0x107`),
descriptor (`0x105`), kernel SP (`0x104`) and cross-domain (`0x103`) stops, without
hardware exceptions, EL1 services or host calls. Shared-emulator, runtime-context
and ordered-input tests pass; the runtime also compiles without profiling.

Use the [pretranslated-memory export/build procedure](el0-pretranslated-memory.md#build-and-verify)
with fresh directories, then run:

```sh
python3 -m unittest discover -s tests -p test_el0_return.py -v
OSREC_EL0_RUNTIME_FAST_IMAGE=build/el0-user-return-20261114a \
OSREC_EL0_NATIVE_STACK_IMAGE=build/el0-user-return-20261114a \
OSREC_EL0_PRETRANSLATED_IMAGE=build/el0-user-return-20261114a PYTHONPATH=tests \
  python3 -m unittest \
    test_el0_runtime_hot.RuntimeImageDiagnostics \
    test_el0_native_stack.NativeStackImage.test_bad_sp_and_cross_domain_vector_stop_before_native_access \
    test_el0_pretranslate.PretranslatedImage.test_descriptor_mismatch_stops_at_return_without_hardware_service -v
```

Use `build/el0-user-return-objects-20261114a` for the matching runtime objects
when reproducing the [instruction measurement](el0-instruction-profile.md#reproduce).
Finalize the annotated copy with `PRETRANSLATE=1` before checking loaded code/data
identity; execute the original ELF for measurement.
