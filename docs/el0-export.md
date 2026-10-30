# Exporting a verified scalar EL0 executable

`tools/export_el0.py` constructs one executable containing the extracted computation, a concrete argument checkpoint, an expected return value and embedded provenance. It runs on the matching host OS without LLVM, KLEE, the source checkout or its construction sidecars. The validated platform is macOS ARM64 with the normal system runtime. It recompiles source-level kernel computation for a host user process; it does not run an original privileged kernel image.

The first generic export contract accepts an `i32` return and up to six `i32` arguments, interpreted as unsigned argument bits. Code must have a closed, nonrecursive call closure, complete callback targets, no external model boundaries, no global bindings or pointer interfaces, and only supported modular integer operations and initialized private stack memory. Overflow flags, shifts/division, unsupported instructions, unresolved callbacks and external state are rejected. This intentionally narrow contract makes the initial equivalence obligation explicit.

```text
exact input bitcode
        |
        +--> call/memory analysis --> supported scalar contract
        |
        +--> reference entry -----------------------+
        |                                          |
        +--> dependency slice --> extracted entry -+--> KLEE comparison
                                                        |
                                      complete, zero errors/partial paths
                                                        |
                                      native differential replay of KTests
                                                        |
                                      checkpoint + extracted code + checks
                                                        |
                                               one host executable
```

## Build the matching analysis and KLEE toolchain

KLEE and the compiler/plugin must use the same LLVM major. This workspace uses KLEE 3.2 and LLVM 16.0.6:

```sh
cmake -S . -B build/el0-llvm16 -G Ninja \
  -DOSREC_BUILD_EL0_ANALYZER=ON -DOSREC_BUILD_EL0_EXPORT_TESTS=ON \
  -DOSREC_BUILD_LLVM_PLANNER=OFF \
  -DLLVM_DIR=/opt/homebrew/opt/llvm@16/lib/cmake/llvm \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm@16/bin/clang++
cmake --build build/el0-llvm16
ctest --test-dir build/el0-llvm16 --output-on-failure
```

The LLVM 22 recorder planner remains separate. The EL0 analyzer and extraction pass work with both majors; symbolic export here is validated with LLVM 16.

## Extract the callback example

```sh
mkdir -p build/el0
/opt/homebrew/opt/llvm@16/bin/clang -O0 -g -fno-builtin -emit-llvm -c \
  examples/el0_callback_slice.c -o build/el0/callback16.bc
python3 tools/export_el0.py build/el0/callback16.bc \
  --root callback_scenario --arguments '[100,1]' \
  --llvm-bin /opt/homebrew/opt/llvm@16/bin \
  --plugin build/el0-llvm16/osrec_el0.so \
  --out build/scenarios/callback_slice
build/scenarios/callback_slice
build/scenarios/callback_slice --describe
```

The LLVM 16 root falls from 23 instructions to 13, removing four debug intrinsics and six ordinary instructions. Both finite callback targets remain available. KLEE completes two paths with zero partial paths for all combinations of the two 32-bit arguments; both generated tests pass native differential replay. The packaged checkpoint returns `107`. These counts are toolchain-dependent and are not recorder overhead measurements.

## Export actual pinned LiteOS-A computation

`tools/prepare_liteos_el0.py` verifies the pinned checkout revision, file hash and exact `LOS_Align` body from `kernel/base/misc/los_misc.c`. It retains the source license and uses explicit 32-bit `UINTPTR`/`UINT32` integer widths from the Cortex-A7/AArch32 configuration. These values do not become host pointers. The preparer emits hash-bound source identity for the exporter.

```sh
python3 tools/prepare_liteos_el0.py \
  --kernel-root build/kernel_liteos_a \
  --llvm-bin /opt/homebrew/opt/llvm@16/bin --out build/el0/liteos-align
python3 tools/export_el0.py build/el0/liteos-align/los_align.bc \
  --root LOS_Align --arguments '[4099,4096]' \
  --source-identity build/el0/liteos-align/source-identity.json \
  --llvm-bin /opt/homebrew/opt/llvm@16/bin \
  --plugin build/el0-llvm16/osrec_el0.so \
  --out build/scenarios/liteos_align
build/scenarios/liteos_align
```

The checkpoint returns `8192`. KLEE completes one path and no partial paths, comparing the reference and extracted IR over all 32-bit argument values, including the helper's unsigned overflow fallback. A separate native check matched independent unsigned-32 arithmetic for 1,100 cases, including wraparound and non-power-of-two boundaries. This optimized helper only loses two debug instructions, leaving six executable IR instructions. It demonstrates packaging real kernel computation; it demonstrates no substantive slicing saving for this helper.

## Validation and scope

The extractor recomputes the root's dependency closure rather than accepting deletion ordinals from a report. It retains all control-flow terminators and their conditions, observable effects and required memory definitions. Reachable callee bodies are retained whole. LLVM module verification checks structural validity.

KLEE executes reference and extracted entries with the same fully symbolic scalar arguments and checks equality of their return bits. No input assumptions or path pruning are added. Timeouts, errors, partial paths, unmodeled externals and malformed/missing KTests reject publication. Native execution compares both implementations for every generated test and for the concrete checkpoint. The standalone artifact contains only the extracted implementation; it checks the checkpoint's result when run.

This comparison concerns the two host-adapted LLVM implementations under the stated contract. It does not prove arbitrary source-language definedness, compiler correctness, equivalence to an executing target kernel, timing, or concurrent behavior. Live capture, pointer relocation, shared state, scheduler/IRQ replay and MMIO/sysreg models remain separate work. The installed KLEE emits a module/host target-triple warning; the saved proof log preserves it.

The exporter audits dynamic dependencies and runs a copied executable in an otherwise empty directory with a minimal environment. `.analysis.json`, `.manifest.json`, `.reference.bc`, `.extracted.bc`, `.equivalence.bc` and `.klee.log` sidecars are review artifacts and are unnecessary at runtime. `--describe` exposes embedded hashes, source identity/license, checkpoint, extraction statistics and symbolic verification details. Source identity is a hash-bound provenance declaration; its contents require a trusted preparer or reviewer.

Five export regressions check isolated execution, malformed checkpoints preserving existing artifacts, rejection of unsupported memory/arithmetic, deliberate mismatches detected by KLEE, and integer min/max plus source-identity binding. Two extraction regressions verify transformed IR, native reference comparisons and rejected module initialization.
