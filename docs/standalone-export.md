# Standalone LiteOS A scenario executable

`tools/export_sysread.py` produces one executable containing the pinned LiteOS-A `SysRead` body, the user application, checkpoint, retained boundary observations, reconstruction code and expected behavior. The executable runs without a source checkout, capture file, Python, compiler or KLEE. Its declared platform supplies the normal OS system runtime; the validated artifact is a macOS ARM64 Mach-O binary linked only to `/usr/lib/libSystem.B.dylib`.

The current scenario uses explicit user-address, descriptor and VFS/device models. Its capture provenance is synthetic. It reproduces a bounded sequential user/kernel interaction; real scheduler, interrupt, MMU and driver execution belong to later integration.

## Build and run

First generate a certified plan using [trace analysis](trace-analysis.md). Keep that plan and its analysis directory available during construction.

```sh
python3 tools/analyze_trace.py \
  --kernel-root build/kernel_liteos_a --out build/trace-analysis \
  --llvm-bin /opt/homebrew/opt/llvm@16/bin \
  --klee-include /opt/homebrew/opt/klee/include

python3 tools/export_sysread.py \
  --plan build/trace-analysis/trace-plan.json \
  --kernel-root build/kernel_liteos_a \
  --compiler /opt/homebrew/opt/llvm@16/bin/clang \
  --case examples/sysread_short_case.json \
  --out build/scenarios/sysread_short

build/scenarios/sysread_short
build/scenarios/sysread_short --describe
```

The example requests eight bytes, receives two, recognizes the leading `A`, and preserves the remaining six initial buffer bytes. The normal run prints:

```text
scenario verified: return=2 errno=0 recognized=1
```

`--describe` prints embedded provenance, build identity, model hashes, checkpoint, trace, expectations, execution-platform information and the upstream kernel copyright/license notice. Other arguments are rejected.

The executable is the runtime deliverable. Optional `.capture.json` and `.manifest.json` files support review and subsequent construction. The capture contains required state, reduced observations and expected behavior; it excludes the original environment parameters and unwritten payload bytes. The manifest records artifact hash/size, platform libraries, exporter/compiler identities and the isolated execution result.

An existing retained capture can be packaged without its original environment case:

```sh
python3 tools/export_sysread.py \
  --plan build/trace-analysis/trace-plan.json \
  --kernel-root build/kernel_liteos_a \
  --compiler /opt/homebrew/opt/llvm@16/bin/clang \
  --capture build/scenarios/sysread_short.capture.json \
  --out build/scenarios/sysread_repacked
```

The capture binds to the exact certified report hash. Preserve the corresponding analysis directory when rebuilding captures; regenerating the report creates a new construction identity.

## Construction and reconstruction

```text
certified plan + pinned source + model case
                        |
          execute original code to capture
                        |
      checkpoint + retained trace + expectations
                        |
             compile embedded executable
                        |
       delete generated construction sources
                        |
       copy only binary to an empty directory
                        |
          execute with a clean environment
                        |
          publish after successful verification
```

For an existing capture, construction starts with the checkpoint and retained transcript. Export checks the certified projection, completed sufficiency/reconstruction checks, proof-module hashes, model-source hashes, generated kernel/header hashes and pinned source revision/body. The compiler version and target must match the analysis; installation-path aliases are allowed. Compilation uses captured source snapshots and separate translation units with no link-time optimization.

The shared execution and reconstruction functions are extracted unchanged from the source covered by the KLEE checks. The binary reconstructs a representative environment from checkpoint and retained observations, calls the user program and original `SysRead`, verifies transcript consistency, and compares recomputed outputs, memory and boundary counts against embedded expectations. Expectations are not passed to the reconstruction function. A mismatch exits unsuccessfully.

The reduced mask records errno presence/value and the presence/value of written bytes. Byte presence determines successful read length, so the backend return observation is erased. In the two-byte example, the retained payload is `41420000` and presence mask is 3; the original unused `CD` bytes are excluded from replay input.

Export rejects unsupported or extra capture fields, hidden values in omitted observations, out-of-domain requests, stale source/proof identities and uncertified plans. It audits linked libraries, deletes its generated source files, runs a copied binary in an otherwise empty directory with a minimal environment, and verifies that `--describe` matches the scenario. Publication occurs only after those checks. The current dependency audit supports macOS system libraries and Linux binaries using `readelf` and system libc; Linux export is not validated in this workspace.

## Validation and remaining integration

The standalone regression covers nine scenarios: full read, short read, backend zero-byte return, zero-length request, invalid descriptor, invalid range, null buffer, EINTR and EIO. Each binary runs after its case and optional sidecars are removed. Capture-only repackaging also passes. Six rejection checks cover changed expectations, changed payload, hidden return information, extra state, uncertified plans and stale model fingerprints. Together with recorder, context, capsule, object-checkpoint, planner, EL0 analysis/extraction and KLEE checks, the enabled configuration has sixteen CTest suites. The separate [scalar EL0 exporter](el0-export.md) has its own matching LLVM/KLEE configuration.

The next asynchronous artifact must embed the required task/context state, wait-object generations, interrupt inputs and causal event relationships, then execute included continuation/handler code or explicit effect models. The kernel recorder must supply these construction inputs from a real execution, replacing the current synthetic model capture. KLEE's behavior contract must grow with that scenario before observation omissions are applied to it.
