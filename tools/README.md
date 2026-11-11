# Current tool entry points

| Task | Entry point |
| --- | --- |
| Prepare a reusable captured-kernel capsule and build a supplied user ELF | `el0_application.py kernel` / `el0_application.py build` |
| Export the original captured user/kernel workload | `export_el0_program.py` |
| Validate a complete EL0 executor natively or in QEMU application mode | `check_el0_program.py` |
| Audit EL0 executable admission | `audit_el0_image.py` (shared Python module) |
| Build, run and compare source-built kernel images | `source_image.py` |
| Audit kernel code against a fresh source build | `kernel_source_verify.py`, including `--all` |
| Capture and replay one live binary kernel boundary | `kernel_boundary_capture.py` / `kernel_boundary_replay.py` |
| Observe live state and replay an original source slice | `svc_boundary.py` / `reduced_boundary_replay.py` |
| Prepare and validate reviewed Linux syscall profiles | `preflight_linux_aarch64.py` / `run_linux_aarch64_checkpoint_pipeline.py` |

See [the user-binary workflow](../docs/el0-user-binary.md), [source-image flow](../docs/source-image-flow.md), and [Linux syscall profiles](../docs/linux-aarch64-slices.md) for inputs, commands and limits.

The source-image, native Linux and monitor tools remain construction/reference harnesses. In particular, `export_monitor_checkpoint.py` constructs the fixed-input monitor used by `check_monitor_checkpoint.py --code-log` to produce reference code coverage. LiteOS, syscall-slice and KLEE tools retain their documented workflows and regression uses.

The direct-umask EL0 bring-up exporter, driver, checker and counting command have been retired in favor of the complete executor. The unreferenced per-call `source_kernel_replay.py` orchestration has also been removed; source-image execution and the shared kernel-source verifier cover the current workflow. These historical tools remain recoverable from commit `bf670da`.

The shared gateway has a fixture-independent AArch64 Linux check:

```sh
make -C runtime/el0_flat CC=clang-19 check-gateway
```
