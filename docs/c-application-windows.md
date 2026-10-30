# Compiled C applications and resumable syscall windows

The input checkpoint is a user-space ELF containing application code and data for a concrete execution point. The current verification frontend produces such an ELF from C code with syscall wrappers. The image loader uses its entry and PT_LOAD segments, initializes the application stack, and supplies the saved CPU frame. Data initialized in C is carried by the ELF; BSS is zero-filled. Snapshot overlays are optional.

The application defines `void osrec_application_main(void)` and includes the generated `osrec_application.h`. It can call `osrec_app_syscall(number, a0, a1, a2, a3, a4, a5)` or generated `osrec_app_<kernel-root>` inline wrappers. Numbers, argument counts, and register conventions come from the selected kernel port. Pointer arguments use `(uint64_t)(uintptr_t)pointer`. The frontend is freestanding C without libc, with explicit application stack and exit code.

By default, wrappers share one assembly SVC site. For multiple sites, the optional spec supplies `call_sites`, an ordered list of wrapper names with one entry per expected call. `default` selects `osrec_app_syscall`; another name such as `prefix` generates `osrec_app_syscall_prefix` with the same seven-argument interface and its own SVC. Addresses are derived after linking, so checkpoint metadata needs no manual PCs. The ordered names are an explicit execution contract; the frontend does not infer dynamic control flow from C. Replay checks the actual dynamic count and the selected kernel adapter checks arguments and call order. Extra or missing calls diverge. This count is supplied with `--calls` or taken from the selected kernel checkpoint by the single-command workflow.

The assembly wrapper translates AAPCS arguments into the port's syscall registers, then translates its result back to x0. It saves x19–x30 on the application stack, so a port can use callee-saved registers or LR for syscall inputs/results without breaking the compiled C caller. Tests also use number=x30, arguments=x19–x24, result=x25.

## Single-command workflow

Start with a verified kernel-slice package built by the current exporter. For the practical OHOS file profile:

```sh
python3 tools/export_syscall_slices.py \
  --capture tests/fixtures/files-native \
  --out build/my-window-kernel --cpu-gateway

python3 tools/build_c_file_application_fixture.py \
  --slices build/my-window-kernel --out build/my-c-file-app

python3 tools/run_c_application_slices.py \
  --slices build/my-window-kernel \
  --source build/my-c-file-app/application.c \
  --spec build/my-c-file-app/spec.json \
  --out build/my-c-file-replay --window-calls 1
```

The final command compiles C, derives checkpoint metadata, imports and patches the ELF, links the kernel library, runs ELF/raw checks, and verifies all four QEMU loading/start modes. `workflow.json` pins input source, kernel package, route, image, and verification identities. The image embeds all payloads and uses no runtime host services.

`--window-calls 1` pauses after each syscall and the following application continuation, just before the next syscall. A larger limit groups calls; a final short group is allowed. Zero executes the whole sequence in one gateway entry. The source can be replaced with another compatible C application. Its calls, arguments, and memory objects must satisfy the selected kernel checkpoint and models; compiling it does not broaden those models' syscall coverage.

The optional spec provides object IDs, CPU initialization, snapshots, and final memory assertions. Addresses can be bound to ELF symbols:

```json
{
  "objects": [{"symbol": "app_witness", "bytes": 192, "id": 1}],
  "assertions": [{"symbol": "app_count", "data": "2000000000000000"}]
}
```

The file fixture compiles the complete 32-call lifecycle from C. It prepares the recorded buffers, reads/writes/seeks/stats the modelled file, checks raw returns and output memory, and witnesses TLS preservation. Its initialized marker resides in ELF data and it needs no snapshot overlays. The current file adapter still requires a 192-byte caller witness at object ID 1 and the captured 32-call contract.

To exercise two distinct SVC locations in the file fixture, pass `--prefix-calls 5` to its builder. The resulting C/spec pair uses the `prefix` wrapper for five calls and the default wrapper thereafter; the existing one-command workflows accept it directly.

For separate stages, use `tools/compile_c_application.py --source ... --port ... --calls ... --out ...`, the existing application importer, then `tools/export_application_replay.py --window-calls N`. New route packages include `osrec_import_bind_window`; new archives publish `hardware_cpu_windows_included`. Earlier packages remain usable for whole-sequence execution and need rebuilding for window support.

## Pause and resume behavior

The generated binding selects an ordered subrange of sites and sets its stop PC to the next SVC. `osrec_aarch64_gateway_run_window()` executes that subrange, then captures the live EL0 frame at the next patched SVC without executing it or advancing its PC. The paused frame therefore contains the arguments prepared by actual application instructions for the next call. The session ordinal and kernel state include only completed calls.

The container retains the same session, kernel context, application memory, and saved frame. It binds the next subrange and resumes at the paused PC. Repeated visits to the same SVC PC work because the boundary is reached only after all calls in the current window complete. Pauses reuse the existing route BRK and require no additional code patches. The final window uses the terminal exit BRK. A partial window cannot satisfy kernel completion; completion is checked after the full sequence.

The composed proof restores application and kernel once at the beginning, preserves both across all windows, then performs a joint restore and repeats. Result ABI 22 checks call progress, pauses, resumes, completed windows, final assertions, and private stack guards after every window. The public gateway struct remains ABI 2; run mode is private, and existing whole-sequence execution retains its behavior.

## Verification and remaining scope

The C single-command package is retained in `build/c-application-windows-pipeline-final-v1`. Its `workflow.json` and `qemu-verified/verification-matrix.json` report 64 calls across two runs, 62 pauses/resumes, 64 state-progress and stack-guard checks, and five final application assertions per run. All four QEMU modes match, with no guest host services.

Additional one-call and five-call window evidence is retained under `build/application-windows-final-v1`. `tests/test_application_windows.py` verifies C applications with window sizes 1, 5, and 64, alternate register conventions, rejected binding/runtime inputs, and mutations that reset kernel or user state, skip calls, drop pause mode, pause prematurely, or advance the paused PC. It is registered as `freestanding_application_windows` in CTest.

All seven relevant regression suites passed in 121.87 seconds, including the existing callable/frame/gateway/import checks, AArch64 image checks, new C/window checks, and a fresh native capture. Evidence is recorded in `build/live-syscall-checks/qemu-application-windows-results.xml`.

Windows retain state in a resident image. The [standalone joint-checkpoint workflow](standalone-application-checkpoints.md) now exports a reviewed intermediate kernel/application snapshot and restores it in a fresh QEMU image. The ELF import bounds and Cortex-A53 execution contract are unchanged; see [the application checkpoint workflow](application-checkpoints.md). The OHOS backend remains original ARMv7 LiteOS kernel C recompiled for AArch64 with captured 32-bit kernel scalars and reviewed boundary models.
