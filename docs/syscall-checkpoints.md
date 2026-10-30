# End-to-end syscall session checkpoints

`tools/syscall_checkpoint.py` builds entry checkpoints and standalone replay for sequential calls through the pinned LiteOS-A `SysRead` body. A session restores its process, file and buffer objects once, executes the syscall and user errno adapter for each invocation, and retains mutable state between calls. The initial graph, call arguments, ordered dependency transcript and observations are embedded in one executable.

This is a host execution of actual extracted syscall code with explicit models. Inputs may come from synthetic cases or captured read observations. The initial graph is still supplied as a reviewed manifest. This is not a checkpoint captured from a running OHOS kernel, does not execute SVC/exception entry, and does not run the target VFS, drivers, MMU, scheduler or interrupts. The first OHOS device/board remains unspecified.

```text
reviewed entry graph + modeled read inputs
                    |
       build a capture driver with pinned SysRead
                    |
        execute sequential user/kernel calls
                    |
        checkpoint + ordered transcript + observations
                    |
            build standalone executable
                    |
      restore fresh entry objects and descriptor aliases
                    |
        execute user adapter -> original SysRead
                    |
       models consume/verify boundary transcript
                    |
        check observations after every invocation
```

## Build and run

The pinned checkout is the same one used by the original combined KLEE scenario. No earlier trace plan is required: this pipeline retains a conservative complete boundary transcript and applies no certified omissions.

```sh
python3 tools/syscall_checkpoint.py capture \
  --kernel-root build/kernel_liteos_a \
  --case examples/sysread_session_case.json \
  --out build/captures/sysread_session.json
python3 tools/syscall_checkpoint.py export \
  --kernel-root build/kernel_liteos_a \
  --capture build/captures/sysread_session.json \
  --out build/scenarios/sysread_session
build/scenarios/sysread_session
build/scenarios/sysread_session --describe
```

Use `--compiler` to select another C compiler. Native capture/export defaults to the system `cc`; the separate KLEE pipeline needs its matching LLVM 16 toolchain. Source fingerprints pin the kernel revision, file and function body, host adaptation, checkpoint reference runtime, session models and declarations. The full kernel source license is embedded in `--describe` metadata. The native target validated here is macOS ARM64 with only its normal system runtime.

## Capturing data to be read

The [live LiteOS-A QEMU demo](live-liteos-qemu.md) uses this stream from the actual booted kernel and its RAMFS/VFS path. The earlier [freestanding QEMU demo](qemu-demo.md) uses a separate ARMv7 harness with a semihost backend. Both compare independent guest/native observations.

The data source is needed during recording. Replay uses the recorded bytes embedded in the executable. Working adapters perform actual host file reads and QEMU semihost reads. Another emulator or a board can supply the same framed observations once the hook is integrated at its backend read boundary.

```text
RECORD                                  REPLAY
host file / emulator / board            embedded checkpoint + observations
             |                                      |
 backend read -> result/errno/bytes      restore entry objects once
             |                                      |
 portable read stream                    user adapter -> original SysRead
             |                                      |
 import against entry + call manifest    consume bytes at backend boundary
             |                                      |
 execute SysRead, export executable       check each call's state and return
```

A runnable host-file example:

```sh
python3 -c "from pathlib import Path; Path('build/read-fixture.bin').write_bytes(b'0123456789ABCDE')"
python3 tools/record_host_reads.py \
  --kernel-root build/kernel_liteos_a \
  --entry examples/sysread_session_entry.json \
  --file 20=build/read-fixture.bin --out build/captures/host_reads.osrec
python3 tools/syscall_checkpoint.py capture \
  --kernel-root build/kernel_liteos_a \
  --case examples/sysread_session_entry.json \
  --reads build/captures/host_reads.osrec --source-kind host-file \
  --out build/captures/sysread_host_file.json
python3 tools/syscall_checkpoint.py export \
  --kernel-root build/kernel_liteos_a \
  --capture build/captures/sysread_host_file.json \
  --out build/scenarios/sysread_host_file
build/scenarios/sysread_host_file
```

The entry file cursor is 10. Real reads return `ABCD`, then `E`, then EOF; raw returns are `[4,1,0,0]`, including the final zero-length syscall which makes no backend call. Aliased descriptors share the same host open file description during recording. The modeled cursor advances to 14, then 15, and remains 15. The final buffer is `00 11 41 42 45 44 66 77`. Replay needs neither the original file nor the stream/manifest files. The adapter opens files read-only and currently requires seekable input; it does not capture live kernel objects.

`include/osrec/io_capture.h` provides `osrec_record_read` for a target adapter. After a backend read, supply its saved result, saved errno (zero on success), a safely accessible view of exactly the returned bytes, invocation index, backend handle and normalized destination object/offset. Begin/finish use the caller-owned recorder buffer. The hook allocates no memory and performs no device I/O. It records up to 64 returned bytes; the current session importer accepts up to eight. The adapter must provide a coherent entry checkpoint, safe user copying, writer exclusion and a transport to the host. Recorder functions must be excluded from instrumentation. The QEMU harness installs this hook around a semihost file backend. A live LiteOS-A QEMU adapter now records the actual VFS read and validates a bounded initial-state schema. General state discovery and real-board integration remain pending.

The stream contains a context hash binding the pinned kernel, normalized entry and call sequence, one observation per reached backend boundary, and a final completion record. It stores signed read return, numeric errno and exactly the returned bytes. Negative backend returns use `-1` with errno in 1..4095; replay recomputes the syscall's negative errno result. Missing, truncated, reordered, extra or mismatched records reject import before replacing an output. Buffer overflow or any failed hook invalidates a target capture. `--source-kind` is an adapter declaration, not hardware attestation; metadata retains context/stream hashes. Host errno numbers describe this host model and require explicit translation if a target ABI differs.

Import reruns the kernel body with recorded dependency outcomes to derive the full boundary transcript and observations. Thus real input bytes are captured, while descriptor mapping, address validation and file cursor effects remain the declared host models. Capturing the actual OHOS state and those dependencies is the next target integration step.

## Entry state and invocation arguments

The schema supports one eight-byte buffer, one modeled process and at most two reachable file objects. The root is `current_process`. Process fields bind the buffer, user descriptor slots 3/4, initial kernel errno and initial user errno. Slots may be null or may alias the same file. File fields hold a positive backend handle and a modeled unsigned 32-bit cursor. These are semantic model fields, not a dump of actual LiteOS-A object layouts.

Typed object reconstruction uses the shared reference runtime. Objects are created and registered before references are resolved. Struct references point to object bases; syscall buffer arguments are object IDs plus byte offsets. Arbitrary initial buffer bytes are retained. Calls may use null or one-past-end pointers so the original syscall can reproduce zero-length behavior or EFAULT. Pointers beyond the allocation are rejected before code generation. Request lengths are bounded to 0..9 and user descriptors to 0..4; sessions contain 1..8 calls.

No reset occurs between invocations. Successful modeled reads write the observed payload and advance the shared file cursor. Backend failures update kernel errno. The user adapter converts a negative raw syscall return to `-1` and updates user errno; successful calls leave user errno unchanged. A small user computation recognizes whether a nonempty read begins with `A`. All of this executes during replay.

## Device model and ordered boundary transcript

The replay backend is in-memory. Backend handle 17 in the example is a model identifier, not a host file descriptor or selected physical device. The capture driver supplies each modeled backend outcome, either from a synthetic case or an imported read observation. Export retains only the events that execution actually produced; the original environment array is absent from the capture and binary metadata.

| Kind | Boundary | Behavior during replay |
| --- | --- | --- |
| 1 | User address range | Compute validity from restored buffer bounds; compare arguments and result |
| 2 | Descriptor mapping | Resolve restored descriptor slot; compare user/backend descriptors |
| 3 | Backend read | Consume recorded result, errno and returned bytes; execute model writes/cursor update; compare the event |
| 4 | Kernel errno read | Read current modeled kernel errno; compare the result |

Read events include buffer identity/offset, requested length, mapped descriptor, cursor before/after and exactly the returned bytes. Unused event fields are zero. Every emitted event must match the next transcript record, and the transcript must be completely consumed. Missing, reordered or extra events reject replay. The transcript is grouped by syscall invocation, preserving session order.

Backend writes are declared modeled dependency effects. Final expected memory and file positions are checked after execution; they are never used to restore post-call state. Range checks, descriptor mapping, syscall branches, user processing, errno translation and cursor updates are recomputed.

## Four-call example

The entry buffer is `00 11 22 33 44 55 66 77`. Both user descriptors alias one file with cursor 10.

| Invocation | Modeled backend outcome | User return | User errno | Cursor afterward |
| --- | --- | --- | --- | --- |
| fd 3, buffer+2, request 4 | Two bytes `AB` | 2 | 0 | 12 |
| fd 4, buffer+4, request 2 | One byte `C` | 1 | 0 | 13 |
| fd 3, buffer+6, request 2 | EINTR | -1 | 4 | 13 |
| fd 0, null, request 0 | No backend call | 0 | 4 | 13 |

The final buffer is `00 11 41 42 43 55 66 77`. The session emits ten boundary events, with no events for the zero-length invocation. Observations include raw/user return values, user errno, recognition, all buffer bytes, every file cursor and kernel errno after each call.

## Validation

Five integration tests cover the four-call session, execution of the binary alone, twelve corruption/rejection cases, distinct file objects with cursor wraparound and fault/error paths, and EOF plus a missing descriptor. Corrupted entry bytes, cursors, errno, aliases, event order, arguments, payload or expectations fail construction without replacing an existing executable. Source-identity mismatches are rejected before execution. The four-call generated replay also passes AddressSanitizer/UndefinedBehaviorSanitizer. The `.manifest.json` and `.sources` directory are review artifacts and are unnecessary at runtime.

A separate KLEE check validates the reconstruction core for a declared two-call contract:

```sh
python3 tools/verify_syscall_checkpoint.py \
  --kernel-root build/kernel_liteos_a --out build/syscall-checkpoint-proof \
  --llvm-bin /opt/homebrew/opt/llvm@16/bin
```

It makes all eight entry buffer bytes, all 32-bit cursor bits and bounded initial errno values symbolic. Descriptors 3/4 alias one file; the calls use fixed valid buffer offsets 2/4 and lengths 4/2. Each backend read result ranges from -1 to 2, with arbitrary returned bytes and EINTR/EIO on failure. It captures the first execution, rebuilds fresh entry objects and reruns using only the transcript, then compares observations and ordered events after both calls. The validated run completed 16 paths with zero partial paths; all 16 generated cases passed native replay. The saved log preserves KLEE's module/host target-triple warning.

This proof neither certifies arbitrary sessions nor justifies removing checkpoint fields/events. Standalone metadata keeps `symbolic_equivalence_verified=false` rather than applying the bounded proof to a different session. Future analysis should bind proofs to particular session contracts, check trace/checkpoint omissions with independently varied hidden state, and validate generated loaders. Live kernel checkpoints additionally require reviewed kernel object schemas, allocation/lifetime tracking and a consistent boundary across relevant writers.

The C hook tests cover real wire emission, EOF/errors, invalid byte views and capture overflow. The hook tests pass AddressSanitizer/UndefinedBehaviorSanitizer; the hook also compiles for freestanding AArch64. Recorded-input integration tests decode that C stream in Python, reproduce EAGAIN through the actual syscall body, reject incomplete/badly bound streams while preserving existing output, and record a real file before deleting the source inputs and running the copied executable alone.

Configure `OSREC_BUILD_LITEOS_KLEE_SCENARIO=ON` to include recorded-input/session integration and the bounded KLEE check in CTest.
