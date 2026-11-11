# Simulator-neutral EL0 acceptance runner

`tools/el0_model.py` loads or verifies the standalone executor through an all-stop GDB remote stub, runs from ELF entry to the declared completion PC, and checks the RAM result before optional terminal exit. The runner attaches to an already started model; it does not boot a kernel or install an exception monitor.

## Model setup

Provide one halted AArch64 little-endian CPU in EL0t, normal RAM covering every ELF PT_LOAD memory extent, and accessible FP/SIMD. Configure address mappings, memory attributes, higher-EL trap controls and other CPU implementation settings outside the delivered executable. GDB memory addresses must refer to the same address space as the ELF load addresses. The model should remain stopped when a debugger disconnects; disconnect behavior belongs to the model.

The stub must support target XML (`qXfer:features:read`), register reads for PC, CPSR/PSTATE and X0, memory reads, hardware breakpoints (`Z1`/`z1`), and all-stop continue/interrupt. Loading additionally requires memory writes and a writable PC register. Inline and included XML features are supported; register numbers come from the descriptions. The runner never writes PSTATE or higher-EL controls and does not substitute a software breakpoint if hardware breakpoints are unavailable. Advertised packet capacities above the runner's limits are accepted; memory transfers remain bounded to 64 KiB.

## Load and run

After starting the model with its GDB stub halted:

```sh
python3 tools/el0_model.py \
  --image build/el0-new-application-20261111b/program \
  --host 127.0.0.1 --port 3333 \
  --out build/model-acceptance \
  --label "my processor model"
```

The image directory must contain `checkpoint` and its generated `load-plan.json`. The runner independently audits the executable and rejects a plan that differs from the derived contract. Before continuing the CPU, it writes every segment's file bytes, zeros every memory tail, reads them back, sets PC to ELF entry and confirms the register value. Startup installs its own stack; no ELF arguments or host resources are supplied. The default admitted memory budget is 4 GiB; `--max-memory-bytes` changes that limit explicitly.

If the model's loader has already initialized the ELF, add `--preloaded`. This mode verifies every segment and memory tail without writing RAM or registers, and requires PC already at entry. Both modes require a clear initial result record.

Byte-for-byte comparison is the default. `--memory-check crc32` explicitly selects per-block GDB `qCRC` checks instead; that optional packet must be implemented by the stub. The report distinguishes exact byte comparison from CRC comparison, which can have collisions. There is no automatic switch to CRC or acceptance of an unsupported packet. The algorithm follows the [GDB qCRC definition](https://sourceware.org/gdb/current/onlinedocs/gdb.html/General-Query-Packets.html).

`--timeout` bounds a debugger response and the execution wait. Large memory transfers involve multiple responses, so their total duration can exceed that timeout. Preparation and debugger transfers occur before the execution interval.

The CLI reports initialization progress to stderr every 64 MiB and prints its final JSON summary to stdout. The supplied-user-ELF example has about 908 MiB of segment memory: its QEMU reference byte check took about eight minutes, followed by roughly 0.57 seconds to reach completion. These host wall times describe the reference harness, not processor timing.

## Acceptance and evidence

The hardware completion breakpoint is armed only after initialization is checked. A successful run requires the expected completion PC, observed EL0 state, zero X0 return, the complete 320-byte result ABI version 2, passing embedded checks, no first mismatch, and no missing code target. An unexpected stop, timeout, malformed result, unsupported operation or failed debugger cleanup produces a failed report. On execution timeout, the runner requests an interrupt before closing the connection. A stop reply that already establishes a halted or exited target avoids another interrupt; breakpoint removal is attempted only while the target still exists. Stop replies and the last known execution state are retained in the report, following the [GDB stop reply contract](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Stop-Reply-Packets.html).

The evidence directory contains:

- `load-plan.json`: the audited plan snapshot;
- `entry.json` and `completion.json`: observed CPU boundary fields;
- `result.bin`: the unmodified terminal RAM record, when available;
- `verification.json`: artifact and evidence hashes, initialization method and extent, computation results, and failure diagnostics.

The runner issues no detach or continue after reading completion. The evidence describes the stopped observation; it does not guarantee how a stub behaves after the connection closes.

`terminal_exit_executed_before_observation` is false once the expected completion boundary has been observed. It remains unset when a failure prevents that observation, including premature target termination.

The execution interval covers startup, transformed computation, adapters and validation. Its reported host wall time is not a processor cycle count. The runner observes listed CPU fields and debugger-visible memory; it does not attest all platform controls, RAM attributes, cache/TLB state, or every intermediate exception level. `rtl_execution_verified` and `cycles_verified` remain false, and instruction/cycle counts remain unset. A model-specific integration must establish those additional claims.

## Functional GDB reference

QEMU user mode supplies an EL0 functional GDB reference without an EL1 bootstrap. The optional integration exercises GDB loading of a small protocol fixture, rejection of an invalid instruction, premature exit and failed embedded result, and exact initial-memory/completion checking of a real standalone executor:

```sh
OSREC_EL0_MODEL_IMAGE=/absolute/path/to/program \
OSREC_EL0_MODEL_EVIDENCE=/absolute/path/to/new/evidence-parent \
python3 tests/test_el0_model.py QemuIntegration -v
```

This requires `qemu-aarch64` and, for constructing the small protocol fixture, `clang-19` on an AArch64 Linux construction host. Each run creates a new evidence subdirectory. QEMU's current packaged stub does not implement `qCRC`, so the integration uses byte-for-byte verification. The small fixture tests the debugger protocol; the supplied executor provides the captured-kernel functional case. These checks do not establish RTL or cycle accuracy.
