# Pretranslated memory embedded in ELF

The latest [optimized runtime image](el0-runtime-optimization.md) also embeds PC
lookup tables, directly branches from proven returns, and elides redundant
memory checks, reducing runtime instructions to **4,465,783 (1.4684:1)**. The latest
live user walks reuse their canonical RAM base and pair root/TCR loads while
retaining per-access PTE and permission checks. The memory
implementation and preceding 17,086,418-instruction measurement below remain
the baseline for that change.

`--hardware-memory --pretranslated-memory` resolves the captured mappings during
construction and embeds the prepared page tables and initial RAM in the delivered
ELF. Ordinary kernel RAM accesses execute their original load/store instructions.
Both user and kernel code use native SP; handlers use the private runtime stack.

The hardware MMU performs ordinary address translation. The resolved accesses
have no generated range scan, software page-table walk, scratch-register frame
or context gateway around the load/store.

## What is embedded

- **Initial RAM:** 279 nonzero checkpoint runs become initialized `PT_LOAD`
  segments referencing payload bytes already in the ELF. Zero gaps remain
  zero-fill loads. The 561 load segments do not overlap in physical RAM.
- **Hardware tables:** 3,121,152 bytes of resolved tables live inside the ELF's
  read-only load segment, at `flat_embedded_page_tables` (`0x4381a000` in this
  image). There is no external page-table image dependency.
- **Aliases:** captured kernel mappings and five initially resident user pages
  map to the same canonical physical backing. Aliases remain coherent.
- **Boundary checks:** eleven deduplicated captured-PTE descriptor addresses,
  masks and expected values are precomputed. At return to user code, runtime
  checks these addresses directly, the captured root/TCR and preserved user
  registers. It does not rediscover the mappings by walking the tables.

`flat_program_initialize()` no longer copies the snapshot. The ELF loader
initializes its memory before `_start`; startup still initializes the RAM UART
status buffer and checks admitted user text. A model installs the declared MMU
register state before EL0 entry. The QEMU setup stub is pre-entry initialization;
no EL1 service handles the running computation.

## Native access selection

The export removes a further 83,884 static RAM adaptations in addition to native
stack operations. Ordinary kernel RAM instructions, exclusive windows and
eligible native zeroing execute directly. Explicit user-access instructions,
alignment-sensitive checked cases, PC-relative adaptations and MMIO hooks retain
their appropriate handling.

For user code, a conservative finite-set analysis proves 43 memory sites remain
inside prepared resident mappings with the required permissions. These include
the hottest loop's stack stores and RNG state. The analysis uses checkpoint
registers, instructions, mappings and immutable constants. It follows both sides
of conditional branches and computed immutable-table targets. Unknown values,
calls or unresolved indirect control flow lose the optimization. It does not use
recorded branch outcomes or future syscall results.

Syscall and fault transitions record the user context. On return, runtime checks
the register/SP/PC preservation assumed by the analysis; X0 may change on syscall
return. Changing a prepared binding or returning an incompatible context stops
explicitly for retranslation. Code and construction-time constants remain
immutable through their captured aliases.

Demand-created mappings are not fabricated ahead of the kernel. Unresolved
accesses still use the current captured tables and execute the captured fault
handler when required. New mappings can therefore support those accesses without
changing the fixed prepared aliases. Native stacks must remain in prepared
writable RAM. General native kernel RAM fault recovery and arbitrary address-space
replacement remain outside this backend's admission. MMIO hook coverage is tied
to admitted source sites; device values and addresses are still handled live.

## Measured result

Delivered image: [checkpoint](../build/el0-pretranslated-20261113c/checkpoint),
SHA-256 `20a9746083af77287ed32fa5897b5ab5a7b08206b599d09f3ccfec8604b61ce3`.
QEMU 9.2.3 TCG Cortex-A53, one vCPU, `PROFILE=1`.

| Dynamic count | Native kernel-stack baseline | Pretranslated ELF |
| --- | ---: | ---: |
| Runtime/adaptation, execution interval | 65,640,936 | **17,086,418** |
| Original kernel operation visits | 3,041,214 | 3,041,214 |
| Native kernel payload instructions | 2,817,604 | 2,817,620 |
| Native application payload instructions | 131,951 | 131,951 |
| Total execution-interval instructions | 68,590,491 | **20,035,989** |
| Total whole-ELF instructions | 294,817,990 | **20,177,648** |
| Runtime / original kernel operations | 21.5838:1 | **5.6183:1** |

Execution-interval runtime instructions decrease **73.97%**. Startup and final
validation now add only 141,659 instructions, instead of 226,227,499. Memory
adapters fall from 51,421,709 to 4,893,604 instructions. Native payload counts
include prefetch instructions that may previously have been skipped by software
fault checks.

All **2,272 events**, **nine ordered counter inputs** and **92 UART bytes** match,
with **zero hardware exceptions**, no EL1 runtime service and no host call before
completion. There are 4,664 gateways. Validation succeeded with the external
`page-tables.bin` absent; the retained `page-tables.debug.bin` is diagnostic data.

The **0.20:1 ceiling** and **0.10:1 target** remain unmet. The largest remaining
costs are indirect-target lookup (5,957,790), unresolved/special memory adapters
(4,893,604), runtime functions, and privileged-operation emulation. These are
instruction counts, not processor cycles.

- [ELF initialization and embedded-table report](../build/el0-pretranslated-20261113c/pretranslated-elf.json)
- [Counts and budget assessment](../build/el0-pretranslated-profile-20261113c/counts.json)
- [Full workload validation](../build/el0-pretranslated-validation-20261113c/validation.json)
- [Hardware register/load plan](../build/el0-pretranslated-model-20261113d/hardware-load-plan.json)
- [Identical loaded code/data verification](../build/el0-pretranslated-profile-20261113c/profile-plan.json)
- [Remaining hotspots](../build/el0-pretranslated-profile-20261113c/hotspots.json)

## Build and verify

Use fresh output directories. The post-link finalizer is included by
`PRETRANSLATE=1`; it preserves the original executable if table construction
fails, and repeated finalization is idempotent.

```sh
python3 tools/export_el0_program.py \
  --package build/native-application-20261109a \
  --vmlinux build/linux-kernel-clang19-20261108/vmlinux \
  --user-elf build/linux-svc-machine-checkpoint-random-fault-20261108a/init \
  --oracle build/native-application-oracle-20261109b \
  --coverage build/el0-program-reference-code-20261109a.log \
  --hardware-memory --pretranslated-memory --out build/my-pretranslated
make -C runtime/el0_flat \
  'CC=/opt/homebrew/opt/llvm@16/bin/clang --target=aarch64-none-elf' \
  PROFILE=1 LTO=1 PRETRANSLATE=1 OUT="$PWD/build/my-pretranslated-runtime" \
  IMAGE="$PWD/build/my-pretranslated" program
python3 tools/el0_hardware_model.py prepare \
  --image build/my-pretranslated --out build/my-pretranslated-model
python3 tools/el0_hardware_model.py run \
  --image build/my-pretranslated --prepared build/my-pretranslated-model \
  --out build/my-pretranslated-validation
python3 -m unittest discover -s tests -p test_el0_pretranslate.py -v
OSREC_EL0_PRETRANSLATED_IMAGE=build/my-pretranslated PYTHONPATH=tests \
  python3 -m unittest test_el0_pretranslate.PretranslatedImage -v
```

The tests cover descriptor permissions/AF/cycles, conservative address proofs,
mutable computed-target tables, native loader initialization, failed-finalization
rollback, repeated finalization, corrupt embedded tables and guard metadata, and
a runtime descriptor mismatch that stops without a hardware exception or EL1
service. Full instruction measurement uses the existing
[per-instruction profiler](el0-instruction-profile.md).
