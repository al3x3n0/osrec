# Dynamic runtime instruction ratio

The acceptance ceiling is **20% runtime/adaptation instructions per original
kernel operation**, with a **10% target**. A ratio of 0.20:1 means 20%; the
31.3153:1 baseline below is 3,131.53% and fails this requirement.
[`instruction-budget.json`](../runtime/el0_flat/instruction-budget.json) records
the metric and thresholds. The execution interval is the budgeted window;
startup and final validation remain separately reported.

A separate [fixed-mapping Linux-user IPC experiment](el0-linux-user-ipc.md)
measures 0.3311 runtime instructions per kernel instruction at 10 million
kernel instructions. It uses a prepared capture and a different workload.

For the measured 3,041,214 kernel operations, the ceiling permits **608,242**
runtime instructions and the target permits **304,121**. Run the acceptance
check with:

```sh
python3 tools/el0_instruction_profile.py check-budget \
  --profile build/el0-instruction-profile-20261113a
```

The command returns exit status 1 when the ceiling is exceeded. Functional
validation and performance acceptance are independent; a matching event ledger
does not make an over-budget image acceptable.

## Current result: target not met

The [latest grouped-system pass](el0-runtime-optimization.md#grouped-daif-forwarding)
with the trusted syscall/fault ABI and `PROFILE=0 LTO=1` measures **3,516,375 runtime
instructions (1.1562:1)** and **6,491,209 whole-ELF instructions**: **0.038% fewer
runtime instructions** than the compact-state image's 3,517,707. DAIF forwarding
removes **1,332 redundant loads** within existing system groups. Source-PC
frequencies and terminal guest/shadow state remain unchanged. Production retains
245 gateways; the validation-enabled image still matches all 2,272 events and
its complete result and profiles. Production reports remain `execution-completion`;
the 0.20:1 ceiling remains unmet. See the current
[counts](../build/el0-daif-forward-profile-20261117a/counts.json) and
[comparison](../build/el0-daif-forward-profile-20261117a/comparison.json).
The last profiled validation-enabled result follows.

The latest [combined runtime pass](el0-runtime-optimization.md), with LTO, retains all
2,136 syscall gateways and reduces execution-interval runtime/adaptation to
**4,465,783 instructions (1.4684:1)**. Return-validation comparison chains, paired
field loads and reused memory-walk address setup remove another 87,551
instructions. Every original PC's execution frequency matches the preceding
image. Memory adapters are **655,400**; live user translation remains.
Whole-ELF execution is **7,577,710 instructions**, including 141,950 outside the execution interval.
Native kernel/application counts remain 2,838,026/131,951. All workload checks
pass; the **0.20:1 ceiling** remains unmet. See the current
[counts](../build/el0-next-slices-profile-20261117a/counts.json) and
[hotspots](../build/el0-next-slices-profile-20261117a/hotspots.json).

Earlier results include the combined pass at 4,553,334 (1.4972:1),
user-exclusion lookups at 4,743,396 (1.5597:1),
memory elision at 4,877,985 (1.6040:1),
folded address arithmetic at 5,206,759 (1.7121:1),
return-reaching copies at 5,286,113, compact control lowering at 5,309,843,
and partial leaf returns at 6,177,120. The latter eliminated 6,138 additional
indirect-return adapters after the shadow-header image's 6,298,245.
Preceding results include paired return checks
at 6,375,145, the LTO runtime's
6,443,275, the cached resolver's 6,471,631 and the
[generated user returns'](el0-inline-return.md) 6,631,124. The
[page-bitmap ELF](el0-page-bitmap.md) baseline was 8,107,172. The preceding
[indexed-control ELF](el0-indexed-control.md) reduced runtime from 17,086,418 to
12,011,626. Initial RAM and resolved page tables
remain embedded through the [pretranslated-memory backend](el0-pretranslated-memory.md).
All workload checks pass; the **0.20:1** ceiling remains unmet. The measurements
below retain the preceding backend baselines.

The earlier [native kernel-stack backend](el0-native-stack.md) reduced runtime
instructions further to **65,640,936** and the ratio to **21.5838:1**, with all
workload checks passing. It remains above the **0.20:1** ceiling. Its syscall
context gateway count rises to 4,685 while total execution instructions fall
to 68,590,491. The cached-target result below is the preceding baseline.

The first optimization after setting the budget adds a per-site indirect-target
cache. Cache fills use the existing immutable original-PC table; hits compare
the live original target and preserve NZCV and all guest registers. Target
changes and misses retain the checked lookup, and a zero native target cannot
be used from an uninitialized entry. No recorded target sequence is supplied.

The updated `PROFILE=1` image is
`build/el0-hardware-memory-20261113i/checkpoint`, SHA-256
`4b1fe3cf17272fac2d09c12f5e39aa75c88919026bca3dc0c825db3710c4a6a5`.

| Execution-window metric | Before | Cached targets |
| --- | ---: | ---: |
| Runtime/adaptation instructions | 95,236,615 | 82,574,553 |
| Native kernel payload instructions | 2,817,604 | 2,817,604 |
| Native application payload instructions | 131,951 | 131,951 |
| Original kernel operation visits | 3,041,214 | 3,041,214 |
| Total instructions | 98,186,170 | 85,524,108 |
| Runtime / original kernel operations | 31.3153:1 | **27.1518:1** |
| 20% ceiling met | No | **No** |
| 10% target met | No | **No** |

This removes **12,662,062 runtime instructions (13.30%)**, while retaining all
2,272 events, nine counter inputs, 92 UART bytes, 2,549 gateways and zero
hardware exceptions. The ratio remains 2,715.18%, rather than 27.15%.
The whole-ELF runtime ratio is 101.5391:1, including startup and final validation.

- [Current counts and budget assessment](../build/el0-instruction-profile-20261113b/counts.json)
- [Current code-identity and PC-map verification](../build/el0-instruction-profile-20261113b/profile-plan.json)
- [Current full-workload measurement validation](../build/el0-instruction-validation-20261113b/validation.json)
- [Budget check output](../build/el0-instruction-profile-20261113b/budget.json)
- [Current hotspots](../build/el0-instruction-profile-20261113b/hotspots.json):
  memory remains 68,467,136 instructions; indirect lookup falls from
  18,741,732 to 6,079,670 instructions.
- [Cache contract fixture](../tests/test_el0_indirect_cache.py): 7,776 executed
  cases cover hits, changing targets, misses, empty/partial/full tables, scratch
  aliases, BR/BLR/RET, links, every NZCV combination and stack preservation.

## Baseline

Measured on 2026-11-13 using the preceding `PROFILE=1` hardware-memory image,
SHA-256 `f72fc9da9778c8290631ddc47896623d1d54ffc66d4df9d8ccf2cbb28b9b127b`.
QEMU 9.2.3 TCG models one Cortex-A53 CPU. These are dynamic instruction
executions, not gateway entries or cycle measurements.

The execution interval has **31.3153 runtime/adaptation instructions per
original kernel operation**. Counting only kernel instructions that execute
natively as the denominator gives **33.8006:1**.

| Dynamic count | Execution interval | Whole ELF |
| --- | ---: | ---: |
| Runtime/adaptation instructions | 95,236,615 | 321,464,114 |
| Native kernel payload instructions | 2,817,604 | 2,817,604 |
| Native application payload instructions | 131,951 | 131,951 |
| Total executed instructions | 98,186,170 | 324,413,669 |
| Original kernel operation visits | 3,041,214 | 3,041,214 |
| Original application operation visits | 139,096 | 139,096 |
| Synthetic lowering-veneer visits | 2,082 | 2,082 |
| Runtime / original kernel operations | **31.3153:1** | **105.7026:1** |
| Runtime / native kernel payload | 33.8006:1 | 114.0913:1 |

The execution interval starts at `flat_run` entry and ends before the first
instruction after its call in `flat_main`. The whole-ELF window starts at
`_start` and stops before `flat_completed`. Initial RAM restoration, startup
checks and final event/output validation add **226,227,499** instructions.
The QEMU EL1 setup stub and optional terminal exit are outside both windows.

Runtime/adaptation includes inline guards, address translation, shadow-state
operations, expanded control/address operations, resume thunks, gateways,
emulation and the existing guest profiling bookkeeping. It includes adapters
needed by both kernel and application code. Native application payload is
counted separately and excluded from the runtime numerator. Native payload
includes redirected memory instructions and relocated native branches.

An original-operation visit counts arrival at a source instruction, including
an emulated `eret`, an expanded ADR/ADRP or a software-detected fault. Interior
instructions in exclusive windows are counted individually. Captured synthetic
veneers are excluded from the kernel denominator. The native-payload denominator
excludes operations implemented entirely through adapters or emulation. This
is a source-operation count for the transformed run, rather than a separate
unmodified-kernel benchmark; exclusive retries can affect dynamic counts.

The measured run still matches **2,272 events, nine ordered counter inputs and
92 UART bytes**, with **2,549 gateways**, zero hardware exceptions, no EL1 runtime
services and no host calls before completion. ERET remains emulated.

## Executed adapter costs

An execution-window histogram attributes the baseline's 95,236,615 adapter
instructions as follows. This is a second full validated run of the unchanged
image; its histogram totals exactly match the accepted baseline counters.

| Adapter | Executed instructions | Share of runtime |
| --- | ---: | ---: |
| Memory | 68,467,136 | 71.89% |
| Indirect branch lookup | 18,741,732 | 19.68% |
| Runtime functions | 3,920,564 | 4.12% |
| Shadow/system operations | 1,697,526 | 1.78% |
| Logical stack | 893,074 | 0.94% |
| Native control/address expansion | 587,365 | 0.62% |
| Logical syscall entry | 566,040 | 0.59% |
| Resume thunks | 277,773 | 0.29% |
| Result observation | 85,400 | 0.09% |
| Completion boundary | 5 | <0.01% |

[Hotspot details](../build/el0-instruction-profile-20261113a/hotspots.json)
also record the most expensive source sites and runtime functions. Five user
memory sites account for 26.5 million instructions. Kernel and application
memory adapters are both included in the memory row.

Even removing the memory and indirect rows entirely would leave 8,027,747
adapter instructions, a 2.6397:1 ratio. Meeting 0.10–0.20:1 therefore requires
changing the execution representation: ordinary memory, stack and control flow
must execute directly, and runtime work must be restricted to the architecture
edges that need emulation. Further gateway-count reductions alone cannot meet
this budget. Native user memory also needs a way to retain the captured changing
PTEs, permission checks and demand-fault behavior under the EL0-only contract.

## Method and evidence

[`instruction_profile.c`](../tools/qemu_plugins/instruction_profile.c) registers
an execution callback for each guest instruction. It accumulates counters in
a host shared mapping, so debugger stops and QEMU termination preserve them.
It does not multiply translation-block length by entry count or write a trace
per instruction. The run uses one vCPU.

[`el0_instruction_profile.py`](../tools/el0_instruction_profile.py) adds zero-size
provenance symbols to a throwaway assembly copy. It checks identical program
header layout and loaded code/data. The header coordinates and clustered
RAM file offsets can move when symbols are added to the annotated copy.
The original ELF executes with the resulting PC map. Both boundary-hit counts
and workload validation must pass before a report is accepted.

Pass `--user-entry <linked-pc>` to `map` to count from the first relocated user
instruction through the instruction before `flat_completed`. This includes
final validation and reports the whole ELF window alongside it. The instruction
budget uses the separate `flat_run` interval.

- [Measured counts](../build/el0-instruction-profile-20261113a/counts.json)
- [Image identity, PC-map hash and interval addresses](../build/el0-instruction-profile-20261113a/profile-plan.json)
- [Full workload validation](../build/el0-instruction-validation-20261113a/validation.json)
- [Counter and load-identity tests](../tests/test_el0_instruction_profile.py)

The sanity fixture verifies a five-iteration taken loop, both window edges,
native kernel/application separation and synthetic visits. A second test accepts
added symbols while rejecting a changed loaded instruction.

Pass `--histogram` to the `run` command to collect per-PC counters in addition
to the totals. Attribute them with:

```sh
python3 tools/el0_instruction_hotspots.py \
  --profile build/el0-instruction-profile-20261113a \
  --annotated build/el0-instruction-annotated-20261113a \
  --histogram build/el0-instruction-profile-20261113a/histogram.bin
```

## Reproduce

Use fresh output directories when rerunning. The runtime object directory must
match the original image; the map step rejects changed code/data.

```sh
clang -O2 -Wall -Wextra -Werror -dynamiclib -undefined dynamic_lookup \
  -I/opt/homebrew/include $(pkg-config --cflags glib-2.0) \
  tools/qemu_plugins/instruction_profile.c \
  -o build/qemu-plugins/libinstruction_profile.dylib
python3 -m unittest discover -s tests -p test_el0_instruction_profile.py -v
python3 tools/el0_instruction_profile.py annotate \
  --image build/el0-hardware-memory-20261113h \
  --out build/el0-instruction-annotated-20261113a
make -C runtime/el0_flat \
  'CC=/opt/homebrew/opt/llvm@16/bin/clang --target=aarch64-none-elf' PROFILE=1 \
  OUT="$PWD/build/el0-hardware-runtime-20261112h" \
  IMAGE="$PWD/build/el0-instruction-annotated-20261113a" program
python3 tools/el0_instruction_profile.py map \
  --image build/el0-hardware-memory-20261113h \
  --annotated build/el0-instruction-annotated-20261113a \
  --out build/el0-instruction-profile-20261113a
python3 tools/el0_instruction_profile.py run \
  --profile build/el0-instruction-profile-20261113a \
  --prepared build/el0-hardware-model-20261113h \
  --out build/el0-instruction-validation-20261113a \
  --plugin build/qemu-plugins/libinstruction_profile.dylib
```
