# Native kernel stack at EL0

The subsequent [pretranslated ELF backend](el0-pretranslated-memory.md) also
uses native user SP, embeds initial RAM and hardware tables, and reduces the
runtime ratio further to 5.6183:1. This page records the native kernel-stack
baseline used for that comparison.

`--hardware-memory --native-kernel-stack` keeps the kernel's real SP live
between architecture edges. Ordinary kernel SP arithmetic and single/pair
SP-relative memory operations execute their original instructions, including
native pre/post-index writeback. This removes 45,910 static stack adaptations
from the current export. It does not specialize recorded branch outcomes.

User code retains the logical-stack backend and live captured-PTE translation.
Explicit user accesses, exclusive windows, device accesses and general kernel
memory accesses retain their checked paths. This is the first step toward
direct execution between architecture boundaries.

## Context edges

Syscall entry uses the existing context gateway to update the logical exception
state and switch from the private execution stack to the native kernel SP.
The captured kernel vector and syscall body still run, at EL0.

At a kernel architecture edge, `flat_native_capture` preserves 32 bytes of
scratch state below kernel SP, switches to the private runtime stack and captures
the original SP and complete CPU state. C handlers execute on that private stack.
`flat_native_resume` restores a native kernel SP; the existing `flat_resume`
keeps execution on the private stack for logical user code. ERET remains emulated
and selects the appropriate continuation through the existing architectural state.

Inline architectural helpers temporarily spill their scratch registers on the
native kernel stack and restore SP before continuing. The model remains single
CPU and non-reentrant, with the AArch64 stack convention that storage below SP
is available for a new frame.

User and kernel indirect targets use separate immutable PC tables. C dispatch
also checks that the target domain matches the logical mode. Transitions between
domains occur through syscall, exception and emulated-return handling.

## Mapping and admission

Native kernel SP must address writable captured static RAM. Runtime-controlled
entry checks SP alignment and at least 64 bytes of mapped, writable, non-code
headroom. The hardware model makes immutable code pages read-only through their
captured aliases, including aliases whose original mapping was writable. The
initial canonical backing remains writable for checkpoint restoration.

Native stack operations use hardware permissions. An unmapped or otherwise
unsupported native stack access stops at the model's unexpected-exception
boundary; this backend does not add an EL1 fault service. General native kernel
stack-fault recovery is not admitted. User demand faults and checked explicit
user accesses retain their software detection and captured-kernel handling.

The positive workload still has zero hardware exceptions, no runtime EL1 service
and no host calls before completion.

## Measured result

Image: `build/el0-native-stack-20261113a/checkpoint`, SHA-256
`699e7515f42a105eedda04e6cc9c6a7f70312331dcb5ea41109efa94d53d9b06`.
The comparison uses `PROFILE=1`, QEMU 9.2.3 TCG Cortex-A53 and the same execution
window and original-operation denominator as the preceding measurement.

| Execution-window metric | Cached-target backend | Native kernel stack |
| --- | ---: | ---: |
| Runtime/adaptation instructions | 82,574,553 | **65,640,936** |
| Native kernel payload instructions | 2,817,604 | 2,817,604 |
| Native application payload instructions | 131,951 | 131,951 |
| Original kernel operation visits | 3,041,214 | 3,041,214 |
| Total executed instructions | 85,524,108 | **68,590,491** |
| Runtime / original kernel operations | 27.1518:1 | **21.5838:1** |
| Gateway entries | 2,549 | 4,685 |

Runtime instructions decrease by **16,933,617 (20.51%)**. The added 2,136 gateways
are logical syscall context transitions. Stack-adapter instructions fall
from 893,074 to 336, all remaining in logical user code. Memory
adapters decrease from 68,467,136 to 51,421,709 instructions. The general memory
adapters, indirect lookup and architecture edges still dominate the remaining cost.

All **2,272 events**, **nine counter inputs** and **92 UART bytes** match. The
20% ceiling means **0.20:1**, with a **0.10:1** target. **Both remain unmet**;
the budget check returns failure for this image. Counts do not establish cycles.

- [Counts and budget assessment](../build/el0-native-stack-profile-20261113a/counts.json)
- [Code identity and PC-map verification](../build/el0-native-stack-profile-20261113a/profile-plan.json)
- [Full EL0 workload validation](../build/el0-native-stack-validation-20261113a/validation.json)
- [Hardware model plan](../build/el0-native-stack-model-20261113a/hardware-load-plan.json)
- [Executed adapter hotspots](../build/el0-native-stack-profile-20261113a/hotspots.json)
- [Context and negative tests](../tests/test_el0_native_stack.py)

The isolated context fixture tests all GPRs, SIMD, NZCV, FPCR/FPSR, two native
stacks, logical user SP, private handler SP, nested-entry rejection and stack
canaries. Corrupting the x17 restore makes the fixture fail. Full-image negative
checks reject an unmapped kernel SP and a cross-domain vector before native
access, with zero hardware exceptions or EL1 runtime services.

## Build and check

Add `--native-kernel-stack` to the hardware export command in
[the hardware-memory guide](el0-hardware-memory.md). Use a fresh runtime `OUT`
directory, prepare its hardware model, then measure it using
[the instruction profiler](el0-instruction-profile.md).

```sh
python3 -m unittest discover -s tests -p test_el0_native_stack.py -v
OSREC_EL0_NATIVE_STACK_IMAGE=build/el0-native-stack-20261113a \
  PYTHONPATH=tests python3 -m unittest test_el0_native_stack.NativeStackImage -v
python3 tools/el0_instruction_profile.py check-budget \
  --profile build/el0-native-stack-profile-20261113a
```

The isolated instruction fixture uses an EL1 QEMU harness; full-image validation
checks actual EL0 entry and completion. The budget command currently exits 1.
