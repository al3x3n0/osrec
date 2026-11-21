# Compact relocation of the captured dump

The target is to make native memory instructions access compact ELF backing
addresses, including accesses originating in user code. The current
pretranslated backend retains original virtual aliases and does not meet this
target. In particular, `0x0000ffffc39f7000` is a captured user mapping, not an
unlowered canonical kernel address.

## Implemented foundation

`tools/el0_relocation_plan.py` assigns the entire captured RAM extent to a
proposed contiguous backing extent. Zero and currently unmapped RAM retain
backing. Initial kernel and user aliases reference the same backing offset when
they reference the same physical bytes. This preserves alias identity in the
plan. A multi-page access resolves only when its entire initial mapping is
contiguous in backing memory. Missing mappings, overflow, and discontiguous
spans do not acquire invented targets. Address resolution does not establish
permissions or fault equivalence.

The report is explicitly **not executable**. Its backing base is a planning
input, not a linked address or a checked reservation against runtime segments.
It is bound to the input register/package and RAM hashes. Device mappings are
listed separately and do not get ordinary RAM targets.

```sh
python3 tools/el0_relocation_plan.py \
  --package build/native-application-20261109a \
  --backing-base 0x50000000 \
  --out build/el0-compact-relocation-plan-20261117a.json
```

`tools/export_el0_program.py --whole-kernel-text` removes workload/function
closure selection for persistent kernel instructions. It uses ELF `$x`/`$d`
mapping symbols, reads the captured instruction bytes, and includes instruction
ranges outside function symbols. Unmapped ranges are recorded in the manifest's
`absent_kernel_text`; ELF bytes are not substituted for absent captured code.
Init sections remain excluded. This option does not identify arbitrary code in
anonymous, module, or generated executable pages and does not itself relocate
memory accesses. The normal exporter mode remains unchanged.

## First executable access rewrite

`--compact-proven-loads`, used with `--pretranslated-memory`, rewrites integer
user loads whose finite-set proof identifies exactly one physical target. The
load destination materializes `flat_phys + offset` using linked ADRP/ADD, then
executes the original load encoding with that base. It needs no runtime lookup,
page walk, scratch-register spill, or flag change. Original logical pointer
values remain unchanged in other registers and memory.

This pass relies on the existing resident-mapping and user-return preservation
contract. It does not admit unknown pointers from a captured value alone. Stores,
writeback, vector/pair loads, and unresolved/multiple backing targets retain
their existing paths. `compact-loads.json` explicitly records `complete: false`.
The option is disabled by default.

The checked image `build/el0-compact-loads-checked-20261117a/checkpoint`
(SHA-256 `d031e8c1d41971baa9ef165807be0b07e3d42153ef2b83998a55f5e4d9ed2ef2`)
contains 16 such sites, including accesses within `0xffffc39f7000`. All 2,272
workload events, nine counter inputs, and 92 UART bytes validate, with zero
hardware exceptions, runtime EL1 services, or host calls before completion.
This uses the existing workload closure, not a whole-kernel exported executable.

The instruction fixture executes 837 cases under QEMU, covering all integer
destination registers, signed/unsigned widths, page crossings, register and
NZCV preservation, and an unusable guest SP. A separate linked-image audit
reconstructs the source proofs and decodes each emitted ADRP/ADD/load to verify
its actual backing target:

```sh
python3 tools/el0_compact_access.py \
  --image build/el0-compact-loads-checked-20261117a
```

Reports are `compact-loads-compiled.json` in that image and
`build/el0-compact-loads-execution-20261117a/validation.json`. These establish a
partial functional rewrite, not complete relocation or a performance gain.

## Dynamic address conversion

The opt-in `--compact-dynamic-memory` hybrid also implies
`--compact-proven-loads`. It retains adapters for original memory operations
instead of admitting raw native RAM accesses. Ordinary kernel accesses compute
their live effective address and select a permission-filtered, immutable
`(VA start, VA end, backing offset)` record. The resulting native memory operand
is `flat_phys + backing offset + VA - start`. Logical pointers are preserved.

Adjacent virtual ranges merge only when their backing is also contiguous. Store
ranges exclude immutable physical pages through every alias. The model rebuilds
the expected records from the captured mapping table and immutable spans, checks
their bytes against the linked ELF, and rejects writable translation records.
These are the backend's fixed kernel mappings, not a cache of mutable user PTEs.

User accesses retain fresh user-page-table translation. Native-SP writeback
and rejected conversions use the existing canonical-RAM C path;
checked stores execute on the private runtime stack until writeback commits.
The fast path does not retain a guessed backing address after a failed lookup.

Ordinary non-SP writeback now remains inline: a 48-byte adapter frame saves the
logical effective address before conversion, and writeback uses that saved
address after the native payload. The backing pointer is never written into the
guest base register. Native-SP writeback remains excluded because a push or pop
can overlap the adapter's spill frame.

Admitted exclusive groups also remain inline. Alignment, mode, writable-span,
and backing conversion checks finish before LDXR/LDXP. No callback or spill
operation is inserted inside the original reservation window. Original local
branches, conditional exits, flags, and STXR/STXP status remain intact. Rejected
admission falls through to the existing checked handler.

The initial hybrid export's source audit covers 120,050 memory entries and two
zeroing entries, and checks 1,292 specialized call copies for memory bypasses.
There are now 680 QEMU conversion cases covering indexed and signed-offset
accesses, scalar/pair/vector writeback, acquire operations, permissions, high
unmapped logical addresses, aliases, and contiguous/discontiguous boundaries.
Separate exclusive tests cover scalar/pair reservations, conditional exits,
misalignment, read-only rejection, and register/flag preservation.
Live-user-translation tests also exercise fresh mappings and permissions.

The checked hybrid image is
`build/el0-compact-dynamic-checked-20261117a/checkpoint`, SHA-256
`2594ed2bf5c9e496c097168da8208f9c887a65a8585a63356fae87de6308a701`.
The finalized load plan is in `build/el0-compact-dynamic-model-20261117b`.
All 2,272 workload events, nine counter inputs, and 92 UART bytes validate with
zero hardware exceptions, runtime EL1 services, or host calls before completion.
Final guest register bytes and UART bytes equal the selected checked baseline.
The only final shadow difference is the diagnostic emulation counter at offset
88: 95,259 becomes 106,662 because 11,403 original zeroing visits now use the
checked emulator. Architectural shadow fields match.

Validation and state comparison are in
`build/el0-compact-dynamic-execution-20261117a/validation.json` and
`baseline-state-comparison.json`. The run uses 204,487 gateways, including
190,898 memory gateways. This is a correctness milestone, not an instruction
overhead improvement; no production default changes.

```sh
python3 tools/el0_compact_dynamic.py \
  --image build/el0-compact-dynamic-checked-20261117a
```

This mode does **not** eliminate native stack aliases or all high-VA accesses
inside runtime helpers. It does not establish whole-dump pointer relocation or
lower instruction overhead; the extra conversions increase generated code.

### Inline atomic and writeback revision

The revised checked image is
`build/el0-compact-inline-checked-20261117a/checkpoint`, SHA-256
`c6ba3d7fc167ba3e2f2b6c0a1500c07bc488fbd8ceaf668f67d0697df8b474ba`.
Its load plan is in `build/el0-compact-inline-model-20261117a`.

| Checked hybrid measurement | Initial conversion | Inline revision |
| --- | ---: | ---: |
| Execution-interval instructions | 124,349,014 | 109,350,549 |
| Gateway transitions | 204,487 | 166,025 |
| Memory gateways | 190,898 | 152,436 |

The revision saves **14,998,465 instructions (12.06%)**. Both measurements use
the same QEMU instruction-counting plugin and checked `PROFILE=1` configuration.
They count all instructions in the execution interval, without kernel/runtime
attribution; these are not cycle measurements or a production overhead ratio.
The empty provenance map intentionally counts totals only and does not classify
payload instructions as runtime overhead.

All 2,272 events validate, with zero hardware exceptions, runtime EL1 services,
or host calls before completion. Final guest state, shadow state (including
diagnostic counters), and UART bytes are identical between the two hybrid runs.
Remaining exclusive fallbacks drop from 13,429 to five. Native-SP writeback and
zeroing still use checked fallbacks; the mode remains opt-in.

The source audit and 16 linked static-load proofs also pass. The measurement
script is `build/measure_compact_totals_20261117.py`; raw counters, ELF/plugin
identities, window boundaries, workload validation, and the comparison are in
`build/el0-compact-dynamic-totals-20261117a` and
`build/el0-compact-inline-totals-20261117a`.

### Inline zeroing revision

`zero_path(..., compact=True)` rounds the live logical address to the admitted
hardware zero-block size, checks the entire block against the immutable writable
translation records, and executes DC ZVA against canonical backing. Input GPRs,
SP, and NZCV are preserved. The diagnostic emulation counter increments once
after successful admission; rejected accesses leave it unchanged before the
checked fallback. The existing loader checks DCZID and enables EL0 zeroing
before entry. Immutable and read-only pages remain excluded through all aliases.

The checked image is `build/el0-compact-zero-checked-20261117a/checkpoint`, SHA-256
`fef918dd60f79885a088fbb2313f5c5f3a0172babe5725e1ef8afd74bbe53a06`, with its
load plan in `build/el0-compact-zero-model-20261117a`.

| Checked hybrid measurement | Inline atomic/writeback | Inline zeroing |
| --- | ---: | ---: |
| Execution-interval instructions | 109,350,549 | 102,177,659 |
| Gateway transitions | 166,025 | 154,622 |
| System gateways | 11,452 | 49 |

This removes all 11,403 zeroing gateways and saves **7,172,890 instructions
(6.56%)**. The measurement uses the same checked `PROFILE=1` configuration and
counts total execution-interval instructions, not cycles or runtime-only cost.
All 2,272 events validate, with zero hardware exceptions, runtime EL1 services,
or host calls before completion. Guest state, shadow state, and UART bytes match
the preceding hybrid image exactly.

Tests cover 768 zeroing cases, every address register (including XZR), all NZCV
patterns, block rounding, aliases, unmapped high logical addresses, read-only and
immutable pages, and unchanged memory/counters on rejection. The other 680
dynamic-access cases and exclusive tests also pass. Source admission, embedded
table checks, and the 16 linked static-load proofs pass. Reports and raw counters
are in `build/el0-compact-zero-totals-20261117a`; the mode remains opt-in.

## Lower-address kernel capture for native accesses

The repository already has two construction options in
`integrations/linux_aarch64/full-kernel/build.sh`: `VA_BITS=39` and
`LAYOUT_VARIABLES=1`. The latter uses `layout_variables.py` to expose selected
kernel C layout constants as variables. It explicitly retains the original
assembly/linker constants, early boot/EFI and other separately built code, PCI
I/O, and fixmap addresses. Neither option establishes a low-VA boot by itself.

A lower-address capture needs a coordinated kernel layout, linker and boot/MMU
change, with direct-map, vmemmap, vmalloc, and fixed mappings checked together.
User stack and mmap placement also need an explicit policy: the reported
`0xffffc39f7000` page is a user mapping and does not follow the kernel link address.
Changing physical load placement alone would not establish low virtual accesses.

The requirement is that the original loads, stores, and atomics execute
directly against addresses the customer can map. Use the kernel's Clang
compilation database to inspect each address producer before machine code is
emitted. Use ELF relocations to verify the symbolic references resolved by the
linker. The original kernel ELF has 177,993 boot-time relative fixups. A
separate relink of the saved kernel objects with `--emit-relocs` exposed another
483,700 static records targeting executable sections and 337,040 targeting
loaded data. Compared with a plain link using the same linker, the only
allocated section that changed was `.notes`, which includes the build ID.
The inventories can be reproduced with `tools/kernel_relocation_inventory.py`.

Clang 19 IR from the actual kernel build shows three independent address
producers. Early boot computes its mapping from `KIMAGE_VADDR`. The linear map
forms addresses with a constant `PAGE_OFFSET`. ELF exec calls
`randomize_stack_top(1 << 48)`. The layout-variable overlay changes the
linear-map constant into a variable in the tested MMU translation unit. The
early boot translation unit retains its original constant. Compiler outputs
and relink logs are under `build/kernel-relocation-source-20261118a` and
`build/kernel-relocation-probe-20261118a`.

With `CONFIG_ARM64_VA_BITS_39`, the user allocation ceiling is `0x8000000000`.
A separate 512 GiB kernel window `[0x8000000000, 0x10000000000)` fits alongside
it below the customer limit `0x800000000000`. Adding `0x10000000000` modulo
2^64 to a canonical 39-bit kernel address preserves its page offset and all
distances within the kernel window. The user addresses stay at their captured
values. Run `tools/kernel_low_layout.py --dump DUMP` to verify both live page
maps, their physical backing and the captured stack and entry addresses.

Clang 19 with the 39-bit build's own flags compiled an experimental header
overlay for the direct-map base and end, the vmemmap end and the fixmap top.
The resulting IR computes the linear-map base as `0x8000000000` and the early
kernel-image base as `0xc080000000`. The ELF exec user stack ceiling stays at
`0x8000000000`. The IR, build commands and compiled layout constants are in
`build/linux-kernel-clang19-va39-20261118a/geometry.json` and adjacent files.

A stock 39-bit build booted the same application binary in QEMU. The cold run
and both checkpoint resumes returned the original checksum and file bytes.
At the selected `fcntl` entry, SP_EL0 was `0x7fcb9a6620`, below the 47-bit
limit. The audit projected all 206,207 kernel virtual pages into the low
window, including 65,589 pages outside the captured RAM. It preserved all
five user mappings and their physical aliases. The report is in
`build/kernel-state-va39-20261118a/low-layout.json`.

A separate QEMU probe ran the captured `__pi_memcpy` and
`refcount_dec_if_one` instruction bytes in EL0 with 47-bit TTBR0 and TTBR1
disabled. It checked all 256 bytes copied from the captured user stack into
the projected kernel stack and a native `LDXR`/`STLXR` decrement from 1 to 0.
The probe supplies relocated operands at entry and maps the needed captured
pages. Its setup, trace and results are under
`build/kernel-va39-native-copy-20261118a`.

The remaining kernel work is to install the kernel window in a TTBR0 root
alongside the user mappings, cover the early boot and address-space switch
paths, and seed kernel stack, allocator and saved pointer state in that
window. Require a full QEMU workload pass with native memory operands to
validate the resulting image. The stock capture still has canonical upper-half
kernel values. `build/kernel-state-va39-20261118a/va-survey.json` lists candidate
pointer locations by region. Those counts come from matching stored values
against address ranges and do not establish their types.

### Shared 47-bit TTBR0 root

`tools/kernel_replay_tables.py` builds a level-0 table with two populated
entries. Entry 0 references the captured 39-bit user root directly. Entry 1
references a copy of the captured kernel subtree in the projected window.
The copy preserves physical aliases, block mappings, and memory types. It
gives the RAM-backed kernel leaves the captured supervisor's read, write and
execute permissions at EL0. `--profile` also grants native data access to
device ranges listed in an existing source-image profile. Other outside-RAM
leaves retain privileged access. The table image uses about 1.03 MiB.

```sh
python3 tools/kernel_replay_tables.py \
  --dump build/kernel-state-va39-20261118a \
  --table-base 0x60100000 \
  --profile integrations/linux_aarch64/source-image/fd-control.json \
  --out build/my-shared-ttbr0
```

QEMU compared read and write translations for all 206,212 captured virtual
pages with TTBR1 disabled in the replay root. In the RAM-only build, EL0 reads
of the 65,589 outside-RAM pages faulted. The switch probe installed a root with
only the shared kernel entry, a root with a different user backing and ASID,
then the original root. The kernel mapping remained available. The original
copy and atomic routines ran with this root, and an attempt to execute from
the projected kernel stack produced an instruction permission fault. With
the PL011 range enabled, a native EL0 load read the flags and a native store
wrote a byte to the emulated serial console through the captured device
mapping. The tables, probes and reports are in `build/kernel-shared-ttbr0-20261118a`.

The Linux boot port can keep its existing three-level kernel table builder.
The level-0 root needs the kernel entry during identity-map installation and
removal as well as during task switches, where the reserved root currently
removes the complete TTBR0 mapping. `cpu_do_switch_mm` also needs to put the
ASID in TTBR0 with `TCR.A1` clear. The default TTBR0 size must stay at 47 bits
while `TASK_SIZE_64` remains 39 bits. These changes concern root installation
in `head.S`, `pi/map_kernel.c`, `mmu_context.h`, and `mm/context.c`. The table
builder itself leaves the capture's registers and stored pointer values intact.

### Linux boot with the shared root

`integrations/linux_aarch64/full-kernel/low-ttbr0-6.10.14.patch` moves the
layout definitions and linker base together. Early boot attaches the kernel
subtree to the identity root, then installs a kernel-only reserved root.
Address-space switches attach the current user subtree and keep the shared
kernel entry. The boot configuration keeps 39-bit user allocations and a
47-bit TTBR0 throughout. TTBR1 is disabled.

Apply the patch to a writable copy of the pinned Linux 6.10.14 source and
build it in the Clang 19 environment:

```sh
patch -d "$LINUX_SOURCE" -p1 < integrations/linux_aarch64/full-kernel/low-ttbr0-6.10.14.patch
sh integrations/linux_aarch64/full-kernel/build-low-ttbr0.sh "$LINUX_SOURCE" "$LINUX_BUILD"
```

The tested build uses the smaller arm64 configuration with virtio block,
ext4, memfd and futex support on single-vCPU QEMU `virt-9.2` with Cortex-A53.
The same application binary passed the initial run and two checkpoint
resumes. The `fcntl` capture recorded PC `0xc080010c00`, SP_EL1
`0x8000858000`, SP_EL0 `0x7ff2be05f0`, TCR_EL1 `0x32b5993511` and a zero
TTBR1_EL1. The shared root contained 134,406 kernel pages and five user
pages. See `build/linux-svc-machine-checkpoint-low-20261118b/report.json`
and `build/kernel-state-low-20261118b/low-boot.json`.

A QEMU counter run from the resumable machine checkpoint through the PASS
line recorded 2,881,928 kernel instructions, 139,128 user instructions and
984,784 data memory events. No observed access reached `1 << 47`. The largest
observed accessed byte was `0xfec002a017`. See
`build/linux-native-low-count-20261118b/counts.json`.

`tools/kernel_replay_tables.py` now accepts this shared-root capture. It
clones the kernel subtree with the EL0 permissions required by the replay
probe. The copy and atomic routines ran in QEMU EL0 at their original
captured PCs, with the original stack addresses and a direct PL011 store.

### Full EL0 replay of the low capture

The EL0 monitor takes the user subtree from the guest's live TTBR0 root.
It supplies separate kernel permission views for application and kernel
execution. Its own code and page-table access live in a third TTBR0 entry.
Loads, stores and atomics in the workload keep their captured instructions
and addresses. Privileged instructions and exception entry and return use
the existing shadow state. Branch dispatch can update simple shadow
registers and DAIF directly, and the remaining traps look up their sites
within the faulting instruction's page.

The shared-root branch mode patches `MRS TPIDR_EL1` to a stack-free veneer
that reads the live shadow slot through a read-only alias. Writes still go
through the monitor and update that same slot. `MRS DCZID_EL0` becomes one
`MOVZ` when the capture provides an encodable value for the read-only
register. The patched sites preserve NZCV and write the original destination.

```sh
python3 tools/source_image.py build --execution el0-minios --el0-dispatch branches \
  --dump build/kernel-state-low-20261118b \
  --vmlinux build/linux-kernel-low-boot-20261118a/vmlinux \
  --profile integrations/linux_aarch64/source-image/fd-control.json \
  --out build/my-shared-el0
python3 tools/source_image.py run --image build/my-shared-el0 \
  --out build/my-shared-el0-run --memory
```

The QEMU run printed the original checksum and file bytes and reached the
`kernel_power_off` boundary. All 2,272 events and 2,135 completed-call
user-memory snapshots matched native Linux. The linked image audit found
only architecture-edge replacements and configured boundary traps in
captured executable pages. See `build/el0-shared-root-hot-sysregs-20261118a`
and `build/el0-shared-root-hot-sysregs-memory-20261118a/comparison.json`.

From the selected `fcntl` SVC to `kernel_power_off`, the replay executed
8,161,997 guest instructions after patching these two reads, down from
11,698,761 with the previous branch dispatch. Monitor entries fell from
37,360 to 22,358. The optimized run included 2,253,051 unchanged kernel
instructions and 139,096 application instructions. It measured 2.91 times
the guest instruction count of its native QEMU reference. These counts are
from single-vCPU Cortex-A53 TCG. See
`build/el0-shared-root-hot-sysregs-profile-20261118a/counts.json` and
`build/el0-shared-root-hot-sysregs-overhead-20261118a/breakdown.json`.

### Populate and lock workload pages before capture

Pass `--pin-user-pages` to the Linux VM checkpoint builder to call
`mlockall(MCL_CURRENT | MCL_FUTURE)` in the guest before the workload starts.
The guest populates and locks its current mappings before capture and does
the same for future mappings as they are created. A failed `mlockall`
aborts the capture. The mode applies to the workload's address space.

```sh
python3 tools/build_linux_vm_checkpoint.py \
  --kernel-image build/linux-kernel-low-boot-20261118a/Image \
  --workload build/linux-svc-machine-checkpoint-low-20261118b/sources/init.c \
  --success-suffix ' state=ok' --pin-user-pages \
  --out build/my-pinned-linux
```

For the file, futex and random-mapping workload above, the captured user
page count rose from 5 to 102. Application page faults fell from 136 to
zero and in-kernel page faults from 49 to 15. All 15 remaining faults
accessed the deliberately invalid pointer `0x10`. Eager population of
later mappings raised total replay instructions from 8,161,997 to
9,155,083. The pinned native and EL0 runs matched all 2,136 syscall
records and 2,135 memory snapshots. See
`build/el0-shared-root-pinned-faults-20261118a/faults.json`,
`build/el0-shared-root-pinned-profile-20261118a/counts.json`, and
`build/el0-shared-root-pinned-memory-20261118a/comparison.json`.

### Branch patches for live-register sites

Shared-root branch dispatch can now patch shadow-register writes and DAIF
updates even when all general-purpose registers are live. The patch uses
hardware `TPIDR_EL0` to hold its address register, restores the original GPR
values, and leaves NZCV intact. The monitor saves the application TLS value
on kernel entry and restores the shadow value on return. The guest kernel's
own `TPIDR_EL0` instructions access that shadow value.

On the pinned capture this cut replay instructions from 9,155,083 to
5,406,649. Monitor entries fell from 21,530 to 4,774. The remaining emulation
traps were 2,150 `ERET` and 473 `TLBI VALE1IS`. The 2,136 syscall records,
2,135 memory snapshots, and 15 deliberate invalid-pointer faults still
matched. The TLS test used a nonzero application value and verified the
registers across a patched `MSR SP_EL0` and the following syscall return.
See `build/el0-shared-root-pinned-state-branches-profile-20261118a` and
`build/el0-shared-root-pinned-state-branches-overhead-20261118a/breakdown.json`.

### Constant MRS reads and runtime accounting

Shared-root branch dispatch emits a single move at the original `MRS`
site when the logical kernel mode or captured read-only CPU register
establishes a constant value. The encoder supports `MOVZ`, `MOVN`, and
the logical-immediate `MOV` alias, including 32-bit writes that zero-extend
to the original 64-bit destination. A discarded result preserves SP.
Mutable registers keep their live-state path. The pinned build has 76
in-place constant reads, up from 4, and this workload visits only the
previously inlined `DCZID_EL0` sites.

The shared-root profiler counts direct replacements and their branch patch
bodies as kernel payload. It counts the monitor and trapping kernel sites
as runtime. All executed instructions are included in the guest total.
The pinned build measured 1,204,678 runtime instructions over 3,335,542
kernel visits, or 0.3612 per visit. The full replay still executed 5,406,649
instructions. See `build/el0-shared-root-pinned-constant-mrs-profile-20261118a/counts.json`.

```sh
python3 tools/source_image_profile.py \
  --image build/el0-shared-root-pinned-constant-mrs-20261118a \
  --bundle build/linux-svc-machine-checkpoint-low-pinned-20261118a/checkpoint \
  --application build/linux-svc-machine-checkpoint-low-pinned-20261118a/init \
  --plugin build/qemu-plugins/libinstruction_profile.dylib \
  --out build/my-source-image-profile
```

### ELF loaders that allocate exactly the load segments

Add `--segment-only` to the shared-root image build. Each `PT_LOAD` maps
`p_memsz` bytes at `p_paddr`, copies `p_filesz` bytes from `p_offset`, and
zero-fills the remaining bytes. `p_vaddr` equals `p_paddr` and the file and
memory offsets meet the 4 KiB alignment requirement. Memory tails cover
the whole captured RAM bank and the monitor's stack and BSS. The pinned
ELF has 94 load segments, a 17.3 MiB file, and 516.1 MiB of mapped RAM.

Start one AArch64 Cortex-A53 in non-secure EL1h with the MMU off, at the
ELF entry. The bootstrap installs TTBR0, the EL1 vectors, and the monitor
stack. Provide a PL011 console at physical `0x09000000`. On QEMU `virt`,
`source_image.py run` uses `-kernel image.elf` for this format so the first
RAM segment can occupy the address used by the generic loader's DTB.

```sh
python3 tools/source_image.py build --execution el0-minios --el0-dispatch branches \
  --segment-only --dump build/kernel-state-low-pinned-20261118a \
  --vmlinux build/linux-kernel-low-boot-20261118a/vmlinux \
  --profile integrations/linux_aarch64/source-image/fd-control.json \
  --out build/my-segment-only-image
python3 tools/source_image.py run --image build/my-segment-only-image \
  --out build/my-segment-only-qemu --memory
python3 tools/run_source_image_unicorn.py \
  --image build/my-segment-only-image/image.elf \
  --out build/my-segment-only-unicorn
```

The reference loader uses Unicorn 2.1.4 with the CPU MMU. Its callbacks
provide PL011 transmit and EL1 exception entry for SVC, BRK, and the
checkpoint's LDTR/STTR translation faults. The ELF needs only its load
segments for RAM. For differential checks, pass the source-image directory
as `--image` and the native recording as `--reference`.

The segment-only build writes `load-plan.json` beside the ELF. It records
the image hash, entry point, and physical address, file extent, memory
extent, and permissions for each segment. The build and both runners use
the same preflight to check guest RAM coverage, monitor BSS, the staged
page copies, and file backing for every table reachable from the generated
TTBR0 roots. It verifies veneer code and its state aliases in both
execution views. The preflight also runs on a standalone ELF with
`python3 tools/source_image_load.py image.elf`.

QEMU and Unicorn both matched the native run's 2,136 syscall records and
2,135 user-memory snapshots. QEMU's footprint recorded 1,870,237 RAM
accesses, all within `PT_LOAD` ranges. See
`build/el0-shared-root-pinned-segment-only-unicorn-20261118a/report.json`
and `build/el0-shared-root-pinned-segment-only-profile-20261118a/footprint/coverage.json`.

### Checkpoint symbols and callstacks

Shared-root builds put kernel function names, monitor symbols, and named
system-register veneers in `image.elf`. Veneer names identify the kernel
function, operation and original PC. The ELF section and symbol tables are
debugger metadata. The ELF entry and all `PT_LOAD` headers and payload bytes
are preserved. `tools/source_image_symbols.py --image IMAGE_DIR --out FILE`
can add the same metadata to a previously built sectionless image.

Open the symbolized image directly in GDB. After attaching to QEMU's gdbstub,
`hbreak __arm64_sys_fcntl`, `continue`, and `bt` show the native kernel stack.
The matching `vmlinux` and `monitor.elf` provide DWARF when source lines or
local variables are needed.

```sh
python3 tools/source_image.py run --image build/el0-shared-root-debug-20261118a \
  --out build/my-callstacks --trace __arm64_sys_fcntl \
  --trace osrec_emulate_site --trace-limit 12
```

`callstacks.json` records the breakpoint symbol, interrupted guest PC and
native kernel frames. A monitor breakpoint reads the saved EL0 context. A
veneer breakpoint uses its original kernel callsite and live frame pointer.
The recorder follows the kernel's frame records across the monitor's stack
switch, where GDB's regular `bt` can stop. The tested image contains 11,991
kernel symbols, 54 runtime symbols and 2,644 veneer symbols. The QEMU trace
recorded 12 samples of each code type and preserved the differential workload
result. See `build/el0-shared-root-callstacks-20261118a/callstacks.json` and
`build/el0-shared-root-debug-20261118a/gdb-backtrace.txt`.

## Address dataflow lowering

`tools/el0_pointer_flow.py` combines unsigned interval propagation with the
existing finite-set facts. Intervals retain bounded dynamic indices beyond the
32-value enumeration limit. Finite sets retain exact jump-table targets. The
analysis joins incoming register bounds and uses the checked syscall return
and initial mapping contracts from pretranslation. Mutable loads supply value
bounds from the load width where applicable.

For a proved access, the whole effective-address interval must fit a single
permitted contiguous backing region. The emitter computes
`flat_phys + (origin_pa - ram_base) + (live_ea - origin_va)` without a lookup or
range guard. It retains logical pointer values in the source registers. Native
stack scratch space is still required, including alignment and a proof that the
payload cannot alias the helper spill through another virtual mapping. This uses
the existing native-stack scratch contract, not a fully relocated stack.

The QEMU fixture executes 256 dynamic indices for both loads and stores with the
logical high address unmapped, checking values, scratch registers and NZCV.
Unit tests cover extension widths, overflow, joins, widening, immutable jump
tables, mutable pointer loads, permissions, bounds and physical spill aliases.

Run the report without modifying the executor:

```sh
python3 tools/el0_pointer_flow.py \
  --image build/el0-compact-zero-checked-20261117a \
  --out build/el0-pointer-flow-20261117a.json
```

Unsigned bitfield and shift propagation now admits 43 captured-user sites, up
from the initial 42. The added site, `0x2025a8`, uses a live byte shifted right
by four as a table index. Its value range follows from load width and arithmetic,
not from the captured byte. The 256-value fixture also demonstrates a proof beyond
finite enumeration. Bitfield tests cover truncation wrap as well as extraction.

The exporter option `--dataflow-memory` requires `--compact-dynamic-memory` and
runtime validation. The existing 16 singleton integer loads retain their cheaper
lowering. Dataflow lowering handles another 27 sites: 21 stores and six loads,
including four non-singleton effective-address ranges. `dataflow-memory.json`
records the selected sites and analysis. Preparation automatically reconstructs
their proofs and independently assembles each rewrite at its actual linked
address, comparing every instruction byte with the delivered ELF. The audit can
also be run with `tools/el0_pointer_flow.py --image IMAGE --verify-compiled`.

Validated artifact: `build/el0-dataflow-checked-20261117a/checkpoint`, SHA-256
`8ad8263f14a6d184c9d7783b96839f53b3beec6a2b653790be294f61453916a0`.
The source audit covers 120,050 memory entries, two zeroing entries and 1,292
call copies without memory operations. Linked audits verify all 27 dataflow
rewrites and the 16 existing singleton loads.

The checked `PROFILE=1` execution interval decreases from **102,177,659** to
**100,933,556** total instructions: **1,244,103 fewer (1.217588%)**. Whole-ELF
execution is 101,075,582 instructions. These are total instruction counts, not
runtime-only overhead ratios. All 2,272 events, nine counter inputs and 92 UART
bytes pass, with no hardware exceptions, runtime EL1 services or host calls before
completion. Final guest state (792 bytes), shadow state (104 bytes) and UART output
match the previous compact-zero image byte-for-byte. Gateway count remains
154,622: this change removes inline address checks rather than C gateways.
Evidence is in `build/el0-dataflow-totals-20261117a/{comparison.json,
total-instructions.json,execution/validation.json}`.

The second analysis version refines register bounds on unsigned branches
immediately after a compare with an immediate. It drops the comparison fact if
any reachable edge enters the branch directly. Widening uses thresholds around
compare constants so that growing loop intervals can converge at a bound the
source branch enforces. The linked audit uses the analysis version recorded in
the export and defaults to version 1 for older images.

This admits two more byte loads in the captured user workload, at `0x201800`
and `0x202594`. Their index loops cover ten and eight byte positions,
respectively. The export now emits 29 dataflow rewrites alongside the 16
singleton loads.

The checked loop image is `build/el0-dataflow-loops-checked-20261117a/checkpoint`.
Its linked audit verifies all 29 dataflow rewrites. QEMU passes all 2,272 events
with zero hardware exceptions and byte-identical guest state, shadow state and
UART output. The checked interval executes 100,931,882 instructions, saving
1,674 (0.00166%) from the previous dataflow image. See
`build/el0-dataflow-loops-totals-20261117a/comparison.json`.

Kernel interprocedural summaries, mutable-memory pointer flow, other loop
forms and changing mappings remain necessary for whole-dump coverage.

## Running without original address aliases

Export with `--hardware-memory --alias-free-memory` to run on a model with a
47-bit TTBR0 range. The actual SP stays in low runtime memory. The guest stack
and guest addresses stay in logical state. Eligible kernel accesses convert
their addresses to canonical RAM inline. User accesses keep the checked
translation path. This mode keeps the startup RAM copy and uses external model
page tables.

The verified model maps the ELF segments and setup code, with zero original
kernel or user VA aliases. Its load plan sets `TCR_EL1=0x280903511`. To repeat
the system QEMU run with the prepared artifacts:

```sh
python3 tools/el0_hardware_model.py run \
  --image build/el0-alias-free-checked-20261118a \
  --prepared build/el0-alias-free-model-20261118a \
  --out build/el0-alias-free-repro
```

The checked workload passed all 2,272 events with no hardware exceptions and
matching UART output. Execution took 90,929,514 instructions, down from
720,080,302 for the 47-bit software fallback. Whole-ELF execution including
startup took 260,635,576 instructions, down from 889,786,364. Both runs used
checked LTO builds with runtime counters disabled. See
`build/el0-alias-free-totals-20261118a/comparison.json`.

Add `--elf-ram-initialization` at export and build with `PRETRANSLATE=1` to
load captured RAM and the model page tables from the checkpoint ELF. The
loader must honor all `PT_LOAD` entries, including zero-filled regions.
The 47-bit model still uses zero original address aliases.

```sh
python3 tools/el0_hardware_model.py run \
  --image build/el0-alias-free-embedded-20261118a \
  --prepared build/el0-alias-free-embedded-boot-20261118a \
  --out build/el0-alias-free-embedded-repro
```

The boot directory contains the setup ELF and load plan. QEMU ran all 2,272
events with zero hardware exceptions and produced identical results, guest
state, shadow state, and UART output. Whole-ELF execution fell from
260,635,576 to 91,071,507 instructions, a reduction of 65.06%. The checked
workload interval was 90,929,514 instructions in both runs. See
`build/el0-alias-free-embedded-totals-20261118a/comparison.json`.

Current alias-free exports check larger admitted ranges first. Once the full
access fits a range, one addition applies the address adjustment resolved by
the linker. Model preparation verifies each adjustment against the captured
mapping and the linked RAM address. The checked QEMU workload fell from
90,929,514 to 73,694,613 instructions, a reduction of 18.95%. All 2,272 events
passed with zero hardware exceptions and identical final state and UART
output. Use the same run command with image
`build/el0-alias-free-ranked-20261118a` and prepared model
`build/el0-alias-free-ranked-model-20261118a`. See
`build/el0-alias-free-ranked-totals-20261118a/comparison.json`.

The shorter memory adapter pairs scratch and condition flag saves and restores,
reads the shadow mode directly from its page, and folds offsets into the
effective-address instruction where possible. The checked interval fell from
73,694,613 to 70,610,559 instructions with identical final state. A separate
indexed lookup trial took 76,179,257 instructions, so the export keeps the
ranked table. To repeat the shorter adapter run, use image
`build/el0-alias-free-short-adapter-20261118a` and model
`build/el0-alias-free-short-adapter-model-20261118a`. See
`build/el0-alias-free-short-adapter-totals-20261118a/comparison.json`.

The current export precomputes the last valid start address for each access
width and probes the largest range directly before searching the others.
Model preparation checks the linked addresses and width bounds against the
captured mappings. The checked interval fell to 67,888,423 instructions
(3.86% fewer), with identical final state. The ELF grew by 3.8 MiB. The image
and model are `build/el0-alias-free-width-bounds-20261118a` and
`build/el0-alias-free-width-bounds-model-20261118a`. See
`build/el0-alias-free-width-bounds-totals-20261118a/comparison.json`.

## Remaining whole-dump obligations

1. Classify all executable dump pages and every memory operation, including
   exclusive, atomic, vector, stack, literal, user-copy, and zeroing accesses.
2. Establish pointer provenance for stored values and saved registers. A word
   matching a mapped VA is a candidate, not sufficient evidence of a pointer.
3. Rewrite address-producing code and account for address differences, hashes,
   comparisons, tagged/encoded pointers, syscall arguments, and returned pointers.
4. Prove backing invariance for each statically relocated access. A current PTE
   alone is insufficient: allocation, remapping, and fault handling may change it.
5. Resolve code and backing addresses after linking, then audit every emitted
   memory access and validate architectural state and workload results.

These obligations remain open for the general case. The selected production
image remains unchanged. The opt-in results above demonstrate partial static
relocation and instruction savings; complete whole-dump relocation remains open.
