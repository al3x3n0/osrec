# EL0 checkpoint loader on macOS

## Native process runner

On Apple Silicon, the native runner loads the static AArch64 ELF into an
ordinary macOS process with Mach VM calls. It uses the ELF's linked
addresses and maps code read/execute and data read/write. Static aliases
share the original backing. The kernel code runs as user-space instructions
with the process's own memory mappings.

Build an alias-free checkpoint as described below and link it with
`MACOS_NATIVE=1` so the ELF fits above the macOS page-zero reservation and
its executable and writable loads use separate 16 KiB host pages.

~~~sh
make -C runtime/el0_flat program CC='clang --target=aarch64-none-elf' \
  IMAGE="$PWD/build/my-native-checkpoint" OUT="$PWD/build/my-native-objects" \
  MACOS_NATIVE=1 LTO=1 PRETRANSLATE=1
make -C runtime/el0_macos native-loader
python3 tools/el0_macos_native.py \
  --image build/my-native-checkpoint/checkpoint --out build/my-native-run
~~~

Pass `--user-elf` and `--reference` to bind the run to the input ELF and
recorded calls. The runner verifies the saved registers at the relocated
user entry and catches the completion boundary before the Linux exit
instruction. The process handles these boundaries with Darwin signals.
The loader links only against libSystem and requires no hypervisor
entitlement. Existing replay adapters still implement Linux behavior
inside checkpoint ELFs that use them.

The host uses 16 KiB pages on the tested Mac. Static aliases must fit that
granule. Darwin reserves `x18` and can clear it on exceptions. The native
build reserves it in the compiler-generated runtime. It uses
`llvm-objdump` on the original user ELF and lowers supported uses of
`x18` to a checkpoint-local slot initialized from the saved register.
This handles the original random/fault test's `MOVZ` and multiply-add or
multiply-subtract instructions. An unsupported user use stops the build
at its original PC. Captured kernel instructions that depend on
`x18` surviving a host exception still require adaptation.
[Apple arm64 ABI](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms)

The native runner reproduced all 2,272 events and 92 output bytes of the
original random/fault test. The whole-kernel IPC checkpoint reproduced all
16 events and bound the saved entry to the original user ELF. A separate
test called the byte-identical captured Linux `__memcpy` at its original
kernel address and checked the 128 output bytes in the shared backing.

### Direct memory for compatible captures

Pass `--macos-direct-memory` with `--macos-native-cc` to the application
builder. It uses the earlier native-stack and pretranslated-memory lowering,
including the indexed branch resolver and native exclusive sequences. The
loader installs shared data aliases once, before the saved user entry.
Ordinary loads and stores then use their captured addresses and native stack
pointers. Syscall and system-register edges still run through the EL0 runtime.

~~~sh
python3 tools/el0_application.py build --libkernel build/my-libkernel \
  --user-elf build/my-user.elf --macos-native-cc clang \
  --macos-direct-memory --out build/my-direct-checkpoint
~~~

The capture must fit the native loader's address window and map complete
16 KiB host pages with coherent backing. The build protects captured code
through every data alias and uses the existing descriptor checks to verify
fixed user mappings. The ELF contains the captured RAM and no guest page
tables for execution. Mapping changes that invalidate those bindings,
explicit architecture address-translation operations, and unexpected access
faults stop the direct run. The existing IPC capture requires a different
address layout before it can use this mode.

## Hypervisor-backed runner

Build and run on an Apple Silicon Mac with the Xcode command-line tools and
Python 3. Flat execution requires macOS 15 or later and Hypervisor support for
configuring EL2.

~~~sh
make -C runtime/el0_macos loader
python3 tools/el0_macos.py \
  --image build/el0-macos-preloaded-checkpoint-20261119a/checkpoint \
  --out build/macos-checkpoint-run
~~~

Use the [complete checkpoint export inputs](source-image-flow.md#complete-userkernel-checkpoint)
with `--hardware-memory --alias-free-memory --elf-ram-initialization
--no-model-page-tables`. Build the `program` target with `PRETRANSLATE=1` to
finalize the ELF's sparse RAM loads. The loader places the captured nonzero
bytes in canonical RAM and leaves the other ranges zero before the first
EL0 instruction. Software-memory and earlier alias-free ELF exports also
use the flat loader path.

To make the same flat checkpoint loadable by a standard 4 KiB AArch64 Linux
ELF loader, add `MERGE_SEGMENTS=1` to the `PRETRANSLATE=1` build. You can also
repackage an existing sparse checkpoint in place with its manifest and RAM
metadata present:

~~~sh
python3 tools/pretranslate_el0_image.py --image build/ipc-executor/program --merge-segments
~~~

Clustering copies the packed RAM bytes to page-aligned file offsets, keeps
the largest zero gaps in zero-fill tails, and fits the program-header table
within 4 KiB. The ELF entry and virtual addresses stay the same. The macOS
loader checks the clustered bytes and zero gaps against the embedded snapshot
before running. The tradeoff is a larger ELF. Native hosts with a different
page size require separate compatibility checks.

The Mach-O loader uses Apple's Hypervisor framework to run the ELF on one
hardware vCPU with the ELF's AArch64 register ABI. The build ad hoc signs it
with the Hypervisor entitlement. In flat mode, the harness backs ELF addresses
directly with RAM, loads every `PT_LOAD`, and configures Normal cacheable
memory. Guest stage-1 translation is disabled and both guest table roots stay
zero. The linked user and kernel code execute in one EL0 address space. The
replay still reads any captured Linux page-table bytes needed to reproduce
the original workload's memory and fault behavior.

Before the first relocated user instruction, the loader stops at a hardware
breakpoint and compares X0–X30, NZCV, the logical stack pointer, all 32 SIMD
registers, FPCR and FPSR with the saved frame. It checks the actual SP against
the resume thunk's stack convention. A mismatch stops the run at that
breakpoint. If the state matches, the loader resumes the checkpoint and stops
at `flat_completed`, before the terminal exit instruction. An unexpected
exception fails the run. The report includes the syndrome when
Hypervisor.framework returns the vCPU state.

For checked images, the host independently compares the raw syscall and fault
ledger with the ELF's expected events. It also verifies the guest stop PC,
counter count and UART bytes. Pass `--user-elf` to bind the saved PC to the
supplied ELF's entry. A preloaded image also checks the supplied instruction
bytes against the captured user text. Pass `--reference` with the separately
recorded `calls.json` to verify the embedded event table and stop PC before
running the vCPU. The supplied-ELF builder passes both automatically.

The output directory contains `validation.json`, `user-entry-state.bin`, and
raw result, terminal register state, event and UART records. Check
`user_entry.verified`, `host_events_verified`, `guest_stage1_translation` and
`runtime_snapshot_copy` in `validation.json`. The report distinguishes the
event checks performed by a validation-enabled image from completion of an
execution-only image. The entry breakpoint is part of functional verification.
RTL verification and cycle equivalence require separate measurements.

## Direct host aliases

A flat ELF can define a read-only `flat_host_aliases` symbol with its size set
to the table size. Each entry contains four little-endian 64-bit fields in
order: guest alias address, backing address in an ELF load segment, length in
bytes, and ELF permission flags (R, RX, or RW). Align addresses and lengths to
the host mapping granule. The loader maps each alias to its backing RAM before
starting the vCPU. It widens the IPA aperture when required and checks aliases
for overlaps and compatible backing permissions. Guest stage-1 translation
stays disabled.

Code linked to the aliased addresses can load and store directly. The
existing checkpoint exporter still uses its software memory path for
changing captured Linux mappings.

### Checking a capture for native mappings

Check the capture's initial RAM aliases at the macOS host granule before
using them for direct loads and stores. The projection accepts a host page
when its captured subpages cover the full page with the same access flags
and point to matching offsets in one backing page.

~~~sh
python3 tools/el0_relocation_plan.py --package build/my-checkpoint/state \
  --backing-base 0x7000000000 --host-page-size 0x4000 \
  --host-va-min 0x100000000 --host-va-end 0x800000000000 \
  --out build/my-native-layout.json
~~~

The report lists candidates for preinstalled shared aliases and gives each
blocked range's address, backing, or permission mismatch. The loader still
has to reserve the candidate addresses in the process. The projection
covers initial RAM only. Changes to Linux mappings and device accesses
require separate handling at their boundaries.

### 4 KiB host mappings

Build the loader with the macOS 26 SDK and pass `--4k-ipa` on macOS 26 or
later to select the Hypervisor framework's 4 KiB IPA granule. This selects
the backing granule for both initial aliases and mapping-gate operations.
Distinct guest addresses can refer to the same 4 KiB slice of ELF backing
with different permissions. Guest stage-1 translation stays disabled, and
the loader reports the selected size in `host_ipa_granule_bytes`. The
default invocation uses the existing host granule. A request for 4 KiB
fails explicitly on an older system or build.
[Apple Hypervisor documentation](https://developer.apple.com/documentation/hypervisor/hv_vm_config_set_ipa_granule(_:_:))

On macOS 15.5 the framework rejected a 4 KiB mapping directly. In a low
unpinned checkpoint, the read-only user addresses `0x200000` and `0x201000`
and the writable kernel direct-map address `0x800051e000` all refer to
physical page `0x4051e000`. They occupy different offsets in their 16 KiB
groups. The 4 KiB alias fixture preserved all five resident user mappings
and their four kernel direct-map views in QEMU. It verified shared writes
and independent 4 KiB map, protect, unmap, and remap operations. The fixture
requires a macOS 26 host to run through Hypervisor.framework at 4 KiB.

### Mapping changes during flat execution

A flat ELF can also opt into explicit mapping updates after user entry.
Define `flat_host_mapping_gate` as an eight-byte executable symbol containing
`nop` followed by `ret`. Define the read-only `flat_host_mapping_window`
symbol as four little-endian 64-bit fields in order. These are the alias base,
alias length, writable backing base, and backing length. Align both ranges
to the host mapping granule. The alias window starts empty and must be
separate from the initial aliases and ELF RAM aperture.

Call the gate with the following registers set.

| Register | Meaning |
|---|---|
| `x0` | 1 maps a range, 2 unmaps it, 3 changes its permissions, 4 queries an accessible prefix |
| `x1` | Alias address in the declared window |
| `x2` | ELF backing address for map, zero for other operations |
| `x3` | Length in bytes |
| `x4` | ELF flags 4 for read-only or 6 for read/write, zero for unmap |

The host handles the instruction breakpoint at the gate and resumes at the
following `ret`. Mapping changes preserve the guest registers and flags. An
invalid request fails the run. The validation report records successful mapping
operations in `host_mapping_updates`. Ordinary loads and stores use the
installed backing directly.

An adapted sequence can query the gate before accessing a user buffer. For a
query, use flag 4 to check read access or 6 to check write access. Queries
accept unaligned addresses and byte counts. The result in `x0` is the length
of the accessible prefix within the declared window. A zero length, an address
outside the window, or an inaccessible first byte returns zero. The loader
checks the permissions it installed for the alias and leaves guest memory,
the other registers, and the flags alone. The validation report counts these
calls in `host_access_queries`.

In the macOS 15.5 flat test, a write to the protected alias and a read
after unmapping each terminated the Hypervisor.framework loader. A separate
user-copy test used the query at the copy entry. Valid ranges executed the
captured Linux copy instructions. For a disallowed first byte, the wrapper
returned the requested length as the number of uncopied bytes.

### Captured Linux user-copy fixups

An ELF can opt into guarded copies by defining the read-only
`flat_host_uaccess_fixups` table. Its first pair of little-endian 64-bit
addresses identifies the original copy-from-user and copy-to-user entry
points. The remaining pairs contain a sorted access PC and its Linux
exception-table target. Use entries whose fixups change the PC alone.
The loader checks that the access PC points to an `LDTR` or `STTR` in
executable ELF backing.

Call the mapping gate with `x0=5`, `x1=destination`, `x2=source`,
`x3=length`, and `x4=4` for copy-from-user or `x4=6` for copy-to-user.
The user range must fit inside the declared window. The host launches the
original routine with its usual argument registers. For a fully accessible
range, the routine runs directly to its caller. Otherwise the host makes the
first inaccessible page accessible for the duration of the call and sets a
single watchpoint for the requested access. A watchpoint exit at a listed
instruction resumes at its Linux fixup. The caller receives the number of
uncopied bytes from the routine. The loader restores the original mapping
before resuming the caller and reports `host_uaccess_calls` and
`host_uaccess_fixups`.

The Apple Silicon fixture matched an independent QEMU run that executed the
same routines and took eight real translation or permission faults. The
faulting PCs, addresses, fixup targets, uncopied byte counts, and all 256
output bytes matched. One partial write changed 24 bytes while Linux
reported 16 bytes copied. The Apple Silicon run remained at EL0 with
stage-1 disabled.

An Apple Silicon probe also caught stores that touched a watched 4 KiB
range within a 16 KiB host mapping, including a store that crossed into the
range. Stores confined to either neighboring 4 KiB range ran through. The
checkpoint exporter still needs to emit the copy boundaries and the
original backing relationships for the full workload.
