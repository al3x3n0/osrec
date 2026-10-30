# Kernel type sources and layout correspondence

Live bindings, typed paths and binding drafts read kernel record layouts through
one interface, `kernel_btf.TypeTable`. Two sources implement it:

| Source | Module | Use |
| --- | --- | --- |
| Embedded BTF | `tools/kernel_btf.py` | Kernels such as Linux with `CONFIG_DEBUG_INFO_BTF` |
| DWARF | `tools/kernel_dwarf.py` | Any ELF built with debug information, such as a proprietary kernel build |

Pointer width is per type: BTF uses 8 bytes, while DWARF uses the unit address
size unless a pointer DIE states its own. Typed paths, descriptor tables and
binding projection therefore work on 32-bit kernels.

## DWARF reader

`DWARF(elf)` parses the DIE listing from `llvm-dwarfdump --debug-info`. It
handles the following:
- base, pointer, struct, union, enum, typedef, qualifier, array (including
  multi-dimensional) and function types;
- DWARF2 `DW_OP_plus_uconst` and DWARF4 constant member locations;
- bitfields, which are marked and never treated as byte-addressable.

An anonymous struct takes its typedef name. A typedef of a named struct, such
as `LosTaskCB` → `TagTaskCB`, resolves to the same definition.

Every compile unit repeats the records it uses, so definitions are merged by
layout. The merge key is the size, plus each member's name, bit offset, width
and type. Typedef spellings, qualifiers and the completeness of pointed-to
structs are ignored, since none of them changes layout. A name with genuinely
different layouts keeps all of them, and `struct()` rejects it as ambiguous.

For the LiteOS-A kernel (`build/ohos/out/liteos`, 32-bit ARM, `-gdwarf-2`),
this gives 352 named records, none ambiguous.

## Source/binary layout correspondence

Gap 5 asks whether a source tree and build configuration actually correspond to
a running binary. `tools/layout_correspondence.py` checks the data-layout part
of that:

```sh
python3 tools/layout_correspondence.py --elf build/ohos/out/liteos \
  --compile-commands build/whole-kernel-discovery-v2/compile_commands.json \
  --out build/liteos-layout-correspondence-20261026/report.json
```

For each compile unit in the binary's DWARF that has a compile command, the
tool takes the records that unit defines. It compiles a probe that includes
that same source file under the unit's own command (flags, defines and include
paths). The probe evaluates `sizeof` and `__builtin_offsetof` for every named,
byte-addressable member. Clang's values are read from a filtered AST dump and
compared with DWARF.

A record the probe cannot name, such as a compiler builtin or a function-local
type, is reported as excluded rather than as matching. Units without a compile
command are listed separately. `--extra-flag` appends compiler flags, which is
how negative controls are run.

Results on 2026-10-26 (`build/liteos-layout-correspondence-20261026/report.json`):

| | |
| --- | --- |
| Units in the binary | 226 |
| Units checked | 214, all matching |
| Size/offset checks | 28,065 over 3,844 per-unit record definitions, 0 mismatches |
| Units without a command | 12, all assembly |
| Excluded | `__va_list` (builtin) in 21 units; 2 bitfields skipped |
| Negative control `-fpack-struct=1` on `los_task.c`/`los_process.c` | both units mismatch, e.g. `ProcessCB` is 210 bytes vs 216 |

The whole run takes about 5 seconds with 6 jobs.

## Limits

- Only data layout is checked. Code, inlining, constants that never reach a
  layout, and semantics are not. A matching layout means the configuration
  reproduces these records; it does not attest that the binary was built from
  this source.
- Records are probed only in units that define them. Bitfield placement is not
  compared yet.
- The DWARF reader depends on the `llvm-dwarfdump` text format, pinned to the
  installed LLVM 22.
- Linux has BTF but no matching source tree here, so its correspondence is not
  checked.
