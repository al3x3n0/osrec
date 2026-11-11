#!/usr/bin/env python3
"""Overlay headers that make the arm64 kernel's virtual layout runtime variables (Linux 6.10).

Usage: layout_variables.py SOURCE_TREE OVERLAY_DIR [STRUCT_PAGE_SHIFT]. struct page is incomplete where memory.h
is included, so its size is a parameter (log2, 6 = 64 bytes for this configuration); after the build, the
variables' initial values in vmlinux are checked against the original constants. Writes OVERLAY_DIR/arch/arm64/include/asm/memory.h, a copy of the
pinned header with one change: in C code of the kernel proper, PAGE_OFFSET, PAGE_END, MODULES_VADDR, VMEMMAP_START
and VMEMMAP_END read variables (weak definitions in .data..ro_after_init, initialized to the usual constants)
instead of being compile-time constants. Everything derived from them follows: MODULES_END, KIMAGE_VADDR,
VMALLOC_START/END, vmemmap, __va/__pa, virt_to_page, page_to_virt. The compiler can no longer fold or sparsely
encode them, so moving the kernel's virtual layout is a change of data, not of code.

Kept constant: assembly and the linker script (link addresses), code built apart from the kernel proper that cannot
reference its variables (the early position-independent code and the EFI stub, __DISABLE_EXPORTS; the vDSO,
BUILD_VDSO; KVM hypervisor objects), and sizes (VMEMMAP_RANGE, VMEMMAP_SIZE). PCI I/O and fixmap stay constant.

The build puts OVERLAY_DIR/arch/arm64/include first on the include path (LINUXINCLUDE), so the pinned tree is not
modified.
"""
import sys
from pathlib import Path

VARIABLES=[('PAGE_OFFSET','page_offset'),('PAGE_END','page_end'),('MODULES_VADDR','modules_vaddr'),
           ('VMEMMAP_START','vmemmap_start'),('VMEMMAP_END','vmemmap_end')]
BLOCK='''
/*
 * OSREC layout variables (integrations/linux_aarch64/full-kernel/layout_variables.py): in C code of the kernel
 * proper the virtual layout is read from variables, so a relocation of the kernel's address space changes data
 * only. The *_CONST names keep the compile-time values for sizes and code that must not use them.
 */
#define OSREC_CONST_PAGE_OFFSET		(_PAGE_OFFSET(VA_BITS))
#define OSREC_CONST_PAGE_END		(_PAGE_END(VA_BITS_MIN))
#define OSREC_CONST_MODULES_VADDR	(_PAGE_END(VA_BITS_MIN))
#define OSREC_CONST_VMEMMAP_END		(-UL(SZ_1G))
#define OSREC_CONST_VMEMMAP_START	(OSREC_CONST_VMEMMAP_END - ((VMEMMAP_RANGE >> PAGE_SHIFT) << %(page_shift)d))
#if !defined(__ASSEMBLY__) && !defined(LINKER_SCRIPT) && !defined(__DISABLE_EXPORTS) && !defined(BUILD_VDSO) && \\
    !defined(__KVM_NVHE_HYPERVISOR__) && !defined(__KVM_VHE_HYPERVISOR__)
#define OSREC_LAYOUT_VARIABLES 1
%s
#endif
'''


def overlay(source,out,page_shift=6):
    src=Path(source)/'arch/arm64/include/asm/memory.h';text=src.read_text()
    # Sizes keep the constant offsets (they are used in static checks).
    old='#define VMEMMAP_RANGE	(_PAGE_END(VA_BITS_MIN) - PAGE_OFFSET)'
    if text.count(old)!=1:raise SystemExit('memory.h: VMEMMAP_RANGE definition not found as expected')
    text=text.replace(old,'#define VMEMMAP_RANGE	(_PAGE_END(VA_BITS_MIN) - (_PAGE_OFFSET(VA_BITS)))')
    # PCI I/O stays where it is (a constant, checked by static assertions): it hangs off the constant VMEMMAP_END.
    old='#define PCI_IO_START		(VMEMMAP_END + SZ_8M)'
    if text.count(old)!=1:raise SystemExit('memory.h: PCI_IO_START definition not found as expected')
    text=text.replace(old,'#define PCI_IO_START		((-UL(SZ_1G)) + SZ_8M)')
    # After the last layout definition (PAGE_END, defined once KASAN is decided), switch C code to the variables.
    anchor='#define PAGE_END		(_PAGE_END(VA_BITS_MIN))\n#endif /* CONFIG_KASAN */'
    if text.count(anchor)!=1:raise SystemExit('memory.h: PAGE_END anchor not found as expected')
    decls=[]
    for macro,name in VARIABLES:
        var='osrec_layout_'+name
        decls.append('extern unsigned long %s;\nunsigned long __attribute__((weak, section(".data..ro_after_init"))) %s = OSREC_CONST_%s;\n#undef %s\n#define %s\t((unsigned long)%s)'%(var,var,macro,macro,macro,var))
    text=text.replace(anchor,anchor+(BLOCK.replace('%(page_shift)d',str(page_shift)))%'\n'.join(decls))
    dst=Path(out)/'arch/arm64/include/asm/memory.h';dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(text)
    return dst


if __name__=='__main__':print(overlay(sys.argv[1],sys.argv[2],int(sys.argv[3]) if len(sys.argv)>3 else 6))
