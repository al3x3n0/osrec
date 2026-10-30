/* start.S with a stage-1 identity map at EL1.
 *
 * Entry is as for start.S: EL1, MMU and caches off, interrupts masked. After
 * clearing .bss, this builds a flat (VA == PA) translation for the first 2 GiB
 * and turns the MMU on, caches still off:
 *
 * - 0x00000000-0x3fffffff: Device-nGnRnE, execute-never. This is what every
 *   access is with the MMU off.
 * - 0x40000000-0x7fffffff (RAM): Normal Non-cacheable, EL1 and EL0 read/write,
 *   EL0 executable. Unaligned accesses and DC ZVA work on Normal memory; with
 *   the MMU off they fault, which keeps arm64 memset.S from running.
 * - [__text_start, __text_end): 4 KiB pages, read-only and executable at EL1
 *   and EL0. Memory that EL0 can write is never executable at EL1, so the
 *   image's code cannot share the read/write mapping.
 *
 * Nothing above 2 GiB is mapped. Memory stays non-cacheable, so physical
 * memory is what a host or RTL observer reads after a run.
 */
#define DEVICE_BLOCK 0x0060000000000441 /* block, AttrIndx 0, AP EL1/EL0 RW, AF, PXN, UXN */
#define RW_BLOCK     0x0020000000000645 /* block, AttrIndx 1, AP EL1/EL0 RW, outer shareable, AF, PXN */
#define RW_PAGE      0x0020000000000647 /* the same as a level-3 page */
#define TEXT_PAGE    0x00000000000006c7 /* page, AttrIndx 1, AP EL1/EL0 RO, outer shareable, AF */
#define MAIR         0x4400             /* attr0 Device-nGnRnE, attr1 Normal Non-cacheable */
#define TCR          0x800020           /* T0SZ 32 (4 GiB, walk from level 1), 4 KiB granule, non-cacheable walks, EPD1, IPS 4 GiB */
#define TEXT_TABLES  4                  /* level-3 tables: text may span four 2 MiB blocks */

.section .text.boot,"ax"
.global _start
_start:
    msr daifset, #15
    ldr x0, =__stack_top
    mov sp, x0
    mrs x0, sctlr_el1
    bic x0, x0, #1
    bic x0, x0, #4
    bic x0, x0, #4096
    msr sctlr_el1, x0
    isb
    adr x0, vectors
    msr vbar_el1, x0
    isb
    ldr x0, =__bss_start
    ldr x1, =__bss_end
1:  cmp x0, x1
    b.hs 2f
    str xzr, [x0], #8
    b 1b
2:  bl osrec_identity_map
    bl replay_main
    b fault_entry

osrec_identity_map:
    ldr x9, =osrec_level1
    ldr x10, =osrec_level2
    ldr x11, =osrec_level3
    ldr x12, =__text_start
    ldr x13, =__text_end
    ldr x0, =DEVICE_BLOCK
    str x0, [x9]
    orr x0, x10, #3
    str x0, [x9, #8]
    lsr x3, x12, #21            /* first and last 2 MiB block holding text */
    sub x4, x13, #1
    lsr x4, x4, #21
    mov x1, #0                  /* level-2 index */
    mov x2, #0x40000000         /* its block address */
3:  lsr x6, x2, #21
    cmp x6, x3
    b.lo 6f
    cmp x6, x4
    b.hi 6f
    mov x7, #0                  /* text block: one level-3 table of pages */
4:  add x8, x2, x7, lsl #12
    ldr x0, =RW_PAGE
    cmp x8, x12
    b.lo 5f
    cmp x8, x13
    b.hs 5f
    ldr x0, =TEXT_PAGE
5:  orr x0, x0, x8
    str x0, [x11, x7, lsl #3]
    add x7, x7, #1
    cmp x7, #512
    b.lo 4b
    orr x0, x11, #3
    add x11, x11, #4096
    b 7f
6:  ldr x0, =RW_BLOCK
    orr x0, x0, x2
7:  str x0, [x10, x1, lsl #3]
    add x1, x1, #1
    add x2, x2, #0x200000
    cmp x1, #512
    b.lo 3b
    ldr x0, =MAIR
    msr mair_el1, x0
    ldr x0, =TCR
    msr tcr_el1, x0
    msr ttbr0_el1, x9
    dsb sy
    tlbi vmalle1
    dsb sy
    isb
    mrs x0, sctlr_el1
    orr x0, x0, #1              /* M */
    bic x0, x0, #2              /* A: no alignment checks, as for Normal memory in Linux */
    bic x0, x0, #(1 << 19)      /* WXN */
    msr sctlr_el1, x0
    isb
    ret

.balign 2048
vectors:
.rept 16
    b fault_entry
    .space 124
.endr
fault_entry:
    msr daifset, #15
    ldr x0, =__stack_top
    mov sp, x0
    b replay_fault
.section .bss.stack,"aw",%nobits
.balign 16
 .global __stack_bottom
__stack_bottom:
    .space 16384
.global __stack_top
__stack_top:
.section .bss.translation,"aw",%nobits
.balign 4096
.global osrec_level1   /* the gateway checks TTBR0_EL1 against it */
osrec_level1:
    .space 4096
osrec_level2:
    .space 4096
osrec_level3:
    .space 4096 * TEXT_TABLES
