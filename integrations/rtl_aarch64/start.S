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
2:  bl replay_main
    b fault_entry
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
