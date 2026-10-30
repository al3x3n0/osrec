.syntax unified
.cpu cortex-a7
.arm
.section .text.boot,"ax"
.global _start
_start:
    cpsid if
    cps #0x13
    ldr sp, =__stack_top
    mrc p15, 0, r0, c1, c0, 0
    bic r0, r0, #1
    bic r0, r0, #4
    bic r0, r0, #(1 << 12)
    bic r0, r0, #(1 << 13)
    mcr p15, 0, r0, c1, c0, 0
    isb
    ldr r0, =vectors
    mcr p15, 0, r0, c12, c0, 0
    isb
    ldr r0, =__bss_start
    ldr r1, =__bss_end
    mov r2, #0
1:  cmp r0, r1
    strlo r2, [r0], #4
    blo 1b
    bl replay_main
    b replay_fault
.balign 32
vectors:
.rept 8
    b fault_entry
.endr
fault_entry:
    cpsid if
    cps #0x13
    ldr sp, =__stack_top
    b replay_fault
.section .bss.stack,"aw",%nobits
.balign 16
 .global __stack_bottom
__stack_bottom:
    .space 16384
.global __stack_top
__stack_top:
