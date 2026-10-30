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
.rept 5
    b fault_entry
    .space 124
.endr
    // Current EL with SP_EL1: IRQ is slot 5. All other exceptions fail.
    b irq_entry
    .space 124
.rept 10
    b fault_entry
    .space 124
.endr
irq_entry:
    sub sp, sp, #288
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    mrs x0, elr_el1
    mrs x1, spsr_el1
    stp x0, x1, [sp, #256]
    bl replay_irq
    ldp x0, x1, [sp, #256]
    msr elr_el1, x0
    msr spsr_el1, x1
    ldr x30, [sp, #240]
    ldp x28, x29, [sp, #224]
    ldp x26, x27, [sp, #208]
    ldp x24, x25, [sp, #192]
    ldp x22, x23, [sp, #176]
    ldp x20, x21, [sp, #160]
    ldp x18, x19, [sp, #144]
    ldp x16, x17, [sp, #128]
    ldp x14, x15, [sp, #112]
    ldp x12, x13, [sp, #96]
    ldp x10, x11, [sp, #80]
    ldp x8, x9, [sp, #64]
    ldp x6, x7, [sp, #48]
    ldp x4, x5, [sp, #32]
    ldp x2, x3, [sp, #16]
    ldp x0, x1, [sp, #0]
    add sp, sp, #288
    eret
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
