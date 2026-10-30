.syntax unified
.cpu cortex-a7
.arm
.section .text.boot,"ax"
.global _start
_start:
    cpsid if
    ldr sp, =kernel_stack_top
    ldr r0, =vectors
    mcr p15, 0, r0, c12, c0, 0
    isb
    ldr r0, =__bss_start
    ldr r1, =__bss_end
    mov r2, #0
1:  cmp r0, r1
    strlo r2, [r0], #4
    blo 1b
    bl guest_main
    b unexpected_exception
.balign 32
vectors:
    b fatal_entry
    b fatal_entry
    b svc_entry
    b fatal_entry
    b fatal_entry
    b fatal_entry
    b fatal_entry
    b fatal_entry
fatal_entry:
    cps #0x13
    ldr sp, =kernel_stack_top
    b unexpected_exception
svc_entry:
    push {r0-r12, lr}
    mov r0, sp
    bl svc_dispatch
    str r0, [sp]
    pop {r0-r12, lr}
    movs pc, lr
.global enter_user
enter_user:
    cps #0x1f
    ldr sp, =user_stack_top
    cps #0x13
    ldr lr, =user_main
    mov r0, #0xd0
    msr spsr_cxsf, r0
    movs pc, lr
.section .bss,"aw",%nobits
.balign 16
kernel_stack:
    .space 16384
kernel_stack_top:
user_stack:
    .space 16384
user_stack_top:
