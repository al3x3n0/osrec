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
    b fatal
.balign 32
vectors:
    b fatal
    b fatal
    b svc_entry
    b fatal
    b fatal
    b fatal
    b fatal
    b fatal
svc_entry:
    push {r0-r12, lr}
    mov r0, sp
    mrs r1, spsr
    bl linux_syscall
    str r0, [sp]
    pop {r0-r12, lr}
    movs pc, lr
.global enter_user
enter_user:
    mov r2, r0
    cps #0x1f
    mov sp, r1
    cps #0x13
    mov lr, r2
    mov r0, #0xd0
    msr spsr_cxsf, r0
    movs pc, lr
.section .bss,"aw",%nobits
.balign 16
kernel_stack:
    .space 16384
kernel_stack_top:
