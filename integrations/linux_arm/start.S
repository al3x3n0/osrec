.syntax unified
.arm
.section .text.start,"ax",%progbits
.global _start
.type _start,%function
_start:
    ldr r0, [sp]
    add r1, sp, #4
    bl main
    mov r7, #1
    svc #0
1:  b 1b
.size _start, .-_start
.section .note.GNU-stack,"",%progbits
