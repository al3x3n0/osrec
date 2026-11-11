.arch armv8-a
.text
.global _start
.type _start,%function
_start:
    ldr x0,[sp]
    add x1,sp,#8
    bl program_main
    mov x8,#93
    svc #0
1:  b 1b
.size _start,.-_start
.section .note.GNU-stack,"",%progbits
