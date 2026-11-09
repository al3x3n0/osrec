/* Independent dynamic-count check: 2 + 5*3 + 3 = 20 instructions. */
    .text
    .global _start,count_loop,count_end
_start:
    mov x0,#0
    mov x1,#5
count_loop:
    add x0,x0,#1
    subs x1,x1,#1
    b.ne count_loop
count_end:
    mov x0,#0
    mov x8,#93
    svc #0
    .section .note.GNU-stack,"",%progbits
