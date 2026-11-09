/* Model entry is EL0 with accessible ELF RAM. No privileged bootstrap.
 * Linux can also load this static ELF to validate execution at actual EL0. */
    .text
    .global _start
    .type _start,%function
_start:
    adrp x0,flat_start_stack_top
    add x0,x0,:lo12:flat_start_stack_top
    mov sp,x0
    mov x29,xzr
    mov x30,xzr
    bl flat_main
    .global flat_completed
flat_completed:
    /* The model may observe RAM and stop at this PC. Linux validation uses
     * the sole permitted terminal exit. No other SVC exists in the image. */
    mov x8,#93
    svc #0
1:  b 1b
    .size _start,.-_start
    .bss
    .balign 16
    .space 65536
flat_start_stack_top:
    .section .note.GNU-stack,"",%progbits
