/* No CRT, loader, TLS, libc, or compiler runtime. Linux supplies the stack. */
    .text
    .balign 4
    .global _start
    .type _start,%function
_start:
    mov x29,xzr
    mov x30,xzr
    mov x0,sp
    bl lk_host_start
    brk #0
    .size _start,.-_start

    .global lk_host_sigreturn
    .type lk_host_sigreturn,%function
lk_host_sigreturn:
    mov x8,#139 /* __NR_rt_sigreturn */
    svc #0
    brk #0
    .size lk_host_sigreturn,.-lk_host_sigreturn

    .global lk_setjmp
    .type lk_setjmp,%function
lk_setjmp:
    stp x19,x20,[x0,#0]
    stp x21,x22,[x0,#16]
    stp x23,x24,[x0,#32]
    stp x25,x26,[x0,#48]
    stp x27,x28,[x0,#64]
    stp x29,x30,[x0,#80]
    mov x1,sp
    str x1,[x0,#96]
    .arch_extension fp
    stp d8,d9,[x0,#104]
    stp d10,d11,[x0,#120]
    stp d12,d13,[x0,#136]
    stp d14,d15,[x0,#152]
    mov x0,#0
    ret
    .size lk_setjmp,.-lk_setjmp

    .global lk_longjmp
    .type lk_longjmp,%function
lk_longjmp:
    ldp x19,x20,[x0,#0]
    ldp x21,x22,[x0,#16]
    ldp x23,x24,[x0,#32]
    ldp x25,x26,[x0,#48]
    ldp x27,x28,[x0,#64]
    ldp x29,x30,[x0,#80]
    ldr x2,[x0,#96]
    ldp d8,d9,[x0,#104]
    ldp d10,d11,[x0,#120]
    ldp d12,d13,[x0,#136]
    ldp d14,d15,[x0,#152]
    mov sp,x2
    cmp w1,#0
    csinc w0,w1,wzr,ne
    ret
    .size lk_longjmp,.-lk_longjmp
    .section .note.GNU-stack,"",%progbits
