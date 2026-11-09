/* Explicit-context checkpoint ABI: same arguments and LR as lk_el0_call.
 * This is not the transparent raw-register/SVC-site gateway. */
#if defined(__aarch64__)
    .text
    .balign 4
    .global lk_el0_veneer
    .type lk_el0_veneer, %function
lk_el0_veneer:
    b lk_el0_call
    .size lk_el0_veneer, .-lk_el0_veneer
    .section .note.GNU-stack,"",%progbits
#endif
