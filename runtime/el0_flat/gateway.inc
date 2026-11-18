/* EL0 context edges. Logical-stack macros keep SP private; native-stack
 * macros preserve a small scratch spill on kernel SP and run C privately. */
.macro flat_capture name,pc,word=0,kind=0
    .balign 4
\name:
    sub sp,sp,#800
    stp x0,x1,[sp,#0]
    adrp x0,\name\()_site
    add x0,x0,:lo12:\name\()_site
    b flat_capture_rest
    .pushsection .rodata,"a"
    .balign 8
\name\()_site:
    .quad \pc
    .word \word,\kind
    .popsection
.endm
/* Native kernel SP is live between architecture edges. Only 32 bytes below
 * it are used to preserve the entry scratch registers before switching to
 * the private runtime stack. The handler itself never runs on guest SP. */
.macro flat_native_capture name,pc,word=0,kind=0
    .balign 4
\name:
    stp x0,x1,[sp,#-32]!
    stp x16,x17,[sp,#16]
    mov x16,sp
    adrp x17,flat_active
    ldr x17,[x17,:lo12:flat_active]
    ldr x17,[x17,#8]
    mov sp,x17
    sub sp,sp,#800
    ldp x0,x1,[x16]
    stp x0,x1,[sp]
    ldp x0,x1,[x16,#16]
    stp x0,x1,[sp,#128]
    add x0,x16,#32
    str x0,[sp,#248]
    adrp x0,\name\()_site
    add x0,x0,:lo12:\name\()_site
    b flat_native_capture_rest
    .pushsection .rodata,"a"
    .balign 8
\name\()_site:
    .quad \pc
    .word \word,\kind
    .popsection
.endm

.macro flat_native_resume name,target,export=1
    .balign 4
    .if \export
    .global \name
    .endif
\name:
    ldr x17,[sp,#248]
    sub x17,x17,#16
    ldr x16,[sp,#128]
    str x16,[x17]
    ldr x16,[sp,#136]
    str x16,[x17,#8]
    mov sp,x17
    ldp x16,x17,[sp],#16
    b \target
.endm
.macro flat_resume name,target,export=1
    .balign 4
    .if \export
    .global \name
    .endif
\name:
    ldp x16,x17,[sp,#128]
    add sp,sp,#800
    b \target
.endm
