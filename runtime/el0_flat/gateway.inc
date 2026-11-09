/* Assembly contract for generated EL0 blocks. No guest stack is touched. */
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
