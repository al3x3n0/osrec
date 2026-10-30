.arch armv8-a
.section .osrec_syscall,"ax"
.global osrec_app_syscall,osrec_application_svc
osrec_app_syscall:
    stp x0,x1,[sp,#-160]!
    stp x2,x3,[sp,#16]
    stp x4,x5,[sp,#32]
    str x6,[sp,#48]
    stp x19,x20,[sp,#64]
    stp x21,x22,[sp,#80]
    stp x23,x24,[sp,#96]
    stp x25,x26,[sp,#112]
    stp x27,x28,[sp,#128]
    stp x29,x30,[sp,#144]
    ldr x8,[sp]
    ldr x0,[sp,#8]
    ldr x1,[sp,#16]
    ldr x2,[sp,#24]
    ldr x3,[sp,#32]
    ldr x4,[sp,#40]
    ldr x5,[sp,#48]
osrec_application_svc:
    svc #0
    mov x0,x0
    ldp x19,x20,[sp,#64]
    ldp x21,x22,[sp,#80]
    ldp x23,x24,[sp,#96]
    ldp x25,x26,[sp,#112]
    ldp x27,x28,[sp,#128]
    ldp x29,x30,[sp,#144]
    add sp,sp,#160
    ret
.arch armv8-a
.section .osrec_syscall,"ax"
.global osrec_app_syscall_prefix,osrec_application_svc_prefix
osrec_app_syscall_prefix:
    stp x0,x1,[sp,#-160]!
    stp x2,x3,[sp,#16]
    stp x4,x5,[sp,#32]
    str x6,[sp,#48]
    stp x19,x20,[sp,#64]
    stp x21,x22,[sp,#80]
    stp x23,x24,[sp,#96]
    stp x25,x26,[sp,#112]
    stp x27,x28,[sp,#128]
    stp x29,x30,[sp,#144]
    ldr x8,[sp]
    ldr x0,[sp,#8]
    ldr x1,[sp,#16]
    ldr x2,[sp,#24]
    ldr x3,[sp,#32]
    ldr x4,[sp,#40]
    ldr x5,[sp,#48]
osrec_application_svc_prefix:
    svc #0
    mov x0,x0
    ldp x19,x20,[sp,#64]
    ldp x21,x22,[sp,#80]
    ldp x23,x24,[sp,#96]
    ldp x25,x26,[sp,#112]
    ldp x27,x28,[sp,#128]
    ldp x29,x30,[sp,#144]
    add sp,sp,#160
    ret
