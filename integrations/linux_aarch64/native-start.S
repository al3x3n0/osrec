.arch armv8-a
.section .text.entry,"ax"
.global _start
_start:
#ifdef OSREC_PIN_USER_PAGES
    mov x0, #3  // MCL_CURRENT | MCL_FUTURE
    mov x8, #230 // mlockall
    svc #0
    cbz x0, .Lmain
    mov x0, #1
    adr x1, .Lpin_failure
    mov x2, #(.Lpin_failure_end - .Lpin_failure)
    mov x8, #64 // write
    svc #0
    b .Lhalt
.Lmain:
#endif
    bl osrec_native_main
.Lhalt:
    wfe
    b .Lhalt

#ifdef OSREC_PIN_USER_PAGES
.pushsection .rodata
.Lpin_failure:
    .ascii "OSREC_VM_FAIL mlockall\n"
.Lpin_failure_end:
.popsection
#endif
