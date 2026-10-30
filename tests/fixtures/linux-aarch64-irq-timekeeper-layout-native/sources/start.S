.arch armv8-a
.section .text.entry,"ax"
.global _start
_start:
    bl osrec_native_main
1:  wfe
    b 1b
