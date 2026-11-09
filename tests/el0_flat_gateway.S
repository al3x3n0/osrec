#include "gateway.inc"
    .text
flat_probe_body:
    b flat_probe_capture
flat_capture flat_probe_capture,0x1000
flat_resume flat_probe_resume,flat_probe_body
flat_probe_body2:
    eor x0,x0,x30
    add x16,x16,x17
    eor v31.16b,v31.16b,v0.16b
    b flat_probe_capture2
flat_capture flat_probe_capture2,0x2000
flat_resume flat_probe_resume2,flat_probe_body2
    .section .note.GNU-stack,"",%progbits
