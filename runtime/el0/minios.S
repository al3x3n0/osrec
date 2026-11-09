/* The research mini-OS: boot, exception vectors and context switch of the EL1 monitor.
 *
 * Boot runs at the physical load address with the MMU off: it copies staged pages into place (blob pages the
 * loader could not place directly), loads the translation regime (our TTBR1 tables, a temporary identity map in
 * TTBR0), turns the MMU on and continues at the monitor's virtual address. The monitor then installs the user
 * program's tables and enters the program at its captured SVC instruction, at EL0.
 *
 * Data the builder generates (data.S): boot_params, staged_pages/staged_count, osrec_shadow, osrec_sites,
 * osrec_site_count, osrec_start_context (struct osrec_context) and osrec_start_fp (v0-v31, FPSR, FPCR,
 * TPIDR_EL0, TPIDRRO_EL0). */
#define CTX 272
#define BP_MAIR 0
#define BP_TCR 8
#define BP_TTBR1 16
#define BP_TTBR0 24
#define BP_CPACR 32
#define BP_CNTKCTL 40
#define BP_SCTLR 48
#define BP_VBAR 56
#define BP_STACK 64
#define BP_MAIN 72

    .section .text.boot, "ax"
    .global _start
_start:
    msr daifset, #0xf
    adrp x20, boot_params
    add x20, x20, :lo12:boot_params
    /* Staged pages: (source, destination) physical pairs, 4 KiB each. */
    adrp x4, staged_pages
    add x4, x4, :lo12:staged_pages
    adrp x5, staged_count
    ldr x5, [x5, :lo12:staged_count]
1:  cbz x5, 3f
    ldp x6, x7, [x4], #16
    mov x9, #512
2:  ldr x10, [x6], #8
    str x10, [x7], #8
    subs x9, x9, #1
    b.ne 2b
    sub x5, x5, #1
    b 1b
3:  ldr x0, [x20, #BP_MAIR]
    msr mair_el1, x0
    ldr x0, [x20, #BP_TCR]
    msr tcr_el1, x0
    ldr x0, [x20, #BP_TTBR1]
    msr ttbr1_el1, x0
    ldr x0, [x20, #BP_TTBR0]
    msr ttbr0_el1, x0
    ldr x0, [x20, #BP_CPACR]
    msr cpacr_el1, x0
    ldr x0, [x20, #BP_CNTKCTL]
    msr cntkctl_el1, x0
    isb
    tlbi vmalle1
    dsb nsh
    isb
    ldr x0, [x20, #BP_SCTLR]
    msr sctlr_el1, x0
    isb
    ldr x0, [x20, #BP_VBAR]
    msr vbar_el1, x0
    ldr x0, [x20, #BP_STACK]
    mov sp, x0
    ldr x0, [x20, #BP_MAIN]
    br x0

    .text
    .global minios_main
minios_main:
    bl minios_start
    /* The user program's FP/SIMD state and thread registers. */
    adrp x1, osrec_start_fp
    add x1, x1, :lo12:osrec_start_fp
    ldp q0, q1, [x1, #0]
    ldp q2, q3, [x1, #32]
    ldp q4, q5, [x1, #64]
    ldp q6, q7, [x1, #96]
    ldp q8, q9, [x1, #128]
    ldp q10, q11, [x1, #160]
    ldp q12, q13, [x1, #192]
    ldp q14, q15, [x1, #224]
    ldp q16, q17, [x1, #256]
    ldp q18, q19, [x1, #288]
    ldp q20, q21, [x1, #320]
    ldp q22, q23, [x1, #352]
    ldp q24, q25, [x1, #384]
    ldp q26, q27, [x1, #416]
    ldp q28, q29, [x1, #448]
    ldp q30, q31, [x1, #480]
    ldr x2, [x1, #512]
    msr fpsr, x2
    ldr x2, [x1, #520]
    msr fpcr, x2
    ldr x2, [x1, #528]
    msr tpidr_el0, x2
    ldr x2, [x1, #536]
    msr tpidrro_el0, x2
    /* The start context onto the monitor stack, then the common return path. */
    sub sp, sp, #CTX
    adrp x1, osrec_start_context
    add x1, x1, :lo12:osrec_start_context
    mov x2, sp
    mov x3, #(CTX / 8)
1:  ldr x4, [x1], #8
    str x4, [x2], #8
    subs x3, x3, #1
    b.ne 1b
    b minios_return

    .balign 2048
    .global minios_vectors
minios_vectors:
    .rept 8                 /* current EL: the monitor itself faulted */
    .balign 128
    b minios_fault_entry
    .endr
    .balign 128             /* lower EL, AArch64, synchronous */
    b minios_sync_entry
    .rept 7                 /* lower EL IRQ/FIQ/SError and AArch32: not expected */
    .balign 128
    b minios_fault_entry
    .endr

minios_sync_entry:
    sub sp, sp, #CTX
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    mrs x0, sp_el0
    str x0, [sp, #248]
    mrs x0, elr_el1
    str x0, [sp, #256]
    mrs x0, spsr_el1
    str x0, [sp, #264]
    mov x0, sp
    mrs x1, esr_el1
    mrs x2, far_el1
    bl minios_sync
minios_return:
    ldr x0, [sp, #248]
    msr sp_el0, x0
    ldr x0, [sp, #256]
    msr elr_el1, x0
    ldr x0, [sp, #264]
    msr spsr_el1, x0
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    ldp x0, x1, [sp, #0]
    add sp, sp, #CTX
    eret

minios_fault_entry:
    mrs x0, esr_el1
    mrs x1, elr_el1
    mrs x2, far_el1
    bl minios_runtime_fault

    /* osrec_platform_stop(reason, pc, detail, far): the run ends here; a testbench or debugger watches this
     * address and reads x0-x3. */
    .global osrec_platform_stop, osrec_stopped
osrec_platform_stop:
#ifdef OSREC_CHECKPOINT
    sub sp,sp,#32
    stp x0,x1,[sp,#0]
    stp x2,x3,[sp,#16]
    bl osrec_checkpoint_finish
    ldp x0,x1,[sp,#0]
    ldp x2,x3,[sp,#16]
    add sp,sp,#32
#endif
osrec_stopped:
    b osrec_stopped
