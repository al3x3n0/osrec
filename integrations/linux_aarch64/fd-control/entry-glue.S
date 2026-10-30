/* Reviewed model of the hardware and per-CPU setup around Linux's arm64
 * exception entry (linux-entry.S, the original arch/arm64/kernel/entry.S).
 *
 * osrec_linux_el0_svc(ctx, number, arguments) enters Linux as an SVC #0 from
 * AArch64 EL0 enters it:
 *
 * - The hardware part of exception entry is modeled: ESR_EL1 is an SVC64
 *   syndrome, ELR_EL1 the EL0 return address, SPSR_EL1 EL0t, and execution
 *   continues at the vector for synchronous exceptions from 64-bit EL0
 *   (vectors + 0x400) at EL1h with DAIF masked. SP_EL1 is the caller's stack:
 *   kernel_ventry places struct pt_regs below it.
 * - The registers hold the system call: x0-x5 the arguments, x8 the number,
 *   every other general register zero. SP_EL0 is zero.
 * - Per-CPU variables are plain symbols with TPIDR_EL1 (the per-CPU offset)
 *   zero. __entry_task is the slice's current task.
 *
 * Linux then runs unchanged: kernel_entry, el0t_64_sync_handler,
 * ret_to_user, kernel_exit and its ERET. The return is real: ERET drops to EL0
 * at osrec_el0_return, whose UDF traps back through this file's vector table,
 * and the result is x0 as kernel_exit restored it. Any other exception taken
 * while Linux's entry runs is a replay fault.
 *
 * The other exception-class handlers entry.S names, its fork return and the
 * boot-time alternative patching callbacks are outside the replay: entry.S's
 * alternatives stay unpatched (their default instructions run).
 */
	.text
	.balign	4
	.global	osrec_linux_el0_svc
	.type	osrec_linux_el0_svc, %function
osrec_linux_el0_svc:
	stp	x29, x30, [sp, #-96]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	stp	x23, x24, [sp, #48]
	stp	x25, x26, [sp, #64]
	stp	x27, x28, [sp, #80]
	mov	x19, x0				// ctx
	mov	x20, x1				// number
	mov	x21, x2				// arguments[6]
	adrp	x22, osrec_entry_saved
	add	x22, x22, :lo12:osrec_entry_saved
	str	x19, [x22, #0]
	mrs	x9, vbar_el1
	mrs	x10, sp_el0
	stp	x9, x10, [x22, #8]
	mrs	x9, tpidr_el1
	mrs	x10, elr_el1
	stp	x9, x10, [x22, #24]
	mrs	x9, spsr_el1
	mrs	x10, esr_el1
	stp	x9, x10, [x22, #40]
	bl	osrec_kernel_osrec_entry_task	// x0 = ctx -> current task
	adrp	x9, __entry_task
	str	x0, [x9, :lo12:__entry_task]
	msr	tpidr_el1, xzr
	adrp	x9, osrec_entry_vectors
	add	x9, x9, :lo12:osrec_entry_vectors
	msr	vbar_el1, x9
	adrp	x9, osrec_el0_return
	add	x9, x9, :lo12:osrec_el0_return
	msr	elr_el1, x9
	msr	spsr_el1, xzr			// EL0t
	mov	x9, #0x56000000			// ESR_ELx_EC_SVC64 << 26 | ESR_ELx_IL, ISS imm16 0
	msr	esr_el1, x9
	msr	sp_el0, xzr
	mov	x9, sp
	str	x9, [x22, #56]
	isb
	ldp	x0, x1, [x21, #0]
	ldp	x2, x3, [x21, #16]
	ldp	x4, x5, [x21, #32]
	mov	x8, x20
	mov	x6, xzr
	mov	x7, xzr
	mov	x9, xzr
	mov	x10, xzr
	mov	x11, xzr
	mov	x12, xzr
	mov	x13, xzr
	mov	x14, xzr
	mov	x15, xzr
	mov	x16, xzr
	mov	x17, xzr
	mov	x18, xzr
	mov	x19, xzr
	mov	x20, xzr
	mov	x21, xzr
	mov	x22, xzr
	mov	x23, xzr
	mov	x24, xzr
	mov	x25, xzr
	mov	x26, xzr
	mov	x27, xzr
	mov	x28, xzr
	mov	x29, xzr
	mov	x30, xzr
	b	vectors + 0x400
	.size	osrec_linux_el0_svc, .-osrec_linux_el0_svc

/* EL0: Linux's ERET returns here; the undefined instruction traps back. */
	.balign	4
	.type	osrec_el0_return, %function
osrec_el0_return:
	udf	#0
	.size	osrec_el0_return, .-osrec_el0_return

	.balign	2048
osrec_entry_vectors:
	.rept	8
	b	osrec_entry_unexpected
	.balign	128
	.endr
	b	osrec_entry_return		// synchronous, lower EL, AArch64
	.balign	128
	.rept	7
	b	osrec_entry_unexpected
	.balign	128
	.endr

osrec_entry_return:
	mrs	x9, esr_el1			// an unknown-reason (UDF) trap ...
	lsr	x9, x9, #26
	cbnz	x9, osrec_entry_unexpected
	mrs	x9, elr_el1			// ... at osrec_el0_return
	adrp	x10, osrec_el0_return
	add	x10, x10, :lo12:osrec_el0_return
	cmp	x9, x10
	b.ne	osrec_entry_unexpected
	adrp	x22, osrec_entry_saved
	add	x22, x22, :lo12:osrec_entry_saved
	ldr	x9, [x22, #56]
	mov	sp, x9
	ldp	x9, x10, [x22, #8]
	msr	vbar_el1, x9
	msr	sp_el0, x10
	ldp	x9, x10, [x22, #24]
	msr	tpidr_el1, x9
	msr	elr_el1, x10
	ldp	x9, x10, [x22, #40]
	msr	spsr_el1, x9
	msr	esr_el1, x10
	isb
	ldp	x19, x20, [sp, #16]
	ldp	x21, x22, [sp, #32]
	ldp	x23, x24, [sp, #48]
	ldp	x25, x26, [sp, #64]
	ldp	x27, x28, [sp, #80]
	ldp	x29, x30, [sp], #96
	ret

osrec_entry_unexpected:
	b	replay_fault

/* entry.S calls el0t_64_sync_handler(regs); the slice's handler takes its context first. */
	.global	el0t_64_sync_handler
	.type	el0t_64_sync_handler, %function
el0t_64_sync_handler:
	mov	x1, x0
	adrp	x0, osrec_entry_saved
	ldr	x0, [x0, :lo12:osrec_entry_saved]
	b	osrec_kernel_el0t_64_sync_handler
	.size	el0t_64_sync_handler, .-el0t_64_sync_handler

	.irp	name, el1t_64_sync_handler, el1t_64_irq_handler, el1t_64_fiq_handler, el1t_64_error_handler, \
		el1h_64_sync_handler, el1h_64_irq_handler, el1h_64_fiq_handler, el1h_64_error_handler, \
		el0t_64_irq_handler, el0t_64_fiq_handler, el0t_64_error_handler, \
		el0t_32_sync_handler, el0t_32_irq_handler, el0t_32_fiq_handler, el0t_32_error_handler, \
		schedule_tail, asm_exit_to_user_mode
	.global	\name
	.type	\name, %function
\name:
	b	osrec_entry_unexpected
	.endr

/* Boot-time alternative patching callbacks: entry.S's alternatives stay unpatched. */
	.irp	name, smccc_patch_fw_mitigation_conduit, spectre_bhb_patch_loop_iter, spectre_v4_patch_fw_mitigation_enable
	.global	\name
	.type	\name, %function
\name:
	b	osrec_entry_unexpected
	.endr

	.bss
	.balign	8
osrec_entry_saved:			// ctx, VBAR, SP_EL0, TPIDR_EL1, ELR, SPSR, ESR, SP
	.space	64
	.global	__entry_task, arm64_ssbd_callback_required, irq_stack_ptr, this_cpu_vector
__entry_task:
	.space	8
arm64_ssbd_callback_required:
	.space	8
irq_stack_ptr:
	.space	8
this_cpu_vector:
	.space	8
