/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 arch/arm64/kernel/entry-common.c definitions: the EL0 synchronous exception handler and its SVC path. */

static __always_inline void __enter_from_user_mode(void)
{
	lockdep_hardirqs_off(CALLER_ADDR0);
	CT_WARN_ON(ct_state() != CONTEXT_USER);
	user_exit_irqoff();
	trace_hardirqs_off_finish();
	mte_disable_tco_entry(current);
}

static __always_inline void enter_from_user_mode(struct pt_regs *regs)
{
	__enter_from_user_mode();
}

static __always_inline void __exit_to_user_mode(void)
{
	trace_hardirqs_on_prepare();
	lockdep_hardirqs_on_prepare();
	user_enter_irqoff();
	lockdep_hardirqs_on(CALLER_ADDR0);
}

static __always_inline void exit_to_user_mode_prepare(struct pt_regs *regs)
{
	unsigned long flags;

	local_irq_disable();

	flags = read_thread_flags();
	if (unlikely(flags & _TIF_WORK_MASK))
		do_notify_resume(regs, flags);

	local_daif_mask();

	lockdep_sys_exit();
}

static __always_inline void exit_to_user_mode(struct pt_regs *regs)
{
	exit_to_user_mode_prepare(regs);
	mte_check_tfsr_exit();
	__exit_to_user_mode();
}

static void cortex_a76_erratum_1463225_svc_handler(void) { }

static inline void fp_user_discard(void)
{
	/*
	 * If SME is active then exit streaming mode.  If ZA is active
	 * then flush the SVE registers but leave userspace access to
	 * both SVE and SME enabled, otherwise disable SME for the
	 * task and fall through to disabling SVE too.  This means
	 * that after a syscall we never have any streaming mode
	 * register state to track, if this changes the KVM code will
	 * need updating.
	 */
	if (system_supports_sme())
		sme_smstop_sm();

	if (!system_supports_sve())
		return;

	if (test_thread_flag(TIF_SVE)) {
		unsigned int sve_vq_minus_one;

		sve_vq_minus_one = sve_vq_from_vl(task_get_sve_vl(current)) - 1;
		sve_flush_live(true, sve_vq_minus_one);
	}
}

static void noinstr el0_svc(struct pt_regs *regs)
{
	enter_from_user_mode(regs);
	cortex_a76_erratum_1463225_svc_handler();
	fp_user_discard();
	local_daif_restore(DAIF_PROCCTX);
	do_el0_svc(regs);
	exit_to_user_mode(regs);
}

asmlinkage void noinstr el0t_64_sync_handler(struct pt_regs *regs)
{
	unsigned long esr = read_sysreg(esr_el1);

	switch (ESR_ELx_EC(esr)) {
	case ESR_ELx_EC_SVC64:
		el0_svc(regs);
		break;
	case ESR_ELx_EC_DABT_LOW:
		el0_da(regs, esr);
		break;
	case ESR_ELx_EC_IABT_LOW:
		el0_ia(regs, esr);
		break;
	case ESR_ELx_EC_FP_ASIMD:
		el0_fpsimd_acc(regs, esr);
		break;
	case ESR_ELx_EC_SVE:
		el0_sve_acc(regs, esr);
		break;
	case ESR_ELx_EC_SME:
		el0_sme_acc(regs, esr);
		break;
	case ESR_ELx_EC_FP_EXC64:
		el0_fpsimd_exc(regs, esr);
		break;
	case ESR_ELx_EC_SYS64:
	case ESR_ELx_EC_WFx:
		el0_sys(regs, esr);
		break;
	case ESR_ELx_EC_SP_ALIGN:
		el0_sp(regs, esr);
		break;
	case ESR_ELx_EC_PC_ALIGN:
		el0_pc(regs, esr);
		break;
	case ESR_ELx_EC_UNKNOWN:
		el0_undef(regs, esr);
		break;
	case ESR_ELx_EC_BTI:
		el0_bti(regs);
		break;
	case ESR_ELx_EC_MOPS:
		el0_mops(regs, esr);
		break;
	case ESR_ELx_EC_BREAKPT_LOW:
	case ESR_ELx_EC_SOFTSTP_LOW:
	case ESR_ELx_EC_WATCHPT_LOW:
	case ESR_ELx_EC_BRK64:
		el0_dbg(regs, esr);
		break;
	case ESR_ELx_EC_FPAC:
		el0_fpac(regs, esr);
		break;
	default:
		el0_inv(regs, esr);
	}
}
