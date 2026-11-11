/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10 arch/arm64/include/asm/syscall.h definitions. */

static inline void syscall_set_return_value(struct task_struct *task,
					    struct pt_regs *regs,
					    int error, long val)
{
	if (error)
		val = error;

	if (is_compat_thread(task_thread_info(task)))
		val = lower_32_bits(val);

	regs->regs[0] = val;
}
