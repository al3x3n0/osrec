/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10 arch/arm64/include/asm/uaccess.h definitions (CONFIG_ARM64_SW_TTBR0_PAN off). */

static inline int access_ok(const void __user *addr, unsigned long size)
{
	/*
	 * Asynchronous I/O running in a kernel thread does not have the
	 * TIF_TAGGED_ADDR flag of the process owning the mm, so always untag
	 * the user address before checking.
	 */
	if (IS_ENABLED(CONFIG_ARM64_TAGGED_ADDR_ABI) &&
	    (current->flags & PF_KTHREAD || test_thread_flag(TIF_TAGGED_ADDR)))
		addr = untagged_addr(addr);

	return likely(__access_ok(addr, size));
}

static inline bool uaccess_ttbr0_disable(void)
{
	return false;
}

static inline bool uaccess_ttbr0_enable(void)
{
	return false;
}
