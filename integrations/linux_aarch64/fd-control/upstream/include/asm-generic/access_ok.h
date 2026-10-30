/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 include/asm-generic/access_ok.h definitions. */

static inline int __access_ok(const void __user *ptr, unsigned long size)
{
	unsigned long limit = TASK_SIZE_MAX;
	unsigned long addr = (unsigned long)ptr;

	if (IS_ENABLED(CONFIG_ALTERNATE_USER_ADDRESS_SPACE) ||
	    !IS_ENABLED(CONFIG_MMU))
		return true;

	return (size <= limit) && (addr <= (limit - size));
}
