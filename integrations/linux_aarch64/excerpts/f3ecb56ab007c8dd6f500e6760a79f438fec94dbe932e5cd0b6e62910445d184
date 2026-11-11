// SPDX-License-Identifier: GPL-2.0
/* Selected original definitions/macros, Linux v6.10 include/linux/capability.h.
 * https://raw.githubusercontent.com/torvalds/linux/v6.10/include/linux/capability.h */
# define CAP_FS_MASK     (BIT_ULL(CAP_CHOWN)		\
			| BIT_ULL(CAP_MKNOD)		\
			| BIT_ULL(CAP_DAC_OVERRIDE)	\
			| BIT_ULL(CAP_DAC_READ_SEARCH)	\
			| BIT_ULL(CAP_FOWNER)		\
			| BIT_ULL(CAP_FSETID)		\
			| BIT_ULL(CAP_MAC_OVERRIDE))
# define CAP_FS_SET       ((kernel_cap_t) { CAP_FS_MASK | BIT_ULL(CAP_LINUX_IMMUTABLE) })

static inline kernel_cap_t cap_drop(const kernel_cap_t a,
				    const kernel_cap_t drop)
{
	return (kernel_cap_t) { a.val &~ drop.val };
}

static inline kernel_cap_t cap_drop_fs_set(const kernel_cap_t a)
{
	return cap_drop(a, CAP_FS_SET);
}

static inline kernel_cap_t cap_raise_fs_set(const kernel_cap_t a,
					    const kernel_cap_t permitted)
{
	return cap_combine(a, cap_intersect(permitted, CAP_FS_SET));
}


