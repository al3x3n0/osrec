/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 include/linux/mnt_idmapping.h definitions. */

static inline uid_t __vfsuid_val(vfsuid_t uid)
{
	return uid.val;
}

static inline gid_t __vfsgid_val(vfsgid_t gid)
{
	return gid.val;
}

static inline bool vfsuid_valid(vfsuid_t uid)
{
	return __vfsuid_val(uid) != (uid_t)-1;
}

static inline bool vfsgid_valid(vfsgid_t gid)
{
	return __vfsgid_val(gid) != (gid_t)-1;
}
