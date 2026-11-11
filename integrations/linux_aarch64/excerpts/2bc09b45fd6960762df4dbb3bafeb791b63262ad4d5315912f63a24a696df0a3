/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 include/linux/mount.h definitions. */

static inline struct mnt_idmap *mnt_idmap(const struct vfsmount *mnt)
{
	/* Pairs with smp_store_release() in do_idmap_mount(). */
	return smp_load_acquire(&mnt->mnt_idmap);
}
