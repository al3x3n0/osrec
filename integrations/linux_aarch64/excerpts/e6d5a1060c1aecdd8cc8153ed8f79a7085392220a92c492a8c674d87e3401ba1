/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 include/linux/filelock.h definitions. */

static inline int break_deleg(struct inode *inode, unsigned int mode)
{
	/*
	 * Since this check is lockless, we must ensure that any refcounts
	 * taken are done before checking i_flctx->flc_lease. Otherwise, we
	 * could end up racing with tasks trying to set a new lease on this
	 * file.
	 */
	smp_mb();
	if (inode->i_flctx && !list_empty_careful(&inode->i_flctx->flc_lease))
		return __break_lease(inode, mode, FL_DELEG);
	return 0;
}

static inline int try_break_deleg(struct inode *inode, struct inode **delegated_inode)
{
	int ret;

	ret = break_deleg(inode, O_WRONLY|O_NONBLOCK);
	if (ret == -EWOULDBLOCK && delegated_inode) {
		*delegated_inode = inode;
		ihold(inode);
	}
	return ret;
}

static inline struct file_lock_context *
locks_inode_context(const struct inode *inode)
{
	return smp_load_acquire(&inode->i_flctx);
}
