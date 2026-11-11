/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10 fs/locks.c definitions. */

void locks_remove_posix(struct file *filp, fl_owner_t owner)
{
	int error;
	struct inode *inode = file_inode(filp);
	struct file_lock lock;
	struct file_lock_context *ctx;

	/*
	 * If there are no locks held on this file, we don't need to call
	 * posix_lock_file().  Another process could be setting a lock on this
	 * file at the same time, but we wouldn't remove that lock anyway.
	 */
	ctx = locks_inode_context(inode);
	if (!ctx || list_empty(&ctx->flc_posix))
		return;

	locks_init_lock(&lock);
	lock.c.flc_type = F_UNLCK;
	lock.c.flc_flags = FL_POSIX | FL_CLOSE;
	lock.fl_start = 0;
	lock.fl_end = OFFSET_MAX;
	lock.c.flc_owner = owner;
	lock.c.flc_pid = current->tgid;
	lock.c.flc_file = filp;
	lock.fl_ops = NULL;
	lock.fl_lmops = NULL;

	error = vfs_lock_file(filp, F_SETLK, &lock, NULL);

	if (lock.fl_ops && lock.fl_ops->fl_release_private)
		lock.fl_ops->fl_release_private(&lock);
	trace_locks_remove_posix(inode, &lock, error);
}
