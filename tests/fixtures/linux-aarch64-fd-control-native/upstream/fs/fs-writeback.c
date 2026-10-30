/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10 fs/fs-writeback.c definitions. */

void __mark_inode_dirty(struct inode *inode, int flags)
{
	struct super_block *sb = inode->i_sb;
	int dirtytime = 0;
	struct bdi_writeback *wb = NULL;

	trace_writeback_mark_inode_dirty(inode, flags);

	if (flags & I_DIRTY_INODE) {
		/*
		 * Inode timestamp update will piggback on this dirtying.
		 * We tell ->dirty_inode callback that timestamps need to
		 * be updated by setting I_DIRTY_TIME in flags.
		 */
		if (inode->i_state & I_DIRTY_TIME) {
			spin_lock(&inode->i_lock);
			if (inode->i_state & I_DIRTY_TIME) {
				inode->i_state &= ~I_DIRTY_TIME;
				flags |= I_DIRTY_TIME;
			}
			spin_unlock(&inode->i_lock);
		}

		/*
		 * Notify the filesystem about the inode being dirtied, so that
		 * (if needed) it can update on-disk fields and journal the
		 * inode.  This is only needed when the inode itself is being
		 * dirtied now.  I.e. it's only needed for I_DIRTY_INODE, not
		 * for just I_DIRTY_PAGES or I_DIRTY_TIME.
		 */
		trace_writeback_dirty_inode_start(inode, flags);
		if (sb->s_op->dirty_inode)
			sb->s_op->dirty_inode(inode,
				flags & (I_DIRTY_INODE | I_DIRTY_TIME));
		trace_writeback_dirty_inode(inode, flags);

		/* I_DIRTY_INODE supersedes I_DIRTY_TIME. */
		flags &= ~I_DIRTY_TIME;
	} else {
		/*
		 * Else it's either I_DIRTY_PAGES, I_DIRTY_TIME, or nothing.
		 * (We don't support setting both I_DIRTY_PAGES and I_DIRTY_TIME
		 * in one call to __mark_inode_dirty().)
		 */
		dirtytime = flags & I_DIRTY_TIME;
		WARN_ON_ONCE(dirtytime && flags != I_DIRTY_TIME);
	}

	/*
	 * Paired with smp_mb() in __writeback_single_inode() for the
	 * following lockless i_state test.  See there for details.
	 */
	smp_mb();

	if ((inode->i_state & flags) == flags)
		return;

	spin_lock(&inode->i_lock);
	if ((inode->i_state & flags) != flags) {
		const int was_dirty = inode->i_state & I_DIRTY;

		inode_attach_wb(inode, NULL);

		inode->i_state |= flags;

		/*
		 * Grab inode's wb early because it requires dropping i_lock and we
		 * need to make sure following checks happen atomically with dirty
		 * list handling so that we don't move inodes under flush worker's
		 * hands.
		 */
		if (!was_dirty) {
			wb = locked_inode_to_wb_and_lock_list(inode);
			spin_lock(&inode->i_lock);
		}

		/*
		 * If the inode is queued for writeback by flush worker, just
		 * update its dirty state. Once the flush worker is done with
		 * the inode it will place it on the appropriate superblock
		 * list, based upon its state.
		 */
		if (inode->i_state & I_SYNC_QUEUED)
			goto out_unlock;

		/*
		 * Only add valid (hashed) inodes to the superblock's
		 * dirty list.  Add blockdev inodes as well.
		 */
		if (!S_ISBLK(inode->i_mode)) {
			if (inode_unhashed(inode))
				goto out_unlock;
		}
		if (inode->i_state & I_FREEING)
			goto out_unlock;

		/*
		 * If the inode was already on b_dirty/b_io/b_more_io, don't
		 * reposition it (that would break b_dirty time-ordering).
		 */
		if (!was_dirty) {
			struct list_head *dirty_list;
			bool wakeup_bdi = false;

			inode->dirtied_when = jiffies;
			if (dirtytime)
				inode->dirtied_time_when = jiffies;

			if (inode->i_state & I_DIRTY)
				dirty_list = &wb->b_dirty;
			else
				dirty_list = &wb->b_dirty_time;

			wakeup_bdi = inode_io_list_move_locked(inode, wb,
							       dirty_list);

			spin_unlock(&wb->list_lock);
			spin_unlock(&inode->i_lock);
			trace_writeback_dirty_inode_enqueue(inode);

			/*
			 * If this is the first dirty inode for this bdi,
			 * we have to wake-up the corresponding bdi thread
			 * to make sure background write-back happens
			 * later.
			 */
			if (wakeup_bdi &&
			    (wb->bdi->capabilities & BDI_CAP_WRITEBACK))
				wb_wakeup_delayed(wb);
			return;
		}
	}
out_unlock:
	if (wb)
		spin_unlock(&wb->list_lock);
	spin_unlock(&inode->i_lock);
}
