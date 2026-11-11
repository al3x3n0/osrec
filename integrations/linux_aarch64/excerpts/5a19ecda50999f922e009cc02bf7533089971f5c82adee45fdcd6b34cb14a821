/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10 fs/libfs.c definitions. */

bool inode_maybe_inc_iversion(struct inode *inode, bool force)
{
	u64 cur, new;

	/*
	 * The i_version field is not strictly ordered with any other inode
	 * information, but the legacy inode_inc_iversion code used a spinlock
	 * to serialize increments.
	 *
	 * Here, we add full memory barriers to ensure that any de-facto
	 * ordering with other info is preserved.
	 *
	 * This barrier pairs with the barrier in inode_query_iversion()
	 */
	smp_mb();
	cur = inode_peek_iversion_raw(inode);
	do {
		/* If flag is clear then we needn't do anything */
		if (!force && !(cur & I_VERSION_QUERIED))
			return false;

		/* Since lowest bit is flag, add 2 to avoid it */
		new = (cur & ~I_VERSION_QUERIED) + I_VERSION_INCREMENT;
	} while (!atomic64_try_cmpxchg(&inode->i_version, &cur, new));
	return true;
}
