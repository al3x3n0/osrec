/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 include/linux/iversion.h definitions. */

static inline u64
inode_peek_iversion_raw(const struct inode *inode)
{
	return atomic64_read(&inode->i_version);
}

static inline bool
inode_iversion_need_inc(struct inode *inode)
{
	return inode_peek_iversion_raw(inode) & I_VERSION_QUERIED;
}

static inline void
inode_inc_iversion(struct inode *inode)
{
	inode_maybe_inc_iversion(inode, true);
}
