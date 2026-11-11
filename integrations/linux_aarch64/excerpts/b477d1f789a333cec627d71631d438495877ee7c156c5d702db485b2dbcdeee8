/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 include/linux/dcache.h definitions. */

static inline struct inode *d_inode(const struct dentry *dentry)
{
	return dentry->d_inode;
}

static inline struct inode *d_backing_inode(const struct dentry *upper)
{
	struct inode *inode = upper->d_inode;

	return inode;
}
