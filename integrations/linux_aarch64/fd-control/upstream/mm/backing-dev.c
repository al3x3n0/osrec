/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10 mm/backing-dev.c definitions. */

struct backing_dev_info *inode_to_bdi(struct inode *inode)
{
	struct super_block *sb;

	if (!inode)
		return &noop_backing_dev_info;

	sb = inode->i_sb;
#ifdef CONFIG_BLOCK
	if (sb_is_blkdev_sb(sb))
		return I_BDEV(inode)->bd_disk->bdi;
#endif
	return sb->s_bdi;
}
