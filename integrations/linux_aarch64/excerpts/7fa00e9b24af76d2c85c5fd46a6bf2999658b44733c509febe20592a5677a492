/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 include/linux/quotaops.h definitions. */

static inline bool is_quota_modification(struct mnt_idmap *idmap,
					 struct inode *inode, struct iattr *ia)
{
	return ((ia->ia_valid & ATTR_SIZE) ||
		i_uid_needs_update(idmap, ia, inode) ||
		i_gid_needs_update(idmap, ia, inode));
}
