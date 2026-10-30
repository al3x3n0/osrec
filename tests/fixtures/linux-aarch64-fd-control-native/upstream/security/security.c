// SPDX-License-Identifier: GPL-2.0-or-later
/* Reviewed original Linux v6.10 security/security.c definitions. */

int security_file_permission(struct file *file, int mask)
{
	return call_int_hook(file_permission, file, mask);
}

int security_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return call_int_hook(file_fcntl, file, cmd, arg);
}

int security_inode_setattr(struct mnt_idmap *idmap,
			   struct dentry *dentry, struct iattr *attr)
{
	if (unlikely(IS_PRIVATE(d_backing_inode(dentry))))
		return 0;
	return call_int_hook(inode_setattr, idmap, dentry, attr);
}

void security_inode_post_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
				 int ia_valid)
{
	if (unlikely(IS_PRIVATE(d_backing_inode(dentry))))
		return;
	call_void_hook(inode_post_setattr, idmap, dentry, ia_valid);
}

int security_file_truncate(struct file *file)
{
	return call_int_hook(file_truncate, file);
}
