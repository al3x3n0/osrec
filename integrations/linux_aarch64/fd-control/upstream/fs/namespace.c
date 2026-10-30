/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10 fs/namespace.c definitions. */

bool __mnt_is_readonly(struct vfsmount *mnt)
{
	return (mnt->mnt_flags & MNT_READONLY) || sb_rdonly(mnt->mnt_sb);
}

int mnt_get_write_access_file(struct file *file)
{
	if (file->f_mode & FMODE_WRITER) {
		/*
		 * Superblock may have become readonly while there are still
		 * writable fd's, e.g. due to a fs error with errors=remount-ro
		 */
		if (__mnt_is_readonly(file->f_path.mnt))
			return -EROFS;
		return 0;
	}
	return mnt_get_write_access(file->f_path.mnt);
}

void mnt_put_write_access_file(struct file *file)
{
	if (!(file->f_mode & FMODE_WRITER))
		mnt_put_write_access(file->f_path.mnt);
}
