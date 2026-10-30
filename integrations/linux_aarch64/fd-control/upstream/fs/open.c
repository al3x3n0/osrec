// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 1991, 1992 Linus Torvalds.
 * Reviewed original Linux v6.10 fs/open.c definitions. */
int filp_close(struct file *filp, fl_owner_t id)
{
	int retval;

	retval = filp_flush(filp, id);
	fput(filp);

	return retval;
}

SYSCALL_DEFINE1(close, unsigned int, fd)
{
	int retval;
	struct file *file;

	file = file_close_fd(fd);
	if (!file)
		return -EBADF;

	retval = filp_flush(file, current->files);

	/*
	 * We're returning to user space. Don't bother
	 * with any delayed fput() cases.
	 */
	__fput_sync(file);
	/* can't restart close syscall because file table entry was cleared */
	if (unlikely(retval == -ERESTARTSYS ||
		     retval == -ERESTARTNOINTR ||
		     retval == -ERESTARTNOHAND ||
		     retval == -ERESTART_RESTARTBLOCK))
		retval = -EINTR;

	return retval;
}

/* Additional original Linux v6.10 positioned I/O/truncation definitions. */
long do_ftruncate(struct file *file, loff_t length, int small)
{
	struct inode *inode;
	struct dentry *dentry;
	int error;

	/* explicitly opened as large or we are on 64-bit box */
	if (file->f_flags & O_LARGEFILE)
		small = 0;
	dentry = file->f_path.dentry;
	inode = dentry->d_inode;
	if (!S_ISREG(inode->i_mode) || !(file->f_mode & FMODE_WRITE))
		return -EINVAL;

	/* Cannot ftruncate over 2^31 bytes without large file support */
	if (small && length > MAX_NON_LFS)
		return -EINVAL;
	/* Check IS_APPEND on real upper inode */
	if (IS_APPEND(file_inode(file)))
		return -EPERM;
	sb_start_write(inode->i_sb);
	error = security_file_truncate(file);
	if (!error)
		error = do_truncate(file_mnt_idmap(file), dentry, length,
				    ATTR_MTIME | ATTR_CTIME, file);
	sb_end_write(inode->i_sb);

	return error;
}

long do_sys_ftruncate(unsigned int fd, loff_t length, int small)
{
	struct fd f;
	int error;

	if (length < 0)
		return -EINVAL;
	f = fdget(fd);
	if (!f.file)
		return -EBADF;
	error = do_ftruncate(f.file, length, small);

	fdput(f);
	return error;
}

SYSCALL_DEFINE2(ftruncate, unsigned int, fd, off_t, length)
{
	return do_sys_ftruncate(fd, length, 1);
}

int do_truncate(struct mnt_idmap *idmap, struct dentry *dentry,
		loff_t length, unsigned int time_attrs, struct file *filp)
{
	int ret;
	struct iattr newattrs;

	/* Not pretty: "inode->i_size" shouldn't really be signed. But it is. */
	if (length < 0)
		return -EINVAL;

	newattrs.ia_size = length;
	newattrs.ia_valid = ATTR_SIZE | time_attrs;
	if (filp) {
		newattrs.ia_file = filp;
		newattrs.ia_valid |= ATTR_FILE;
	}

	/* Remove suid, sgid, and file capabilities on truncate too */
	ret = dentry_needs_remove_privs(idmap, dentry);
	if (ret < 0)
		return ret;
	if (ret)
		newattrs.ia_valid |= ret | ATTR_FORCE;

	inode_lock(dentry->d_inode);
	/* Note any delegations or leases have already been broken: */
	ret = notify_change(idmap, dentry, &newattrs, NULL);
	inode_unlock(dentry->d_inode);
	return ret;
}

static int filp_flush(struct file *filp, fl_owner_t id)
{
	int retval = 0;

	if (CHECK_DATA_CORRUPTION(file_count(filp) == 0,
			"VFS: Close: file count is 0 (f_op=%ps)",
			filp->f_op)) {
		return 0;
	}

	if (filp->f_op->flush)
		retval = filp->f_op->flush(filp, id);

	if (likely(!(filp->f_mode & FMODE_PATH))) {
		dnotify_flush(filp, id);
		locks_remove_posix(filp, id);
	}
	return retval;
}
