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



SYSCALL_DEFINE3(close_range, unsigned int, fd, unsigned int, max_fd,
		unsigned int, flags)
{
	return __close_range(fd, max_fd, flags);
}

int chmod_common(const struct path *path, umode_t mode)
{
	struct inode *inode = path->dentry->d_inode;
	struct inode *delegated_inode = NULL;
	struct iattr newattrs;
	int error;
	error = mnt_want_write(path->mnt);
	if (error)
		return error;
retry_deleg:
	inode_lock(inode);
	error = security_path_chmod(path, mode);
	if (error)
		goto out_unlock;
	newattrs.ia_mode = (mode & S_IALLUGO) | (inode->i_mode & ~S_IALLUGO);
	newattrs.ia_valid = ATTR_MODE | ATTR_CTIME;
	error = notify_change(mnt_idmap(path->mnt), path->dentry,
			      &newattrs, &delegated_inode);
out_unlock:
	inode_unlock(inode);
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
	mnt_drop_write(path->mnt);
	return error;
}
int vfs_fchmod(struct file *file, umode_t mode)
{
	audit_file(file);
	return chmod_common(&file->f_path, mode);
}

SYSCALL_DEFINE2(fchmod, unsigned int, fd, umode_t, mode)
{
	struct fd f = fdget(fd);
	int err = -EBADF;

	if (f.file) {
		err = vfs_fchmod(f.file, mode);
		fdput(f);
	}
	return err;
}

static inline bool setattr_vfsuid(struct iattr *attr, kuid_t kuid)
{
	if (!uid_valid(kuid))
		return false;
	attr->ia_valid |= ATTR_UID;
	attr->ia_vfsuid = VFSUIDT_INIT(kuid);
	return true;
}
static inline bool setattr_vfsgid(struct iattr *attr, kgid_t kgid)
{
	if (!gid_valid(kgid))
		return false;
	attr->ia_valid |= ATTR_GID;
	attr->ia_vfsgid = VFSGIDT_INIT(kgid);
	return true;
}
int chown_common(const struct path *path, uid_t user, gid_t group)
{
	struct mnt_idmap *idmap;
	struct user_namespace *fs_userns;
	struct inode *inode = path->dentry->d_inode;
	struct inode *delegated_inode = NULL;
	int error;
	struct iattr newattrs;
	kuid_t uid;
	kgid_t gid;

	uid = make_kuid(current_user_ns(), user);
	gid = make_kgid(current_user_ns(), group);

	idmap = mnt_idmap(path->mnt);
	fs_userns = i_user_ns(inode);
retry_deleg:
	newattrs.ia_vfsuid = INVALID_VFSUID;
	newattrs.ia_vfsgid = INVALID_VFSGID;
	newattrs.ia_valid =  ATTR_CTIME;
	if ((user != (uid_t)-1) && !setattr_vfsuid(&newattrs, uid))
		return -EINVAL;
	if ((group != (gid_t)-1) && !setattr_vfsgid(&newattrs, gid))
		return -EINVAL;
	inode_lock(inode);
	if (!S_ISDIR(inode->i_mode))
		newattrs.ia_valid |= ATTR_KILL_SUID | ATTR_KILL_PRIV |
				     setattr_should_drop_sgid(idmap, inode);
	/* Continue to send actual fs values, not the mount values. */
	error = security_path_chown(
		path,
		from_vfsuid(idmap, fs_userns, newattrs.ia_vfsuid),
		from_vfsgid(idmap, fs_userns, newattrs.ia_vfsgid));
	if (!error)
		error = notify_change(idmap, path->dentry, &newattrs,
				      &delegated_inode);
	inode_unlock(inode);
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
	return error;
}
int vfs_fchown(struct file *file, uid_t user, gid_t group)
{
	int error;

	error = mnt_want_write_file(file);
	if (error)
		return error;
	audit_file(file);
	error = chown_common(&file->f_path, user, group);
	mnt_drop_write_file(file);
	return error;
}

int ksys_fchown(unsigned int fd, uid_t user, gid_t group)
{
	struct fd f = fdget(fd);
	int error = -EBADF;

	if (f.file) {
		error = vfs_fchown(f.file, user, group);
		fdput(f);
	}
	return error;
}
SYSCALL_DEFINE3(fchown, unsigned int, fd, uid_t, user, gid_t, group)
{
	return ksys_fchown(fd, user, group);
}
