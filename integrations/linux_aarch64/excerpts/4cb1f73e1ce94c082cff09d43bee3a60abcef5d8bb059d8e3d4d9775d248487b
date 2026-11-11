/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10.14 fs/attr.c definitions. */

int may_setattr(struct mnt_idmap *idmap, struct inode *inode,
		unsigned int ia_valid)
{
	int error;

	if (ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_TIMES_SET)) {
		if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
			return -EPERM;
	}

	/*
	 * If utimes(2) and friends are called with times == NULL (or both
	 * times are UTIME_NOW), then we need to check for write permission
	 */
	if (ia_valid & ATTR_TOUCH) {
		if (IS_IMMUTABLE(inode))
			return -EPERM;

		if (!inode_owner_or_capable(idmap, inode)) {
			error = inode_permission(idmap, inode, MAY_WRITE);
			if (error)
				return error;
		}
	}
	return 0;
}

int inode_newsize_ok(const struct inode *inode, loff_t offset)
{
	if (offset < 0)
		return -EINVAL;
	if (inode->i_size < offset) {
		unsigned long limit;

		limit = rlimit(RLIMIT_FSIZE);
		if (limit != RLIM_INFINITY && offset > limit)
			goto out_sig;
		if (offset > inode->i_sb->s_maxbytes)
			goto out_big;
	} else {
		/*
		 * truncation of in-use swapfiles is disallowed - it would
		 * cause subsequent swapout to scribble on the now-freed
		 * blocks.
		 */
		if (IS_SWAPFILE(inode))
			return -ETXTBSY;
	}

	return 0;
out_sig:
	send_sig(SIGXFSZ, current, 0);
out_big:
	return -EFBIG;
}

int setattr_prepare(struct mnt_idmap *idmap, struct dentry *dentry,
		    struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	unsigned int ia_valid = attr->ia_valid;

	/*
	 * First check size constraints.  These can't be overriden using
	 * ATTR_FORCE.
	 */
	if (ia_valid & ATTR_SIZE) {
		int error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;
	}

	/* If force is set do it anyway. */
	if (ia_valid & ATTR_FORCE)
		goto kill_priv;

	/* Make sure a caller can chown. */
	if ((ia_valid & ATTR_UID) &&
	    !chown_ok(idmap, inode, attr->ia_vfsuid))
		return -EPERM;

	/* Make sure caller can chgrp. */
	if ((ia_valid & ATTR_GID) &&
	    !chgrp_ok(idmap, inode, attr->ia_vfsgid))
		return -EPERM;

	/* Make sure a caller can chmod. */
	if (ia_valid & ATTR_MODE) {
		vfsgid_t vfsgid;

		if (!inode_owner_or_capable(idmap, inode))
			return -EPERM;

		if (ia_valid & ATTR_GID)
			vfsgid = attr->ia_vfsgid;
		else
			vfsgid = i_gid_into_vfsgid(idmap, inode);

		/* Also check the setgid bit! */
		if (!in_group_or_capable(idmap, inode, vfsgid))
			attr->ia_mode &= ~S_ISGID;
	}

	/* Check for setting the inode time. */
	if (ia_valid & (ATTR_MTIME_SET | ATTR_ATIME_SET | ATTR_TIMES_SET)) {
		if (!inode_owner_or_capable(idmap, inode))
			return -EPERM;
	}

kill_priv:
	/* User has permission for the change */
	if (ia_valid & ATTR_KILL_PRIV) {
		int error;

		error = security_inode_killpriv(idmap, dentry);
		if (error)
			return error;
	}

	return 0;
}

void setattr_copy(struct mnt_idmap *idmap, struct inode *inode,
		  const struct iattr *attr)
{
	unsigned int ia_valid = attr->ia_valid;

	i_uid_update(idmap, attr, inode);
	i_gid_update(idmap, attr, inode);
	if (ia_valid & ATTR_ATIME)
		inode_set_atime_to_ts(inode, attr->ia_atime);
	if (ia_valid & ATTR_MTIME)
		inode_set_mtime_to_ts(inode, attr->ia_mtime);
	if (ia_valid & ATTR_CTIME)
		inode_set_ctime_to_ts(inode, attr->ia_ctime);
	if (ia_valid & ATTR_MODE) {
		umode_t mode = attr->ia_mode;
		if (!in_group_or_capable(idmap, inode,
					 i_gid_into_vfsgid(idmap, inode)))
			mode &= ~S_ISGID;
		inode->i_mode = mode;
	}
}

int notify_change(struct mnt_idmap *idmap, struct dentry *dentry,
		  struct iattr *attr, struct inode **delegated_inode)
{
	struct inode *inode = dentry->d_inode;
	umode_t mode = inode->i_mode;
	int error;
	struct timespec64 now;
	unsigned int ia_valid = attr->ia_valid;

	WARN_ON_ONCE(!inode_is_locked(inode));

	error = may_setattr(idmap, inode, ia_valid);
	if (error)
		return error;

	if ((ia_valid & ATTR_MODE)) {
		/*
		 * Don't allow changing the mode of symlinks:
		 *
		 * (1) The vfs doesn't take the mode of symlinks into account
		 *     during permission checking.
		 * (2) This has never worked correctly. Most major filesystems
		 *     did return EOPNOTSUPP due to interactions with POSIX ACLs
		 *     but did still updated the mode of the symlink.
		 *     This inconsistency led system call wrapper providers such
		 *     as libc to block changing the mode of symlinks with
		 *     EOPNOTSUPP already.
		 * (3) To even do this in the first place one would have to use
		 *     specific file descriptors and quite some effort.
		 */
		if (S_ISLNK(inode->i_mode))
			return -EOPNOTSUPP;

		/* Flag setting protected by i_mutex */
		if (is_sxid(attr->ia_mode))
			inode->i_flags &= ~S_NOSEC;
	}

	now = current_time(inode);

	attr->ia_ctime = now;
	if (!(ia_valid & ATTR_ATIME_SET))
		attr->ia_atime = now;
	else
		attr->ia_atime = timestamp_truncate(attr->ia_atime, inode);
	if (!(ia_valid & ATTR_MTIME_SET))
		attr->ia_mtime = now;
	else
		attr->ia_mtime = timestamp_truncate(attr->ia_mtime, inode);

	if (ia_valid & ATTR_KILL_PRIV) {
		error = security_inode_need_killpriv(dentry);
		if (error < 0)
			return error;
		if (error == 0)
			ia_valid = attr->ia_valid &= ~ATTR_KILL_PRIV;
	}

	/*
	 * We now pass ATTR_KILL_S*ID to the lower level setattr function so
	 * that the function has the ability to reinterpret a mode change
	 * that's due to these bits. This adds an implicit restriction that
	 * no function will ever call notify_change with both ATTR_MODE and
	 * ATTR_KILL_S*ID set.
	 */
	if ((ia_valid & (ATTR_KILL_SUID|ATTR_KILL_SGID)) &&
	    (ia_valid & ATTR_MODE))
		BUG();

	if (ia_valid & ATTR_KILL_SUID) {
		if (mode & S_ISUID) {
			ia_valid = attr->ia_valid |= ATTR_MODE;
			attr->ia_mode = (inode->i_mode & ~S_ISUID);
		}
	}
	if (ia_valid & ATTR_KILL_SGID) {
		if (mode & S_ISGID) {
			if (!(ia_valid & ATTR_MODE)) {
				ia_valid = attr->ia_valid |= ATTR_MODE;
				attr->ia_mode = inode->i_mode;
			}
			attr->ia_mode &= ~S_ISGID;
		}
	}
	if (!(attr->ia_valid & ~(ATTR_KILL_SUID | ATTR_KILL_SGID)))
		return 0;

	/*
	 * Verify that uid/gid changes are valid in the target
	 * namespace of the superblock.
	 */
	if (ia_valid & ATTR_UID &&
	    !vfsuid_has_fsmapping(idmap, inode->i_sb->s_user_ns,
				  attr->ia_vfsuid))
		return -EOVERFLOW;
	if (ia_valid & ATTR_GID &&
	    !vfsgid_has_fsmapping(idmap, inode->i_sb->s_user_ns,
				  attr->ia_vfsgid))
		return -EOVERFLOW;

	/* Don't allow modifications of files with invalid uids or
	 * gids unless those uids & gids are being made valid.
	 */
	if (!(ia_valid & ATTR_UID) &&
	    !vfsuid_valid(i_uid_into_vfsuid(idmap, inode)))
		return -EOVERFLOW;
	if (!(ia_valid & ATTR_GID) &&
	    !vfsgid_valid(i_gid_into_vfsgid(idmap, inode)))
		return -EOVERFLOW;

	error = security_inode_setattr(idmap, dentry, attr);
	if (error)
		return error;

	/*
	 * If ATTR_DELEG is set, then these attributes are being set on
	 * behalf of the holder of a write delegation. We want to avoid
	 * breaking the delegation in this case.
	 */
	if (!(ia_valid & ATTR_DELEG)) {
		error = try_break_deleg(inode, delegated_inode);
		if (error)
			return error;
	}

	if (inode->i_op->setattr)
		error = inode->i_op->setattr(idmap, dentry, attr);
	else
		error = simple_setattr(idmap, dentry, attr);

	if (!error) {
		fsnotify_change(dentry, ia_valid);
		security_inode_post_setattr(idmap, dentry, ia_valid);
	}

	return error;
}
