/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10 fs/inode.c definitions. */

struct timespec64 timestamp_truncate(struct timespec64 t, struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	unsigned int gran = sb->s_time_gran;

	t.tv_sec = clamp(t.tv_sec, sb->s_time_min, sb->s_time_max);
	if (unlikely(t.tv_sec == sb->s_time_max || t.tv_sec == sb->s_time_min))
		t.tv_nsec = 0;

	/* Avoid division in the common cases 1 ns and 1 s. */
	if (gran == 1)
		; /* nothing */
	else if (gran == NSEC_PER_SEC)
		t.tv_nsec = 0;
	else if (gran > 1 && gran < NSEC_PER_SEC)
		t.tv_nsec -= t.tv_nsec % gran;
	else
		WARN(1, "invalid file time granularity: %u", gran);
	return t;
}

struct timespec64 current_time(struct inode *inode)
{
	struct timespec64 now;

	ktime_get_coarse_real_ts64(&now);
	return timestamp_truncate(now, inode);
}

struct timespec64 inode_set_ctime_current(struct inode *inode)
{
	struct timespec64 now = current_time(inode);

	inode_set_ctime_to_ts(inode, now);
	return now;
}

int inode_update_timestamps(struct inode *inode, int flags)
{
	int updated = 0;
	struct timespec64 now;

	if (flags & (S_MTIME|S_CTIME|S_VERSION)) {
		struct timespec64 ctime = inode_get_ctime(inode);
		struct timespec64 mtime = inode_get_mtime(inode);

		now = inode_set_ctime_current(inode);
		if (!timespec64_equal(&now, &ctime))
			updated |= S_CTIME;
		if (!timespec64_equal(&now, &mtime)) {
			inode_set_mtime_to_ts(inode, now);
			updated |= S_MTIME;
		}
		if (IS_I_VERSION(inode) && inode_maybe_inc_iversion(inode, updated))
			updated |= S_VERSION;
	} else {
		now = current_time(inode);
	}

	if (flags & S_ATIME) {
		struct timespec64 atime = inode_get_atime(inode);

		if (!timespec64_equal(&now, &atime)) {
			inode_set_atime_to_ts(inode, now);
			updated |= S_ATIME;
		}
	}
	return updated;
}

int generic_update_time(struct inode *inode, int flags)
{
	int updated = inode_update_timestamps(inode, flags);
	int dirty_flags = 0;

	if (updated & (S_ATIME|S_MTIME|S_CTIME))
		dirty_flags = inode->i_sb->s_flags & SB_LAZYTIME ? I_DIRTY_TIME : I_DIRTY_SYNC;
	if (updated & S_VERSION)
		dirty_flags |= I_DIRTY_SYNC;
	__mark_inode_dirty(inode, dirty_flags);
	return updated;
}

int inode_update_time(struct inode *inode, int flags)
{
	if (inode->i_op->update_time)
		return inode->i_op->update_time(inode, flags);
	generic_update_time(inode, flags);
	return 0;
}

static bool relatime_need_update(struct vfsmount *mnt, struct inode *inode,
			     struct timespec64 now)
{
	struct timespec64 atime, mtime, ctime;

	if (!(mnt->mnt_flags & MNT_RELATIME))
		return true;
	/*
	 * Is mtime younger than or equal to atime? If yes, update atime:
	 */
	atime = inode_get_atime(inode);
	mtime = inode_get_mtime(inode);
	if (timespec64_compare(&mtime, &atime) >= 0)
		return true;
	/*
	 * Is ctime younger than or equal to atime? If yes, update atime:
	 */
	ctime = inode_get_ctime(inode);
	if (timespec64_compare(&ctime, &atime) >= 0)
		return true;

	/*
	 * Is the previous atime value older than a day? If yes,
	 * update atime:
	 */
	if ((long)(now.tv_sec - atime.tv_sec) >= 24*60*60)
		return true;
	/*
	 * Good, we can skip the atime update:
	 */
	return false;
}

bool atime_needs_update(const struct path *path, struct inode *inode)
{
	struct vfsmount *mnt = path->mnt;
	struct timespec64 now, atime;

	if (inode->i_flags & S_NOATIME)
		return false;

	/* Atime updates will likely cause i_uid and i_gid to be written
	 * back improprely if their true value is unknown to the vfs.
	 */
	if (HAS_UNMAPPED_ID(mnt_idmap(mnt), inode))
		return false;

	if (IS_NOATIME(inode))
		return false;
	if ((inode->i_sb->s_flags & SB_NODIRATIME) && S_ISDIR(inode->i_mode))
		return false;

	if (mnt->mnt_flags & MNT_NOATIME)
		return false;
	if ((mnt->mnt_flags & MNT_NODIRATIME) && S_ISDIR(inode->i_mode))
		return false;

	now = current_time(inode);

	if (!relatime_need_update(mnt, inode, now))
		return false;

	atime = inode_get_atime(inode);
	if (timespec64_equal(&atime, &now))
		return false;

	return true;
}

void touch_atime(const struct path *path)
{
	struct vfsmount *mnt = path->mnt;
	struct inode *inode = d_inode(path->dentry);

	if (!atime_needs_update(path, inode))
		return;

	if (!sb_start_write_trylock(inode->i_sb))
		return;

	if (mnt_get_write_access(mnt) != 0)
		goto skip_update;
	/*
	 * File systems can error out when updating inodes if they need to
	 * allocate new space to modify an inode (such is the case for
	 * Btrfs), but since we touch atime while walking down the path we
	 * really don't care if we failed to update the atime of the file,
	 * so just ignore the return value.
	 * We may also fail on filesystems that have the ability to make parts
	 * of the fs read only, e.g. subvolumes in Btrfs.
	 */
	inode_update_time(inode, S_ATIME);
	mnt_put_write_access(mnt);
skip_update:
	sb_end_write(inode->i_sb);
}

static int inode_needs_update_time(struct inode *inode)
{
	int sync_it = 0;
	struct timespec64 now = current_time(inode);
	struct timespec64 ts;

	/* First try to exhaust all avenues to not sync */
	if (IS_NOCMTIME(inode))
		return 0;

	ts = inode_get_mtime(inode);
	if (!timespec64_equal(&ts, &now))
		sync_it = S_MTIME;

	ts = inode_get_ctime(inode);
	if (!timespec64_equal(&ts, &now))
		sync_it |= S_CTIME;

	if (IS_I_VERSION(inode) && inode_iversion_need_inc(inode))
		sync_it |= S_VERSION;

	return sync_it;
}

static int __file_update_time(struct file *file, int sync_mode)
{
	int ret = 0;
	struct inode *inode = file_inode(file);

	/* try to update time settings */
	if (!mnt_get_write_access_file(file)) {
		ret = inode_update_time(inode, sync_mode);
		mnt_put_write_access_file(file);
	}

	return ret;
}

int file_update_time(struct file *file)
{
	int ret;
	struct inode *inode = file_inode(file);

	ret = inode_needs_update_time(inode);
	if (ret <= 0)
		return ret;

	return __file_update_time(file, ret);
}

int file_remove_privs_flags(struct file *file, unsigned int flags)
{
	struct dentry *dentry = file_dentry(file);
	struct inode *inode = file_inode(file);
	int error = 0;
	int kill;

	if (IS_NOSEC(inode) || !S_ISREG(inode->i_mode))
		return 0;

	kill = dentry_needs_remove_privs(file_mnt_idmap(file), dentry);
	if (kill < 0)
		return kill;

	if (kill) {
		if (flags & IOCB_NOWAIT)
			return -EAGAIN;

		error = __remove_privs(file_mnt_idmap(file), dentry, kill);
	}

	if (!error)
		inode_has_no_xattr(inode);
	return error;
}

int file_remove_privs(struct file *file)
{
	return file_remove_privs_flags(file, 0);
}

int dentry_needs_remove_privs(struct mnt_idmap *idmap,
			      struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	int mask = 0;
	int ret;

	if (IS_NOSEC(inode))
		return 0;

	mask = setattr_should_drop_suidgid(idmap, inode);
	ret = security_inode_need_killpriv(dentry);
	if (ret < 0)
		return ret;
	if (ret)
		mask |= ATTR_KILL_PRIV;
	return mask;
}
