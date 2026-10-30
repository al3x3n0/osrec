/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 include/linux/fs.h definitions. */

static inline void init_sync_kiocb(struct kiocb *kiocb, struct file *filp)
{
	*kiocb = (struct kiocb) {
		.ki_filp = filp,
		.ki_flags = filp->f_iocb_flags,
		.ki_ioprio = get_current_ioprio(),
	};
}

static inline void file_start_write(struct file *file)
{
	if (!S_ISREG(file_inode(file)->i_mode))
		return;
	sb_start_write(file_inode(file)->i_sb);
}

static inline void file_end_write(struct file *file)
{
	if (!S_ISREG(file_inode(file)->i_mode))
		return;
	sb_end_write(file_inode(file)->i_sb);
}

static inline loff_t i_size_read(const struct inode *inode)
{
#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
	loff_t i_size;
	unsigned int seq;

	do {
		seq = read_seqcount_begin(&inode->i_size_seqcount);
		i_size = inode->i_size;
	} while (read_seqcount_retry(&inode->i_size_seqcount, seq));
	return i_size;
#elif BITS_PER_LONG==32 && defined(CONFIG_PREEMPTION)
	loff_t i_size;

	preempt_disable();
	i_size = inode->i_size;
	preempt_enable();
	return i_size;
#else
	/* Pairs with smp_store_release() in i_size_write() */
	return smp_load_acquire(&inode->i_size);
#endif
}

static inline void file_accessed(struct file *file)
{
	if (!(file->f_flags & O_NOATIME))
		touch_atime(&file->f_path);
}

static inline int mapping_writably_mapped(struct address_space *mapping)
{
	return atomic_read(&mapping->i_mmap_writable) > 0;
}

static inline struct timespec64 inode_get_atime(const struct inode *inode)
{
	return inode->__i_atime;
}

static inline struct timespec64 inode_get_mtime(const struct inode *inode)
{
	return inode->__i_mtime;
}

static inline struct timespec64 inode_get_ctime(const struct inode *inode)
{
	return inode->__i_ctime;
}

static inline struct timespec64 inode_set_atime_to_ts(struct inode *inode,
						      struct timespec64 ts)
{
	inode->__i_atime = ts;
	return ts;
}

static inline struct timespec64 inode_set_mtime_to_ts(struct inode *inode,
						      struct timespec64 ts)
{
	inode->__i_mtime = ts;
	return ts;
}

static inline struct timespec64 inode_set_ctime_to_ts(struct inode *inode,
						      struct timespec64 ts)
{
	inode->__i_ctime = ts;
	return ts;
}

static inline struct user_namespace *i_user_ns(const struct inode *inode)
{
	return inode->i_sb->s_user_ns;
}

static inline vfsuid_t i_uid_into_vfsuid(struct mnt_idmap *idmap,
					 const struct inode *inode)
{
	return make_vfsuid(idmap, i_user_ns(inode), inode->i_uid);
}

static inline vfsgid_t i_gid_into_vfsgid(struct mnt_idmap *idmap,
					 const struct inode *inode)
{
	return make_vfsgid(idmap, i_user_ns(inode), inode->i_gid);
}

static inline bool HAS_UNMAPPED_ID(struct mnt_idmap *idmap,
				   struct inode *inode)
{
	return !vfsuid_valid(i_uid_into_vfsuid(idmap, inode)) ||
	       !vfsgid_valid(i_gid_into_vfsgid(idmap, inode));
}

static inline int inode_unhashed(struct inode *inode)
{
	return hlist_unhashed(&inode->i_hash);
}

static inline void i_size_write(struct inode *inode, loff_t i_size)
{
#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
	preempt_disable();
	write_seqcount_begin(&inode->i_size_seqcount);
	inode->i_size = i_size;
	write_seqcount_end(&inode->i_size_seqcount);
	preempt_enable();
#elif BITS_PER_LONG==32 && defined(CONFIG_PREEMPTION)
	preempt_disable();
	inode->i_size = i_size;
	preempt_enable();
#else
	/*
	 * Pairs with smp_load_acquire() in i_size_read() to ensure
	 * changes related to inode size (such as page contents) are
	 * visible before we see the changed inode size.
	 */
	smp_store_release(&inode->i_size, i_size);
#endif
}

static inline struct dentry *file_dentry(const struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;

	WARN_ON_ONCE(d_inode(dentry) != file_inode(file));
	return dentry;
}

static inline void inode_lock(struct inode *inode)
{
	down_write(&inode->i_rwsem);
}

static inline void inode_unlock(struct inode *inode)
{
	up_write(&inode->i_rwsem);
}

static inline struct mnt_idmap *file_mnt_idmap(const struct file *file)
{
	return mnt_idmap(file->f_path.mnt);
}

static inline bool i_uid_needs_update(struct mnt_idmap *idmap,
				      const struct iattr *attr,
				      const struct inode *inode)
{
	return ((attr->ia_valid & ATTR_UID) &&
		!vfsuid_eq(attr->ia_vfsuid,
			   i_uid_into_vfsuid(idmap, inode)));
}

static inline bool i_gid_needs_update(struct mnt_idmap *idmap,
				      const struct iattr *attr,
				      const struct inode *inode)
{
	return ((attr->ia_valid & ATTR_GID) &&
		!vfsgid_eq(attr->ia_vfsgid,
			   i_gid_into_vfsgid(idmap, inode)));
}

static inline void i_uid_update(struct mnt_idmap *idmap,
				const struct iattr *attr,
				struct inode *inode)
{
	if (attr->ia_valid & ATTR_UID)
		inode->i_uid = from_vfsuid(idmap, i_user_ns(inode),
					   attr->ia_vfsuid);
}

static inline void i_gid_update(struct mnt_idmap *idmap,
				const struct iattr *attr,
				struct inode *inode)
{
	if (attr->ia_valid & ATTR_GID)
		inode->i_gid = from_vfsgid(idmap, i_user_ns(inode),
					   attr->ia_vfsgid);
}

static inline int inode_is_locked(struct inode *inode)
{
	return rwsem_is_locked(&inode->i_rwsem);
}
