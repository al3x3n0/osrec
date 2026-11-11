// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 1998-1999, Stephen Tweedie and Bill Hawes.
 * Reviewed original Linux v6.10 fs/file.c definitions. */
static unsigned int find_next_fd(struct fdtable *fdt, unsigned int start)
{
	unsigned int maxfd = fdt->max_fds; /* always multiple of BITS_PER_LONG */
	unsigned int maxbit = maxfd / BITS_PER_LONG;
	unsigned int bitbit = start / BITS_PER_LONG;

	bitbit = find_next_zero_bit(fdt->full_fds_bits, maxbit, bitbit) * BITS_PER_LONG;
	if (bitbit >= maxfd)
		return maxfd;
	if (bitbit > start)
		start = bitbit;
	return find_next_zero_bit(fdt->open_fds, maxfd, start);
}

static int alloc_fd(unsigned start, unsigned end, unsigned flags)
{
	struct files_struct *files = current->files;
	unsigned int fd;
	int error;
	struct fdtable *fdt;

	spin_lock(&files->file_lock);
repeat:
	fdt = files_fdtable(files);
	fd = start;
	if (fd < files->next_fd)
		fd = files->next_fd;

	if (fd < fdt->max_fds)
		fd = find_next_fd(fdt, fd);
	/*
	 * N.B. For clone tasks sharing a files structure, this test
	 * will limit the total number of files that can be opened.
	 */
	error = -EMFILE;
	if (fd >= end)
		goto out;

	error = expand_files(files, fd);
	if (error < 0)
		goto out;

	/*
	 * If we needed to expand the fs array we
	 * might have blocked - try again.
	 */
	if (error)
		goto repeat;

	if (start <= files->next_fd)
		files->next_fd = fd + 1;
	__set_open_fd(fd, fdt);
	if (flags & O_CLOEXEC)
		__set_close_on_exec(fd, fdt);
	else
		__clear_close_on_exec(fd, fdt);
	error = fd;
#if 1
	/* Sanity check */
	if (rcu_access_pointer(fdt->fd[fd]) != NULL) {
		printk(KERN_WARNING "alloc_fd: slot %d not NULL!\n", fd);
		rcu_assign_pointer(fdt->fd[fd], NULL);
	}
#endif

out:
	spin_unlock(&files->file_lock);
	return error;
}

int __get_unused_fd_flags(unsigned flags, unsigned long nofile)
{
	return alloc_fd(0, nofile, flags);
}
int get_unused_fd_flags(unsigned flags)
{
	return __get_unused_fd_flags(flags, rlimit(RLIMIT_NOFILE));
}

static void __put_unused_fd(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = files_fdtable(files);
	__clear_open_fd(fd, fdt);
	if (fd < files->next_fd)
		files->next_fd = fd;
}

void fd_install(unsigned int fd, struct file *file)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;

	if (WARN_ON_ONCE(unlikely(file->f_mode & FMODE_BACKING)))
		return;

	rcu_read_lock_sched();
	if (unlikely(files->resize_in_progress)) {
		rcu_read_unlock_sched();
		spin_lock(&files->file_lock);
		fdt = files_fdtable(files);
		BUG_ON(fdt->fd[fd] != NULL);
		rcu_assign_pointer(fdt->fd[fd], file);
		spin_unlock(&files->file_lock);
		return;
	}
	/* coupled with smp_wmb() in expand_fdtable() */
	smp_rmb();
	fdt = rcu_dereference_sched(files->fdt);
	BUG_ON(fdt->fd[fd] != NULL);
	rcu_assign_pointer(fdt->fd[fd], file);
	rcu_read_unlock_sched();
}

struct file *file_close_fd_locked(struct files_struct *files, unsigned fd)
{
	struct fdtable *fdt = files_fdtable(files);
	struct file *file;

	lockdep_assert_held(&files->file_lock);
	if (fd >= fdt->max_fds)
		return NULL;

	fd = array_index_nospec(fd, fdt->max_fds);
	file = fdt->fd[fd];
	if (file) {
		rcu_assign_pointer(fdt->fd[fd], NULL);
		__put_unused_fd(files, fd);
	}
	return file;
}

struct file *file_close_fd(unsigned int fd)
{
	struct files_struct *files = current->files;
	struct file *file;

	spin_lock(&files->file_lock);
	file = file_close_fd_locked(files, fd);
	spin_unlock(&files->file_lock);

	return file;
}

static inline struct file *__fget_files_rcu(struct files_struct *files,
       unsigned int fd, fmode_t mask)
{
	for (;;) {
		struct file *file;
		struct fdtable *fdt = rcu_dereference_raw(files->fdt);
		struct file __rcu **fdentry;
		unsigned long nospec_mask;
		/* Mask is a 0 for invalid fd's, ~0 for valid ones */
		nospec_mask = array_index_mask_nospec(fd, fdt->max_fds);

		/*
		 * fdentry points to the 'fd' offset, or fdt->fd[0].
		 * Loading from fdt->fd[0] is always safe, because the
		 * array always exists.
		 */
		fdentry = fdt->fd + (fd & nospec_mask);

		/* Do the load, then mask any invalid result */
		file = rcu_dereference_raw(*fdentry);
		file = (void *)(nospec_mask & (unsigned long)file);
		if (unlikely(!file))
			return NULL;
		/*
		 * Ok, we have a file pointer that was valid at
		 * some point, but it might have become stale since.
		 *
		 * We need to confirm it by incrementing the refcount
		 * and then check the lookup again.
		 *
		 * atomic_long_inc_not_zero() gives us a full memory
		 * barrier. We only really need an 'acquire' one to
		 * protect the loads below, but we don't have that.
		 */
		if (unlikely(!atomic_long_inc_not_zero(&file->f_count)))
			continue;
		/*
		 * Such a race can take two forms:
		 *
		 *  (a) the file ref already went down to zero and the
		 *      file hasn't been reused yet or the file count
		 *      isn't zero but the file has already been reused.
		 *
		 *  (b) the file table entry has changed under us.
		 *       Note that we don't need to re-check the 'fdt->fd'
		 *       pointer having changed, because it always goes
		 *       hand-in-hand with 'fdt'.
		 *
		 * If so, we need to put our ref and try again.
		 */
		if (unlikely(file != rcu_dereference_raw(*fdentry)) ||
		    unlikely(rcu_dereference_raw(files->fdt) != fdt)) {
			fput(file);
			continue;
		}
		/*
		 * This isn't the file we're looking for or we're not
		 * allowed to get a reference to it.
		 */
		if (unlikely(file->f_mode & mask)) {
			fput(file);
			return NULL;
		}

		/*
		 * Ok, we have a ref to the file, and checked that it
		 * still exists.
		 */
		return file;
	}
}

static struct file *__fget_files(struct files_struct *files, unsigned int fd,
				 fmode_t mask)
{
	struct file *file;

	rcu_read_lock();
	file = __fget_files_rcu(files, fd, mask);
	rcu_read_unlock();

	return file;
}
static inline struct file *__fget(unsigned int fd, fmode_t mask)
{
	return __fget_files(current->files, fd, mask);
}

struct file *fget_raw(unsigned int fd)
{
	return __fget(fd, 0);
}

static int do_dup2(struct files_struct *files,
	struct file *file, unsigned fd, unsigned flags)
__releases(&files->file_lock)
{
	struct file *tofree;
	struct fdtable *fdt;
	/*
	 * We need to detect attempts to do dup2() over allocated but still
	 * not finished descriptor.  NB: OpenBSD avoids that at the price of
	 * extra work in their equivalent of fget() - they insert struct
	 * file immediately after grabbing descriptor, mark it larval if
	 * more work (e.g. actual opening) is needed and make sure that
	 * fget() treats larval files as absent.  Potentially interesting,
	 * but while extra work in fget() is trivial, locking implications
	 * and amount of surgery on open()-related paths in VFS are not.
	 * FreeBSD fails with -EBADF in the same situation, NetBSD "solution"
	 * deadlocks in rather amusing ways, AFAICS.  All of that is out of
	 * scope of POSIX or SUS, since neither considers shared descriptor
	 * tables and this condition does not arise without those.
	 */
	fdt = files_fdtable(files);
	tofree = fdt->fd[fd];
	if (!tofree && fd_is_open(fd, fdt))
		goto Ebusy;
	get_file(file);
	rcu_assign_pointer(fdt->fd[fd], file);
	__set_open_fd(fd, fdt);
	if (flags & O_CLOEXEC)
		__set_close_on_exec(fd, fdt);
	else
		__clear_close_on_exec(fd, fdt);
	spin_unlock(&files->file_lock);
	if (tofree)
		filp_close(tofree, files);

	return fd;

Ebusy:
	spin_unlock(&files->file_lock);
	return -EBUSY;
}

static int ksys_dup3(unsigned int oldfd, unsigned int newfd, int flags)
{
	int err = -EBADF;
	struct file *file;
	struct files_struct *files = current->files;

	if ((flags & ~O_CLOEXEC) != 0)
		return -EINVAL;

	if (unlikely(oldfd == newfd))
		return -EINVAL;

	if (newfd >= rlimit(RLIMIT_NOFILE))
		return -EBADF;
	spin_lock(&files->file_lock);
	err = expand_files(files, newfd);
	file = files_lookup_fd_locked(files, oldfd);
	if (unlikely(!file))
		goto Ebadf;
	if (unlikely(err < 0)) {
		if (err == -EMFILE)
			goto Ebadf;
		goto out_unlock;
	}
	return do_dup2(files, file, newfd, flags);

Ebadf:
	err = -EBADF;
out_unlock:
	spin_unlock(&files->file_lock);
	return err;
}

SYSCALL_DEFINE3(dup3, unsigned int, oldfd, unsigned int, newfd, int, flags)
{
	return ksys_dup3(oldfd, newfd, flags);
}

SYSCALL_DEFINE1(dup, unsigned int, fildes)
{
	int ret = -EBADF;
	struct file *file = fget_raw(fildes);
	if (file) {
		ret = get_unused_fd_flags(0);
		if (ret >= 0)
			fd_install(ret, file);
		else
			fput(file);
	}
	return ret;
}


void set_close_on_exec(unsigned int fd, int flag)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (flag)
		__set_close_on_exec(fd, fdt);
	else
		__clear_close_on_exec(fd, fdt);
	spin_unlock(&files->file_lock);
}

bool get_close_on_exec(unsigned int fd)
{
	bool res;
	rcu_read_lock();
	res = close_on_exec(fd, current->files);
	rcu_read_unlock();
	return res;
}

int f_dupfd(unsigned int from, struct file *file, unsigned flags)
{
	unsigned long nofile = rlimit(RLIMIT_NOFILE);
	int err;
	if (from >= nofile)
		return -EINVAL;
	err = alloc_fd(from, nofile, flags);
	if (err >= 0) {
		get_file(file);
		fd_install(err, file);
	}
	return err;
}

static inline unsigned last_fd(struct fdtable *fdt)
{
	return fdt->max_fds - 1;
}

static inline void __range_cloexec(struct files_struct *cur_fds,
				   unsigned int fd, unsigned int max_fd)
{
	struct fdtable *fdt;
	/* make sure we're using the correct maximum value */
	spin_lock(&cur_fds->file_lock);
	fdt = files_fdtable(cur_fds);
	max_fd = min(last_fd(fdt), max_fd);
	if (fd <= max_fd)
		bitmap_set(fdt->close_on_exec, fd, max_fd - fd + 1);
	spin_unlock(&cur_fds->file_lock);
}

static inline void __range_close(struct files_struct *files, unsigned int fd,
				 unsigned int max_fd)
{
	struct file *file;
	unsigned n;

	spin_lock(&files->file_lock);
	n = last_fd(files_fdtable(files));
	max_fd = min(max_fd, n);
	for (; fd <= max_fd; fd++) {
		file = file_close_fd_locked(files, fd);
		if (file) {
			spin_unlock(&files->file_lock);
			filp_close(file, files);
			cond_resched();
			spin_lock(&files->file_lock);
		} else if (need_resched()) {
			spin_unlock(&files->file_lock);
			cond_resched();
			spin_lock(&files->file_lock);
		}
	}
	spin_unlock(&files->file_lock);
}

int __close_range(unsigned fd, unsigned max_fd, unsigned int flags)
{
	struct task_struct *me = current;
	struct files_struct *cur_fds = me->files, *fds = NULL;
	if (flags & ~(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC))
		return -EINVAL;

	if (fd > max_fd)
		return -EINVAL;

	if (flags & CLOSE_RANGE_UNSHARE) {
		int ret;
		unsigned int max_unshare_fds = NR_OPEN_MAX;
		/*
		 * If the caller requested all fds to be made cloexec we always
		 * copy all of the file descriptors since they still want to
		 * use them.
		 */
		if (!(flags & CLOSE_RANGE_CLOEXEC)) {
			/*
			 * If the requested range is greater than the current
			 * maximum, we're closing everything so only copy all
			 * file descriptors beneath the lowest file descriptor.
			 */
			rcu_read_lock();
			if (max_fd >= last_fd(files_fdtable(cur_fds)))
				max_unshare_fds = fd;
			rcu_read_unlock();
		}
		ret = unshare_fd(CLONE_FILES, max_unshare_fds, &fds);
		if (ret)
			return ret;

		/*
		 * We used to share our file descriptor table, and have now
		 * created a private one, make sure we're using it below.
		 */
		if (fds)
			swap(cur_fds, fds);
	}

	if (flags & CLOSE_RANGE_CLOEXEC)
		__range_cloexec(cur_fds, fd, max_fd);
	else
		__range_close(cur_fds, fd, max_fd);
	if (fds) {
		/*
		 * We're done closing the files we were supposed to. Time to install
		 * the new file descriptor table and drop the old one.
		 */
		task_lock(me);
		me->files = cur_fds;
		task_unlock(me);
		put_files_struct(fds);
	}

	return 0;
}
