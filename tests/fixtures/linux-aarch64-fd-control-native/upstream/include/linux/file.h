/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 include/linux/file.h definitions. */
static inline void fdput(struct fd fd)
{
	if (fd.flags & FDPUT_FPUT)
		fput(fd.file);
}

static inline struct fd __to_fd(unsigned long v)
{
	return (struct fd){(struct file *)(v & ~3),v & 3};
}

static inline struct fd fdget(unsigned int fd)
{
	return __to_fd(__fdget(fd));
}

static inline struct fd fdget_raw(unsigned int fd)
{
	return __to_fd(__fdget_raw(fd));
}

static inline struct fd fdget_pos(int fd)
{
	return __to_fd(__fdget_pos(fd));
}

static inline void fdput_pos(struct fd f)
{
	if (f.flags & FDPUT_POS_UNLOCK)
		__f_unlock_pos(f.file);
	fdput(f);
}
