/* SPDX-License-Identifier: GPL-2.0+ */
/* Reviewed original Linux v6.10 include/linux/uio.h definitions. */

static inline void iov_iter_ubuf(struct iov_iter *i, unsigned int direction,
			void __user *buf, size_t count)
{
	WARN_ON(direction & ~(READ | WRITE));
	*i = (struct iov_iter) {
		.iter_type = ITER_UBUF,
		.data_source = direction,
		.ubuf = buf,
		.count = count,
		.nr_segs = 1
	};
}

static inline enum iter_type iov_iter_type(const struct iov_iter *i)
{
	return i->iter_type;
}

static inline bool iter_is_ubuf(const struct iov_iter *i)
{
	return iov_iter_type(i) == ITER_UBUF;
}

static inline bool iter_is_iovec(const struct iov_iter *i)
{
	return iov_iter_type(i) == ITER_IOVEC;
}

static inline bool user_backed_iter(const struct iov_iter *i)
{
	return iter_is_ubuf(i) || iter_is_iovec(i);
}

static inline size_t iov_iter_count(const struct iov_iter *i)
{
	return i->count;
}

static inline void iov_iter_truncate(struct iov_iter *i, u64 count)
{
	/*
	 * count doesn't have to fit in size_t - comparison extends both
	 * operands to u64 here and any value that would be truncated by
	 * conversion in assignement is by definition greater than all
	 * values of size_t, including old i->count.
	 */
	if (i->count > count)
		i->count = count;
}

static inline bool iov_iter_is_discard(const struct iov_iter *i)
{
	return iov_iter_type(i) == ITER_DISCARD;
}

static inline bool iov_iter_is_xarray(const struct iov_iter *i)
{
	return iov_iter_type(i) == ITER_XARRAY;
}

static inline bool iov_iter_is_bvec(const struct iov_iter *i)
{
	return iov_iter_type(i) == ITER_BVEC;
}

static inline const struct iovec *iter_iov(const struct iov_iter *iter)
{
	if (iter->iter_type == ITER_UBUF)
		return (const struct iovec *) &iter->__ubuf_iovec;
	return iter->__iov;
}

static inline bool iov_iter_is_kvec(const struct iov_iter *i)
{
	return iov_iter_type(i) == ITER_KVEC;
}
