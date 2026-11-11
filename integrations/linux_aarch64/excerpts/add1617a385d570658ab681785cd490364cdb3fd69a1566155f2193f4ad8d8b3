/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Reviewed original Linux v6.10 include/linux/iov_iter.h definitions. */

static __always_inline
size_t iterate_ubuf(struct iov_iter *iter, size_t len, void *priv, void *priv2,
		    iov_ustep_f step)
{
	void __user *base = iter->ubuf;
	size_t progress = 0, remain;

	remain = step(base + iter->iov_offset, 0, len, priv, priv2);
	progress = len - remain;
	iter->iov_offset += progress;
	iter->count -= progress;
	return progress;
}

static __always_inline
size_t iterate_iovec(struct iov_iter *iter, size_t len, void *priv, void *priv2,
		     iov_ustep_f step)
{
	const struct iovec *p = iter->__iov;
	size_t progress = 0, skip = iter->iov_offset;

	do {
		size_t remain, consumed;
		size_t part = min(len, p->iov_len - skip);

		if (likely(part)) {
			remain = step(p->iov_base + skip, progress, part, priv, priv2);
			consumed = part - remain;
			progress += consumed;
			skip += consumed;
			len -= consumed;
			if (skip < p->iov_len)
				break;
		}
		p++;
		skip = 0;
	} while (len);

	iter->nr_segs -= p - iter->__iov;
	iter->__iov = p;
	iter->iov_offset = skip;
	iter->count -= progress;
	return progress;
}

static __always_inline
size_t iterate_and_advance2(struct iov_iter *iter, size_t len, void *priv,
			    void *priv2, iov_ustep_f ustep, iov_step_f step)
{
	if (unlikely(iter->count < len))
		len = iter->count;
	if (unlikely(!len))
		return 0;

	if (likely(iter_is_ubuf(iter)))
		return iterate_ubuf(iter, len, priv, priv2, ustep);
	if (likely(iter_is_iovec(iter)))
		return iterate_iovec(iter, len, priv, priv2, ustep);
	if (iov_iter_is_bvec(iter))
		return iterate_bvec(iter, len, priv, priv2, step);
	if (iov_iter_is_kvec(iter))
		return iterate_kvec(iter, len, priv, priv2, step);
	if (iov_iter_is_xarray(iter))
		return iterate_xarray(iter, len, priv, priv2, step);
	return iterate_discard(iter, len, priv, priv2, step);
}

static __always_inline
size_t iterate_and_advance(struct iov_iter *iter, size_t len, void *priv,
			   iov_ustep_f ustep, iov_step_f step)
{
	return iterate_and_advance2(iter, len, priv, NULL, ustep, step);
}
