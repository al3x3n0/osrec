/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10 lib/iov_iter.c definitions. */

static inline bool page_copy_sane(struct page *page, size_t offset, size_t n)
{
	struct page *head;
	size_t v = n + offset;

	/*
	 * The general case needs to access the page order in order
	 * to compute the page size.
	 * However, we mostly deal with order-0 pages and thus can
	 * avoid a possible cache line miss for requests that fit all
	 * page orders.
	 */
	if (n <= v && v <= PAGE_SIZE)
		return true;

	head = compound_head(page);
	v += (page - head) << PAGE_SHIFT;

	if (WARN_ON(n > v || v > page_size(head)))
		return false;
	return true;
}

size_t copy_page_to_iter(struct page *page, size_t offset, size_t bytes,
			 struct iov_iter *i)
{
	size_t res = 0;
	if (!page_copy_sane(page, offset, bytes))
		return 0;
	if (WARN_ON_ONCE(i->data_source))
		return 0;
	page += offset / PAGE_SIZE; // first subpage
	offset %= PAGE_SIZE;
	while (1) {
		void *kaddr = kmap_local_page(page);
		size_t n = min(bytes, (size_t)PAGE_SIZE - offset);
		n = _copy_to_iter(kaddr + offset, n, i);
		kunmap_local(kaddr);
		res += n;
		bytes -= n;
		if (!bytes || !n)
			break;
		offset += n;
		if (offset == PAGE_SIZE) {
			page++;
			offset = 0;
		}
	}
	return res;
}

size_t fault_in_iov_iter_readable(const struct iov_iter *i, size_t size)
{
	if (iter_is_ubuf(i)) {
		size_t n = min(size, iov_iter_count(i));
		n -= fault_in_readable(i->ubuf + i->iov_offset, n);
		return size - n;
	} else if (iter_is_iovec(i)) {
		size_t count = min(size, iov_iter_count(i));
		const struct iovec *p;
		size_t skip;

		size -= count;
		for (p = iter_iov(i), skip = i->iov_offset; count; p++, skip = 0) {
			size_t len = min(count, p->iov_len - skip);
			size_t ret;

			if (unlikely(!len))
				continue;
			ret = fault_in_readable(p->iov_base + skip, len);
			count -= len - ret;
			if (ret)
				break;
		}
		return count + size;
	}
	return 0;
}

size_t copy_page_from_iter_atomic(struct page *page, size_t offset,
		size_t bytes, struct iov_iter *i)
{
	size_t n, copied = 0;

	if (!page_copy_sane(page, offset, bytes))
		return 0;
	if (WARN_ON_ONCE(!i->data_source))
		return 0;

	do {
		char *p;

		n = bytes - copied;
		if (PageHighMem(page)) {
			page += offset / PAGE_SIZE;
			offset %= PAGE_SIZE;
			n = min_t(size_t, n, PAGE_SIZE - offset);
		}

		p = kmap_atomic(page) + offset;
		n = __copy_from_iter(p, n, i);
		kunmap_atomic(p);
		copied += n;
		offset += n;
	} while (PageHighMem(page) && copied != bytes && n > 0);

	return copied;
}

void iov_iter_revert(struct iov_iter *i, size_t unroll)
{
	if (!unroll)
		return;
	if (WARN_ON(unroll > MAX_RW_COUNT))
		return;
	i->count += unroll;
	if (unlikely(iov_iter_is_discard(i)))
		return;
	if (unroll <= i->iov_offset) {
		i->iov_offset -= unroll;
		return;
	}
	unroll -= i->iov_offset;
	if (iov_iter_is_xarray(i) || iter_is_ubuf(i)) {
		BUG(); /* We should never go beyond the start of the specified
			* range since we might then be straying into pages that
			* aren't pinned.
			*/
	} else if (iov_iter_is_bvec(i)) {
		const struct bio_vec *bvec = i->bvec;
		while (1) {
			size_t n = (--bvec)->bv_len;
			i->nr_segs++;
			if (unroll <= n) {
				i->bvec = bvec;
				i->iov_offset = n - unroll;
				return;
			}
			unroll -= n;
		}
	} else { /* same logics for iovec and kvec */
		const struct iovec *iov = iter_iov(i);
		while (1) {
			size_t n = (--iov)->iov_len;
			i->nr_segs++;
			if (unroll <= n) {
				i->__iov = iov;
				i->iov_offset = n - unroll;
				return;
			}
			unroll -= n;
		}
	}
}

static __always_inline
size_t copy_to_user_iter(void __user *iter_to, size_t progress,
			 size_t len, void *from, void *priv2)
{
	if (should_fail_usercopy())
		return len;
	if (access_ok(iter_to, len)) {
		from += progress;
		instrument_copy_to_user(iter_to, from, len);
		len = raw_copy_to_user(iter_to, from, len);
	}
	return len;
}

static __always_inline
size_t copy_from_user_iter(void __user *iter_from, size_t progress,
			   size_t len, void *to, void *priv2)
{
	size_t res = len;

	if (should_fail_usercopy())
		return len;
	if (access_ok(iter_from, len)) {
		to += progress;
		instrument_copy_from_user_before(to, iter_from, len);
		res = raw_copy_from_user(to, iter_from, len);
		instrument_copy_from_user_after(to, iter_from, len, res);
	}
	return res;
}

static __always_inline
size_t memcpy_to_iter(void *iter_to, size_t progress,
		      size_t len, void *from, void *priv2)
{
	memcpy(iter_to, from + progress, len);
	return 0;
}

static __always_inline
size_t memcpy_from_iter(void *iter_from, size_t progress,
			size_t len, void *to, void *priv2)
{
	memcpy(to + progress, iter_from, len);
	return 0;
}

size_t _copy_to_iter(const void *addr, size_t bytes, struct iov_iter *i)
{
	if (WARN_ON_ONCE(i->data_source))
		return 0;
	if (user_backed_iter(i))
		might_fault();
	return iterate_and_advance(i, bytes, (void *)addr,
				   copy_to_user_iter, memcpy_to_iter);
}

static __always_inline
size_t __copy_from_iter(void *addr, size_t bytes, struct iov_iter *i)
{
	return iterate_and_advance(i, bytes, addr,
				   copy_from_user_iter, memcpy_from_iter);
}
