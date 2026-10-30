/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10 mm/filemap.c definitions. */

void *filemap_get_entry(struct address_space *mapping, pgoff_t index)
{
	XA_STATE(xas, &mapping->i_pages, index);
	struct folio *folio;

	rcu_read_lock();
repeat:
	xas_reset(&xas);
	folio = xas_load(&xas);
	if (xas_retry(&xas, folio))
		goto repeat;
	/*
	 * A shadow entry of a recently evicted page, or a swap entry from
	 * shmem/tmpfs.  Return it without attempting to raise page count.
	 */
	if (!folio || xa_is_value(folio))
		goto out;

	if (!folio_try_get(folio))
		goto repeat;

	if (unlikely(folio != xas_reload(&xas))) {
		folio_put(folio);
		goto repeat;
	}
out:
	rcu_read_unlock();

	return folio;
}

void folio_unlock(struct folio *folio)
{
	/* Bit 7 allows x86 to check the byte's sign bit */
	BUILD_BUG_ON(PG_waiters != 7);
	BUILD_BUG_ON(PG_locked > 7);
	VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
	if (folio_xor_flags_has_waiters(folio, 1 << PG_locked))
		folio_wake_bit(folio, PG_locked);
}

ssize_t generic_perform_write(struct kiocb *iocb, struct iov_iter *i)
{
	struct file *file = iocb->ki_filp;
	loff_t pos = iocb->ki_pos;
	struct address_space *mapping = file->f_mapping;
	const struct address_space_operations *a_ops = mapping->a_ops;
	long status = 0;
	ssize_t written = 0;

	do {
		struct page *page;
		unsigned long offset;	/* Offset into pagecache page */
		unsigned long bytes;	/* Bytes to write to page */
		size_t copied;		/* Bytes copied from user */
		void *fsdata = NULL;

		offset = (pos & (PAGE_SIZE - 1));
		bytes = min_t(unsigned long, PAGE_SIZE - offset,
						iov_iter_count(i));

again:
		/*
		 * Bring in the user page that we will copy from _first_.
		 * Otherwise there's a nasty deadlock on copying from the
		 * same page as we're writing to, without it being marked
		 * up-to-date.
		 */
		if (unlikely(fault_in_iov_iter_readable(i, bytes) == bytes)) {
			status = -EFAULT;
			break;
		}

		if (fatal_signal_pending(current)) {
			status = -EINTR;
			break;
		}

		status = a_ops->write_begin(file, mapping, pos, bytes,
						&page, &fsdata);
		if (unlikely(status < 0))
			break;

		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		copied = copy_page_from_iter_atomic(page, offset, bytes, i);
		flush_dcache_page(page);

		status = a_ops->write_end(file, mapping, pos, bytes, copied,
						page, fsdata);
		if (unlikely(status != copied)) {
			iov_iter_revert(i, copied - max(status, 0L));
			if (unlikely(status < 0))
				break;
		}
		cond_resched();

		if (unlikely(status == 0)) {
			/*
			 * A short copy made ->write_end() reject the
			 * thing entirely.  Might be memory poisoning
			 * halfway through, might be a race with munmap,
			 * might be severe memory pressure.
			 */
			if (copied)
				bytes = copied;
			goto again;
		}
		pos += status;
		written += status;

		balance_dirty_pages_ratelimited(mapping);
	} while (iov_iter_count(i));

	if (!written)
		return status;
	iocb->ki_pos += written;
	return written;
}

static inline struct folio *find_get_entry(struct xa_state *xas, pgoff_t max,
		xa_mark_t mark)
{
	struct folio *folio;

retry:
	if (mark == XA_PRESENT)
		folio = xas_find(xas, max);
	else
		folio = xas_find_marked(xas, max, mark);

	if (xas_retry(xas, folio))
		goto retry;
	/*
	 * A shadow entry of a recently evicted page, a swap
	 * entry from shmem/tmpfs or a DAX entry.  Return it
	 * without attempting to raise page count.
	 */
	if (!folio || xa_is_value(folio))
		return folio;

	if (!folio_try_get(folio))
		goto reset;

	if (unlikely(folio != xas_reload(xas))) {
		folio_put(folio);
		goto reset;
	}

	return folio;
reset:
	xas_reset(xas);
	goto retry;
}

unsigned find_lock_entries(struct address_space *mapping, pgoff_t *start,
		pgoff_t end, struct folio_batch *fbatch, pgoff_t *indices)
{
	XA_STATE(xas, &mapping->i_pages, *start);
	struct folio *folio;

	rcu_read_lock();
	while ((folio = find_get_entry(&xas, end, XA_PRESENT))) {
		if (!xa_is_value(folio)) {
			if (folio->index < *start)
				goto put;
			if (folio_next_index(folio) - 1 > end)
				goto put;
			if (!folio_trylock(folio))
				goto put;
			if (folio->mapping != mapping ||
			    folio_test_writeback(folio))
				goto unlock;
			VM_BUG_ON_FOLIO(!folio_contains(folio, xas.xa_index),
					folio);
		}
		indices[fbatch->nr] = xas.xa_index;
		if (!folio_batch_add(fbatch, folio))
			break;
		continue;
unlock:
		folio_unlock(folio);
put:
		folio_put(folio);
	}
	rcu_read_unlock();

	if (folio_batch_count(fbatch)) {
		unsigned long nr = 1;
		int idx = folio_batch_count(fbatch) - 1;

		folio = fbatch->folios[idx];
		if (!xa_is_value(folio))
			nr = folio_nr_pages(folio);
		*start = indices[idx] + nr;
	}
	return folio_batch_count(fbatch);
}

unsigned find_get_entries(struct address_space *mapping, pgoff_t *start,
		pgoff_t end, struct folio_batch *fbatch, pgoff_t *indices)
{
	XA_STATE(xas, &mapping->i_pages, *start);
	struct folio *folio;

	rcu_read_lock();
	while ((folio = find_get_entry(&xas, end, XA_PRESENT)) != NULL) {
		indices[fbatch->nr] = xas.xa_index;
		if (!folio_batch_add(fbatch, folio))
			break;
	}
	rcu_read_unlock();

	if (folio_batch_count(fbatch)) {
		unsigned long nr = 1;
		int idx = folio_batch_count(fbatch) - 1;

		folio = fbatch->folios[idx];
		if (!xa_is_value(folio))
			nr = folio_nr_pages(folio);
		*start = indices[idx] + nr;
	}
	return folio_batch_count(fbatch);
}
