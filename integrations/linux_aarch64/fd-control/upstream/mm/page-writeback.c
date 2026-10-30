/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10 mm/page-writeback.c definitions. */

int balance_dirty_pages_ratelimited_flags(struct address_space *mapping,
					unsigned int flags)
{
	struct inode *inode = mapping->host;
	struct backing_dev_info *bdi = inode_to_bdi(inode);
	struct bdi_writeback *wb = NULL;
	int ratelimit;
	int ret = 0;
	int *p;

	if (!(bdi->capabilities & BDI_CAP_WRITEBACK))
		return ret;

	if (inode_cgwb_enabled(inode))
		wb = wb_get_create_current(bdi, GFP_KERNEL);
	if (!wb)
		wb = &bdi->wb;

	ratelimit = current->nr_dirtied_pause;
	if (wb->dirty_exceeded)
		ratelimit = min(ratelimit, 32 >> (PAGE_SHIFT - 10));

	preempt_disable();
	/*
	 * This prevents one CPU to accumulate too many dirtied pages without
	 * calling into balance_dirty_pages(), which can happen when there are
	 * 1000+ tasks, all of them start dirtying pages at exactly the same
	 * time, hence all honoured too large initial task->nr_dirtied_pause.
	 */
	p =  this_cpu_ptr(&bdp_ratelimits);
	if (unlikely(current->nr_dirtied >= ratelimit))
		*p = 0;
	else if (unlikely(*p >= ratelimit_pages)) {
		*p = 0;
		ratelimit = 0;
	}
	/*
	 * Pick up the dirtied pages by the exited tasks. This avoids lots of
	 * short-lived tasks (eg. gcc invocations in a kernel build) escaping
	 * the dirty throttling and livelock other long-run dirtiers.
	 */
	p = this_cpu_ptr(&dirty_throttle_leaks);
	if (*p > 0 && current->nr_dirtied < ratelimit) {
		unsigned long nr_pages_dirtied;
		nr_pages_dirtied = min(*p, ratelimit - current->nr_dirtied);
		*p -= nr_pages_dirtied;
		current->nr_dirtied += nr_pages_dirtied;
	}
	preempt_enable();

	if (unlikely(current->nr_dirtied >= ratelimit))
		ret = balance_dirty_pages(wb, current->nr_dirtied, flags);

	wb_put(wb);
	return ret;
}

void balance_dirty_pages_ratelimited(struct address_space *mapping)
{
	balance_dirty_pages_ratelimited_flags(mapping, 0);
}

bool noop_dirty_folio(struct address_space *mapping, struct folio *folio)
{
	if (!folio_test_dirty(folio))
		return !folio_test_set_dirty(folio);
	return false;
}

bool folio_mark_dirty(struct folio *folio)
{
	struct address_space *mapping = folio_mapping(folio);

	if (likely(mapping)) {
		/*
		 * readahead/folio_deactivate could remain
		 * PG_readahead/PG_reclaim due to race with folio_end_writeback
		 * About readahead, if the folio is written, the flags would be
		 * reset. So no problem.
		 * About folio_deactivate, if the folio is redirtied,
		 * the flag will be reset. So no problem. but if the
		 * folio is used by readahead it will confuse readahead
		 * and make it restart the size rampup process. But it's
		 * a trivial problem.
		 */
		if (folio_test_reclaim(folio))
			folio_clear_reclaim(folio);
		return mapping->a_ops->dirty_folio(mapping, folio);
	}

	return noop_dirty_folio(mapping, folio);
}

void folio_wait_writeback(struct folio *folio)
{
	while (folio_test_writeback(folio)) {
		trace_folio_wait_writeback(folio, folio_mapping(folio));
		folio_wait_bit(folio, PG_writeback);
	}
}
