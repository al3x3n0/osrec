/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10 mm/swap.c definitions. */

static void folio_inc_refs(struct folio *folio)
{
	unsigned long new_flags, old_flags = READ_ONCE(folio->flags);

	if (folio_test_unevictable(folio))
		return;

	if (!folio_test_referenced(folio)) {
		folio_set_referenced(folio);
		return;
	}

	if (!folio_test_workingset(folio)) {
		folio_set_workingset(folio);
		return;
	}

	/* see the comment on MAX_NR_TIERS */
	do {
		new_flags = old_flags & LRU_REFS_MASK;
		if (new_flags == LRU_REFS_MASK)
			break;

		new_flags += BIT(LRU_REFS_PGOFF);
		new_flags |= old_flags & ~LRU_REFS_MASK;
	} while (!try_cmpxchg(&folio->flags, &old_flags, new_flags));
}

void folio_mark_accessed(struct folio *folio)
{
	if (lru_gen_enabled()) {
		folio_inc_refs(folio);
		return;
	}

	if (!folio_test_referenced(folio)) {
		folio_set_referenced(folio);
	} else if (folio_test_unevictable(folio)) {
		/*
		 * Unevictable pages are on the "LRU_UNEVICTABLE" list. But,
		 * this list is never rotated or maintained, so marking an
		 * unevictable page accessed has no effect.
		 */
	} else if (!folio_test_active(folio)) {
		/*
		 * If the folio is on the LRU, queue it for activation via
		 * cpu_fbatches.activate. Otherwise, assume the folio is in a
		 * folio_batch, mark it active and it'll be moved to the active
		 * LRU on the next drain.
		 */
		if (folio_test_lru(folio))
			folio_activate(folio);
		else
			__lru_cache_activate_folio(folio);
		folio_clear_referenced(folio);
		workingset_activation(folio);
	}
	if (folio_test_idle(folio))
		folio_clear_idle(folio);
}

void folio_batch_remove_exceptionals(struct folio_batch *fbatch)
{
	unsigned int i, j;

	for (i = 0, j = 0; i < folio_batch_count(fbatch); i++) {
		struct folio *folio = fbatch->folios[i];
		if (!xa_is_value(folio))
			fbatch->folios[j++] = folio;
	}
	fbatch->nr = j;
}
