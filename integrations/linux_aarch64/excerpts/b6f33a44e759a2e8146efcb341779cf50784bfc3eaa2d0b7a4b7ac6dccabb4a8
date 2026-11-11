/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 include/linux/pagemap.h definitions. */

static inline gfp_t mapping_gfp_mask(struct address_space * mapping)
{
	return mapping->gfp_mask;
}

static inline struct page *folio_file_page(struct folio *folio, pgoff_t index)
{
	return folio_page(folio, index & (folio_nr_pages(folio) - 1));
}

static inline bool folio_trylock(struct folio *folio)
{
	return likely(!test_and_set_bit_lock(PG_locked, folio_flags(folio, 0)));
}

static inline void folio_lock(struct folio *folio)
{
	might_sleep();
	if (!folio_trylock(folio))
		__folio_lock(folio);
}

static inline pgoff_t folio_index(struct folio *folio)
{
        if (unlikely(folio_test_swapcache(folio)))
                return swapcache_index(folio);
        return folio->index;
}

static inline bool folio_contains(struct folio *folio, pgoff_t index)
{
	return index - folio_index(folio) < folio_nr_pages(folio);
}

static inline pgoff_t folio_next_index(struct folio *folio)
{
	return folio->index + folio_nr_pages(folio);
}
