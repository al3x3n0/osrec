/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10 mm/util.c definitions. */

struct address_space *folio_mapping(struct folio *folio)
{
	struct address_space *mapping;

	/* This happens if someone calls flush_dcache_page on slab page */
	if (unlikely(folio_test_slab(folio)))
		return NULL;

	if (unlikely(folio_test_swapcache(folio)))
		return swap_address_space(folio->swap);

	mapping = folio->mapping;
	if ((unsigned long)mapping & PAGE_MAPPING_FLAGS)
		return NULL;

	return mapping;
}
