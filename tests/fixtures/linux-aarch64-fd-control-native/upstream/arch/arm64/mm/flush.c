/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10 arch/arm64/mm/flush.c definitions. */

void flush_dcache_folio(struct folio *folio)
{
	if (test_bit(PG_dcache_clean, &folio->flags))
		clear_bit(PG_dcache_clean, &folio->flags);
}

void flush_dcache_page(struct page *page)
{
	flush_dcache_folio(page_folio(page));
}
