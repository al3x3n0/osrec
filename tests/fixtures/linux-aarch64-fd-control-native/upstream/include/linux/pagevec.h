/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 include/linux/pagevec.h definitions. */

static inline void folio_batch_init(struct folio_batch *fbatch)
{
	fbatch->nr = 0;
	fbatch->i = 0;
	fbatch->percpu_pvec_drained = false;
}

static inline unsigned int folio_batch_count(struct folio_batch *fbatch)
{
	return fbatch->nr;
}

static inline unsigned int folio_batch_space(struct folio_batch *fbatch)
{
	return PAGEVEC_SIZE - fbatch->nr;
}

static inline unsigned folio_batch_add(struct folio_batch *fbatch,
		struct folio *folio)
{
	fbatch->folios[fbatch->nr++] = folio;
	return folio_batch_space(fbatch);
}

static inline void folio_batch_release(struct folio_batch *fbatch)
{
	if (folio_batch_count(fbatch))
		__folio_batch_release(fbatch);
}
