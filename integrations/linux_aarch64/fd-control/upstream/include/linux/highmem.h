/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 include/linux/highmem.h definitions. */

static inline void folio_zero_range(struct folio *folio,
		size_t start, size_t length)
{
	zero_user_segments(&folio->page, start, start + length, 0, 0);
}
