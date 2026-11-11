/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10.14 mm/truncate.c definitions. */

static void truncate_cleanup_folio(struct folio *folio)
{
	if (folio_mapped(folio))
		unmap_mapping_folio(folio);

	if (folio_needs_release(folio))
		folio_invalidate(folio, 0, folio_size(folio));

	/*
	 * Some filesystems seem to re-dirty the page even after
	 * the VM has canceled the dirty bit (eg ext3 journaling).
	 * Hence dirty accounting check is placed after invalidation.
	 */
	folio_cancel_dirty(folio);
	folio_clear_mappedtodisk(folio);
}

int truncate_inode_folio(struct address_space *mapping, struct folio *folio)
{
	if (folio->mapping != mapping)
		return -EIO;

	truncate_cleanup_folio(folio);
	filemap_remove_folio(folio);
	return 0;
}

bool truncate_inode_partial_folio(struct folio *folio, loff_t start, loff_t end)
{
	loff_t pos = folio_pos(folio);
	unsigned int offset, length;

	if (pos < start)
		offset = start - pos;
	else
		offset = 0;
	length = folio_size(folio);
	if (pos + length <= (u64)end)
		length = length - offset;
	else
		length = end + 1 - pos - offset;

	folio_wait_writeback(folio);
	if (length == folio_size(folio)) {
		truncate_inode_folio(folio->mapping, folio);
		return true;
	}

	/*
	 * We may be zeroing pages we're about to discard, but it avoids
	 * doing a complex calculation here, and then doing the zeroing
	 * anyway if the page split fails.
	 */
	folio_zero_range(folio, offset, length);

	if (folio_needs_release(folio))
		folio_invalidate(folio, offset, length);
	if (!folio_test_large(folio))
		return true;
	if (split_folio(folio) == 0)
		return true;
	if (folio_test_dirty(folio))
		return false;
	truncate_inode_folio(folio->mapping, folio);
	return true;
}
