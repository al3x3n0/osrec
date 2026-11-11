/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 mm/shmem.c definitions. */

bool shmem_mapping(struct address_space *mapping)
{
	return mapping->a_ops == &shmem_aops;
}

static int shmem_get_folio_gfp(struct inode *inode, pgoff_t index,
		struct folio **foliop, enum sgp_type sgp, gfp_t gfp,
		struct vm_fault *vmf, vm_fault_t *fault_type)
{
	struct vm_area_struct *vma = vmf ? vmf->vma : NULL;
	struct mm_struct *fault_mm;
	struct folio *folio;
	int error;
	bool alloced;

	if (WARN_ON_ONCE(!shmem_mapping(inode->i_mapping)))
		return -EINVAL;

	if (index > (MAX_LFS_FILESIZE >> PAGE_SHIFT))
		return -EFBIG;
repeat:
	if (sgp <= SGP_CACHE &&
	    ((loff_t)index << PAGE_SHIFT) >= i_size_read(inode))
		return -EINVAL;

	alloced = false;
	fault_mm = vma ? vma->vm_mm : NULL;

	folio = filemap_get_entry(inode->i_mapping, index);
	if (folio && vma && userfaultfd_minor(vma)) {
		if (!xa_is_value(folio))
			folio_put(folio);
		*fault_type = handle_userfault(vmf, VM_UFFD_MINOR);
		return 0;
	}

	if (xa_is_value(folio)) {
		error = shmem_swapin_folio(inode, index, &folio,
					   sgp, gfp, fault_mm, fault_type);
		if (error == -EEXIST)
			goto repeat;

		*foliop = folio;
		return error;
	}

	if (folio) {
		folio_lock(folio);

		/* Has the folio been truncated or swapped out? */
		if (unlikely(folio->mapping != inode->i_mapping)) {
			folio_unlock(folio);
			folio_put(folio);
			goto repeat;
		}
		if (sgp == SGP_WRITE)
			folio_mark_accessed(folio);
		if (folio_test_uptodate(folio))
			goto out;
		/* fallocated folio */
		if (sgp != SGP_READ)
			goto clear;
		folio_unlock(folio);
		folio_put(folio);
	}

	/*
	 * SGP_READ: succeed on hole, with NULL folio, letting caller zero.
	 * SGP_NOALLOC: fail on hole, with NULL folio, letting caller fail.
	 */
	*foliop = NULL;
	if (sgp == SGP_READ)
		return 0;
	if (sgp == SGP_NOALLOC)
		return -ENOENT;

	/*
	 * Fast cache lookup and swap lookup did not find it: allocate.
	 */

	if (vma && userfaultfd_missing(vma)) {
		*fault_type = handle_userfault(vmf, VM_UFFD_MISSING);
		return 0;
	}

	if (shmem_is_huge(inode, index, false, fault_mm,
			  vma ? vma->vm_flags : 0)) {
		gfp_t huge_gfp;

		huge_gfp = vma_thp_gfp_mask(vma);
		huge_gfp = limit_gfp_mask(huge_gfp, gfp);
		folio = shmem_alloc_and_add_folio(huge_gfp,
				inode, index, fault_mm, true);
		if (!IS_ERR(folio)) {
			count_vm_event(THP_FILE_ALLOC);
			goto alloced;
		}
		if (PTR_ERR(folio) == -EEXIST)
			goto repeat;
	}

	folio = shmem_alloc_and_add_folio(gfp, inode, index, fault_mm, false);
	if (IS_ERR(folio)) {
		error = PTR_ERR(folio);
		if (error == -EEXIST)
			goto repeat;
		folio = NULL;
		goto unlock;
	}

alloced:
	alloced = true;
	if (folio_test_pmd_mappable(folio) &&
	    DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE) <
					folio_next_index(folio) - 1) {
		struct shmem_sb_info *sbinfo = SHMEM_SB(inode->i_sb);
		struct shmem_inode_info *info = SHMEM_I(inode);
		/*
		 * Part of the large folio is beyond i_size: subject
		 * to shrink under memory pressure.
		 */
		spin_lock(&sbinfo->shrinklist_lock);
		/*
		 * _careful to defend against unlocked access to
		 * ->shrink_list in shmem_unused_huge_shrink()
		 */
		if (list_empty_careful(&info->shrinklist)) {
			list_add_tail(&info->shrinklist,
				      &sbinfo->shrinklist);
			sbinfo->shrinklist_len++;
		}
		spin_unlock(&sbinfo->shrinklist_lock);
	}

	if (sgp == SGP_WRITE)
		folio_set_referenced(folio);
	/*
	 * Let SGP_FALLOC use the SGP_WRITE optimization on a new folio.
	 */
	if (sgp == SGP_FALLOC)
		sgp = SGP_WRITE;
clear:
	/*
	 * Let SGP_WRITE caller clear ends if write does not fill folio;
	 * but SGP_FALLOC on a folio fallocated earlier must initialize
	 * it now, lest undo on failure cancel our earlier guarantee.
	 */
	if (sgp != SGP_WRITE && !folio_test_uptodate(folio)) {
		long i, n = folio_nr_pages(folio);

		for (i = 0; i < n; i++)
			clear_highpage(folio_page(folio, i));
		flush_dcache_folio(folio);
		folio_mark_uptodate(folio);
	}

	/* Perhaps the file has been truncated since we checked */
	if (sgp <= SGP_CACHE &&
	    ((loff_t)index << PAGE_SHIFT) >= i_size_read(inode)) {
		error = -EINVAL;
		goto unlock;
	}
out:
	*foliop = folio;
	return 0;

	/*
	 * Error recovery.
	 */
unlock:
	if (alloced)
		filemap_remove_folio(folio);
	shmem_recalc_inode(inode, 0, 0);
	if (folio) {
		folio_unlock(folio);
		folio_put(folio);
	}
	return error;
}

int shmem_get_folio(struct inode *inode, pgoff_t index, struct folio **foliop,
		enum sgp_type sgp)
{
	return shmem_get_folio_gfp(inode, index, foliop, sgp,
			mapping_gfp_mask(inode->i_mapping), NULL, NULL);
}

static ssize_t shmem_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct address_space *mapping = inode->i_mapping;
	pgoff_t index;
	unsigned long offset;
	int error = 0;
	ssize_t retval = 0;
	loff_t *ppos = &iocb->ki_pos;

	index = *ppos >> PAGE_SHIFT;
	offset = *ppos & ~PAGE_MASK;

	for (;;) {
		struct folio *folio = NULL;
		struct page *page = NULL;
		pgoff_t end_index;
		unsigned long nr, ret;
		loff_t i_size = i_size_read(inode);

		end_index = i_size >> PAGE_SHIFT;
		if (index > end_index)
			break;
		if (index == end_index) {
			nr = i_size & ~PAGE_MASK;
			if (nr <= offset)
				break;
		}

		error = shmem_get_folio(inode, index, &folio, SGP_READ);
		if (error) {
			if (error == -EINVAL)
				error = 0;
			break;
		}
		if (folio) {
			folio_unlock(folio);

			page = folio_file_page(folio, index);
			if (PageHWPoison(page)) {
				folio_put(folio);
				error = -EIO;
				break;
			}
		}

		/*
		 * We must evaluate after, since reads (unlike writes)
		 * are called without i_rwsem protection against truncate
		 */
		nr = PAGE_SIZE;
		i_size = i_size_read(inode);
		end_index = i_size >> PAGE_SHIFT;
		if (index == end_index) {
			nr = i_size & ~PAGE_MASK;
			if (nr <= offset) {
				if (folio)
					folio_put(folio);
				break;
			}
		}
		nr -= offset;

		if (folio) {
			/*
			 * If users can be writing to this page using arbitrary
			 * virtual addresses, take care about potential aliasing
			 * before reading the page on the kernel side.
			 */
			if (mapping_writably_mapped(mapping))
				flush_dcache_page(page);
			/*
			 * Mark the page accessed if we read the beginning.
			 */
			if (!offset)
				folio_mark_accessed(folio);
			/*
			 * Ok, we have the page, and it's up-to-date, so
			 * now we can copy it to user space...
			 */
			ret = copy_page_to_iter(page, offset, nr, to);
			folio_put(folio);

		} else if (user_backed_iter(to)) {
			/*
			 * Copy to user tends to be so well optimized, but
			 * clear_user() not so much, that it is noticeably
			 * faster to copy the zero page instead of clearing.
			 */
			ret = copy_page_to_iter(ZERO_PAGE(0), offset, nr, to);
		} else {
			/*
			 * But submitting the same page twice in a row to
			 * splice() - or others? - can result in confusion:
			 * so don't attempt that optimization on pipes etc.
			 */
			ret = iov_iter_zero(nr, to);
		}

		retval += ret;
		offset += ret;
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;

		if (!iov_iter_count(to))
			break;
		if (ret < nr) {
			error = -EFAULT;
			break;
		}
		cond_resched();
	}

	*ppos = ((loff_t) index << PAGE_SHIFT) + offset;
	file_accessed(file);
	return retval ? retval : error;
}

static ssize_t shmem_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto unlock;
	ret = file_remove_privs(file);
	if (ret)
		goto unlock;
	ret = file_update_time(file);
	if (ret)
		goto unlock;
	ret = generic_perform_write(iocb, from);
unlock:
	inode_unlock(inode);
	return ret;
}

static int
shmem_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len,
			struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct shmem_inode_info *info = SHMEM_I(inode);
	pgoff_t index = pos >> PAGE_SHIFT;
	struct folio *folio;
	int ret = 0;

	/* i_rwsem is held by caller */
	if (unlikely(info->seals & (F_SEAL_GROW |
				   F_SEAL_WRITE | F_SEAL_FUTURE_WRITE))) {
		if (info->seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE))
			return -EPERM;
		if ((info->seals & F_SEAL_GROW) && pos + len > inode->i_size)
			return -EPERM;
	}

	ret = shmem_get_folio(inode, index, &folio, SGP_WRITE);
	if (ret)
		return ret;

	*pagep = folio_file_page(folio, index);
	if (PageHWPoison(*pagep)) {
		folio_unlock(folio);
		folio_put(folio);
		*pagep = NULL;
		return -EIO;
	}

	return 0;
}

static int
shmem_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	struct folio *folio = page_folio(page);
	struct inode *inode = mapping->host;

	if (pos + copied > inode->i_size)
		i_size_write(inode, pos + copied);

	if (!folio_test_uptodate(folio)) {
		if (copied < folio_size(folio)) {
			size_t from = offset_in_folio(folio, pos);
			folio_zero_segments(folio, 0, from,
					from + copied, folio_size(folio));
		}
		folio_mark_uptodate(folio);
	}
	folio_mark_dirty(folio);
	folio_unlock(folio);
	folio_put(folio);

	return copied;
}

static inline int shmem_reacct_size(unsigned long flags,
		loff_t oldsize, loff_t newsize)
{
	if (!(flags & VM_NORESERVE)) {
		if (VM_ACCT(newsize) > VM_ACCT(oldsize))
			return security_vm_enough_memory_mm(current->mm,
					VM_ACCT(newsize) - VM_ACCT(oldsize));
		else if (VM_ACCT(newsize) < VM_ACCT(oldsize))
			vm_unacct_memory(VM_ACCT(oldsize) - VM_ACCT(newsize));
	}
	return 0;
}

static void shmem_recalc_inode(struct inode *inode, long alloced, long swapped)
{
	struct shmem_inode_info *info = SHMEM_I(inode);
	long freed;

	spin_lock(&info->lock);
	info->alloced += alloced;
	info->swapped += swapped;
	freed = info->alloced - info->swapped -
		READ_ONCE(inode->i_mapping->nrpages);
	/*
	 * Special case: whereas normally shmem_recalc_inode() is called
	 * after i_mapping->nrpages has already been adjusted (up or down),
	 * shmem_writepage() has to raise swapped before nrpages is lowered -
	 * to stop a racing shmem_recalc_inode() from thinking that a page has
	 * been freed.  Compensate here, to avoid the need for a followup call.
	 */
	if (swapped > 0)
		freed += swapped;
	if (freed > 0)
		info->alloced -= freed;
	spin_unlock(&info->lock);

	/* The quota case may block */
	if (freed > 0)
		shmem_inode_unacct_blocks(inode, freed);
}

static struct folio *shmem_get_partial_folio(struct inode *inode, pgoff_t index)
{
	struct folio *folio;

	/*
	 * At first avoid shmem_get_folio(,,,SGP_READ): that fails
	 * beyond i_size, and reports fallocated folios as holes.
	 */
	folio = filemap_get_entry(inode->i_mapping, index);
	if (!folio)
		return folio;
	if (!xa_is_value(folio)) {
		folio_lock(folio);
		if (folio->mapping == inode->i_mapping)
			return folio;
		/* The folio has been swapped out */
		folio_unlock(folio);
		folio_put(folio);
	}
	/*
	 * But read a folio back from swap if any of it is within i_size
	 * (although in some cases this is just a waste of time).
	 */
	folio = NULL;
	shmem_get_folio(inode, index, &folio, SGP_READ);
	return folio;
}

static void shmem_undo_range(struct inode *inode, loff_t lstart, loff_t lend,
								 bool unfalloc)
{
	struct address_space *mapping = inode->i_mapping;
	struct shmem_inode_info *info = SHMEM_I(inode);
	pgoff_t start = (lstart + PAGE_SIZE - 1) >> PAGE_SHIFT;
	pgoff_t end = (lend + 1) >> PAGE_SHIFT;
	struct folio_batch fbatch;
	pgoff_t indices[PAGEVEC_SIZE];
	struct folio *folio;
	bool same_folio;
	long nr_swaps_freed = 0;
	pgoff_t index;
	int i;

	if (lend == -1)
		end = -1;	/* unsigned, so actually very big */

	if (info->fallocend > start && info->fallocend <= end && !unfalloc)
		info->fallocend = start;

	folio_batch_init(&fbatch);
	index = start;
	while (index < end && find_lock_entries(mapping, &index, end - 1,
			&fbatch, indices)) {
		for (i = 0; i < folio_batch_count(&fbatch); i++) {
			folio = fbatch.folios[i];

			if (xa_is_value(folio)) {
				if (unfalloc)
					continue;
				nr_swaps_freed += !shmem_free_swap(mapping,
							indices[i], folio);
				continue;
			}

			if (!unfalloc || !folio_test_uptodate(folio))
				truncate_inode_folio(mapping, folio);
			folio_unlock(folio);
		}
		folio_batch_remove_exceptionals(&fbatch);
		folio_batch_release(&fbatch);
		cond_resched();
	}

	/*
	 * When undoing a failed fallocate, we want none of the partial folio
	 * zeroing and splitting below, but shall want to truncate the whole
	 * folio when !uptodate indicates that it was added by this fallocate,
	 * even when [lstart, lend] covers only a part of the folio.
	 */
	if (unfalloc)
		goto whole_folios;

	same_folio = (lstart >> PAGE_SHIFT) == (lend >> PAGE_SHIFT);
	folio = shmem_get_partial_folio(inode, lstart >> PAGE_SHIFT);
	if (folio) {
		same_folio = lend < folio_pos(folio) + folio_size(folio);
		folio_mark_dirty(folio);
		if (!truncate_inode_partial_folio(folio, lstart, lend)) {
			start = folio_next_index(folio);
			if (same_folio)
				end = folio->index;
		}
		folio_unlock(folio);
		folio_put(folio);
		folio = NULL;
	}

	if (!same_folio)
		folio = shmem_get_partial_folio(inode, lend >> PAGE_SHIFT);
	if (folio) {
		folio_mark_dirty(folio);
		if (!truncate_inode_partial_folio(folio, lstart, lend))
			end = folio->index;
		folio_unlock(folio);
		folio_put(folio);
	}

whole_folios:

	index = start;
	while (index < end) {
		cond_resched();

		if (!find_get_entries(mapping, &index, end - 1, &fbatch,
				indices)) {
			/* If all gone or hole-punch or unfalloc, we're done */
			if (index == start || end != -1)
				break;
			/* But if truncating, restart to make sure all gone */
			index = start;
			continue;
		}
		for (i = 0; i < folio_batch_count(&fbatch); i++) {
			folio = fbatch.folios[i];

			if (xa_is_value(folio)) {
				if (unfalloc)
					continue;
				if (shmem_free_swap(mapping, indices[i], folio)) {
					/* Swap was replaced by page: retry */
					index = indices[i];
					break;
				}
				nr_swaps_freed++;
				continue;
			}

			folio_lock(folio);

			if (!unfalloc || !folio_test_uptodate(folio)) {
				if (folio_mapping(folio) != mapping) {
					/* Page was replaced by swap: retry */
					folio_unlock(folio);
					index = indices[i];
					break;
				}
				VM_BUG_ON_FOLIO(folio_test_writeback(folio),
						folio);

				if (!folio_test_large(folio)) {
					truncate_inode_folio(mapping, folio);
				} else if (truncate_inode_partial_folio(folio, lstart, lend)) {
					/*
					 * If we split a page, reset the loop so
					 * that we pick up the new sub pages.
					 * Otherwise the THP was entirely
					 * dropped or the target range was
					 * zeroed, so just continue the loop as
					 * is.
					 */
					if (!folio_test_large(folio)) {
						folio_unlock(folio);
						index = start;
						break;
					}
				}
			}
			folio_unlock(folio);
		}
		folio_batch_remove_exceptionals(&fbatch);
		folio_batch_release(&fbatch);
	}

	shmem_recalc_inode(inode, 0, -nr_swaps_freed);
}

void shmem_truncate_range(struct inode *inode, loff_t lstart, loff_t lend)
{
	shmem_undo_range(inode, lstart, lend, false);
	inode_set_mtime_to_ts(inode, inode_set_ctime_current(inode));
	inode_inc_iversion(inode);
}

static int shmem_setattr(struct mnt_idmap *idmap,
			 struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	struct shmem_inode_info *info = SHMEM_I(inode);
	int error;
	bool update_mtime = false;
	bool update_ctime = true;

	error = setattr_prepare(idmap, dentry, attr);
	if (error)
		return error;

	if ((info->seals & F_SEAL_EXEC) && (attr->ia_valid & ATTR_MODE)) {
		if ((inode->i_mode ^ attr->ia_mode) & 0111) {
			return -EPERM;
		}
	}

	if (S_ISREG(inode->i_mode) && (attr->ia_valid & ATTR_SIZE)) {
		loff_t oldsize = inode->i_size;
		loff_t newsize = attr->ia_size;

		/* protected by i_rwsem */
		if ((newsize < oldsize && (info->seals & F_SEAL_SHRINK)) ||
		    (newsize > oldsize && (info->seals & F_SEAL_GROW)))
			return -EPERM;

		if (newsize != oldsize) {
			error = shmem_reacct_size(SHMEM_I(inode)->flags,
					oldsize, newsize);
			if (error)
				return error;
			i_size_write(inode, newsize);
			update_mtime = true;
		} else {
			update_ctime = false;
		}
		if (newsize <= oldsize) {
			loff_t holebegin = round_up(newsize, PAGE_SIZE);
			if (oldsize > holebegin)
				unmap_mapping_range(inode->i_mapping,
							holebegin, 0, 1);
			if (info->alloced)
				shmem_truncate_range(inode,
							newsize, (loff_t)-1);
			/* unmap again to remove racily COWed private pages */
			if (oldsize > holebegin)
				unmap_mapping_range(inode->i_mapping,
							holebegin, 0, 1);
		}
	}

	if (is_quota_modification(idmap, inode, attr)) {
		error = dquot_initialize(inode);
		if (error)
			return error;
	}

	/* Transfer quota accounting */
	if (i_uid_needs_update(idmap, attr, inode) ||
	    i_gid_needs_update(idmap, attr, inode)) {
		error = dquot_transfer(idmap, inode, attr);
		if (error)
			return error;
	}

	setattr_copy(idmap, inode, attr);
	if (attr->ia_valid & ATTR_MODE)
		error = posix_acl_chmod(idmap, dentry, inode->i_mode);
	if (!error && update_ctime) {
		inode_set_ctime_current(inode);
		if (update_mtime)
			inode_set_mtime_to_ts(inode, inode_get_ctime(inode));
		inode_inc_iversion(inode);
	}
	return error;
}
