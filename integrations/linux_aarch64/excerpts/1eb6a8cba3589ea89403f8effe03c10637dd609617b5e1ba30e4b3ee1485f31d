/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Reviewed original Linux v6.10 fs/notify/dnotify/dnotify.c definitions. */

void dnotify_flush(struct file *filp, fl_owner_t id)
{
	struct fsnotify_mark *fsn_mark;
	struct dnotify_mark *dn_mark;
	struct dnotify_struct *dn;
	struct dnotify_struct **prev;
	struct inode *inode;
	bool free = false;

	inode = file_inode(filp);
	if (!S_ISDIR(inode->i_mode))
		return;

	fsn_mark = fsnotify_find_inode_mark(inode, dnotify_group);
	if (!fsn_mark)
		return;
	dn_mark = container_of(fsn_mark, struct dnotify_mark, fsn_mark);

	fsnotify_group_lock(dnotify_group);

	spin_lock(&fsn_mark->lock);
	prev = &dn_mark->dn;
	while ((dn = *prev) != NULL) {
		if ((dn->dn_owner == id) && (dn->dn_filp == filp)) {
			*prev = dn->dn_next;
			kmem_cache_free(dnotify_struct_cache, dn);
			dnotify_recalc_inode_mask(fsn_mark);
			break;
		}
		prev = &dn->dn_next;
	}

	spin_unlock(&fsn_mark->lock);

	/* nothing else could have found us thanks to the dnotify_groups
	   mark_mutex */
	if (dn_mark->dn == NULL) {
		fsnotify_detach_mark(fsn_mark);
		free = true;
	}

	fsnotify_group_unlock(dnotify_group);

	if (free)
		fsnotify_free_mark(fsn_mark);
	fsnotify_put_mark(fsn_mark);
}
