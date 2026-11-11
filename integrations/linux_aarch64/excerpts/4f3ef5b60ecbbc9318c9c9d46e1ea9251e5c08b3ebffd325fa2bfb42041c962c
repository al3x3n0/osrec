/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 include/linux/fsnotify_backend.h definitions. */

static inline struct fsnotify_sb_info *fsnotify_sb_info(struct super_block *sb)
{
#ifdef CONFIG_FSNOTIFY
	return READ_ONCE(sb->s_fsnotify_info);
#else
	return NULL;
#endif
}
