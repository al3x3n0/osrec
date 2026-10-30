/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 include/linux/list.h definitions. */

static inline int hlist_unhashed(const struct hlist_node *h)
{
	return !h->pprev;
}

static inline int list_empty(const struct list_head *head)
{
	return READ_ONCE(head->next) == head;
}
