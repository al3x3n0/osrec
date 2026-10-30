/* SPDX-License-Identifier: GPL-2.0+ */
/* Reviewed original Linux v6.10 include/linux/xarray.h definitions. */

static inline void *xa_mk_internal(unsigned long v)
{
	return (void *)((v << 2) | 2);
}

static inline unsigned long xa_to_internal(const void *entry)
{
	return (unsigned long)entry >> 2;
}

static inline bool xa_is_internal(const void *entry)
{
	return ((unsigned long)entry & 3) == 2;
}

static inline bool xa_is_value(const void *entry)
{
	return (unsigned long)entry & 1;
}

static inline bool xa_is_zero(const void *entry)
{
	return unlikely(entry == XA_ZERO_ENTRY);
}

static inline bool xa_is_err(const void *entry)
{
	return unlikely(xa_is_internal(entry) &&
			entry >= xa_mk_internal(-MAX_ERRNO));
}

static inline int xa_err(void *entry)
{
	/* xa_to_internal() would not do sign extension. */
	if (xa_is_err(entry))
		return (long)entry >> 2;
	return 0;
}

static inline void *xa_head(const struct xarray *xa)
{
	return rcu_dereference_check(xa->xa_head,
						lockdep_is_held(&xa->xa_lock));
}

static inline void *xa_entry(const struct xarray *xa,
				const struct xa_node *node, unsigned int offset)
{
	XA_NODE_BUG_ON(node, offset >= XA_CHUNK_SIZE);
	return rcu_dereference_check(node->slots[offset],
						lockdep_is_held(&xa->xa_lock));
}

static inline bool xa_is_node(const void *entry)
{
	return xa_is_internal(entry) && (unsigned long)entry > 4096;
}

static inline struct xa_node *xa_to_node(const void *entry)
{
	return (struct xa_node *)((unsigned long)entry - 2);
}

static inline void *xa_mk_sibling(unsigned int offset)
{
	return xa_mk_internal(offset);
}

static inline bool xa_is_sibling(const void *entry)
{
	return IS_ENABLED(CONFIG_XARRAY_MULTI) && xa_is_internal(entry) &&
		(entry < xa_mk_sibling(XA_CHUNK_SIZE - 1));
}

static inline unsigned long xa_to_sibling(const void *entry)
{
	return xa_to_internal(entry);
}

static inline bool xa_is_retry(const void *entry)
{
	return unlikely(entry == XA_RETRY_ENTRY);
}

static inline int xas_error(const struct xa_state *xas)
{
	return xa_err(xas->xa_node);
}

static inline bool xas_invalid(const struct xa_state *xas)
{
	return (unsigned long)xas->xa_node & 3;
}

static inline bool xas_valid(const struct xa_state *xas)
{
	return !xas_invalid(xas);
}

static inline void xas_reset(struct xa_state *xas)
{
	xas->xa_node = XAS_RESTART;
}

static inline bool xas_retry(struct xa_state *xas, const void *entry)
{
	if (xa_is_zero(entry))
		return true;
	if (!xa_is_retry(entry))
		return false;
	xas_reset(xas);
	return true;
}

static inline void *xas_reload(struct xa_state *xas)
{
	struct xa_node *node = xas->xa_node;
	void *entry;
	char offset;

	if (!node)
		return xa_head(xas->xa);
	if (IS_ENABLED(CONFIG_XARRAY_MULTI)) {
		offset = (xas->xa_index >> node->shift) & XA_CHUNK_MASK;
		entry = xa_entry(xas->xa, node, offset);
		if (!xa_is_sibling(entry))
			return entry;
		offset = xa_to_sibling(entry);
	} else {
		offset = xas->xa_offset;
	}
	return xa_entry(xas->xa, node, offset);
}

static inline struct xa_node *xa_parent(const struct xarray *xa,
					const struct xa_node *node)
{
	return rcu_dereference_check(node->parent,
						lockdep_is_held(&xa->xa_lock));
}

static inline bool xas_not_node(struct xa_node *node)
{
	return ((unsigned long)node & 3) || !node;
}
