/* SPDX-License-Identifier: GPL-2.0-only */
/* Reviewed original Linux v6.10 kernel/user_namespace.c definitions. */

static int cmp_map_id(const void *k, const void *e)
{
	u32 first, last, id2;
	const struct idmap_key *key = k;
	const struct uid_gid_extent *el = e;

	id2 = key->id + key->count - 1;

	/* handle map_id_{down,up}() */
	if (key->map_up)
		first = el->lower_first;
	else
		first = el->first;

	last = first + el->count - 1;

	if (key->id >= first && key->id <= last &&
	    (id2 >= first && id2 <= last))
		return 0;

	if (key->id < first || id2 < first)
		return -1;

	return 1;
}

static struct uid_gid_extent *
map_id_up_base(unsigned extents, struct uid_gid_map *map, u32 id)
{
	unsigned idx;
	u32 first, last;

	/* Find the matching extent */
	for (idx = 0; idx < extents; idx++) {
		first = map->extent[idx].lower_first;
		last = first + map->extent[idx].count - 1;
		if (id >= first && id <= last)
			return &map->extent[idx];
	}
	return NULL;
}

static struct uid_gid_extent *
map_id_up_max(unsigned extents, struct uid_gid_map *map, u32 id)
{
	struct idmap_key key;

	key.map_up = true;
	key.count = 1;
	key.id = id;

	return bsearch(&key, map->reverse, extents,
		       sizeof(struct uid_gid_extent), cmp_map_id);
}

u32 map_id_up(struct uid_gid_map *map, u32 id)
{
	struct uid_gid_extent *extent;
	unsigned extents = map->nr_extents;
	smp_rmb();

	if (extents <= UID_GID_MAP_MAX_BASE_EXTENTS)
		extent = map_id_up_base(extents, map, id);
	else
		extent = map_id_up_max(extents, map, id);

	/* Map the id or note failure */
	if (extent)
		id = (id - extent->lower_first) + extent->first;
	else
		id = (u32) -1;

	return id;
}

uid_t from_kuid(struct user_namespace *targ, kuid_t kuid)
{
	/* Map the uid from a global kernel uid */
	return map_id_up(&targ->uid_map, __kuid_val(kuid));
}

uid_t from_kuid_munged(struct user_namespace *targ, kuid_t kuid)
{
	uid_t uid;
	uid = from_kuid(targ, kuid);

	if (uid == (uid_t) -1)
		uid = overflowuid;
	return uid;
}

gid_t from_kgid(struct user_namespace *targ, kgid_t kgid)
{
	/* Map the gid from a global kernel gid */
	return map_id_up(&targ->gid_map, __kgid_val(kgid));
}

gid_t from_kgid_munged(struct user_namespace *targ, kgid_t kgid)
{
	gid_t gid;
	gid = from_kgid(targ, kgid);

	if (gid == (gid_t) -1)
		gid = overflowgid;
	return gid;
}
