/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 fs/mnt_idmapping.c definitions. */

static inline bool initial_idmapping(const struct user_namespace *ns)
{
	return ns == &init_user_ns;
}

vfsuid_t make_vfsuid(struct mnt_idmap *idmap,
		     struct user_namespace *fs_userns,
		     kuid_t kuid)
{
	uid_t uid;

	if (idmap == &nop_mnt_idmap)
		return VFSUIDT_INIT(kuid);
	if (initial_idmapping(fs_userns))
		uid = __kuid_val(kuid);
	else
		uid = from_kuid(fs_userns, kuid);
	if (uid == (uid_t)-1)
		return INVALID_VFSUID;
	return VFSUIDT_INIT_RAW(map_id_down(&idmap->uid_map, uid));
}

vfsgid_t make_vfsgid(struct mnt_idmap *idmap,
		     struct user_namespace *fs_userns, kgid_t kgid)
{
	gid_t gid;

	if (idmap == &nop_mnt_idmap)
		return VFSGIDT_INIT(kgid);
	if (initial_idmapping(fs_userns))
		gid = __kgid_val(kgid);
	else
		gid = from_kgid(fs_userns, kgid);
	if (gid == (gid_t)-1)
		return INVALID_VFSGID;
	return VFSGIDT_INIT_RAW(map_id_down(&idmap->gid_map, gid));
}
