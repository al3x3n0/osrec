// SPDX-License-Identifier: GPL-2.0
/* Selected, unmodified syscall definitions from Linux v6.10 kernel/sys.c.
 * Copyright (C) 1991, 1992 Linus Torvalds.
 * https://raw.githubusercontent.com/torvalds/linux/v6.10/kernel/sys.c
 * This is a reviewed excerpt, not a complete Linux source tree.
 */
SYSCALL_DEFINE0(getpid)
{
	return task_tgid_vnr(current);
}
SYSCALL_DEFINE0(gettid)
{
	return task_pid_vnr(current);
}
SYSCALL_DEFINE0(getppid)
{
	int pid;

	rcu_read_lock();
	pid = task_tgid_vnr(rcu_dereference(current->real_parent));
	rcu_read_unlock();

	return pid;
}
SYSCALL_DEFINE0(getuid)
{
	/* Only we change this so SMP safe */
	return from_kuid_munged(current_user_ns(), current_uid());
}
SYSCALL_DEFINE0(geteuid)
{
	/* Only we change this so SMP safe */
	return from_kuid_munged(current_user_ns(), current_euid());
}
SYSCALL_DEFINE0(getgid)
{
	/* Only we change this so SMP safe */
	return from_kgid_munged(current_user_ns(), current_gid());
}
SYSCALL_DEFINE0(getegid)
{
	/* Only we change this so SMP safe */
	return from_kgid_munged(current_user_ns(), current_egid());
}
SYSCALL_DEFINE3(getresuid, uid_t __user *, ruidp, uid_t __user *, euidp, uid_t __user *, suidp)
{
	const struct cred *cred = current_cred();
	int retval;
	uid_t ruid, euid, suid;
	ruid = from_kuid_munged(cred->user_ns, cred->uid);
	euid = from_kuid_munged(cred->user_ns, cred->euid);
	suid = from_kuid_munged(cred->user_ns, cred->suid);

	retval = put_user(ruid, ruidp);
	if (!retval) {
		retval = put_user(euid, euidp);
		if (!retval)
			return put_user(suid, suidp);
	}
	return retval;
}
SYSCALL_DEFINE3(getresgid, gid_t __user *, rgidp, gid_t __user *, egidp, gid_t __user *, sgidp)
{
	const struct cred *cred = current_cred();
	int retval;
	gid_t rgid, egid, sgid;

	rgid = from_kgid_munged(cred->user_ns, cred->gid);
	egid = from_kgid_munged(cred->user_ns, cred->egid);
	sgid = from_kgid_munged(cred->user_ns, cred->sgid);

	retval = put_user(rgid, rgidp);
	if (!retval) {
		retval = put_user(egid, egidp);
		if (!retval)
			retval = put_user(sgid, sgidp);
	}

	return retval;
}
SYSCALL_DEFINE1(umask, int, mask)
{
	mask = xchg(&current->fs->umask, mask & S_IRWXUGO);
	return mask;
}

long __sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kgid_t krgid, kegid, ksgid;
	bool rgid_new, egid_new, sgid_new;

	krgid = make_kgid(ns, rgid);
	kegid = make_kgid(ns, egid);
	ksgid = make_kgid(ns, sgid);
	if ((rgid != (gid_t) -1) && !gid_valid(krgid))
		return -EINVAL;
	if ((egid != (gid_t) -1) && !gid_valid(kegid))
		return -EINVAL;
	if ((sgid != (gid_t) -1) && !gid_valid(ksgid))
		return -EINVAL;

	old = current_cred();

	/* check for no-op */
	if ((rgid == (gid_t) -1 || gid_eq(krgid, old->gid)) &&
	    (egid == (gid_t) -1 || (gid_eq(kegid, old->egid) &&
				    gid_eq(kegid, old->fsgid))) &&
	    (sgid == (gid_t) -1 || gid_eq(ksgid, old->sgid)))
		return 0;
	rgid_new = rgid != (gid_t) -1        && !gid_eq(krgid, old->gid) &&
		   !gid_eq(krgid, old->egid) && !gid_eq(krgid, old->sgid);
	egid_new = egid != (gid_t) -1        && !gid_eq(kegid, old->gid) &&
		   !gid_eq(kegid, old->egid) && !gid_eq(kegid, old->sgid);
	sgid_new = sgid != (gid_t) -1        && !gid_eq(ksgid, old->gid) &&
		   !gid_eq(ksgid, old->egid) && !gid_eq(ksgid, old->sgid);
	if ((rgid_new || egid_new || sgid_new) &&
	    !ns_capable_setid(old->user_ns, CAP_SETGID))
		return -EPERM;
	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	if (rgid != (gid_t) -1)
		new->gid = krgid;
	if (egid != (gid_t) -1)
		new->egid = kegid;
	if (sgid != (gid_t) -1)
		new->sgid = ksgid;
	new->fsgid = new->egid;

	retval = security_task_fix_setgid(new, old, LSM_SETID_RES);
	if (retval < 0)
		goto error;

	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

SYSCALL_DEFINE3(setresgid, gid_t, rgid, gid_t, egid, gid_t, sgid)
{
	return __sys_setresgid(rgid, egid, sgid);
}
