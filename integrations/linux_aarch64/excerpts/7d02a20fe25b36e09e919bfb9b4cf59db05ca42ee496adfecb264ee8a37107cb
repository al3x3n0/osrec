// SPDX-License-Identifier: GPL-2.0
long __sys_setfsuid(uid_t uid)
{
	const struct cred *old;
	struct cred *new;
	uid_t old_fsuid;
	kuid_t kuid;

	old = current_cred();
	old_fsuid = from_kuid_munged(old->user_ns, old->fsuid);
	kuid = make_kuid(old->user_ns, uid);
	if (!uid_valid(kuid))
		return old_fsuid;

	new = prepare_creds();
	if (!new)
		return old_fsuid;

	if (uid_eq(kuid, old->uid)  || uid_eq(kuid, old->euid)  ||
	    uid_eq(kuid, old->suid) || uid_eq(kuid, old->fsuid) ||
	    ns_capable_setid(old->user_ns, CAP_SETUID)) {
		if (!uid_eq(kuid, old->fsuid)) {
			new->fsuid = kuid;
			if (security_task_fix_setuid(new, old, LSM_SETID_FS) == 0)
				goto change_okay;
		}
	}

	abort_creds(new);
	return old_fsuid;
change_okay:
	commit_creds(new);
	return old_fsuid;
}

SYSCALL_DEFINE1(setfsuid, uid_t, uid)
{
	return __sys_setfsuid(uid);
}

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

static int set_user(struct cred *new)
{
	struct user_struct *new_user;

	new_user = alloc_uid(new->uid);
	if (!new_user)
		return -EAGAIN;

	free_uid(new->user);
	new->user = new_user;
	return 0;
}

static void flag_nproc_exceeded(struct cred *new)
{
	if (new->ucounts == current_ucounts())
		return;
	/*
	 * We don't fail in case of NPROC limit excess here because too many
	 * poorly written programs don't check set*uid() return code, assuming
	 * it never fails if called by root.  We may still enforce NPROC limit
	 * for programs doing set*uid()+execve() by harmlessly deferring the
	 * failure to the execve() stage.
	 */
	if (is_rlimit_overlimit(new->ucounts, UCOUNT_RLIMIT_NPROC, rlimit(RLIMIT_NPROC)) &&
			new->user != INIT_USER)
		current->flags |= PF_NPROC_EXCEEDED;
	else
		current->flags &= ~PF_NPROC_EXCEEDED;
}


long __sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kuid_t kruid, keuid, ksuid;
	bool ruid_new, euid_new, suid_new;

	kruid = make_kuid(ns, ruid);
	keuid = make_kuid(ns, euid);
	ksuid = make_kuid(ns, suid);
	if ((ruid != (uid_t) -1) && !uid_valid(kruid))
		return -EINVAL;

	if ((euid != (uid_t) -1) && !uid_valid(keuid))
		return -EINVAL;

	if ((suid != (uid_t) -1) && !uid_valid(ksuid))
		return -EINVAL;

	old = current_cred();

	/* check for no-op */
	if ((ruid == (uid_t) -1 || uid_eq(kruid, old->uid)) &&
	    (euid == (uid_t) -1 || (uid_eq(keuid, old->euid) &&
				    uid_eq(keuid, old->fsuid))) &&
	    (suid == (uid_t) -1 || uid_eq(ksuid, old->suid)))
		return 0;
	ruid_new = ruid != (uid_t) -1        && !uid_eq(kruid, old->uid) &&
		   !uid_eq(kruid, old->euid) && !uid_eq(kruid, old->suid);
	euid_new = euid != (uid_t) -1        && !uid_eq(keuid, old->uid) &&
		   !uid_eq(keuid, old->euid) && !uid_eq(keuid, old->suid);
	suid_new = suid != (uid_t) -1        && !uid_eq(ksuid, old->uid) &&
		   !uid_eq(ksuid, old->euid) && !uid_eq(ksuid, old->suid);
	if ((ruid_new || euid_new || suid_new) &&
	    !ns_capable_setid(old->user_ns, CAP_SETUID))
		return -EPERM;
	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	if (ruid != (uid_t) -1) {
		new->uid = kruid;
		if (!uid_eq(kruid, old->uid)) {
			retval = set_user(new);
			if (retval < 0)
				goto error;
		}
	}
	if (euid != (uid_t) -1)
		new->euid = keuid;
	if (suid != (uid_t) -1)
		new->suid = ksuid;
	new->fsuid = new->euid;

	retval = security_task_fix_setuid(new, old, LSM_SETID_RES);
	if (retval < 0)
		goto error;

	retval = set_cred_ucounts(new);
	if (retval < 0)
		goto error;
	flag_nproc_exceeded(new);
	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)
{
	return __sys_setresuid(ruid, euid, suid);
}


long __sys_setreuid(uid_t ruid, uid_t euid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kuid_t kruid, keuid;
	kruid = make_kuid(ns, ruid);
	keuid = make_kuid(ns, euid);

	if ((ruid != (uid_t) -1) && !uid_valid(kruid))
		return -EINVAL;
	if ((euid != (uid_t) -1) && !uid_valid(keuid))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	retval = -EPERM;
	if (ruid != (uid_t) -1) {
		new->uid = kruid;
		if (!uid_eq(old->uid, kruid) &&
		    !uid_eq(old->euid, kruid) &&
		    !ns_capable_setid(old->user_ns, CAP_SETUID))
			goto error;
	}
	if (euid != (uid_t) -1) {
		new->euid = keuid;
		if (!uid_eq(old->uid, keuid) &&
		    !uid_eq(old->euid, keuid) &&
		    !uid_eq(old->suid, keuid) &&
		    !ns_capable_setid(old->user_ns, CAP_SETUID))
			goto error;
	}

	if (!uid_eq(new->uid, old->uid)) {
		retval = set_user(new);
		if (retval < 0)
			goto error;
	}
	if (ruid != (uid_t) -1 ||
	    (euid != (uid_t) -1 && !uid_eq(keuid, old->uid)))
		new->suid = new->euid;
	new->fsuid = new->euid;
	retval = security_task_fix_setuid(new, old, LSM_SETID_RE);
	if (retval < 0)
		goto error;

	retval = set_cred_ucounts(new);
	if (retval < 0)
		goto error;

	flag_nproc_exceeded(new);
	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

SYSCALL_DEFINE2(setreuid, uid_t, ruid, uid_t, euid)
{
	return __sys_setreuid(ruid, euid);
}

long __sys_setuid(uid_t uid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kuid_t kuid;
	kuid = make_kuid(ns, uid);
	if (!uid_valid(kuid))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	retval = -EPERM;
	if (ns_capable_setid(old->user_ns, CAP_SETUID)) {
		new->suid = new->uid = kuid;
		if (!uid_eq(kuid, old->uid)) {
			retval = set_user(new);
			if (retval < 0)
				goto error;
		}
	} else if (!uid_eq(kuid, old->uid) && !uid_eq(kuid, new->suid)) {
		goto error;
	}

	new->fsuid = new->euid = kuid;
	retval = security_task_fix_setuid(new, old, LSM_SETID_ID);
	if (retval < 0)
		goto error;

	retval = set_cred_ucounts(new);
	if (retval < 0)
		goto error;

	flag_nproc_exceeded(new);
	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

SYSCALL_DEFINE1(setuid, uid_t, uid)
{
	return __sys_setuid(uid);
}

