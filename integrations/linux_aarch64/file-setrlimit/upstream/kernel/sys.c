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

long __sys_setfsgid(gid_t gid)
{
	const struct cred *old;
	struct cred *new;
	gid_t old_fsgid;
	kgid_t kgid;

	old = current_cred();
	old_fsgid = from_kgid_munged(old->user_ns, old->fsgid);

	kgid = make_kgid(old->user_ns, gid);
	if (!gid_valid(kgid))
		return old_fsgid;

	new = prepare_creds();
	if (!new)
		return old_fsgid;
	if (gid_eq(kgid, old->gid)  || gid_eq(kgid, old->egid)  ||
	    gid_eq(kgid, old->sgid) || gid_eq(kgid, old->fsgid) ||
	    ns_capable_setid(old->user_ns, CAP_SETGID)) {
		if (!gid_eq(kgid, old->fsgid)) {
			new->fsgid = kgid;
			if (security_task_fix_setgid(new,old,LSM_SETID_FS) == 0)
				goto change_okay;
		}
	}

	abort_creds(new);
	return old_fsgid;

change_okay:
	commit_creds(new);
	return old_fsgid;
}
SYSCALL_DEFINE1(setfsgid, gid_t, gid)
{
	return __sys_setfsgid(gid);
}

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


long __sys_setgid(gid_t gid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kgid_t kgid;

	kgid = make_kgid(ns, gid);
	if (!gid_valid(kgid))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();
	retval = -EPERM;
	if (ns_capable_setid(old->user_ns, CAP_SETGID))
		new->gid = new->egid = new->sgid = new->fsgid = kgid;
	else if (gid_eq(kgid, old->gid) || gid_eq(kgid, old->sgid))
		new->egid = new->fsgid = kgid;
	else
		goto error;

	retval = security_task_fix_setgid(new, old, LSM_SETID_ID);
	if (retval < 0)
		goto error;

	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}
SYSCALL_DEFINE1(setgid, gid_t, gid)
{
	return __sys_setgid(gid);
}
long __sys_setregid(gid_t rgid, gid_t egid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kgid_t krgid, kegid;
	krgid = make_kgid(ns, rgid);
	kegid = make_kgid(ns, egid);

	if ((rgid != (gid_t) -1) && !gid_valid(krgid))
		return -EINVAL;
	if ((egid != (gid_t) -1) && !gid_valid(kegid))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();
	retval = -EPERM;
	if (rgid != (gid_t) -1) {
		if (gid_eq(old->gid, krgid) ||
		    gid_eq(old->egid, krgid) ||
		    ns_capable_setid(old->user_ns, CAP_SETGID))
			new->gid = krgid;
		else
			goto error;
	}
	if (egid != (gid_t) -1) {
		if (gid_eq(old->gid, kegid) ||
		    gid_eq(old->egid, kegid) ||
		    gid_eq(old->sgid, kegid) ||
		    ns_capable_setid(old->user_ns, CAP_SETGID))
			new->egid = kegid;
		else
			goto error;
	}
	if (rgid != (gid_t) -1 ||
	    (egid != (gid_t) -1 && !gid_eq(kegid, old->gid)))
		new->sgid = new->egid;
	new->fsgid = new->egid;

	retval = security_task_fix_setgid(new, old, LSM_SETID_RE);
	if (retval < 0)
		goto error;

	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}
SYSCALL_DEFINE2(setregid, gid_t, rgid, gid_t, egid)
{
	return __sys_setregid(rgid, egid);
}

SYSCALL_DEFINE1(setuid, uid_t, uid)
{
	return __sys_setuid(uid);
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

SYSCALL_DEFINE2(setreuid, uid_t, ruid, uid_t, euid)
{
	return __sys_setreuid(ruid, euid);
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

SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)
{
	return __sys_setresuid(ruid, euid, suid);
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

SYSCALL_DEFINE2(getrlimit, unsigned int, resource, struct rlimit __user *, rlim)
{
	struct rlimit value;
	int ret;

	ret = do_prlimit(current, resource, NULL, &value);
	if (!ret)
		ret = copy_to_user(rlim, &value, sizeof(*rlim)) ? -EFAULT : 0;

	return ret;
}

static int do_prlimit(struct task_struct *tsk, unsigned int resource,
		      struct rlimit *new_rlim, struct rlimit *old_rlim)
{
	struct rlimit *rlim;
	int retval = 0;

	if (resource >= RLIM_NLIMITS)
		return -EINVAL;
	resource = array_index_nospec(resource, RLIM_NLIMITS);
	if (new_rlim) {
		if (new_rlim->rlim_cur > new_rlim->rlim_max)
			return -EINVAL;
		if (resource == RLIMIT_NOFILE &&
				new_rlim->rlim_max > sysctl_nr_open)
			return -EPERM;
	}
	/* Holding a refcount on tsk protects tsk->signal from disappearing. */
	rlim = tsk->signal->rlim + resource;
	task_lock(tsk->group_leader);
	if (new_rlim) {
		/*
		 * Keep the capable check against init_user_ns until cgroups can
		 * contain all limits.
		 */
		if (new_rlim->rlim_max > rlim->rlim_max &&
				!capable(CAP_SYS_RESOURCE))
			retval = -EPERM;
		if (!retval)
			retval = security_task_setrlimit(tsk, resource, new_rlim);
	}
	if (!retval) {
		if (old_rlim)
			*old_rlim = *rlim;
		if (new_rlim)
			*rlim = *new_rlim;
	}
	task_unlock(tsk->group_leader);
	/*
	 * RLIMIT_CPU handling. Arm the posix CPU timer if the limit is not
	 * infinite. In case of RLIM_INFINITY the posix CPU timer code
	 * ignores the rlimit.
	 */
	if (!retval && new_rlim && resource == RLIMIT_CPU &&
	    new_rlim->rlim_cur != RLIM_INFINITY &&
	    IS_ENABLED(CONFIG_POSIX_TIMERS)) {
		/*
		 * update_rlimit_cpu can fail if the task is exiting, but there
		 * may be other tasks in the thread group that are not exiting,
		 * and they need their cpu timers adjusted.
		 *
		 * The group_leader is the last task to be released, so if we
		 * cannot update_rlimit_cpu on it, then the entire process is
		 * exiting and we do not need to update at all.
		 */
		update_rlimit_cpu(tsk->group_leader, new_rlim->rlim_cur);
	}
	return retval;
}

SYSCALL_DEFINE2(setrlimit, unsigned int, resource, struct rlimit __user *, rlim)
{
	struct rlimit new_rlim;

	if (copy_from_user(&new_rlim, rlim, sizeof(*rlim)))
		return -EFAULT;
	return do_prlimit(current, resource, &new_rlim, NULL);
}

