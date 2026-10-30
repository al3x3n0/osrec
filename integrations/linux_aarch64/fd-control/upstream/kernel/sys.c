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
