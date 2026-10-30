// SPDX-License-Identifier: GPL-2.0-or-later
/* Task credentials management - see Documentation/security/credentials.rst
 *
 * Copyright (C) 2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
/* Original Linux v6.10 kernel/cred.c selected accounting definition. */
int set_cred_ucounts(struct cred *new)
{
	struct ucounts *new_ucounts, *old_ucounts = new->ucounts;

	/*
	 * This optimization is needed because alloc_ucounts() uses locks
	 * for table lookups.
	 */
	if (old_ucounts->ns == new->user_ns && uid_eq(old_ucounts->uid, new->uid))
		return 0;
	if (!(new_ucounts = alloc_ucounts(new->user_ns, new->uid)))
		return -EAGAIN;

	new->ucounts = new_ucounts;
	put_ucounts(old_ucounts);

	return 0;
}

