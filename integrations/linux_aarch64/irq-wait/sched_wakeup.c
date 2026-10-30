// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 1991-2002 Linus Torvalds
 * Selected Linux v6.10 kernel/sched/core.c definitions.
 */
static inline void ttwu_do_wakeup(struct task_struct *p)
{
	WRITE_ONCE(p->__state, TASK_RUNNING);
	trace_sched_wakeup(p);
}

int wake_up_process(struct task_struct *p)
{
	return try_to_wake_up(p, TASK_NORMAL, 0);
}
