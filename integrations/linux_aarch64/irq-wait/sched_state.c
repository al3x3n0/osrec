// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 1991-2002 Linus Torvalds
 * Selected Linux v6.10 kernel/sched/core.c definitions; internal comments omitted.
 */
static __always_inline
int __task_state_match(struct task_struct *p, unsigned int state)
{
	if (READ_ONCE(p->__state) & state)
		return 1;

	if (READ_ONCE(p->saved_state) & state)
		return -1;

	return 0;
}

static __always_inline
bool ttwu_state_match(struct task_struct *p, unsigned int state, int *success)
{
	int match;
	if (IS_ENABLED(CONFIG_DEBUG_PREEMPT)) {
		WARN_ON_ONCE((state & TASK_RTLOCK_WAIT) &&
			     state != TASK_RTLOCK_WAIT);
	}

	*success = !!(match = __task_state_match(p, state));
	if (match < 0)
		p->saved_state = TASK_RUNNING;
	return match > 0;
}
