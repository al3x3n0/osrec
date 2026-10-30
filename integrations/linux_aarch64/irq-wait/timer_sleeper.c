// SPDX-License-Identifier: GPL-2.0
/* Copyright(C) 2005-2006, Thomas Gleixner <tglx@linutronix.de>
 * Copyright(C) 2005-2007, Red Hat, Inc., Ingo Molnar
 * Copyright(C) 2006-2007 Timesys Corp., Thomas Gleixner
 * Selected Linux v6.10 kernel/time/hrtimer.c definitions; internal comments omitted.
 */
void hrtimer_sleeper_start_expires(struct hrtimer_sleeper *sl,
				   enum hrtimer_mode mode)
{
	if (IS_ENABLED(CONFIG_PREEMPT_RT) && sl->timer.is_hard)
		mode |= HRTIMER_MODE_HARD;
	hrtimer_start_expires(&sl->timer, mode);
}

static void __hrtimer_init_sleeper(struct hrtimer_sleeper *sl,
				   clockid_t clock_id, enum hrtimer_mode mode)
{
	if (IS_ENABLED(CONFIG_PREEMPT_RT)) {
		if (task_is_realtime(current) && !(mode & HRTIMER_MODE_SOFT))
			mode |= HRTIMER_MODE_HARD;
	}
	__hrtimer_init(&sl->timer, clock_id, mode);
	sl->timer.function = hrtimer_wakeup;
	sl->task = current;
}

void hrtimer_init_sleeper(struct hrtimer_sleeper *sl, clockid_t clock_id,
			  enum hrtimer_mode mode)
{
	debug_init(&sl->timer, clock_id, mode);
	__hrtimer_init_sleeper(sl, clock_id, mode);
}
