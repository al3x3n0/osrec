// SPDX-License-Identifier: GPL-2.0
/* Copyright(C) 2005-2006, Thomas Gleixner <tglx@linutronix.de>
 * Copyright(C) 2005-2007, Red Hat, Inc., Ingo Molnar
 * Copyright(C) 2006-2007 Timesys Corp., Thomas Gleixner
 * Selected Linux v6.10 kernel/time/hrtimer.c definition; internal comments omitted.
 */
static void __run_hrtimer(struct hrtimer_cpu_base *cpu_base,
			  struct hrtimer_clock_base *base,
			  struct hrtimer *timer, ktime_t *now,
			  unsigned long flags) __must_hold(&cpu_base->lock)
{
	enum hrtimer_restart (*fn)(struct hrtimer *);
	bool expires_in_hardirq;
	int restart;

	lockdep_assert_held(&cpu_base->lock);

	debug_deactivate(timer);
	base->running = timer;
	raw_write_seqcount_barrier(&base->seq);

	__remove_hrtimer(timer, base, HRTIMER_STATE_INACTIVE, 0);
	fn = timer->function;
	if (IS_ENABLED(CONFIG_TIME_LOW_RES))
		timer->is_rel = false;
	raw_spin_unlock_irqrestore(&cpu_base->lock, flags);
	trace_hrtimer_expire_entry(timer, now);
	expires_in_hardirq = lockdep_hrtimer_enter(timer);

	restart = fn(timer);

	lockdep_hrtimer_exit(expires_in_hardirq);
	trace_hrtimer_expire_exit(timer);
	raw_spin_lock_irq(&cpu_base->lock);
	if (restart != HRTIMER_NORESTART &&
	    !(timer->state & HRTIMER_STATE_ENQUEUED))
		enqueue_hrtimer(timer, base, HRTIMER_MODE_ABS);
	raw_write_seqcount_barrier(&base->seq);

	WARN_ON_ONCE(base->running != timer);
	base->running = NULL;
}
