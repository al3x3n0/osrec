/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed original Linux v6.10 kernel/time/timekeeping.c definitions. */

static inline struct timespec64 tk_xtime(const struct timekeeper *tk)
{
	struct timespec64 ts;

	ts.tv_sec = tk->xtime_sec;
	ts.tv_nsec = (long)(tk->tkr_mono.xtime_nsec >> tk->tkr_mono.shift);
	return ts;
}

void ktime_get_coarse_real_ts64(struct timespec64 *ts)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	unsigned int seq;

	do {
		seq = read_seqcount_begin(&tk_core.seq);

		*ts = tk_xtime(tk);
	} while (read_seqcount_retry(&tk_core.seq, seq));
}
