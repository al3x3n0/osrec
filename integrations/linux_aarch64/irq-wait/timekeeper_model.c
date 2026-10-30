/* Provider assumptions for the optional original timekeeper body. These are not
 * native global-state snapshots or Linux sequence/clocksource implementations. */
typedef uint64_t u64;
struct tk_read_base {ktime_t base;};
struct timekeeper {struct tk_read_base tkr_mono;unsigned clock_was_set_seq;ktime_t offs_real,offs_boot,offs_tai,next_leap_ktime;};
static struct {unsigned seq;struct timekeeper timekeeper;} tk_core;
static unsigned timekeeper_calls,timekeeper_reads,timekeeper_ns_reads,timekeeper_adds,timekeeper_retries,timekeeper_witness_count;
struct timekeeper_witness {u64 kind,seq_reads,ns_reads,adds,retries,provider_seq,output_seq,offset_match,now,lock;};
_Static_assert(sizeof(struct timekeeper_witness)==80,"timekeeper witness layout");
struct timekeeper_witness osrec_linux_irq_timekeeper[4];
static void timekeeper_snapshot(unsigned kind,ktime_t now)
{
    check(checkpoint_timekeeper_source && kind==timekeeper_witness_count+1 && timekeeper_witness_count<4);
    const struct clock_input *entry=&checkpoint_clock_entries[delivered];
    unsigned matches=(timer_cpu.clock_base[1].offset==entry->real)|
        ((timer_cpu.clock_base[2].offset==entry->boot)<<1)|((timer_cpu.clock_base[3].offset==entry->tai)<<2);
    osrec_linux_irq_timekeeper[timekeeper_witness_count++]=(struct timekeeper_witness){kind,
        timekeeper_reads,timekeeper_ns_reads,timekeeper_adds,timekeeper_retries,tk_core.timekeeper.clock_was_set_seq,
        timer_cpu.clock_was_set_seq,matches,(u64)now,timer_cpu.lock};
}
static unsigned read_seqcount_begin(unsigned *seq)
{
    check(checkpoint_timekeeper_source && timekeeper_calls==1 && !timekeeper_reads && seq==&tk_core.seq && !*seq && timer_cpu.lock==1);
    ++timekeeper_reads;timekeeper_snapshot(1,0);return 0;
}
static u64 timekeeping_get_ns(struct tk_read_base *mono)
{
    check(mono==&tk_core.timekeeper.tkr_mono && timekeeper_reads==1 && !timekeeper_ns_reads && mono->base==(ktime_t)observed_now);
    ++timekeeper_ns_reads;timekeeper_snapshot(2,0);return 0;
}
static ktime_t ktime_add_ns(ktime_t base,u64 nsecs)
{
    check(base==(ktime_t)observed_now && !nsecs && timekeeper_ns_reads==1 && !timekeeper_adds);
    ++timekeeper_adds;return base;
}
static int read_seqcount_retry(unsigned *seq,unsigned start)
{
    check(seq==&tk_core.seq && !*seq && !start && timekeeper_reads==1 && timekeeper_ns_reads==1 && timekeeper_adds==1 && !timekeeper_retries);
    ++timekeeper_retries;timekeeper_snapshot(3,0);return 0;
}
/* These branches are exercised only by isolated host tests, not admitted replay. */
static ktime_t ktime_set(int seconds,unsigned long ns){(void)seconds;(void)ns;finish(1);}
static ktime_t ktime_sub(ktime_t lhs,ktime_t rhs){(void)lhs;(void)rhs;finish(1);}
#define unlikely(value) (value)
#define ktime_get_update_offsets_now source_ktime_get_update_offsets_now
#include "timekeeper_update.c"
#undef ktime_get_update_offsets_now
#undef unlikely
static ktime_t run_source_timekeeper(unsigned *seq,ktime_t *real,ktime_t *boot,ktime_t *tai)
{
    check(checkpoint_timekeeper_source && checkpoint_clock_entry && !timekeeper_calls && outer_active && timer_cpu.lock==1);
    const struct clock_input *entry=&checkpoint_clock_entries[delivered];
    const struct clock_input *out=&checkpoint_clocks[delivered];
    check(entry->sequence==out->sequence && entry->real==out->real && entry->boot==out->boot && entry->tai==out->tai);
    tk_core.timekeeper=(struct timekeeper){.tkr_mono={.base=(ktime_t)observed_now},.clock_was_set_seq=entry->sequence,
        .offs_real=entry->real==11?12:11,.offs_boot=entry->boot==22?23:22,.offs_tai=entry->tai==33?34:33,.next_leap_ktime=INT64_MAX};
    ++timekeeper_calls;
    ktime_t now=source_ktime_get_update_offsets_now(seq,real,boot,tai);
    check(now==(ktime_t)observed_now && *seq==entry->sequence && *real==entry->real && *boot==entry->boot && *tai==entry->tai &&
          timekeeper_reads==1 && timekeeper_ns_reads==1 && timekeeper_adds==1 && timekeeper_retries==1);
    timekeeper_snapshot(4,now);return now;
}
