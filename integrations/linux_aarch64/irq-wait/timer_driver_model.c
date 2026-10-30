/* One monotonic base, zero offset, captured expiry input; no tick/clock driver. */
#define HRTIMER_ACTIVE_HARD 0x0fu
#define HRTIMER_ACTIVE_SOFT 0xf0u
static unsigned driver_dispatch_calls;
static unsigned driver_witness_count,driver_getnext_calls,driver_soft_checks,driver_base_visits;
struct driver_witness {uint32_t kind,callbacks,selected_queued,first_id,active_mask,getnext_calls,soft_checks,base_visits;};
_Static_assert(sizeof(struct driver_witness)==32,"driver witness layout");
struct driver_witness osrec_linux_irq_driver[4];
static struct hrtimer_clock_base *single_active_base(struct hrtimer_cpu_base *cpu,unsigned active)
{
    check(cpu==&timer_cpu && cpu->lock==1 && irq_depth==1 && phase==3 && !(active&~1u));
    ++driver_dispatch_calls;if(!active)return NULL;
    ++driver_base_visits;return &timer_base;
}
#define for_each_active_base(base,cpu,active) \
    for(base=single_active_base(cpu,active);base;base=NULL)
static ktime_t ktime_add(ktime_t now,ktime_t offset)
{check(now>=0 && offset==0);return now;}
static struct timerqueue_node *timerqueue_getnext(struct timerqueue_head *head)
{
    check(head==&timer_base.active && timer_cpu.lock==1 && irq_depth==1 && ++driver_getnext_calls<=4);
    return ordered_first(head);
}
static ktime_t hrtimer_get_softexpires_tv64(const struct hrtimer *timer)
{
    check((timer==&sleeper.timer || timer==&residual_timer) && timer->soft<=UINT64_C(0x7fffffffffffffff));
    ++driver_soft_checks;return (ktime_t)timer->soft;
}
static void hrtimer_sync_wait_running(struct hrtimer_cpu_base *cpu,unsigned long flags)
{(void)cpu;(void)flags;finish(1);}
#include "timer_driver.c"
#undef for_each_active_base
static void record_queue_pass(unsigned kind)
{
    check(kind==driver_witness_count+1 && driver_witness_count<4);
    struct timerqueue_node *first=ordered_first(&timer_base.active);
    osrec_linux_irq_driver[driver_witness_count++]=(struct driver_witness){kind,callback_count,
        sleeper.timer.node.queued,first?first->id:0,timer_cpu.active_bases,
        driver_getnext_calls,driver_soft_checks,driver_base_visits};
}

static void run_queue_pass(ktime_t now,unsigned mask,unsigned kind)
{__hrtimer_run_queues(&timer_cpu,now,1,mask);record_queue_pass(kind);}
