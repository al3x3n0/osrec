/* Captured clock input, no high-resolution transition or softirq delivery. */
#define KTIME_MAX INT64_MAX
/* Logical selector at an unsupported boundary, not a native softirq ABI. */
enum {HRTIMER_SOFTIRQ};
static unsigned native_outer_state_count;
static unsigned outer_witness_count,outer_active,outer_updates,outer_ticks,outer_raises;
struct outer_witness {uint32_t kind,lock,clock_updates,tick_checks,softirq_raises,dispatches,callbacks,softirq_activated;};
_Static_assert(sizeof(struct outer_witness)==32,"outer timer witness layout");
struct outer_witness osrec_linux_irq_outer[7];
static void outer_snapshot(unsigned kind)
{
    check(outer_active && kind==outer_witness_count+1 && outer_witness_count<7 && driver_dispatch_calls>=2);
    osrec_linux_irq_outer[outer_witness_count++]=(struct outer_witness){kind,timer_cpu.lock,
        outer_updates,outer_ticks,outer_raises,driver_dispatch_calls-2,callback_count,timer_cpu.softirq_activated};
}
static struct hrtimer_cpu_base *outer_cpu(struct hrtimer_cpu_base *cpu)
{
    check(cpu==&timer_cpu && irq_depth==1 && phase==3 && !cpu->lock && !callback_count);
    outer_snapshot(1);return cpu;
}
static int hrtimer_hres_active(struct hrtimer_cpu_base *cpu)
{check(cpu==&timer_cpu && !cpu->lock);outer_snapshot(2);return 0;}
static int hrtimer_is_hres_enabled(void){return 0;}
static int tick_check_oneshot_change(int allow_nohz)
{check(allow_nohz==1 && !timer_cpu.lock && !outer_ticks);++outer_ticks;outer_snapshot(3);return 0;}
static void hrtimer_switch_to_hres(void){finish(1);}
static unsigned long outer_lock(unsigned *lock)
{check(lock==&timer_cpu.lock && !*lock);*lock=1;outer_snapshot(4);return 1;}
#include "timer_clock_model.c"
static int ktime_before(ktime_t now,ktime_t next)
{
    check(now==(ktime_t)observed_now && next==KTIME_MAX && outer_updates==1 && timer_cpu.lock==1);
    verify_clock_update(now);outer_snapshot(6);return now<next;
}
static void raise_softirq_irqoff(unsigned selector)
{(void)selector;++outer_raises;finish(1);}
static void outer_unlock(unsigned *lock,unsigned long flags)
{
    check(lock==&timer_cpu.lock && *lock==1 && flags==1 && driver_dispatch_calls==3 && callback_count==1);
    record_queue_pass(3);*lock=0;outer_snapshot(7);
}
#define this_cpu_ptr(ptr) outer_cpu(ptr)
#define hrtimer_bases timer_cpu
#define raw_spin_lock_irqsave(lock,flags) ((flags)=outer_lock(lock))
#define raw_spin_unlock_irqrestore(lock,flags) outer_unlock(lock,flags)
#include "timer_outer.c"
#undef raw_spin_unlock_irqrestore
#undef raw_spin_lock_irqsave
#undef hrtimer_bases
#undef this_cpu_ptr
static void run_outer_timer(void)
{
    check(!outer_active && !outer_witness_count && !timer_cpu.lock);
    timer_cpu.softirq_expires_next=KTIME_MAX;timer_cpu.softirq_activated=0;
    seed_clock_offsets();
    outer_active=1;hrtimer_run_queues();outer_active=0;
    check(clock_witness_count==2 && outer_witness_count==7 && !timer_cpu.lock && outer_updates==1 && outer_ticks==1 &&
          !outer_raises && !timer_cpu.softirq_activated && timer_cpu.softirq_expires_next==KTIME_MAX);
}

static void emit_outer_state(void)
{
    check(checkpoint_outer_state && !native_outer_state_count && outer_active && outer_updates==1 &&
          irq_depth==1 && phase==3 && !timer_cpu.lock && timer_base.cpu_base==&timer_cpu && !callback_count);
    emit(18,1,(uint64_t)timer_cpu.softirq_expires_next,timer_cpu.softirq_activated);
    ++native_outer_state_count;
}
