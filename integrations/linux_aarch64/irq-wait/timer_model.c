/* The selected non-RT, relative-monotonic timer construction/start boundaries.
 * Timer queues, clock bases and debug-object machinery remain explicit models.
 */
static unsigned timer_init_calls,timer_debug_calls,timer_start_calls,timer_witness_count;
struct timer_witness {uint32_t kind,clock_id,mode,callback_matches,linked_tid,is_hard,inits,starts;};
_Static_assert(sizeof(struct timer_witness)==32,"timer witness layout");
struct timer_witness osrec_linux_irq_timer[4];
static void timer_snapshot(unsigned kind)
{
    check(timer_witness_count<4);
    osrec_linux_irq_timer[timer_witness_count++]=(struct timer_witness){kind,
        (uint32_t)sleeper.timer.clock_id,(uint32_t)sleeper.timer.mode,
        sleeper.timer.function==hrtimer_wakeup,sleeper.task?sleeper.task->id:0,
        sleeper.timer.is_hard,timer_init_calls,timer_start_calls};
}
#include "timer_queue_model.c"
static void debug_init(struct hrtimer *timer,clockid_t clock_id,enum hrtimer_mode mode)
{
    check(timer==&sleeper.timer && current==1 && !irq_depth && phase==1 &&
          clock_id==1 && mode==HRTIMER_MODE_REL && !timer_debug_calls && !timer_init_calls);
    ++timer_debug_calls;timer_snapshot(1);emit(2,timer->id,(uint64_t)clock_id,(uint64_t)mode);
}
static void __hrtimer_init(struct hrtimer *timer,clockid_t clock_id,enum hrtimer_mode mode)
{
    check(timer==&sleeper.timer && timer_debug_calls==1 && !timer_init_calls &&
          clock_id==1 && mode==HRTIMER_MODE_REL && !timer->function && !sleeper.task);
    timer->clock_id=clock_id;timer->mode=mode;timer->is_hard=!!(mode&HRTIMER_MODE_HARD);
    ++timer_init_calls;timer_snapshot(2);
}
static void hrtimer_start_expires(struct hrtimer *timer,enum hrtimer_mode mode)
{
    check(timer==&sleeper.timer && phase==2 && current==1 && !irq_depth &&
          timer_init_calls==1 && !timer_start_calls && timer->clock_id==1 &&
          timer->mode==HRTIMER_MODE_REL && mode==HRTIMER_MODE_REL &&
          timer->function==hrtimer_wakeup && sleeper.task==&selected &&
          selected.__state==checkpoint_sleep_state && timer->expires-timer->soft==50000);
    ++timer_start_calls;timer_snapshot(4);projected_timer_enqueue(timer,mode);
}
/* The original source uses the current-task pointer; the harness otherwise keeps an ID. */
#define current (&selected)
#define task_is_realtime(task) ((void)(task),false)
#include "timer_sleeper.c"
#undef task_is_realtime
#undef current
