/* One selected timer and an optional synthetic ordering sentinel for an inferred
 * nonempty remainder. Its UINT64_MAX key is not an observed native deadline.
 * The two-slot ordered array is a replay model, not a native rbtree or queue.
 */
#define HRTIMER_STATE_INACTIVE 0
#define HRTIMER_STATE_ENQUEUED 1
struct hrtimer_cpu_base;
struct hrtimer_clock_base {struct hrtimer_cpu_base *cpu_base;unsigned index;struct timerqueue_head active;struct hrtimer *running;unsigned seq;ktime_t offset;};
enum {HRTIMER_BASE_MONOTONIC,HRTIMER_BASE_REALTIME,HRTIMER_BASE_BOOTTIME,HRTIMER_BASE_TAI,
      HRTIMER_BASE_MONOTONIC_SOFT,HRTIMER_BASE_REALTIME_SOFT,HRTIMER_BASE_BOOTTIME_SOFT,HRTIMER_BASE_TAI_SOFT};
struct hrtimer_cpu_base {unsigned online,active_bases;struct hrtimer *next_timer;unsigned lock;ktime_t softirq_expires_next;unsigned softirq_activated,clock_was_set_seq;struct hrtimer_clock_base clock_base[8];};
static struct hrtimer_cpu_base timer_cpu={.online=1};
static struct hrtimer_clock_base timer_base={.cpu_base=&timer_cpu};
static struct hrtimer residual_timer={.id=2,.soft=UINT64_C(0x7fffffffffffffff),
    .node={.expires=UINT64_MAX,.id=2}};
#define residual_node (residual_timer.node)
static unsigned ordered_witness_count;
struct ordered_witness {uint32_t kind,count,first,second,selected_queued,residual_queued,adds,deletes;};
_Static_assert(sizeof(struct ordered_witness)==32,"ordered queue witness layout");
struct ordered_witness osrec_linux_irq_ordered[4];
static unsigned timer_add_calls,timer_del_calls,timer_reprogram_calls,inactive_remove_probes,timer_queue_witness_count;
struct timer_queue_witness {uint32_t kind,state,active_mask,queued_id,adds,deletes,reprograms,inactive_probes;};
_Static_assert(sizeof(struct timer_queue_witness)==32,"timer queue witness layout");
struct timer_queue_witness osrec_linux_irq_timer_queue[5];
static void ordered_snapshot(unsigned kind)
{
    ordered_validate(&timer_base.active);check(ordered_witness_count<4);
    struct timerqueue_node *first=ordered_first(&timer_base.active);
    osrec_linux_irq_ordered[ordered_witness_count++]=(struct ordered_witness){kind,
        timer_base.active.count,first?first->id:0,timer_base.active.count==2?timer_base.active.nodes[1]->id:0,
        sleeper.timer.node.queued,residual_node.queued,timer_add_calls,timer_del_calls};
}
static void seed_ordered_queue(void)
{
    check(!timer_base.active.count && !ordered_witness_count && !timer_add_calls && !timer_del_calls);
    sleeper.timer.node.id=1;
    if(checkpoint_background_active)check(ordered_insert(&timer_base.active,&residual_node)==1);
    timer_cpu.active_bases=checkpoint_background_active;ordered_snapshot(1);
}
static void timer_queue_snapshot(unsigned kind)
{
    check(timer_queue_witness_count<5);
    osrec_linux_irq_timer_queue[timer_queue_witness_count++]=(struct timer_queue_witness){kind,
        sleeper.timer.state,timer_cpu.active_bases,sleeper.timer.node.queued?1:0,
        timer_add_calls,timer_del_calls,timer_reprogram_calls,inactive_remove_probes};
}
static void debug_activate(struct hrtimer *timer,enum hrtimer_mode mode)
{
    check(timer==&sleeper.timer && current==1 && !irq_depth && phase==2 && mode==HRTIMER_MODE_REL &&
          timer_start_calls==1 && !timer_add_calls && !timer->state && timer_cpu.active_bases==checkpoint_background_active);
    emit(3,timer->id,timer->expires,timer->soft);
}
static int timerqueue_add(struct timerqueue_head *head,struct timerqueue_node *node)
{
    check(head==&timer_base.active && node==&sleeper.timer.node && !node->queued && head->count==checkpoint_background_active &&
          sleeper.timer.state==HRTIMER_STATE_ENQUEUED && timer_cpu.active_bases==1 &&
          node->expires==sleeper.timer.expires && !timer_add_calls);
    int first=ordered_insert(head,node);++timer_add_calls;ordered_snapshot(2);return first;
}
static int timerqueue_del(struct timerqueue_head *head,struct timerqueue_node *node)
{
    check(head==&timer_base.active && node==&sleeper.timer.node && ordered_first(head)==node &&
          sleeper.timer.state==HRTIMER_STATE_INACTIVE && timer_cpu.active_bases==1 &&
          timer_add_calls==1 && !timer_del_calls && irq_depth==1);
    int nonempty=ordered_remove(head,node);++timer_del_calls;ordered_snapshot(3);return nonempty;
}
static void hrtimer_force_reprogram(struct hrtimer_cpu_base *cpu,int skip_equal)
{(void)cpu;(void)skip_equal;++timer_reprogram_calls;finish(1);}
#include "timer_queue.c"
static void projected_timer_enqueue(struct hrtimer *timer,enum hrtimer_mode mode)
{
    check(timer==&sleeper.timer && !timer_queue_witness_count);
    timer->node.expires=timer->expires;timer_queue_snapshot(1);
    int first=enqueue_hrtimer(timer,&timer_base,mode);
    check(first==1 && timer->state==HRTIMER_STATE_ENQUEUED && ordered_first(&timer_base.active)==&timer->node &&
          timer_cpu.active_bases==1 && timer_add_calls==1);
    timer_cpu.next_timer=timer;timer_queue_snapshot(2);
}
static void projected_inactive_remove_probe(struct hrtimer *timer)
{
    check(timer==&sleeper.timer && irq_depth==1 && phase==3 && timer_cpu.lock==1 &&
          timer_del_calls==1 && timer_queue_witness_count==4 && residual_node.queued==checkpoint_background_active);
    /* Synthetic contract check: inactive removal must not delete a second time. */
    __remove_hrtimer(timer,&timer_base,HRTIMER_STATE_INACTIVE,0);++inactive_remove_probes;
    check(timer_del_calls==1 && !timer->state && !sleeper.timer.node.queued && timer_cpu.active_bases==checkpoint_background_active);
    timer_queue_snapshot(5);ordered_snapshot(4);
}
