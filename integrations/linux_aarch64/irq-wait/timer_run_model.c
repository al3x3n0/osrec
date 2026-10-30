/* Checked single-CPU boundaries around the original callback-run function.
 * The logical lock/save token and sequence steps are not native lock snapshots.
 * Hardware IRQ delivery stays in the exception wrapper; these hooks do not unmask it.
 */
static unsigned callback_witness_count,callback_unlocks,callback_relocks,native_timer_state_count;
static unsigned native_timer_return_count;
static void emit_outer_state(void);
static void emit_propagated_offsets(void);
static unsigned native_base_state_count;
static void emit_base_state(unsigned stage)
{
    check(checkpoint_base_state && stage==native_base_state_count+1 &&
          timer_base.cpu_base==&timer_cpu && timer_base.index<32);
    if(stage==1)check(irq_depth==1 && phase==3 && !callback_count && timer_base.running==&sleeper.timer);
    else check(stage==2 && !irq_depth && phase==4 && resume_count==1 && native_timer_return_count==1);
    emit(17,stage,timer_base.index,(timer_base.cpu_base->active_bases>>timer_base.index)&1);
    ++native_base_state_count;
}
static void emit_timer_return(void)
{
    check(checkpoint_timer_return && !native_timer_return_count && !irq_depth && current==1 &&
          phase==4 && resume_count==1 && callback_count==1 && !sleeper.timer.state && !sleeper.task);
    emit(16,sleeper.timer.id,1,timer_base.running?timer_base.running->id:0);
    ++native_timer_return_count;
}
struct callback_witness {uint32_t kind,running_id,state,lock,barriers,unlocks,relocks,calls;};
_Static_assert(sizeof(struct callback_witness)==32,"callback witness layout");
struct callback_witness osrec_linux_irq_callback[7];
static void callback_snapshot(unsigned kind)
{
    check(callback_witness_count<7);
    osrec_linux_irq_callback[callback_witness_count++]=(struct callback_witness){kind,
        timer_base.running?1:0,sleeper.timer.state,timer_cpu.lock,timer_base.seq,
        callback_unlocks,callback_relocks,callback_count};
}
static void lockdep_assert_held(unsigned *lock)
{
    check(lock==&timer_cpu.lock && *lock==1 && irq_depth==1 && phase==3 && !callback_count);
    callback_snapshot(1);
}
static void debug_deactivate(struct hrtimer *timer)
{
    check(timer==&sleeper.timer && phase==3 && !cancelled && irq_depth==1 && timer_cpu.lock==1);
    cancelled=1;emit(6,timer->id,0,0);
}
static void raw_write_seqcount_barrier(unsigned *sequence)
{
    check(sequence==&timer_base.seq && timer_cpu.lock==1 && timer_base.running==&sleeper.timer);
    if(*sequence==0)check(!callback_count && sleeper.timer.state==HRTIMER_STATE_ENQUEUED);
    else check(*sequence==1 && callback_count==1 && !sleeper.timer.state && sleeper.task==NULL);
    ++*sequence;barrier();callback_snapshot(*sequence==1?2:6);
}
static void raw_spin_unlock_irqrestore(unsigned *lock,unsigned long flags)
{
    check(lock==&timer_cpu.lock && *lock==1 && flags==1 && irq_depth==1 && timer_base.seq==1 &&
          timer_base.running==&sleeper.timer && !sleeper.timer.state && timer_del_calls==1);
    *lock=0;++callback_unlocks;callback_snapshot(3);
}
static void trace_hrtimer_expire_entry(struct hrtimer *timer,ktime_t *now)
{
    check(timer==&sleeper.timer && now && (uint64_t)*now==observed_now && observed_now>=timer->expires &&
          !timer_cpu.lock && timer_base.running==timer && !timer->state && !sleeper.timer.node.queued &&
          timer_cpu.active_bases==checkpoint_background_active && timer_queue_witness_count==3);
    timer_queue_snapshot(4);emit(7,timer->id,observed_now,0);
}
static bool lockdep_hrtimer_enter(struct hrtimer *timer)
{
    check(timer==&sleeper.timer && !timer_cpu.lock && irq_depth==1 && timer_base.running==timer &&
          timer->function==hrtimer_wakeup && !callback_count);
    if(checkpoint_clock_offsets)emit_propagated_offsets();
    if(checkpoint_outer_state)emit_outer_state();
    if(checkpoint_base_state)emit_base_state(1);
    if(checkpoint_timer_state){
        check(!native_timer_state_count);
        emit(15,1,timer->state,timer_base.running==timer?timer->id:0);++native_timer_state_count;
    }
    emit_sleeper_state(2);return true;
}
static void lockdep_hrtimer_exit(bool hardirq)
{
    check(hardirq && irq_depth==1 && !timer_cpu.lock && timer_base.running==&sleeper.timer &&
          sleeper.task==NULL && wake_count==1 && !callback_count);
    ++callback_count;emit_sleeper_state(3);callback_snapshot(4);
}
static void trace_hrtimer_expire_exit(struct hrtimer *timer)
{
    check(timer==&sleeper.timer && !timer_cpu.lock && callback_count==1 && timer_base.running==timer);
    emit(10,timer->id,0,0);
}
static void raw_spin_lock_irq(unsigned *lock)
{
    check(lock==&timer_cpu.lock && !*lock && irq_depth==1 && callback_count==1 && callback_unlocks==1);
    *lock=1;++callback_relocks;callback_snapshot(5);
}
#define __must_hold(lock)
#include "timer_run.c"
#undef __must_hold
#include "timer_driver_model.c"
#include "timer_outer_model.c"
static void projected_run_timer(struct hrtimer *timer)
{
    check(timer==&sleeper.timer && phase==3 && irq_depth==1 && !callback_count && !cancelled &&
          !timer_cpu.lock && !timer_base.running && timer_queue_witness_count==2);
    unsigned prefix=(checkpoint_clock_state?2:0)+(checkpoint_clock_entry?2:0);
    check(position+prefix+1<checkpoint_count && checkpoint_events[position+prefix].kind==6 &&
          checkpoint_events[position+prefix+1].kind==7 && (!prefix ||
          (checkpoint_events[position+(checkpoint_clock_entry?2:0)].kind==19 && checkpoint_events[position+(checkpoint_clock_entry?2:0)+1].kind==20)));
    if(checkpoint_clock_entry)check(checkpoint_events[position].kind==22 && checkpoint_events[position+1].kind==23);
    observed_now=checkpoint_events[position+prefix+1].b;
    check(observed_now>=timer->expires && observed_now<=UINT64_C(0x7fffffffffffffff));
    ktime_t now=(ktime_t)observed_now;
    timer_cpu.lock=1;timer_queue_snapshot(3);
    check(timer->soft>0 && observed_now<UINT64_C(0x7fffffffffffffff));
    unsigned before=position;
    run_queue_pass(now,0,1);check(position==before && !callback_count && timer->node.queued);
    run_queue_pass((ktime_t)timer->soft-1,HRTIMER_ACTIVE_HARD,2);
    check(position==before && !callback_count && timer->node.queued);
    timer_cpu.lock=0;run_outer_timer();timer_cpu.lock=1;
    before=position;run_queue_pass(now,HRTIMER_ACTIVE_HARD,4);
    check(position==before && callback_count==1);
    check(!timer_base.running && timer_cpu.lock==1 && timer_base.seq==2 && callback_count==1 &&
          callback_unlocks==1 && callback_relocks==1 && !timer->state && !sleeper.timer.node.queued);
    callback_snapshot(7);projected_inactive_remove_probe(timer);timer_cpu.lock=0;
}
