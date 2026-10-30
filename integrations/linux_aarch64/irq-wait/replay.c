/* Actual GICv2 timer delivery; Linux scheduling/clock boundaries are modeled. */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "irq_checkpoint.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result")));
struct irq_event {uint32_t kind,pid;uint64_t a,b,c;};
_Static_assert(sizeof(struct irq_event)==32,"portable event layout");
struct irq_event osrec_linux_irq_events[4096];
static unsigned position,current=1,irq_depth,max_depth,callback_count,wake_count,resume_count,phase,cancelled;
static volatile unsigned delivered;
/* Projected Linux state and independent queue/CPU membership, not native layouts. */
#define TASK_RUNNING 0u
#define TASK_INTERRUPTIBLE 1u
#define TASK_UNINTERRUPTIBLE 2u
#define TASK_NORMAL (TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)
#define TASK_RTLOCK_WAIT 0x1000u
#define TASK_FROZEN 0x8000u
#define CONFIG_DEBUG_PREEMPT 0
#define CONFIG_PREEMPT_RT 0
#define CONFIG_TIME_LOW_RES 0
#define IS_ENABLED(option) (option)
#define __always_inline inline __attribute__((always_inline))
#define READ_ONCE(value) (*(volatile __typeof__(value) *)&(value))
#define WRITE_ONCE(value,new_value) (READ_ONCE(value)=(new_value))
struct rq;
struct task_struct;
struct sched_class {
    void (*enqueue_task)(struct rq *,struct task_struct *,int);
    void (*dequeue_task)(struct rq *,struct task_struct *,int);
};
static const struct sched_class projected_class;
struct task_struct {uint32_t id,__state,saved_state,on_rq,on_cpu;const struct sched_class *sched_class;};
static unsigned activation_count,wake_attempts,denied_wakes,state_guard_checks,native_state_count,sleeper_state_count;
enum hrtimer_restart {HRTIMER_NORESTART,HRTIMER_RESTART};
enum hrtimer_mode {HRTIMER_MODE_ABS=0,HRTIMER_MODE_REL=1,HRTIMER_MODE_SOFT=4,HRTIMER_MODE_HARD=8};
typedef int clockid_t;
typedef uint8_t u8;
typedef int64_t ktime_t;
static void check(int condition);
#include "ordered_timer_queue.h"
struct hrtimer {
    uint64_t id,expires,soft;
    enum hrtimer_restart (*function)(struct hrtimer *);
    clockid_t clock_id;enum hrtimer_mode mode;unsigned is_hard;
    u8 state;struct timerqueue_node node;bool is_rel;
};
struct hrtimer_sleeper {struct hrtimer timer;struct task_struct *task;};
static struct task_struct selected={1,TASK_RUNNING,TASK_RUNNING,1,1,&projected_class};
static struct hrtimer_sleeper sleeper={.timer={.id=1},.task=NULL};
static uint64_t observed_now;
#define container_of(ptr,type,member) ((type *)((unsigned char *)(ptr)-offsetof(type,member)))
static void mask(void){__asm__ volatile("msr daifset, #2":::"memory");}
static void unmask(void){__asm__ volatile("msr daifclr, #2\n isb":::"memory");}
static void barrier(void){__asm__ volatile("dsb sy\n isb":::"memory");}
static uint64_t ticks(void){uint64_t t;__asm__ volatile("mrs %0,cntpct_el0":"=r"(t));return t;}
static uint64_t frequency(void){uint64_t f;__asm__ volatile("mrs %0,cntfrq_el0":"=r"(f));return f;}
static volatile uint32_t *reg(uintptr_t p){return (volatile uint32_t *)p;}
#define GICD UINT64_C(0x08000000)
#define GICC UINT64_C(0x08010000)
__attribute__((noreturn)) static void finish(unsigned error)
{
    mask();osrec_result[0]=0x4f535243;osrec_result[1]=29;osrec_result[3]=error;
    osrec_result[4]=position;osrec_result[5]=checkpoint_count;
    osrec_result[6]=delivered;osrec_result[7]=checkpoint_irqs;
    osrec_result[8]=callback_count;osrec_result[9]=wake_count;
    osrec_result[10]=selected.id;osrec_result[11]=selected.__state;
    osrec_result[12]=sleeper.task==NULL;osrec_result[13]=resume_count;
    osrec_result[14]=max_depth;osrec_result[15]=irq_depth;
    osrec_result[16]=(uint32_t)sleeper.timer.expires;osrec_result[17]=(uint32_t)(sleeper.timer.expires>>32);
    osrec_result[18]=(uint32_t)sleeper.timer.soft;osrec_result[19]=(uint32_t)(sleeper.timer.soft>>32);
    osrec_result[20]=(uint32_t)observed_now;osrec_result[21]=(uint32_t)(observed_now>>32);
    osrec_result[22]=current;osrec_result[23]=checkpoint_native_irq;
    osrec_result[24]=phase;osrec_result[25]=cancelled;
    osrec_result[26]=selected.on_rq;osrec_result[27]=selected.on_cpu;
    osrec_result[28]=activation_count;osrec_result[29]=wake_attempts;
    osrec_result[30]=denied_wakes;osrec_result[31]=state_guard_checks;
    barrier();osrec_result[2]=error?3:2;barrier();for(;;)__asm__ volatile("wfi");
}
static void check(int value){if(!value)finish(1);}
void replay_fault(void){finish(100);}
static void emit(uint32_t kind,uint64_t a,uint64_t b,uint64_t c)
{
    check(position<checkpoint_count);
    const struct irq_record *e=&checkpoint_events[position];
    check(e->kind==kind && e->pid==current && e->a==a && e->b==b && e->c==c);
    osrec_linux_irq_events[position]=(struct irq_event){kind,current,a,b,c};++position;
}
static void emit_sleeper_state(unsigned stage)
{
    if(checkpoint_sleeper_state){
        check(stage==sleeper_state_count+1);
        emit(14,stage,sleeper.timer.id,sleeper.task?sleeper.task->id:0);++sleeper_state_count;
    }
}
static void emit_task_state(unsigned stage)
{
    if(checkpoint_task_state){
        check(stage==native_state_count+1 && !selected.saved_state);
        emit(13,stage,selected.__state,selected.on_rq|((uint64_t)selected.on_cpu<<32));
        ++native_state_count;
    }
}
#define WARN_ON_ONCE(condition) check(!(condition))
#include "sched_state.c"
#include "sched_queue_model.c"
static void trace_sched_wakeup(struct task_struct *task)
{
    check(task==&selected && task->__state==TASK_RUNNING && task->on_rq && !task->on_cpu);
    emit(9,task->id,0,0);++wake_count;
}
static void ttwu_do_wakeup(struct task_struct *p);
/* Bounded local activation model. Linux locking, CPU selection and queues remain modeled. */
static int try_to_wake_up(struct task_struct *task,unsigned state,int wake_flags)
{
    check(task==&selected && wake_flags==0);if(!wake_attempts)emit_task_state(2);++wake_attempts;
    barrier();int success=0;
    if(!ttwu_state_match(task,state,&success)){++denied_wakes;return success;}
    check(irq_depth==1 && current!=selected.id && selected.__state==checkpoint_sleep_state &&
          sleeper.task==NULL && wake_count==0 && !task->on_rq && !task->on_cpu);
    emit(8,selected.id,0,0);
    selected.__state=checkpoint_activation_state;
    projected_activate(task);
    emit_task_state(4);
    ttwu_do_wakeup(task);return success;
}
#include "sched_wakeup.c"
/* Additional target contract probes; these are not native captured wakeups. */
static void validate_state_guards(void)
{
    const unsigned states[]={TASK_RUNNING,TASK_INTERRUPTIBLE,TASK_UNINTERRUPTIBLE,TASK_FROZEN};
    for(unsigned i=0;i<4;++i){
        struct task_struct probe={0,states[i],TASK_RUNNING,0,0,NULL};int success=-1;
        int matched=ttwu_state_match(&probe,TASK_NORMAL,&success);
        check(matched==(i==1 || i==2) && success==matched && probe.__state==states[i]);
        ++state_guard_checks;
    }
    struct task_struct probe={0,TASK_INTERRUPTIBLE,TASK_RUNNING,0,0,NULL};int success=-1;
    check(!ttwu_state_match(&probe,TASK_UNINTERRUPTIBLE,&success) && !success);++state_guard_checks;
    probe.__state=TASK_RTLOCK_WAIT;probe.saved_state=TASK_INTERRUPTIBLE;success=0;
    check(!ttwu_state_match(&probe,TASK_NORMAL,&success) && success==1 &&
          probe.saved_state==TASK_RUNNING && probe.__state==TASK_RTLOCK_WAIT);++state_guard_checks;
}
#include "hrtimer_wakeup.c"
#include "timer_model.c"
#include "timer_run_model.c"
void replay_irq(void)
{
    uint32_t acknowledged=*reg(GICC+0x0c);
    check((acknowledged&1023)==30 && !irq_depth);
    __asm__ volatile("msr cntp_ctl_el0,%0\n isb"::"r"(UINT64_C(0)):"memory");
    irq_depth=1;max_depth=1;
    emit(5,checkpoint_native_irq,1,0);
    while(position<checkpoint_count && checkpoint_events[position].kind!=11){
        unsigned irq_position=position;
        const struct irq_record *e=&checkpoint_events[position];
        unsigned clock_prefix=checkpoint_clock_entry?4:2;
        if((e->kind==19 || e->kind==22) && position+clock_prefix<checkpoint_count && checkpoint_events[position+clock_prefix].kind==11){
            replay_context_clock();
        }else if(e->kind==6 || e->kind==19 || e->kind==22){
            projected_run_timer(&sleeper.timer);
            /* Synthetic repeat-wake guard, after the original callback-run body. */
            unsigned before=position;
            check(wake_up_process(&selected)==0 && position==before && wake_count==1 && activation_count==1);
            phase=4;
        }else finish(2);
        check(position>irq_position);
    }
    emit(11,checkpoint_native_irq,1,0);
    irq_depth=0;*reg(GICC+0x10)=acknowledged;barrier();++delivered;
}
static void deliver_irq(void)
{
    unsigned before=delivered;uint64_t interval=frequency()/1000;check(interval>0);
    __asm__ volatile("msr cntp_tval_el0,%0\n msr cntp_ctl_el0,%1\n isb"
                     ::"r"(interval),"r"(UINT64_C(1)):"memory");
    uint64_t deadline=ticks()+frequency();unmask();
    while(delivered==before){if(ticks()>deadline)finish(3);__asm__ volatile("yield");}
    mask();check(delivered==before+1 && !irq_depth);
}
void replay_main(void)
{
    validate_state_guards();
    check(checkpoint_background_active<=1);
    seed_ordered_queue();
    *reg(GICD)=0;*reg(GICC)=0;
    *reg(GICD+0x180)=0xffffffff;*reg(GICD+0x280)=0xffffffff;
    *(volatile unsigned char *)(GICD+0x400+30)=0x80;
    *reg(GICD+0x100)=1u<<30;*reg(GICC+4)=0xff;*reg(GICC+8)=0;
    *reg(GICD)=1;*reg(GICC)=1;barrier();
    while(position<checkpoint_count){
        unsigned before=position;
        const struct irq_record *e=&checkpoint_events[position];
        if(e->kind==1){check(phase==0 && current==1);emit(1,101,20000000,50000);phase=1;}
        else if(e->kind==2){
            check(phase==1 && !sleeper.task && !sleeper.timer.function);
            hrtimer_init_sleeper(&sleeper,1,HRTIMER_MODE_REL);
            check(timer_init_calls==1 && timer_debug_calls==1 && sleeper.task==&selected &&
                  sleeper.timer.function==hrtimer_wakeup);
            timer_snapshot(3);phase=2;
        }
        else if(e->kind==3){
            check(phase==2 && current==1 && e->b-e->c==50000);
            sleeper.timer.expires=e->b;sleeper.timer.soft=e->c;selected.__state=checkpoint_sleep_state;
            hrtimer_sleeper_start_expires(&sleeper,HRTIMER_MODE_REL);phase=3;
        }else if(e->kind==14){
            check(checkpoint_sleeper_state && current==1 && !irq_depth);
            if(e->a==1)check(phase==2 && !sleeper_state_count);
            else check(e->a==4 && phase==4 && resume_count==1 && selected.__state==TASK_RUNNING);
            emit_sleeper_state((unsigned)e->a);
        }else if(e->kind==17){
            emit_base_state(2);
        }else if(e->kind==16){
            emit_timer_return();
        }else if(e->kind==13){
            check(checkpoint_task_state && e->a==1 && current==1 && phase==3 && !native_state_count);
            projected_deactivate(&selected);
        }else if(e->kind==4){
            uint32_t next=(uint32_t)e->b;check(!irq_depth && e->a==current && next!=current);
            if(current==1){
                check(phase==3 && selected.__state==checkpoint_sleep_state && e->c==1 && selected.on_cpu);
                if(checkpoint_task_state)check(!selected.on_rq && native_state_count==1);
                else{check(selected.on_rq);projected_deactivate(&selected);}
                selected.on_cpu=0;
            }
            if(next==1){check(phase==4 && selected.__state==TASK_RUNNING && selected.on_rq && !selected.on_cpu && !resume_count);selected.on_cpu=1;++resume_count;}
            emit(4,current,next,e->c);current=next;
        }else if(e->kind==5){deliver_irq();}
        else if(e->kind==12){
            check(phase==4 && current==1 && selected.__state==TASK_RUNNING && resume_count==1 && sleeper.task==NULL);
            emit(12,0,0,0);phase=5;
        }else finish(4);
        check(position>before);
    }
    check(phase==5 && callback_count==1 && wake_count==1 && delivered==checkpoint_irqs && !irq_depth);
    check(callback_witness_count==7 && timer_base.seq==2 && callback_unlocks==1 && callback_relocks==1 && !timer_cpu.lock && !timer_base.running);
    check(timer_queue_witness_count==5 && timer_add_calls==1 && timer_del_calls==1 && inactive_remove_probes==1 &&
          !sleeper.timer.state && timer_cpu.active_bases==checkpoint_background_active && !sleeper.timer.node.queued && !timer_reprogram_calls);
    check(native_propagated_offset_count==(checkpoint_clock_offsets?1:0));
    check(timekeeper_calls==(checkpoint_timekeeper_source?1:0) && timekeeper_witness_count==(checkpoint_timekeeper_source?4:0));
    check(native_clock_entry_count==(checkpoint_clock_entry?checkpoint_irqs:0));
    check(native_clock_return_count==(checkpoint_clock_state?checkpoint_irqs:0));
    check(native_outer_state_count==(checkpoint_outer_state?1:0));
    check(clock_witness_count==2 && outer_witness_count==7 && !outer_active && outer_updates==1 && outer_ticks==1 && !outer_raises);
    check(driver_dispatch_calls==4);
    check(driver_witness_count==4 && driver_getnext_calls==3+checkpoint_background_active &&
          driver_soft_checks==2+2*checkpoint_background_active && driver_base_visits==2+checkpoint_background_active);
    check(ordered_witness_count==4 && timer_base.active.count==checkpoint_background_active &&
          residual_node.queued==checkpoint_background_active && !sleeper.timer.node.queued);
    check(timer_witness_count==4 && timer_init_calls==1 && timer_start_calls==1);
    check(sleeper_state_count==(checkpoint_sleeper_state?4:0));
    check(native_timer_state_count==(checkpoint_timer_state?1:0));
    check(native_timer_return_count==(checkpoint_timer_return?1:0));
    check(native_base_state_count==(checkpoint_base_state?2:0));
    check(native_state_count==(checkpoint_task_state?4:0));
    check(queue_witness_count==4 && projected_rq.queued==&selected && projected_rq.nr_running==1 && !queue_operation);
    finish(0);
}
