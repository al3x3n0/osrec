/* One scoped real SysNanoSleep. Callback wrappers always call original code.
 * Fixed buffers, no allocations or printing inside scheduling/IRQ hooks.
 */
extern int __real_SysNanoSleep(const struct timespec *,struct timespec *);
#ifdef OSREC_ASYNC_WAIT_CAPTURE
#include "los_hook.h"
#include "los_hook_types.h"
#include "los_sched_pri.h"
#ifdef LOSCFG_KERNEL_SMP
#error "async wait capture requires one CPU"
#endif
enum { WAIT_ENTRY=1,WAIT_DELAY=2,WAIT_SWITCH=3,WAIT_IRQ_ENTER=4,
       WAIT_IRQ_EXIT=5,WAIT_ENQUEUE=6,WAIT_DELAY_RETURN=7,WAIT_EXIT=8,WAIT_DEADLINE=9 };
static UINT32 wait_rows[256][10],wait_count,wait_failed,wait_active,wait_depth,wait_calls;
static UINT32 wait_state[32];
static LosTaskCB *wait_task;
static const SchedOps *wait_original_ops;
static SchedOps wait_ops;
static void osrec_wait_event(UINT32 kind,const LosTaskCB *subject,UINT32 a,UINT32 b)
{
    UINT32 saved=LOS_IntLock();
    if(wait_active){
        if(wait_count==256){wait_failed=1;}
        else{
            UINT32 *r=wait_rows[wait_count];r[0]=wait_count++;r[1]=kind;
            r[2]=OsCurrTaskGet()->taskID;r[3]=subject?subject->taskID:0;
            r[4]=subject?subject->taskStatus:0;r[5]=wait_depth;r[6]=a;r[7]=b;
            __asm__ volatile("mrs %0,cpsr":"=r"(r[8]));r[9]=wait_task->taskStatus;
        }
    }
    LOS_IntRestore(saved);
}
static void wait_switch(const LosTaskCB *next,const LosTaskCB *previous)
{osrec_wait_event(WAIT_SWITCH,next,previous->taskID,next->taskID);}
static void wait_irq_enter(UINT32 irq)
{if(wait_active){++wait_depth;osrec_wait_event(WAIT_IRQ_ENTER,NULL,irq,0);}}
static void wait_irq_exit(UINT32 irq)
{if(wait_active){if(!wait_depth)wait_failed=1;osrec_wait_event(WAIT_IRQ_EXIT,NULL,irq,0);if(wait_depth)--wait_depth;}}
static UINT32 wait_delay(LosTaskCB *task,UINT64 cycles)
{
    if(task!=wait_task || !wait_active)wait_failed=1;
    osrec_wait_event(WAIT_DELAY,task,(UINT32)cycles,(UINT32)(cycles>>32));
    UINT32 ret=wait_original_ops->delay(task,cycles);
    osrec_wait_event(WAIT_DELAY_RETURN,task,ret,0);return ret;
}
static void wait_enqueue(SchedRunqueue *rq,LosTaskCB *task)
{
    if(task!=wait_task || !wait_active)wait_failed=1;
    wait_original_ops->enqueue(rq,task);
    UINT64 now=OsGetCurrSchedTimeCycle();
    wait_state[29]=(UINT32)now;wait_state[30]=(UINT32)(now>>32);
    osrec_wait_event(WAIT_ENQUEUE,task,(UINT32)now,(UINT32)(now>>32));
}
static UINT64 wait_deadline(LosTaskCB *task)
{
    if(task!=wait_task || !wait_active)wait_failed=1;
    wait_state[24]=(UINT32)task->startTime;wait_state[25]=(UINT32)(task->startTime>>32);
    UINT64 result=wait_original_ops->waitTimeGet(task);
    wait_state[26]=(UINT32)result;wait_state[27]=(UINT32)(result>>32);
    osrec_wait_event(WAIT_DEADLINE,task,(UINT32)result,(UINT32)(result>>32));return result;
}
static void wait_hooks_init(void)
{
    check(LOS_HookReg(LOS_HOOK_TYPE_TASK_SWITCHEDIN,wait_switch)==LOS_OK);
    check(LOS_HookReg(LOS_HOOK_TYPE_ISR_ENTER,wait_irq_enter)==LOS_OK);
    check(LOS_HookReg(LOS_HOOK_TYPE_ISR_EXIT,wait_irq_exit)==LOS_OK);
}
int __wrap_SysNanoSleep(const struct timespec *request,struct timespec *remaining)
{
    struct timespec input;
    check(!wait_calls && !wait_active && remaining==NULL);
    check(LOS_ArchCopyFromUser(&input,request,sizeof(input))==0);
    check(input.tv_sec==0 && input.tv_nsec==20000000);
    UINT32 saved=LOS_IntLock();wait_task=OsCurrTaskGet();
    check(((const SchedHPF *)&wait_task->sp)->policy==LOS_SCHED_RR);
    wait_original_ops=wait_task->ops;wait_ops=*wait_original_ops;
    wait_ops.delay=wait_delay;wait_ops.enqueue=wait_enqueue;wait_ops.waitTimeGet=wait_deadline;
    wait_state[0]=1;wait_state[1]=wait_task->taskID;wait_state[2]=LOS_GetCurrProcessID();
    wait_state[3]=wait_task->taskStatus;wait_state[4]=OS_TASK_STATUS_RUNNING;
    wait_state[5]=OS_TASK_STATUS_READY;wait_state[6]=OS_TASK_STATUS_DELAY;
    wait_state[7]=(UINT32)input.tv_sec;wait_state[8]=(UINT32)input.tv_nsec;
    wait_state[9]=sizeof(input);wait_state[10]=LOSCFG_BASE_CORE_TICK_PER_SECOND;
    wait_state[28]=OS_SYS_CLOCK;
    wait_state[31]=((const SchedHPF *)&wait_task->sp)->policy;
    wait_state[11]=(UINT32)wait_task->waitTime;wait_state[12]=(UINT32)(wait_task->waitTime>>32);
    wait_state[13]=(UINT32)wait_task->startTime;wait_state[14]=(UINT32)(wait_task->startTime>>32);
    wait_task->ops=&wait_ops;wait_active=1;
    osrec_wait_event(WAIT_ENTRY,wait_task,0,0);LOS_IntRestore(saved);
    int ret=__real_SysNanoSleep(request,remaining);
    saved=LOS_IntLock();osrec_wait_event(WAIT_EXIT,wait_task,(UINT32)ret,0);
    wait_active=0;wait_task->ops=wait_original_ops;++wait_calls;
    wait_state[15]=wait_task->taskStatus;wait_state[16]=(UINT32)ret;
    wait_state[17]=wait_count;wait_state[18]=wait_failed;wait_state[19]=wait_depth;
    wait_state[20]=(UINT32)wait_task->waitTime;wait_state[21]=(UINT32)(wait_task->waitTime>>32);
    wait_state[22]=(UINT32)wait_task->startTime;wait_state[23]=(UINT32)(wait_task->startTime>>32);
    LOS_IntRestore(saved);return ret;
}
static void wait_report(void)
{
    check(wait_calls==1 && !wait_active && !wait_failed && !wait_depth);
    hex("OSREC_WAIT_STATE",wait_state,sizeof(wait_state));
    hex("OSREC_WAIT_EVENTS",wait_rows,wait_count*sizeof(wait_rows[0]));
}
#else
int __wrap_SysNanoSleep(const struct timespec *request,struct timespec *remaining)
{return __real_SysNanoSleep(request,remaining);}
#endif
