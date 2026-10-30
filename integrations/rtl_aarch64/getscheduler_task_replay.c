/* ABI 10: original task-mode syscall, logical task and ordered callback outcomes. */
#include <stdint.h>
#include "getscheduler_model.h"
#include "getscheduler_checkpoint.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static uint32_t cursor,invocation,bounds_checks,lookups,permissions,callbacks,locks,unlocks,depth,phase;
static LosTaskCB task;
extern int SysSchedGetScheduler(int,int);
__attribute__((noreturn)) static void complete(uint32_t status,uint32_t error)
{
    osrec_result[3]=error;osrec_result[5]=cursor;osrec_result[6]=CHECKPOINT_EVENTS;
    osrec_result[7]=4;osrec_result[8]=invocation;
    osrec_result[9]=bounds_checks;osrec_result[10]=lookups;osrec_result[11]=permissions;
    osrec_result[12]=callbacks;osrec_result[13]=locks;osrec_result[24]=unlocks;
    osrec_result[25]=depth;osrec_result[26]=157;osrec_result[27]=128;
    __asm__ volatile("dmb sy" ::: "memory");osrec_result[2]=status;
    __asm__ volatile("dsb sy" ::: "memory");for (;;) __asm__ volatile("b ." ::: "memory");
}
static void require(int condition,uint32_t error) { if(!condition) complete(3,error); }
static const struct checkpoint_event *consume(uint32_t kind,uint32_t id)
{
    require(cursor<CHECKPOINT_EVENTS,1);
    const struct checkpoint_event *event=&checkpoint_events[cursor];
    require(event->invocation==invocation,2);
    require(event->kind==kind && event->id==id,3);
    ++cursor;return event;
}
static unsigned int policy_get(const LosTaskCB *selected,SchedParam *param);
static const SchedOps ops={policy_get};
int osrec_task_invalid(int id)
{
    require(depth==0 && phase==0,101);phase=1;++bounds_checks;
    const struct checkpoint_event *event=consume(3,(uint32_t)id);
    require(event->raw==128 && event->policy==0 && event->written==0,101);
    return (uint32_t)id>=event->raw;
}
LosTaskCB *osrec_task_lookup(int id)
{
    require(phase==1 && depth==0 && (uint32_t)id<128 && (uint32_t)id==checkpoint_calls[invocation].id,102);
    phase=2;++lookups;task.id=(uint32_t)id;task.ops=&ops;return &task;
}
void osrec_scheduler_lock(unsigned int *saved)
{
    require(phase==2 && depth==0 && saved!=0,103);
    *saved=UINT32_C(0x13579bdf);depth=1;phase=3;++locks;
}
void osrec_scheduler_unlock(unsigned int saved)
{
    require(depth==1 && (phase==4 || phase==5) && saved==UINT32_C(0x13579bdf),104);
    depth=0;phase=6;++unlocks;
}
int OsUserTaskOperatePermissionsCheck(const LosTaskCB *selected)
{
    require(phase==3 && depth==1 && selected==&task && selected->ops==&ops,105);
    phase=4;++permissions;
    const struct checkpoint_event *event=consume(4,selected->id);
    require(event->policy==0 && event->written==0,105);
    return (int32_t)event->raw;
}
static unsigned int policy_get(const LosTaskCB *selected,SchedParam *param)
{
    require(phase==4 && depth==1 && selected==&task && selected->ops==&ops && param!=0,106);
    require(param->policy==0 && param->basePrio==0 && param->priority==0 && param->timeSlice==0 && param->runTimeUs==0 && param->deadlineUs==0 && param->periodUs==0,106);
    phase=5;++callbacks;
    const struct checkpoint_event *event=consume(5,selected->id);
    require(event->written==1 && event->policy<=UINT16_MAX,106);
    param->policy=(uint16_t)event->policy;return event->raw;
}
unsigned int LOS_GetCurrProcessID(void) { complete(3,107); }
int LOS_GetProcessScheduler(int id,int *policy,void *param)
{ (void)id;(void)policy;(void)param;complete(3,107); }
void replay_fault(void) { osrec_result[0]=UINT32_C(0x4f535243);osrec_result[1]=10;complete(3,255); }
void replay_main(void)
{
    for(unsigned i=0;i<32;++i) osrec_result[i]=0;
    osrec_result[0]=UINT32_C(0x4f535243);osrec_result[1]=10;osrec_result[2]=1;
    for(invocation=0;invocation<4;++invocation) {
        const struct checkpoint_call *call=&checkpoint_calls[invocation];phase=0;
        require(call->flag==UINT32_MAX && depth==0,108);
        uint32_t raw=(uint32_t)SysSchedGetScheduler((int32_t)call->id,(int32_t)call->flag);
        osrec_result[14+2*invocation]=raw;osrec_result[15+2*invocation]=cursor;
        require(raw==call->raw,10+invocation);
        require(depth==0 && phase==(invocation==1 ? 1U : 6U),108);
        osrec_result[4]=invocation+1;
    }
    require(cursor==CHECKPOINT_EVENTS && bounds_checks==4 && lookups==3 && permissions==3 && callbacks==1 && locks==3 && unlocks==3,4);
    invocation=3;complete(2,0);
}
