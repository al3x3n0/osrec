/* ABI 9: original process-mode syscall and embedded ordered dependency outcomes. */
#include <stdint.h>
#include "getscheduler_checkpoint.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static uint32_t cursor,invocation,pid_queries,scheduler_queries,policy_writes;
extern int SysSchedGetScheduler(int,int);
__attribute__((noreturn)) static void complete(uint32_t status,uint32_t error)
{
    osrec_result[3]=error;osrec_result[5]=cursor;osrec_result[6]=CHECKPOINT_EVENTS;
    osrec_result[7]=4;osrec_result[8]=invocation;
    osrec_result[9]=pid_queries;osrec_result[10]=scheduler_queries;
    osrec_result[11]=policy_writes;osrec_result[26]=157;
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
unsigned int LOS_GetCurrProcessID(void) { ++pid_queries;return consume(1,0)->raw; }
int LOS_GetProcessScheduler(int id,int *policy,void *param)
{
    require(policy!=0 && param==0,5);++scheduler_queries;
    const struct checkpoint_event *event=consume(2,(uint32_t)id);
    require(event->written==((int32_t)event->raw>=0),6);
    if(event->written) { *policy=(int32_t)event->policy;++policy_writes; }
    return (int32_t)event->raw;
}
void osrec_unsupported_task(void) { complete(3,7); }
void replay_fault(void) { osrec_result[0]=UINT32_C(0x4f535243);osrec_result[1]=9;complete(3,255); }
void replay_main(void)
{
    for(unsigned i=0;i<32;++i) osrec_result[i]=0;
    osrec_result[0]=UINT32_C(0x4f535243);osrec_result[1]=9;osrec_result[2]=1;
    for(invocation=0;invocation<4;++invocation) {
        const struct checkpoint_call *call=&checkpoint_calls[invocation];
        require(call->flag==0,8);
        uint32_t raw=(uint32_t)SysSchedGetScheduler((int32_t)call->id,(int32_t)call->flag);
        osrec_result[14+2*invocation]=raw;osrec_result[15+2*invocation]=cursor;
        require(raw==call->raw,10+invocation);osrec_result[4]=invocation+1;
    }
    require(cursor==CHECKPOINT_EVENTS && pid_queries==1 && scheduler_queries==4 && policy_writes==2,4);
    invocation=3;complete(2,0);
}
