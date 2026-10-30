/* ABI 7: source-pinned getpriority with embedded dependency outcomes. */
#include <stdint.h>
#include "getpriority_checkpoint.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static uint32_t cursor,invocation,pid_queries,priority_queries;
extern int SysGetProcessPriority(int which,int who);
__attribute__((noreturn)) static void complete(uint32_t status,uint32_t error)
{
    osrec_result[3]=error; osrec_result[5]=cursor; osrec_result[6]=CHECKPOINT_EVENTS;
    osrec_result[7]=6; osrec_result[8]=invocation;
    osrec_result[9]=pid_queries; osrec_result[10]=priority_queries; osrec_result[26]=96;
    __asm__ volatile("dmb sy" ::: "memory");
    osrec_result[2]=status;
    __asm__ volatile("dsb sy" ::: "memory");
    for (;;) __asm__ volatile("b ." ::: "memory");
}
static void require(int condition,uint32_t error) { if(!condition) complete(3,error); }
static uint32_t consume(uint32_t kind,uint32_t which,uint32_t who)
{
    require(cursor<CHECKPOINT_EVENTS,1);
    const struct checkpoint_event *event=&checkpoint_events[cursor];
    require(event->invocation==invocation,2);
    require(event->kind==kind && event->which==which && event->who==who,3);
    ++cursor; return event->raw;
}
unsigned int LOS_GetCurrProcessID(void) { ++pid_queries; return consume(1,0,0); }
int OsGetProcessPriority(int which,int who)
{
    ++priority_queries;
    return (int32_t)consume(2,(uint32_t)which,(uint32_t)who);
}
void replay_fault(void) { osrec_result[0]=UINT32_C(0x4f535243); osrec_result[1]=7; complete(3,255); }
void replay_main(void)
{
    for(unsigned i=0;i<32;++i) osrec_result[i]=0;
    osrec_result[0]=UINT32_C(0x4f535243); osrec_result[1]=7; osrec_result[2]=1;
    cursor=pid_queries=priority_queries=0;
    for(invocation=0;invocation<6;++invocation) {
        const struct checkpoint_call *call=&checkpoint_calls[invocation];
        uint32_t raw=(uint32_t)SysGetProcessPriority((int32_t)call->which,(int32_t)call->who);
        osrec_result[14+2*invocation]=raw; osrec_result[15+2*invocation]=cursor;
        require(raw==call->raw,10+invocation);
        osrec_result[4]=invocation+1;
    }
    require(cursor==CHECKPOINT_EVENTS && pid_queries==4 && priority_queries==6,4);
    invocation=5; complete(2,0);
}
