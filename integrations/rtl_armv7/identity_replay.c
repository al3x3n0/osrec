/* Freestanding identity queries with embedded ordered dependency outcomes.
 * Result ABI version 2: same magic/status/error/completed-call prefix as v1.
 * Words 5/6/7/8: consumed events, event count, call count, last invocation.
 * Words 10..23: seven (raw return bits, cumulative events consumed) pairs.
 */
#include <stdint.h>
#include "checkpoint.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"), aligned(16)));
static uint32_t cursor, invocation;
extern int SysGetUserID(void);
extern int SysGetGroupID(void);
extern int SysGetProcessGroupID(unsigned int pid);

__attribute__((noreturn)) static void complete(uint32_t status,uint32_t error)
{
    osrec_result[3]=error; osrec_result[5]=cursor;
    osrec_result[6]=CHECKPOINT_EVENTS; osrec_result[7]=7; osrec_result[8]=invocation;
    __asm__ volatile("dmb sy" ::: "memory");
    osrec_result[2]=status;
    __asm__ volatile("dsb sy" ::: "memory");
    for (;;) __asm__ volatile("b ." ::: "memory");
}
void replay_fault(void) { osrec_result[0]=UINT32_C(0x4f535243); osrec_result[1]=2; complete(3,255); }
static void require(int condition,uint32_t error) { if(!condition) complete(3,error); }
static uint32_t consume(uint32_t kind,uint32_t argument)
{
    require(cursor<CHECKPOINT_EVENTS,1);
    const struct checkpoint_event *event=&checkpoint_events[cursor];
    require(event->invocation==invocation,2);
    require(event->kind==kind && event->argument==argument,3);
    ++cursor; return event->raw;
}
unsigned int LOS_GetCurrProcessID(void) { return consume(1,0); }
int LOS_GetUserID(void) { return (int32_t)consume(2,0); }
int LOS_GetGroupID(void) { return (int32_t)consume(3,0); }
int LOS_GetProcessGroupID(unsigned int pid) { return (int32_t)consume(4,pid); }
void replay_main(void)
{
    for(unsigned i=0;i<32;++i) osrec_result[i]=0;
    osrec_result[0]=UINT32_C(0x4f535243); osrec_result[1]=2; osrec_result[2]=1;
    for(invocation=0;invocation<7;++invocation) {
        const struct checkpoint_call *call=&checkpoint_calls[invocation];
        int raw;
        if(call->number==199) raw=SysGetUserID();
        else if(call->number==200) raw=SysGetGroupID();
        else {
            require(call->number==65 || call->number==132,4);
            raw=SysGetProcessGroupID(call->argument);
        }
        osrec_result[10+2*invocation]=(uint32_t)raw;
        osrec_result[11+2*invocation]=cursor;
        require((uint32_t)raw==call->raw,10+invocation);
        osrec_result[4]=invocation+1;
    }
    require(cursor==CHECKPOINT_EVENTS,5);
    invocation=6; complete(2,0);
}
