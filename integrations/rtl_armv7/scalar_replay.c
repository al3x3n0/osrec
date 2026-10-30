/* Result ABI 3: words 5..8 = entry PID, PID boundary calls, total calls,
 * last invocation; words 10..23 = seven (raw return bits, syscall number) pairs.
 * All computation, state and checks are embedded; completion uses only RAM.
 */
#include <stdint.h>
#include "checkpoint.h"
_Static_assert(sizeof(int)==4 && sizeof(unsigned int)==4, "32-bit scalar ABI");
volatile uint32_t osrec_result[32] __attribute__((section(".result"), aligned(16)));
static uint32_t current_pid, dependency_calls, invocation;
extern int SysSchedGetPriorityMax(int policy);
extern int SysSchedGetPriorityMin(int policy);
extern unsigned int SysGetPID(void);
__attribute__((noreturn)) static void complete(uint32_t status,uint32_t error)
{
    osrec_result[3]=error; osrec_result[5]=current_pid;
    osrec_result[6]=dependency_calls; osrec_result[7]=7; osrec_result[8]=invocation;
    __asm__ volatile("dmb sy" ::: "memory");
    osrec_result[2]=status;
    __asm__ volatile("dsb sy" ::: "memory");
    for (;;) __asm__ volatile("b ." ::: "memory");
}
void replay_fault(void) { osrec_result[0]=UINT32_C(0x4f535243); osrec_result[1]=3; complete(3,255); }
static void require(int condition,uint32_t error) { if(!condition) complete(3,error); }
unsigned int LOS_GetCurrProcessID(void) { ++dependency_calls; return current_pid; }
void replay_main(void)
{
    for(unsigned i=0;i<32;++i) osrec_result[i]=0;
    osrec_result[0]=UINT32_C(0x4f535243); osrec_result[1]=3; osrec_result[2]=1;
    current_pid=checkpoint_pid;
    for(invocation=0;invocation<7;++invocation) {
        const struct checkpoint_call *call=&checkpoint_calls[invocation];
        uint32_t raw;
        if(call->number==159) raw=(uint32_t)SysSchedGetPriorityMax((int32_t)call->argument);
        else if(call->number==160) raw=(uint32_t)SysSchedGetPriorityMin((int32_t)call->argument);
        else { require(call->number==20,1); raw=SysGetPID(); }
        osrec_result[10+2*invocation]=raw; osrec_result[11+2*invocation]=call->number;
        require(raw==call->raw,10+invocation);
        require(dependency_calls==(invocation==6 ? 1U : 0U),20+invocation);
        osrec_result[4]=invocation+1;
    }
    invocation=6; complete(2,0);
}
