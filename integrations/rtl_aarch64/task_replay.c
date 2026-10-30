/* ABI 5: semantic process-parent and task reconstruction, no host services. */
#include <stdint.h>
#include "task_model.h"
#include "task_checkpoint.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static LosProcessCB parent,process;
static LosTaskCB task;
static uint32_t process_accesses,task_accesses;
extern unsigned int SysGetPPID(void);
extern unsigned int SysGetTid(void);
__attribute__((noreturn)) static void complete(uint32_t status,uint32_t error)
{
    osrec_result[3]=error;
    osrec_result[5]=process.processID; osrec_result[6]=parent.processID; osrec_result[7]=task.taskID;
    osrec_result[8]=process_accesses; osrec_result[9]=task_accesses;
    __asm__ volatile("dmb sy" ::: "memory");
    osrec_result[2]=status;
    __asm__ volatile("dsb sy" ::: "memory");
    for (;;) __asm__ volatile("b ." ::: "memory");
}
LosProcessCB *OsCurrProcessGet(void) { ++process_accesses; return &process; }
LosTaskCB *OsCurrTaskGet(void) { ++task_accesses; return &task; }
void replay_fault(void) { osrec_result[0]=UINT32_C(0x4f535243); osrec_result[1]=5; complete(3,255); }
void replay_main(void)
{
    for(unsigned i=0;i<32;++i) osrec_result[i]=0;
    osrec_result[0]=UINT32_C(0x4f535243); osrec_result[1]=5; osrec_result[2]=1;
    parent.processID=checkpoint_parent; parent.parentProcess=0;
    process.processID=checkpoint_pid; process.parentProcess=&parent;
    task.taskID=checkpoint_tid; process_accesses=task_accesses=0;
    osrec_result[10]=4;
    for(unsigned i=0;i<4;++i) {
        uint32_t number=checkpoint_calls[i].number;
        if(number!=(i&1 ? 224U : 64U)) complete(3,1);
        uint32_t raw;
        if(number==64) { raw=SysGetPPID(); ++osrec_result[11]; }
        else { raw=SysGetTid(); ++osrec_result[12]; }
        osrec_result[14+2*i]=number; osrec_result[15+2*i]=raw;
        osrec_result[22]=i;
        if(raw!=checkpoint_calls[i].raw) complete(3,10+i);
        if(process.parentProcess!=&parent || parent.parentProcess ||
           process.processID!=checkpoint_pid || parent.processID!=checkpoint_parent || task.taskID!=checkpoint_tid)
            complete(3,20+i);
        osrec_result[4]=i+1;
    }
    if(process_accesses!=2 || task_accesses!=2) complete(3,2);
    complete(2,0);
}
