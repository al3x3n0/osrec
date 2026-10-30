/* Single-core ARMv7-A replay: only embedded state and ordinary RAM are used.
 * The target testbench observes the result record; no guest I/O or service call.
 */
#include <stdint.h>
#include "umask_model.h"
#include "checkpoint.h"

/* 32 little-endian u32 words at 0x40000000:
 * magic, version, status, error, completed calls, initial/final mask,
 * lock/unlock/access counts, six pairs of actual return/post-mask, reserved.
 * Status: 0 uninitialized, 1 running, 2 passed, 3 failed. Written last.
 */
volatile uint32_t osrec_result[32] __attribute__((section(".result"), aligned(16)));
static struct osrec_process process;
static uint32_t locked, locks, unlocks, accesses;
extern uint32_t SysUmask(uint32_t mask);

__attribute__((noreturn)) static void complete(uint32_t status, uint32_t error)
{
    osrec_result[3]=error;
    osrec_result[6]=process.umask;
    osrec_result[7]=locks; osrec_result[8]=unlocks; osrec_result[9]=accesses;
    __asm__ volatile("dmb sy" ::: "memory");
    osrec_result[2]=status;
    __asm__ volatile("dsb sy" ::: "memory");
    for (;;) __asm__ volatile("b ." ::: "memory");
}
void replay_fault(void) { osrec_result[0]=UINT32_C(0x4f535243); osrec_result[1]=1; complete(3,255); }
static void require(int condition,uint32_t error) { if(!condition) complete(3,error); }
void OsrecSchedulerLock(uint32_t *saved)
{
    require(!locked,1); *saved=UINT32_C(0x13579bdf); locked=1; ++locks;
}
void OsrecSchedulerUnlock(uint32_t saved)
{
    require(locked && saved==UINT32_C(0x13579bdf),2); locked=0; ++unlocks;
}
struct osrec_process *OsCurrProcessGet(void)
{
    require(locked,3); ++accesses; return &process;
}
void replay_main(void)
{
    for(unsigned i=0;i<32;++i) osrec_result[i]=0;
    osrec_result[0]=UINT32_C(0x4f535243); osrec_result[1]=1;
    osrec_result[5]=checkpoint_initial_mask;
    osrec_result[2]=1;
    process.umask=checkpoint_initial_mask;
    for(unsigned i=0;i<6;++i) {
        require(process.umask==checkpoint_calls[i].before,10+i);
        uint32_t raw=SysUmask(checkpoint_calls[i].argument);
        osrec_result[10+2*i]=raw; osrec_result[11+2*i]=process.umask;
        require(raw==checkpoint_calls[i].raw && process.umask==checkpoint_calls[i].after,20+i);
        require(!locked && locks==i+1 && unlocks==i+1 && accesses==2*(i+1),30+i);
        osrec_result[4]=i+1;
    }
    complete(2,0);
}
