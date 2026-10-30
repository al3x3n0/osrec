/* ABI 6: effective credentials with modeled scheduler locking. */
#include <stdint.h>
#include "credentials_model.h"
#include "credentials_checkpoint.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
#include "entry_reconstruction.h"
static uint32_t depth,locks,unlocks,accesses;
extern int SysGetEffUserID(void);
extern int SysGetEffGID(void);
__attribute__((noreturn)) static void complete(uint32_t status,uint32_t error)
{
    osrec_result[3]=error;
    osrec_result[7]=locks; osrec_result[8]=unlocks; osrec_result[9]=accesses; osrec_result[10]=depth;
    __asm__ volatile("dmb sy" ::: "memory");
    osrec_result[2]=status;
    __asm__ volatile("dsb sy" ::: "memory");
    for (;;) __asm__ volatile("b ." ::: "memory");
}
UINT32 osrec_credentials_lock(void)
{
    if(depth) complete(3,1);
    depth=1; ++locks; return UINT32_C(0x51a7);
}
void osrec_credentials_unlock(UINT32 token)
{
    if(depth!=1 || token!=UINT32_C(0x51a7)) complete(3,2);
    depth=0; ++unlocks;
}
User *OsCurrUserGet(void)
{
    if(depth!=1) complete(3,3);
    ++accesses; return osrec_bound_OsCurrUserGet;
}
void replay_fault(void) { osrec_result[0]=UINT32_C(0x4f535243); osrec_result[1]=6; complete(3,255); }
void replay_main(void)
{
    for(unsigned i=0;i<32;++i) osrec_result[i]=0;
    osrec_result[0]=UINT32_C(0x4f535243); osrec_result[1]=6; osrec_result[2]=1;
    depth=locks=unlocks=accesses=0; osrec_result[11]=4; osrec_result[12]=0; /* Process ID is outside the discovered footprint. */
    for(unsigned i=0;i<4;++i) {
        if(!osrec_restore(i)) complete(3,40+i);
        uint32_t number=checkpoint_calls[i].number;
        if(number!=(i&1 ? 202U : 201U)) complete(3,4);
        uint32_t raw=(uint32_t)(number==201 ? SysGetEffUserID() : SysGetEffGID());
        osrec_result[number==201 ? 5 : 6]=raw;
        osrec_result[14+2*i]=number; osrec_result[15+2*i]=raw; osrec_result[22]=i;
        if(raw!=checkpoint_calls[i].raw) complete(3,10+i);
        if(depth || locks!=i+1 || unlocks!=i+1 || accesses!=i+1) complete(3,20+i);
        if(!osrec_state_unchanged(i)) complete(3,30+i);
        osrec_result[4]=i+1;
    }
    complete(2,0);
}
