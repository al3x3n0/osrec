/* ABI 8 (short sessions) / ABI 30 (bounded result transcript). */
#include <stdint.h>
#include "entry_model.h"
#include "entry_reconstruction.h"
#include "entry_checkpoint.h"
#include "entry_adapter.h"
_Static_assert(OSREC_CHECKPOINT_CALLS>0 && OSREC_CHECKPOINT_CALLS<=256,"result record capacity");
#if OSREC_CHECKPOINT_CALLS > 7
#define OSREC_RESULT_ABI 30
#define OSREC_RESULT_WORDS (32+2*OSREC_CHECKPOINT_CALLS)
#define OSREC_CALL_WORD(i) (32+2*(i))
#define OSREC_RETURN_ERROR(i) (UINT32_C(0x10000)+(i))
#define OSREC_STATE_ERROR(i) (UINT32_C(0x20000)+(i))
#define OSREC_ENTRY_ERROR(i) (UINT32_C(0x30000)+(i))
#else
#define OSREC_RESULT_ABI 8
#define OSREC_RESULT_WORDS 32
#define OSREC_CALL_WORD(i) (10+2*(i))
#define OSREC_RETURN_ERROR(i) (10+(i))
#define OSREC_STATE_ERROR(i) (20+(i))
#define OSREC_ENTRY_ERROR(i) (40+(i))
#endif
volatile uint32_t osrec_result[OSREC_RESULT_WORDS] __attribute__((section(".result"),aligned(16)));
extern uint32_t osrec_invoke(uint32_t number);
__attribute__((noreturn)) static void complete(uint32_t status,uint32_t error)
{
    osrec_result[3]=error;
    __asm__ volatile("dmb sy" ::: "memory");
    osrec_result[2]=status;
    __asm__ volatile("dsb sy" ::: "memory");
    for (;;) __asm__ volatile("b ." ::: "memory");
}
void replay_fault(void) { osrec_result[0]=UINT32_C(0x4f535243); osrec_result[1]=OSREC_RESULT_ABI; complete(3,255); }
void replay_main(void)
{
    for(unsigned i=0;i<OSREC_RESULT_WORDS;++i) osrec_result[i]=0;
    osrec_result[0]=UINT32_C(0x4f535243);osrec_result[1]=OSREC_RESULT_ABI;osrec_result[2]=1;
    osrec_result[5]=OSREC_CHECKPOINT_CALLS;osrec_result[9]=OSREC_HAS_WRITE_EFFECTS;osrec_result[24]=OSREC_CONTINUOUS_REPLAY;
#if OSREC_CHECKPOINT_CALLS > 7
    osrec_result[10]=OSREC_CHECKPOINT_CALLS;osrec_result[11]=8;osrec_result[12]=128;osrec_result[13]=1;
#endif
    for(unsigned i=0;i<OSREC_CHECKPOINT_CALLS;++i) {
        if(!OSREC_CONTINUOUS_REPLAY || i==0) {
            if(!osrec_restore(i)) complete(3,1);
            ++osrec_result[6];
        }
#if OSREC_CONTINUOUS_REPLAY
        if(!osrec_entry_matches(i)) complete(3,OSREC_ENTRY_ERROR(i));
        ++osrec_result[25];
#endif
        uint32_t raw=osrec_invoke(checkpoint_calls[i].number);
        osrec_result[OSREC_CALL_WORD(i)]=checkpoint_calls[i].number;osrec_result[OSREC_CALL_WORD(i)+1]=raw;osrec_result[8]=i;
        if(raw!=checkpoint_calls[i].raw) complete(3,OSREC_RETURN_ERROR(i));
        if(!osrec_state_matches(i)) complete(3,OSREC_STATE_ERROR(i));
        ++osrec_result[7];osrec_result[4]=i+1;
    }
    complete(2,0);
}
