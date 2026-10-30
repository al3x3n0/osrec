/* Result ABI 4: common five-word prefix, calls/events/errno/file count,
 * four (raw,user return,user errno,recognized) rows, final cursors and 8 bytes.
 */
#include <stdint.h>
volatile uint32_t osrec_result[32] __attribute__((section(".result"), aligned(16)));
__attribute__((noreturn)) void replay_complete(uint32_t status,uint32_t error)
{
    osrec_result[3]=error;
    __asm__ volatile("dmb sy" ::: "memory");
    osrec_result[2]=status;
    __asm__ volatile("dsb sy" ::: "memory");
    for (;;) __asm__ volatile("b ." ::: "memory");
}
void replay_fault(void)
{
    osrec_result[0]=UINT32_C(0x4f535243); osrec_result[1]=4; replay_complete(3,255);
}
