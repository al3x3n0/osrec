#include "osrec_application.h"
_Alignas(8) unsigned char app_output[16]={0,0,0,0,0,0,0,0,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5};
uint64_t app_returns[6],app_count,app_failed;
void osrec_application_main(void)
{
    const uint64_t numbers[6]={UINT64_C(0x100000051),UINT64_C(0x100000052),UINT64_C(0x100000051),UINT64_C(0x100000052),UINT64_C(0x100000051),UINT64_C(0x100000052)};
    const uint64_t deltas[6]={UINT64_C(0x100000005),UINT64_C(0xfffffffffffffffd),9,UINT64_C(0xfffffffeffffffff),UINT64_C(0x200000003),UINT64_C(0xfffffffffffffff9)};
    for(unsigned i=0;i<6;++i){
        uint64_t raw=(uint64_t)(i<2 ? osrec_app_syscall_prefix(numbers[i],deltas[i],(uintptr_t)app_output,0,0,0,0) : osrec_app_syscall(numbers[i],deltas[i],(uintptr_t)app_output,0,0,0,0));
        app_returns[i]=raw;++app_count;
        for(unsigned j=0;j<16;++j)app_failed|=app_output[j]!=(j<8 ? (unsigned char)(raw>>(8*j)) : 0xa5);
    }
}
