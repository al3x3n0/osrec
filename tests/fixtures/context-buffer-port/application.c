#include "osrec_application.h"
_Alignas(8) unsigned char app_output[16]={0,0,0,0,0,0,0,0,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5};
uint64_t app_returns[6],app_count,app_failed;
void osrec_application_main(void)
{
    for(unsigned i=0;i<6;++i){
        uint64_t raw=(uint64_t)osrec_app_syscall(UINT64_C(0x200000077),i,(uintptr_t)app_output,0,0,0,0);
        app_returns[i]=raw;++app_count;
        for(unsigned j=0;j<16;++j)app_failed|=app_output[j]!=(j<8 ? (unsigned char)(raw>>(8*j)) : 0xa5);
    }
}
