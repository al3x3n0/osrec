#include "osrec_application.h"
_Alignas(8) unsigned char app_output[16]={0,0,0,0,0,0,0,0,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5};
uint64_t app_returns[6],app_count,app_failed;
void osrec_application_main(void)
{
    const uint64_t operations[6]={1,1,2,3,1,4};
    const uint64_t values[6]={UINT64_C(0x10000000b),UINT64_C(0x200000007),5,0,UINT64_C(0x300000009),0};
    for(unsigned i=0;i<6;++i){
        uint64_t raw=(uint64_t)osrec_app_GraphStep(operations[i],values[i],(uintptr_t)app_output);
        app_returns[i]=raw;++app_count;
        for(unsigned j=0;j<16;++j)app_failed|=app_output[j]!=(j<8 ? (unsigned char)(raw>>(8*j)) : 0xa5);
    }
}
