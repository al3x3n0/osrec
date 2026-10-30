#include "osrec_application.h"
static const uint64_t numbers[62]={172,178,173,174,175,176,177,166,148,166,150,148,166,150,166,148,150,172,166,178,149,149,149,177,150,149,176,150,149,149,177,150,149,150,149,150,149,166,174,166,176,150,152,152,150,152,152,149,152,177,152,152,149,152,150,152,149,152,152,150,176,150};
static const uint64_t scalar[62][3]={
[7]={UINT64_C(63),UINT64_C(0),UINT64_C(0)},
[9]={UINT64_C(4294967807),UINT64_C(0),UINT64_C(0)},
[12]={UINT64_MAX,UINT64_C(0),UINT64_C(0)},
[14]={UINT64_C(2),UINT64_C(0),UINT64_C(0)},
[18]={UINT64_C(18),UINT64_C(0),UINT64_C(0)},
[20]={UINT64_C(3000),UINT64_MAX,UINT64_MAX},
[21]={UINT64_MAX,UINT64_MAX,UINT64_MAX},
[22]={UINT64_MAX,UINT64_C(2001),UINT64_MAX},
[25]={UINT64_C(4294969299),UINT64_C(2003),UINT64_C(2001)},
[28]={UINT64_MAX,UINT64_C(2002),UINT64_MAX},
[29]={UINT64_MAX,UINT64_C(2001),UINT64_MAX},
[32]={UINT64_C(2001),UINT64_C(2003),UINT64_C(2003)},
[34]={UINT64_MAX,UINT64_C(2001),UINT64_MAX},
[36]={UINT64_MAX,UINT64_MAX,UINT64_MAX},
[37]={UINT64_C(63),UINT64_C(0),UINT64_C(0)},
[39]={UINT64_C(18),UINT64_C(0),UINT64_C(0)},
[42]={UINT64_C(2003),UINT64_C(0),UINT64_C(0)},
[43]={UINT64_MAX,UINT64_C(0),UINT64_C(0)},
[45]={UINT64_C(3000),UINT64_C(0),UINT64_C(0)},
[46]={UINT64_C(2003),UINT64_C(0),UINT64_C(0)},
[47]={UINT64_MAX,UINT64_C(2001),UINT64_MAX},
[48]={UINT64_C(4294969299),UINT64_C(0),UINT64_C(0)},
[50]={UINT64_MAX,UINT64_C(0),UINT64_C(0)},
[51]={UINT64_C(2001),UINT64_C(0),UINT64_C(0)},
[52]={UINT64_C(2003),UINT64_C(2003),UINT64_C(2001)},
[53]={UINT64_C(2001),UINT64_C(0),UINT64_C(0)},
[55]={UINT64_C(2002),UINT64_C(0),UINT64_C(0)},
[56]={UINT64_MAX,UINT64_C(2003),UINT64_MAX},
[57]={UINT64_C(2003),UINT64_C(0),UINT64_C(0)},
[58]={UINT64_MAX,UINT64_C(0),UINT64_C(0)}};
static const int indices[62][3]={
[8]={1,2,3},
[10]={1,2,3},
[11]={1,-1,3},
[13]={-1,2,3},
[15]={1,1,1},
[16]={1,2,-2},
[24]={1,2,3},
[27]={1,2,3},
[31]={1,2,3},
[33]={1,2,-2},
[35]={1,2,3},
[41]={1,2,3},
[44]={1,2,3},
[54]={-1,2,3},
[59]={1,1,1},
[61]={1,2,3}};
_Alignas(8) uint32_t app_words[8];
uint64_t app_returns[62],app_count;
#ifdef OSREC_NATIVE_CAPTURE
void osrec_native_record(unsigned,uint64_t,const uint64_t *);
#endif
void osrec_application_main(void)
{
    for(unsigned i=0;i<62;++i){
        for(unsigned j=0;j<8;++j)app_words[j]=UINT32_C(0xa5a50000)+j;
        uint64_t args[3]={scalar[i][0],scalar[i][1],scalar[i][2]};
        if(numbers[i]==148 || numbers[i]==150)
            for(unsigned j=0;j<3;++j)args[j]=indices[i][j]==-1 ? 0 : indices[i][j]==-2 ? 1 : (uintptr_t)&app_words[indices[i][j]];
        app_returns[i]=(uint64_t)(i<8 ? osrec_app_syscall_prefix(numbers[i],args[0],args[1],args[2],0,0,0) : osrec_app_syscall(numbers[i],args[0],args[1],args[2],0,0,0));
        ++app_count;
#ifdef OSREC_NATIVE_CAPTURE
        osrec_native_record(i,numbers[i],args);
#endif
    }
}
