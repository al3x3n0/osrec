#include "osrec_application.h"
static const uint64_t numbers[42]={172,178,173,174,175,176,177,166,148,166,150,148,166,150,166,148,150,172,166,178,
149,149,149,177,150,149,176,150,149,149,177,150,149,150,149,150,149,166,174,166,176,150};
static const uint64_t scalar[42][3]={
[7]={077},[9]={UINT64_C(0x1000001ff)},[12]={UINT64_MAX},[14]={002},[18]={022},
[20]={3000,UINT64_MAX,UINT64_MAX},[21]={UINT64_MAX,UINT64_MAX,UINT64_MAX},[22]={UINT64_MAX,2001,UINT64_MAX},
[25]={UINT64_C(0x1000007d3),2003,2001},[28]={UINT64_MAX,2002,UINT64_MAX},[29]={UINT64_MAX,2001,UINT64_MAX},
[32]={2001,2003,2003},[34]={UINT64_MAX,2001,UINT64_MAX},[36]={UINT64_MAX,UINT64_MAX,UINT64_MAX},[37]={077},[39]={022}};
static const int indices[42][3]={[8]={1,2,3},[10]={1,2,3},[11]={1,-1,3},[13]={-1,2,3},[15]={1,1,1},[16]={1,2,-2},
[24]={1,2,3},[27]={1,2,3},[31]={1,2,3},[33]={1,2,-2},[35]={1,2,3},[41]={1,2,3}};
_Alignas(8) uint32_t app_words[8];
uint64_t app_returns[42],app_count;
#ifdef OSREC_NATIVE_CAPTURE
void osrec_native_record(unsigned,uint64_t,const uint64_t *);
#endif
void osrec_application_main(void)
{
    for(unsigned i=0;i<42;++i){
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
