#include "osrec_application.h"
/* The same application executes real Linux SVCs during capture and local
 * kernel-slice routes during replay. Three pointer indices use -1 for NULL. */
static const uint64_t numbers[20]={172,178,173,174,175,176,177,166,148,166,150,148,166,150,166,148,150,172,166,178};
static const uint64_t masks[20]={0,0,0,0,0,0,0,077,0,UINT64_C(0x1000001ff),0,0,UINT64_MAX,0,002,0,0,0,022,0};
static const int indices[20][3]={[8]={1,2,3},[10]={1,2,3},[11]={1,-1,3},[13]={-1,2,3},[15]={1,1,1},[16]={1,2,-2}};
_Alignas(8) uint32_t app_words[8];
uint64_t app_returns[20],app_count;
#ifdef OSREC_NATIVE_CAPTURE
void osrec_native_record(unsigned,uint64_t,const uint64_t *);
#endif
void osrec_application_main(void)
{
    for(unsigned i=0;i<20;++i){
        for(unsigned j=0;j<8;++j)app_words[j]=UINT32_C(0xa5a50000)+j;
        uint64_t args[3]={masks[i],0,0};
        if(numbers[i]==148 || numbers[i]==150)
            for(unsigned j=0;j<3;++j)args[j]=indices[i][j]==-1 ? 0 : indices[i][j]==-2 ? 1 : (uintptr_t)&app_words[indices[i][j]];
        app_returns[i]=(uint64_t)(i<8 ? osrec_app_syscall_prefix(numbers[i],args[0],args[1],args[2],0,0,0) : osrec_app_syscall(numbers[i],args[0],args[1],args[2],0,0,0));
        ++app_count;
#ifdef OSREC_NATIVE_CAPTURE
        osrec_native_record(i,numbers[i],args);
#endif
    }
}
