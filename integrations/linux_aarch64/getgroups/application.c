#include "osrec_application.h"
static const uint64_t numbers[112]={172,178,173,174,175,176,177,166,148,166,150,148,166,150,166,148,150,172,166,178,149,149,149,177,150,149,176,150,149,149,177,150,149,150,149,150,149,166,174,166,176,150,152,152,150,152,152,149,152,177,152,152,149,152,150,152,149,152,152,150,176,150,144,150,144,144,143,176,143,143,150,144,143,143,144,144,143,144,149,144,143,152,144,177,143,144,143,144,152,150,166,172,166,150,158,158,158,158,158,158,158,158,158,158,158,144,158,158,143,158,158,158};
static const uint64_t scalar[112][3]={
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
[58]={UINT64_MAX,UINT64_C(0),UINT64_C(0)},
[62]={UINT64_C(2001),UINT64_C(0),UINT64_C(0)},
[64]={UINT64_C(3000),UINT64_C(0),UINT64_C(0)},
[65]={UINT64_MAX,UINT64_C(0),UINT64_C(0)},
[66]={UINT64_C(2001),UINT64_C(3000),UINT64_C(0)},
[68]={UINT64_MAX,UINT64_MAX,UINT64_C(0)},
[69]={UINT64_C(4294969297),UINT64_C(2003),UINT64_C(0)},
[71]={UINT64_C(2003),UINT64_C(0),UINT64_C(0)},
[72]={UINT64_MAX,UINT64_C(2001),UINT64_C(0)},
[73]={UINT64_C(2003),UINT64_MAX,UINT64_C(0)},
[74]={UINT64_C(2003),UINT64_C(0),UINT64_C(0)},
[75]={UINT64_C(2001),UINT64_C(0),UINT64_C(0)},
[76]={UINT64_MAX,UINT64_C(2003),UINT64_C(0)},
[77]={UINT64_C(2003),UINT64_C(0),UINT64_C(0)},
[78]={UINT64_MAX,UINT64_MAX,UINT64_C(2001)},
[79]={UINT64_C(2003),UINT64_C(0),UINT64_C(0)},
[80]={UINT64_MAX,UINT64_C(2003),UINT64_C(0)},
[81]={UINT64_C(2001),UINT64_C(0),UINT64_C(0)},
[82]={UINT64_C(4294969297),UINT64_C(0),UINT64_C(0)},
[84]={UINT64_MAX,UINT64_C(8589934591),UINT64_C(0)},
[85]={UINT64_C(8589934591),UINT64_C(0),UINT64_C(0)},
[86]={UINT64_C(2001),UINT64_C(2001),UINT64_C(0)},
[87]={UINT64_C(2003),UINT64_C(0),UINT64_C(0)},
[88]={UINT64_C(2003),UINT64_C(0),UINT64_C(0)},
[90]={UINT64_C(63),UINT64_C(0),UINT64_C(0)},
[92]={UINT64_C(18),UINT64_C(0),UINT64_C(0)},
[95]={UINT64_C(3),UINT64_C(0),UINT64_C(0)},
[96]={UINT64_C(2),UINT64_C(0),UINT64_C(0)},
[97]={UINT64_MAX,UINT64_C(0),UINT64_C(0)},
[98]={UINT64_C(4),UINT64_C(0),UINT64_C(0)},
[99]={UINT64_C(3),UINT64_C(0),UINT64_C(0)},
[101]={UINT64_C(4294967299),UINT64_C(0),UINT64_C(0)},
[102]={UINT64_C(8589934591),UINT64_C(0),UINT64_C(0)},
[103]={UINT64_C(4),UINT64_C(0),UINT64_C(0)},
[104]={UINT64_C(3),UINT64_C(0),UINT64_C(0)},
[105]={UINT64_C(2001),UINT64_C(0),UINT64_C(0)},
[106]={UINT64_C(3),UINT64_C(0),UINT64_C(0)},
[107]={UINT64_C(8),UINT64_C(0),UINT64_C(0)},
[108]={UINT64_MAX,UINT64_MAX,UINT64_C(0)},
[109]={UINT64_C(4294967296),UINT64_C(0),UINT64_C(0)},
[110]={UINT64_C(3),UINT64_C(0),UINT64_C(0)}};
static const int indices[112][3]={
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
[61]={1,2,3},
[63]={1,2,3},
[70]={1,-1,3},
[89]={1,2,3},
[93]={1,2,3},
[94]={0,-1,0},
[95]={0,1,0},
[96]={0,1,0},
[97]={0,-1,0},
[98]={0,-1,0},
[99]={0,7,0},
[100]={0,-2,0},
[101]={0,1,0},
[102]={0,1,0},
[103]={0,1,0},
[104]={0,-2,0},
[106]={0,6,0},
[107]={0,0,0},
[109]={0,-1,0},
[110]={0,1,0},
[111]={0,-1,0}};
/* Last 32 bytes of a page, followed by one dedicated guard page. */
_Alignas(4096) uint32_t app_guard_storage[2048];
extern uint32_t app_words[8];
__asm__(".global app_words\n.type app_words,%object\n.set app_words,app_guard_storage+4064\n.size app_words,32\n");
uint64_t app_returns[112],app_count;
#ifdef OSREC_NATIVE_CAPTURE
void osrec_native_record(unsigned,uint64_t,const uint64_t *);
#endif
void osrec_application_main(void)
{
    for(unsigned i=0;i<112;++i){
        for(unsigned j=0;j<8;++j)app_words[j]=UINT32_C(0xa5a50000)+j;
        uint64_t args[3]={scalar[i][0],scalar[i][1],scalar[i][2]};
        if(numbers[i]==148 || numbers[i]==150)
            for(unsigned j=0;j<3;++j)args[j]=indices[i][j]==-1 ? 0 : indices[i][j]==-2 ? 1 : (uintptr_t)&app_words[indices[i][j]];
        if(numbers[i]==158)args[1]=indices[i][1]==-1 ? 0 : indices[i][1]==-2 ? 1 : (uintptr_t)&app_words[indices[i][1]];
        app_returns[i]=(uint64_t)(i<8 ? osrec_app_syscall_prefix(numbers[i],args[0],args[1],args[2],0,0,0) : osrec_app_syscall(numbers[i],args[0],args[1],args[2],0,0,0));
        ++app_count;
#ifdef OSREC_NATIVE_CAPTURE
        osrec_native_record(i,numbers[i],args);
#endif
    }
}
