#include "rlimit_model.h"
#include "rlimit_checkpoint.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static uint32_t invocation,cursor,providers,copies,copied,verified;
static uint32_t witness[4];
static void stop(void) { for (;;) __asm__ volatile("wfe"); }
static void fail(uint32_t error)
{
    osrec_result[0]=0x4f535243;osrec_result[1]=12;osrec_result[3]=error;
    osrec_result[2]=3;stop();
}
void replay_fault(void) { fail(99); }
static const struct rlimit_event *event(uint32_t kind,uint32_t argument)
{
    if(cursor>=10) fail(1);
    const struct rlimit_event *e=&rlimit_events[cursor++];
    if(e->invocation!=invocation || e->kind!=kind || e->argument!=argument) fail(2);
    return e;
}
int getrlimit(int resource,struct rlimit *out)
{
    const struct rlimit_event *e=event(1,(uint32_t)resource);++providers;
    if(!out || e->bytes || (e->raw!=0 && e->raw!=UINT32_C(0xffffffea))) fail(3);
    if(!e->raw) {
        out->rlim_cur=((uint64_t)e->cur_hi<<32)|e->cur_lo;
        out->rlim_max=((uint64_t)e->max_hi<<32)|e->max_lo;
    }
    return (int32_t)e->raw;
}
size_t LOS_ArchCopyToUser(void *out,const void *in,size_t size)
{
    uint32_t kind=out==witness ? 0 : out==(void *)(uintptr_t)1 ? 2 : 1;
    const struct rlimit_event *e=event(2,kind);++copies;
    if(size!=16 || e->bytes!=16 || !in || e->raw>16 || (kind!=0 && e->raw!=16))fail(4);
    const unsigned char *source=in;
    for(unsigned i=0;i<16;++i) {
        uint32_t word=i<4 ? e->cur_lo : i<8 ? e->cur_hi : i<12 ? e->max_lo : e->max_hi;
        if(source[i]!=(unsigned char)(word>>(8*(i%4))))fail(5);
    }
    if(kind==0)for(unsigned i=0;i<16-e->raw;++i)((unsigned char *)out)[i]=source[i];
    copied+=16-e->raw;return e->raw;
}
void replay_main(void)
{
    osrec_result[0]=0x4f535243;osrec_result[1]=12;osrec_result[2]=1;
    for(invocation=0;invocation<6;++invocation) {
        const struct rlimit_call *call=&rlimit_calls[invocation];
        for(unsigned j=0;j<4;++j)witness[j]=call->before[j];
        unsigned long long *out=call->pointer_kind==0 ? (unsigned long long *)witness :
            call->pointer_kind==1 ? NULL : (unsigned long long *)(uintptr_t)1;
        if(call->number!=191 || call->pointer_kind>2 || call->error)fail(6);
        int ret=SysUgetrlimit((int32_t)call->resource,out);
        osrec_result[10+invocation]=(uint32_t)ret;osrec_result[16+invocation]=0;
        osrec_result[24+invocation]=call->resource;
        if((uint32_t)ret!=call->raw)fail(7);
        for(unsigned j=0;j<4;++j)if(witness[j]!=call->after[j])fail(8);
        ++verified;osrec_result[4]=invocation+1;
    }
    if(cursor!=10 || providers!=6 || copies!=4 || copied!=32)fail(9);
    osrec_result[5]=providers;osrec_result[6]=copies;osrec_result[7]=copied;
    osrec_result[8]=cursor;osrec_result[22]=6;osrec_result[23]=191;osrec_result[30]=verified;
    __asm__ volatile("dsb sy" ::: "memory");osrec_result[2]=2;stop();
}
