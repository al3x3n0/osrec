#include "clock_model.h"
#include "clock_checkpoint.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
int clock_errno;
static uint32_t invocation,cursor,providers,copies,copied,errno_reads,verified;
static uint32_t witness[4];
static void stop(void) { for (;;) __asm__ volatile("wfe"); }
static void fail(uint32_t error)
{
    osrec_result[0]=0x4f535243;osrec_result[1]=11;osrec_result[3]=error;
    osrec_result[2]=3;stop();
}
void replay_fault(void) { fail(99); }
static const struct clock_event *event(uint32_t kind,uint32_t argument)
{
    if(cursor>=14) fail(1);
    const struct clock_event *e=&clock_events[cursor++];
    if(e->invocation!=invocation || e->kind!=kind || e->argument!=argument) fail(2);
    return e;
}
int get_errno(void) { ++errno_reads;return clock_errno; }
static int provider(uint32_t kind,clockid_t id,struct timespec *out)
{
    const struct clock_event *e=event(kind,(uint32_t)id);++providers;
    if(!out || e->bytes || (e->raw!=0 && e->raw!=UINT32_MAX)) fail(3);
    clock_errno=(int)e->error;
    if(!e->raw) {out->tv_sec=(int64_t)(((uint64_t)e->sec_hi<<32)|e->sec_lo);out->tv_nsec=(int32_t)e->nsec;}
    return (int32_t)e->raw;
}
int clock_gettime(clockid_t id,struct timespec *out) {return provider(1,id,out);}
int clock_getres(clockid_t id,struct timespec *out) {return provider(2,id,out);}
size_t LOS_ArchCopyToUser(void *out,const void *in,size_t size)
{
    uint32_t kind=out==witness ? 0 : out==(void *)(uintptr_t)1 ? 2 : 1;
    const struct clock_event *e=event(3,kind);++copies;
    if(size!=16 || e->bytes!=16 || !in || e->error || e->raw>16 || (kind!=0 && e->raw!=16)) fail(4);
    const unsigned char *source=in;
    for(unsigned i=0;i<16;++i) {
        uint32_t word=i<4 ? e->sec_lo : i<8 ? e->sec_hi : i<12 ? e->nsec : e->padding;
        if(source[i]!=(unsigned char)(word>>(8*(i%4)))) fail(5);
    }
    if(kind==0) for(unsigned i=0;i<16-e->raw;++i)((unsigned char *)out)[i]=source[i];
    copied+=16-e->raw;return e->raw;
}
void replay_main(void)
{
    osrec_result[0]=0x4f535243;osrec_result[1]=11;osrec_result[2]=1;
    for(invocation=0;invocation<10;++invocation) {
        const struct clock_call *call=&clock_calls[invocation];
        for(unsigned j=0;j<4;++j)witness[j]=call->before[j];clock_errno=0;
        struct timespec *out=call->pointer_kind==0 ? (struct timespec *)witness :
            call->pointer_kind==1 ? NULL : (struct timespec *)(uintptr_t)1;
        if(call->pointer_kind>2) fail(6);
        int ret;
        if(call->number==263)ret=SysClockGettime((clockid_t)call->id,out);
        else if(call->number==264)ret=SysClockGetres((clockid_t)call->id,out);
        else {fail(7);return;}
        osrec_result[10+invocation]=(uint32_t)ret;
        osrec_result[20+invocation]=(uint32_t)clock_errno;
        if((uint32_t)ret!=call->raw || (uint32_t)clock_errno!=call->error)fail(8);
        for(unsigned j=0;j<4;++j)if(witness[j]!=call->after[j])fail(9);
        ++verified;osrec_result[4]=invocation+1;
    }
    if(cursor!=14 || providers!=8 || copies!=6 || copied!=64 || errno_reads!=2)fail(10);
    osrec_result[5]=providers;osrec_result[6]=copies;osrec_result[7]=copied;
    osrec_result[8]=cursor;osrec_result[9]=10;osrec_result[30]=verified;osrec_result[31]=errno_reads;
    __asm__ volatile("dsb sy" ::: "memory");osrec_result[2]=2;stop();
}
