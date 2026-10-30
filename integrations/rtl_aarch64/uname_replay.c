#include "uname_model.h"
#include "uname_checkpoint.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static uint32_t invocation,cursor,providers,inputs,outputs,copied,verified;
static unsigned char witness[392];
static void stop(void) {for (;;) __asm__ volatile("wfe");}
static void fail(uint32_t error) {
    osrec_result[0]=0x4f535243;osrec_result[1]=UNAME_ABI;osrec_result[3]=error;
    osrec_result[2]=3;stop();
}
void replay_fault(void) {fail(99);}
static const struct uname_event *event(uint32_t kind,uint32_t argument) {
    if(cursor>=UNAME_EVENT_COUNT)fail(1);
    const struct uname_event *e=&uname_events[cursor++];
    if(e->invocation!=invocation || e->kind!=kind || e->argument!=argument || e->size!=390 || e->mode!=0x113)fail(2);
    return e;
}
size_t LOS_ArchCopyFromUser(void *out,const void *in,size_t size) {
    uint32_t kind=in==witness ? 0 : in==NULL ? 1 : in==(void *)(uintptr_t)1 ? 2 : 3;
    const struct uname_event *e=event(1,kind);++inputs;
    if(size!=390 || !out || kind>2 || e->raw>390 || (kind && e->raw!=390))fail(3);
    if(!kind)for(unsigned j=0;j<390-e->raw;++j) {
        if(((const unsigned char *)in)[j]!=e->memory[j])fail(4);
        ((unsigned char *)out)[j]=e->memory[j];
    }
    copied+=390-e->raw;return e->raw;
}
int uname(struct utsname *out) {
    const struct uname_event *e=event(2,0);++providers;
    if(!out || (e->raw && e->raw!=UINT32_C(0xfffffffb)))fail(5);
    for(unsigned j=0;j<390;++j) {
        if(((unsigned char *)out)[j]!=uname_calls[invocation].before[j])fail(6);
        ((unsigned char *)out)[j]=e->memory[j];
    }
    return (int32_t)e->raw;
}
size_t LOS_ArchCopyToUser(void *out,const void *in,size_t size) {
    const struct uname_event *e=event(3,0);++outputs;
    if(out!=witness || !in || size!=390 || e->raw>390)fail(7);
    for(unsigned j=0;j<390;++j) {
        if(((const unsigned char *)in)[j]!=e->memory[j])fail(8);
        if(j<390-e->raw)((unsigned char *)out)[j]=((const unsigned char *)in)[j];
    }
    copied+=390-e->raw;return e->raw;
}
void replay_main(void) {
    osrec_result[0]=0x4f535243;osrec_result[1]=UNAME_ABI;osrec_result[2]=1;
    for(invocation=0;invocation<UNAME_CALL_COUNT;++invocation) {
        const struct uname_call *c=&uname_calls[invocation];
        if(c->number!=122 || c->pointer_kind>2 || c->error)fail(9);
        for(unsigned j=0;j<390;++j)witness[j]=c->before[j];
        witness[390]=0x5a;witness[391]=0xc3;
        struct utsname *out=c->pointer_kind==0 ? (struct utsname *)witness : c->pointer_kind==1 ? NULL : (struct utsname *)(uintptr_t)1;
        int ret=SysUname(out);osrec_result[10+invocation]=(uint32_t)ret;
        osrec_result[10+UNAME_CALL_COUNT+invocation]=0;
        if((uint32_t)ret!=c->raw)fail(10);
        for(unsigned j=0;j<390;++j)if(witness[j]!=c->after[j])fail(11);
        if(witness[390]!=0x5a || witness[391]!=0xc3)fail(12);
        ++verified;osrec_result[4]=invocation+1;
    }
    if(cursor!=UNAME_EVENT_COUNT || providers!=UNAME_PROVIDERS || inputs!=UNAME_CALL_COUNT || outputs!=UNAME_OUTPUTS || copied!=UNAME_COPIED)fail(13);
    osrec_result[5]=providers;osrec_result[6]=inputs;osrec_result[7]=outputs;
    osrec_result[8]=copied;osrec_result[9]=cursor;osrec_result[10+2*UNAME_CALL_COUNT]=UNAME_CALL_COUNT;
    osrec_result[11+2*UNAME_CALL_COUNT]=122;osrec_result[12+2*UNAME_CALL_COUNT]=390;osrec_result[30]=verified;
    __asm__ volatile("dsb sy" ::: "memory");osrec_result[2]=2;stop();
}
