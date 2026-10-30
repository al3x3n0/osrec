#include "close_model.h"
#include "close_checkpoint.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static uint32_t invocation,cursor,detaches,providers,restores,releases,errno_reads,verified;
static uint32_t mapped,allocated,cloexec,live,error,pending_error;
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(uint32_t code){osrec_result[0]=0x4f535243;osrec_result[1]=15;osrec_result[3]=code;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
static const struct close_event *event(uint32_t kind,uint32_t arg,uint32_t arg2)
{
    if(cursor>=15)fail(1);
    const struct close_event *e=&close_events[cursor++];
    if(e->invocation!=invocation || e->kind!=kind || e->argument!=arg || e->argument2!=arg2 ||
        e->before_map!=mapped || e->before_allocated!=allocated || e->before_cloexec!=cloexec)fail(2);
    return e;
}
static void effect(const struct close_event *e,uint32_t raw)
{
    if(e->raw!=raw || e->error!=error || e->after_map!=mapped || e->after_allocated!=allocated || e->after_cloexec!=cloexec)fail(3);
}
int DisassociateProcessFd(int fd)
{
    const struct close_event *e=event(1,(uint32_t)fd,0);++detaches;
    uint32_t ret=fd==4 ? mapped : UINT32_MAX;
    if(fd==4 && mapped!=UINT32_MAX)mapped=UINT32_MAX;
    effect(e,ret);return (int32_t)ret;
}
int close(int fd)
{
    const struct close_event *e=event(2,(uint32_t)fd,0);++providers;
    int ret;
    if(invocation==0){if((uint32_t)fd!=CLOSE_SYSTEM_FD || !live)fail(4);error=5;ret=-1;}
    else if((uint32_t)fd==CLOSE_SYSTEM_FD && live){live=0;ret=0;}
    else {if(fd!=-1)fail(5);error=9;ret=-1;}
    pending_error=ret<0;effect(e,(uint32_t)ret);return ret;
}
void AssociateSystemFd(int fd,int system)
{
    const struct close_event *e=event(4,(uint32_t)fd,(uint32_t)system);++restores;
    if(!pending_error)fail(6);
    if(fd==4 && system>=0)mapped=(uint32_t)system;
    effect(e,0);
}
void FreeProcessFd(int fd)
{
    const struct close_event *e=event(5,(uint32_t)fd,0);++releases;
    if(pending_error || fd!=4 || live)fail(7);
    allocated=0;cloexec=0;mapped=UINT32_MAX;effect(e,0);
}
int get_errno(void)
{
    if(!pending_error || !error)fail(8);
    pending_error=0;++errno_reads;return (int)error;
}
void replay_main(void)
{
    osrec_result[0]=0x4f535243;osrec_result[1]=15;osrec_result[2]=1;
    mapped=CLOSE_SYSTEM_FD;allocated=1;cloexec=1;live=1;
    for(invocation=0;invocation<5;++invocation){
        const struct close_call *c=&close_calls[invocation];error=0;
        if(c->number!=6 || pending_error || c->before[0]!=mapped || c->before[1]!=allocated || c->before[2]!=cloexec)fail(9);
        int ret=SysClose((int32_t)c->fd);
        osrec_result[10+invocation]=(uint32_t)ret;osrec_result[15+invocation]=error;
        if((uint32_t)ret!=c->raw || error!=c->error || pending_error || c->after[0]!=mapped || c->after[1]!=allocated || c->after[2]!=cloexec || live!=(invocation==0))fail(10);
        ++verified;osrec_result[4]=invocation+1;
    }
    if(cursor!=15 || detaches!=5 || providers!=5 || restores!=4 || releases!=1 || errno_reads!=4 || mapped!=UINT32_MAX || allocated || cloexec || live)fail(11);
    osrec_result[5]=detaches;osrec_result[6]=providers;osrec_result[7]=restores;osrec_result[8]=releases;osrec_result[9]=cursor;
    osrec_result[20]=mapped;osrec_result[21]=allocated;osrec_result[22]=cloexec;osrec_result[23]=live;
    osrec_result[24]=5;osrec_result[25]=6;osrec_result[26]=CLOSE_SYSTEM_FD;osrec_result[29]=errno_reads;osrec_result[30]=verified;
    __asm__ volatile("dsb sy" ::: "memory");osrec_result[2]=2;stop();
}
