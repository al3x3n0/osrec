#define OSREC_DUP_REPLAY 1
#include "dup_model.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static uint32_t invocation,cursor,lookups,allocations,references,associations,verified;
static uint32_t state[10];
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(uint32_t code){osrec_result[0]=0x4f535243;osrec_result[1]=16;osrec_result[3]=code;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
static const struct dup_event *event(uint32_t kind,uint32_t arg,uint32_t arg2)
{
    if(cursor>=12)fail(1);
    const struct dup_event *e=&dup_events[cursor++];
    if(e->invocation!=invocation || e->kind!=kind || e->argument!=arg || e->argument2!=arg2 || e->error)fail(2);
    for(unsigned j=0;j<10;++j)if(e->before[j]!=state[j])fail(3);
    return e;
}
static void effect(const struct dup_event *e,uint32_t raw)
{
    if(e->raw!=raw)fail(4);
    for(unsigned j=0;j<10;++j)if(e->after[j]!=state[j])fail(5);
}
int GetAssociatedSystemFd(int fd)
{
    const struct dup_event *e=event(1,(uint32_t)fd,0);++lookups;
    uint32_t ret=fd>=4 && fd<=6 ? state[3*(fd-4)] : UINT32_MAX;
    effect(e,ret);return (int32_t)ret;
}
int AllocProcessFd(void)
{
    const struct dup_event *e=event(2,0,0);++allocations;
    int ret=-1;
    if(invocation!=0){for(unsigned j=1;j<3;++j)if(!state[3*j+1]){state[3*j+1]=1;ret=(int)j+4;break;}}
    effect(e,(uint32_t)ret);return ret;
}
void files_refer(int fd)
{
    const struct dup_event *e=event(3,(uint32_t)fd,0);++references;
    if((uint32_t)fd!=DUP_SYSTEM_FD || state[9]>=3)fail(6);
    ++state[9];effect(e,0);
}
void AssociateSystemFd(int fd,int system)
{
    const struct dup_event *e=event(4,(uint32_t)fd,(uint32_t)system);++associations;
    if(fd<5 || fd>6 || (uint32_t)system!=DUP_SYSTEM_FD || !state[3*(fd-4)+1] || state[3*(fd-4)]!=UINT32_MAX)fail(7);
    state[3*(fd-4)]=(uint32_t)system;effect(e,0);
}
void replay_main(void)
{
    osrec_result[0]=0x4f535243;osrec_result[1]=16;osrec_result[2]=1;
    state[0]=DUP_SYSTEM_FD;state[1]=1;state[2]=1;state[3]=UINT32_MAX;state[6]=UINT32_MAX;state[9]=1;
    for(invocation=0;invocation<5;++invocation){
        const struct dup_call *c=&dup_calls[invocation];
        if(c->number!=41 || c->error)fail(8);
        for(unsigned j=0;j<10;++j)if(c->before[j]!=state[j])fail(9);
        int ret=SysDup((int32_t)c->fd);osrec_result[10+invocation]=(uint32_t)ret;osrec_result[15+invocation]=0;
        if((uint32_t)ret!=c->raw)fail(10);
        for(unsigned j=0;j<10;++j)if(c->after[j]!=state[j])fail(11);
        ++verified;osrec_result[4]=invocation+1;
    }
    if(cursor!=12 || lookups!=5 || allocations!=3 || references!=2 || associations!=2 || state[9]!=3)fail(12);
    uint32_t allocated=0,cloexec=0;
    for(unsigned j=0;j<3;++j){if(state[3*j]!=DUP_SYSTEM_FD)fail(13);allocated|=state[3*j+1]<<j;cloexec|=state[3*j+2]<<j;}
    if(allocated!=7 || cloexec!=1)fail(14);
    osrec_result[5]=lookups;osrec_result[6]=allocations;osrec_result[7]=references;osrec_result[8]=associations;osrec_result[9]=cursor;
    osrec_result[20]=state[9];osrec_result[21]=state[0];osrec_result[22]=state[3];osrec_result[23]=state[6];
    osrec_result[24]=allocated;osrec_result[25]=cloexec;osrec_result[26]=DUP_SYSTEM_LIMIT;osrec_result[27]=DUP_SYSTEM_FD;
    osrec_result[28]=5;osrec_result[29]=41;osrec_result[30]=verified;
    __asm__ volatile("dsb sy" ::: "memory");osrec_result[2]=2;stop();
}
