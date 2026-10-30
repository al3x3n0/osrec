#include "slice_context.h"
#include "slice_layout.h"
#include "slice_dispatch.h"
#include "capture.h"
#include "osrec/syscall_slice.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static struct osrec_kernel_context contexts[2],snapshot;
static struct osrec_slice_session sessions[2];
static unsigned char memory[2][16],memory_snapshot[16];
static struct osrec_user_region regions[2];
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(uint32_t code){osrec_result[3]=code;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
static void copy(void *out,const void *in,size_t n){for(size_t i=0;i<n;++i)((unsigned char *)out)[i]=((const unsigned char *)in)[i];}
static void same(const void *a,const void *b,size_t n){for(size_t i=0;i<n;++i)if(((const unsigned char *)a)[i]!=((const unsigned char *)b)[i])fail(10);}
static struct osrec_slice_invocation invocation(unsigned s,unsigned i)
{
    return (struct osrec_slice_invocation){i,FIXTURE_NUMBER,{fixture_operations[i],fixture_arguments[i],regions[s].user_address,0,0,0},{&regions[s],1}};
}
static void execute(unsigned s,unsigned i)
{
    struct osrec_slice_invocation in=invocation(s,i);struct osrec_slice_result result;
    if(osrec_slice_execute(&sessions[s],&in,&result) || result.ordinal!=i || sessions[s].next!=i+1)fail(1);
    ++osrec_result[17];
    if((uint64_t)result.raw!=fixture_values[i+1])fail(2);++osrec_result[11];
    for(unsigned j=0;j<16;++j)if(memory[s][j]!=(j<8 ? (unsigned char)(fixture_values[i+1]>>(8*j)) : 0xa5))fail(3);
    ++osrec_result[12];++osrec_result[7];++osrec_result[4];
}
static void finish(unsigned s)
{
    if(osrec_slice_finish(&sessions[s]))fail(4);
    struct osrec_slice_invocation in=invocation(s,FIXTURE_CALLS-1);struct osrec_slice_result result;
    if(osrec_slice_execute(&sessions[s],&in,&result)!=OSREC_SLICE_COMPLETE)fail(5);
    ++osrec_result[6];++osrec_result[18];
}
void replay_main(void)
{
    osrec_result[0]=0x4f535243;osrec_result[1]=26;osrec_result[2]=1;
    for(unsigned s=0;s<2;++s){
        for(unsigned j=0;j<16;++j)memory[s][j]=j<8 ? 0 : 0xa5;
        regions[s]=(struct osrec_user_region){UINT64_C(0x10000000000)+(uint64_t)s*0x1000,memory[s],16,3,1};
        if(osrec_slice_session_init(&sessions[s],&osrec_kernel_adapter,&contexts[s],sizeof(contexts[s])))fail(6);
    }
    for(unsigned i=0;i<4;++i){
        struct osrec_slice_invocation in=invocation(0,0);struct osrec_slice_result result;
        if(i==0)in.ordinal=1;if(i==1)in.number=51;if(i==2)in.args[1]=5;if(i==3)in.args[2]=0;
        copy(&snapshot,&contexts[0],sizeof(snapshot));copy(memory_snapshot,memory[0],16);
        if(osrec_slice_execute(&sessions[0],&in,&result)!=OSREC_SLICE_BAD_INPUT || sessions[0].next || sessions[0].poisoned)fail(7);
        same(&snapshot,&contexts[0],sizeof(snapshot));same(memory_snapshot,memory[0],16);++osrec_result[10];
    }
    for(unsigned i=0;i<FIXTURE_CALLS;++i)for(unsigned s=0;s<2;++s){
        copy(&snapshot,&contexts[1-s],sizeof(snapshot));copy(memory_snapshot,memory[1-s],16);execute(s,i);
        same(&snapshot,&contexts[1-s],sizeof(snapshot));same(memory_snapshot,memory[1-s],16);++osrec_result[8];
    }
    finish(0);finish(1);
    if(osrec_slice_session_restore(&sessions[0]) || sessions[0].next || contexts[0].calls || contexts[0].head || contexts[0].tail || contexts[0].nodes[0].live || contexts[0].nodes[1].live)fail(8);
    ++osrec_result[9];
    for(unsigned i=0;i<FIXTURE_CALLS;++i)execute(0,i);
    finish(0);
    osrec_result[5]=FIXTURE_CALLS;osrec_result[13]=64;osrec_result[14]=OSREC_CONTEXT_FUNCTIONS;osrec_result[15]=OSREC_STATE_OBJECTS;osrec_result[16]=OSREC_SLICE_ABI;
    osrec_result[2]=2;stop();
}
