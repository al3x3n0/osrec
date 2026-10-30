#include "slice_context.h"
#include "slice_dispatch.h"
#include "capture.h"
uint32_t osrec_kernel_checkpoint_check(const void *,uint64_t);
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static struct osrec_kernel_context contexts[2],snapshot;
static struct osrec_slice_session sessions[2];
static unsigned char memory[2][32],memory_snapshot[32];
static struct osrec_user_region regions[2];
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(uint32_t n){osrec_result[3]=n;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
static void copy(void *out,const void *in,size_t n){for(size_t i=0;i<n;++i)((unsigned char *)out)[i]=((const unsigned char *)in)[i];}
static void same(const void *a,const void *b,size_t n){for(size_t i=0;i<n;++i)if(((const unsigned char *)a)[i]!=((const unsigned char *)b)[i])fail(10);}
static void seed(unsigned s,unsigned ordinal){for(unsigned i=0;i<8;++i)for(unsigned j=0;j<4;++j)memory[s][4*i+j]=(unsigned char)(linux_inputs[ordinal][i]>>(8*j));}
static struct osrec_slice_invocation invocation(unsigned s,unsigned i)
{
    const struct linux_observation *c=&linux_calls[i];
    struct osrec_slice_invocation in={i,c->number,{0},{&regions[s],1}};
    for(unsigned j=0;j<3;++j){uint64_t value=c->args[j];if(c->number==148 || c->number==150 || ((c->number==158 || c->number==159) && j==1) || ((c->number==91 || c->number==90) && j<2))value=value==UINT64_MAX ? 0 : value==UINT64_MAX-1 ? 1 : regions[s].user_address+value;in.args[j]=value;}
    return in;
}
static void execute(unsigned s,unsigned i)
{
    seed(s,i);struct osrec_slice_invocation in=invocation(s,i);struct osrec_slice_result out;
    if(osrec_slice_execute(&sessions[s],&in,&out) || out.ordinal!=i || sessions[s].next!=i+1)fail(1);
    ++osrec_result[17];
    if((uint64_t)out.raw!=linux_calls[i].raw)fail(2);++osrec_result[11];
    for(unsigned j=0;j<8;++j)for(unsigned k=0;k<4;++k)if(memory[s][4*j+k]!=(unsigned char)(linux_calls[i].words[j]>>(8*k)))fail(3);
    ++osrec_result[12];++osrec_result[7];++osrec_result[4];
}
static void finish(unsigned s)
{
    if(osrec_slice_finish(&sessions[s]))fail(4);
    struct osrec_slice_invocation in=invocation(s,LINUX_CALLS-1);struct osrec_slice_result out;
    if(osrec_slice_execute(&sessions[s],&in,&out)!=OSREC_SLICE_COMPLETE)fail(5);
    ++osrec_result[6];++osrec_result[18];
}
void replay_main(void)
{
    osrec_result[0]=0x4f535243;osrec_result[1]=26;osrec_result[2]=1;
    for(unsigned s=0;s<2;++s){seed(s,0);regions[s]=(struct osrec_user_region){UINT64_C(0x10000000000)+(uint64_t)s*0x1000,memory[s],32,3,1};if(osrec_slice_session_init(&sessions[s],&osrec_kernel_adapter,&contexts[s],sizeof(contexts[s])))fail(6);}
    for(unsigned i=0;i<4;++i){
        struct osrec_slice_invocation in=invocation(0,0);struct osrec_slice_result out;
        if(i==0)in.ordinal=1;if(i==1)in.number=9999;if(i==2)in.args[5]=1;if(i==3)in.memory.count=0;
        copy(&snapshot,&contexts[0],sizeof(snapshot));copy(memory_snapshot,memory[0],32);
        if(osrec_slice_execute(&sessions[0],&in,&out)!=OSREC_SLICE_BAD_INPUT || sessions[0].next || sessions[0].poisoned)fail(7);
        same(&snapshot,&contexts[0],sizeof(snapshot));same(memory_snapshot,memory[0],32);++osrec_result[10];
    }
    for(unsigned i=0;i<LINUX_CALLS;++i)for(unsigned s=0;s<2;++s){copy(&snapshot,&contexts[1-s],sizeof(snapshot));copy(memory_snapshot,memory[1-s],32);execute(s,i);same(&snapshot,&contexts[1-s],sizeof(snapshot));same(memory_snapshot,memory[1-s],32);++osrec_result[8];}
    finish(0);finish(1);
    if(osrec_slice_session_restore(&sessions[0]) || sessions[0].next || contexts[0].fs.umask!=LINUX_INITIAL_UMASK || osrec_kernel_checkpoint_check(&contexts[0],0))fail(8);
    ++osrec_result[9];for(unsigned i=0;i<LINUX_CALLS;++i)execute(0,i);finish(0);
    osrec_result[5]=LINUX_CALLS;osrec_result[13]=64;osrec_result[14]=OSREC_CONTEXT_FUNCTIONS;osrec_result[15]=OSREC_STATE_OBJECTS;osrec_result[16]=OSREC_SLICE_ABI;osrec_result[2]=2;stop();
}
