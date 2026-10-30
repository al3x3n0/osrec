#include "slice_context.h"
#include "slice_dispatch.h"
#include "slice_layout.h"
/* A simulated checkpointed app calls the returning slice API. No SVC or host services. */
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
extern const struct osrec_slice_adapter osrec_kernel_adapter;
static _Alignas(OSREC_SLICE_STATE_ALIGNMENT) unsigned char state_storage[2][OSREC_SLICE_STATE_BYTES];
#define contexts ((struct osrec_kernel_context *)state_storage)
static struct osrec_kernel_context snapshot;
_Static_assert(sizeof(struct osrec_kernel_context)==OSREC_SLICE_STATE_BYTES,"generated state capacity");
static struct osrec_slice_session sessions[2];
static unsigned char memory[2][192],memory_snapshot[192];
static const unsigned char main_path[]="/dev/shm/osrec-file.bin",missing_path[]="/dev/shm/osrec-missing.bin";
static struct osrec_user_region regions[2][3];
static uint32_t successful,isolated,guards,rejected;
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(uint32_t error){osrec_result[0]=0x4f535243;osrec_result[1]=18;osrec_result[3]=error;osrec_result[4]=successful;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
static void copy(void *out,const void *in,size_t n){for(size_t i=0;i<n;++i)((unsigned char *)out)[i]=((const unsigned char *)in)[i];}
static void same(const void *a,const void *b,size_t n){for(size_t i=0;i<n;++i)if(((const unsigned char *)a)[i]!=((const unsigned char *)b)[i])fail(70);}
static struct osrec_slice_invocation invocation(unsigned session,unsigned index)
{
    const struct files_call *c=&files_calls[index];struct osrec_slice_invocation in={index,c->number,{0},{regions[session],3}};
    /* These stores represent app instructions between syscall sites, not kernel restoration. */
    copy(memory[session],c->buffer_before,192);
    for(unsigned j=0;j<5;++j){unsigned kind=osrec_argument_kind(c->number,j);uint32_t value=c->args[j];
        in.args[j]=kind==3 ? value==1 ? regions[session][0].user_address : value==2 ? UINT64_C(0xdead00000000) : 0 :
            kind==4 ? value==1 ? regions[session][1].user_address : value==2 ? regions[session][2].user_address : value==3 ? UINT64_C(0xdead00000000) : 0 : value;
    }
    return in;
}
static void execute(unsigned session,unsigned index)
{
    struct osrec_slice_invocation in=invocation(session,index);struct osrec_slice_result result;
    if(osrec_slice_execute(&sessions[session],&in,&result)!=OSREC_SLICE_OK || result.raw!=(int64_t)(int32_t)files_calls[index].raw || result.ordinal!=index)fail(71);
    same(memory[session],files_calls[index].buffer_after,192);++successful;++guards;
}
static void reject(struct osrec_slice_invocation *in)
{
    struct osrec_slice_result result;copy(&snapshot,&contexts[0],sizeof(snapshot));
    if(osrec_slice_execute(&sessions[0],in,&result)!=OSREC_SLICE_BAD_INPUT || sessions[0].next || sessions[0].poisoned || sessions[0].active)fail(72);
    same(&snapshot,&contexts[0],sizeof(snapshot));++rejected;
}
void replay_main(void)
{
    osrec_result[0]=0x4f535243;osrec_result[1]=18;osrec_result[2]=1;
    for(unsigned s=0;s<2;++s){uint64_t base=UINT64_C(0x10000000000)+(uint64_t)s*UINT64_C(0x10000000000);
        regions[s][0]=(struct osrec_user_region){base,memory[s],192,3,1};
        regions[s][1]=(struct osrec_user_region){base+0x1000,(unsigned char *)main_path,sizeof(main_path),1,2};
        regions[s][2]=(struct osrec_user_region){base+0x2000,(unsigned char *)missing_path,sizeof(missing_path),1,3};
        if(osrec_slice_session_init(&sessions[s],&osrec_kernel_adapter,&contexts[s],sizeof(contexts[s])))fail(73);
    }
    struct osrec_slice_invocation in=invocation(0,0);in.ordinal=1;reject(&in);
    in=invocation(0,0);in.number=UINT64_MAX;reject(&in);
    in=invocation(0,0);in.args[1]|=UINT64_C(1)<<40;reject(&in);
    in=invocation(0,0);memory[0][0]^=1;reject(&in);
    in=invocation(0,0);regions[0][0].permissions=1;reject(&in);regions[0][0].permissions=3;
    in=invocation(0,0);uint64_t saved=regions[0][1].user_address;regions[0][1].user_address=regions[0][0].user_address;reject(&in);regions[0][1].user_address=saved;
    in=invocation(0,0);saved=regions[0][0].user_address;regions[0][0].user_address=UINT64_MAX-1;reject(&in);regions[0][0].user_address=saved;
    in=invocation(0,0);in.args[5]=1;reject(&in);
    for(unsigned index=0;index<FILE_CALL_COUNT;++index){
        copy(&snapshot,&contexts[1],sizeof(snapshot));copy(memory_snapshot,memory[1],192);execute(0,index);
        same(&snapshot,&contexts[1],sizeof(snapshot));same(memory_snapshot,memory[1],192);++isolated;
        copy(&snapshot,&contexts[0],sizeof(snapshot));copy(memory_snapshot,memory[0],192);execute(1,index);
        same(&snapshot,&contexts[0],sizeof(snapshot));same(memory_snapshot,memory[0],192);++isolated;
    }
    if(osrec_slice_finish(&sessions[0]) || osrec_slice_finish(&sessions[1]))fail(74);
    struct osrec_slice_result result;in=invocation(0,31);
    if(osrec_slice_execute(&sessions[0],&in,&result)!=OSREC_SLICE_COMPLETE)fail(75);
    if(osrec_slice_session_restore(&sessions[0]))fail(76);
    for(unsigned index=0;index<FILE_CALL_COUNT;++index){copy(&snapshot,&contexts[1],sizeof(snapshot));execute(0,index);same(&snapshot,&contexts[1],sizeof(snapshot));}
    if(osrec_slice_finish(&sessions[0]) || osrec_slice_finish(&sessions[1]))fail(77);
    osrec_result[4]=successful;osrec_result[5]=FILE_CALL_COUNT;osrec_result[6]=FILE_CALL_COUNT*3;osrec_result[7]=FILE_CALL_COUNT*2;osrec_result[8]=FILE_CALL_COUNT;
    osrec_result[9]=rejected;osrec_result[10]=isolated;osrec_result[11]=guards;osrec_result[12]=contexts[0].return_hash;osrec_result[13]=contexts[1].return_hash;osrec_result[14]=FILE_RETURN_HASH;
    osrec_result[15]=contexts[0].cursor+contexts[1].cursor;osrec_result[19]=1;osrec_result[20]=FILE_EVENT_COUNT;osrec_result[21]=successful;
    osrec_result[22]=contexts[0].length;osrec_result[23]=contexts[1].length;osrec_result[24]=(contexts[0].state[9]+contexts[0].state[12]+contexts[1].state[9]+contexts[1].state[12])==0;
    osrec_result[25]=regions[0][0].user_address>UINT32_MAX;osrec_result[26]=32;osrec_result[27]=2;osrec_result[28]=OSREC_CONTEXT_FUNCTIONS;osrec_result[29]=OSREC_STATE_OBJECTS;osrec_result[30]=3;osrec_result[31]=OSREC_SLICE_ABI;
    /* A divergence returns to the caller, poisons only this session, and requires restore. */
    if(osrec_slice_session_restore(&sessions[0]))fail(78);
    execute(0,0);contexts[0].state[0]=99;in=invocation(0,1);
    if(osrec_slice_execute(&sessions[0],&in,&result)!=OSREC_SLICE_DIVERGED || result.diagnostic!=30 || !sessions[0].poisoned || sessions[0].active)fail(79);
    osrec_result[16]=1;
    if(osrec_slice_execute(&sessions[0],&in,&result)!=OSREC_SLICE_POISONED)fail(80);osrec_result[17]=1;
    if(osrec_slice_session_restore(&sessions[0]) || sessions[0].next || sessions[0].poisoned || contexts[0].opens || contexts[0].cursor || contexts[0].process.vmSpace!=&contexts[0].space || osrec_slice_finish(&sessions[0])!=OSREC_SLICE_BAD_INPUT || osrec_slice_finish(&sessions[1]))fail(81);
    osrec_result[18]=1;__asm__ volatile("dsb sy" ::: "memory");osrec_result[2]=2;stop();
}
