#include "slice_context.h"
#include "slice_dispatch.h"
#include "slice_layout.h"
#include "osrec/aarch64_frame.h"
/* Saved app frames route mapped SVC sites into slices, without executing SVC. */
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
extern const struct osrec_slice_adapter osrec_kernel_adapter;
static _Alignas(OSREC_SLICE_STATE_ALIGNMENT) unsigned char state_storage[2][OSREC_SLICE_STATE_BYTES];
#define contexts ((struct osrec_kernel_context *)state_storage)
static struct osrec_kernel_context snapshot;
_Static_assert(sizeof(struct osrec_kernel_context)==OSREC_SLICE_STATE_BYTES,"generated state capacity");
static struct osrec_slice_session sessions[2];
static unsigned char memory[2][192],memory_snapshot[192];
static const unsigned char main_path[]="/dev/shm/osrec-file.bin",missing_path[]="/dev/shm/osrec-missing.bin";
static struct osrec_user_region regions[2][4];
static uint32_t successful,isolated,guards,rejected;
static unsigned char code[2][8]={{1,0,0,0xd4,0x1f,0x20,3,0xd5},{1,0,0,0xd4,0x1f,0x20,3,0xd5}};
static struct osrec_aarch64_frame frames[2],frame_snapshot;
static struct osrec_aarch64_syscall_abi abis[2];
static struct osrec_aarch64_site sites[2];
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(uint32_t error){osrec_result[0]=0x4f535243;osrec_result[1]=19;osrec_result[3]=error;osrec_result[4]=successful;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
static void copy(void *out,const void *in,size_t n){for(size_t i=0;i<n;++i)((unsigned char *)out)[i]=((const unsigned char *)in)[i];}
static void same(const void *a,const void *b,size_t n){for(size_t i=0;i<n;++i)if(((const unsigned char *)a)[i]!=((const unsigned char *)b)[i])fail(70);}
static struct osrec_slice_invocation invocation(unsigned session,unsigned index)
{
    const struct files_call *c=&files_calls[index];struct osrec_slice_invocation in={index,c->number,{0},{regions[session],4}};
    /* These stores represent app instructions between syscall sites, not kernel restoration. */
    copy(memory[session],c->buffer_before,192);
    for(unsigned j=0;j<5;++j){unsigned kind=osrec_argument_kind(c->number,j);uint32_t value=c->args[j];
        in.args[j]=kind==3 ? value==1 ? regions[session][0].user_address : value==2 ? UINT64_C(0xdead00000000) : 0 :
            kind==4 ? value==1 ? regions[session][1].user_address : value==2 ? regions[session][2].user_address : value==3 ? UINT64_C(0xdead00000000) : 0 : value;
    }
    return in;
}
static void prepare_frame(unsigned session,unsigned index)
{
    struct osrec_slice_invocation in=invocation(session,index);
    struct osrec_aarch64_frame *f=&frames[session];
    for(unsigned i=0;i<31;++i)f->x[i]=UINT64_C(0xa000000000000000)+(uint64_t)session*0x10000+index*0x100+i;
    f->sp=UINT64_C(0x30000000000)+(uint64_t)session*0x10000;
    f->pc=regions[session][3].user_address;f->pstate=UINT64_C(0xa0000000);
    for(unsigned i=0;i<32;++i){f->v[i].lo=UINT64_C(0x1234000000000000)+i+index;f->v[i].hi=UINT64_C(0xfedc000000000000)+session*0x100+i;}
    f->fpcr=0x400000;f->fpsr=0x800009f;
    f->tpidr_el0=UINT64_C(0x40000000000)+session*0x10000;
    f->tpidrro_el0=UINT64_C(0x50000000000)+session*0x10000;
    f->x[abis[session].number_register]=in.number;
    size_t recipe=0;
    while(recipe<abis[session].syscall_count && abis[session].syscalls[recipe].number!=in.number)++recipe;
    if(recipe==abis[session].syscall_count)fail(84);
    for(unsigned i=0;i<abis[session].syscalls[recipe].argument_count;++i)f->x[abis[session].argument_registers[i]]=in.args[i];
    sites[session]=(struct osrec_aarch64_site){index,f->pc,f->pc+4,in.memory};
}
static uint32_t enter(unsigned session,struct osrec_slice_result *result)
{
    return osrec_aarch64_syscall(&sessions[session],&abis[session],&frames[session],&sites[session],result);
}
static void execute(unsigned session,unsigned index)
{
    struct osrec_slice_result result;prepare_frame(session,index);copy(&frame_snapshot,&frames[session],sizeof(frame_snapshot));
    if(enter(session,&result)!=OSREC_SLICE_OK || result.raw!=(int64_t)(int32_t)files_calls[index].raw || result.ordinal!=index)fail(71);
    frame_snapshot.x[abis[session].result_register]=(uint64_t)result.raw;frame_snapshot.pc=sites[session].continuation_pc;
    same(&frame_snapshot,&frames[session],sizeof(frame_snapshot));
    same(memory[session],files_calls[index].buffer_after,192);++successful;++guards;
}
static void rejected_frame(uint32_t status)
{
    struct osrec_slice_result result;copy(&snapshot,&contexts[0],sizeof(snapshot));copy(&frame_snapshot,&frames[0],sizeof(frame_snapshot));
    uint64_t next=sessions[0].next;
    if(enter(0,&result)!=status || result.status!=status || sessions[0].next!=next)fail(72);
    same(&snapshot,&contexts[0],sizeof(snapshot));same(&frame_snapshot,&frames[0],sizeof(frame_snapshot));++rejected;
}
/* The generic frame transport must not inherit the captured OHOS scalar width. */
static void wide_restore(void *state){*(uint64_t *)state=0;}
static uint32_t wide_enter(void *state,const struct osrec_slice_invocation *in,struct osrec_slice_result *out)
{
    ++*(uint64_t *)state;out->raw=(int64_t)in->args[0];return OSREC_SLICE_OK;
}
static uint32_t wide_finish(const void *state){return *(const uint64_t *)state==1 ? OSREC_SLICE_OK : OSREC_SLICE_DIVERGED;}
static void wide_results(void)
{
    static const struct osrec_slice_adapter adapter={OSREC_SLICE_ABI,"synthetic-64-bit-frame-transport",8,8,1,wide_restore,wide_enter,wide_finish};
    const uint64_t values[2]={UINT64_C(0x100000003),UINT64_C(0x8000000000000001)};
    for(unsigned i=0;i<2;++i){
        uint64_t state;struct osrec_slice_session session;struct osrec_slice_result result;
        prepare_frame(0,0);struct osrec_aarch64_frame f=frames[0],expected;
        f.x[abis[0].argument_registers[0]]=values[i];expected=f;
        if(osrec_slice_session_init(&session,&adapter,&state,sizeof(state)) ||
           osrec_aarch64_syscall(&session,&abis[0],&f,&sites[0],&result) ||
           (uint64_t)result.raw!=values[i] || osrec_slice_finish(&session))fail(83);
        expected.x[abis[0].result_register]=values[i];expected.pc=sites[0].continuation_pc;
        same(&expected,&f,sizeof(f));
    }
}
static void invalid_frames(void)
{
    prepare_frame(0,0);frames[0].pc+=4;rejected_frame(OSREC_SLICE_BAD_INPUT);
    prepare_frame(0,0);sites[0].svc_pc++;frames[0].pc++;sites[0].continuation_pc++;rejected_frame(OSREC_SLICE_BAD_INPUT);
    prepare_frame(0,0);sites[0].continuation_pc+=4;rejected_frame(OSREC_SLICE_BAD_INPUT);
    prepare_frame(0,0);code[0][0]=0;rejected_frame(OSREC_SLICE_BAD_INPUT);code[0][0]=1;
    prepare_frame(0,0);sites[0].svc_pc=UINT64_C(0x90000000000);sites[0].continuation_pc=sites[0].svc_pc+4;frames[0].pc=sites[0].svc_pc;rejected_frame(OSREC_SLICE_BAD_INPUT);
    prepare_frame(0,0);regions[0][3].bytes=4;rejected_frame(OSREC_SLICE_BAD_INPUT);regions[0][3].bytes=8;
    prepare_frame(0,0);abis[0].number_register=31;rejected_frame(OSREC_SLICE_BAD_INPUT);abis[0]=osrec_application_abi;
    prepare_frame(0,0);abis[0].argument_registers[1]=abis[0].argument_registers[0];rejected_frame(OSREC_SLICE_BAD_INPUT);abis[0]=osrec_application_abi;
    prepare_frame(0,0);abis[0].abi=0;rejected_frame(OSREC_SLICE_BAD_INPUT);abis[0]=osrec_application_abi;
    prepare_frame(0,0);abis[0].syscalls=0;rejected_frame(OSREC_SLICE_BAD_INPUT);abis[0]=osrec_application_abi;
    prepare_frame(0,0);abis[0].syscall_count=4097;rejected_frame(OSREC_SLICE_BAD_INPUT);abis[0]=osrec_application_abi;
    static const struct osrec_aarch64_syscall_recipe bad_count[]={{5,7}},duplicates[]={{5,3},{5,3}};
    prepare_frame(0,0);abis[0].syscalls=bad_count;abis[0].syscall_count=1;rejected_frame(OSREC_SLICE_BAD_INPUT);abis[0]=osrec_application_abi;
    prepare_frame(0,0);abis[0].syscalls=duplicates;abis[0].syscall_count=2;rejected_frame(OSREC_SLICE_BAD_INPUT);abis[0]=osrec_application_abi;
    prepare_frame(0,0);frames[0].x[abis[0].number_register]=UINT64_MAX;rejected_frame(OSREC_SLICE_BAD_INPUT);
    prepare_frame(0,0);memory[0][0]^=1;rejected_frame(OSREC_SLICE_BAD_INPUT);
    prepare_frame(0,0);sites[0].ordinal=1;rejected_frame(OSREC_SLICE_BAD_INPUT);
    prepare_frame(0,0);regions[0][0].user_address=UINT64_MAX-1;rejected_frame(OSREC_SLICE_BAD_INPUT);regions[0][0].user_address=UINT64_C(0x10000000000);
    prepare_frame(0,0);unsigned char *saved=regions[0][0].image_address;regions[0][0].image_address=(unsigned char *)&frames[0];rejected_frame(OSREC_SLICE_BAD_INPUT);regions[0][0].image_address=saved;
    prepare_frame(0,0);sessions[0].active=1;rejected_frame(OSREC_SLICE_BUSY);sessions[0].active=0;
    prepare_frame(0,0);struct osrec_slice_result *aliased=(struct osrec_slice_result *)&frames[0];
    copy(&frame_snapshot,&frames[0],sizeof(frame_snapshot));
    if(enter(0,aliased)!=OSREC_SLICE_BAD_INPUT)fail(82);same(&frame_snapshot,&frames[0],sizeof(frame_snapshot));++rejected;
    /* Nonzero SVC immediates must pass the opcode mask too. */
    code[0][1]=0x24;
}
void replay_main(void)
{
    osrec_result[0]=0x4f535243;osrec_result[1]=19;osrec_result[2]=1;
    abis[0]=osrec_application_abi;
    abis[1]=(struct osrec_aarch64_syscall_abi){OSREC_AARCH64_FRAME_ABI,16,{10,11,12,13,14,15},17,osrec_application_abi.syscalls,osrec_application_abi.syscall_count};
    for(unsigned s=0;s<2;++s){uint64_t base=UINT64_C(0x10000000000)+(uint64_t)s*UINT64_C(0x10000000000);
        regions[s][0]=(struct osrec_user_region){base,memory[s],192,3,1};
        regions[s][1]=(struct osrec_user_region){base+0x1000,(unsigned char *)main_path,sizeof(main_path),1,2};
        regions[s][2]=(struct osrec_user_region){base+0x2000,(unsigned char *)missing_path,sizeof(missing_path),1,3};
        regions[s][3]=(struct osrec_user_region){base+0x3000,code[s],8,1,4};
        if(osrec_slice_session_init(&sessions[s],&osrec_kernel_adapter,&contexts[s],sizeof(contexts[s])))fail(73);
    }
    invalid_frames();wide_results();
    for(unsigned index=0;index<FILE_CALL_COUNT;++index){
        copy(&snapshot,&contexts[1],sizeof(snapshot));copy(memory_snapshot,memory[1],192);execute(0,index);
        same(&snapshot,&contexts[1],sizeof(snapshot));same(memory_snapshot,memory[1],192);++isolated;
        copy(&snapshot,&contexts[0],sizeof(snapshot));copy(memory_snapshot,memory[0],192);execute(1,index);
        same(&snapshot,&contexts[0],sizeof(snapshot));same(memory_snapshot,memory[0],192);++isolated;
    }
    if(osrec_slice_finish(&sessions[0]) || osrec_slice_finish(&sessions[1]))fail(74);
    struct osrec_slice_result result;prepare_frame(0,31);
    copy(&frame_snapshot,&frames[0],sizeof(frame_snapshot));
    if(enter(0,&result)!=OSREC_SLICE_COMPLETE)fail(75);same(&frame_snapshot,&frames[0],sizeof(frame_snapshot));
    if(osrec_slice_session_restore(&sessions[0]))fail(76);
    for(unsigned index=0;index<FILE_CALL_COUNT;++index){copy(&snapshot,&contexts[1],sizeof(snapshot));execute(0,index);same(&snapshot,&contexts[1],sizeof(snapshot));}
    if(osrec_slice_finish(&sessions[0]) || osrec_slice_finish(&sessions[1]))fail(77);
    osrec_result[4]=successful;osrec_result[5]=FILE_CALL_COUNT;osrec_result[6]=FILE_CALL_COUNT*3;osrec_result[7]=FILE_CALL_COUNT*2;osrec_result[8]=FILE_CALL_COUNT;
    osrec_result[9]=rejected;osrec_result[10]=isolated;osrec_result[11]=guards;osrec_result[12]=contexts[0].return_hash;osrec_result[13]=contexts[1].return_hash;osrec_result[14]=FILE_RETURN_HASH;
    osrec_result[15]=contexts[0].cursor+contexts[1].cursor;osrec_result[19]=1;osrec_result[20]=FILE_EVENT_COUNT;osrec_result[21]=successful;
    osrec_result[22]=contexts[0].length;osrec_result[23]=contexts[1].length;osrec_result[24]=(contexts[0].state[9]+contexts[0].state[12]+contexts[1].state[9]+contexts[1].state[12])==0;
    osrec_result[25]=regions[0][0].user_address>UINT32_MAX;osrec_result[26]=32;osrec_result[27]=2;osrec_result[28]=guards;osrec_result[29]=2;osrec_result[30]=3;osrec_result[31]=OSREC_AARCH64_FRAME_ABI;
    /* A divergence returns to the caller, poisons only this session, and requires restore. */
    if(osrec_slice_session_restore(&sessions[0]))fail(78);
    execute(0,0);contexts[0].state[0]=99;prepare_frame(0,1);copy(&frame_snapshot,&frames[0],sizeof(frame_snapshot));
    if(enter(0,&result)!=OSREC_SLICE_DIVERGED || result.diagnostic!=30 || !sessions[0].poisoned || sessions[0].active)fail(79);
    same(&frame_snapshot,&frames[0],sizeof(frame_snapshot));osrec_result[16]=1;
    if(enter(0,&result)!=OSREC_SLICE_POISONED)fail(80);same(&frame_snapshot,&frames[0],sizeof(frame_snapshot));osrec_result[17]=1;
    if(osrec_slice_session_restore(&sessions[0]) || sessions[0].next || sessions[0].poisoned || contexts[0].opens || contexts[0].cursor || contexts[0].process.vmSpace!=&contexts[0].space || osrec_slice_finish(&sessions[0])!=OSREC_SLICE_BAD_INPUT || osrec_slice_finish(&sessions[1]))fail(81);
    osrec_result[18]=1;__asm__ volatile("dsb sy" ::: "memory");osrec_result[2]=2;stop();
}
