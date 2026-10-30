#include "slice_context.h"
#include "slice_dispatch.h"
#include "slice_layout.h"
#include "osrec/aarch64_gateway.h"
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
static struct osrec_user_region regions[2][5];
static uint32_t successful,isolated,guards,rejected;
static unsigned char code[2][12];
static _Alignas(16) unsigned char kernel_stacks[2][16384],app_stacks[2][1024];
static struct osrec_aarch64_gateway gateways[2];
static _Alignas(16) struct osrec_aarch64_frame container_seed,container_sample;
extern unsigned char osrec_app_route_a[],osrec_app_exit_a[],osrec_app_route_b[],osrec_app_exit_b[];
extern void osrec_probe_seed(const struct osrec_aarch64_frame *),osrec_probe_sample(struct osrec_aarch64_frame *);
static uint32_t stack_checks,control_checks;
struct controls {uint64_t v[8];};
static void controls(struct controls *c){
    __asm__ volatile("mrs %0,vbar_el1":"=r"(c->v[0]));
    __asm__ volatile("mrs %0,tpidr_el1":"=r"(c->v[1]));
    __asm__ volatile("mrs %0,cpacr_el1":"=r"(c->v[2]));
    __asm__ volatile("mrs %0,sp_el0":"=r"(c->v[3]));
    __asm__ volatile("mrs %0,elr_el1":"=r"(c->v[4]));
    __asm__ volatile("mrs %0,spsr_el1":"=r"(c->v[5]));
    __asm__ volatile("mrs %0,tpidr_el0":"=r"(c->v[6]));
    __asm__ volatile("mrs %0,tpidrro_el0":"=r"(c->v[7]));
}
static struct osrec_aarch64_frame frames[2],frame_snapshot;
static struct osrec_aarch64_syscall_abi abis[2];
static struct osrec_aarch64_site sites[2];
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(uint32_t error){osrec_result[0]=0x4f535243;osrec_result[1]=20;osrec_result[3]=error;osrec_result[4]=successful;osrec_result[2]=3;stop();}
void replay_fault(void){uint64_t esr,pc;__asm__ volatile("mrs %0,esr_el1\nmrs %1,elr_el1":"=r"(esr),"=r"(pc));osrec_result[16]=(uint32_t)esr;osrec_result[17]=(uint32_t)pc;fail(99);}
static void copy(void *out,const void *in,size_t n){for(size_t i=0;i<n;++i)((unsigned char *)out)[i]=((const unsigned char *)in)[i];}
static void same(const void *a,const void *b,size_t n){for(size_t i=0;i<n;++i)if(((const unsigned char *)a)[i]!=((const unsigned char *)b)[i])fail(70);}
static struct osrec_slice_invocation invocation(unsigned session,unsigned index)
{
    const struct files_call *c=&files_calls[index];struct osrec_slice_invocation in={index,c->number,{0},{regions[session],5}};
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
    f->sp=(uintptr_t)app_stacks[session]+sizeof(app_stacks[session]);
    f->pc=regions[session][3].user_address;f->pstate=UINT64_C(0xa00003c0);
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
    uint32_t status=osrec_aarch64_gateway_run(&gateways[session]);
    *result=(struct osrec_slice_result){gateways[session].result.raw,status,gateways[session].diagnostic,sites[session].ordinal};
    return status;
}
static void execute(unsigned session,unsigned index)
{
    struct osrec_slice_result result;prepare_frame(session,index);copy(&frame_snapshot,&frames[session],sizeof(frame_snapshot));
    for(size_t i=0;i<sizeof(app_stacks[session]);++i)app_stacks[session][i]=0xa5;
    for(unsigned i=0;i<16;++i){kernel_stacks[session][i]=0x6a;kernel_stacks[session][16368+i]=0x6a;}
    osrec_probe_seed(&container_seed);struct controls before,after;controls(&before);
    if(enter(session,&result)!=OSREC_SLICE_OK || result.raw!=(int64_t)(int32_t)files_calls[index].raw || result.ordinal!=index || gateways[session].entries!=1 || gateways[session].exits!=1 || gateways[session].active)fail(71);
    controls(&after);same(&before,&after,sizeof(before));osrec_probe_sample(&container_sample);
    for(unsigned i=0;i<32;++i)same(&container_seed.v[i],&container_sample.v[i],16);
    if(container_seed.fpcr!=container_sample.fpcr || container_seed.fpsr!=container_sample.fpsr)fail(85);++control_checks;
    frame_snapshot.x[abis[session].result_register]=(uint64_t)result.raw;frame_snapshot.pc=gateways[session].exit_pc;
    same(&frame_snapshot,&frames[session],sizeof(frame_snapshot));
    uint64_t app_result=0;copy(&app_result,&app_stacks[session][1008],8);
    if(app_result!=(uint64_t)result.raw)fail(86);
    for(unsigned i=0;i<1024;++i)if((i<1008 || i>=1016) && app_stacks[session][i]!=0xa5)fail(87);
    for(unsigned i=0;i<16;++i)if(kernel_stacks[session][i]!=0x6a || kernel_stacks[session][16368+i]!=0x6a)fail(88);++stack_checks;
    same(memory[session],files_calls[index].buffer_after,192);++successful;++guards;
}
static void reject_gateway(uint32_t expected)
{
    copy(&snapshot,&contexts[0],sizeof(snapshot));copy(&frame_snapshot,&frames[0],sizeof(frame_snapshot));
    uint64_t next=sessions[0].next;
    if(osrec_aarch64_gateway_run(&gateways[0])!=expected || sessions[0].next!=next || sessions[0].poisoned || sessions[0].active)fail(72);
    same(&snapshot,&contexts[0],sizeof(snapshot));same(&frame_snapshot,&frames[0],sizeof(frame_snapshot));++rejected;
}
static void invalid_gateways(void)
{
    prepare_frame(0,0);frames[0].pstate|=5;reject_gateway(OSREC_SLICE_BAD_INPUT);
    prepare_frame(0,0);gateways[0].stack++;reject_gateway(OSREC_SLICE_BAD_INPUT);gateways[0].stack--;
    prepare_frame(0,0);gateways[0].stack_bytes=1024;reject_gateway(OSREC_SLICE_BAD_INPUT);gateways[0].stack_bytes=16384;
    prepare_frame(0,0);frames[0].sp++;reject_gateway(OSREC_SLICE_BAD_INPUT);
    prepare_frame(0,0);frames[0].pc-=4;reject_gateway(OSREC_SLICE_BAD_INPUT);
    prepare_frame(0,0);uint64_t saved=gateways[0].exit_pc;gateways[0].exit_pc=frames[0].pc;reject_gateway(OSREC_SLICE_BAD_INPUT);gateways[0].exit_pc=saved;
    prepare_frame(0,0);code[0][0]=0;reject_gateway(OSREC_SLICE_BAD_INPUT);code[0][0]=1;
    prepare_frame(0,0);saved=regions[0][0].user_address;regions[0][0].user_address=UINT64_C(0x10000000000);reject_gateway(OSREC_SLICE_BAD_INPUT);regions[0][0].user_address=saved;
    prepare_frame(0,0);gateways[0].executable.user_address+=4;reject_gateway(OSREC_SLICE_BAD_INPUT);gateways[0].executable.user_address-=4;
    prepare_frame(0,0);gateways[0].active=1;reject_gateway(OSREC_SLICE_BUSY);gateways[0].active=0;
}
extern unsigned char osrec_app_sequence_entry[],osrec_app_sequence_first[],osrec_app_sequence_second[],osrec_app_sequence_exit[],osrec_app_fault_route[],osrec_app_fault_exit[];
struct wide_state {uint64_t sum,calls;};
static volatile uint32_t inject_kernel_fault;
static void wide_restore(void *p){struct wide_state *s=p;s->sum=0;s->calls=0;}
static uint32_t wide_enter(void *p,const struct osrec_slice_invocation *in,struct osrec_slice_result *out)
{struct wide_state *s=p;s->sum+=in->args[0];++s->calls;if(inject_kernel_fault)__asm__ volatile(".inst 0");out->raw=(int64_t)s->sum;return OSREC_SLICE_OK;}
static uint32_t wide_finish(const void *p){return ((const struct wide_state *)p)->calls==2 ? OSREC_SLICE_OK : OSREC_SLICE_DIVERGED;}
static void application_sequence(void)
{
    static const struct osrec_slice_adapter adapter={OSREC_SLICE_ABI,"synthetic-64-bit-live-gateway",sizeof(struct wide_state),8,2,wide_restore,wide_enter,wide_finish};
    static const struct osrec_aarch64_syscall_recipe recipes[]={{UINT64_C(0x100000008),1}};
    const struct osrec_aarch64_syscall_abi abi={OSREC_AARCH64_FRAME_ABI,8,{0,1,2,3,4,5},0,recipes,1};
    struct wide_state state;struct osrec_slice_session session;
    struct osrec_aarch64_frame f=frames[0],expected=f;
    unsigned char original[28];copy(original,osrec_app_sequence_entry,28);
    for(unsigned offset=4;offset<=16;offset+=12){original[offset]=1;original[offset+1]=0;original[offset+2]=0;original[offset+3]=0xd4;}
    struct osrec_user_region memory_view[2]={{(uintptr_t)osrec_app_sequence_entry,original,28,1,1},{(uintptr_t)app_stacks[0],app_stacks[0],1024,3,2}};
    struct osrec_aarch64_site sequence[2]={{0,(uintptr_t)osrec_app_sequence_first,(uintptr_t)osrec_app_sequence_first+4,{memory_view,2}},
        {1,(uintptr_t)osrec_app_sequence_second,(uintptr_t)osrec_app_sequence_second+4,{memory_view,2}}};
    f.pc=(uintptr_t)osrec_app_sequence_entry;f.x[8]=UINT64_C(0x100000008);f.x[0]=UINT64_C(0x100000000);expected=f;
    struct osrec_aarch64_gateway g={.abi=OSREC_AARCH64_GATEWAY_ABI,.session=&session,.registers=&abi,.application=&f,.sites=sequence,.site_count=2,
        .executable={(uintptr_t)osrec_app_sequence_entry,osrec_app_sequence_entry,28,1,3},.exit_pc=(uintptr_t)osrec_app_sequence_exit,.stack=kernel_stacks[0],.stack_bytes=16384};
    if(osrec_slice_session_init(&session,&adapter,&state,sizeof(state)))fail(90);
    uint64_t cpacr;__asm__ volatile("mrs %0,cpacr_el1":"=r"(cpacr));uint64_t disabled=cpacr&~UINT64_C(0x300000);__asm__ volatile("msr cpacr_el1,%0\nisb"::"r"(disabled):"memory");
    struct controls before,after;controls(&before);
    if(osrec_aarch64_gateway_run(&g) || g.cursor!=2 || g.entries!=2 || g.exits!=1 || osrec_slice_finish(&session) || state.sum!=UINT64_C(0x200000007))fail(91);
    controls(&after);same(&before,&after,sizeof(before));
    __asm__ volatile("msr cpacr_el1,%0\nisb"::"r"(cpacr):"memory");
    expected.x[0]=UINT64_C(0x200000007);expected.pc=(uintptr_t)osrec_app_sequence_exit;same(&expected,&f,sizeof(f));
    uint64_t first,second;copy(&first,&app_stacks[0][992],8);copy(&second,&app_stacks[0][1000],8);
    if(first!=UINT64_C(0x100000002) || second!=UINT64_C(0x200000007))fail(92);osrec_result[19]|=2;
    /* An unexpected app instruction fault returns to the container and poisons
     * the session after its already-computed syscall effect, without host help. */
    if(osrec_slice_session_restore(&session))fail(93);
    copy(original,osrec_app_fault_route,12);original[0]=1;original[1]=0;original[2]=0;original[3]=0xd4;
    memory_view[0]=(struct osrec_user_region){(uintptr_t)osrec_app_fault_route,original,12,1,1};
    sequence[0]=(struct osrec_aarch64_site){0,(uintptr_t)osrec_app_fault_route,(uintptr_t)osrec_app_fault_route+4,{memory_view,2}};
    f=expected;f.pc=sequence[0].svc_pc;f.x[0]=UINT64_C(0x8000000000000001);
    g.executable=(struct osrec_user_region){(uintptr_t)osrec_app_fault_route,osrec_app_fault_route,12,1,3};g.exit_pc=(uintptr_t)osrec_app_fault_exit;g.site_count=1;
    controls(&before);
    if(osrec_aarch64_gateway_run(&g)!=OSREC_SLICE_DIVERGED || !session.poisoned || session.next!=1 || state.calls!=1 || state.sum!=UINT64_C(0x8000000000000001) || f.x[0]!=UINT64_C(0x8000000000000001) || f.pc!=sequence[0].continuation_pc || g.active)fail(94);
    controls(&after);same(&before,&after,sizeof(before));
    if(osrec_slice_session_restore(&session) || state.sum || state.calls || session.next || session.poisoned)fail(95);osrec_result[19]|=4;
    copy(original,osrec_app_route_a,12);original[0]=1;original[1]=0;original[2]=0;original[3]=0xd4;
    memory_view[0]=(struct osrec_user_region){(uintptr_t)osrec_app_route_a,original,12,1,1};
    sequence[0]=(struct osrec_aarch64_site){0,(uintptr_t)osrec_app_route_a,(uintptr_t)osrec_app_route_a+4,{memory_view,2}};
    f=expected;f.pc=sequence[0].svc_pc;f.x[0]=UINT64_C(0x100000003);expected=f;
    g.executable=(struct osrec_user_region){(uintptr_t)osrec_app_route_a,osrec_app_route_a,12,1,3};g.exit_pc=(uintptr_t)osrec_app_exit_a;
    inject_kernel_fault=1;controls(&before);
    if(osrec_aarch64_gateway_run(&g)!=OSREC_SLICE_DIVERGED || !session.poisoned || session.active || session.next || state.calls!=1 || state.sum!=UINT64_C(0x100000003) || g.active)fail(96);
    inject_kernel_fault=0;controls(&after);same(&before,&after,sizeof(before));same(&expected,&f,sizeof(f));
    if(osrec_slice_session_restore(&session) || state.sum || state.calls || session.next || session.poisoned)fail(97);osrec_result[19]|=8;
}
void replay_main(void)
{
    osrec_result[0]=0x4f535243;osrec_result[1]=20;osrec_result[2]=1;
    uint64_t cpacr;__asm__ volatile("mrs %0,cpacr_el1":"=r"(cpacr));cpacr|=UINT64_C(0x300000);__asm__ volatile("msr cpacr_el1,%0\nisb"::"r"(cpacr):"memory");
    for(unsigned i=0;i<32;++i){container_seed.v[i].lo=UINT64_C(0x7654000000000000)+i;container_seed.v[i].hi=UINT64_C(0xabba000000000000)+i;}
    container_seed.fpcr=0x800000;container_seed.fpsr=0x80;
    abis[0]=osrec_application_abi;
    abis[1]=(struct osrec_aarch64_syscall_abi){OSREC_AARCH64_FRAME_ABI,16,{10,11,12,13,14,15},17,osrec_application_abi.syscalls,osrec_application_abi.syscall_count};
    for(unsigned s=0;s<2;++s){uint64_t base=(uintptr_t)memory[s];
        unsigned char *route=s ? osrec_app_route_b : osrec_app_route_a,*exit=s ? osrec_app_exit_b : osrec_app_exit_a;
        copy(code[s],route,12);code[s][0]=1;code[s][1]=0;code[s][2]=0;code[s][3]=0xd4;
        regions[s][0]=(struct osrec_user_region){base,memory[s],192,3,1};
        regions[s][1]=(struct osrec_user_region){(uintptr_t)main_path,(unsigned char *)main_path,sizeof(main_path),1,2};
        regions[s][2]=(struct osrec_user_region){(uintptr_t)missing_path,(unsigned char *)missing_path,sizeof(missing_path),1,3};
        regions[s][3]=(struct osrec_user_region){(uintptr_t)route,code[s],12,1,4};
        regions[s][4]=(struct osrec_user_region){(uintptr_t)app_stacks[s],app_stacks[s],sizeof(app_stacks[s]),3,5};
        gateways[s]=(struct osrec_aarch64_gateway){.abi=OSREC_AARCH64_GATEWAY_ABI,.session=&sessions[s],.registers=&abis[s],.application=&frames[s],.sites=&sites[s],.site_count=1,
            .executable={(uintptr_t)route,route,12,1,6},.exit_pc=(uintptr_t)exit,.stack=kernel_stacks[s],.stack_bytes=sizeof(kernel_stacks[s])};
        if(osrec_slice_session_init(&sessions[s],&osrec_kernel_adapter,&contexts[s],sizeof(contexts[s])))fail(73);
    }
    invalid_gateways();
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
    osrec_result[25]=stack_checks;osrec_result[26]=32;osrec_result[27]=2;osrec_result[28]=guards;osrec_result[29]=control_checks;osrec_result[30]=3;osrec_result[31]=OSREC_AARCH64_GATEWAY_ABI;
    /* A divergence returns to the caller, poisons only this session, and requires restore. */
    if(osrec_slice_session_restore(&sessions[0]))fail(78);
    execute(0,0);contexts[0].state[0]=99;prepare_frame(0,1);copy(&frame_snapshot,&frames[0],sizeof(frame_snapshot));
    if(enter(0,&result)!=OSREC_SLICE_DIVERGED || result.diagnostic!=30 || !sessions[0].poisoned || sessions[0].active)fail(79);
    same(&frame_snapshot,&frames[0],sizeof(frame_snapshot));osrec_result[16]=1;
    if(enter(0,&result)!=OSREC_SLICE_POISONED)fail(80);same(&frame_snapshot,&frames[0],sizeof(frame_snapshot));osrec_result[17]=1;
    if(osrec_slice_session_restore(&sessions[0]) || sessions[0].next || sessions[0].poisoned || contexts[0].opens || contexts[0].cursor || contexts[0].process.vmSpace!=&contexts[0].space || osrec_slice_finish(&sessions[0])!=OSREC_SLICE_BAD_INPUT || osrec_slice_finish(&sessions[1]))fail(81);
    osrec_result[18]=1;application_sequence();__asm__ volatile("dsb sy" ::: "memory");osrec_result[2]=2;stop();
}
