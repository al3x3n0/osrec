#include "osrec/aarch64_frame.h"
_Static_assert(sizeof(struct osrec_aarch64_frame)==OSREC_AARCH64_FRAME_BYTES,"saved frame ABI layout");
uint32_t osrec_aarch64_abi_validate(const struct osrec_aarch64_syscall_abi *a)
{
    if(!a || a->abi!=OSREC_AARCH64_FRAME_ABI || a->number_register>=31 || a->result_register>=31 || !a->syscalls || !a->syscall_count || a->syscall_count>4096)return OSREC_SLICE_BAD_INPUT;
    for(unsigned i=0;i<6;++i){
        if(a->argument_registers[i]>=31 || a->argument_registers[i]==a->number_register)return OSREC_SLICE_BAD_INPUT;
        for(unsigned j=0;j<i;++j)if(a->argument_registers[i]==a->argument_registers[j])return OSREC_SLICE_BAD_INPUT;
    }
    for(size_t i=0;i<a->syscall_count;++i){
        if(a->syscalls[i].argument_count>6)return OSREC_SLICE_BAD_INPUT;
        if(i && a->syscalls[i].number<=a->syscalls[i-1].number)return OSREC_SLICE_BAD_INPUT;
    }
    return OSREC_SLICE_OK;
}
static int overlaps(const void *a,size_t an,const void *b,size_t bn)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return x<=y ? y-x<an : x-y<bn;
}
static int writable_alias(const struct osrec_user_memory *m,const void *p,size_t n)
{
    for(size_t i=0;i<m->count;++i)if((m->regions[i].permissions&OSREC_MEMORY_WRITE) && overlaps(p,n,m->regions[i].image_address,m->regions[i].bytes))return 1;
    return 0;
}
uint32_t osrec_aarch64_syscall(struct osrec_slice_session *s,
    const struct osrec_aarch64_syscall_abi *a,struct osrec_aarch64_frame *f,
    const struct osrec_aarch64_site *site,struct osrec_slice_result *out)
{
    /* Do not initialize an aliased result: a rejected call must preserve frame. */
    if(!out || (f && overlaps(out,sizeof(*out),f,sizeof(*f))))return OSREC_SLICE_BAD_INPUT;
    if((s && overlaps(out,sizeof(*out),s,sizeof(*s))) ||
       (a && overlaps(out,sizeof(*out),a,sizeof(*a))) ||
       (site && overlaps(out,sizeof(*out),site,sizeof(*site))))return OSREC_SLICE_BAD_INPUT;
    if(!s || !f || !site || osrec_aarch64_abi_validate(a))goto bad;
    if(overlaps(out,sizeof(*out),a->syscalls,a->syscall_count*sizeof(*a->syscalls)))return OSREC_SLICE_BAD_INPUT;
    if(overlaps(f,sizeof(*f),s,sizeof(*s)) || overlaps(f,sizeof(*f),a,sizeof(*a)) ||
       overlaps(f,sizeof(*f),site,sizeof(*site)) || overlaps(f,sizeof(*f),a->syscalls,a->syscall_count*sizeof(*a->syscalls)))goto bad;
    if(f->pc!=site->svc_pc || !site->svc_pc || (site->svc_pc&3) || site->svc_pc>UINT64_MAX-4 || site->continuation_pc!=site->svc_pc+4)goto bad;
    if(osrec_user_memory_validate(&site->memory))goto bad;
    if(overlaps(out,sizeof(*out),site->memory.regions,site->memory.count*sizeof(*site->memory.regions)) ||
       (s->initialized==1 && overlaps(out,sizeof(*out),s->state,s->adapter->state_bytes)))return OSREC_SLICE_BAD_INPUT;
    if(overlaps(f,sizeof(*f),site->memory.regions,site->memory.count*sizeof(*site->memory.regions)) ||
       (s->initialized==1 && overlaps(f,sizeof(*f),s->state,s->adapter->state_bytes)))goto bad;
    if(writable_alias(&site->memory,f,sizeof(*f)) || writable_alias(&site->memory,s,sizeof(*s)) ||
       writable_alias(&site->memory,a,sizeof(*a)) || writable_alias(&site->memory,site,sizeof(*site)) ||
       writable_alias(&site->memory,a->syscalls,a->syscall_count*sizeof(*a->syscalls)) ||
       writable_alias(&site->memory,out,sizeof(*out)) ||
       writable_alias(&site->memory,site->memory.regions,site->memory.count*sizeof(*site->memory.regions)) ||
       (s->initialized==1 && writable_alias(&site->memory,s->state,s->adapter->state_bytes)))goto bad;
    const unsigned char *instruction=osrec_user_memory_resolve(&site->memory,site->svc_pc,4,OSREC_MEMORY_READ);
    if(!instruction || !osrec_user_memory_resolve(&site->memory,site->continuation_pc,4,OSREC_MEMORY_READ))goto bad;
    uint32_t word=(uint32_t)instruction[0]|(uint32_t)instruction[1]<<8|(uint32_t)instruction[2]<<16|(uint32_t)instruction[3]<<24;
    /* AArch64 SVC #imm16; instruction bytes are read, never executed. */
    if((word&UINT32_C(0xffe0001f))!=UINT32_C(0xd4000001))goto bad;
    struct osrec_slice_invocation in={site->ordinal,f->x[a->number_register],{0},site->memory};
    size_t recipe=0;
    while(recipe<a->syscall_count && a->syscalls[recipe].number!=in.number)++recipe;
    if(recipe==a->syscall_count)goto bad;
    for(unsigned i=0;i<a->syscalls[recipe].argument_count;++i)in.args[i]=f->x[a->argument_registers[i]];
    uint32_t status=osrec_slice_execute(s,&in,out);
    if(status==OSREC_SLICE_OK){f->x[a->result_register]=(uint64_t)out->raw;f->pc=site->continuation_pc;}
    return status;
bad:
    out->raw=0;out->status=OSREC_SLICE_BAD_INPUT;out->diagnostic=0;out->ordinal=site ? site->ordinal : 0;
    return out->status;
}
