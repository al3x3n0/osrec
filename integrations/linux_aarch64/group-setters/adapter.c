#include "slice_context.h"
#include "slice_dispatch.h"
#include "capture.h"
static void restore(void *state){osrec_context_restore(state);}
uint32_t osrec_kernel_checkpoint_check(const void *state,uint64_t next)
{
    const struct osrec_kernel_context *c=state;
    if(next>LINUX_CALLS || c->current!=&c->task || c->task.real_parent!=&c->parent || c->task.fs!=&c->fs || c->user_ns.initial!=1 ||
       c->task.pid!=LINUX_INITIAL_PID || c->task.tgid!=LINUX_INITIAL_TGID || c->parent.pid!=LINUX_INITIAL_PPID || c->parent.tgid!=LINUX_INITIAL_PPID ||
       c->parent.real_parent || c->parent.fs || c->parent.cred || c->fs.umask!=(int)linux_masks[next] || c->rcu_depth || c->active_memory.regions || c->active_memory.count || c->pending_credential)return OSREC_SLICE_BAD_INPUT;
    const struct linux_credential_snapshot *expected=&linux_credentials[next];
    if(c->task.cred!=&c->credential_pool[expected->active] || c->credential_generation!=expected->generation)return OSREC_SLICE_BAD_INPUT;
    for(unsigned i=0;i<2;++i){
        const struct cred *p=&c->credential_pool[i];
        if(p->uid!=LINUX_INITIAL_UID || p->euid!=LINUX_INITIAL_EUID || p->suid!=LINUX_INITIAL_SUID || p->fsuid!=LINUX_INITIAL_EUID ||
           p->gid!=expected->gids[i][0] || p->egid!=expected->gids[i][1] || p->sgid!=expected->gids[i][2] || p->fsgid!=expected->gids[i][3] ||
           p->user_ns!=&c->user_ns || c->credential_slot_generation[i]!=expected->epochs[i])return OSREC_SLICE_BAD_INPUT;
    }
    return OSREC_SLICE_OK;
}
static uint32_t enter(void *state,const struct osrec_slice_invocation *in,struct osrec_slice_result *out)
{
    struct osrec_kernel_context *c=state;
    if(in->ordinal>=LINUX_CALLS || osrec_kernel_checkpoint_check(c,in->ordinal))return OSREC_SLICE_BAD_INPUT;
    const struct linux_observation *call=&linux_calls[in->ordinal];
    if(in->number!=call->number)return OSREC_SLICE_BAD_INPUT;
    const struct osrec_user_region *r=osrec_user_memory_object(&in->memory,1,32,3);
    if(!r || r->bytes!=32)return OSREC_SLICE_BAD_INPUT;
    for(unsigned i=3;i<6;++i)if(in->args[i])return OSREC_SLICE_BAD_INPUT;
    for(unsigned i=0;i<3;++i){
        uint64_t expected=call->args[i];
        if(in->number==148 || in->number==150)expected=expected==UINT64_MAX ? 0 : expected==UINT64_MAX-1 ? 1 : r->user_address+expected;
        if(in->args[i]!=expected)return OSREC_SLICE_BAD_INPUT;
    }
    for(unsigned i=0;i<8;++i)for(unsigned j=0;j<4;++j)if(r->image_address[4*i+j]!=(unsigned char)((UINT32_C(0xa5a50000)+i)>>(8*j)))return OSREC_SLICE_BAD_INPUT;
    c->active_memory=in->memory;
    uintptr_t arguments[6];for(unsigned i=0;i<6;++i)arguments[i]=(uintptr_t)in->args[i];
    out->raw=osrec_kernel_dispatch(c,in->number,arguments);
    c->active_memory=(struct osrec_user_memory){0};
    if((uint64_t)out->raw!=call->raw || osrec_kernel_checkpoint_check(c,in->ordinal+1))return OSREC_SLICE_DIVERGED;
    for(unsigned i=0;i<8;++i)for(unsigned j=0;j<4;++j)if(r->image_address[4*i+j]!=(unsigned char)(call->words[i]>>(8*j)))return OSREC_SLICE_DIVERGED;
    return OSREC_SLICE_OK;
}
static uint32_t finish(const void *state){return osrec_kernel_checkpoint_check(state,LINUX_CALLS);}
const struct osrec_slice_adapter osrec_kernel_adapter={OSREC_SLICE_ABI,"linux-aarch64-group-setters",sizeof(struct osrec_kernel_context),_Alignof(struct osrec_kernel_context),LINUX_CALLS,restore,enter,finish};
