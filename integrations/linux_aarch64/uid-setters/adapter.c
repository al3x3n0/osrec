#include "slice_context.h"
#include "slice_dispatch.h"
#include "capture.h"
static void restore(void *state){osrec_context_restore(state);}
uint32_t osrec_kernel_checkpoint_check(const void *state,uint64_t next)
{
    const struct osrec_kernel_context *c=state;
    if(next>LINUX_CALLS || c->current!=&c->task || c->task.real_parent!=&c->parent || c->task.fs!=&c->fs || c->user_ns.initial!=1 || c->user_ns.setgroups_allowed!=1 ||
       c->task.pid!=LINUX_INITIAL_PID || c->task.tgid!=LINUX_INITIAL_TGID || c->parent.pid!=LINUX_INITIAL_PPID || c->parent.tgid!=LINUX_INITIAL_PPID ||
       c->parent.real_parent || c->parent.fs || c->parent.cred || c->parent.flags || c->task.flags || c->fs.umask!=(int)linux_masks[next] || c->rcu_depth || c->active_memory.regions || c->active_memory.count || c->pending_credential || c->allocated_group)return OSREC_SLICE_BAD_INPUT;
    const struct linux_credential_snapshot *expected=&linux_credentials[next];
    if(c->task.cred!=&c->credential_pool[expected->active] || c->credential_generation!=expected->generation)return OSREC_SLICE_BAD_INPUT;
    const struct linux_group_state *groups=&linux_groups[next];
    for(unsigned i=0;i<2;++i){
        const struct group_info *p=&c->group_pool[i];const struct linux_group_snapshot *e=&groups->pool[i];
        if(p->usage!=e->usage || p->ngroups!=e->ngroups)return OSREC_SLICE_BAD_INPUT;
        for(unsigned j=0;j<4;++j)if(p->gid[j]!=e->gid[j])return OSREC_SLICE_BAD_INPUT;
    }
    for(unsigned i=0;i<2;++i){
        const struct cred *p=&c->credential_pool[i];
        if(p->securebits!=linux_securebits[next][i])return OSREC_SLICE_BAD_INPUT;
        const uint64_t *caps=linux_capabilities[next][i];
        if(p->cap_effective.val!=caps[0] || p->cap_permitted.val!=caps[1] || p->cap_inheritable.val!=caps[2] || p->cap_bset.val!=caps[3] || p->cap_ambient.val!=caps[4])return OSREC_SLICE_BAD_INPUT;
        if(p->uid!=linux_uids[next][i][0] || p->euid!=linux_uids[next][i][1] || p->suid!=linux_uids[next][i][2] || p->fsuid!=linux_fsuids[next][i] ||
           p->gid!=expected->gids[i][0] || p->egid!=expected->gids[i][1] || p->sgid!=expected->gids[i][2] || p->fsgid!=expected->gids[i][3] ||
           p->group_info!=&c->group_pool[groups->links[i]] || p->user_ns!=&c->user_ns || c->credential_slot_generation[i]!=expected->epochs[i])return OSREC_SLICE_BAD_INPUT;
    }
    const uint32_t identities[4]={1001,0,9001,9002};
    for(unsigned j=0;j<4;++j){
        int32_t owned=c->task.cred->uid==identities[j];
        if(c->user_pool[j].uid!=identities[j] || c->user_pool[j].usage!=owned || c->ucounts_pool[j].uid!=identities[j] || c->ucounts_pool[j].usage!=owned || c->ucounts_pool[j].ns!=&c->user_ns)return OSREC_SLICE_BAD_INPUT;
    }
    for(unsigned i=0;i<2;++i){
        const struct cred *p=&c->credential_pool[i];
        unsigned user=linux_user_links[next][i][0],account=linux_user_links[next][i][1];
        if(user>=4 || account>=4 || p->user!=&c->user_pool[user] || p->ucounts!=&c->ucounts_pool[account])return OSREC_SLICE_BAD_INPUT;
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
    for(unsigned i=5;i<6;++i)if(in->args[i])return OSREC_SLICE_BAD_INPUT;
    for(unsigned i=0;i<5;++i){
        uint64_t expected=call->args[i];
        if(((in->number==148 || in->number==150) && i<3) || ((in->number==158 || in->number==159) && i==1) || ((in->number==91 || in->number==90) && i<2))expected=expected==UINT64_MAX ? 0 : expected==UINT64_MAX-1 ? 1 : r->user_address+expected;
        if(in->args[i]!=expected)return OSREC_SLICE_BAD_INPUT;
    }
    for(unsigned i=0;i<8;++i)for(unsigned j=0;j<4;++j)if(r->image_address[4*i+j]!=(unsigned char)(linux_inputs[in->ordinal][i]>>(8*j)))return OSREC_SLICE_BAD_INPUT;
    /* These options terminate in the original commoncap hook, before the
     * general sys_prctl fallback. The fallback/other LSM routes are not admitted. */
    if(in->number==167 && call->args[0]!=7 && call->args[0]!=8 && call->args[0]!=23 && call->args[0]!=24 && call->args[0]!=27 && call->args[0]!=28 && call->args[0]!=47)return OSREC_SLICE_BAD_INPUT;
    c->active_memory=in->memory;
    uintptr_t arguments[6];for(unsigned i=0;i<6;++i)arguments[i]=(uintptr_t)in->args[i];
    out->raw=osrec_kernel_dispatch(c,in->number,arguments);
    c->active_memory=(struct osrec_user_memory){0};
    if((uint64_t)out->raw!=call->raw || osrec_kernel_checkpoint_check(c,in->ordinal+1))return OSREC_SLICE_DIVERGED;
    for(unsigned i=0;i<8;++i)for(unsigned j=0;j<4;++j)if(r->image_address[4*i+j]!=(unsigned char)(call->words[i]>>(8*j)))return OSREC_SLICE_DIVERGED;
    return OSREC_SLICE_OK;
}
static uint32_t finish(const void *state){return osrec_kernel_checkpoint_check(state,LINUX_CALLS);}
const struct osrec_slice_adapter osrec_kernel_adapter={OSREC_SLICE_ABI,"linux-aarch64-uid-setters",sizeof(struct osrec_kernel_context),_Alignof(struct osrec_kernel_context),LINUX_CALLS,restore,enter,finish};
