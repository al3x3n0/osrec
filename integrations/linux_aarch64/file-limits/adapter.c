#include "slice_context.h"
#include "slice_dispatch.h"
#include "capture.h"
static uint32_t fd_check(const struct osrec_kernel_context *c,uint64_t next)
{
    if(next>LINUX_CALLS)return 0;
    const struct linux_fd_snapshot *s=&linux_fds[next];
    if(c->task.files!=&c->files || c->parent.files || c->files.fdt!=&c->files.fdtab || c->files.fdtab.max_fds!=64 ||
        c->files.next_fd!=s->next_fd || c->files.file_lock || c->files.resize_in_progress || c->model_fault ||
        c->files.fdtab.open_fds[0]!=s->open_fds || c->files.fdtab.close_on_exec[0]!=s->cloexec || c->files.fdtab.full_fds_bits[0])return 0;
    for(unsigned i=0;i<2;++i)if(c->file_pool[i].object_id!=i+1 || c->file_pool[i].f_mode!=(i ? 31u : FMODE_STREAM) || c->file_pool[i].f_lock || c->file_pool[i].f_version || (i==0 && c->file_pool[i].f_pos) ||
        c->file_pool[i].f_flags!=linux_file_status[next][i] || c->file_pool[i].f_count!=s->counts[i])return 0;
    for(unsigned fd=0;fd<64;++fd){
        uint32_t id=fd<8 ? s->slots[fd] : 0;
        if(c->files.fdtab.fd[fd]!=(id ? &c->file_pool[id-1] : 0))return 0;
    }
    if(c->superblock.write_depth)return 0;
    for(unsigned i=0;i<2;++i)if(c->file_pool[i].f_path.dentry!=&c->dentry_pool[i] || c->dentry_pool[i].d_inode!=&c->inode_pool[i] ||
        c->inode_pool[i].i_mode!=linux_inode_modes[next][i] || c->inode_pool[i].append || c->inode_pool[i].i_sb!=&c->superblock)return 0;
    for(unsigned i=0;i<2;++i)if(c->file_pool[i].f_path.mnt!=&c->mount_pool[i] || c->mount_pool[i].object_id!=i+1 || c->mount_pool[i].write_depth || c->inode_pool[i].lock_depth)return 0;
    const struct inode *nodes[2]={&c->inode_pool[0],&c->inode_pool[1]};
#define CHECK_META(id) if(nodes[id]->dev!=LINUX_INITIAL_STAT_DEV_##id || nodes[id]->rdev!=LINUX_INITIAL_STAT_RDEV_##id || nodes[id]->ino!=LINUX_INITIAL_STAT_INO_##id || nodes[id]->nlink!=LINUX_INITIAL_STAT_NLINK_##id || nodes[id]->uid!=linux_inode_owners[next][id][0] || nodes[id]->gid!=linux_inode_owners[next][id][1] || nodes[id]->blksize!=LINUX_INITIAL_STAT_BLKSIZE_##id)return 0;
    CHECK_META(0) CHECK_META(1)
    if(nodes[0]->blocks!=LINUX_INITIAL_STAT_BLOCKS_0 || nodes[1]->blocks!=linux_stat_blocks[next])return 0;
    const struct linux_file_snapshot *f=&linux_file_data[next];
    if(c->file_data.size!=f->size || c->file_pool[1].f_pos!=f->pos)return 0;
    for(unsigned i=0;i<64;++i)if(c->file_data.bytes[i]!=f->bytes[i])return 0;
    return 1;
}
static void restore(void *state){osrec_context_restore(state);}
uint32_t osrec_kernel_checkpoint_check(const void *state,uint64_t next)
{
    const struct osrec_kernel_context *c=state;
    if(next>LINUX_CALLS || !fd_check(c,next) || c->current!=&c->task || c->task.real_parent!=&c->parent ||
       c->task.fs!=&c->fs || c->user_ns.initial!=1 || c->task.pid!=LINUX_INITIAL_PID || c->task.tgid!=LINUX_INITIAL_TGID ||
       c->parent.pid!=LINUX_INITIAL_PPID || c->parent.tgid!=LINUX_INITIAL_PPID || c->parent.real_parent || c->parent.fs || c->parent.cred ||
       c->task.flags || c->parent.flags || c->fs.umask!=(int)linux_masks[next] || c->rcu_depth || c->active_memory.regions || c->active_memory.count || c->pending_credential || c->allocated_group)return OSREC_SLICE_BAD_INPUT;
    if(c->resource_limits[0].rlim_cur!=LINUX_INITIAL_RLIMIT_0_CUR || c->resource_limits[0].rlim_max!=LINUX_INITIAL_RLIMIT_0_MAX)return OSREC_SLICE_BAD_INPUT;
    if(c->resource_limits[1].rlim_cur!=LINUX_INITIAL_RLIMIT_1_CUR || c->resource_limits[1].rlim_max!=LINUX_INITIAL_RLIMIT_1_MAX)return OSREC_SLICE_BAD_INPUT;
    if(c->resource_limits[2].rlim_cur!=LINUX_INITIAL_RLIMIT_2_CUR || c->resource_limits[2].rlim_max!=LINUX_INITIAL_RLIMIT_2_MAX)return OSREC_SLICE_BAD_INPUT;
    if(c->resource_limits[3].rlim_cur!=LINUX_INITIAL_RLIMIT_3_CUR || c->resource_limits[3].rlim_max!=LINUX_INITIAL_RLIMIT_3_MAX)return OSREC_SLICE_BAD_INPUT;
    if(c->resource_limits[4].rlim_cur!=LINUX_INITIAL_RLIMIT_4_CUR || c->resource_limits[4].rlim_max!=LINUX_INITIAL_RLIMIT_4_MAX)return OSREC_SLICE_BAD_INPUT;
    if(c->resource_limits[5].rlim_cur!=LINUX_INITIAL_RLIMIT_5_CUR || c->resource_limits[5].rlim_max!=LINUX_INITIAL_RLIMIT_5_MAX)return OSREC_SLICE_BAD_INPUT;
    if(c->resource_limits[6].rlim_cur!=LINUX_INITIAL_RLIMIT_6_CUR || c->resource_limits[6].rlim_max!=LINUX_INITIAL_RLIMIT_6_MAX)return OSREC_SLICE_BAD_INPUT;
    if(c->resource_limits[7].rlim_cur!=LINUX_INITIAL_RLIMIT_7_CUR || c->resource_limits[7].rlim_max!=LINUX_INITIAL_RLIMIT_7_MAX)return OSREC_SLICE_BAD_INPUT;
    if(c->resource_limits[8].rlim_cur!=LINUX_INITIAL_RLIMIT_8_CUR || c->resource_limits[8].rlim_max!=LINUX_INITIAL_RLIMIT_8_MAX)return OSREC_SLICE_BAD_INPUT;
    if(c->resource_limits[9].rlim_cur!=LINUX_INITIAL_RLIMIT_9_CUR || c->resource_limits[9].rlim_max!=LINUX_INITIAL_RLIMIT_9_MAX)return OSREC_SLICE_BAD_INPUT;
    if(c->resource_limits[10].rlim_cur!=LINUX_INITIAL_RLIMIT_10_CUR || c->resource_limits[10].rlim_max!=LINUX_INITIAL_RLIMIT_10_MAX)return OSREC_SLICE_BAD_INPUT;
    if(c->resource_limits[11].rlim_cur!=LINUX_INITIAL_RLIMIT_11_CUR || c->resource_limits[11].rlim_max!=LINUX_INITIAL_RLIMIT_11_MAX)return OSREC_SLICE_BAD_INPUT;
    if(c->resource_limits[12].rlim_cur!=LINUX_INITIAL_RLIMIT_12_CUR || c->resource_limits[12].rlim_max!=LINUX_INITIAL_RLIMIT_12_MAX)return OSREC_SLICE_BAD_INPUT;
    if(c->resource_limits[13].rlim_cur!=LINUX_INITIAL_RLIMIT_13_CUR || c->resource_limits[13].rlim_max!=LINUX_INITIAL_RLIMIT_13_MAX)return OSREC_SLICE_BAD_INPUT;
    if(c->resource_limits[14].rlim_cur!=LINUX_INITIAL_RLIMIT_14_CUR || c->resource_limits[14].rlim_max!=LINUX_INITIAL_RLIMIT_14_MAX)return OSREC_SLICE_BAD_INPUT;
    if(c->resource_limits[15].rlim_cur!=LINUX_INITIAL_RLIMIT_15_CUR || c->resource_limits[15].rlim_max!=LINUX_INITIAL_RLIMIT_15_MAX)return OSREC_SLICE_BAD_INPUT;
    const uint64_t *g=linux_file_generations[next];
    if(c->task.cred!=&c->credential_pool[g[0]] || c->credential_generation!=g[1])return OSREC_SLICE_BAD_INPUT;
    for(unsigned i=0;i<2;++i){
        const struct cred *p=&c->credential_pool[i];const uint64_t *caps=linux_file_capabilities[next][i];
        if(p->user_ns!=&c->user_ns || p->uid!=linux_file_uids[next][i][0] || p->euid!=linux_file_uids[next][i][1] || p->suid!=linux_file_uids[next][i][2] ||
           p->fsuid!=linux_file_fsuids[next][i] || p->securebits!=linux_file_securebits[next][i] || p->fsgid!=linux_file_fsgids[next][i] || p->gid!=linux_file_gids[next][i][0] || p->egid!=linux_file_gids[next][i][1] || p->sgid!=linux_file_gids[next][i][2] || c->credential_slot_generation[i]!=g[2+i] ||
           p->cap_effective.val!=caps[0] || p->cap_permitted.val!=caps[1] || p->cap_inheritable.val!=caps[2] || p->cap_bset.val!=caps[3] || p->cap_ambient.val!=caps[4])return OSREC_SLICE_BAD_INPUT;
    }
    const struct linux_file_groups *groups=&linux_file_groups[next];
    for(unsigned i=0;i<2;++i){
        const struct group_info *p=&c->group_pool[i];
        if(c->credential_pool[i].group_info!=&c->group_pool[groups->links[i]] || p->usage!=groups->usage[i] || p->ngroups!=groups->count[i])return OSREC_SLICE_BAD_INPUT;
        for(unsigned j=0;j<4;++j)if(p->gid[j]!=groups->gids[i][j])return OSREC_SLICE_BAD_INPUT;
    }
    const uint32_t identities[4]={1001,0,9001,9002};
    for(unsigned j=0;j<4;++j){
        int32_t owned=c->task.cred->uid==identities[j];
        if(c->user_pool[j].uid!=identities[j] || c->user_pool[j].usage!=owned || c->ucounts_pool[j].uid!=identities[j] || c->ucounts_pool[j].usage!=owned || c->ucounts_pool[j].ns!=&c->user_ns)return OSREC_SLICE_BAD_INPUT;
    }
    for(unsigned i=0;i<2;++i){
        unsigned user=linux_file_user_links[next][i][0],account=linux_file_user_links[next][i][1];
        if(user>=4 || account>=4 || c->credential_pool[i].user!=&c->user_pool[user] || c->credential_pool[i].ucounts!=&c->ucounts_pool[account])return OSREC_SLICE_BAD_INPUT;
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
    const struct osrec_user_region *sr=osrec_user_memory_object(&in->memory,2,128,3);
    if(!sr || sr->bytes!=128 || !r || r->bytes!=32)return OSREC_SLICE_BAD_INPUT;
    for(unsigned i=5;i<6;++i)if(in->args[i])return OSREC_SLICE_BAD_INPUT;
    for(unsigned i=0;i<5;++i){
        uint64_t expected=call->args[i];
        if(osrec_argument_kind(in->number,i)==3)expected=expected==UINT64_MAX ? 0 : expected==UINT64_MAX-1 ? 1 : (in->number==80 ? sr->user_address : r->user_address)+expected;
        if(in->args[i]!=expected)return OSREC_SLICE_BAD_INPUT;
    }
    for(unsigned i=0;i<8;++i)for(unsigned j=0;j<4;++j)if(r->image_address[4*i+j]!=(unsigned char)(linux_inputs[in->ordinal][i]>>(8*j)))return OSREC_SLICE_BAD_INPUT;
    for(unsigned i=0;i<32;++i)for(unsigned j=0;j<4;++j)if(sr->image_address[4*i+j]!=(unsigned char)((0x5a5a0000u+i)>>(8*j)))return OSREC_SLICE_BAD_INPUT;
    c->active_memory=in->memory;
    uintptr_t arguments[6];for(unsigned i=0;i<6;++i)arguments[i]=(uintptr_t)in->args[i];
    out->raw=osrec_kernel_dispatch(c,in->number,arguments);
    c->active_memory=(struct osrec_user_memory){0};
    if((uint64_t)out->raw!=call->raw || osrec_kernel_checkpoint_check(c,in->ordinal+1))return OSREC_SLICE_DIVERGED;
    for(unsigned i=0;i<8;++i)for(unsigned j=0;j<4;++j)if(r->image_address[4*i+j]!=(unsigned char)(call->words[i]>>(8*j)))return OSREC_SLICE_DIVERGED;
    for(unsigned i=0;i<128;++i){if(in->number==80 && !out->raw && i>=72 && i<120)continue;if(sr->image_address[i]!=(unsigned char)(linux_stat_words[in->ordinal][i/4]>>(8*(i%4))))return OSREC_SLICE_DIVERGED;}
    return OSREC_SLICE_OK;
}
static uint32_t finish(const void *state){return osrec_kernel_checkpoint_check(state,LINUX_CALLS);}
const struct osrec_slice_adapter osrec_kernel_adapter={OSREC_SLICE_ABI,"linux-aarch64-file-limits",sizeof(struct osrec_kernel_context),_Alignof(struct osrec_kernel_context),LINUX_CALLS,restore,enter,finish};
