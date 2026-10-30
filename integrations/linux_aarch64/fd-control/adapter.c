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
    for(unsigned i=0;i<2;++i)if(c->file_pool[i].object_id!=i+1 || c->file_pool[i].f_mode!=(i ? REGULAR_MODE : CONSOLE_MODE) || c->file_pool[i].f_lock || c->file_pool[i].f_version || (i==0 && c->file_pool[i].f_pos) ||
        c->file_pool[i].f_flags!=(i ? LINUX_INITIAL_FILE_FLAGS_1 : LINUX_INITIAL_FILE_FLAGS_0) || c->file_pool[i].f_count!=s->counts[i])return 0;
    for(unsigned fd=0;fd<64;++fd){
        uint32_t id=fd<8 ? s->slots[fd] : 0;
        if(c->files.fdtab.fd[fd]!=(id ? &c->file_pool[id-1] : 0))return 0;
    }
    if(c->superblock.write_depth || c->superblock.s_fsnotify_info)return 0;
    for(unsigned i=0;i<2;++i){
        const struct file_operations *o=&c->fop_pool[i];
        if(c->file_pool[i].f_op!=o || c->file_pool[i].f_pos_lock || c->file_pool[i].f_iocb_flags || o->osrec_class!=i+1 || o->read || !o->read_iter || o->write || !o->write_iter || o->iterate_shared)return 0;
    }
    for(unsigned i=0;i<2;++i)if(c->file_pool[i].f_path.dentry!=&c->dentry_pool[i] || c->dentry_pool[i].d_inode!=&c->inode_pool[i] ||
        c->dentry_pool[i].d_flags || c->dentry_pool[i].d_sb!=&c->superblock || c->inode_pool[i].i_mode!=(i ? 0100000u : 0020000u) || c->inode_pool[i].append || c->inode_pool[i].i_sb!=&c->superblock)return 0;
    const struct linux_file_snapshot *f=&linux_file_data[next];
    if(c->inode_pool[1].i_size!=f->size || c->file_pool[1].f_pos!=f->pos)return 0;
    /* Inode, page-cache and mount topology; the regular file's one folio is cached iff nrpages is 1. */
    const struct folio *folio=&c->folio_pool[0];const struct address_space *data=&c->inode_pool[1].i_data;
    if(data->nrpages>1 || (data->nrpages ? data->i_pages.xa_head!=folio || folio->mapping!=data || folio->index || folio->_refcount.counter<=0 || (folio->flags&1)
        : data->i_pages.xa_head || folio->mapping) || c->inode_pool[0].i_data.i_pages.xa_head || c->inode_pool[0].i_data.nrpages)return 0;
    for(unsigned i=0;i<2;++i){
        const struct inode *n=&c->inode_pool[i];
        if(c->file_pool[i].f_path.mnt!=&c->mount || c->file_pool[i].f_mapping!=&n->i_data || n->i_rwsem || c->fop_pool[i].fop_flags || n->i_mapping!=&n->i_data || n->i_data.host!=n || n->i_data.a_ops!=&c->aops_pool[i] || n->i_op!=&c->iop_pool[i] ||
            n->i_lock || n->i_hash.pprev || n->i_flctx || n->osrec_shmem.lock || n->i_data.i_pages.xa_lock || c->aops_pool[i].osrec_class!=i+1 || c->iop_pool[i].osrec_class!=i+1)return 0;
    }
    if(c->superblock.s_op!=&c->super_ops || c->superblock.s_user_ns!=&c->user_ns || c->mount.mnt_idmap!=&c->nop_mnt_idmap || c->mount.mnt_sb!=&c->superblock ||
        c->mount.osrec_writers || (c->tk_core.seq.sequence&1) || c->inode_wb.list_lock || c->superblock.s_bdi!=&c->noop_bdi)return 0;
    for(unsigned i=0;i<64;++i)if(c->file_data.bytes[i]!=f->bytes[i])return 0;
    return 1;
}
/* Identifier maps the model holds: the base extents only (see model.h). */
static int id_map_ok(const struct uid_gid_map *m){return m->nr_extents<=UID_GID_MAP_MAX_BASE_EXTENTS && !m->forward && !m->reverse;}
static void restore(void *state){osrec_context_restore(state);}
uint32_t osrec_kernel_checkpoint_check(const void *state,uint64_t next)
{
    const struct osrec_kernel_context *c=state;
    return next<=LINUX_CALLS && fd_check(c,next) && c->current==&c->task && c->task.real_parent==&c->parent &&
        c->task.fs==&c->fs && c->task.cred==&c->creds && c->creds.user_ns==&c->user_ns && c->user_ns.initial==1 &&
        c->task.pid==LINUX_INITIAL_PID && c->task.tgid==LINUX_INITIAL_TGID &&
        c->parent.pid==LINUX_INITIAL_PPID && c->parent.tgid==LINUX_INITIAL_PPID && !c->parent.real_parent && !c->parent.fs && !c->parent.cred &&
        c->creds.uid.val==LINUX_INITIAL_UID && c->creds.euid.val==LINUX_INITIAL_EUID && c->creds.suid.val==LINUX_INITIAL_SUID &&
        c->creds.gid.val==LINUX_INITIAL_GID && c->creds.egid.val==LINUX_INITIAL_EGID && c->creds.sgid.val==LINUX_INITIAL_SGID &&
        id_map_ok(&c->user_ns.uid_map) && id_map_ok(&c->user_ns.gid_map) &&
        c->fs.umask==(int)linux_masks[next] && !c->rcu_depth && !c->active_memory.regions && !c->active_memory.count ? OSREC_SLICE_OK : OSREC_SLICE_BAD_INPUT;
}
static uint32_t enter(void *state,const struct osrec_slice_invocation *in,struct osrec_slice_result *out)
{
    struct osrec_kernel_context *c=state;
    if(in->ordinal>=LINUX_CALLS || osrec_kernel_checkpoint_check(c,in->ordinal))return OSREC_SLICE_BAD_INPUT;
    const struct linux_observation *call=&linux_calls[in->ordinal];
    if(in->number!=call->number)return OSREC_SLICE_BAD_INPUT;
    const struct osrec_user_region *r=osrec_user_memory_object(&in->memory,1,32,3);
    if(!r || r->bytes!=32)return OSREC_SLICE_BAD_INPUT;
    for(unsigned i=4;i<6;++i)if(in->args[i])return OSREC_SLICE_BAD_INPUT;
    for(unsigned i=0;i<4;++i){
        uint64_t expected=call->args[i];
        if(osrec_argument_kind(in->number,i)==3)expected=expected==UINT64_MAX ? 0 : expected==UINT64_MAX-1 ? 1 : r->user_address+expected;
        if(in->args[i]!=expected)return OSREC_SLICE_BAD_INPUT;
    }
    for(unsigned i=0;i<8;++i)for(unsigned j=0;j<4;++j)if(r->image_address[4*i+j]!=(unsigned char)(linux_inputs[in->ordinal][i]>>(8*j)))return OSREC_SLICE_BAD_INPUT;
    c->active_memory=in->memory;
    uintptr_t arguments[6];for(unsigned i=0;i<6;++i)arguments[i]=(uintptr_t)in->args[i];
    out->raw=osrec_kernel_dispatch(c,in->number,arguments);
    c->active_memory=(struct osrec_user_memory){0};
    if((uint64_t)out->raw!=call->raw || osrec_kernel_checkpoint_check(c,in->ordinal+1))return OSREC_SLICE_DIVERGED;
    for(unsigned i=0;i<8;++i)for(unsigned j=0;j<4;++j)if(r->image_address[4*i+j]!=(unsigned char)(call->words[i]>>(8*j)))return OSREC_SLICE_DIVERGED;
    return OSREC_SLICE_OK;
}
static uint32_t finish(const void *state){return osrec_kernel_checkpoint_check(state,LINUX_CALLS);}
const struct osrec_slice_adapter osrec_kernel_adapter={OSREC_SLICE_ABI,"linux-aarch64-fd-control",sizeof(struct osrec_kernel_context),_Alignof(struct osrec_kernel_context),LINUX_CALLS,restore,enter,finish};
