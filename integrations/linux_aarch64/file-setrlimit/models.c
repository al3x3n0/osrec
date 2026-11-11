#include "model.h"
#include "capture.h"
/* Reviewed state projection; not Linux's physical task_struct layout. */
struct user_namespace user_ns={1};
struct user_struct user_pool[4]={{1001,1},{0,0},{9001,0},{9002,0}};
struct ucounts ucounts_pool[4]={{&user_ns,1001,1},{&user_ns,0,0},{&user_ns,9001,0},{&user_ns,9002,0}};
struct fs_struct fs={LINUX_INITIAL_UMASK};
struct group_info group_pool[2]={{1,1,{LINUX_INITIAL_OWNER_GROUP,0,0,0}},{0}};
struct group_info *allocated_group;
#define INITIAL_CRED(ns,groups,usr,acct) {LINUX_INITIAL_UID,LINUX_INITIAL_EUID,LINUX_INITIAL_SUID,LINUX_INITIAL_GID,LINUX_INITIAL_EGID,LINUX_INITIAL_SGID,LINUX_INITIAL_FILE_FSGID,LINUX_INITIAL_FILE_FSUID,LINUX_INITIAL_FILE_SECUREBITS,{LINUX_INITIAL_FILE_CAP_EFFECTIVE},{LINUX_INITIAL_FILE_CAP_PERMITTED},{LINUX_INITIAL_FILE_CAP_INHERITABLE},{LINUX_INITIAL_FILE_CAP_BSET},{LINUX_INITIAL_FILE_CAP_AMBIENT},ns,groups,usr,acct}
struct cred credential_pool[2]={INITIAL_CRED(&user_ns,&group_pool[0],&user_pool[0],&ucounts_pool[0]),INITIAL_CRED(&user_ns,&group_pool[0],&user_pool[0],&ucounts_pool[0])};
struct cred *pending_credential;
uint64_t credential_generation,credential_slot_generation[2];
struct task_struct parent={.pid=LINUX_INITIAL_PPID,.tgid=LINUX_INITIAL_PPID};
struct super_block superblock={0};
#define INITIAL_INODE(block,id) {LINUX_INITIAL_STAT_MODE_##id,0,block,LINUX_INITIAL_STAT_DEV_##id,LINUX_INITIAL_STAT_RDEV_##id,LINUX_INITIAL_STAT_NLINK_##id,LINUX_INITIAL_STAT_UID_##id,LINUX_INITIAL_STAT_GID_##id,LINUX_INITIAL_STAT_BLKSIZE_##id,LINUX_INITIAL_STAT_INO_##id,LINUX_INITIAL_STAT_BLOCKS_##id,0}
struct inode inode_pool[2]={INITIAL_INODE(&superblock,0),INITIAL_INODE(&superblock,1)};
struct dentry dentry_pool[2]={{&inode_pool[0]},{&inode_pool[1]}};
struct vfsmount mount_pool[2]={{1,0},{2,0}};
#define INITIAL_FILE(count,mode,flags,id,path,mount) {count,mode,flags,id,0,0,0,{path,mount}}
struct file file_pool[2]={INITIAL_FILE(3,FMODE_STREAM,LINUX_INITIAL_FILE_FLAGS_0,1,&dentry_pool[0],&mount_pool[0]),INITIAL_FILE(1,31,LINUX_INITIAL_FILE_FLAGS_1,2,&dentry_pool[1],&mount_pool[1])};
struct file_data file_data={16,{97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112}};
#define INITIAL_FILES(table,console,seed) {table,{64,{console,console,console,seed},{8},{15},{0}},4,0,0}
struct files_struct files=INITIAL_FILES(&files.fdtab,&file_pool[0],&file_pool[1]);
#define INITIAL_TASK(par,filesystem,credential,descriptors,sig,leader) {LINUX_INITIAL_PID,LINUX_INITIAL_TGID,par,filesystem,credential,descriptors,0,sig,leader}
struct task_struct task=INITIAL_TASK(&parent,&fs,&credential_pool[0],&files,&process_signal,&task);
struct task_struct *current=&task;
struct osrec_user_memory active_memory;
int rcu_depth;
int task_tgid_vnr(const struct task_struct *p){return p->tgid;}
int task_pid_vnr(const struct task_struct *p){return p->pid;}
const struct cred *current_cred(void){return current->cred;}
struct user_namespace *current_user_ns(void){return current_cred()->user_ns;}
uid_t current_uid(void){return current_cred()->uid;}
uid_t current_euid(void){return current_cred()->euid;}
uid_t current_fsuid(void){return current_cred()->fsuid;}
gid_t current_gid(void){return current_cred()->gid;}
gid_t current_egid(void){return current_cred()->egid;}
gid_t current_fsgid(void){return current_cred()->fsgid;}
uid_t from_kuid_munged(const struct user_namespace *ns,uid_t value){return ns->initial ? value : 65534;}
gid_t from_kgid_munged(const struct user_namespace *ns,gid_t value){return ns->initial ? value : 65534;}
void rcu_read_lock(void){++rcu_depth;}
void rcu_read_unlock(void){--rcu_depth;}
int linux_xchg_int(int *p,int value){int old=*p;*p=value;return old;}
int linux_put_user_u32(uint32_t value,uint32_t *p)
{
    const struct osrec_user_region *r=osrec_user_memory_object(&active_memory,1,32,3);
    if(!r || (uintptr_t)p<r->user_address || (uintptr_t)p-r->user_address>28)return -14;
    unsigned char *target=osrec_user_memory_resolve(&active_memory,(uintptr_t)p,4,OSREC_MEMORY_WRITE);
    if(!target)return -14;
    for(unsigned i=0;i<4;++i)target[i]=(unsigned char)(value>>(8*i));
    return 0;
}

/* Reviewed sequential ownership/locking/flush boundaries. No host consumers. */
int model_fault;
int linux_assert(int failure){if(failure)model_fault=1;return !!failure;}
void spin_lock(int *lock){linux_assert(*lock!=0);++*lock;}
void spin_unlock(int *lock){linux_assert(*lock!=1);--*lock;}
void lockdep_assert_held(const int *lock){linux_assert(*lock!=1);}
unsigned long find_next_zero_bit(const unsigned long *bits,unsigned long size,unsigned long start){for(unsigned long i=start;i<size;++i)if(!(bits[i/64]&(1ul<<(i%64))))return i;return size;}
unsigned long array_index_mask_nospec(unsigned long index,unsigned long size){return index<size ? ~0ul : 0;}
unsigned int array_index_nospec(unsigned int index,unsigned int size){linux_assert(index>=size);return index<size ? index : 0;}
struct fdtable *files_fdtable(struct files_struct *p){return p->fdt;}
int expand_files(struct files_struct *p,unsigned int fd){linux_assert(p!=current->files || p->resize_in_progress);return fd<64 ? 0 : -EMFILE;}
struct signal_struct process_signal={{{LINUX_INITIAL_RLIMIT_0_CUR,LINUX_INITIAL_RLIMIT_0_MAX},{LINUX_INITIAL_RLIMIT_1_CUR,LINUX_INITIAL_RLIMIT_1_MAX},{LINUX_INITIAL_RLIMIT_2_CUR,LINUX_INITIAL_RLIMIT_2_MAX},{LINUX_INITIAL_RLIMIT_3_CUR,LINUX_INITIAL_RLIMIT_3_MAX},{LINUX_INITIAL_RLIMIT_4_CUR,LINUX_INITIAL_RLIMIT_4_MAX},{LINUX_INITIAL_RLIMIT_5_CUR,LINUX_INITIAL_RLIMIT_5_MAX},{LINUX_INITIAL_RLIMIT_6_CUR,LINUX_INITIAL_RLIMIT_6_MAX},{LINUX_INITIAL_RLIMIT_7_CUR,LINUX_INITIAL_RLIMIT_7_MAX},{LINUX_INITIAL_RLIMIT_8_CUR,LINUX_INITIAL_RLIMIT_8_MAX},{LINUX_INITIAL_RLIMIT_9_CUR,LINUX_INITIAL_RLIMIT_9_MAX},{LINUX_INITIAL_RLIMIT_10_CUR,LINUX_INITIAL_RLIMIT_10_MAX},{LINUX_INITIAL_RLIMIT_11_CUR,LINUX_INITIAL_RLIMIT_11_MAX},{LINUX_INITIAL_RLIMIT_12_CUR,LINUX_INITIAL_RLIMIT_12_MAX},{LINUX_INITIAL_RLIMIT_13_CUR,LINUX_INITIAL_RLIMIT_13_MAX},{LINUX_INITIAL_RLIMIT_14_CUR,LINUX_INITIAL_RLIMIT_14_MAX},{LINUX_INITIAL_RLIMIT_15_CUR,LINUX_INITIAL_RLIMIT_15_MAX}}};
static struct rlimit *resource_limit(unsigned int resource)
{
    linux_assert(resource>=RLIM_NLIMITS);
    return &current->signal->rlim[resource];
}
unsigned long rlimit(unsigned int resource){return resource_limit(resource)->rlim_cur;}
int resource_lock_depth;
bool capable(int cap){linux_assert(cap!=CAP_SYS_RESOURCE);return ns_capable(current_user_ns(),cap);}
int security_task_setrlimit(struct task_struct *p,unsigned int resource,struct rlimit *value)
{
    return linux_assert(p!=current || resource_lock_depth!=1 || !value || (resource!=3 && resource!=4 && resource!=7 && resource!=8)) ? -EINVAL : 0;
}
void update_rlimit_cpu(struct task_struct *p,unsigned long value){(void)p;(void)value;linux_assert(1);}
void __set_open_fd(unsigned int fd,struct fdtable *t){t->open_fds[fd/64]|=1ul<<(fd%64);if(t->open_fds[fd/64]==~0ul)t->full_fds_bits[0]|=1ul<<(fd/64);}
void __clear_open_fd(unsigned int fd,struct fdtable *t){t->open_fds[fd/64]&=~(1ul<<(fd%64));t->full_fds_bits[0]&=~(1ul<<(fd/64));}
void __set_close_on_exec(unsigned int fd,struct fdtable *t){t->close_on_exec[fd/64]|=1ul<<(fd%64);}
void __clear_close_on_exec(unsigned int fd,struct fdtable *t){t->close_on_exec[fd/64]&=~(1ul<<(fd%64));}
int fd_is_open(unsigned int fd,const struct fdtable *t){return !!(t->open_fds[fd/64]&(1ul<<(fd%64)));}
struct file *files_lookup_fd_locked(struct files_struct *p,unsigned int fd){lockdep_assert_held(&p->file_lock);return fd<p->fdt->max_fds ? p->fdt->fd[fd] : 0;}
int atomic_long_inc_not_zero(int64_t *count){if(!*count)return 0;linux_assert(*count<0);++*count;return 1;}
struct file *get_file(struct file *p){linux_assert(!p || p->f_count<=0);if(p)++p->f_count;return p;}
void fput(struct file *p){linux_assert(!p || p->f_count<=0);if(p)--p->f_count;}
void __fput_sync(struct file *p){fput(p);}
int filp_flush(struct file *p,fl_owner_t owner){linux_assert(!p || p->f_count<=0 || owner!=current->files || current->files->file_lock);return 0;}

void rcu_read_lock_sched(void){rcu_read_lock();}
void rcu_read_unlock_sched(void){rcu_read_unlock();}

/* Reviewed regular-file callback and strong-reference fdget/put boundaries. */
struct fd fdget_pos(unsigned int fd){struct file *p=fget_raw(fd);return (struct fd){p,p ? 1u : 0u};}
void fdput_pos(struct fd f){if(f.flags)fput(f.file);}
int security_file_permission(struct file *p,int mask){linux_assert(p->object_id!=2 || (mask!=MAY_READ && mask!=MAY_WRITE));return 0;}
int fsnotify_file_area_perm(struct file *p,int mask,const loff_t *pos,size_t count){(void)p;(void)mask;(void)pos;(void)count;return 0;}
loff_t vfs_llseek(struct file *p,loff_t offset,int whence){if(!(p->f_mode&4))return -ESPIPE;linux_assert(p->object_id!=2 || whence==SEEK_DATA || whence==SEEK_HOLE);return generic_file_llseek_size(p,offset,whence,INT64_MAX,file_data.size);}
static ssize_t regular_transfer(struct file *p,uintptr_t address,size_t count,loff_t *pos,int writing)
{
    linux_assert(p->object_id!=2 || !pos || *pos<0);
    if(!pos || *pos<0)return -EINVAL;
    /* arm64 access_ok(): TASK_SIZE_MAX is 1 << VA_BITS (48 here); a live boundary
     * observed a successful read from a stack buffer above 1 << 47. */
    if(count>UINT64_C(1)<<48 || address>(UINT64_C(1)<<48)-count)return -EFAULT;
    int error=rw_verify_area(writing ? WRITE : READ,p,pos,count);if(error)return error;
    uint64_t start=(uint64_t)*pos;
    if(writing && count && (p->f_flags&O_APPEND))start=(uint64_t)file_data.size;
    if(!writing && start>=(uint64_t)file_data.size)return 0;
    if(!count)return 0;
    uint64_t length=count;
    if(!writing && length>(uint64_t)file_data.size-start)length=(uint64_t)file_data.size-start;
    linux_assert(writing && (start>64 || length>64-start));
    if(writing && (start>64 || length>64-start))return -EINVAL;
    const struct osrec_user_region *region=osrec_user_memory_object(&active_memory,1,32,3);
    linux_assert(!region);if(!region)return -EFAULT;
    size_t copied=0;
    while(copied<length){
        /* Other imported ELF segments can cover the native guard page.
         * Only this admitted 32-byte caller object is accessible to copies. */
        if(address+copied<region->user_address || address+copied-region->user_address>=32)break;
        unsigned char *at=osrec_user_memory_resolve(&active_memory,address+copied,1,writing ? OSREC_MEMORY_READ : OSREC_MEMORY_WRITE);
        if(!at)break;
        if(start+copied>=64)break; /* file_data.bytes capacity; also proves the index for the analyzer */
        if(writing)file_data.bytes[start+copied]=*at;else *at=file_data.bytes[start+copied];
        ++copied;
    }
    if(!copied)return -EFAULT;
    if(writing && start+copied>(uint64_t)file_data.size)file_data.size=(int64_t)(start+copied);
    if(writing)file_inode(p)->blocks=8;
    *pos=(loff_t)(start+copied);
    return (ssize_t)copied;
}
ssize_t vfs_read(struct file *p,char *buf,size_t count,loff_t *pos){return regular_transfer(p,(uintptr_t)buf,count,pos,0);}
ssize_t vfs_write(struct file *p,const char *buf,size_t count,loff_t *pos){return regular_transfer(p,(uintptr_t)buf,count,pos,1);}

/* Reviewed inode mutation/LSM/superblock boundaries; preserve shared f_pos. */
struct fd fdget(unsigned int fd){return fdget_pos(fd);}
void fdput(struct fd f){fdput_pos(f);}
struct inode *file_inode(struct file *p){return p->f_path.dentry->d_inode;}
void sb_start_write(struct super_block *p){linux_assert(p->write_depth!=0);++p->write_depth;}
void sb_end_write(struct super_block *p){linux_assert(p->write_depth!=1);--p->write_depth;}
int security_file_truncate(struct file *p){linux_assert(p->object_id!=2);return 0;}
void *file_mnt_idmap(struct file *p){linux_assert(p->object_id!=2);return 0;}
int do_truncate(void *map,struct dentry *d,loff_t length,unsigned int attributes,struct file *p)
{
    linux_assert(map || p->object_id!=2 || d!=p->f_path.dentry || !S_ISREG(d->d_inode->i_mode) || d->d_inode->i_sb->write_depth!=1 || attributes!=(ATTR_MTIME|ATTR_CTIME) || length<0 || length>64);
    if(length<0 || length>64)return -EINVAL;
    /* Discarded tail must not reappear after a subsequent extension. */
    for(unsigned i=(unsigned)length;i<64;++i)file_data.bytes[i]=0;
    file_data.size=length;
    if(!length)d->d_inode->blocks=0;
    return 0;
}

/* Reviewed six-command syscall boundary, not original sys_fcntl/do_fcntl.
 * Retained Linux helpers own bitmap mutation and minimum-fd duplication.
 * Only non-O_PATH files and successful LSM admission are in this profile. */
bool close_on_exec(unsigned int fd,struct files_struct *p)
{
    linux_assert(rcu_depth!=1 || fd>=p->fdt->max_fds);
    return !!(p->fdt->close_on_exec[fd/64]&(UINT64_C(1)<<(fd%64)));
}
/* Reviewed memfd-only F_SETFL boundary, not the upstream setfl body.
 * Only APPEND/NONBLOCK/NOATIME are mutable. No async/direct or inode-append flags. */
static int linux_set_file_status(struct file *p,unsigned int flags)
{
    linux_assert(p->object_id!=2 || (flags&(O_DIRECT|FASYNC)) || file_inode(p)->append);
    if((flags&O_NOATIME) && !(p->f_flags&O_NOATIME) && file_inode(p)->uid!=current_fsuid() && !(current_cred()->cap_effective.val&UINT64_C(8)))return -EPERM;
    const unsigned mask=O_APPEND|O_NONBLOCK|O_NOATIME;
    spin_lock(&p->f_lock);p->f_flags=(p->f_flags&~mask)|(flags&mask);spin_unlock(&p->f_lock);
    return 0;
}
long linux_fcntl(unsigned int fd,unsigned int cmd,unsigned long arg)
{
    struct file *p=fget_raw(fd);
    if(!p)return -EBADF;
    long result=-EINVAL;
    switch(cmd){
    case 0:result=f_dupfd((unsigned int)arg,p,0);break;
    case 1030:result=f_dupfd((unsigned int)arg,p,O_CLOEXEC);break;
    case 1:result=get_close_on_exec(fd) ? 1 : 0;break;
    case 2:set_close_on_exec(fd,(int)(arg&1));result=0;break;
    case 3:result=p->f_flags;break;
    case 4:result=linux_set_file_status(p,(unsigned int)arg);break;
    default:break;
    }
    fput(p);
    return result;
}

/* Reviewed bitmap and sequential scheduling boundaries. Closed slots matter. */
void bitmap_set(uint64_t *bits,unsigned int first,unsigned int count)
{
    linux_assert(current->files->file_lock!=1 || bits!=current->files->fdt->close_on_exec || first>=64 || count>64-first);
    if(first>=64 || count>64-first)return;
    for(unsigned int i=first;i<first+count;++i)bits[i/64]|=UINT64_C(1)<<(i%64);
}
void cond_resched(void){linux_assert(current->files->file_lock || rcu_depth);}
bool need_resched(void){linux_assert(current->files->file_lock!=1);return false;}
/* Excluded UNSHARE/table-replacement branches must never be admitted silently. */
int unshare_fd(unsigned long flags,unsigned int max,struct files_struct **out){(void)flags;(void)max;(void)out;linux_assert(1);return -EINVAL;}
void task_lock(struct task_struct *p){linux_assert(p!=current || p->group_leader!=p || resource_lock_depth);++resource_lock_depth;}
void task_unlock(struct task_struct *p){linux_assert(p!=current || resource_lock_depth!=1);--resource_lock_depth;}
void put_files_struct(struct files_struct *p){(void)p;linux_assert(1);}

/* Reviewed direct getattr, device encoding and user-copy boundaries. Clock
 * fields are unconsumed by this application and represented as zero. */
void *memset(void *out,int value,size_t count){for(size_t i=0;i<count;++i)((unsigned char *)out)[i]=(unsigned char)value;return out;}
bool old_valid_dev(uint32_t dev){return (dev>>20)<256 && (dev&0xfffff)<256;}
uint32_t new_encode_dev(uint32_t dev){uint32_t minor=dev&0xfffff;return (minor&0xff)|((dev>>20)<<8)|((minor&~0xffu)<<12);}
struct fd fdget_raw(unsigned int fd){return fdget_pos(fd);}
int security_inode_getattr(const struct path *path){linux_assert(!path || !path->dentry);return 0;}
int vfs_getattr_nosec(const struct path *path,struct kstat *out,u32 mask,unsigned int flags)
{
    struct inode *p=path->dentry->d_inode;
    linux_assert(mask!=STATX_BASIC_STATS || flags || (p!=&inode_pool[0] && p!=&inode_pool[1]));
    memset(out,0,sizeof(*out));
    out->dev=p->dev;out->rdev=p->rdev;out->ino=p->ino;out->mode=p->i_mode;out->nlink=p->nlink;out->uid=p->uid;out->gid=p->gid;
    out->size=p==&inode_pool[1] ? file_data.size : 0;out->blocks=p->blocks;out->blksize=p->blksize;
    return 0;
}
unsigned long copy_to_user(void *out,const void *in,unsigned long count)
{
    const struct osrec_user_region *r=0;
    size_t capacity=0;
    for(unsigned id=1;id<=2;++id){
        size_t bytes=id==1 ? 32 : 128;
        const struct osrec_user_region *candidate=osrec_user_memory_object(&active_memory,id,bytes,3);
        if(candidate && (uintptr_t)out>=candidate->user_address && (uintptr_t)out-candidate->user_address<bytes){r=candidate;capacity=bytes;break;}
    }
    if(!r)return count;
    size_t copied=0;
    while(copied<count){
        uintptr_t address=(uintptr_t)out+copied;
        if(address<r->user_address || address-r->user_address>=capacity)break;
        unsigned char *p=osrec_user_memory_resolve(&active_memory,address,1,OSREC_MEMORY_WRITE);
        if(!p)break;*p=((const unsigned char *)in)[copied];++copied;
    }
    return count-copied;
}

/* Reviewed chmod boundary: one owner, ordinary permission bits, no ACL or
 * delegation consumer. Open-file access modes remain fixed after chmod. */
int mnt_want_write(struct vfsmount *p){linux_assert((p!=&mount_pool[0] && p!=&mount_pool[1]) || p->write_depth);++p->write_depth;return 0;}
void mnt_drop_write(struct vfsmount *p){linux_assert(p->write_depth!=1);--p->write_depth;}
struct mnt_idmap *mnt_idmap(struct vfsmount *p){linux_assert(p->write_depth!=1);return 0;}
void inode_lock(struct inode *p){linux_assert(p->lock_depth);++p->lock_depth;}
void inode_unlock(struct inode *p){linux_assert(p->lock_depth!=1);--p->lock_depth;}
int security_path_chmod(const struct path *p,umode_t mode){(void)mode;linux_assert(p->dentry->d_inode->lock_depth!=1 || p->mnt->write_depth!=1);return 0;}
int notify_change(struct mnt_idmap *map,struct dentry *d,struct iattr *a,struct inode **delegated)
{
    struct inode *p=d->d_inode;
    linux_assert(map || !delegated || *delegated || p->lock_depth!=1);
    if(a->ia_valid&ATTR_MODE){
        linux_assert(a->ia_valid!=(ATTR_MODE|ATTR_CTIME) || (a->ia_mode&07000) || ((a->ia_mode^p->i_mode)&~07777u));
        if(p->uid!=current_fsuid() && !(current_cred()->cap_effective.val&UINT64_C(8)))return -EPERM;
        p->i_mode=a->ia_mode;
    }else{
        linux_assert((a->ia_valid&~(ATTR_CTIME|ATTR_KILL_SUID|ATTR_KILL_PRIV|ATTR_UID|ATTR_GID)) || (a->ia_valid&(ATTR_CTIME|ATTR_KILL_SUID|ATTR_KILL_PRIV))!=(ATTR_CTIME|ATTR_KILL_SUID|ATTR_KILL_PRIV) || (p->i_mode&07000));
        bool owner=p->uid==current_fsuid();
        bool chown=current_cred()->cap_effective.val&UINT64_C(1);
        if(!chown && (a->ia_valid&ATTR_UID) && (!owner || a->ia_vfsuid!=p->uid))return -EPERM;
        if(!chown && (a->ia_valid&ATTR_GID) && (!owner || (a->ia_vfsgid!=p->gid && a->ia_vfsgid!=current_fsgid() && !linux_in_supplementary_group(a->ia_vfsgid))))return -EPERM;
        if(a->ia_valid&ATTR_UID)p->uid=a->ia_vfsuid;
        if(a->ia_valid&ATTR_GID)p->gid=a->ia_vfsgid;
    }
    return 0;
}
int break_deleg_wait(struct inode **p){(void)p;linux_assert(1);return -EINVAL;}
void audit_file(struct file *p){linux_assert(!p || p->f_count<2);}

/* Initial namespace conversions; no idmapped mounts. */
kuid_t make_kuid(const struct user_namespace *ns,uid_t v){linux_assert(ns!=&user_ns || !ns->initial);return v;}
kgid_t make_kgid(const struct user_namespace *ns,gid_t v){linux_assert(ns!=&user_ns || !ns->initial);return v;}
struct user_namespace *i_user_ns(struct inode *p){linux_assert(p!=&inode_pool[0] && p!=&inode_pool[1]);return &user_ns;}
int setattr_should_drop_sgid(struct mnt_idmap *map,struct inode *p){linux_assert(map || p->lock_depth!=1 || (p->i_mode&07000));return 0;}
kuid_t from_vfsuid(struct mnt_idmap *map,struct user_namespace *ns,vfsuid_t v){linux_assert(map || ns!=&user_ns);return v;}
kgid_t from_vfsgid(struct mnt_idmap *map,struct user_namespace *ns,vfsgid_t v){linux_assert(map || ns!=&user_ns);return v;}
int security_path_chown(const struct path *p,kuid_t uid,kgid_t gid){(void)uid;(void)gid;linux_assert(p->dentry->d_inode->lock_depth!=1 || p->mnt->write_depth!=1);return 0;}
int mnt_want_write_file(struct file *p){return mnt_want_write(p->f_path.mnt);}
void mnt_drop_write_file(struct file *p){mnt_drop_write(p->f_path.mnt);}

/* Two bounded slots; candidate state survives abort without publication. */
struct cred *prepare_creds(void)
{
    if(pending_credential){linux_assert(1);return 0;}
    struct cred *candidate=current->cred==&credential_pool[0] ? &credential_pool[1] : &credential_pool[0];
    *candidate=*current->cred;get_group_info(candidate->group_info);get_uid(candidate->user);get_ucounts(candidate->ucounts);pending_credential=candidate;return candidate;
}
int commit_creds(struct cred *candidate)
{
    if(linux_assert(candidate!=pending_credential || candidate==current->cred))return -EINVAL;
    put_group_info(current->cred->group_info);free_uid(current->cred->user);put_ucounts(current->cred->ucounts);current->cred=candidate;++credential_generation;
    credential_slot_generation[candidate==&credential_pool[1]]=credential_generation;
    pending_credential=0;return 0;
}
void abort_creds(struct cred *candidate){linux_assert(candidate!=pending_credential);put_group_info(candidate->group_info);free_uid(candidate->user);put_ucounts(candidate->ucounts);pending_credential=0;}
int linux_get_user_u32(uint32_t *value,const uint32_t *p)
{
    const struct osrec_user_region *r=osrec_user_memory_object(&active_memory,1,32,3);
    if(!r || (uintptr_t)p<r->user_address || (uintptr_t)p-r->user_address>28)return -EFAULT;
    const unsigned char *source=osrec_user_memory_resolve(&active_memory,(uintptr_t)p,4,OSREC_MEMORY_READ);
    if(!source)return -EFAULT;
    uint32_t v=0;for(unsigned i=0;i<4;++i)v|=(uint32_t)source[i]<<(8*i);*value=v;return 0;
}

kernel_cap_t cap_combine(kernel_cap_t a,kernel_cap_t b){return (kernel_cap_t){a.val|b.val};}
kernel_cap_t cap_intersect(kernel_cap_t a,kernel_cap_t b){return (kernel_cap_t){a.val&b.val};}
bool cap_issubset(kernel_cap_t a,kernel_cap_t b){return (a.val&~b.val)==0;}
bool cap_ambient_invariant_ok(const struct cred *p){return (p->cap_ambient.val&~(p->cap_permitted.val&p->cap_inheritable.val))==0;}
int cap_capable(const struct cred *p,const struct user_namespace *ns,int cap,unsigned options)
{
    (void)options;return ns==p->user_ns && ns->initial && cap>=0 && cap<=40 && (p->cap_effective.val&(UINT64_C(1)<<cap)) ? 0 : -EPERM;
}
int security_capset(struct cred *candidate,const struct cred *old,const kernel_cap_t *e,const kernel_cap_t *i,const kernel_cap_t *p)
{
    if(candidate!=pending_credential || old!=current->cred)return -EINVAL;
    return cap_capset(candidate,old,e,i,p);
}
/* Capture/replay has no external audit or warning consumer. */
void audit_log_capset(const struct cred *candidate,const struct cred *old){(void)candidate;(void)old;}
void warn_legacy_capability_use(void){}
void warn_deprecated_v2(void){}
unsigned long linux_copy_from_user(void *out,const void *in,unsigned long n)
{
    const struct osrec_user_region *r=osrec_user_memory_object(&active_memory,1,32,3);
    unsigned char *destination=out;
    for(unsigned long j=0;j<n;++j){
        uintptr_t at=(uintptr_t)in+j;
        const unsigned char *source=r && at>=r->user_address && at-r->user_address<32 ? osrec_user_memory_resolve(&active_memory,at,1,OSREC_MEMORY_READ) : 0;
        if(!source){for(unsigned long k=j;k<n;++k)destination[k]=0;return n-j;}
        destination[j]=*source;
    }
    return 0;
}

/* Group changes preserve capability sets; no additional rejecting LSM consumer. */
bool gid_valid(kgid_t v){return v!=UINT32_MAX;}
bool gid_eq(kgid_t a,kgid_t b){return a==b;}
bool ns_capable_setid(const struct user_namespace *ns,int cap){return ns==current_cred()->user_ns && ns->initial && (cap==CAP_SETGID || cap==CAP_SETUID) && (current_cred()->cap_effective.val&(UINT64_C(1)<<cap));}
int security_task_fix_setgid(struct cred *candidate,const struct cred *old,int flags){return candidate==pending_credential && old==current->cred && (flags==LSM_SETID_FS || flags==LSM_SETID_ID || flags==LSM_SETID_RE || flags==LSM_SETID_RES) ? 0 : -EINVAL;}

bool uid_eq(kuid_t a,kuid_t b){return a==b;}
int security_task_fix_setuid(struct cred *candidate,const struct cred *old,int flags){return candidate==pending_credential && old==current->cred && (flags==LSM_SETID_FS || flags==LSM_SETID_ID || flags==LSM_SETID_RE || flags==LSM_SETID_RES) ? cap_task_fix_setuid(candidate,old,flags) : -EINVAL;}

/* Inactive credentials retain non-owning last-copy pointers. Only the active
 * credential, a prepared candidate and a caller allocation own model refs. */
struct group_info *groups_alloc(int count)
{
    if(allocated_group || count<0 || count>4)return 0;
    for(unsigned i=0;i<2;++i)if(!group_pool[i].usage){
        struct group_info *p=&group_pool[i];p->usage=1;p->ngroups=count;
        for(unsigned j=0;j<4;++j)p->gid[j]=0;
        allocated_group=p;return p;
    }
    return 0;
}
void get_group_info(struct group_info *p){++p->usage;}
void put_group_info(struct group_info *p){--p->usage;if(p==allocated_group)allocated_group=0;}
/* Reviewed replacement for Linux sort's indirect comparator dependency. */
void groups_sort(struct group_info *p)
{
    for(int i=1;i<p->ngroups;++i){uint32_t v=p->gid[i];int j=i;
        while(j>0 && p->gid[j-1]>v){p->gid[j]=p->gid[j-1];--j;}p->gid[j]=v;}
}

/* Initial namespace enabled by the successful native constructor setgroups. */
bool userns_may_setgroups(const struct user_namespace *ns){return ns==current_cred()->user_ns && ns->initial;}
int security_task_fix_setgroups(struct cred *candidate,const struct cred *old){return candidate==pending_credential && old==current->cred ? 0 : -EINVAL;}
bool linux_in_supplementary_group(kgid_t gid){const struct group_info *p=current_cred()->group_info;for(int j=0;j<p->ngroups;++j)if(p->gid[j]==gid)return true;return false;}

/* Single-task target lookup; INT32_MAX is absent in the admitted native recipe. */
struct task_struct *find_task_by_vpid(pid_t pid){return pid==current->pid ? current : 0;}
int security_capget(const struct task_struct *target,kernel_cap_t *e,kernel_cap_t *i,kernel_cap_t *p)
{
    linux_assert(target!=current);
    return cap_capget(target,e,i,p);
}

/* Effective privilege in the captured initial namespace; no external audit consumer. */
bool ns_capable(const struct user_namespace *ns,int cap)
{
    return cap_capable(current_cred(),ns,cap,CAP_OPT_NONE)==0;
}

/* Bounded users/accounting, with native-observed unlimited NPROC. */
struct user_struct *alloc_uid(kuid_t uid)
{
    for(unsigned i=0;i<4;++i)if(user_pool[i].uid==uid){get_uid(&user_pool[i]);return &user_pool[i];}
    return 0;
}
void get_uid(struct user_struct *p){++p->usage;}
void free_uid(struct user_struct *p){--p->usage;}
struct ucounts *alloc_ucounts(struct user_namespace *ns,kuid_t uid)
{
    for(unsigned i=0;i<4;++i)if(ucounts_pool[i].ns==ns && ucounts_pool[i].uid==uid){get_ucounts(&ucounts_pool[i]);return &ucounts_pool[i];}
    return 0;
}
void get_ucounts(struct ucounts *p){++p->usage;}
void put_ucounts(struct ucounts *p){--p->usage;}
struct ucounts *current_ucounts(void){return current_cred()->ucounts;}
/* The reviewed sequential task has an unlimited NPROC limit. Exec/fork and
 * external accounting consumers are outside this profile. */
bool is_rlimit_overlimit(const struct ucounts *p,int type,uint64_t limit){(void)p;(void)type;(void)limit;return false;}

/* fs/read_write.c vfs_writev on the regular file store (vfs_write above): FMODE_WRITE (both files of this model can
 * write, so FMODE_CAN_WRITE holds), then import_iovec's checks on the iovec in the admitted call buffer (more than
 * UIO_MAXIOV segments, or a negative length, is EINVAL; a length is clamped to MAX_RW_COUNT in total), then the
 * segments in order through the store, as the shmem write_iter does. More than UIO_FASTIOV segments would kmalloc
 * the iovec array, which this model does not hold. */
ssize_t vfs_writev(struct file *p,const struct iovec __user *vec,unsigned long vlen,loff_t *pos,rwf_t flags)
{
    (void)flags;
    if(!(p->f_mode&FMODE_WRITE))return -EBADF;
    if(vlen>UIO_MAXIOV)return -EINVAL;
    if(linux_assert(vlen>UIO_FASTIOV))return -ENOMEM;
    uint64_t base[UIO_FASTIOV],length[UIO_FASTIOV],total=0;
    for(unsigned long i=0;i<vlen;++i){
        uint32_t w[4];const uint32_t *entry=(const uint32_t *)((uintptr_t)vec+16*i);
        for(unsigned j=0;j<4;++j)if(linux_get_user_u32(&w[j],entry+j))return -EFAULT;
        base[i]=(uint64_t)w[1]<<32|w[0];length[i]=(uint64_t)w[3]<<32|w[2];
        if((int64_t)length[i]<0)return -EINVAL;
        if(length[i]>MAX_RW_COUNT-total)length[i]=MAX_RW_COUNT-total;
        total+=length[i];
    }
    if(!total)return 0;
    ssize_t written=0;
    for(unsigned long i=0;i<vlen;++i){
        if(!length[i])continue;
        ssize_t r=regular_transfer(p,(uintptr_t)base[i],(size_t)length[i],pos,1);
        if(r<0){if(!written)written=r;break;}
        written+=r;
        if((uint64_t)r<length[i])break;
    }
    return written;
}
/* Below do_futex: a private FUTEX_WAKE or FUTEX_WAIT with no waiter. get_futex_key rejects an unaligned word (EINVAL)
 * and one access_ok refuses (EFAULT); a shared word's key pins its page, outside this model. A wake finds no waiter
 * (0); a wait reads the word and returns EAGAIN when it changed, and would sleep (outside the slice) otherwise. */
static int futex_word_check(u32 __user *uaddr,unsigned int flags)
{
    if((uintptr_t)uaddr%sizeof(u32))return -EINVAL;
    if((uintptr_t)uaddr>(UINT64_C(1)<<48)-sizeof(u32))return -EFAULT;
    if(linux_assert(flags&FLAGS_SHARED))return -EFAULT;
    return 0;
}
int futex_wake(u32 __user *uaddr,unsigned int flags,int nr_wake,u32 bitset)
{
    (void)nr_wake;
    if(!bitset)return -EINVAL;
    return futex_word_check(uaddr,flags);
}
int futex_wait(u32 __user *uaddr,unsigned int flags,u32 val,ktime_t *abs_time,u32 bitset)
{
    if(!bitset)return -EINVAL;
    if(linux_assert(abs_time!=0))return -EINVAL;
    int ret=futex_word_check(uaddr,flags);if(ret)return ret;
    uint32_t uval;if(linux_get_user_u32(&uval,uaddr))return -EFAULT;
    if(uval!=val)return -EAGAIN;
    linux_assert(1);return -EINVAL;
}
int get_timespec64(struct timespec64 *ts,const struct __kernel_timespec __user *u){(void)ts;(void)u;linux_assert(1);return -EFAULT;}
int futex_init_timeout(u32 cmd,u32 op,struct timespec64 *ts,ktime_t *t){(void)cmd;(void)op;(void)ts;(void)t;linux_assert(1);return -EINVAL;}
int futex_requeue(u32 __user *u1,unsigned int f1,u32 __user *u2,unsigned int f2,int nr_wake,int nr_requeue,u32 *cmpval,int pi){(void)u1;(void)f1;(void)u2;(void)f2;(void)nr_wake;(void)nr_requeue;(void)cmpval;(void)pi;linux_assert(1);return -ENOSYS;}
int futex_wake_op(u32 __user *u1,unsigned int flags,u32 __user *u2,int nr_wake,int nr_wake2,int op){(void)u1;(void)flags;(void)u2;(void)nr_wake;(void)nr_wake2;(void)op;linux_assert(1);return -ENOSYS;}
int futex_lock_pi(u32 __user *u,unsigned int flags,ktime_t *time,int trylock){(void)u;(void)flags;(void)time;(void)trylock;linux_assert(1);return -ENOSYS;}
int futex_unlock_pi(u32 __user *u,unsigned int flags){(void)u;(void)flags;linux_assert(1);return -ENOSYS;}
int futex_wait_requeue_pi(u32 __user *u,unsigned int flags,u32 val,ktime_t *time,u32 bitset,u32 __user *u2){(void)u;(void)flags;(void)val;(void)time;(void)bitset;(void)u2;linux_assert(1);return -ENOSYS;}
