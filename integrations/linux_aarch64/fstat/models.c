#include "model.h"
#include "capture.h"
/* Reviewed state projection; not Linux's physical task_struct layout. */
struct user_namespace user_ns={1};
struct fs_struct fs={LINUX_INITIAL_UMASK};
struct cred creds={LINUX_INITIAL_UID,LINUX_INITIAL_EUID,LINUX_INITIAL_SUID,LINUX_INITIAL_GID,LINUX_INITIAL_EGID,LINUX_INITIAL_SGID,&user_ns};
struct task_struct parent={.pid=LINUX_INITIAL_PPID,.tgid=LINUX_INITIAL_PPID};
struct super_block superblock={0};
#define INITIAL_INODE(block,id) {LINUX_INITIAL_STAT_MODE_##id,0,block,LINUX_INITIAL_STAT_DEV_##id,LINUX_INITIAL_STAT_RDEV_##id,LINUX_INITIAL_STAT_NLINK_##id,LINUX_INITIAL_STAT_UID_##id,LINUX_INITIAL_STAT_GID_##id,LINUX_INITIAL_STAT_BLKSIZE_##id,LINUX_INITIAL_STAT_INO_##id,LINUX_INITIAL_STAT_BLOCKS_##id}
struct inode inode_pool[2]={INITIAL_INODE(&superblock,0),INITIAL_INODE(&superblock,1)};
struct dentry dentry_pool[2]={{&inode_pool[0]},{&inode_pool[1]}};
#define INITIAL_FILE(count,mode,flags,id,path) {count,mode,flags,id,0,0,0,{path}}
struct file file_pool[2]={INITIAL_FILE(3,FMODE_STREAM,LINUX_INITIAL_FILE_FLAGS_0,1,&dentry_pool[0]),INITIAL_FILE(1,31,LINUX_INITIAL_FILE_FLAGS_1,2,&dentry_pool[1])};
struct file_data file_data={16,{97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112}};
#define INITIAL_FILES(table,console,seed) {table,{64,{console,console,console,seed},{8},{15},{0}},4,0,0}
struct files_struct files=INITIAL_FILES(&files.fdtab,&file_pool[0],&file_pool[1]);
struct task_struct task={LINUX_INITIAL_PID,LINUX_INITIAL_TGID,&parent,&fs,&creds,&files};
struct task_struct *current=&task;
struct osrec_user_memory active_memory;
int rcu_depth;
int task_tgid_vnr(const struct task_struct *p){return p->tgid;}
int task_pid_vnr(const struct task_struct *p){return p->pid;}
const struct cred *current_cred(void){return current->cred;}
struct user_namespace *current_user_ns(void){return current_cred()->user_ns;}
uid_t current_uid(void){return current_cred()->uid;}
uid_t current_euid(void){return current_cred()->euid;}
gid_t current_gid(void){return current_cred()->gid;}
gid_t current_egid(void){return current_cred()->egid;}
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
unsigned long rlimit(unsigned int resource){linux_assert(resource!=RLIMIT_NOFILE);return 8;}
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
    *pos+=(loff_t)copied;
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

/* Reviewed five-command syscall boundary, not original sys_fcntl/do_fcntl.
 * Retained Linux helpers own bitmap mutation and minimum-fd duplication.
 * Only non-O_PATH files and successful LSM admission are in this profile. */
bool close_on_exec(unsigned int fd,struct files_struct *p)
{
    linux_assert(rcu_depth!=1 || fd>=p->fdt->max_fds);
    return !!(p->fdt->close_on_exec[fd/64]&(UINT64_C(1)<<(fd%64)));
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
void task_lock(struct task_struct *p){(void)p;linux_assert(1);}
void task_unlock(struct task_struct *p){(void)p;linux_assert(1);}
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
    const struct osrec_user_region *r=osrec_user_memory_object(&active_memory,2,128,3);
    if(!r)return count;
    size_t copied=0;
    while(copied<count){
        uintptr_t address=(uintptr_t)out+copied;
        if(address<r->user_address || address-r->user_address>=128)break;
        unsigned char *p=osrec_user_memory_resolve(&active_memory,address,1,OSREC_MEMORY_WRITE);
        if(!p)break;*p=((const unsigned char *)in)[copied];++copied;
    }
    return count-copied;
}
