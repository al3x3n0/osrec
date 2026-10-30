#include "model.h"
#include "capture.h"
/* Reviewed state projection; not Linux's physical task_struct layout. */
/* init_user_ns's static maps (kernel/user_namespace.c): every identifier maps to itself. */
#define IDENTITY_MAP {1,{{0,0,4294967295U}},0,0}
struct user_namespace user_ns={1,IDENTITY_MAP,IDENTITY_MAP};
struct fs_struct fs={LINUX_INITIAL_UMASK};
struct cred creds={{LINUX_INITIAL_UID},{LINUX_INITIAL_EUID},{LINUX_INITIAL_SUID},{LINUX_INITIAL_GID},{LINUX_INITIAL_EGID},{LINUX_INITIAL_SGID},&user_ns};
struct task_struct parent={.pid=LINUX_INITIAL_PPID,.tgid=LINUX_INITIAL_PPID};
/* Operation tables: the console (tty) and the regular shmem file (shmem_aops, shmem_inode_operations, shmem_ops). */
struct address_space_operations aops_pool[2]={{1,0,0,0},{2,1,1,1}};
struct inode_operations iop_pool[2]={{1,0,0},{2,0,1}};
struct super_operations super_ops={2,0};
/* tmpfs on the internal shm mount: SB_NOSEC | SB_I_VERSION (as observed live); 1 ns granularity, full time64 range. */
/* tmpfs inodes use noop_backing_dev_info, which has no BDI_CAP_WRITEBACK. */
struct backing_dev_info noop_bdi;
struct super_block superblock={0,0,SB_NOSEC|SB_I_VERSION,1,INT64_MIN,INT64_MAX,&user_ns,&super_ops,MAX_LFS_FILESIZE,&noop_bdi};
/* Per-CPU dirty-throttling counters (balance_dirty_pages_ratelimited_flags past its bdi check). */
int bdp_ratelimits,dirty_throttle_leaks,ratelimit_pages;
struct mnt_idmap nop_mnt_idmap;
struct vfsmount mount={0,&nop_mnt_idmap,&superblock,0};
/* The coarse real-time clock the slice reads; a live binding supplies the observed value. */
struct tk_core_model tk_core={{0},{{0,0},1}};
struct bdi_writeback inode_wb;
extern struct inode inode_pool[2];
struct folio folio_pool[1]={{(1UL<<PG_referenced)|(1UL<<PG_uptodate)|(1UL<<PG_dirty)|(1UL<<PG_lru)|(1UL<<PG_swapbacked),&inode_pool[1].i_data,0,{1},{0},{0}}};
struct page zero_page;
/* The written memfd inode carries S_NOSEC (inode_has_no_xattr on its first write). */
#define INITIAL_INODE(mode,flags,size,block,op,self,data,head,pages,aops) {mode,0,block,flags,{0},{0},size,{0,0},{0,0},{0,0},{0},0,0,{0,0},0,0,op,data,{self,{0,0,head},0,{0},pages,aops},0,{0,{0,0},VM_NORESERVE,pages,0,0,0},0}
struct inode inode_pool[2]={INITIAL_INODE(0020000,0,0,&superblock,&iop_pool[0],&inode_pool[0],&inode_pool[0].i_data,0,0,&aops_pool[0]),
    INITIAL_INODE(0100000,S_NOSEC,16,&superblock,&iop_pool[1],&inode_pool[1],&inode_pool[1].i_data,&folio_pool[0],1,&aops_pool[1])};
struct dentry dentry_pool[2]={{&inode_pool[0],0,&superblock},{&inode_pool[1],0,&superblock}};
/* Operation tables of the console (tty_fops) and the regular shmem file (shmem_file_operations). */
struct file_operations fop_pool[2]={{1,0,1,0,1,0,0,0},{2,0,1,0,1,0,0,0}};
#define INITIAL_FILE(count,mode,flags,id,path,mnt,op,data) {count,mode,flags,id,0,0,0,{path,mnt},{0},0,0,op,data}
struct file file_pool[2]={INITIAL_FILE(3,CONSOLE_MODE,LINUX_INITIAL_FILE_FLAGS_0,1,&dentry_pool[0],&mount,&fop_pool[0],&inode_pool[0].i_data),INITIAL_FILE(1,REGULAR_MODE,LINUX_INITIAL_FILE_FLAGS_1,2,&dentry_pool[1],&mount,&fop_pool[1],&inode_pool[1].i_data)};
struct file_data file_data={{97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112}};
#define INITIAL_FILES(table,console,seed) {table,{64,{console,console,console,seed},{8},{15},{0}},4,0,0,{1},{0}}
struct files_struct files=INITIAL_FILES(&files.fdtab,&file_pool[0],&file_pool[1]);
struct task_struct task={{0},LINUX_INITIAL_PID,LINUX_INITIAL_TGID,&parent,&fs,&creds,&files,{0,0,0,0},0,0,0,{0},0};
struct task_struct *current=&task;
struct osrec_user_memory active_memory;
int rcu_depth;
int task_tgid_vnr(const struct task_struct *p){return p->tgid;}
int task_pid_vnr(const struct task_struct *p){return p->pid;}
const struct cred *current_cred(void){return current->cred;}
struct user_namespace *current_user_ns(void){return current_cred()->user_ns;}
kuid_t current_uid(void){return current_cred()->uid;}
kuid_t current_euid(void){return current_cred()->euid;}
kgid_t current_gid(void){return current_cred()->gid;}
kgid_t current_egid(void){return current_cred()->egid;}
int overflowuid=65534,overflowgid=65534;
/* lib/bsearch.c calls its comparison through a pointer; only maps of more than
 * UID_GID_MAP_MAX_BASE_EXTENTS extents search, and the model holds none. */
void *bsearch(const void *key,const void *base,size_t num,size_t size,cmp_func_t cmp){(void)key;(void)base;(void)num;(void)size;(void)cmp;linux_assert(1);return 0;}
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
unsigned long array_index_mask_nospec(unsigned long index,unsigned long size){return index<size ? ~0ul : 0;}
unsigned int array_index_nospec(unsigned int index,unsigned int size){linux_assert(index>=size);return index<size ? index : 0;}
struct fdtable *files_fdtable(struct files_struct *p){return p->fdt;}
/* The descriptor table never grows: RLIMIT_NOFILE (8) is below max_fds (64). */
int expand_fdtable(struct files_struct *p,unsigned int nr){(void)p;(void)nr;linux_assert(1);return -EMFILE;}
void wake_up_all(struct wait_queue_head *q){(void)q;}
/* RLIMIT_NOFILE is 8 and RLIMIT_FSIZE unlimited; the live bindings check both. */
unsigned long rlimit(unsigned int resource){linux_assert(resource!=RLIMIT_NOFILE && resource!=RLIMIT_FSIZE);return resource==RLIMIT_FSIZE ? RLIM_INFINITY : 8;}
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

void rcu_read_lock_sched(void){rcu_read_lock();}
void rcu_read_unlock_sched(void){rcu_read_unlock();}

/* Reviewed regular-file callback boundaries below the original vfs_read/vfs_write. */
int fsnotify_file_area_perm(struct file *p,int mask,const loff_t *pos,size_t count){(void)p;(void)mask;(void)pos;(void)count;return 0;}
loff_t vfs_llseek(struct file *p,loff_t offset,int whence){if(!(p->f_mode&4))return -ESPIPE;linux_assert(p->object_id!=2 || whence==SEEK_DATA || whence==SEEK_HOLE);return generic_file_llseek_size(p,offset,whence,INT64_MAX,file_inode(p)->i_size);}
/* The I/O priority only reaches kiocb.ki_ioprio, which no retained callee reads. */
int get_current_ioprio(void){return 0;}
void mutex_lock(int *lock){linux_assert(*lock!=0);++*lock;}
void mutex_unlock(int *lock){linux_assert(*lock!=1);--*lock;}
/* No fsnotify mark exists on the superblock (s_fsnotify_info is NULL): the parent/child notification paths are unreachable. */
int linux_dentry_is_root(const struct dentry *d){(void)d;linux_assert(1);return 0;}
int __fsnotify_parent(struct dentry *d,__u32 mask,const void *data,int type){(void)d;(void)mask;(void)data;(void)type;linux_assert(1);return 0;}
int fsnotify(__u32 mask,const void *data,int type,struct inode *dir,const void *name,struct inode *inode,uint32_t cookie){(void)mask;(void)data;(void)type;(void)dir;(void)name;(void)inode;(void)cookie;linux_assert(1);return 0;}
/* Reviewed boundaries below the original shmem read path and atime update. */
unsigned int read_seqcount_begin(const seqcount_raw_spinlock_t *s){linux_assert(s->sequence&1);return s->sequence;}
int read_seqcount_retry(const seqcount_raw_spinlock_t *s,unsigned int start){return s->sequence!=start;}
/* shmem_inode_operations has no update_time and shmem_ops no dirty_inode. */
int osrec_i_op_update_time(const struct inode_operations *ops,struct inode *inode,int flags){(void)ops;(void)inode;(void)flags;linux_assert(1);return 0;}
void osrec_s_op_dirty_inode(const struct super_operations *ops,struct inode *inode,int flags){(void)ops;(void)inode;(void)flags;linux_assert(1);}
/* Writeback association is not modeled; an unhashed shmem inode leaves __mark_inode_dirty before any wb list. */
void inode_attach_wb(struct inode *inode,struct folio *folio){(void)inode;(void)folio;}
struct bdi_writeback *locked_inode_to_wb_and_lock_list(struct inode *inode){spin_unlock(&inode->i_lock);spin_lock(&inode_wb.list_lock);return &inode_wb;}
bool inode_io_list_move_locked(struct inode *inode,struct bdi_writeback *wb,struct list_head *head){(void)inode;(void)wb;(void)head;linux_assert(1);return false;}
void wb_wakeup_delayed(struct bdi_writeback *wb){(void)wb;linux_assert(1);}
unsigned long linux_jiffies(void){linux_assert(1);return 0;}
/* The superblock is never frozen; freeze protection balances within the call. */
bool sb_start_write_trylock(struct super_block *sb){sb_start_write(sb);return true;}
/* Mount write access (the per-CPU writer count and MNT_WRITE_HOLD wait are not modeled). */
int mnt_get_write_access(struct vfsmount *m)
{
    ++m->osrec_writers;
    if((m->mnt_flags&MNT_READONLY) || (m->mnt_sb->s_flags&SB_RDONLY)){--m->osrec_writers;return -EROFS;}
    return 0;
}
void mnt_put_write_access(struct vfsmount *m){linux_assert(m->osrec_writers!=1);--m->osrec_writers;}
/* Only the identity mount mapping exists. */
uint32_t map_id_down(const void *map,uint32_t id){(void)map;linux_assert(1);return id;}
/* Folio flag operations (page-flags.h) on the single model folio. */
unsigned long *linux_folio_flags(struct folio *folio){return (unsigned long *)&folio->flags;}
long folio_nr_pages(struct folio *folio){linux_assert((folio->flags>>PG_head)&1);return 1;}
bool test_and_set_bit_lock(long nr,unsigned long *p){bool old=(*p>>nr)&1;*p|=1UL<<nr;return old;}
void __folio_lock(struct folio *folio){(void)folio;linux_assert(1);}
bool folio_xor_flags_has_waiters(struct folio *folio,unsigned long mask){folio->flags^=mask;return (folio->flags>>PG_waiters)&1;}
void folio_wake_bit(struct folio *folio,int bit){(void)folio;(void)bit;linux_assert(1);}
bool folio_test_locked(struct folio *folio){return (folio->flags>>PG_locked)&1;}
bool folio_test_uptodate(struct folio *folio){return (folio->flags>>PG_uptodate)&1;}
bool folio_test_referenced(struct folio *folio){return (folio->flags>>PG_referenced)&1;}
void folio_set_referenced(struct folio *folio){folio->flags|=1UL<<PG_referenced;}
void folio_clear_referenced(struct folio *folio){folio->flags&=~(1UL<<PG_referenced);}
bool folio_test_unevictable(struct folio *folio){return (folio->flags>>PG_unevictable)&1;}
bool folio_test_workingset(struct folio *folio){return (folio->flags>>PG_workingset)&1;}
void folio_set_workingset(struct folio *folio){folio->flags|=1UL<<PG_workingset;}
bool folio_test_active(struct folio *folio){return (folio->flags>>PG_active)&1;}
bool folio_test_lru(struct folio *folio){return (folio->flags>>PG_lru)&1;}
/* No CONFIG_PAGE_IDLE_FLAG on 64-bit without idle-page tracking. */
bool folio_test_idle(struct folio *folio){(void)folio;return false;}
void folio_clear_idle(struct folio *folio){(void)folio;}
/* CONFIG_LRU_GEN_ENABLED: the multi-generation LRU is on, so the classic activation path is unreachable. */
bool lru_gen_enabled(void){return true;}
void folio_activate(struct folio *folio){(void)folio;linux_assert(1);}
void __lru_cache_activate_folio(struct folio *folio){(void)folio;linux_assert(1);}
void workingset_activation(struct folio *folio){(void)folio;linux_assert(1);}
bool try_cmpxchg(unsigned long *p,unsigned long *old,unsigned long value){if(*p==*old){*p=value;return true;}*old=*p;return false;}
bool atomic64_try_cmpxchg(atomic64_t *v,u64 *old,u64 value){if((u64)v->counter==*old){v->counter=(int64_t)value;return true;}*old=(u64)v->counter;return false;}
/* A folio found in the page cache holds that cache's reference, so a lookup never sees a zero count. */
bool folio_try_get(struct folio *folio){linux_assert(folio->_refcount.counter<=0);++folio->_refcount.counter;return true;}
bool folio_put_testzero(struct folio *folio){linux_assert(folio->_refcount.counter<=0);return --folio->_refcount.counter==0;}
/* The last reference frees the folio; a freed folio has no observable state. */
void __folio_put(struct folio *folio){linux_assert(folio->mapping!=0);folio->flags=0;}
void cond_resched(void){}
/* Linear-map addresses of the folio's page (the 64-byte store) and of the zero page. */
static const unsigned char zero_bytes[64];
void *kmap_local_page(struct page *page)
{
    if(page==&folio_pool[0].page)return file_data.bytes;
    linux_assert(page!=&zero_page);
    return (void *)zero_bytes;
}
struct page *linux_zero_page(void){return &zero_page;}
/* arch/arm64/lib/copy_to_user.S and copy_from_user.S: unprivileged loads and
 * stores through the user address space. The kernel reaches only the observed
 * user object (object 1, 32 bytes); the live workload places a guard page after
 * it, so an access outside it faults. A faulting access ends the copy and the
 * result is the number of bytes not copied (the uaccess exception-table fixup);
 * this copy is byte-exact where the assembly may stop up to one chunk short of
 * the fault. Kernel-side page bytes are the 64-byte store (file_data) or the
 * zero page's. */
static unsigned char *user_byte(uintptr_t address,uint32_t access)
{
    const struct osrec_user_region *region=osrec_user_memory_object(&active_memory,1,32,3);
    linux_assert(!region);
    if(!region || address<region->user_address || address-region->user_address>=32)return 0;
    return osrec_user_memory_resolve(&active_memory,address,1,access);
}
static void page_span(const unsigned char *p,unsigned long n)
{
    if(p>=file_data.bytes && p<file_data.bytes+64)linux_assert(n>(size_t)(file_data.bytes+64-p));
    else if(p>=zero_bytes && p<zero_bytes+64)linux_assert(n>(size_t)(zero_bytes+64-p));
}
unsigned long __arch_copy_to_user(void __user *to,const void *from,unsigned long n)
{
    const unsigned char *source=from;unsigned long copied=0;page_span(source,n);
    for(;copied<n;++copied){unsigned char *at=user_byte((uintptr_t)to+copied,OSREC_MEMORY_WRITE);if(!at)break;*at=source[copied];}
    return n-copied;
}
unsigned long __arch_copy_from_user(void *to,const void __user *from,unsigned long n)
{
    unsigned char *target=to;unsigned long copied=0;page_span(target,n);
    for(;copied<n;++copied){const unsigned char *at=user_byte((uintptr_t)from+copied,OSREC_MEMORY_READ);if(!at)break;target[copied]=*at;}
    return n-copied;
}
/* System calls here build only user-backed (ITER_UBUF) iterators. */
size_t iterate_bvec(struct iov_iter *i,size_t len,void *priv,void *priv2,iov_step_f step){(void)i;(void)priv;(void)priv2;(void)step;linux_assert(1);return len;}
size_t iterate_kvec(struct iov_iter *i,size_t len,void *priv,void *priv2,iov_step_f step){(void)i;(void)priv;(void)priv2;(void)step;linux_assert(1);return len;}
size_t iterate_xarray(struct iov_iter *i,size_t len,void *priv,void *priv2,iov_step_f step){(void)i;(void)priv;(void)priv2;(void)step;linux_assert(1);return len;}
size_t iterate_discard(struct iov_iter *i,size_t len,void *priv,void *priv2,iov_step_f step){(void)i;(void)priv;(void)priv2;(void)step;linux_assert(1);return len;}
size_t iov_iter_zero(size_t bytes,struct iov_iter *i){(void)bytes;(void)i;linux_assert(1);return 0;}
struct page *compound_head(struct page *page){linux_assert(1);return page;}
size_t page_size(struct page *page){(void)page;linux_assert(1);return PAGE_SIZE;}
/* shmem paths below a page-cache hit or hole: swap, userfaultfd, huge pages and allocation. */
vm_fault_t handle_userfault(struct vm_fault *f,unsigned long reason){(void)f;(void)reason;linux_assert(1);return 0;}
int shmem_swapin_folio(struct inode *inode,pgoff_t index,struct folio **f,enum sgp_type sgp,gfp_t gfp,struct mm_struct *mm,vm_fault_t *type){(void)inode;(void)index;(void)f;(void)sgp;(void)gfp;(void)mm;(void)type;linux_assert(1);return -EINVAL;}
/* The internal shm mount has huge=never. */
bool shmem_is_huge(struct inode *inode,pgoff_t index,bool shmem_huge_force,struct mm_struct *mm,unsigned long flags){(void)inode;(void)index;(void)shmem_huge_force;(void)mm;(void)flags;return false;}
gfp_t vma_thp_gfp_mask(struct vm_area_struct *vma){(void)vma;linux_assert(1);return 0;}
gfp_t limit_gfp_mask(gfp_t huge,gfp_t limit){(void)huge;(void)limit;linux_assert(1);return 0;}
/* A new order-0 folio for the hole at index 0: locked, swap-backed, in the page cache with the
 * caller's reference (2). Block accounting, memcg charge and the per-CPU LRU batch are not modeled. */
struct folio *shmem_alloc_and_add_folio(gfp_t gfp,struct inode *inode,pgoff_t index,struct mm_struct *mm,bool huge)
{
    (void)gfp;(void)mm;
    struct address_space *mapping=inode->i_mapping;
    linux_assert(huge || index || inode!=&inode_pool[1] || mapping->i_pages.xa_head || mapping->nrpages);
    folio_pool[0]=(struct folio){(1UL<<PG_locked)|(1UL<<PG_swapbacked),mapping,index,{2},{0},{0}};
    mapping->i_pages.xa_head=&folio_pool[0];mapping->nrpages=1;++inode->osrec_shmem.alloced;
    return &folio_pool[0];
}
bool linux_is_err(const void *p){return (uintptr_t)p>=(uintptr_t)-MAX_ERRNO;}
long linux_ptr_err(const void *p){return (long)(intptr_t)p;}
void count_vm_event(int item){(void)item;linux_assert(1);}
bool folio_test_pmd_mappable(struct folio *folio){(void)folio;return false;}
struct shmem_sb_info *SHMEM_SB(struct super_block *sb){(void)sb;linux_assert(1);return 0;}
struct shmem_inode_info *SHMEM_I(struct inode *inode){return &inode->osrec_shmem;}
bool list_empty_careful(const struct list_head *head){(void)head;linux_assert(1);return true;}
void list_add_tail(struct list_head *entry,struct list_head *head){(void)entry;(void)head;linux_assert(1);}
void clear_highpage(struct page *page){(void)page;linux_assert(1);}
void folio_mark_uptodate(struct folio *folio){folio->flags|=1UL<<PG_uptodate;}
/* Page-cache deletion (__filemap_remove_folio, filemap_free_folio): the store, the mapping link and
 * the page-cache reference go; statistics and memcg uncharge are not modeled. */
void filemap_remove_folio(struct folio *folio)
{
    struct address_space *mapping=folio->mapping;
    linux_assert(folio!=&folio_pool[0] || !mapping || mapping->i_pages.xa_head!=folio || folio->_refcount.counter<2);
    mapping->i_pages.xa_head=0;mapping->nrpages=0;folio->mapping=0;--folio->_refcount.counter;
    /* The store models the cached page: with no page cached the file reads as zeros. */
    for(unsigned i=0;i<64;++i)file_data.bytes[i]=0;
}
/* Operation-table dispatch: only the regular shmem file's read_iter/write_iter is retained. */
/* Neither tty_fops nor shmem_file_operations has a flush operation. */
int osrec_f_op_flush(const struct file_operations *ops,struct file *p,fl_owner_t id){(void)ops;(void)p;(void)id;linux_assert(1);return 0;}
/* POSIX locks and dnotify marks: never present in the model (see model.h). */
void locks_init_lock(struct file_lock *fl){(void)fl;linux_assert(1);}
int vfs_lock_file(struct file *p,unsigned int cmd,struct file_lock *fl,struct file_lock *conf){(void)p;(void)cmd;(void)fl;(void)conf;linux_assert(1);return 0;}
void osrec_fl_release_private(const struct file_lock_operations *ops,struct file_lock *fl){(void)ops;(void)fl;linux_assert(1);}
struct fsnotify_mark *fsnotify_find_inode_mark(struct inode *inode,struct fsnotify_group *group){(void)inode;(void)group;linux_assert(1);return 0;}
void fsnotify_group_lock(struct fsnotify_group *group){(void)group;linux_assert(1);}
void fsnotify_group_unlock(struct fsnotify_group *group){(void)group;linux_assert(1);}
void kmem_cache_free(struct kmem_cache *cache,void *object){(void)cache;(void)object;linux_assert(1);}
void dnotify_recalc_inode_mask(struct fsnotify_mark *mark){(void)mark;linux_assert(1);}
void fsnotify_detach_mark(struct fsnotify_mark *mark){(void)mark;linux_assert(1);}
void fsnotify_free_mark(struct fsnotify_mark *mark){(void)mark;linux_assert(1);}
void fsnotify_put_mark(struct fsnotify_mark *mark){(void)mark;linux_assert(1);}
ssize_t osrec_f_op_read(const struct file_operations *ops,struct file *p,char *buf,size_t count,loff_t *pos){(void)ops;(void)p;(void)buf;(void)count;(void)pos;linux_assert(1);return -EINVAL;}
ssize_t osrec_f_op_write(const struct file_operations *ops,struct file *p,const char *buf,size_t count,loff_t *pos){(void)ops;(void)p;(void)buf;(void)count;(void)pos;linux_assert(1);return -EINVAL;}
ssize_t osrec_f_op_read_iter(const struct file_operations *ops,struct kiocb *k,struct iov_iter *i){if(ops->osrec_class==2)return shmem_file_read_iter(k,i);linux_assert(1);return -EINVAL;}
ssize_t osrec_f_op_write_iter(const struct file_operations *ops,struct kiocb *k,struct iov_iter *i){if(ops->osrec_class==2)return shmem_file_write_iter(k,i);linux_assert(1);return -EINVAL;}

/* Reviewed inode mutation/LSM/superblock boundaries; preserve shared f_pos. */
struct inode *file_inode(const struct file *p){return p->f_path.dentry->d_inode;}
void sb_start_write(struct super_block *p){linux_assert(p->write_depth!=0);++p->write_depth;}
void sb_end_write(struct super_block *p){linux_assert(p->write_depth!=1);--p->write_depth;}

/* Reviewed boundaries of the original fcntl entry and do_fcntl.
 * Retained Linux helpers own bitmap mutation and minimum-fd duplication.
 * fdget, fdget_raw and fdput are original: a table with one owner is
 * borrowed from, a shared one takes a reference fdput releases.
 * Every LSM admits the call. Commands other than F_DUPFD, F_DUPFD_CLOEXEC,
 * F_GETFD, F_SETFD, F_GETFL, F_GETSIG, F_SETSIG and unknown ones reach a
 * fault boundary; O_PATH files take the original check_fcntl_cmd filter. */
bool close_on_exec(unsigned int fd,struct files_struct *p)
{
    linux_assert(rcu_depth!=1 || fd>=p->fdt->max_fds);
    return !!(p->fdt->close_on_exec[fd/64]&(UINT64_C(1)<<(fd%64)));
}
int valid_signal(unsigned long sig){return sig<=_NSIG ? 1 : 0;}
unsigned long copy_from_user(void *to,const void *from,unsigned long n){(void)to;(void)from;linux_assert(1);return n;}
unsigned long copy_to_user(void *to,const void *from,unsigned long n){(void)to;(void)from;linux_assert(1);return n;}
long f_dupfd_query(int fd,struct file *p){(void)fd;(void)p;linux_assert(1);return -EINVAL;}
int setfl(int fd,struct file *p,unsigned int arg){(void)fd;(void)p;(void)arg;linux_assert(1);return -EINVAL;}
int fcntl_getlk(struct file *p,unsigned int cmd,struct flock *l){(void)p;(void)cmd;(void)l;linux_assert(1);return -EINVAL;}
int fcntl_setlk(unsigned int fd,struct file *p,unsigned int cmd,struct flock *l){(void)fd;(void)p;(void)cmd;(void)l;linux_assert(1);return -EINVAL;}
pid_t f_getown(struct file *p){(void)p;linux_assert(1);return 0;}
int f_setown(struct file *p,int who,int force){(void)p;(void)who;(void)force;linux_assert(1);return -EINVAL;}
int f_getown_ex(struct file *p,unsigned long arg){(void)p;(void)arg;linux_assert(1);return -EINVAL;}
int f_setown_ex(struct file *p,unsigned long arg){(void)p;(void)arg;linux_assert(1);return -EINVAL;}
int f_getowner_uids(struct file *p,unsigned long arg){(void)p;(void)arg;linux_assert(1);return -EINVAL;}
int fcntl_getlease(struct file *p){(void)p;linux_assert(1);return -EINVAL;}
int fcntl_setlease(unsigned int fd,struct file *p,int arg){(void)fd;(void)p;(void)arg;linux_assert(1);return -EINVAL;}
int fcntl_dirnotify(int fd,struct file *p,unsigned int arg){(void)fd;(void)p;(void)arg;linux_assert(1);return -EINVAL;}
long pipe_fcntl(struct file *p,unsigned int cmd,unsigned int arg){(void)p;(void)cmd;(void)arg;linux_assert(1);return -EINVAL;}
long memfd_fcntl(struct file *p,unsigned int cmd,unsigned int arg){(void)p;(void)cmd;(void)arg;linux_assert(1);return -EINVAL;}
long fcntl_get_rw_hint(struct file *p,unsigned int cmd,unsigned long arg){(void)p;(void)cmd;(void)arg;linux_assert(1);return -EINVAL;}
long fcntl_set_rw_hint(struct file *p,unsigned int cmd,unsigned long arg){(void)p;(void)cmd;(void)arg;linux_assert(1);return -EINVAL;}

/* Reviewed boundaries below the original shmem write path. */
int linux_get_user_byte(const void *p,char *value)
{
    const struct osrec_user_region *region=osrec_user_memory_object(&active_memory,1,32,3);
    linux_assert(!region);if(!region)return -EFAULT;
    uintptr_t address=(uintptr_t)p;
    if(address<region->user_address || address-region->user_address>=32)return -EFAULT;
    const unsigned char *at=osrec_user_memory_resolve(&active_memory,address,1,OSREC_MEMORY_READ);
    if(!at)return -EFAULT;
    *value=(char)*at;return 0;
}
/* No signal is pending for the task. */
int fatal_signal_pending(struct task_struct *p){(void)p;return 0;}
void send_sig(int sig,struct task_struct *p,int priv){(void)sig;(void)p;(void)priv;linux_assert(1);}
void down_write(int *sem){linux_assert(*sem!=0);++*sem;}
void up_write(int *sem){linux_assert(*sem!=1);--*sem;}
struct folio *linux_page_folio(struct page *page){linux_assert(page!=&folio_pool[0].page);return &folio_pool[0];}
size_t folio_size(struct folio *folio){(void)folio;return PAGE_SIZE;}
size_t offset_in_folio(struct folio *folio,loff_t pos){(void)folio;return (size_t)pos&(PAGE_SIZE-1);}
/* Zeroing outside the written range; the store's bytes past 64 are zero by the binding's invariant. */
void folio_zero_segments(struct folio *folio,size_t start1,size_t end1,size_t start2,size_t end2)
{
    linux_assert(folio!=&folio_pool[0] || start1>end1 || start2>end2 || end1>64);
    for(size_t i=start1;i<end1 && i<64;++i)file_data.bytes[i]=0;
    for(size_t i=start2;i<end2 && i<64;++i)file_data.bytes[i]=0;
}
bool folio_test_dirty(struct folio *folio){return (folio->flags>>PG_dirty)&1;}
bool folio_test_set_dirty(struct folio *folio){bool old=(folio->flags>>PG_dirty)&1;folio->flags|=1UL<<PG_dirty;return old;}
bool folio_test_reclaim(struct folio *folio){return (folio->flags>>PG_reclaim)&1;}
void folio_clear_reclaim(struct folio *folio){folio->flags&=~(1UL<<PG_reclaim);}
/* A shmem page-cache folio is neither a slab page nor in the swap cache. */
bool folio_test_slab(struct folio *folio){(void)folio;return false;}
bool folio_test_swapcache(struct folio *folio){(void)folio;return false;}
struct address_space *swap_address_space(swp_entry_t entry){(void)entry;linux_assert(1);return 0;}
bool test_bit(long nr,const unsigned long *p){return (*p>>nr)&1;}
void clear_bit(long nr,unsigned long *p){*p&=~(1UL<<nr);}
/* S_NOSEC inodes skip privilege removal; the other paths are not modeled. */
int __remove_privs(struct mnt_idmap *idmap,struct dentry *d,int kill){(void)idmap;(void)d;(void)kill;linux_assert(1);return 0;}
void inode_has_no_xattr(struct inode *inode){(void)inode;linux_assert(1);}
int osrec_a_ops_write_begin(const struct address_space_operations *ops,struct file *p,struct address_space *m,loff_t pos,unsigned len,struct page **page,void **data)
{if(ops->osrec_class==2)return shmem_write_begin(p,m,pos,len,page,data);linux_assert(1);return -EINVAL;}
int osrec_a_ops_write_end(const struct address_space_operations *ops,struct file *p,struct address_space *m,loff_t pos,unsigned len,unsigned copied,struct page *page,void *data)
{if(ops->osrec_class==2)return shmem_write_end(p,m,pos,len,copied,page,data);linux_assert(1);return -EINVAL;}
/* shmem_aops.dirty_folio is noop_dirty_folio. */
bool osrec_a_ops_dirty_folio(const struct address_space_operations *ops,struct address_space *m,struct folio *folio)
{if(ops->osrec_class==2)return noop_dirty_folio(m,folio);linux_assert(1);return false;}
bool inode_cgwb_enabled(struct inode *inode){(void)inode;linux_assert(1);return false;}
struct bdi_writeback *wb_get_create_current(struct backing_dev_info *bdi,unsigned int gfp){(void)gfp;linux_assert(1);return &bdi->wb;}
int balance_dirty_pages(struct bdi_writeback *wb,unsigned long dirtied,unsigned int flags){(void)wb;(void)dirtied;(void)flags;linux_assert(1);return 0;}
void wb_put(struct bdi_writeback *wb){(void)wb;}

/* Reviewed boundaries below the original truncation path. */
bool is_sxid(umode_t mode){return mode & S_ISUID || ((mode & S_ISGID) && (mode & 0010));}
int rwsem_is_locked(int *sem){return *sem!=0;}
/* An S_NOSEC regular file needs no privilege removal and nothing changes owners or modes here. */
kuid_t from_vfsuid(struct mnt_idmap *idmap,struct user_namespace *ns,vfsuid_t uid){(void)idmap;(void)ns;linux_assert(1);return (kuid_t){uid.val};}
kgid_t from_vfsgid(struct mnt_idmap *idmap,struct user_namespace *ns,vfsgid_t gid){(void)idmap;(void)ns;linux_assert(1);return (kgid_t){gid.val};}
bool vfsuid_has_fsmapping(struct mnt_idmap *idmap,struct user_namespace *ns,vfsuid_t uid){(void)idmap;(void)ns;(void)uid;linux_assert(1);return true;}
bool vfsgid_has_fsmapping(struct mnt_idmap *idmap,struct user_namespace *ns,vfsgid_t gid){(void)idmap;(void)ns;(void)gid;linux_assert(1);return true;}
bool inode_owner_or_capable(struct mnt_idmap *idmap,const struct inode *inode){(void)idmap;(void)inode;linux_assert(1);return true;}
int inode_permission(struct mnt_idmap *idmap,struct inode *inode,int mask){(void)idmap;(void)inode;(void)mask;linux_assert(1);return 0;}
bool chown_ok(struct mnt_idmap *idmap,const struct inode *inode,vfsuid_t uid){(void)idmap;(void)inode;(void)uid;linux_assert(1);return true;}
bool chgrp_ok(struct mnt_idmap *idmap,const struct inode *inode,vfsgid_t gid){(void)idmap;(void)inode;(void)gid;linux_assert(1);return true;}
bool in_group_or_capable(struct mnt_idmap *idmap,const struct inode *inode,vfsgid_t gid){(void)idmap;(void)inode;(void)gid;linux_assert(1);return true;}
int setattr_should_drop_suidgid(struct mnt_idmap *idmap,struct inode *inode){(void)idmap;(void)inode;linux_assert(1);return 0;}
int security_inode_need_killpriv(struct dentry *d){(void)d;linux_assert(1);return 0;}
int security_inode_killpriv(struct mnt_idmap *idmap,struct dentry *d){(void)idmap;(void)d;linux_assert(1);return 0;}
/* Every LSM admits the size change. */
int simple_setattr(struct mnt_idmap *idmap,struct dentry *d,struct iattr *attr){(void)idmap;(void)d;(void)attr;linux_assert(1);return -EINVAL;}
int __break_lease(struct inode *inode,unsigned int mode,unsigned int type){(void)inode;(void)mode;(void)type;linux_assert(1);return 0;}
void ihold(struct inode *inode){(void)inode;linux_assert(1);}
/* shmem_inode_operations.setattr is shmem_setattr; the console's is not retained. */
int osrec_i_op_setattr(const struct inode_operations *ops,struct mnt_idmap *idmap,struct dentry *d,struct iattr *attr)
{if(ops->osrec_class==2)return shmem_setattr(idmap,d,attr);linux_assert(1);return -EINVAL;}
/* memfd inodes are VM_NORESERVE: shmem_reacct_size never accounts. */
/* The LSM hook lists (see model.h): BPF's entry on each. */
static const struct lsm_id bpf_lsmid={"bpf",LSM_ID_BPF};
#define BPF_HOOK(HOOK) {{0,0},(struct hlist_head *)&security_hook_heads.HOOK,&bpf_lsmid}
static const struct security_hook_list bpf_lsm_hooks[5]={BPF_HOOK(file_permission),BPF_HOOK(file_fcntl),BPF_HOOK(file_truncate),BPF_HOOK(inode_setattr),BPF_HOOK(inode_post_setattr)};
#define HEAD(i) {(struct hlist_node *)&bpf_lsm_hooks[i].list}
const struct security_hook_heads security_hook_heads={HEAD(0),HEAD(1),HEAD(2),HEAD(3),HEAD(4)};
int security_vm_enough_memory_mm(struct mm_struct *mm,long pages){(void)mm;(void)pages;linux_assert(1);return 0;}
void vm_unacct_memory(long pages){(void)pages;linux_assert(1);}
/* The mapping is not mmapped (i_mmap_writable is 0 and no VMA maps it). */
void unmap_mapping_range(struct address_space *mapping,loff_t start,loff_t length,int even_cows){(void)mapping;(void)start;(void)length;(void)even_cows;}
/* No quota is active on the internal shm mount. */
int dquot_initialize(struct inode *inode){(void)inode;return 0;}
int dquot_transfer(struct mnt_idmap *idmap,struct inode *inode,struct iattr *attr){(void)idmap;(void)inode;(void)attr;linux_assert(1);return 0;}
int posix_acl_chmod(struct mnt_idmap *idmap,struct dentry *d,umode_t mode){(void)idmap;(void)d;(void)mode;linux_assert(1);return 0;}
/* Block accounting of the shm superblock is not modeled. */
void shmem_inode_unacct_blocks(struct inode *inode,long pages){(void)inode;(void)pages;}
int shmem_free_swap(struct address_space *mapping,pgoff_t index,void *radswap){(void)mapping;(void)index;(void)radswap;linux_assert(1);return 0;}
struct folio *xas_find_marked(struct xa_state *xas,unsigned long max,xa_mark_t mark){(void)xas;(void)max;(void)mark;linux_assert(1);return 0;}
pgoff_t swapcache_index(struct folio *folio){linux_assert(1);return folio->index;}
bool folio_test_writeback(struct folio *folio){return (folio->flags>>PG_writeback)&1;}
bool folio_test_large(struct folio *folio){return (folio->flags>>PG_head)&1;}
void folio_wait_bit(struct folio *folio,int bit){(void)folio;(void)bit;linux_assert(1);}
loff_t folio_pos(struct folio *folio){return (loff_t)folio->index<<PAGE_SHIFT;}
bool folio_mapped(struct folio *folio){(void)folio;return false;}
void unmap_mapping_folio(struct folio *folio){(void)folio;linux_assert(1);}
/* No private data and no AS_RELEASE_ALWAYS on a shmem mapping. */
bool folio_needs_release(struct folio *folio){return (folio->flags>>PG_private)&1;}
void folio_invalidate(struct folio *folio,size_t offset,size_t length){(void)folio;(void)offset;(void)length;linux_assert(1);}
/* shmem's bdi cannot write back, so __folio_cancel_dirty only clears the dirty flag. */
void folio_cancel_dirty(struct folio *folio){folio->flags&=~(1UL<<PG_dirty);}
void folio_clear_mappedtodisk(struct folio *folio){folio->flags&=~(1UL<<PG_mappedtodisk);}
int split_folio(struct folio *folio){(void)folio;linux_assert(1);return -EINVAL;}
void __folio_batch_release(struct folio_batch *fbatch)
{
    for(unsigned i=0;i<fbatch->nr && i<PAGEVEC_SIZE;++i)if(folio_put_testzero(fbatch->folios[i]))__folio_put(fbatch->folios[i]);
    fbatch->nr=0;
}
/* zero_user_segments over the page's first 64 bytes: the store's tail past i_size, and so past 64, is zero. */
void zero_user_segments(struct page *page,unsigned start1,unsigned end1,unsigned start2,unsigned end2)
{
    unsigned char *kaddr=kmap_local_page(page);
    linux_assert(end1>PAGE_SIZE || end2>PAGE_SIZE);
    if(end1>start1 && start1<64)memset(kaddr+start1,0,(end1<64 ? end1 : 64)-start1);
    if(end2>start2 && start2<64)memset(kaddr+start2,0,(end2<64 ? end2 : 64)-start2);
    flush_dcache_page(page);
}

/* System call entry (arch/arm64/kernel/entry-common.c, syscall.c). */
void local_daif_restore(unsigned long flags){(void)flags;}
void local_daif_mask(void){}
void local_irq_disable(void){}
bool system_supports_sme(void){return false;}
bool system_supports_sve(void){return false;}
void mte_disable_tco_entry(struct task_struct *task){(void)task;}
void mte_check_tfsr_exit(void){}
unsigned long read_thread_flags(void){return READ_ONCE(current->thread_info.flags);}
int test_thread_flag(int flag){return (int)((current->thread_info.flags>>flag)&1);}
bool is_compat_task(void){return false;}
bool is_compat_thread(struct thread_info *thread){(void)thread;return false;}
/* kernel/sys_ni.c */
long sys_ni_syscall(void){return -ENOSYS;}
void do_notify_resume(struct pt_regs *regs,unsigned long thread_flags){(void)regs;(void)thread_flags;linux_assert(1);}
int syscall_trace_enter(struct pt_regs *regs){(void)regs;linux_assert(1);return NO_SYSCALL;}
void syscall_trace_exit(struct pt_regs *regs){(void)regs;linux_assert(1);}
long compat_arm_syscall(struct pt_regs *regs,int scno){(void)regs;(void)scno;linux_assert(1);return -ENOSYS;}
void sme_smstop_sm(void){linux_assert(1);}
unsigned int sve_vq_from_vl(unsigned int vl){(void)vl;linux_assert(1);return 1;}
unsigned int task_get_sve_vl(const struct task_struct *task){(void)task;linux_assert(1);return 0;}
void sve_flush_live(bool flush_ffr,unsigned long vq_minus_1){(void)flush_ffr;(void)vq_minus_1;linux_assert(1);}
void el0_da(struct pt_regs *regs,unsigned long esr){(void)regs;(void)esr;linux_assert(1);}
void el0_ia(struct pt_regs *regs,unsigned long esr){(void)regs;(void)esr;linux_assert(1);}
void el0_fpsimd_acc(struct pt_regs *regs,unsigned long esr){(void)regs;(void)esr;linux_assert(1);}
void el0_sve_acc(struct pt_regs *regs,unsigned long esr){(void)regs;(void)esr;linux_assert(1);}
void el0_sme_acc(struct pt_regs *regs,unsigned long esr){(void)regs;(void)esr;linux_assert(1);}
void el0_fpsimd_exc(struct pt_regs *regs,unsigned long esr){(void)regs;(void)esr;linux_assert(1);}
void el0_sys(struct pt_regs *regs,unsigned long esr){(void)regs;(void)esr;linux_assert(1);}
void el0_sp(struct pt_regs *regs,unsigned long esr){(void)regs;(void)esr;linux_assert(1);}
void el0_pc(struct pt_regs *regs,unsigned long esr){(void)regs;(void)esr;linux_assert(1);}
void el0_undef(struct pt_regs *regs,unsigned long esr){(void)regs;(void)esr;linux_assert(1);}
void el0_bti(struct pt_regs *regs){(void)regs;linux_assert(1);}
void el0_mops(struct pt_regs *regs,unsigned long esr){(void)regs;(void)esr;linux_assert(1);}
void el0_dbg(struct pt_regs *regs,unsigned long esr){(void)regs;(void)esr;linux_assert(1);}
void el0_fpac(struct pt_regs *regs,unsigned long esr){(void)regs;(void)esr;linux_assert(1);}
void el0_inv(struct pt_regs *regs,unsigned long esr){(void)regs;(void)esr;linux_assert(1);}
const syscall_fn_t sys_call_table[__NR_syscalls]={[23]=23,[24]=24,[25]=25,[46]=46,[57]=57,[62]=62,[63]=63,[64]=64,[67]=67,[68]=68,
    [148]=148,[150]=150,[166]=166,[172]=172,[173]=173,[174]=174,[175]=175,[176]=176,[177]=177,[178]=178};
long osrec_sys_call(syscall_fn_t syscall_fn,const struct pt_regs *regs)
{
    const uint64_t *x=regs->regs;
    switch(syscall_fn){
    case 172:return linux_getpid();
    case 178:return linux_gettid();
    case 173:return linux_getppid();
    case 174:return linux_getuid();
    case 175:return linux_geteuid();
    case 176:return linux_getgid();
    case 177:return linux_getegid();
    case 148:return linux_getresuid((uid_t __user *)(long)x[0],(uid_t __user *)(long)x[1],(uid_t __user *)(long)x[2]);
    case 150:return linux_getresgid((gid_t __user *)(long)x[0],(gid_t __user *)(long)x[1],(gid_t __user *)(long)x[2]);
    case 166:return linux_umask((int)(long)x[0]);
    case 23:return linux_dup((unsigned int)(long)x[0]);
    case 24:return linux_dup3((unsigned int)(long)x[0],(unsigned int)(long)x[1],(int)(long)x[2]);
    case 57:return linux_close((unsigned int)(long)x[0]);
    case 46:return linux_ftruncate((unsigned int)(long)x[0],(off_t)(long)x[1]);
    case 63:return linux_read((unsigned int)(long)x[0],(char __user *)(long)x[1],(size_t)(long)x[2]);
    case 64:return linux_write((unsigned int)(long)x[0],(const char __user *)(long)x[1],(size_t)(long)x[2]);
    case 62:return linux_lseek((unsigned int)(long)x[0],(off_t)(long)x[1],(unsigned int)(long)x[2]);
    case 67:return linux_pread64((unsigned int)(long)x[0],(char __user *)(long)x[1],(size_t)(long)x[2],(loff_t)(long)x[3]);
    case 68:return linux_pwrite64((unsigned int)(long)x[0],(const char __user *)(long)x[1],(size_t)(long)x[2],(loff_t)(long)x[3]);
    case 25:return linux_fcntl((unsigned int)(long)x[0],(unsigned int)(long)x[1],(unsigned long)(long)x[2]);
    default:return sys_ni_syscall();
    }
}
struct task_struct *osrec_entry_task(void){return current;}
