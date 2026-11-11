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
/* This CPU's copies of the superblock's per-CPU freeze-protection read counts; a live binding supplies the write level's. */
unsigned int sb_read_count[SB_FREEZE_LEVELS];
struct super_block superblock={{0,{{{0},&sb_read_count[0],{0}},{{0},&sb_read_count[1],{0}},{{0},&sb_read_count[2],{0}}}},0,SB_NOSEC|SB_I_VERSION,1,INT64_MIN,INT64_MAX,&user_ns,&super_ops,MAX_LFS_FILESIZE,&noop_bdi,0};
/* Per-CPU dirty-throttling counters (balance_dirty_pages_ratelimited_flags past its bdi check). */
int bdp_ratelimits,dirty_throttle_leaks,ratelimit_pages;
struct mnt_idmap nop_mnt_idmap;
/* The internal shm mount and this CPU's copy of its per-CPU counts; a live binding supplies the writer count. */
struct mnt_pcp mount_pcp;
/* This CPU's rcu_data fields rcu_all_qs reads; a live binding supplies them. */
struct rcu_data rcu_data;
/* SLUB state (model.h's slab block): the KMALLOC_NORMAL kmalloc-192 cache with its per-CPU freelist holding one
 * object of its per-CPU slab. A live binding supplies the size index table, the cache entries and every value. */
uint8_t kmalloc_size_index[24];
struct kmalloc_object kmalloc_object;
struct slab kmalloc_object_slab;
struct kmem_cache_cpu kmalloc_cpu;
struct kmem_cache kmalloc_cache;
struct kmalloc96_object kmalloc96_object;
struct slab kmalloc96_object_slab;
struct kmem_cache_cpu kmalloc96_cpu;
struct kmem_cache kmalloc96_cache;
struct kmem_cache *kmalloc_caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIGH + 1];
struct mount vfs_mount={&mount_pcp,{0,&nop_mnt_idmap,&superblock}};
/* The coarse real-time clock the slice reads; a live binding supplies the observed value. */
struct tk_core_model tk_core={{0},{{0,0},1}};
struct bdi_writeback inode_wb;
extern struct inode inode_pool[2];
struct folio folio_pool[1]={{(1UL<<PG_referenced)|(1UL<<PG_uptodate)|(1UL<<PG_dirty)|(1UL<<PG_lru)|(1UL<<PG_swapbacked),&inode_pool[1].i_data,0,{1},{0},{0},{0}}};
struct page zero_page;
/* The written memfd inode carries S_NOSEC (inode_has_no_xattr on its first write). */
#define INITIAL_INODE(mode,flags,size,block,op,self,data,head,pages,aops) {mode,0,block,flags,{0},{0},size,{0,0},{0,0},{0,0},{0},0,0,{0,0},0,0,op,data,{self,{0,0,head},0,{0},pages,aops},{{0},{0}},{0,{0,0},VM_NORESERVE,pages,0,0,0},0}
struct inode inode_pool[2]={INITIAL_INODE(0020000,0,0,&superblock,&iop_pool[0],&inode_pool[0],&inode_pool[0].i_data,0,0,&aops_pool[0]),
    INITIAL_INODE(0100000,S_NOSEC,16,&superblock,&iop_pool[1],&inode_pool[1],&inode_pool[1].i_data,&folio_pool[0],1,&aops_pool[1])};
struct dentry dentry_pool[2]={{&inode_pool[0],0,&superblock},{&inode_pool[1],0,&superblock}};
/* Operation tables of the console (tty_fops) and the regular shmem file (shmem_file_operations). */
struct file_operations fop_pool[2]={{1,0,1,0,1,0,0,0},{2,0,1,0,1,0,0,0}};
#define INITIAL_FILE(count,mode,flags,id,path,mnt,op,data) {count,mode,flags,id,0,0,0,{path,mnt},{0},0,0,op,data}
struct file file_pool[2]={INITIAL_FILE(3,CONSOLE_MODE,LINUX_INITIAL_FILE_FLAGS_0,1,&dentry_pool[0],&vfs_mount.mnt,&fop_pool[0],&inode_pool[0].i_data),INITIAL_FILE(1,REGULAR_MODE,LINUX_INITIAL_FILE_FLAGS_1,2,&dentry_pool[1],&vfs_mount.mnt,&fop_pool[1],&inode_pool[1].i_data)};
struct file_data file_data={{97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112}};
#define INITIAL_FILES(table,console,seed) {table,{64,{console,console,console,seed},{8},{15},{0}},4,0,0,{1},{0}}
struct files_struct files=INITIAL_FILES(&files.fdtab,&file_pool[0],&file_pool[1]);
/* A running task with preemption enabled and no reschedule pending: arm64 keeps need_resched inverted in the
 * upper half of preempt_count, so its value is 1<<32. */
struct task_struct task={{0,UINT64_C(1)<<32},LINUX_INITIAL_PID,LINUX_INITIAL_TGID,&parent,&fs,&creds,&files,{0,0,0,0},0,0,0,{0},0,0,{0},&nsproxy,{0},{0},0,0};
struct task_struct *current=&task;
/* The futex hash (kernel/futex/core.c): futex_init allocates hashsize buckets with empty chains and
 * no waiters; a live binding supplies the hash size and each bucket's waiter count. */
#define FUTEX_BUCKET(b,i) {{0},0,{{&b[i].chain.node_list,&b[i].chain.node_list}}}
#define FUTEX_BUCKETS4(b,i) FUTEX_BUCKET(b,i),FUTEX_BUCKET(b,(i)+1),FUTEX_BUCKET(b,(i)+2),FUTEX_BUCKET(b,(i)+3)
#define FUTEX_BUCKETS16(b,i) FUTEX_BUCKETS4(b,i),FUTEX_BUCKETS4(b,(i)+4),FUTEX_BUCKETS4(b,(i)+8),FUTEX_BUCKETS4(b,(i)+12)
#define FUTEX_BUCKETS64(b,i) FUTEX_BUCKETS16(b,i),FUTEX_BUCKETS16(b,(i)+16),FUTEX_BUCKETS16(b,(i)+32),FUTEX_BUCKETS16(b,(i)+48)
struct futex_hash_bucket futex_hash_buckets[OSREC_FUTEX_BUCKETS]={FUTEX_BUCKETS64(futex_hash_buckets,0),FUTEX_BUCKETS64(futex_hash_buckets,64),FUTEX_BUCKETS64(futex_hash_buckets,128),FUTEX_BUCKETS64(futex_hash_buckets,192)};
struct futex_data __futex_data={&futex_hash_buckets[0],OSREC_FUTEX_BUCKETS};
/* This CPU's hrtimer bases (kernel/time/hrtimer.c's DEFINE_PER_CPU initializer for the fields the slice holds):
 * each clock base knows its CPU base, index and clock; a live binding supplies each one's seq and running. */
#define OSREC_CLOCK_BASE(b,i,clock) {&b,i,clock,{0},0}
struct hrtimer_cpu_base hrtimer_bases={{OSREC_CLOCK_BASE(hrtimer_bases,HRTIMER_BASE_MONOTONIC,CLOCK_MONOTONIC),OSREC_CLOCK_BASE(hrtimer_bases,HRTIMER_BASE_REALTIME,CLOCK_REALTIME),
    OSREC_CLOCK_BASE(hrtimer_bases,HRTIMER_BASE_BOOTTIME,CLOCK_BOOTTIME),OSREC_CLOCK_BASE(hrtimer_bases,HRTIMER_BASE_TAI,CLOCK_TAI),OSREC_CLOCK_BASE(hrtimer_bases,HRTIMER_BASE_MONOTONIC_SOFT,CLOCK_MONOTONIC),
    OSREC_CLOCK_BASE(hrtimer_bases,HRTIMER_BASE_REALTIME_SOFT,CLOCK_REALTIME),OSREC_CLOCK_BASE(hrtimer_bases,HRTIMER_BASE_BOOTTIME_SOFT,CLOCK_BOOTTIME),OSREC_CLOCK_BASE(hrtimer_bases,HRTIMER_BASE_TAI_SOFT,CLOCK_TAI)}};
/* kernel/time/hrtimer.c's hrtimer_clock_to_base_table, its designated initializer spelled out: every clock maps to
 * HRTIMER_MAX_CLOCK_BASES (8, unsupported) except CLOCK_REALTIME (0) -> HRTIMER_BASE_REALTIME (1), CLOCK_MONOTONIC (1)
 * -> HRTIMER_BASE_MONOTONIC (0), CLOCK_BOOTTIME (7) -> HRTIMER_BASE_BOOTTIME (2) and CLOCK_TAI (11) -> HRTIMER_BASE_TAI (3). */
_Static_assert(CLOCK_REALTIME==0 && CLOCK_MONOTONIC==1 && CLOCK_BOOTTIME==7 && CLOCK_TAI==11 && MAX_CLOCKS==16,"clock ids");
_Static_assert(HRTIMER_BASE_MONOTONIC==0 && HRTIMER_BASE_REALTIME==1 && HRTIMER_BASE_BOOTTIME==2 && HRTIMER_BASE_TAI==3 && HRTIMER_MAX_CLOCK_BASES==8,"hrtimer bases");
const int hrtimer_clock_to_base_table[MAX_CLOCKS] = {1,0,8,8,8,8,8,2,8,8,8,3,8,8,8,8};
/* The task's namespaces: the initial time namespace (a live binding checks the task is in it). */
struct time_namespace init_time_ns;
struct nsproxy nsproxy={&init_time_ns};
/* kernel/futex/requeue.c */
const struct futex_q futex_q_init = {
	/* list gets initialized in futex_queue()*/
	.wake		= futex_wake_mark,
	.key		= FUTEX_KEY_INIT,
	.bitset		= FUTEX_BITSET_MATCH_ANY,
	.requeue_state	= ATOMIC_INIT(Q_REQUEUE_PI_NONE),
};
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
/* __set_bit/__clear_bit on close_on_exec: every caller passes a descriptor it validated (fdget,
 * alloc_fd, dup2) below max_fds; like close_on_exec, the model flags one that is not. */
void __set_close_on_exec(unsigned int fd,struct fdtable *t){linux_assert(fd>=t->max_fds);t->close_on_exec[fd/64]|=1ul<<(fd%64);}
void __clear_close_on_exec(unsigned int fd,struct fdtable *t){linux_assert(fd>=t->max_fds);t->close_on_exec[fd/64]&=~(1ul<<(fd%64));}
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
/* Mount hash locking only on PREEMPT_RT (unset). */
void lock_mount_hash(void){linux_assert(1);}
struct mount *real_mount(struct vfsmount *mnt){linux_assert(mnt!=&vfs_mount.mnt);return &vfs_mount;}
void unlock_mount_hash(void){linux_assert(1);}
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
 * user objects (the call's buffer, or a writev iovec array and its segments);
 * the live workload places a guard page after a buffer, so an access outside
 * them faults. A faulting access ends the copy and the
 * result is the number of bytes not copied (the uaccess exception-table fixup);
 * this copy is byte-exact where the assembly may stop up to one chunk short of
 * the fault. Kernel-side page bytes are the 64-byte store (file_data) or the
 * zero page's. */
/* The user objects a call names: its buffer (object 1, the first 32 bytes) and a writev iovec
 * array with its segments (objects from OSREC_CALL_OBJECTS). Other admitted user memory (the
 * application's code and stack in a checkpoint chain) is outside every user copy. */
#define OSREC_CALL_OBJECTS 0x10000u
static unsigned char *call_bytes(uintptr_t address,size_t n,uint32_t access)
{
    int named=0;
    for(size_t i=0;i<active_memory.count;++i){
        const struct osrec_user_region *r=&active_memory.regions[i];
        size_t extent=r->object_id==1 && r->bytes>=32 && ((r->permissions&3)==3 || !r->permissions) ? 32 : r->object_id>=OSREC_CALL_OBJECTS ? r->bytes : 0;
        if(!extent)continue;
        named=1;
        /* An object the call names that the user address space does not map (permissions 0): no memory, no fault. */
        if(!r->permissions && address>=r->user_address && address-r->user_address<extent)return 0;
        if(address>=r->user_address && address-r->user_address<extent && n<=extent-(size_t)(address-r->user_address) && (r->permissions&access)==access)
            return r->image_address+(size_t)(address-r->user_address);
    }
    linux_assert(!named);
    return 0;
}
static unsigned char *user_byte(uintptr_t address,uint32_t access){return call_bytes(address,1,access);}
/* The kernel side of every user copy here is the 64-byte store, for a copy
 * to user memory only the zero page's bytes (kmap_local_page), or for a copy from
 * user memory the slice's stack. The span must lie inside one of them; any other pointer fails. The footprint analysis relies on
 * this check (the copies are checked-span boundaries in analysis-contracts.json). */
extern const unsigned char __stack_bottom[],__stack_top[];
static void page_span(const unsigned char *p,unsigned long n,int store)
{
    if(p>=file_data.bytes && p<file_data.bytes+64)linux_assert(n>(size_t)(file_data.bytes+64-p));
    else if(!store && p>=zero_bytes && p<zero_bytes+64)linux_assert(n>(size_t)(zero_bytes+64-p));
    /* A copy into automatic storage (get_timespec64's struct __kernel_timespec) stays on the slice's stack. */
    else if(store && p>=__stack_bottom && p<__stack_top)linux_assert(n>(size_t)(__stack_top-p));
    else linux_assert(1);
}
unsigned long __arch_copy_to_user(void __user *to,const void *from,unsigned long n)
{
    const unsigned char *source=from;unsigned long copied=0;page_span(source,n,0);
    for(;copied<n;++copied){unsigned char *at=user_byte((uintptr_t)to+copied,OSREC_MEMORY_WRITE);if(!at)break;*at=source[copied];}
    return n-copied;
}
unsigned long __arch_copy_from_user(void *to,const void __user *from,unsigned long n)
{
    unsigned char *target=to;unsigned long copied=0;page_span(target,n,1);
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
    folio_pool[0]=(struct folio){(1UL<<PG_locked)|(1UL<<PG_swapbacked),mapping,index,{2},{0},{0},{0}};
    mapping->i_pages.xa_head=&folio_pool[0];mapping->nrpages=1;++inode->osrec_shmem.alloced;
    return &folio_pool[0];
}
bool linux_is_err(const void *p){return (uintptr_t)p>=(uintptr_t)-MAX_ERRNO;}
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
void copy_overflow(int size,unsigned long count){(void)size;(void)count;linux_assert(1);}
void __bad_copy_from(void){}
void __bad_copy_to(void){}
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
/* __get_user: a naturally sized load from an admitted user object, -EFAULT outside them. */
int linux_get_user(void *value,const void *p,unsigned long size)
{
    const unsigned char *at=call_bytes((uintptr_t)p,size,OSREC_MEMORY_READ);
    if(!at)return -EFAULT;
    for(unsigned long i=0;i<size;++i)((unsigned char *)value)[i]=at[i];
    return 0;
}
bool in_compat_syscall(void){return test_thread_flag(TIF_32BIT);}
int copy_compat_iovec_from_user(struct iovec *iov,const struct iovec __user *uvec,unsigned long nr){(void)iov;(void)uvec;(void)nr;linux_assert(1);return -EFAULT;}
/* SLUB (model.h's slab block). virt_to_folio is arm64's linear-map translation (virt_to_page, then page_folio):
 * the slice's one slab object lies in the slice's one slab, which the live binding checks is the object's page,
 * a slab head page. Large kmalloc, the slow paths and the memcg and debug branches fault. */
struct folio *virt_to_folio(const void *x)
{
    if((const char *)x>=(const char *)&kmalloc96_object && (const char *)x<(const char *)(&kmalloc96_object+1))return (struct folio *)&kmalloc96_object_slab;
    linux_assert((const char *)x<(const char *)&kmalloc_object || (const char *)x>=(const char *)(&kmalloc_object+1));return (struct folio *)&kmalloc_object_slab;
}
void free_large_kmalloc(struct folio *folio,void *object){(void)folio;(void)object;linux_assert(1);}
void *kmalloc_large_noprof(size_t size,gfp_t flags){(void)size;(void)flags;linux_assert(1);return 0;}
void *__kmalloc_large_node(size_t size,gfp_t flags,int node){(void)size;(void)flags;(void)node;linux_assert(1);return 0;}
unsigned int get_order(unsigned long size){(void)size;linux_assert(1);return 0;}
void *__slab_alloc(struct kmem_cache *s,gfp_t flags,int node,unsigned long addr,struct kmem_cache_cpu *c,unsigned int orig_size){(void)s;(void)flags;(void)node;(void)addr;(void)c;(void)orig_size;linux_assert(1);return 0;}
void __slab_free(struct kmem_cache *s,struct slab *slab,void *head,void *tail,int cnt,unsigned long addr){(void)s;(void)slab;(void)head;(void)tail;(void)cnt;(void)addr;linux_assert(1);}
void note_cmpxchg_failure(const char *n,const struct kmem_cache *s,unsigned long tid){(void)n;(void)s;(void)tid;linux_assert(1);}
bool __memcg_slab_post_alloc_hook(struct kmem_cache *s,struct list_lru *lru,gfp_t flags,size_t size,void **p){(void)s;(void)lru;(void)flags;(void)size;(void)p;linux_assert(1);return false;}
void memcg_alloc_abort_single(struct kmem_cache *s,void *object){(void)s;(void)object;linux_assert(1);}
void kmem_cache_free_bulk(struct kmem_cache *s,size_t size,void **p){(void)s;(void)size;(void)p;linux_assert(1);}
struct slabobj_ext *slab_obj_exts(struct slab *slab){(void)slab;linux_assert(1);return 0;}
void __memcg_slab_free_hook(struct kmem_cache *s,struct slab *slab,void **p,int objects,struct slabobj_ext *obj_exts){(void)s;(void)slab;(void)p;(void)objects;(void)obj_exts;linux_assert(1);}
bool freeptr_outside_object(struct kmem_cache *s){(void)s;linux_assert(1);return false;}
long copy_from_kernel_nofault(void *dst,const void *src,size_t size){(void)dst;(void)src;(void)size;linux_assert(1);return -EFAULT;}
unsigned int get_info_end(struct kmem_cache *s){(void)s;linux_assert(1);return 0;}
unsigned int get_orig_size(struct kmem_cache *s,void *object){(void)s;(void)object;linux_assert(1);return 0;}
void set_orig_size(struct kmem_cache *s,void *object,unsigned int size){(void)s;(void)object;(void)size;linux_assert(1);}
void iov_iter_bvec_advance(struct iov_iter *i,size_t size){(void)i;(void)size;linux_assert(1);}
/* No signal is pending for the task. */
int fatal_signal_pending(struct task_struct *p){(void)p;return 0;}
void send_sig(int sig,struct task_struct *p,int priv){(void)sig;(void)p;(void)priv;linux_assert(1);}
struct folio *linux_page_folio(struct page *page){if(page==&user_folio.page)return &user_folio;linux_assert(page!=&folio_pool[0].page);return &folio_pool[0];}
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
/* folio_test_slab (include/linux/page-flags.h) tests the page type; the slice's folios carry none, so the
 * slab type is the slice's one slab (the live binding checks its page type), and page-cache folios are not slabs. */
bool folio_test_slab(struct folio *folio){return (void *)folio==(void *)&kmalloc_object_slab || (void *)folio==(void *)&kmalloc96_object_slab;}
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
const syscall_fn_t sys_call_table[__NR_syscalls]={[23]=23,[24]=24,[25]=25,[46]=46,[57]=57,[62]=62,[63]=63,[64]=64,[66]=66,[67]=67,[68]=68,[98]=98,
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
    case 66:return linux_writev((unsigned long)x[0],(const struct iovec __user *)(long)x[1],(unsigned long)x[2]);
    case 98:return linux_futex((u32 __user *)(long)x[0],(int)(long)x[1],(u32)x[2],(const struct __kernel_timespec __user *)(long)x[3],(u32 __user *)(long)x[4],(u32)x[5]);
    default:return sys_ni_syscall();
    }
}
struct task_struct *osrec_entry_task(void){return current;}
/* Futex paths outside the slice's admitted calls (private FUTEX_WAKE with no waiter, private FUTEX_WAIT on
 * a changed value): shared keys, timeouts, sleeping, waking a waiter and the other commands fault. */
long set_restart_fn(struct restart_block *r,long (*fn)(struct restart_block *)){(void)r;(void)fn;linux_assert(1);return -EINVAL;}
long futex_wait_restart(struct restart_block *r){(void)r;return -EINVAL;}
int signal_pending(struct task_struct *t){(void)t;linux_assert(1);return 0;}
struct folio user_folio;
unsigned long user_page_address;
/* The pinned tables (model.h): the live binding dumps them for a shared futex's word, with their physical addresses. */
struct osrec_pgd_page osrec_pgd_table;struct osrec_pud_page osrec_pud_table;struct osrec_pmd_page osrec_pmd_table;struct osrec_pte_page osrec_pte_table;
unsigned long osrec_mm_value,osrec_pud_table_pa,osrec_pmd_table_pa,osrec_pte_table_pa,osrec_user_pfn;
/* Each asserts its pinned input (a faulted run is never equivalent) and returns the bound table. */
pgd_t *osrec_mm_pgd(struct mm_struct *mm){linux_assert((unsigned long)mm!=osrec_mm_value || !osrec_mm_value);return osrec_pgd_table.entries;}
/* gup_fast_pte_range's pages[*nr] = page for the one page the slice's callers pin (get_futex_key: nr_pages 1). */
void osrec_gup_store(struct page **pages,int nr,struct page *page){linux_assert(nr!=0);pages[0]=page;}
pud_t *osrec_pud_va(phys_addr_t pa){linux_assert(pa!=osrec_pud_table_pa || !pa);return osrec_pud_table.entries;}
pmd_t *osrec_pmd_va(phys_addr_t pa){linux_assert(pa!=osrec_pmd_table_pa || !pa);return osrec_pmd_table.entries;}
pte_t *osrec_pte_va(phys_addr_t pa){linux_assert(pa!=osrec_pte_table_pa || !pa);return osrec_pte_table.entries;}
struct page *osrec_pfn_to_page(unsigned long pfn){linux_assert(pfn!=osrec_user_pfn || !osrec_user_pfn);return &user_folio.page;}
pte_t contpte_ptep_get_lockless(pte_t *p){(void)p;linux_assert(1);return __pte(0);}
pte_t contpte_ptep_get(pte_t *p,pte_t pte){(void)p;(void)pte;linux_assert(1);return __pte(0);}
int folio_ref_count(const struct folio *folio){return folio->_refcount.counter;}
bool folio_ref_try_add(struct folio *folio,int count){if(!folio->_refcount.counter)return false;folio->_refcount.counter+=count;return true;}
void folio_put_refs(struct folio *folio,int refs){if((folio->_refcount.counter-=refs)==0)__folio_put(folio);}
/* A user page here is an order-0 anonymous page, not a hugetlb one. */
bool folio_test_hugetlb(const struct folio *folio){(void)folio;return false;}
bool secretmem_mapping(struct address_space *mapping){(void)mapping;linux_assert(1);return false;}
bool is_zero_page(const struct page *page){(void)page;linux_assert(1);return false;}
bool is_zero_folio(const struct folio *folio){(void)folio;linux_assert(1);return false;}
bool folio_is_longterm_pinnable(struct folio *folio){(void)folio;linux_assert(1);return false;}
void node_stat_mod_folio(struct folio *folio,enum node_stat_item item,int n){(void)folio;(void)item;(void)n;linux_assert(1);}
void mm_set_has_pinned_flag(unsigned long *flags){(void)flags;linux_assert(1);}
long __gup_longterm_locked(struct mm_struct *mm,unsigned long start,unsigned long nr,struct page **pages,int *locked,unsigned int flags){(void)mm;(void)start;(void)nr;(void)pages;(void)locked;(void)flags;linux_assert(1);return -EFAULT;}
int gup_fast_pmd_leaf(pmd_t pmd,pmd_t *pmdp,unsigned long a,unsigned long e,unsigned int f,struct page **p,int *n){(void)pmd;(void)pmdp;(void)a;(void)e;(void)f;(void)p;(void)n;linux_assert(1);return 0;}
int gup_fast_pud_leaf(pud_t pud,pud_t *pudp,unsigned long a,unsigned long e,unsigned int f,struct page **p,int *n){(void)pud;(void)pudp;(void)a;(void)e;(void)f;(void)p;(void)n;linux_assert(1);return 0;}
int gup_hugepd(struct vm_area_struct *v,hugepd_t h,unsigned long a,unsigned int s,unsigned long e,unsigned int f,struct page **p,int *n,bool fast){(void)v;(void)h;(void)a;(void)s;(void)e;(void)f;(void)p;(void)n;(void)fast;linux_assert(1);return 0;}
struct dev_pagemap *get_dev_pagemap(unsigned long pfn,struct dev_pagemap *pg){(void)pfn;(void)pg;linux_assert(1);return 0;}
void put_dev_pagemap(struct dev_pagemap *pg){(void)pg;linux_assert(1);}
void gup_fast_undo_dev_pagemap(int *nr,int start,unsigned int flags,struct page **pages){(void)nr;(void)start;(void)flags;(void)pages;linux_assert(1);}
bool gup_must_unshare(struct vm_area_struct *v,unsigned int flags,struct page *page){(void)v;(void)flags;(void)page;linux_assert(1);return false;}
void atomic_add(int n,atomic_t *v){(void)n;(void)v;linux_assert(1);}
void atomic_sub(int n,atomic_t *v){(void)n;(void)v;linux_assert(1);}
void folio_ref_add(struct folio *folio,int n){(void)folio;(void)n;linux_assert(1);}
void gup_fast_unpin_user_pages(struct page **pages,unsigned long n){(void)pages;(void)n;linux_assert(1);}
void sanity_check_pinned_pages(struct page **pages,unsigned long n){(void)pages;(void)n;linux_assert(1);}
int gup_fast_pgd_leaf(pgd_t pgd,pgd_t *pgdp,unsigned long a,unsigned long e,unsigned int f,struct page **p,int *n){(void)pgd;(void)pgdp;(void)a;(void)e;(void)f;(void)p;(void)n;linux_assert(1);return 0;}
swp_entry_t pmd_to_swp_entry(pmd_t pmd){(void)pmd;linux_assert(1);return (swp_entry_t){0};}
int is_migration_entry(swp_entry_t e){(void)e;linux_assert(1);return 0;}
void pmd_clear_bad(pmd_t *pmd){(void)pmd;linux_assert(1);}
unsigned long folio_page_idx(struct folio *folio,struct page *page){(void)folio;(void)page;linux_assert(1);return 0;}
u64 get_inode_sequence_number(struct inode *inode){(void)inode;linux_assert(1);return 0;}
/* hrtimer slow paths: only an armed or running timer reaches these (the wait returns before arming it). */
/* Only hrtimer_wakeup's address reaches the slice (the sleeper's callback); the timer never fires here, so its
 * body touches no state, like futex_wake_mark's. */
enum hrtimer_restart hrtimer_wakeup(struct hrtimer *t){(void)t;return HRTIMER_NORESTART;}
bool task_is_realtime(struct task_struct *p){(void)p;linux_assert(1);return false;}
void hrtimer_cancel_wait_running(struct hrtimer *t){(void)t;linux_assert(1);}
struct hrtimer_clock_base *lock_hrtimer_base(const struct hrtimer *t,unsigned long *f){(void)t;(void)f;linux_assert(1);return 0;}
int hrtimer_callback_running(struct hrtimer *t){(void)t;linux_assert(1);return 0;}
int remove_hrtimer(struct hrtimer *t,struct hrtimer_clock_base *b,bool restart,bool keep){(void)t;(void)b;(void)restart;(void)keep;linux_assert(1);return 0;}
void unlock_hrtimer_base(const struct hrtimer *t,unsigned long *f){(void)t;(void)f;linux_assert(1);}
/* A non-initial time namespace's offsets (do_timens_ktime_to_host) are outside the slice. */
ktime_t do_timens_ktime_to_host(clockid_t c,ktime_t t,struct timens_offsets *o){(void)c;(void)o;linux_assert(1);return t;}
/* ktime_get: a fixed 0 (model.h's note: the arch counter is not reproducible, and the value arms only a timer cancelled unarmed). */
ktime_t ktime_get(void){return 0;}
void futex_wait_queue(struct futex_hash_bucket *hb,struct futex_q *q,struct hrtimer_sleeper *to){(void)hb;(void)q;(void)to;linux_assert(1);}
int futex_unqueue(struct futex_q *q){(void)q;linux_assert(1);return 0;}
/* Only addresses of these two reach the slice (futex_q_init.wake, set_restart_fn's argument); they are called
 * through osrec_futex_q_wake and a restarted syscall, both outside it, so their bodies touch no state. */
void futex_wake_mark(struct wake_q_head *w,struct futex_q *q){(void)w;(void)q;}
void osrec_futex_q_wake(futex_wake_fn *wake,struct wake_q_head *w,struct futex_q *q){(void)wake;(void)w;(void)q;linux_assert(1);}
/* __futex_atomic_op (model.h): the user word's load, operation and store on one CPU, or -EFAULT outside the admitted objects. */
int osrec_futex_atomic_op(int op,int *oldval,u32 __user *uaddr,int oparg)
{
    u32 old,value;
    if(linux_get_user(&old,uaddr,sizeof(old)))return -EFAULT;
    unsigned char *target=osrec_user_memory_resolve(&active_memory,(uintptr_t)uaddr,4,OSREC_MEMORY_WRITE);
    if(!target)return -EFAULT;
    switch(op){
    case FUTEX_OP_SET:value=(u32)oparg;break;
    case FUTEX_OP_ADD:value=old+(u32)oparg;break;
    case FUTEX_OP_OR:value=old|(u32)oparg;break;
    case FUTEX_OP_ANDN:value=old&(u32)oparg;break;
    case FUTEX_OP_XOR:value=old^(u32)oparg;break;
    default:linux_assert(1);return -ENOSYS;
    }
    for(unsigned i=0;i<4;++i)target[i]=(unsigned char)(value>>(8*i));
    *oldval=(int)old;
    return 0;
}
/* Waking a queued task, moving a waiter between buckets and the PI requeue steps: only with a waiter, outside the slice.
 * put_pi_state(NULL) is the original's early return (futex_requeue drops its never-taken reference). */
int wake_up_process(struct task_struct *t){(void)t;linux_assert(1);return 0;}
void put_task_struct(struct task_struct *t){(void)t;linux_assert(1);}
void get_pi_state(struct futex_pi_state *p){(void)p;linux_assert(1);}
void put_pi_state(struct futex_pi_state *p){linux_assert(p!=0);}
int futex_proxy_trylock_atomic(u32 __user *u,struct futex_hash_bucket *hb1,struct futex_hash_bucket *hb2,union futex_key *k1,union futex_key *k2,struct futex_pi_state **ps,struct task_struct **exiting,int set_waiters){(void)u;(void)hb1;(void)hb2;(void)k1;(void)k2;(void)ps;(void)exiting;(void)set_waiters;linux_assert(1);return -EINVAL;}
int fault_in_user_writeable(u32 __user *u){(void)u;linux_assert(1);return -EFAULT;}
void wait_for_owner_exiting(int ret,struct task_struct *t){(void)ret;(void)t;linux_assert(1);}
bool futex_requeue_pi_prepare(struct futex_q *q,struct futex_pi_state *p){(void)q;(void)p;linux_assert(1);return false;}
int rt_mutex_start_proxy_lock(struct rt_mutex_base *l,struct rt_mutex_waiter *w,struct task_struct *t){(void)l;(void)w;(void)t;linux_assert(1);return -EINVAL;}
void requeue_pi_wake_futex(struct futex_q *q,union futex_key *k,struct futex_hash_bucket *hb){(void)q;(void)k;(void)hb;linux_assert(1);}
void requeue_futex(struct futex_q *q,struct futex_hash_bucket *hb1,struct futex_hash_bucket *hb2,union futex_key *k){(void)q;(void)hb1;(void)hb2;(void)k;linux_assert(1);}
void futex_requeue_pi_complete(struct futex_q *q,int locked){(void)q;(void)locked;linux_assert(1);}
/* futex_atomic_cmpxchg_inatomic (model.h): load the admitted user word, store newval if it holds oldval; -EFAULT if
 * either access faults (an unwritable word faults only when the store happens, as stlxr does). */
int futex_atomic_cmpxchg_inatomic(u32 *uval,u32 __user *uaddr,u32 oldval,u32 newval)
{
    u32 value;
    if(linux_get_user(&value,uaddr,sizeof(value)))return -EFAULT;
    if(value==oldval){
        unsigned char *target=osrec_user_memory_resolve(&active_memory,(uintptr_t)uaddr,4,OSREC_MEMORY_WRITE);
        if(!target)return -EFAULT;
        for(unsigned i=0;i<4;++i)target[i]=(unsigned char)(newval>>(8*i));
    }
    *uval=value;
    return 0;
}
/* Contended PI futexes: another owner or a waiter (pi_state attach, rt_mutex proxy locking, queueing). */
int attach_to_pi_state(u32 __user *u,u32 v,struct futex_pi_state *p,struct futex_pi_state **ps){(void)u;(void)v;(void)p;(void)ps;linux_assert(1);return -EINVAL;}
int attach_to_pi_owner(u32 __user *u,u32 v,union futex_key *k,struct futex_pi_state **ps,struct task_struct **e){(void)u;(void)v;(void)k;(void)ps;(void)e;linux_assert(1);return -EINVAL;}
void __attach_to_pi_owner(struct task_struct *t,union futex_key *k,struct futex_pi_state **ps){(void)t;(void)k;(void)ps;linux_assert(1);}
struct rt_mutex_waiter *rt_mutex_top_waiter(struct rt_mutex_base *l){(void)l;linux_assert(1);return 0;}
void __futex_unqueue(struct futex_q *q){(void)q;linux_assert(1);}
int wake_futex_pi(u32 __user *u,u32 v,struct futex_pi_state *p,struct rt_mutex_waiter *w){(void)u;(void)v;(void)p;(void)w;linux_assert(1);return -EINVAL;}
void __futex_queue(struct futex_q *q,struct futex_hash_bucket *hb){(void)q;(void)hb;linux_assert(1);}
int rt_mutex_futex_trylock(struct rt_mutex_base *l){(void)l;linux_assert(1);return 0;}
void rt_mutex_pre_schedule(void){linux_assert(1);}
void rt_mutex_post_schedule(void){linux_assert(1);}
void rt_mutex_init_waiter(struct rt_mutex_waiter *w){(void)w;linux_assert(1);}
int __rt_mutex_start_proxy_lock(struct rt_mutex_base *l,struct rt_mutex_waiter *w,struct task_struct *t){(void)l;(void)w;(void)t;linux_assert(1);return -EINVAL;}
void hrtimer_sleeper_start_expires(struct hrtimer_sleeper *s,enum hrtimer_mode m){(void)s;(void)m;linux_assert(1);}
int rt_mutex_wait_proxy_lock(struct rt_mutex_base *l,struct hrtimer_sleeper *s,struct rt_mutex_waiter *w){(void)l;(void)s;(void)w;linux_assert(1);return -EINVAL;}
bool rt_mutex_cleanup_proxy_lock(struct rt_mutex_base *l,struct rt_mutex_waiter *w){(void)l;(void)w;linux_assert(1);return false;}
int fixup_pi_owner(u32 __user *u,struct futex_q *q,int locked){(void)u;(void)q;(void)locked;linux_assert(1);return 0;}
void futex_unqueue_pi(struct futex_q *q){(void)q;linux_assert(1);}
int futex_wait_requeue_pi(u32 __user *u,unsigned int flags,u32 val,ktime_t *time,u32 bitset,u32 __user *u2){(void)u;(void)flags;(void)val;(void)time;(void)bitset;(void)u2;linux_assert(1);return -ENOSYS;}
/* Contended rwsems (a waiter, or a writer holding the lock) are outside the slice. */
struct rw_semaphore *rwsem_down_write_slowpath(struct rw_semaphore *sem,int state){(void)state;linux_assert(1);return sem;}
struct rw_semaphore *rwsem_wake(struct rw_semaphore *sem){linux_assert(1);return sem;}
/* A superblock being frozen (rcu_sync not idle) is outside the slice. */
bool __percpu_down_read(struct percpu_rw_semaphore *sem,bool try){(void)sem;(void)try;linux_assert(1);return true;}
void rcuwait_wake_up(struct rcuwait *w){(void)w;linux_assert(1);}
/* Rescheduling, and reporting an urgently needed RCU quiescent state, are outside the slice. */
void preempt_schedule_common(void){linux_assert(1);}
void rcu_momentary_dyntick_idle(void){linux_assert(1);}
void rcu_qs(void){linux_assert(1);}
