#ifndef OSREC_LINUX_MODEL_H
#define OSREC_LINUX_MODEL_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "osrec/syscall_slice.h"
typedef uint32_t uid_t;
typedef uint32_t gid_t;
#define __user
#define S_IRWXUGO 0777
typedef struct {uint32_t val;} kuid_t;
typedef struct {uint32_t val;} kgid_t;
/* include/linux/user_namespace.h. The kernel overlays extent[] with the
 * forward/reverse arrays that maps of more than UID_GID_MAP_MAX_BASE_EXTENTS
 * extents use; the model keeps them as separate members and holds at most the
 * base extents (the adapter rejects more), so reverse is never read. */
#define UID_GID_MAP_MAX_BASE_EXTENTS 5
struct uid_gid_extent {uint32_t first;uint32_t lower_first;uint32_t count;};
struct uid_gid_map {uint32_t nr_extents;struct uid_gid_extent extent[UID_GID_MAP_MAX_BASE_EXTENTS];struct uid_gid_extent *forward,*reverse;};
/* initial: the bound namespace is the initial one (level 0), which the model's
 * init_user_ns names; uid_map/gid_map are its live identifier maps. */
struct user_namespace {uint32_t initial;struct uid_gid_map uid_map,gid_map;};
/* kernel/user_namespace.c */
struct idmap_key {
	bool map_up; /* true  -> id from kid; false -> kid from id */
	uint32_t id; /* id to find */
	uint32_t count; /* == 0 unless used with map_id_range_down() */
};
typedef int (*cmp_func_t)(const void *a, const void *b);
void *bsearch(const void *,const void *,size_t,size_t,cmp_func_t);
struct fs_struct {int umask;};
struct cred {kuid_t uid,euid,suid;kgid_t gid,egid,sgid;struct user_namespace *user_ns;};
struct files_struct;
/* CONFIG_TASK_XACCT read/write accounting (include/linux/task_io_accounting.h). */
struct task_io_accounting {uint64_t rchar,wchar,syscr,syscw;};
/* nr_dirtied/nr_dirtied_pause are read only when the bdi writes back (shmem's does not). */
struct mm_struct;
/* preempt_count: arm64's union of the preemption count and the inverted need-resched flag, read as one u64. */
struct thread_info {unsigned long flags;uint64_t preempt_count;};
struct thread_struct {uint64_t sctlr_user;};
/* thread_info first, as on arm64 (THREAD_INFO_IN_TASK); entry.S reads it and thread.sctlr_user. */
/* flags: the PF_KTHREAD bit access_ok reads. */
/* include/linux/restart_block.h, with only the futex member of its union: futex_wait fills it when a timed wait is interrupted. */
struct restart_block {unsigned long arch_data;long (*fn)(struct restart_block *);struct {uint32_t __user *uaddr;uint32_t val,flags,bitset;uint64_t time;uint32_t __user *uaddr2;} futex;};
/* mm: futex keys of private futexes hash the mm pointer's value; the slice never dereferences it.
 * timer_slack_ns: futex_wait passes it to futex_setup_timer. */
/* include/linux/sched/wake_q.h: a task's link in a wake queue (wake_up_q). */
struct wake_q_node {struct wake_q_node *next;};
#define TASK_COMM_LEN 16
struct task_struct {struct thread_info thread_info;int32_t pid,tgid;struct task_struct *real_parent;struct fs_struct *fs;struct cred *cred;struct files_struct *files;struct task_io_accounting ioac;int nr_dirtied,nr_dirtied_pause;struct mm_struct *mm;struct thread_struct thread;unsigned int flags;uint64_t timer_slack_ns;struct restart_block restart_block;struct nsproxy *nsproxy;char comm[TASK_COMM_LEN];struct wake_q_node wake_q;
    /* PI futexes: the task's preallocated pi_state (refill_pi_state_cache) and its pi_lock word. */
    struct futex_pi_state *pi_state_cache;int pi_lock;};
extern struct task_struct *current;
int task_tgid_vnr(const struct task_struct *);
int task_pid_vnr(const struct task_struct *);
const struct cred *current_cred(void);
struct user_namespace *current_user_ns(void);
kuid_t current_uid(void);
kuid_t current_euid(void);
kgid_t current_gid(void);
kgid_t current_egid(void);
#define __kuid_val(uid) ((uid).val)
#define __kgid_val(gid) ((gid).val)
/* kernel/sys.c's overflowuid/overflowgid sysctls at their defaults
 * (DEFAULT_OVERFLOWUID/GID); the initial namespace maps every identifier, so
 * they are never returned. */
extern int overflowuid,overflowgid;
uint32_t map_id_up(struct uid_gid_map *,uint32_t);
uid_t from_kuid(struct user_namespace *,kuid_t);
gid_t from_kgid(struct user_namespace *,kgid_t);
uid_t from_kuid_munged(struct user_namespace *,kuid_t);
gid_t from_kgid_munged(struct user_namespace *,kgid_t);
void rcu_read_lock(void);
void rcu_read_unlock(void);
#define rcu_dereference(p) (p)
int linux_xchg_int(int *,int);
#define xchg(p,v) linux_xchg_int((p),(v))
int linux_put_user_u32(uint32_t,uint32_t *);
#define put_user(v,p) linux_put_user_u32((v),(p))
long linux_getpid(void);
long linux_gettid(void);
long linux_getppid(void);
long linux_getuid(void);
long linux_geteuid(void);
long linux_getgid(void);
long linux_getegid(void);
long linux_getresuid(uid_t *,uid_t *,uid_t *);
long linux_getresgid(gid_t *,gid_t *,gid_t *);
long linux_umask(int);
typedef uint32_t fmode_t;
typedef void *fl_owner_t;
/* Selected mode bits for a stream console and one seekable RW file. */
struct dentry;
struct vfsmount;
struct path {struct dentry *dentry;struct vfsmount *mnt;};
/* f_owner keeps only the signal number F_GETSIG/F_SETSIG read and write. */
struct fown_struct {int signum;};
struct file_operations;
/* f_pos_lock is the f_pos mutex; f_op selects the object class's operation table. */
struct address_space;
struct file {int64_t f_count;uint32_t f_mode,f_flags,object_id;int64_t f_pos;uint64_t f_version;int f_lock;struct path f_path;struct fown_struct f_owner;int f_pos_lock;uint32_t f_iocb_flags;const struct file_operations *f_op;struct address_space *f_mapping;};
struct fdtable {unsigned int max_fds;struct file *fd[64];uint64_t close_on_exec[1],open_fds[1],full_fds_bits[1];};
/* count is the number of tasks sharing the table; __fget_light borrows when it is 1. */
typedef struct {int counter;} atomic_t;
#define atomic_read_acquire(v) ((v)->counter)
struct wait_queue_head {int osrec_waiters;};
struct files_struct {struct fdtable *fdt;struct fdtable fdtab;unsigned int next_fd;int file_lock,resize_in_progress;atomic_t count;struct wait_queue_head resize_wait;};
#define __rcu
#define __releases(p)
#define __acquires(p)
#define BITS_PER_LONG 64
/* include/linux/bits.h, bitmap.h, find.h and asm-generic/bitops/builtin-__ffs.h (arm64). */
#define GENMASK(h, l) (((~0UL) - (1UL << (l)) + 1) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#define small_const_nbits(nbits) (__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG && (nbits) > 0)
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define __ffs(word) ((unsigned long)__builtin_ctzl(word))
#define ffz(x) __ffs(~(x))
unsigned long _find_next_zero_bit(const unsigned long *,unsigned long,unsigned long);
/* lib/find_bit.c's FIND_NEXT_BIT, verbatim (v6.10): _find_next_zero_bit's body. */
#define FIND_NEXT_BIT(FETCH, MUNGE, size, start)				\
({										\
	unsigned long mask, idx, tmp, sz = (size), __start = (start);		\
										\
	if (unlikely(__start >= sz))						\
		goto out;							\
										\
	mask = MUNGE(BITMAP_FIRST_WORD_MASK(__start));				\
	idx = __start / BITS_PER_LONG;						\
										\
	for (tmp = (FETCH) & mask; !tmp; tmp = (FETCH)) {			\
		if ((idx + 1) * BITS_PER_LONG >= sz)				\
			goto out;						\
		idx++;								\
	}									\
										\
	sz = min(idx * BITS_PER_LONG + __ffs(MUNGE(tmp)), sz);			\
out:										\
	sz;									\
})
#define O_CLOEXEC 02000000
#define RLIMIT_NOFILE 7
#define FMODE_BACKING (1u<<25)
#define EBADF 9
#define EMFILE 24
#define EINVAL 22
#define EBUSY 16
#define EINTR 4
#define ERESTARTSYS 512
#define ERESTARTNOINTR 513
#define ERESTARTNOHAND 514
#define ERESTART_RESTARTBLOCK 516
#define unlikely(v) (v)
#define likely(v) (v)
#define rcu_dereference_raw(p) (p)
#define rcu_dereference_sched(p) (p)
#define rcu_access_pointer(p) (p)
#define rcu_assign_pointer(p,v) ((p)=(v))
void rcu_read_lock_sched(void);
void rcu_read_unlock_sched(void);
#define smp_rmb() ((void)0)
#define WARN_ON_ONCE(v) linux_assert(v)
#define BUG_ON(v) ((void)linux_assert(v))
#define KERN_WARNING ""
#define printk(...) ((void)linux_assert(1))
int linux_assert(int);
void spin_lock(int *);
void spin_unlock(int *);
void lockdep_assert_held(const int *);
unsigned long array_index_mask_nospec(unsigned long,unsigned long);
unsigned int array_index_nospec(unsigned int,unsigned int);
struct fdtable *files_fdtable(struct files_struct *);
int expand_fdtable(struct files_struct *,unsigned int);
/* fs/file.c's sysctl_nr_open at its default; expand_files reads it only past max_fds. */
#define sysctl_nr_open (1024 * 1024)
/* One task runs: a wait would never end, and nothing waits to be woken. */
#define wait_event(wq_head,condition) linux_assert(!(condition))
void wake_up_all(struct wait_queue_head *);
unsigned long rlimit(unsigned int);
void __set_open_fd(unsigned int,struct fdtable *);
void __clear_open_fd(unsigned int,struct fdtable *);
void __set_close_on_exec(unsigned int,struct fdtable *);
void __clear_close_on_exec(unsigned int,struct fdtable *);
int fd_is_open(unsigned int,const struct fdtable *);
struct file *files_lookup_fd_locked(struct files_struct *,unsigned int);
int atomic_long_inc_not_zero(int64_t *);
struct file *get_file(struct file *);
void fput(struct file *);
void __fput_sync(struct file *);
long linux_dup(unsigned int);
long linux_dup3(unsigned int,unsigned int,int);
long linux_close(unsigned int);
typedef int64_t loff_t;
typedef int64_t off_t;
typedef int64_t ssize_t;
struct fd {struct file *file;unsigned int flags;};
/* The regular file's page bytes; its size is inode_pool[1].i_size. */
struct file_data {uint8_t bytes[64];};
#define FMODE_STREAM (1u<<21)
#define FMODE_UNSIGNED_OFFSET (1u<<13)
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#define SEEK_DATA 3
#define SEEK_HOLE 4
#define SEEK_MAX 4
#define ENXIO 6
#define ESPIPE 29
#define EOVERFLOW 75
#define EFAULT 14
#define READ 0
#define WRITE 1
#define MAY_READ 4
#define MAY_WRITE 2
struct file *fget_raw(unsigned int);
ssize_t vfs_read(struct file *,char *,size_t,loff_t *);
ssize_t vfs_write(struct file *,const char *,size_t,loff_t *);
loff_t vfs_llseek(struct file *,loff_t,int);
loff_t generic_file_llseek_size(struct file *,loff_t,int,loff_t,loff_t);
int rw_verify_area(int,struct file *,const loff_t *,size_t);
int fsnotify_file_area_perm(struct file *,int,const loff_t *,size_t);
long linux_read(unsigned int,char *,size_t);
long linux_write(unsigned int,const char *,size_t);
long linux_lseek(unsigned int,off_t,unsigned int);
#define FMODE_WRITE 2u
#define FMODE_PREAD 8u
#define FMODE_PWRITE 16u
#define O_LARGEFILE 0x20000
#define MAX_NON_LFS INT32_MAX
#define EPERM 1
#define ATTR_MTIME 32u
#define ATTR_CTIME 64u
struct fsnotify_sb_info;
/* Reviewed inode, superblock, mount, page-cache and clock projections (types below). */
struct timespec64 {int64_t tv_sec;int64_t tv_nsec;};
typedef struct {int64_t counter;} atomic64_t;
typedef unsigned int gfp_t;
struct list_head {struct list_head *next,*prev;};
struct hlist_node {struct hlist_node *next,**pprev;};
struct folio;
struct xarray {int xa_lock;unsigned int xa_flags;struct folio *xa_head;};
struct address_space_operations;
struct address_space {struct inode *host;struct xarray i_pages;unsigned int gfp_mask;atomic_t i_mmap_writable;uint64_t nrpages;const struct address_space_operations *a_ops;};
struct super_operations;
struct inode_operations;
struct user_namespace;
/* s_fsnotify_info is NULL while no fsnotify mark was ever added on the superblock. */
struct backing_dev_info;
/* Freeze protection (include/linux/fs.h, percpu-rwsem.h, rcu_sync.h): one percpu_rw_semaphore per freeze level,
 * read-held by writers. read_count is a per-CPU pointer to this CPU's copy (sb_read_count); the wait queues and
 * the lock map are left out (the slow paths, which use them, fault). */
struct rcu_sync {int gp_state;};
struct rcuwait {struct task_struct *task;};
struct percpu_rw_semaphore {struct rcu_sync rss;unsigned int *read_count;struct rcuwait writer;};
enum {SB_UNFROZEN = 0,SB_FREEZE_WRITE	= 1,SB_FREEZE_PAGEFAULT = 2,SB_FREEZE_FS = 3,SB_FREEZE_COMPLETE = 4};
#define SB_FREEZE_LEVELS (SB_FREEZE_COMPLETE - 1)
struct sb_writers {unsigned short frozen;struct percpu_rw_semaphore rw_sem[SB_FREEZE_LEVELS];};
struct super_block {struct sb_writers s_writers;struct fsnotify_sb_info *s_fsnotify_info;uint64_t s_flags;uint32_t s_time_gran;int64_t s_time_min,s_time_max;struct user_namespace *s_user_ns;const struct super_operations *s_op;int64_t s_maxbytes;struct backing_dev_info *s_bdi;int s_readonly_remount;};
/* The shmem_inode_info enclosing a shmem inode, as the model's inode member. */
struct shmem_inode_info {uint32_t seals;struct list_head shrinklist;uint64_t flags;int64_t alloced,swapped;uint64_t fallocend;int lock;};
typedef struct {int64_t counter;} atomic_long_t;
/* include/linux/rwsem.h without lockdep, the wait list (only the contended slow paths, which fault, use it)
 * and the optimistic-spinning lock; owner holds the writer task (rwsem_set_owner/rwsem_clear_owner). */
struct rw_semaphore {atomic_long_t count;atomic_long_t owner;};
struct inode {uint32_t i_mode,append;struct super_block *i_sb;uint32_t i_flags;kuid_t i_uid;kgid_t i_gid;int64_t i_size;struct timespec64 __i_atime,__i_mtime,__i_ctime;atomic64_t i_version;uint64_t i_state;int i_lock;struct hlist_node i_hash;uint64_t dirtied_when,dirtied_time_when;const struct inode_operations *i_op;struct address_space *i_mapping;struct address_space i_data;struct rw_semaphore i_rwsem;struct shmem_inode_info osrec_shmem;struct file_lock_context *i_flctx;};
/* i_flctx is NULL: no file lock or lease was ever set on the inode. */
struct file_lock_context {struct list_head flc_lease;struct list_head flc_posix;};
/* include/linux/filelock.h: the file_lock members locks_remove_posix sets. It
 * builds one only when the inode holds POSIX locks, which the model's never do. */
struct file_lock_operations {int fl_release_private;};
struct lock_manager_operations;
struct file_lock_core {int flc_type;unsigned int flc_flags;fl_owner_t flc_owner;int flc_pid;struct file *flc_file;};
struct file_lock {struct file_lock_core c;loff_t fl_start,fl_end;const struct file_lock_operations *fl_ops;const struct lock_manager_operations *fl_lmops;};
#define F_UNLCK 2
#define FL_POSIX 1
#define FL_CLOSE 64
#define OFFSET_MAX INT64_MAX
void locks_init_lock(struct file_lock *);
int vfs_lock_file(struct file *,unsigned int,struct file_lock *,struct file_lock *);
void osrec_fl_release_private(const struct file_lock_operations *,struct file_lock *);
/* A tracepoint whose static key is off (no tracer attached). */
#define trace_locks_remove_posix(inode,fl,ret) ((void)(inode),(void)(fl),(void)(ret))
/* fs/notify/dnotify: dnotify_flush looks for a mark only on directories. */
struct fsnotify_group;
struct kmem_cache;
struct fsnotify_mark {int lock;};
struct dnotify_struct {struct dnotify_struct *dn_next;uint32_t dn_mask;int dn_fd;struct file *dn_filp;fl_owner_t dn_owner;};
struct dnotify_mark {struct fsnotify_mark fsn_mark;struct dnotify_struct *dn;};
/* dnotify.c's group and cache; no directory is open, so neither is used. */
#define dnotify_group ((struct fsnotify_group *)0)
#define dnotify_struct_cache ((struct kmem_cache *)0)
struct fsnotify_mark *fsnotify_find_inode_mark(struct inode *,struct fsnotify_group *);
void fsnotify_group_lock(struct fsnotify_group *);
void fsnotify_group_unlock(struct fsnotify_group *);
void kmem_cache_free(struct kmem_cache *,void *);
void dnotify_recalc_inode_mask(struct fsnotify_mark *);
void fsnotify_detach_mark(struct fsnotify_mark *);
void fsnotify_free_mark(struct fsnotify_mark *);
void fsnotify_put_mark(struct fsnotify_mark *);
#define container_of(ptr,type,member) ((type *)(void *)((char *)(ptr)-offsetof(type,member)))
/* d_flags and d_sb are read only on fsnotify paths a watched superblock enables. */
struct dentry {struct inode *d_inode;unsigned int d_flags;struct super_block *d_sb;};
#define S_ISREG(mode) (((mode)&0170000)==0100000)
#define IS_APPEND(inode) ((inode)->append)
struct inode *file_inode(const struct file *);
struct mnt_idmap;
int do_truncate(struct mnt_idmap *,struct dentry *,loff_t,unsigned int,struct file *);
long linux_ftruncate(unsigned int,off_t);
long linux_pread64(unsigned int,char *,size_t,loff_t);
long linux_pwrite64(unsigned int,const char *,size_t,loff_t);
bool close_on_exec(unsigned int,struct files_struct *);
void set_close_on_exec(unsigned int,int);
bool get_close_on_exec(unsigned int);
int f_dupfd(unsigned int,struct file *,unsigned);
long linux_fcntl(unsigned int,unsigned int,unsigned long);
/* Original fcntl entry and do_fcntl (fs/fcntl.c). Command values are
 * include/uapi/asm-generic/fcntl.h and include/uapi/linux/fcntl.h. */
#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#define F_GETLK 5
#define F_SETLK 6
#define F_SETLKW 7
#define F_SETOWN 8
#define F_GETOWN 9
#define F_SETSIG 10
#define F_GETSIG 11
#define F_SETOWN_EX 15
#define F_GETOWN_EX 16
#define F_GETOWNER_UIDS 17
#define F_OFD_GETLK 36
#define F_OFD_SETLK 37
#define F_OFD_SETLKW 38
#define F_LINUX_SPECIFIC_BASE 1024
#define F_SETLEASE (F_LINUX_SPECIFIC_BASE+0)
#define F_GETLEASE (F_LINUX_SPECIFIC_BASE+1)
#define F_NOTIFY (F_LINUX_SPECIFIC_BASE+2)
#define F_DUPFD_QUERY (F_LINUX_SPECIFIC_BASE+3)
#define F_DUPFD_CLOEXEC (F_LINUX_SPECIFIC_BASE+6)
#define F_SETPIPE_SZ (F_LINUX_SPECIFIC_BASE+7)
#define F_GETPIPE_SZ (F_LINUX_SPECIFIC_BASE+8)
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE+9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE+10)
#define F_GET_RW_HINT (F_LINUX_SPECIFIC_BASE+11)
#define F_SET_RW_HINT (F_LINUX_SPECIFIC_BASE+12)
#define FD_CLOEXEC 1
#define FMODE_PATH (1u<<14)
#define _NSIG 64
#define fallthrough __attribute__((__fallthrough__))
#define force_successful_syscall_return() ((void)0)
typedef int pid_t;
struct flock {short l_type;short l_whence;long l_start;long l_len;int l_pid;};
#define FDPUT_FPUT 1
#define FDPUT_POS_UNLOCK 2
int valid_signal(unsigned long);
/* include/linux/uaccess.h's copy_from_user (arm64 INLINE_COPY_FROM_USER) and thread_info.h's check_copy_size are
 * original; without HARDENED_USERCOPY check_object_size is empty, and an overflowing size faults. */
#define __must_check
#define INT_MAX ((int)(~0U >> 1))
#define check_object_size(ptr,n,to_user) ((void)0)
void copy_overflow(int,unsigned long);
void __bad_copy_from(void);
void __bad_copy_to(void);
unsigned long copy_to_user(void *,const void *,unsigned long);
long f_dupfd_query(int,struct file *);
int setfl(int,struct file *,unsigned int);
int fcntl_getlk(struct file *,unsigned int,struct flock *);
int fcntl_setlk(unsigned int,struct file *,unsigned int,struct flock *);
pid_t f_getown(struct file *);
int f_setown(struct file *,int,int);
int f_getown_ex(struct file *,unsigned long);
int f_setown_ex(struct file *,unsigned long);
int f_getowner_uids(struct file *,unsigned long);
int fcntl_getlease(struct file *);
int fcntl_setlease(unsigned int,struct file *,int);
int fcntl_dirnotify(int,struct file *,unsigned int);
long pipe_fcntl(struct file *,unsigned int,unsigned int);
long memfd_fcntl(struct file *,unsigned int,unsigned int);
long fcntl_get_rw_hint(struct file *,unsigned int,unsigned long);
long fcntl_set_rw_hint(struct file *,unsigned int,unsigned long);
/* Original vfs_read/vfs_write, fdget_pos and their header helpers. */
typedef uint32_t __u32;
typedef int32_t __s32;
typedef uint16_t u16;
#define FMODE_READ 1u
#define FMODE_ATOMIC_POS (1u<<15)
#define FMODE_CAN_READ (1u<<17)
#define FMODE_CAN_WRITE (1u<<18)
#define FMODE_NONOTIFY (1u<<26)
#define MAX_RW_COUNT (INT32_MAX & ~4095)
#define EIOCBQUEUED 529
#define WARN_ON(v) linux_assert(v)
#define READ_ONCE(x) (x)
#define file_count(x) ((x)->f_count)
/* Live f_mode of the console and of the memfd (alloc_file_pseudo sets no FMODE_ATOMIC_POS). */
#define CONSOLE_MODE (FMODE_READ|FMODE_WRITE|FMODE_CAN_READ|FMODE_CAN_WRITE)
#define REGULAR_MODE (31u|FMODE_CAN_READ|FMODE_CAN_WRITE)
/* The operation-table members the retained code tests; osrec_class selects the callee. */
struct file_operations {uint32_t osrec_class;int read,read_iter,write,write_iter,iterate_shared;uint32_t fop_flags;int flush;};
int osrec_f_op_flush(const struct file_operations *,struct file *,fl_owner_t);
/* include/linux/bug.h without CONFIG_BUG_ON_DATA_CORRUPTION: a detected corruption WARNs (a model fault here) and is returned. */
#define CHECK_DATA_CORRUPTION(condition,...) linux_assert(condition)
struct kiocb {struct file *ki_filp;loff_t ki_pos;int ki_flags;u16 ki_ioprio;};
enum iter_type {ITER_UBUF,ITER_IOVEC,ITER_BVEC,ITER_KVEC,ITER_XARRAY,ITER_DISCARD};
#define ITER_SOURCE 1
#define ITER_DEST 0
struct iovec {void *iov_base;size_t iov_len;};
struct bio_vec {size_t bv_len;};
/* Linux's layout: __ubuf_iovec overlays ubuf and count. */
struct iov_iter {uint8_t iter_type;bool nofault;bool data_source;size_t iov_offset;union {struct iovec __ubuf_iovec;struct {union {const struct iovec *__iov;const struct bio_vec *bvec;void *ubuf;};size_t count;};};union {unsigned long nr_segs;};};
#define atomic_long_read(v) ((v)->counter)
enum fsnotify_group_prio {FSNOTIFY_PRIO_NORMAL,FSNOTIFY_PRIO_CONTENT,FSNOTIFY_PRIO_PRE_CONTENT,__FSNOTIFY_PRIO_NUM};
struct fsnotify_sb_info {atomic_long_t watched_objects[__FSNOTIFY_PRIO_NUM];};
#define CONFIG_FSNOTIFY 1
#define FS_ACCESS 0x00000001
#define FS_MODIFY 0x00000002
#define FS_OPEN_PERM 0x00010000
#define FS_ACCESS_PERM 0x00020000
#define FS_OPEN_EXEC_PERM 0x00040000
#define ALL_FSNOTIFY_PERM_EVENTS (FS_OPEN_PERM | FS_ACCESS_PERM | FS_OPEN_EXEC_PERM)
#define FS_ISDIR 0x40000000
#define FSNOTIFY_EVENT_PATH 1
#define S_ISDIR(mode) (((mode)&0170000)==0040000)
#define DCACHE_FSNOTIFY_PARENT_WATCHED (1u<<14)
#define IS_ROOT(x) linux_dentry_is_root(x)
int linux_dentry_is_root(const struct dentry *);
int __fsnotify_parent(struct dentry *,__u32,const void *,int);
int fsnotify(__u32,const void *,int,struct inode *,const void *,struct inode *,uint32_t);
int get_current_ioprio(void);
void mutex_lock(int *);
void mutex_unlock(int *);
ssize_t osrec_f_op_read(const struct file_operations *,struct file *,char *,size_t,loff_t *);
ssize_t osrec_f_op_read_iter(const struct file_operations *,struct kiocb *,struct iov_iter *);
ssize_t osrec_f_op_write(const struct file_operations *,struct file *,const char *,size_t,loff_t *);
ssize_t osrec_f_op_write_iter(const struct file_operations *,struct kiocb *,struct iov_iter *);
ssize_t shmem_file_read_iter(struct kiocb *,struct iov_iter *);
ssize_t shmem_file_write_iter(struct kiocb *,struct iov_iter *);
/* Original shmem read path, page-cache lookup and atime/ctime/mtime updates. */
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint64_t pgoff_t;
typedef unsigned int vm_fault_t;
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL<<PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE-1))
#define MAX_LFS_FILESIZE INT64_MAX
#define NSEC_PER_SEC 1000000000L
#define EIO 5
#define EFBIG 27
#define ENOENT 2
#define EEXIST 17
#define EROFS 30
#define ENOSPC 28
#define MAX_ERRNO 4095
#define IS_ENABLED(option) (option)
#define __always_inline inline
#define atomic_read(v) ((v)->counter)
#define atomic64_read(v) ((v)->counter)
#define CONFIG_XARRAY_MULTI 1
#define CONFIG_BASE_SMALL 0
#define min(a,b) __extension__({__typeof__(a) osrec_a=(a);__typeof__(b) osrec_b=(b);osrec_a<osrec_b ? osrec_a : osrec_b;})
#define max(a,b) __extension__({__typeof__(a) osrec_a=(a);__typeof__(b) osrec_b=(b);osrec_a>osrec_b ? osrec_a : osrec_b;})
#define clamp(v,lo,hi) min(max(v,lo),hi)
#define WARN(cond,...) linux_assert(cond)
#define BUILD_BUG_ON(cond) _Static_assert(!(cond),"build bug")
#define VM_BUG_ON_FOLIO(cond,folio) ((void)linux_assert(cond))
#define XA_NODE_BUG_ON(node,cond) ((void)linux_assert(cond))
#define might_sleep() ((void)0)
#define smp_mb() ((void)0)
#define smp_load_acquire(p) (*(p))
#define rcu_dereference_check(p,c) (p)
#define lockdep_is_held(l) 1
#define trace_writeback_mark_inode_dirty(i,f) ((void)0)
#define trace_writeback_dirty_inode_start(i,f) ((void)0)
#define trace_writeback_dirty_inode(i,f) ((void)0)
#define trace_writeback_dirty_inode_enqueue(i) ((void)0)
#define O_NOATIME 01000000
#define S_ISBLK(mode) (((mode)&0170000)==0060000)
/* inode->i_flags */
#define S_NOATIME (1u<<1)
#define S_IMMUTABLE (1u<<3)
#define S_NOCMTIME (1u<<7)
#define S_SWAPFILE (1u<<8)
#define S_NOSEC (1u<<12)
#define S_PRIVATE (1u<<9)
#define IS_PRIVATE(inode) ((inode)->i_flags & S_PRIVATE)
enum {S_ATIME=1,S_MTIME=2,S_CTIME=4,S_VERSION=8};
/* inode->i_state */
#define I_DIRTY_SYNC (1<<0)
#define I_DIRTY_DATASYNC (1<<1)
#define I_DIRTY_PAGES (1<<2)
#define I_FREEING (1<<5)
#define I_DIRTY_TIME (1<<11)
#define I_SYNC_QUEUED (1<<17)
#define I_DIRTY_INODE (I_DIRTY_SYNC | I_DIRTY_DATASYNC)
#define I_DIRTY (I_DIRTY_INODE | I_DIRTY_PAGES)
/* super_block->s_flags */
#define SB_RDONLY (1UL<<0)
#define SB_NOATIME (1UL<<10)
#define SB_NODIRATIME (1UL<<11)
#define SB_I_VERSION (1UL<<23)
#define SB_LAZYTIME (1UL<<25)
#define __IS_FLG(inode,flg) ((inode)->i_sb->s_flags & (flg))
#define IS_NOATIME(inode) __IS_FLG(inode, SB_RDONLY|SB_NOATIME)
#define IS_I_VERSION(inode) __IS_FLG(inode, SB_I_VERSION)
/* vfsmount->mnt_flags */
#define MNT_NOATIME 0x08
#define MNT_NODIRATIME 0x10
#define MNT_RELATIME 0x20
#define MNT_READONLY 0x40
#define I_VERSION_QUERIED 1ULL
#define I_VERSION_INCREMENT 2ULL
/* The identity mapping's maps are never read (make_vfsuid returns before them). */
struct mnt_idmap {struct uid_gid_map uid_map,gid_map;};
struct vfsmount {int mnt_flags;struct mnt_idmap *mnt_idmap;struct super_block *mnt_sb;};
/* fs/mount.h: the mount around a vfsmount, with the fields mnt_get_write_access uses. mnt_pcp is a per-CPU
 * pointer; the slice runs on one CPU and holds that CPU's copy, so this_cpu_inc/dec act on it directly. */
struct mnt_pcp {int mnt_count;int mnt_writers;};
struct mount {struct mnt_pcp *mnt_pcp;struct vfsmount mnt;};
#define MNT_WRITE_HOLD	0x200
#define CONFIG_PREEMPT_RT 0 /* not set in the live kernel */
#define this_cpu_inc(pcp) ((void)++(pcp))
#define this_cpu_dec(pcp) ((void)--(pcp))
#define might_lock(lock) ((void)0)
#define cpu_relax() ((void)0)
void lock_mount_hash(void);
/* cond_resched (include/linux/sched.h, PREEMPT_NONE): without DEBUG_ATOMIC_SLEEP and LIVEPATCH, __might_resched and
 * klp_sched_try_switch are empty. rcu_data (kernel/rcu/tree.h) is per-CPU: the slice holds this CPU's copy with the
 * fields rcu_all_qs reads, so the per-CPU accessors act on it directly. */
#define cond_resched() ({			\
	__might_resched(__FILE__, __LINE__, 0);	\
	_cond_resched();			\
})
#define __might_resched(file,line,offsets) ((void)0)
#define klp_sched_try_switch() ((void)0)
#define current_thread_info() (&current->thread_info)
struct rcu_data {bool rcu_need_heavy_qs;bool rcu_urgent_qs;};
extern struct rcu_data rcu_data;
#define raw_cpu_read(pcp) (pcp)
#define this_cpu_write(pcp,val) ((void)((pcp)=(val)))
#define local_irq_save(flags) ((void)((flags)=0))
#define local_irq_restore(flags) ((void)(flags))
void preempt_schedule_common(void);
void rcu_momentary_dyntick_idle(void);
void rcu_qs(void);
#define rwsem_acquire_read(l,s,t,i) ((void)0)
#define RCU_LOCKDEP_WARN(c,s) ((void)0)
bool __percpu_down_read(struct percpu_rw_semaphore *,bool);
void rcuwait_wake_up(struct rcuwait *);
/* real_mount (fs/mount.h) is container_of(mnt, struct mount, mnt); every file's vfsmount is the one slice mount's. */
struct mount *real_mount(struct vfsmount *);
void unlock_mount_hash(void);
typedef struct {uint32_t val;} vfsuid_t;
typedef struct {uint32_t val;} vfsgid_t;
#define VFSUIDT_INIT(value) (vfsuid_t){ __kuid_val(value) }
#define VFSGIDT_INIT(value) (vfsgid_t){ __kgid_val(value) }
#define VFSUIDT_INIT_RAW(value) (vfsuid_t){ value }
#define VFSGIDT_INIT_RAW(value) (vfsgid_t){ value }
#define INVALID_VFSUID VFSUIDT_INIT_RAW((uint32_t)-1)
#define INVALID_VFSGID VFSGIDT_INIT_RAW((uint32_t)-1)
/* The initial user namespace and the identity mount mapping are the model's own objects. */
#define init_user_ns user_ns
extern struct mnt_idmap nop_mnt_idmap;
extern struct user_namespace user_ns;
uint32_t map_id_down(const void *,uint32_t);
/* Operation tables: the members the retained code tests; osrec_class selects the callee. */
struct inode_operations {uint32_t osrec_class;int update_time,setattr;};
struct super_operations {uint32_t osrec_class;int dirty_inode;};
struct address_space_operations {uint32_t osrec_class;int dirty_folio,write_begin,write_end;};
#define shmem_aops aops_pool[1]
extern struct address_space_operations aops_pool[2];
int osrec_i_op_update_time(const struct inode_operations *,struct inode *,int);
void osrec_s_op_dirty_inode(const struct super_operations *,struct inode *,int);
/* Coarse clock: tk_core holds the coarse real time the vDSO data page publishes. */
typedef struct {uint32_t sequence;} seqcount_raw_spinlock_t;
struct tk_read_base {uint64_t xtime_nsec;uint32_t shift;};
struct timekeeper {struct tk_read_base tkr_mono;int64_t xtime_sec;};
struct tk_core_model {seqcount_raw_spinlock_t seq;struct timekeeper timekeeper;};
extern struct tk_core_model tk_core;
unsigned int read_seqcount_begin(const seqcount_raw_spinlock_t *);
int read_seqcount_retry(const seqcount_raw_spinlock_t *,unsigned int);
/* Writeback association of a dirtied inode (not modeled beyond its lock discipline). */
#define BDI_CAP_WRITEBACK (1u<<0)
struct bdi_writeback {int list_lock;struct backing_dev_info *bdi;struct list_head b_dirty,b_dirty_time;int dirty_exceeded;};
struct backing_dev_info {unsigned int capabilities;struct bdi_writeback wb;};
void inode_attach_wb(struct inode *,struct folio *);
struct bdi_writeback *locked_inode_to_wb_and_lock_list(struct inode *);
bool inode_io_list_move_locked(struct inode *,struct bdi_writeback *,struct list_head *);
void wb_wakeup_delayed(struct bdi_writeback *);
unsigned long linux_jiffies(void);
#define jiffies linux_jiffies()
/* xarray */
#define XA_CHUNK_SHIFT (IS_ENABLED(CONFIG_BASE_SMALL) ? 4 : 6)
#define XA_CHUNK_SIZE (1UL << XA_CHUNK_SHIFT)
#define XA_CHUNK_MASK (XA_CHUNK_SIZE - 1)
struct xa_node {unsigned char shift,offset,count,nr_values;struct xa_node *parent;struct xarray *array;void *slots[XA_CHUNK_SIZE];};
struct xa_state {struct xarray *xa;unsigned long xa_index;unsigned char xa_shift,xa_sibs,xa_offset,xa_pad;struct xa_node *xa_node,*xa_alloc;};
#define XAS_BOUNDS ((struct xa_node *)1UL)
#define XAS_RESTART ((struct xa_node *)3UL)
#define XA_STATE(name,array,index) struct xa_state name={.xa=array,.xa_index=index,.xa_shift=0,.xa_sibs=0,.xa_offset=0,.xa_pad=0,.xa_node=XAS_RESTART,.xa_alloc=NULL}
#define XA_RETRY_ENTRY xa_mk_internal(256)
#define XA_ZERO_ENTRY xa_mk_internal(257)
/* Folios: one order-0 page-cache folio of the regular file. Page flag bits are enum pageflags. */
enum pageflags {PG_locked,PG_writeback,PG_referenced,PG_uptodate,PG_dirty,PG_lru,PG_head,PG_waiters,PG_active,PG_workingset,PG_error,PG_owner_priv_1,PG_arch_1,PG_reserved,PG_private,PG_private_2,PG_mappedtodisk,PG_reclaim,PG_swapbacked,PG_unevictable,PG_mlocked,PG_arch_2,PG_arch_3};
/* Without NUMA, NUMA balancing or KASAN tags: zone bits 62-63, LRU generation 59-61, LRU refs 57-58. */
#define LRU_REFS_PGOFF 57
#define LRU_REFS_MASK (3UL << LRU_REFS_PGOFF)
#define BIT(n) (1UL << (n))
struct page {uint8_t osrec_page;};
typedef struct {uint64_t val;} swp_entry_t;
struct folio {uint64_t flags;struct address_space *mapping;uint64_t index;atomic_t _refcount;struct page page;swp_entry_t swap;atomic_t _pincount;};
#define folio_flags(folio,n) linux_folio_flags(folio)
unsigned long *linux_folio_flags(struct folio *);
#define folio_page(folio,n) (&(folio)->page + (n))
long folio_nr_pages(struct folio *);
bool test_and_set_bit_lock(long,unsigned long *);
void __folio_lock(struct folio *);
bool folio_xor_flags_has_waiters(struct folio *,unsigned long);
void folio_wake_bit(struct folio *,int);
bool folio_test_locked(struct folio *);
bool folio_test_uptodate(struct folio *);
bool folio_test_referenced(struct folio *);
void folio_set_referenced(struct folio *);
void folio_clear_referenced(struct folio *);
bool folio_test_unevictable(struct folio *);
bool folio_test_workingset(struct folio *);
void folio_set_workingset(struct folio *);
bool folio_test_active(struct folio *);
bool folio_test_lru(struct folio *);
bool folio_test_idle(struct folio *);
void folio_clear_idle(struct folio *);
void folio_activate(struct folio *);
void __lru_cache_activate_folio(struct folio *);
void workingset_activation(struct folio *);
bool lru_gen_enabled(void);
bool try_cmpxchg(unsigned long *,unsigned long *,unsigned long);
bool atomic64_try_cmpxchg(atomic64_t *,u64 *,u64);
#define PageHWPoison(page) 0
bool folio_try_get(struct folio *);
bool folio_put_testzero(struct folio *);
void __folio_put(struct folio *);
/* Highmem-free arm64: a page's kernel address is its linear-map address. */
void *kmap_local_page(struct page *);
#define kunmap_local(addr) ((void)(addr))
struct page *linux_zero_page(void);
#define ZERO_PAGE(vaddr) linux_zero_page()
size_t _copy_to_iter(const void *,size_t,struct iov_iter *);
/* include/linux/iov_iter.h steps. The iterators are always inlined, so each
 * call site's step is a constant. The closure's two steps over user addresses
 * (copy_to_user_iter, copy_from_user_iter) are named by this enumeration, and
 * the iterators call the named step directly (prepare.py's reviewed rewrites).
 * Steps over kernel addresses stay function pointers; only the iterators below
 * take them, for iterator types no system call here builds. */
typedef enum {OSREC_USTEP_COPY_TO_USER=1,OSREC_USTEP_COPY_FROM_USER} iov_ustep_f;
typedef size_t (*iov_step_f)(void *iter_base, size_t progress, size_t len, void *priv, void *priv2);
size_t iterate_bvec(struct iov_iter *,size_t,void *,void *,iov_step_f);
size_t iterate_kvec(struct iov_iter *,size_t,void *,void *,iov_step_f);
size_t iterate_xarray(struct iov_iter *,size_t,void *,void *,iov_step_f);
size_t iterate_discard(struct iov_iter *,size_t,void *,void *,iov_step_f);
/* arch/arm64 user access (CONFIG_ARM64_TAGGED_ADDR_ABI, no SW_TTBR0_PAN,
 * VA_BITS 48), include/linux/instrumented.h with KASAN/KCSAN/KMSAN off and
 * might_fault() without PROVE_LOCKING or DEBUG_ATOMIC_SLEEP. */
typedef uint8_t __u8;
typedef uint64_t __u64;
typedef int64_t __s64;
#define CONFIG_ARM64_TAGGED_ADDR_ABI 1
#define CONFIG_ALTERNATE_USER_ADDRESS_SPACE 0
#define CONFIG_MMU 1
#define PF_KTHREAD 0x00200000
#define TIF_TAGGED_ADDR 26
#define VA_BITS 48
#define TASK_SIZE_MAX (1UL << VA_BITS)
#define __untagged_addr(addr) ((__typeof__(addr))sign_extend64((u64)(addr), 55))
#define untagged_addr(addr) ({ u64 __addr = (u64)(addr); __addr &= __untagged_addr(__addr); (__typeof__(addr))__addr; })
/* __uaccess_mask_ptr's BIC of bit 55 (inline assembly in the kernel). */
static inline void *__uaccess_mask_ptr(const void *ptr){return (void *)((unsigned long)ptr & ~(1UL << 55));}
unsigned long __arch_copy_to_user(void __user *,const void *,unsigned long);
unsigned long __arch_copy_from_user(void *,const void __user *,unsigned long);
#define raw_copy_from_user(to, from, n)					\
({									\
	unsigned long __acfu_ret;					\
	uaccess_ttbr0_enable();						\
	__acfu_ret = __arch_copy_from_user((to),			\
				      __uaccess_mask_ptr(from), (n));	\
	uaccess_ttbr0_disable();					\
	__acfu_ret;							\
})
#define raw_copy_to_user(to, from, n)					\
({									\
	unsigned long __actu_ret;					\
	uaccess_ttbr0_enable();						\
	__actu_ret = __arch_copy_to_user(__uaccess_mask_ptr(to),	\
				    (from), (n));			\
	uaccess_ttbr0_disable();					\
	__actu_ret;							\
})
#define instrument_copy_to_user(to,from,n) ((void)(to),(void)(from),(void)(n))
#define instrument_copy_from_user_before(to,from,n) ((void)(to),(void)(from),(void)(n))
#define instrument_copy_from_user_after(to,from,n,left) ((void)(to),(void)(from),(void)(n),(void)(left))
#define might_fault() ((void)0)
size_t iov_iter_zero(size_t,struct iov_iter *);
struct page *compound_head(struct page *);
size_t page_size(struct page *);
void flush_dcache_page(struct page *);
/* shmem: everything below a page-cache hit or hole is a reviewed boundary. */
enum sgp_type {SGP_READ,SGP_NOALLOC,SGP_CACHE,SGP_WRITE,SGP_FALLOC};
struct mm_struct;
struct vm_area_struct {struct mm_struct *vm_mm;unsigned long vm_flags;};
struct vm_fault {struct vm_area_struct *vma;};
#define VM_UFFD_MINOR 0
#define VM_UFFD_MISSING 0
#define THP_FILE_ALLOC 0
#define userfaultfd_minor(vma) false
#define userfaultfd_missing(vma) false
vm_fault_t handle_userfault(struct vm_fault *,unsigned long);
int shmem_swapin_folio(struct inode *,pgoff_t,struct folio **,enum sgp_type,gfp_t,struct mm_struct *,vm_fault_t *);
bool shmem_is_huge(struct inode *,pgoff_t,bool,struct mm_struct *,unsigned long);
gfp_t vma_thp_gfp_mask(struct vm_area_struct *);
gfp_t limit_gfp_mask(gfp_t,gfp_t);
struct folio *shmem_alloc_and_add_folio(gfp_t,struct inode *,pgoff_t,struct mm_struct *,bool);
#define IS_ERR(ptr) linux_is_err(ptr)
/* include/linux/err.h PTR_ERR: the address as its error code. */
#define PTR_ERR(ptr) ((long)(ptr))
bool linux_is_err(const void *);
void count_vm_event(int);
bool folio_test_pmd_mappable(struct folio *);
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
struct shmem_sb_info {int shrinklist_lock;struct list_head shrinklist;unsigned long shrinklist_len;};
struct shmem_sb_info *SHMEM_SB(struct super_block *);
struct shmem_inode_info *SHMEM_I(struct inode *);
bool list_empty_careful(const struct list_head *);
void list_add_tail(struct list_head *,struct list_head *);
void clear_highpage(struct page *);
void flush_dcache_folio(struct folio *);
void folio_mark_uptodate(struct folio *);
void filemap_remove_folio(struct folio *);
/* Original shmem write path, write checks, c/mtime update and page dirtying. */
#define ETXTBSY 26
#define EAGAIN 11
#define RLIMIT_FSIZE 1
#define RLIM_INFINITY (~0UL)
#define SIGXFSZ 25
#define IOCB_HIPRI 1
#define IOCB_NOWAIT 8
#define IOCB_APPEND 16
#define IOCB_DIRECT (1 << 17)
/* include/uapi/linux/fs.h RWF flags; include/linux/fs.h's IOCB bits that kiocb_set_rw_flags maps them to. */
typedef int rwf_t;
#define RWF_HIPRI 0x1
#define RWF_DSYNC 0x2
#define RWF_SYNC 0x4
#define RWF_NOWAIT 0x8
#define RWF_APPEND 0x10
#define RWF_NOAPPEND 0x20
#define RWF_SUPPORTED (RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND | RWF_NOAPPEND)
#define IOCB_DSYNC RWF_DSYNC
#define IOCB_SYNC RWF_SYNC
#define IOCB_EVENTFD (1 << 16)
#define IOCB_NOIO (1 << 20)
#define FMODE_NOWAIT (1u << 27)
/* readv/writev (include/uapi/linux/uio.h, include/linux/uio.h, include/linux/err.h). */
#define UIO_FASTIOV 8
#define UIO_MAXIOV 1024
#define iter_iov_addr(iter)	(iter_iov(iter)->iov_base + (iter)->iov_offset)
#define iter_iov_len(iter)	(iter_iov(iter)->iov_len - (iter)->iov_offset)
#define __noclone
#define __force
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#ifndef ENOMEM
#define ENOMEM 12
#endif
/* include/linux/err.h ERR_PTR: the error code as an address in the last page. */
#define ERR_PTR(error) ((void *)(long)(error))
/* A compat (32-bit) task copies compat iovecs; the model holds 64-bit tasks (TIF_32BIT is bound). */
#define TIF_32BIT 22
bool in_compat_syscall(void);
int copy_compat_iovec_from_user(struct iovec *,const struct iovec __user *,unsigned long);
/* More than UIO_FASTIOV segments need a kmalloc'd iovec array (include/linux/slab.h; the slab block below). */
struct kmem_cache;
void kfree(const void *);
/* Without MEM_ALLOC_PROFILING the allocation hooks are the call itself (include/linux/alloc_tag.h). */
#define alloc_hooks(_do_alloc) (_do_alloc)
#define kmalloc_array(...) alloc_hooks(kmalloc_array_noprof(__VA_ARGS__))
/* kernel/locking/rwsem.c's write-lock fast paths and include/linux/rwsem.h's constants. PREEMPT_NONE without
 * DEBUG_ATOMIC_SLEEP, DEBUG_RWSEMS or lockdep: might_sleep, the lockdep annotations and the debug checks are empty,
 * and LOCK_CONTENDED takes the lock directly. Atomics are single-CPU operations on the counters. */
#define __sched
#define RWSEM_UNLOCKED_VALUE		0UL
#define RWSEM_WRITER_LOCKED		(1UL << 0)
#define RWSEM_FLAG_WAITERS	(1UL << 1)
#define TASK_UNINTERRUPTIBLE		0x00000002
#define rwsem_acquire(l,s,t,i) ((void)0)
#define rwsem_release(l,i) ((void)0)
#define lockdep_assert_preemption_disabled() ((void)0)
#define DEBUG_RWSEMS_WARN_ON(c, sem) ((void)0)
#define atomic_long_read(v) ((v)->counter)
#define atomic_long_set(v,i) ((void)((v)->counter=(i)))
#define atomic_long_try_cmpxchg_acquire(v,old,new) __extension__({__typeof__(old) osrec_old=(old);bool osrec_ok=(v)->counter==*osrec_old;if(osrec_ok)(v)->counter=(int64_t)(new);else *osrec_old=(v)->counter;osrec_ok;})
#define atomic_long_fetch_add_release(i,v) __extension__({int64_t osrec_prior=(v)->counter;(v)->counter+=(int64_t)(i);osrec_prior;})
struct rw_semaphore *rwsem_down_write_slowpath(struct rw_semaphore *,int);
struct rw_semaphore *rwsem_wake(struct rw_semaphore *);
/* SLUB's kmalloc and kfree fast paths (mm/slub.c, mm/slab.h, include/linux/slab.h), with the
 * include/linux/slab.h, instruction_pointer.h, gfp_types.h and mm/slab.h definitions they use.
 * Configuration: SLUB without SLUB_TINY, SLAB_FREELIST_HARDENED, RANDOM_KMALLOC_CACHES, NUMA, PREEMPTION,
 * SLUB_STATS, KASAN, KFENCE, KMSAN, KCSAN, kmemleak, DEBUG_OBJECTS, FAILSLAB or MEM_ALLOC_PROFILING;
 * with SLUB_DEBUG, MEMCG_KMEM and ZONE_DMA. Their hooks are the kernel's empty inline stubs.
 * Static keys the fast paths test are off: slub_debug_enabled (no slab_debug), init_on_alloc and
 * init_on_free (INIT_ON_*_DEFAULT_ON unset, no init_on_* parameter), memcg_kmem_online (no kmem-accounting
 * memory cgroup online), debug_pagealloc and the kmem tracepoints (trace_kmalloc, trace_kfree).
 * The slice holds one kmalloc cache, this CPU's kmem_cache_cpu of it, one object on its per-CPU freelist
 * and that object's slab. The slow paths (__slab_alloc, __slab_free), large kmalloc and the memcg and
 * debug branches fault. Per-CPU accessors act on this CPU's copy directly; the 128-bit freelist/tid
 * cmpxchg is a single-CPU compare and store. */
#define ZERO_SIZE_PTR ((void *)16)
#define ZERO_OR_NULL_PTR(x) ((unsigned long)(x) <= 				(unsigned long)ZERO_SIZE_PTR)
#define _RET_IP_		(unsigned long)__builtin_return_address(0)
#define trace_kfree(call_site,ptr) ((void)0)
#define trace_kmalloc(call_site,ptr,req,alloc,flags,node) ((void)0)
typedef unsigned int slab_flags_t;
typedef unsigned __int128 u128;
#define __GFP_DMA 0x01u
#define __GFP_RECLAIMABLE 0x10u
#define __GFP_ZERO 0x100u
#define __GFP_ACCOUNT 0x400000u
/* mm/mm_init.c sets gfp_allowed_mask to __GFP_BITS_MASK once boot finishes; only empty hooks consume it here. */
#define gfp_allowed_mask ((gfp_t)((1u << 26) - 1))
#define might_alloc(gfp_mask) ((void)(gfp_mask))
#define NUMA_NO_NODE (-1)
#define KMALLOC_SHIFT_HIGH (PAGE_SHIFT + 1)
#define KMALLOC_MAX_CACHE_SIZE (1UL << KMALLOC_SHIFT_HIGH)
enum kmalloc_cache_type {KMALLOC_NORMAL = 0,KMALLOC_RANDOM_START = KMALLOC_NORMAL,KMALLOC_RANDOM_END = KMALLOC_RANDOM_START + 0,KMALLOC_RECLAIM,KMALLOC_DMA,KMALLOC_CGROUP,NR_KMALLOC_TYPES};
#define KMALLOC_NOT_NORMAL_BITS (__GFP_RECLAIMABLE | __GFP_DMA | __GFP_ACCOUNT)
#define CONFIG_ZONE_DMA 1
#define CONFIG_MEMCG_KMEM 1
#define CONFIG_SLUB_DEBUG 1
#define __alloc_size(...)
#define __fastpath_inline __always_inline
#define __no_kmsan_checks
#define check_mul_overflow(a,b,d) __builtin_mul_overflow(a,b,d)
#define fls(x) ((x) ? 32 - __builtin_clz((unsigned int)(x)) : 0)
/* include/linux/slab.h flag bits for this configuration (no DEBUG_OBJECTS, FAILSLAB, KASAN_GENERIC or KFENCE). */
#define SLAB_CONSISTENCY_CHECKS ((slab_flags_t)(1U << 0))
#define SLAB_RED_ZONE ((slab_flags_t)(1U << 1))
#define SLAB_POISON ((slab_flags_t)(1U << 2))
#define SLAB_KMALLOC ((slab_flags_t)(1U << 3))
#define SLAB_STORE_USER ((slab_flags_t)(1U << 7))
#define SLAB_TYPESAFE_BY_RCU ((slab_flags_t)(1U << 9))
#define SLAB_TRACE ((slab_flags_t)(1U << 10))
#define SLAB_ACCOUNT ((slab_flags_t)(1U << 13))
#define SLAB_DEBUG_OBJECTS ((slab_flags_t)0U)
#define SLAB_DEBUG_FLAGS (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | SLAB_TRACE | SLAB_CONSISTENCY_CHECKS)
#define KCSAN_ACCESS_WRITE (1 << 0)
#define KCSAN_ACCESS_ASSERT (1 << 3)
#define VM_WARN_ON_ONCE(cond) ((void)0)
/* Static keys: all off (see above). */
#define static_branch_unlikely(key) false
#define static_branch_maybe(config,key) false
#define memcg_kmem_online() false
#define debug_pagealloc_enabled_static() false
/* Disabled sanitizers and fault injection: include/linux/kasan.h, kfence.h, kmsan.h, kmemleak.h,
 * debug_locks.h, debugobjects.h, kcsan-checks.h and fault-inject.h stubs. */
#define kasan_reset_tag(addr) ((void *)(addr))
static inline void *kasan_slab_alloc(struct kmem_cache *s,void *object,gfp_t flags,bool init){(void)s;(void)flags;(void)init;return object;}
#define kasan_kmalloc(s,object,size,flags) (object)
#define kasan_slab_free(s,object,init) false
#define kasan_has_integrated_init() false
#define kfence_alloc(s,size,flags) ((void *)0)
#define kfence_free(addr) false
static inline void kmsan_slab_alloc(struct kmem_cache *s,void *object,gfp_t flags){(void)s;(void)object;(void)flags;}
#define kmsan_slab_free(s,object) ((void)0)
static inline void kmemleak_alloc_recursive(const void *ptr,size_t size,int min_count,slab_flags_t flags,gfp_t gfp){(void)ptr;(void)size;(void)min_count;(void)flags;(void)gfp;}
#define kmemleak_free_recursive(ptr,flags) ((void)0)
#define debug_check_no_locks_freed(from,len) ((void)0)
#define debug_check_no_obj_freed(address,size) ((void)0)
#define __kcsan_check_access(ptr,size,type) ((void)0)
#define __should_failslab(s,gfpflags) false
#define alloc_tagging_slab_free_hook(s,slab,p,objects) ((void)0)
#define prefetchw(x) ((void)(x))
/* mm/slub.c: no PREEMPT_RT, so the lockless fast paths are used; TID_STEP is 1 without PREEMPTION. */
#define USE_LOCKLESS_FAST_PATH() (true)
#define TID_STEP 1
enum stat_item {ALLOC_FASTPATH,FREE_FASTPATH};
typedef struct {unsigned long v;} freeptr_t;
/* mm/slab.h: arm64 has cmpxchg128 and HAVE_ALIGNED_STRUCT_PAGE, so the freelist and tid pair is one 128-bit word. */
typedef u128 freelist_full_t;
typedef union {struct {void *freelist;unsigned long counter;};freelist_full_t full;} freelist_aba_t;
struct kmem_cache_cpu {union {struct {void **freelist;unsigned long tid;};freelist_aba_t freelist_tid;};struct slab *slab;};
/* The kmem_cache fields the fast paths read (mm/slab.h). */
struct kmem_cache {struct kmem_cache_cpu *cpu_slab;slab_flags_t flags;unsigned int size;unsigned int object_size;unsigned int offset;void (*ctor)(void *);unsigned int red_left_pad;};
/* The fields of struct slab (mm/slab.h) the fast paths read; the slice keeps a slab apart from page-cache folios. */
struct slab {unsigned long __page_flags;struct kmem_cache *slab_cache;};
#define folio_slab(folio)	(_Generic((folio),				const struct folio *:	(const struct slab *)(folio),			struct folio *:		(struct slab *)(folio)))
#define raw_cpu_ptr(p) (p)
/* A compiler barrier orders nothing on the slice's one CPU (the other barriers here are no-ops too). */
#define barrier() ((void)0)
#define this_cpu_try_cmpxchg_freelist(pcp,ovalp,nval) __extension__({freelist_full_t *osrec_old=(ovalp);bool osrec_ok=(pcp)==*osrec_old;if(osrec_ok)(pcp)=(nval);else *osrec_old=(pcp);osrec_ok;})
struct list_lru;
struct slabobj_ext;
/* include/linux/slab.h globals and the slice's two caches: kmalloc-192 (writev's iovec array) and kmalloc-96 (a
 * task's pi_state), each with its per-CPU state, the object on that CPU's freelist and the object's slab (a live
 * binding supplies each). */
#define OSREC_KMALLOC_OBJECT_WORDS 24
struct kmalloc_object {uint64_t words[OSREC_KMALLOC_OBJECT_WORDS];};
#define OSREC_KMALLOC96_OBJECT_WORDS 12
struct kmalloc96_object {uint64_t words[OSREC_KMALLOC96_OBJECT_WORDS];};
extern struct kmem_cache kmalloc96_cache;
extern struct kmem_cache_cpu kmalloc96_cpu;
extern struct kmalloc96_object kmalloc96_object;
extern struct slab kmalloc96_object_slab;
/* include/linux/slab.h on arm64: ARCH_KMALLOC_MINALIGN is 8, so the smallest cache is kmalloc-8 and kmalloc-96 exists.
 * __kmalloc_index ends in BUILD_BUG_ON_MSG for a constant size no cache fits, a build failure the kernel's constant
 * folding removes for every valid size; reaching it here faults. */
#define CONFIG_PROFILE_ALL_BRANCHES 0
#define KMALLOC_SHIFT_LOW 3
#define KMALLOC_MIN_SIZE (1 << KMALLOC_SHIFT_LOW)
#define BUILD_BUG_ON_MSG(cond,msg) ((void)linux_assert(cond))
#define kmalloc_index(s) __kmalloc_index(s, true)
#define kzalloc(...) kzalloc_noprof(__VA_ARGS__)
extern struct kmem_cache *kmalloc_caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIGH + 1];
extern uint8_t kmalloc_size_index[24];
extern struct kmem_cache kmalloc_cache;
extern struct kmem_cache_cpu kmalloc_cpu;
extern struct kmalloc_object kmalloc_object;
extern struct slab kmalloc_object_slab;
void *kmalloc_large_noprof(size_t,gfp_t);
void *__kmalloc_large_node(size_t,gfp_t,int);
unsigned int get_order(unsigned long);
void *__slab_alloc(struct kmem_cache *,gfp_t,int,unsigned long,struct kmem_cache_cpu *,unsigned int);
void __slab_free(struct kmem_cache *,struct slab *,void *,void *,int,unsigned long);
void note_cmpxchg_failure(const char *,const struct kmem_cache *,unsigned long);
bool __memcg_slab_post_alloc_hook(struct kmem_cache *,struct list_lru *,gfp_t,size_t,void **);
void memcg_alloc_abort_single(struct kmem_cache *,void *);
void kmem_cache_free_bulk(struct kmem_cache *,size_t,void **);
struct slabobj_ext *slab_obj_exts(struct slab *);
void __memcg_slab_free_hook(struct kmem_cache *,struct slab *,void **,int,struct slabobj_ext *);
bool freeptr_outside_object(struct kmem_cache *);
long copy_from_kernel_nofault(void *,const void *,size_t);
unsigned int get_info_end(struct kmem_cache *);
unsigned int get_orig_size(struct kmem_cache *,void *);
void set_orig_size(struct kmem_cache *,void *,unsigned int);
#define local_lock(lock) ((void)0)
#define local_unlock(lock) ((void)0)
struct folio *virt_to_folio(const void *);
void free_large_kmalloc(struct folio *,void *);
/* System calls here build only user-backed (ubuf and iovec) iterators. */
void iov_iter_bvec_advance(struct iov_iter *,size_t);
#define FOP_BUFFER_WASYNC (1u << 1)
#define FMODE_WRITER (1u<<16)
#define F_SEAL_SEAL 0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW 0x0004
#define F_SEAL_WRITE 0x0008
#define F_SEAL_FUTURE_WRITE 0x0010
#define SB_NOSEC (1UL<<28)
#define IS_NOSEC(inode) ((inode)->i_flags & S_NOSEC)
#define IS_SWAPFILE(inode) ((inode)->i_flags & S_SWAPFILE)
#define IS_NOCMTIME(inode) ((inode)->i_flags & S_NOCMTIME)
#define sb_rdonly(sb) ((sb)->s_flags & SB_RDONLY)
#define smp_store_release(p,v) (*(p)=(v))
#define min_t(type,a,b) min((type)(a),(type)(b))
#define PAGE_ALIGN(addr) (((addr)+PAGE_SIZE-1)&PAGE_MASK)
#define PAGE_ALIGNED(addr) (!((unsigned long)(addr)&(PAGE_SIZE-1)))
#define PAGE_MAPPING_FLAGS 0x3
#define PG_dcache_clean PG_arch_1
#define GFP_KERNEL 0xcc0
#define BUG() ((void)linux_assert(1))
#define preempt_disable() ((void)0)
#define preempt_enable() ((void)0)
#define user_read_access_begin(ptr,len) access_ok(ptr,len)
#define user_read_access_end() ((void)0)
/* include/linux/uaccess.h's generic fallbacks (arm64 defines no user_access_begin): user_access_begin is
 * access_ok, user_access_end does nothing and unsafe_get_user is __get_user with a jump to the fault
 * label. __get_user reads an admitted user object (linux_get_user). */
#define user_access_begin(ptr,len) access_ok(ptr,len)
#define user_access_end() ((void)0)
#define unsafe_get_user(x,ptr,label) do {_Static_assert(sizeof(x)==sizeof(*(ptr)),"unsafe_get_user width");if(linux_get_user((void *)&(x),(const void *)(ptr),sizeof(*(ptr))))goto label;} while(0)
int linux_get_user(void *,const void *,unsigned long);
int fatal_signal_pending(struct task_struct *);
void send_sig(int,struct task_struct *,int);
#define kmap_atomic(page) kmap_local_page(page)
#define kunmap_atomic(addr) ((void)(addr))
#define PageHighMem(page) 0
#define page_folio(page) linux_page_folio(page)
struct folio *linux_page_folio(struct page *);
size_t folio_size(struct folio *);
size_t offset_in_folio(struct folio *,loff_t);
void folio_zero_segments(struct folio *,size_t,size_t,size_t,size_t);
bool folio_test_dirty(struct folio *);
bool folio_test_set_dirty(struct folio *);
bool folio_test_reclaim(struct folio *);
void folio_clear_reclaim(struct folio *);
bool folio_test_slab(struct folio *);
bool folio_test_swapcache(struct folio *);
struct address_space *swap_address_space(swp_entry_t);
#define noop_backing_dev_info noop_bdi
extern struct backing_dev_info noop_bdi;
bool test_bit(long,const unsigned long *);
void clear_bit(long,unsigned long *);
int dentry_needs_remove_privs(struct mnt_idmap *,struct dentry *);
int __remove_privs(struct mnt_idmap *,struct dentry *,int);
void inode_has_no_xattr(struct inode *);
int osrec_a_ops_write_begin(const struct address_space_operations *,struct file *,struct address_space *,loff_t,unsigned,struct page **,void **);
int osrec_a_ops_write_end(const struct address_space_operations *,struct file *,struct address_space *,loff_t,unsigned,unsigned,struct page *,void *);
bool osrec_a_ops_dirty_folio(const struct address_space_operations *,struct address_space *,struct folio *);
int shmem_write_begin(struct file *,struct address_space *,loff_t,unsigned,struct page **,void **);
int shmem_write_end(struct file *,struct address_space *,loff_t,unsigned,unsigned,struct page *,void *);
bool noop_dirty_folio(struct address_space *,struct folio *);
/* Dirty throttling: only reached for a bdi that writes back. */
bool inode_cgwb_enabled(struct inode *);
struct bdi_writeback *wb_get_create_current(struct backing_dev_info *,unsigned int);
#define this_cpu_ptr(p) (p)
extern int bdp_ratelimits,dirty_throttle_leaks;
extern int ratelimit_pages;
int balance_dirty_pages(struct bdi_writeback *,unsigned long,unsigned int);
void wb_put(struct bdi_writeback *);
/* Original truncation: do_truncate, notify_change, shmem_setattr and the page-cache undo. */
typedef uint16_t umode_t;
#define ATTR_MODE (1 << 0)
#define ATTR_UID (1 << 1)
#define ATTR_GID (1 << 2)
#define ATTR_SIZE (1 << 3)
#define ATTR_ATIME (1 << 4)
#define ATTR_ATIME_SET (1 << 7)
#define ATTR_MTIME_SET (1 << 8)
#define ATTR_FORCE (1 << 9)
#define ATTR_KILL_SUID (1 << 11)
#define ATTR_KILL_SGID (1 << 12)
#define ATTR_FILE (1 << 13)
#define ATTR_KILL_PRIV (1 << 14)
#define ATTR_TIMES_SET (1 << 16)
#define ATTR_TOUCH (1 << 17)
#define ATTR_DELEG (1 << 18)
struct iattr {unsigned int ia_valid;umode_t ia_mode;union {kuid_t ia_uid;vfsuid_t ia_vfsuid;};union {kgid_t ia_gid;vfsgid_t ia_vfsgid;};loff_t ia_size;struct timespec64 ia_atime,ia_mtime,ia_ctime;struct file *ia_file;};
#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISLNK(mode) (((mode)&0170000)==0120000)
#define IS_IMMUTABLE(inode) ((inode)->i_flags & S_IMMUTABLE)
#define EOPNOTSUPP 95
#define EWOULDBLOCK EAGAIN
#define O_WRONLY 01
#define O_NONBLOCK 04000
#define FL_DELEG 4
#define FS_ATTRIB 0x00000004
#define FSNOTIFY_EVENT_DENTRY 3
#define F_SEAL_EXEC 0x0020
#define VM_NORESERVE 0x00200000
#define VM_ACCT(size) (PAGE_ALIGN(size) >> PAGE_SHIFT)
#define round_up(x,y) ((((x)-1) | ((__typeof__(x))((y)-1)))+1)
#define PAGEVEC_SIZE 31
struct folio_batch {unsigned char nr,i;bool percpu_pvec_drained;struct folio *folios[PAGEVEC_SIZE];};
typedef unsigned int xa_mark_t;
#define XA_PRESENT 8U
#define trace_folio_wait_writeback(folio,mapping) ((void)0)
#define vfsuid_eq(left,right) (vfsuid_valid(left) && __vfsuid_val(left) == __vfsuid_val(right))
#define vfsgid_eq(left,right) (vfsgid_valid(left) && __vfsgid_val(left) == __vfsgid_val(right))
bool is_sxid(umode_t);
kuid_t from_vfsuid(struct mnt_idmap *,struct user_namespace *,vfsuid_t);
kgid_t from_vfsgid(struct mnt_idmap *,struct user_namespace *,vfsgid_t);
bool vfsuid_has_fsmapping(struct mnt_idmap *,struct user_namespace *,vfsuid_t);
bool vfsgid_has_fsmapping(struct mnt_idmap *,struct user_namespace *,vfsgid_t);
bool inode_owner_or_capable(struct mnt_idmap *,const struct inode *);
int inode_permission(struct mnt_idmap *,struct inode *,int);
bool chown_ok(struct mnt_idmap *,const struct inode *,vfsuid_t);
bool chgrp_ok(struct mnt_idmap *,const struct inode *,vfsgid_t);
bool in_group_or_capable(struct mnt_idmap *,const struct inode *,vfsgid_t);
int security_inode_need_killpriv(struct dentry *);
int security_inode_killpriv(struct mnt_idmap *,struct dentry *);
int setattr_should_drop_suidgid(struct mnt_idmap *,struct inode *);
int simple_setattr(struct mnt_idmap *,struct dentry *,struct iattr *);
int __break_lease(struct inode *,unsigned int,unsigned int);
void ihold(struct inode *);
int osrec_i_op_setattr(const struct inode_operations *,struct mnt_idmap *,struct dentry *,struct iattr *);
int shmem_setattr(struct mnt_idmap *,struct dentry *,struct iattr *);
int security_vm_enough_memory_mm(struct mm_struct *,long);
/* include/linux/lsm_hooks.h and security/security.c (v6.10): each hook's list
 * of the LSMs that registered it, built at boot and read-only after init. The
 * built LSMs are capability, integrity (IMA and EVM off) and BPF; of them only
 * BPF registers these hooks (all of them, as attachment points). */
struct hlist_head {struct hlist_node *first;};
struct lsm_id {const char *name;u64 id;};
#define LSM_ID_BPF 110
struct security_hook_list {struct hlist_node list;struct hlist_head *head;const struct lsm_id *lsmid;};
struct security_hook_heads {struct hlist_head file_permission,file_fcntl,file_truncate,inode_setattr,inode_post_setattr;};
extern const struct security_hook_heads security_hook_heads;
#define hlist_entry(ptr, type, member) container_of(ptr,type,member)
#define hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})
#define hlist_for_each_entry(pos, head, member)				\
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))
#define LSM_RET_DEFAULT(NAME) (NAME##_default)
static const int __attribute__((unused)) file_permission_default = (0);
static const int __attribute__((unused)) file_fcntl_default = (0);
static const int __attribute__((unused)) file_truncate_default = (0);
static const int __attribute__((unused)) inode_setattr_default = (0);
/* security.c's call_void_hook and call_int_hook. The kernel calls each entry's
 * function through the entry (P->hook.FUNC); here osrec_lsm_FUNC calls the
 * registering LSM's function directly. */
#define call_void_hook(FUNC, ...)				\
	do {							\
		struct security_hook_list *P;			\
								\
		hlist_for_each_entry(P, &security_hook_heads.FUNC, list) \
			osrec_lsm_##FUNC(P, __VA_ARGS__);	\
	} while (0)
#define call_int_hook(FUNC, ...) ({				\
	int RC = LSM_RET_DEFAULT(FUNC);				\
	do {							\
		struct security_hook_list *P;			\
								\
		hlist_for_each_entry(P, &security_hook_heads.FUNC, list) { \
			RC = osrec_lsm_##FUNC(P, __VA_ARGS__);	\
			if (RC != LSM_RET_DEFAULT(FUNC))	\
				break;				\
		}						\
	} while (0);						\
	RC;							\
})
/* The nop function each BPF LSM hook gets for BPF programs to attach to: none is attached (the live traces run
 * each as its four-instruction default). prepare.py expands kernel/bpf/bpf_lsm.c's LSM_HOOK over the
 * include/linux/lsm_hook_defs.h entries into the slice, so these are their declarations. */
/* The kernel calls each hook through its list entry's function pointer, which no compiler sees through; the slice
 * calls them directly, so noinline also makes them weak: an interposable definition keeps the call (no constant
 * propagation of the return value), as the kernel's indirect call does. Only these hooks use noinline. */
#define noinline __attribute__((__noinline__,__weak__))
#define LSM_RET_VOID ((void) 0)
int bpf_lsm_file_permission(struct file *file,int mask);
int bpf_lsm_file_fcntl(struct file *file,unsigned int cmd,unsigned long arg);
int bpf_lsm_file_truncate(struct file *file);
int bpf_lsm_inode_setattr(struct mnt_idmap *idmap,struct dentry *dentry,struct iattr *attr);
void bpf_lsm_inode_post_setattr(struct mnt_idmap *idmap,struct dentry *dentry,int ia_valid);
/* An entry's function is its LSM's: every entry in the table is BPF's. */
/* The dispatch for the walk's entries, all BPF defaults: macros, so the context transform renames the call. */
#define osrec_lsm_file_permission(p,...) bpf_lsm_file_permission(__VA_ARGS__)
#define osrec_lsm_file_fcntl(p,...) bpf_lsm_file_fcntl(__VA_ARGS__)
#define osrec_lsm_file_truncate(p,...) bpf_lsm_file_truncate(__VA_ARGS__)
#define osrec_lsm_inode_setattr(p,...) bpf_lsm_inode_setattr(__VA_ARGS__)
#define osrec_lsm_inode_post_setattr(p,...) bpf_lsm_inode_post_setattr(__VA_ARGS__)
void vm_unacct_memory(long);
void unmap_mapping_range(struct address_space *,loff_t,loff_t,int);
int dquot_initialize(struct inode *);
int dquot_transfer(struct mnt_idmap *,struct inode *,struct iattr *);
int posix_acl_chmod(struct mnt_idmap *,struct dentry *,umode_t);
void shmem_inode_unacct_blocks(struct inode *,long);
int shmem_free_swap(struct address_space *,pgoff_t,void *);
struct folio *xas_find_marked(struct xa_state *,unsigned long,xa_mark_t);
bool folio_test_writeback(struct folio *);
pgoff_t swapcache_index(struct folio *);
bool folio_test_large(struct folio *);
void folio_wait_bit(struct folio *,int);
loff_t folio_pos(struct folio *);
bool folio_mapped(struct folio *);
void unmap_mapping_folio(struct folio *);
bool folio_needs_release(struct folio *);
void folio_invalidate(struct folio *,size_t,size_t);
void folio_cancel_dirty(struct folio *);
void folio_clear_mappedtodisk(struct folio *);
int split_folio(struct folio *);
void __folio_batch_release(struct folio_batch *);
void zero_user_segments(struct page *,unsigned,unsigned,unsigned,unsigned);
void *memset(void *,int,size_t);
void *memcpy(void *,const void *,size_t);
/* arm64 system call entry: arch/arm64/kernel/entry-common.c and syscall.c.
 * struct pt_regs keeps the kernel's layout (orig_x0 at 272, syscallno at 280). */
#define asmlinkage
#define noinstr
struct pt_regs {
    union {struct {uint64_t regs[31];uint64_t sp;uint64_t pc;uint64_t pstate;};};
    uint64_t orig_x0;int32_t syscallno;uint32_t unused2;uint64_t sdei_ttbr1;uint64_t pmr_save;uint64_t stackframe[2];uint64_t lockdep_hardirqs;uint64_t exit_rcu;
};
/* ASM-OFFSETS BEGIN */
#define PT_REGS_SIZE 336
#define S_LR 240
#define S_SP 248
#define S_PC 256
#define S_SYSCALLNO 280
#define S_STACKFRAME 304
#define TSK_TI_FLAGS 0
#define THREAD_SCTLR_USER 104
/* Used only by alternatives that stay unpatched, cpu_switch_to and the KPTI trampoline. */
#define THREAD_KEYS_USER 0
#define THREAD_KEYS_KERNEL 0
#define THREAD_CPU_CONTEXT 0
#define PTRAUTH_USER_KEY_APIA 0
#define PTRAUTH_KERNEL_KEY_APIA 0
#define VMA_VM_MM 0
#define ARM64_FTR_SYSVAL 0
#define TRAMP_VALIAS 0
/* ASM-OFFSETS END */
_Static_assert(offsetof(struct pt_regs,regs[30])==S_LR && offsetof(struct pt_regs,sp)==S_SP && offsetof(struct pt_regs,pc)==S_PC && offsetof(struct pt_regs,syscallno)==S_SYSCALLNO && offsetof(struct pt_regs,stackframe)==S_STACKFRAME && sizeof(struct pt_regs)==PT_REGS_SIZE,"struct pt_regs layout");
_Static_assert(offsetof(struct pt_regs,orig_x0)==272,"struct pt_regs layout");
_Static_assert(offsetof(struct task_struct,thread_info.flags)==TSK_TI_FLAGS && offsetof(struct task_struct,thread.sctlr_user)==THREAD_SCTLR_USER,"task layout seen by entry.S");
#define PSR_MODE_EL0t 0x00000000
#define NO_SYSCALL (-1)
#define ENOSYS 38
#define __NR_syscalls 463
/* arch/arm64/include/asm/thread_info.h */
#define TIF_SIGPENDING		0	/* signal pending */
#define TIF_NEED_RESCHED	1	/* rescheduling necessary */
#define TIF_NOTIFY_RESUME	2	/* callback before returning to user */
#define TIF_FOREIGN_FPSTATE	3	/* CPU's FP state is not current's */
#define TIF_UPROBE		4	/* uprobe breakpoint or singlestep */
#define TIF_MTE_ASYNC_FAULT	5	/* MTE Asynchronous Tag Check Fault */
#define TIF_NOTIFY_SIGNAL	6	/* signal notifications exist */
#define TIF_SYSCALL_TRACE	8	/* syscall trace active */
#define TIF_SYSCALL_AUDIT	9	/* syscall auditing */
#define TIF_SYSCALL_TRACEPOINT	10	/* syscall tracepoint for ftrace */
#define TIF_SECCOMP		11	/* syscall secure computing */
#define TIF_SYSCALL_EMU		12	/* syscall emulation active */
#define TIF_SINGLESTEP		21
#define TIF_SVE			23	/* Scalable Vector Extension in use */
#define _TIF_SIGPENDING		(1 << TIF_SIGPENDING)
#define _TIF_NEED_RESCHED	(1 << TIF_NEED_RESCHED)
#define _TIF_NOTIFY_RESUME	(1 << TIF_NOTIFY_RESUME)
#define _TIF_FOREIGN_FPSTATE	(1 << TIF_FOREIGN_FPSTATE)
#define _TIF_UPROBE		(1 << TIF_UPROBE)
#define _TIF_MTE_ASYNC_FAULT	(1 << TIF_MTE_ASYNC_FAULT)
#define _TIF_NOTIFY_SIGNAL	(1 << TIF_NOTIFY_SIGNAL)
#define _TIF_SYSCALL_TRACE	(1 << TIF_SYSCALL_TRACE)
#define _TIF_SYSCALL_AUDIT	(1 << TIF_SYSCALL_AUDIT)
#define _TIF_SYSCALL_TRACEPOINT	(1 << TIF_SYSCALL_TRACEPOINT)
#define _TIF_SECCOMP		(1 << TIF_SECCOMP)
#define _TIF_SYSCALL_EMU	(1 << TIF_SYSCALL_EMU)
#define _TIF_SINGLESTEP		(1 << TIF_SINGLESTEP)
#define _TIF_WORK_MASK		(_TIF_NEED_RESCHED | _TIF_SIGPENDING | \
				 _TIF_NOTIFY_RESUME | _TIF_FOREIGN_FPSTATE | \
				 _TIF_UPROBE | _TIF_MTE_ASYNC_FAULT | \
				 _TIF_NOTIFY_SIGNAL)
#define _TIF_SYSCALL_WORK	(_TIF_SYSCALL_TRACE | _TIF_SYSCALL_AUDIT | \
				 _TIF_SYSCALL_TRACEPOINT | _TIF_SECCOMP | \
				 _TIF_SYSCALL_EMU)
#define task_thread_info(task) (&(task)->thread_info)
/* include/linux/thread_info.h read_thread_flags() and test_thread_flag() on current. */
unsigned long read_thread_flags(void);
int test_thread_flag(int flag);
/* arch/arm64/include/asm/esr.h */
#define ESR_ELx_EC_UNKNOWN	(0x00UL)
#define ESR_ELx_EC_WFx		(0x01UL)
#define ESR_ELx_EC_FP_ASIMD	(0x07UL)
#define ESR_ELx_EC_BTI		(0x0DUL)
#define ESR_ELx_EC_SVC64	(0x15UL)
#define ESR_ELx_EC_SYS64	(0x18UL)
#define ESR_ELx_EC_SVE		(0x19UL)
#define ESR_ELx_EC_FPAC		(0x1CUL)
#define ESR_ELx_EC_SME		(0x1DUL)
#define ESR_ELx_EC_IABT_LOW	(0x20UL)
#define ESR_ELx_EC_PC_ALIGN	(0x22UL)
#define ESR_ELx_EC_DABT_LOW	(0x24UL)
#define ESR_ELx_EC_SP_ALIGN	(0x26UL)
#define ESR_ELx_EC_MOPS		(0x27UL)
#define ESR_ELx_EC_FP_EXC64	(0x2CUL)
#define ESR_ELx_EC_BREAKPT_LOW	(0x30UL)
#define ESR_ELx_EC_SOFTSTP_LOW	(0x32UL)
#define ESR_ELx_EC_WATCHPT_LOW	(0x34UL)
#define ESR_ELx_EC_BRK64	(0x3CUL)
#define ESR_ELx_EC_SHIFT	(26)
#define ESR_ELx_EC_MASK		(0x3FUL << ESR_ELx_EC_SHIFT)
#define ESR_ELx_EC(esr)		(((esr) & ESR_ELx_EC_MASK) >> ESR_ELx_EC_SHIFT)
#define ESR_ELx_IL		(1UL << 25)
/* Configuration-off forms, as include/linux/{lockdep,irqflags,context_tracking}.h
 * define them without CONFIG_PROVE_LOCKING, CONFIG_TRACE_IRQFLAGS and
 * CONFIG_CONTEXT_TRACKING_USER (all off in the live kernel). */
#define lockdep_hardirqs_off(ip) do { } while (0)
#define lockdep_hardirqs_on_prepare() do { } while (0)
#define lockdep_hardirqs_on(ip) do { } while (0)
#define lockdep_sys_exit() do { } while (0)
#define trace_hardirqs_off_finish() do { } while (0)
#define trace_hardirqs_on_prepare() do { } while (0)
#define CT_WARN_ON(cond) do { } while (0)
#define user_exit_irqoff() do { } while (0)
#define user_enter_irqoff() do { } while (0)
/* CONFIG_RANDOMIZE_KSTACK_OFFSET is built but its static key is off
 * (CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT is not set; the live trace has nops). */
#define add_random_kstack_offset() do { } while (0)
#define choose_random_kstack_offset(rand) do { } while (0)
#define CONFIG_DEBUG_RSEQ 0 /* not set in the live kernel */
#define lower_32_bits(n) ((uint32_t)((n) & 0xffffffff))
/* Exception and interrupt masking: no observable effect in the interrupt-free,
 * single-CPU replay. DAIF_PROCCTX unmasks everything, as Linux does for process context. */
#define DAIF_PROCCTX 0
void local_daif_restore(unsigned long flags);
void local_daif_mask(void);
void local_irq_disable(void);
/* arch/arm64/include/asm/sysreg.h; the kernel builds as gnu11, where asm is a keyword. */
#define asm __asm__
#define typeof __typeof__
#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)
#define read_sysreg(r) ({					\
	u64 __val;						\
	asm volatile("mrs %0, " __stringify(r) : "=r" (__val));	\
	__val;							\
})
/* CPU capabilities of the live Cortex-A53: no SME, SVE or MTE. */
bool system_supports_sme(void);
bool system_supports_sve(void);
void mte_disable_tco_entry(struct task_struct *task);
void mte_check_tfsr_exit(void);
bool is_compat_task(void);
bool is_compat_thread(struct thread_info *thread);
/* Fault boundaries: work on return, tracing, other exception classes, SVE/SME state. */
void do_notify_resume(struct pt_regs *regs, unsigned long thread_flags);
int syscall_trace_enter(struct pt_regs *regs);
void syscall_trace_exit(struct pt_regs *regs);
long compat_arm_syscall(struct pt_regs *regs, int scno);
long sys_ni_syscall(void);
void sme_smstop_sm(void);
unsigned int sve_vq_from_vl(unsigned int vl);
unsigned int task_get_sve_vl(const struct task_struct *task);
void sve_flush_live(bool flush_ffr, unsigned long vq_minus_1);
void el0_da(struct pt_regs *regs, unsigned long esr);
void el0_ia(struct pt_regs *regs, unsigned long esr);
void el0_fpsimd_acc(struct pt_regs *regs, unsigned long esr);
void el0_sve_acc(struct pt_regs *regs, unsigned long esr);
void el0_sme_acc(struct pt_regs *regs, unsigned long esr);
void el0_fpsimd_exc(struct pt_regs *regs, unsigned long esr);
void el0_sys(struct pt_regs *regs, unsigned long esr);
void el0_sp(struct pt_regs *regs, unsigned long esr);
void el0_pc(struct pt_regs *regs, unsigned long esr);
void el0_undef(struct pt_regs *regs, unsigned long esr);
void el0_bti(struct pt_regs *regs);
void el0_mops(struct pt_regs *regs, unsigned long esr);
void el0_dbg(struct pt_regs *regs, unsigned long esr);
void el0_fpac(struct pt_regs *regs, unsigned long esr);
void el0_inv(struct pt_regs *regs, unsigned long esr);
/* The system call table holds the slice's system call numbers instead of
 * function pointers; osrec_sys_call is the reviewed table call: it unpacks the
 * argument registers as the SYSCALL_DEFINE wrappers do and calls the root. */
/* Futexes: kernel/futex (core.c, waitwake.c, syscalls.c, futex.h), include/linux/futex.h and
 * include/uapi/linux/futex.h of v6.10. Constants and macros are copied from those headers. */
#define CONFIG_SMP 1
#define ENOSYS 38
#define ETIMEDOUT 110
typedef int64_t ktime_t;
struct __kernel_timespec {int64_t tv_sec;long long tv_nsec;};
#define FUTEX_WAIT		0
#define FUTEX_WAKE		1
#define FUTEX_FD		2
#define FUTEX_REQUEUE		3
#define FUTEX_CMP_REQUEUE	4
#define FUTEX_WAKE_OP		5
#define FUTEX_LOCK_PI		6
#define FUTEX_UNLOCK_PI		7
#define FUTEX_TRYLOCK_PI	8
#define FUTEX_WAIT_BITSET	9
#define FUTEX_WAKE_BITSET	10
#define FUTEX_WAIT_REQUEUE_PI	11
#define FUTEX_CMP_REQUEUE_PI	12
#define FUTEX_LOCK_PI2		13
#define FUTEX_PRIVATE_FLAG	128
#define FUTEX_CLOCK_REALTIME	256
#define FUTEX_CMD_MASK		~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)
#define FUTEX_BITSET_MATCH_ANY	0xffffffff
/* include/uapi/linux/futex.h: FUTEX_WAKE_OP's encoded operation. */
#define FUTEX_OP_SET		0
#define FUTEX_OP_ADD		1
#define FUTEX_OP_OR		2
#define FUTEX_OP_ANDN		3
#define FUTEX_OP_XOR		4
#define FUTEX_OP_OPARG_SHIFT	8
#define FUTEX_OP_CMP_EQ		0
#define FUTEX_OP_CMP_NE		1
#define FUTEX_OP_CMP_LT		2
#define FUTEX_OP_CMP_LE		3
#define FUTEX_OP_CMP_GT		4
#define FUTEX_OP_CMP_GE		5
#define CONFIG_FUTEX_PI 1
/* include/uapi/linux/futex.h: the PI futex word. */
#define FUTEX_WAITERS		0x80000000
#define FUTEX_OWNER_DIED	0x40000000
#define FUTEX_TID_MASK		0x3fffffff
#define FLAGS_SIZE_32		0x0002
#define FLAGS_SIZE_MASK		0x0003
#define FLAGS_SHARED		0x0010
#define FLAGS_CLOCKRT		0x0020
#define FLAGS_HAS_TIMEOUT	0x0040
#define FLAGS_STRICT		0x0100
#define FUT_OFF_INODE    1 /* We set bit 0 if key has a reference on inode */
#define FUT_OFF_MMSHARED 2 /* We set bit 1 if key has a reference on mm */
union futex_key {
	struct {
		u64 i_seq;
		unsigned long pgoff;
		unsigned int offset;
	} shared;
	struct {
		union {
			struct mm_struct *mm;
			u64 __tmp;
		};
		unsigned long address;
		unsigned int offset;
	} private;
	struct {
		u64 ptr;
		unsigned long word;
		unsigned int offset;
	} both;
};
#define FUTEX_KEY_INIT (union futex_key) { .both = { .ptr = 0ULL } }
enum futex_access {
	FUTEX_READ,
	FUTEX_WRITE
};
/* include/linux/plist.h and list.h iteration (the walk runs only when a bucket has waiters). */
struct plist_head {struct list_head node_list;};
struct plist_node {int prio;struct list_head prio_list;struct list_head node_list;};
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, __typeof__(*(pos)), member)
#define list_entry_is_head(pos, head, member)				\
	(&pos->member == (head))
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, __typeof__(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     !list_entry_is_head(pos, head, member); 			\
	     pos = n, n = list_next_entry(n, member))
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, __typeof__(*pos), member);	\
	     !list_entry_is_head(pos, head, member);			\
	     pos = list_next_entry(pos, member))
/* include/linux/plist.h. The futex hash chains these walk are empty at every boundary the slice replays (it
 * queues no waiter; the live binding requires each chain empty): the analysis proves each walk ends at its head
 * (analysis-contracts.json empty_lists). */
#define plist_for_each_entry(pos, head, mem)	\
	 list_for_each_entry(pos, &(head)->node_list, mem.node_list)
#define plist_for_each_entry_safe(pos, m, head, mem)	\
	 list_for_each_entry_safe(pos, m, &(head)->node_list, mem.node_list)
/* Locks are the model's int lock words (spin_lock/spin_unlock). */
struct futex_hash_bucket {atomic_t waiters;int lock;struct plist_head chain;};
struct futex_pi_state;
struct rt_mutex_waiter;
/* include/linux/sched/wake_q.h */
struct wake_q_head {struct wake_q_node *first;struct wake_q_node **lastp;};
#define WAKE_Q_TAIL ((struct wake_q_node *) 0x01)
#define WAKE_Q_HEAD_INITIALIZER(name)				\
	{ WAKE_Q_TAIL, &name.first }
#define DEFINE_WAKE_Q(name)					\
	struct wake_q_head name = WAKE_Q_HEAD_INITIALIZER(name)
void wake_up_q(struct wake_q_head *head);
struct futex_q;
typedef void (futex_wake_fn)(struct wake_q_head *wake_q, struct futex_q *q);
struct futex_q {
	struct plist_node list;
	struct task_struct *task;
	int *lock_ptr;
	futex_wake_fn *wake;
	void *wake_data;
	union futex_key key;
	struct futex_pi_state *pi_state;
	struct rt_mutex_waiter *rt_waiter;
	union futex_key *requeue_pi_key;
	u32 bitset;
	atomic_t requeue_state;
};
enum {Q_REQUEUE_PI_NONE = 0};
#define ATOMIC_INIT(i) { (i) }
extern const struct futex_q futex_q_init;
/* __futex_data is a static anonymous struct in core.c; the model names its type. The bucket array
 * is a pool of the live hash size (roundup_pow_of_two(256 * num_possible_cpus()), one CPU here). */
#define OSREC_FUTEX_BUCKETS 256
struct futex_data {struct futex_hash_bucket *queues;uint64_t hashsize;};
extern struct futex_data __futex_data;
extern struct futex_hash_bucket futex_hash_buckets[OSREC_FUTEX_BUCKETS];
#define futex_queues   (__futex_data.queues)
#define futex_hashsize (__futex_data.hashsize)
/* Single-CPU atomics on the model's counters; barriers are no-ops. */
#define atomic_inc(v) ((void)++(v)->counter)
#define atomic_dec(v) ((void)--(v)->counter)
#define smp_mb__after_atomic() ((void)0)
/* include/linux/jhash.h */
#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}
#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}
#define JHASH_INITVAL		0xdeadbeef
/* User reads: __get_user reads an admitted user object (linux_get_user, 0 or -EFAULT); page faults
 * are not handled in the slice, so pagefault_disable/enable have nothing to switch. */
#define __get_user(x,ptr) __extension__({_Static_assert(sizeof(x)==sizeof(*(ptr)),"__get_user width");linux_get_user((void *)&(x),(const void *)(ptr),sizeof(*(ptr)));})
#define get_user(x,ptr) (access_ok(ptr,sizeof(*(ptr))) ? __get_user(x,ptr) : -EFAULT)
#define pagefault_disable() ((void)0)
#define pagefault_enable() ((void)0)
/* High-resolution timers (include/linux/hrtimer.h, hrtimer_defs.h, timerqueue.h) for a futex timeout: the
 * on-stack sleeper is initialized against this CPU's clock base and cancelled unarmed when the wait returns at
 * once. The fields are those the original init and cancel paths touch. hrtimer_bases is per-CPU: the slice
 * holds this CPU's copy, whose clock bases' seq and running a live binding supplies. Without
 * DEBUG_OBJECTS_TIMERS the debug-object hooks are empty; PREEMPT_RT is off. Arming and expiry (a timer that
 * is enqueued or running) fault: hrtimer_try_to_cancel's locked path and hrtimer_cancel_wait_running. */
typedef int clockid_t;
typedef int64_t s64;
/* include/linux/ktime.h: addition that may wrap (ktime_add_safe checks it). */
#define ktime_add_unsafe(lhs, rhs)	((u64) (lhs) + (rhs))
/* Only PREEMPT_RT kernels ask whether the sleeper's task is real-time. */
bool task_is_realtime(struct task_struct *);
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_BOOTTIME 7
#define CLOCK_TAI 11
#define MAX_CLOCKS 16
enum hrtimer_mode {HRTIMER_MODE_ABS = 0x00,HRTIMER_MODE_REL = 0x01,HRTIMER_MODE_PINNED = 0x02,HRTIMER_MODE_SOFT = 0x04,HRTIMER_MODE_HARD = 0x08};
enum hrtimer_restart {HRTIMER_NORESTART,HRTIMER_RESTART};
enum hrtimer_base_type {HRTIMER_BASE_MONOTONIC,HRTIMER_BASE_REALTIME,HRTIMER_BASE_BOOTTIME,HRTIMER_BASE_TAI,HRTIMER_BASE_MONOTONIC_SOFT,
    HRTIMER_BASE_REALTIME_SOFT,HRTIMER_BASE_BOOTTIME_SOFT,HRTIMER_BASE_TAI_SOFT,HRTIMER_MAX_CLOCK_BASES};
#define HRTIMER_STATE_INACTIVE 0x00
struct rb_node_model {unsigned long __rb_parent_color;struct rb_node_model *rb_right,*rb_left;};
struct timerqueue_node {struct rb_node_model node;ktime_t expires;};
#define RB_CLEAR_NODE(node) ((node)->__rb_parent_color = (unsigned long)(node))
static inline void timerqueue_init(struct timerqueue_node *node){RB_CLEAR_NODE(&node->node);}
struct hrtimer_clock_base;
struct hrtimer {struct timerqueue_node node;ktime_t _softexpires;enum hrtimer_restart (*function)(struct hrtimer *);struct hrtimer_clock_base *base;
    uint8_t state;uint8_t is_rel;uint8_t is_soft;uint8_t is_hard;};
struct hrtimer_sleeper {struct hrtimer timer;struct task_struct *task;};
struct hrtimer_cpu_base;
struct hrtimer_clock_base {struct hrtimer_cpu_base *cpu_base;unsigned int index;clockid_t clockid;seqcount_raw_spinlock_t seq;struct hrtimer *running;};
struct hrtimer_cpu_base {struct hrtimer_clock_base clock_base[HRTIMER_MAX_CLOCK_BASES];};
extern struct hrtimer_cpu_base hrtimer_bases;
extern const int hrtimer_clock_to_base_table[MAX_CLOCKS];
#define debug_object_init_on_stack(addr,descr) ((void)0)
#define debug_init(timer,clockid,mode) ((void)0)
#define raw_read_seqcount_begin(s) read_seqcount_begin(s)
#define ns_to_ktime(ns) ((ktime_t)(ns))
#define KTIME_MAX ((ktime_t)~((u64)1 << 63))
#define KTIME_SEC_MAX (KTIME_MAX / NSEC_PER_SEC)
enum hrtimer_restart hrtimer_wakeup(struct hrtimer *);
int hrtimer_try_to_cancel(struct hrtimer *);
void hrtimer_cancel_wait_running(struct hrtimer *);
struct hrtimer_clock_base *lock_hrtimer_base(const struct hrtimer *,unsigned long *);
int hrtimer_callback_running(struct hrtimer *);
int remove_hrtimer(struct hrtimer *,struct hrtimer_clock_base *,bool,bool);
void unlock_hrtimer_base(const struct hrtimer *,unsigned long *);
/* Time namespaces (include/linux/time_namespace.h, TIME_NS): the task is in the initial namespace (the live
 * binding checks current->nsproxy->time_ns against the derived init_time_ns), whose offsets are zero. */
struct timens_offsets {struct timespec64 monotonic,boottime;};
struct time_namespace {struct timens_offsets offsets;};
struct nsproxy {struct time_namespace *time_ns;};
extern struct nsproxy nsproxy;
extern struct time_namespace init_time_ns;
ktime_t do_timens_ktime_to_host(clockid_t,ktime_t,struct timens_offsets *);
/* ktime_get reads the arch counter, which a replay cannot reproduce; its value only arms an on-stack timer that is
 * cancelled unarmed, so no observable state depends on it. The model returns 0. */
ktime_t ktime_get(void);
long set_restart_fn(struct restart_block *,long (*)(struct restart_block *));
long futex_wait_restart(struct restart_block *);
int signal_pending(struct task_struct *);
/* Shared futexes (get_futex_key past its private return) and the commands outside WAKE/WAIT. */
#define FOLL_WRITE 0x01
/* include/linux/page-flags.h: the low bit of an anonymous folio's mapping (its anon_vma). */
#define PAGE_MAPPING_ANON 0x1
/* A shared futex key pins the word's page (GUP-fast, one page) and reads its folio: the slice holds that folio
 * (user_folio, at user page address user_page_address), which the live binding finds by walking the task's page
 * tables (user_page). Its mapping is a live pointer the slice only tests (anon bit, null). */
extern struct folio user_folio;
extern unsigned long user_page_address;
/* GUP-fast (mm/gup.c, original) walks the task's page tables: arm64, CONFIG_PGTABLE_LEVELS=4, 4 KiB pages, 48-bit VA and
 * PA, no LPA2, so the p4d level folds into the pgd (include/asm-generic/pgtable-nop4d.h). The types, accessors and
 * constants below are the kernel's (arch/arm64/include/asm/pgtable{,-types,-hwdef,-prot}.h, include/linux/pgtable.h),
 * each in the variant this configuration compiles. The setup pins every table the walk reads: the live binding
 * dumps the four table pages for the word's address (user_page), and the slice holds them as osrec_page_tables. */
typedef u64 phys_addr_t;
typedef u64 pteval_t;
typedef u64 pmdval_t;
typedef u64 pudval_t;
typedef u64 p4dval_t;
typedef u64 pgdval_t;
typedef struct { pteval_t pte; } pte_t;
#define pte_val(x)	((x).pte)
#define __pte(x)	((pte_t) { (x) } )
typedef struct { pmdval_t pmd; } pmd_t;
#define pmd_val(x)	((x).pmd)
#define __pmd(x)	((pmd_t) { (x) } )
typedef struct { pudval_t pud; } pud_t;
#define pud_val(x)	((x).pud)
#define __pud(x)	((pud_t) { (x) } )
typedef struct { pgdval_t pgd; } pgd_t;
#define pgd_val(x)	((x).pgd)
#define __pgd(x)	((pgd_t) { (x) } )
/* include/asm-generic/pgtable-nop4d.h folds p4d into pgd: its p4d_t wraps one pgd_t and p4d_offset views the pgd
 * entry as that wrapper. Here the folded level is the pgd_t itself (same layout, same value), so the view is the
 * entry pointer, with no pointer conversion. */
typedef pgd_t p4d_t;
#define p4d_val(x)				pgd_val(x)
#define __p4d(x)				__pgd(x)
static inline int pgd_none(pgd_t pgd)		{ (void)pgd; return 0; }
static inline p4d_t *p4d_offset(pgd_t *pgd, unsigned long address)
{
	(void)address; return pgd;
}
#define p4d_offset_lockless(pgdp, pgd, address) p4d_offset(&(pgd), address)
#define p4d_addr_end(addr, end)			(end)
#define _AT(T,X) ((T)(X))
#define _AC(X,Y) (X##Y)
#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - 3) * (4 - (n)) + 3)
#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - 3))
#define PMD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(2)
#define PMD_SIZE		(_AC(1, UL) << PMD_SHIFT)
#define PMD_MASK		(~(PMD_SIZE-1))
#define PTRS_PER_PMD		(1 << (PAGE_SHIFT - 3))
#define PUD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(1)
#define PUD_SIZE		(_AC(1, UL) << PUD_SHIFT)
#define PUD_MASK		(~(PUD_SIZE-1))
#define PTRS_PER_PUD		(1 << (PAGE_SHIFT - 3))
#define CONFIG_PGTABLE_LEVELS 4
#define PGDIR_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(4 - CONFIG_PGTABLE_LEVELS)
#define PGDIR_SIZE		(_AC(1, UL) << PGDIR_SHIFT)
#define PGDIR_MASK		(~(PGDIR_SIZE-1))
#define PTRS_PER_PGD		(1 << (VA_BITS - PGDIR_SHIFT))
#define PTE_VALID		(_AT(pteval_t, 1) << 0)
#define PTE_USER		(_AT(pteval_t, 1) << 6)		/* AP[1] */
#define PTE_NG			(_AT(pteval_t, 1) << 11)	/* nG */
#define PTE_DBM			(_AT(pteval_t, 1) << 51)	/* Dirty Bit Management */
#define PTE_CONT		(_AT(pteval_t, 1) << 52)	/* Contiguous range */
#define PTE_UXN			(_AT(pteval_t, 1) << 54)	/* User XN */
#define PTE_ADDR_LOW		(((_AT(pteval_t, 1) << (48 - PAGE_SHIFT)) - 1) << PAGE_SHIFT)
#define PTE_WRITE		(PTE_DBM)		 /* same as DBM (51) */
#define PTE_SPECIAL		(_AT(pteval_t, 1) << 56)
#define PTE_DEVMAP		(_AT(pteval_t, 1) << 57)
#define PTE_PRESENT_INVALID	(PTE_NG)		 /* only when !PTE_VALID */
#define PMD_TYPE_MASK		(_AT(pmdval_t, 3) << 0)
#define PMD_TYPE_TABLE		(_AT(pmdval_t, 3) << 0)
#define PUD_TYPE_MASK		(_AT(pudval_t, 3) << 0)
#define PUD_TYPE_TABLE		(_AT(pudval_t, 3) << 0)
#define __pte_to_phys(pte)	(pte_val(pte) & PTE_ADDR_LOW)
#define pte_pfn(pte)		(__pte_to_phys(pte) >> PAGE_SHIFT)
#define pte_valid(pte)		(!!(pte_val(pte) & PTE_VALID))
#define pte_special(pte)	(!!(pte_val(pte) & PTE_SPECIAL))
#define pte_write(pte)		(!!(pte_val(pte) & PTE_WRITE))
#define pte_devmap(pte)		(!!(pte_val(pte) & PTE_DEVMAP))
#define pte_user(pte)		(!!(pte_val(pte) & PTE_USER))
#define pte_user_exec(pte)	(!(pte_val(pte) & PTE_UXN))
#define pte_cont(pte)		(!!(pte_val(pte) & PTE_CONT))
#define pte_valid_cont(pte)	(pte_valid(pte) && pte_cont(pte))
#define pte_present_invalid(pte) \
	((pte_val(pte) & (PTE_VALID | PTE_PRESENT_INVALID)) == PTE_PRESENT_INVALID)
#define pte_present(pte)	(pte_valid(pte) || pte_present_invalid(pte))
#define pte_access_permitted(pte, write) \
	(((pte_val(pte) & (PTE_VALID | PTE_USER)) == (PTE_VALID | PTE_USER)) && (!(write) || pte_write(pte)))
static inline int pte_protnone(pte_t pte)
{
	return pte_present_invalid(pte) && !pte_user(pte) && !pte_user_exec(pte);
}
static inline pte_t pmd_pte(pmd_t pmd)
{
	return __pte(pmd_val(pmd));
}
static inline pte_t pud_pte(pud_t pud)
{
	return __pte(pud_val(pud));
}
static inline pte_t p4d_pte(p4d_t p4d)
{
	return __pte(p4d_val(p4d));
}
#define pmd_present(pmd)	pte_present(pmd_pte(pmd))
#define pmd_table(pmd)		((pmd_val(pmd) & PMD_TYPE_MASK) == \
				 PMD_TYPE_TABLE)
#define pmd_leaf(pmd)		(pmd_present(pmd) && !pmd_table(pmd))
static inline int pmd_protnone(pmd_t pmd)
{
	return pte_protnone(pmd_pte(pmd));
}
#define pud_present(pud)	pte_present(pud_pte(pud))
#define pud_table(pud)		((pud_val(pud) & PUD_TYPE_MASK) == \
				 PUD_TYPE_TABLE)
#define pud_leaf(pud)		(pud_present(pud) && !pud_table(pud))
#define p4d_none(p4d)		(pgtable_l4_enabled() && !p4d_val(p4d))
#define p4d_present(p4d)	(!p4d_none(p4d))
#define p4d_leaf(x)	false
#define P4D_SHIFT		PGDIR_SHIFT
#define pgd_leaf(x)	false
#define __pmd_to_phys(pmd)	__pte_to_phys(pmd_pte(pmd))
#define __pud_to_phys(pud)	__pte_to_phys(pud_pte(pud))
#define __p4d_to_phys(p4d)	__pte_to_phys(p4d_pte(p4d))
static inline phys_addr_t pmd_page_paddr(pmd_t pmd)
{
	return __pmd_to_phys(pmd);
}
static inline phys_addr_t pud_page_paddr(pud_t pud)
{
	return __pud_to_phys(pud);
}
static inline phys_addr_t p4d_page_paddr(p4d_t p4d)
{
	return __p4d_to_phys(p4d);
}
/* arch/arm64/include/asm/memory.h's __va (the linear map), modeled per level of GUP-fast's walk (the call rewrites
 * in prepare.py): the slice holds only the pinned table pages, and __va of a level's table physical address is that
 * page; any other address faults. */
struct osrec_pud_page;struct osrec_pmd_page;struct osrec_pte_page;
static inline bool pgtable_l4_enabled(void) { return true; }
#define pgd_index(a)  (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
static inline unsigned long pud_index(unsigned long address)
{
	return (address >> PUD_SHIFT) & (PTRS_PER_PUD - 1);
}
static inline unsigned long pmd_index(unsigned long address)
{
	return (address >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
}
static inline unsigned long pte_index(unsigned long address)
{
	return (address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
}
static inline pgd_t *pgd_offset_pgd(pgd_t *pgd, unsigned long address)
{
	return (pgd + pgd_index(address));
}
/* include/linux/pgtable.h's pgd_offset reads mm->pgd; the slice's mm is the live pointer value (a futex key hashes
 * it), so the read is a model: the pinned top-level table of the bound mm. */
pgd_t *osrec_mm_pgd(struct mm_struct *);
#define pgd_offset(mm, address)		pgd_offset_pgd(osrec_mm_pgd(mm), (address))
static inline pte_t __ptep_get(pte_t *ptep)
{
	return READ_ONCE(*ptep);
}
pte_t contpte_ptep_get_lockless(pte_t *);
pte_t contpte_ptep_get(pte_t *, pte_t);
/* include/linux/pgtable.h */
#define pmd_offset_lockless(pudp, pud, address) pmd_offset(&(pud), address)
static inline pmd_t pmdp_get(pmd_t *pmdp)
{
	return READ_ONCE(*pmdp);
}
static inline pmd_t pmdp_get_lockless(pmd_t *pmdp)
{
	return pmdp_get(pmdp);
}
#define pgd_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PGDIR_SIZE) & PGDIR_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})
#define pud_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PUD_SIZE) & PUD_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})
#define pmd_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PMD_SIZE) & PMD_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})
/* include/uapi/linux/const.h, include/linux/align.h */
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (__typeof__(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))
#define PTR_ALIGN_DOWN(p, a)	((typeof(p))ALIGN_DOWN((unsigned long)(p), (a)))
/* include/linux/overflow.h */
#define check_add_overflow(a, b, d) __builtin_add_overflow(a, b, d)
/* arch/arm64/include/asm/pgtable.h, include/linux/huge_mm.h, include/linux/swapops.h (THP=y, THP migration=y). */
#define PMD_TABLE_BIT		(_AT(pmdval_t, 1) << 1)
#define pmd_none(pmd)		(!pmd_val(pmd))
#define pmd_bad(pmd)		(!pmd_table(pmd))
#define pmd_devmap(pmd)		pte_devmap(pmd_pte(pmd))
static inline int pmd_trans_huge(pmd_t pmd)
{
	return pmd_val(pmd) && pmd_present(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT);
}
static inline int is_swap_pmd(pmd_t pmd)
{
	return !pmd_none(pmd) && !pmd_present(pmd);
}
/* A swap pmd is outside the pinned-table envelope: these fault. */
swp_entry_t pmd_to_swp_entry(pmd_t);
int is_migration_entry(swp_entry_t);
/* include/linux/swapops.h's is_pmd_migration_entry (THP migration=y), as a macro: its swap half reaches models. */
#define is_pmd_migration_entry(pmd) (is_swap_pmd(pmd) && is_migration_entry(pmd_to_swp_entry(pmd)))
void pmd_clear_bad(pmd_t *);
/* mm/pgtable-generic.c, !CONFIG_GUP_GET_PXX_LOW_HIGH (inline here: model.h is in every unit) */
static inline unsigned long pmdp_get_lockless_start(void) { return 0; }
static inline void pmdp_get_lockless_end(unsigned long irqflags) { (void)irqflags; }
#define pte_offset_map(pmd, addr)	__pte_offset_map(pmd, addr, NULL)
/* include/linux/mm.h, arm64 SPARSEMEM_VMEMMAP pfn_to_page, modeled like __va: the pinned user page's frame is the bound
 * user folio's page; another frame faults. */
struct page *osrec_pfn_to_page(unsigned long);
#define pfn_to_page(pfn) osrec_pfn_to_page(pfn)
#define pte_page(pte)		(pfn_to_page(pte_pfn(pte)))
/* The pinned tables: the bound task's top-level table and, for the bound user page, the next three levels. */
struct osrec_pgd_page {pgd_t entries[512];};
struct osrec_pud_page {pud_t entries[512];};
struct osrec_pmd_page {pmd_t entries[512];};
struct osrec_pte_page {pte_t entries[512];};
extern struct osrec_pgd_page osrec_pgd_table;extern struct osrec_pud_page osrec_pud_table;
extern struct osrec_pmd_page osrec_pmd_table;extern struct osrec_pte_page osrec_pte_table;
void osrec_gup_store(struct page **,int,struct page *);
pud_t *osrec_pud_va(phys_addr_t);pmd_t *osrec_pmd_va(phys_addr_t);pte_t *osrec_pte_va(phys_addr_t);
extern unsigned long osrec_mm_value,osrec_pud_table_pa,osrec_pmd_table_pa,osrec_pte_table_pa,osrec_user_pfn;
/* mm/gup.c's flags (include/linux/mm_types.h, mm/internal.h) and the GUP-fast callees off a shared futex's path: a pinned
 * (FOLL_PIN) or long-term pin, huge and device-mapped pages and the slow path fault. */
#define FOLL_GET (1 << 1)
#define FOLL_FORCE (1 << 3)
#define FOLL_NOFAULT (1 << 5)
#define FOLL_LONGTERM (1 << 8)
#define FOLL_PCI_P2PDMA (1 << 10)
#define FOLL_HONOR_NUMA_FAULT (1 << 12)
#define FOLL_TOUCH (1 << 16)
#define FOLL_TRIED (1 << 17)
#define FOLL_REMOTE (1 << 18)
#define FOLL_PIN (1 << 19)
#define FOLL_FAST_ONLY (1 << 20)
#define FOLL_UNLOCKABLE (1 << 21)
#define FOLL_MADV_POPULATE (1 << 22)
#define INTERNAL_GUP_FLAGS (FOLL_TOUCH | FOLL_TRIED | FOLL_REMOTE | FOLL_PIN | \
			    FOLL_FAST_ONLY | FOLL_UNLOCKABLE | \
			    FOLL_MADV_POPULATE)
#define GUP_PIN_COUNTING_BIAS (1U << 10)
#define CONFIG_HAVE_GUP_FAST 1
#define CONFIG_SECRETMEM 1
enum node_stat_item {NR_FOLL_PIN_ACQUIRED,NR_FOLL_PIN_RELEASED};
/* Folio references are single-CPU operations on the slice folio's _refcount (as the other folio atomics here). */
int folio_ref_count(const struct folio *);
bool folio_ref_try_add(struct folio *,int);
void folio_put_refs(struct folio *,int);
static inline bool put_devmap_managed_folio_refs(struct folio *folio, int refs)
{
	(void)folio;(void)refs;return false;
}
static inline bool is_pci_p2pdma_page(const struct page *page)
{
	(void)page;return false;
}
#define is_hugepd(hugepd) (0)
#define __hugepd(x) ((hugepd_t) { (x) })
typedef struct { unsigned long pd; } hugepd_t;
#define irqs_disabled() (1)
/* CONFIG_DEBUG_VM is off: VM_BUG_ON evaluates nothing (include/linux/mmdebug.h). */
#define VM_BUG_ON(cond) ((void)0)
/* The mm fields only FOLL_PIN and the slow path use (the slice's mm is never dereferenced on the fast path). */
struct mm_struct {unsigned long flags;seqcount_raw_spinlock_t write_protect_seq;int mmap_lock;};
#define raw_read_seqcount(s) ((s)->sequence)
static inline int arch_make_page_accessible(struct page *page)
{
	(void)page;return 0;
}
void atomic_add(int,atomic_t *);
void atomic_sub(int,atomic_t *);
void folio_ref_add(struct folio *,int);
void gup_fast_unpin_user_pages(struct page **,unsigned long);
void sanity_check_pinned_pages(struct page **,unsigned long);
int gup_fast_pgd_leaf(pgd_t,pgd_t *,unsigned long,unsigned long,unsigned int,struct page **,int *);
#define lockdep_assert_irqs_disabled() ((void)0)
#define might_lock_read(lock) ((void)0)
bool folio_test_hugetlb(const struct folio *);
bool secretmem_mapping(struct address_space *);
bool is_zero_page(const struct page *);
bool is_zero_folio(const struct folio *);
bool folio_is_longterm_pinnable(struct folio *);
void node_stat_mod_folio(struct folio *,enum node_stat_item,int);
void mm_set_has_pinned_flag(unsigned long *);
long __gup_longterm_locked(struct mm_struct *,unsigned long,unsigned long,struct page **,int *,unsigned int);
int gup_fast_pmd_leaf(pmd_t,pmd_t *,unsigned long,unsigned long,unsigned int,struct page **,int *);
int gup_fast_pud_leaf(pud_t,pud_t *,unsigned long,unsigned long,unsigned int,struct page **,int *);
int gup_hugepd(struct vm_area_struct *,hugepd_t,unsigned long,unsigned int,unsigned long,unsigned int,struct page **,int *,bool);
struct dev_pagemap;
struct dev_pagemap *get_dev_pagemap(unsigned long,struct dev_pagemap *);
void put_dev_pagemap(struct dev_pagemap *);
void gup_fast_undo_dev_pagemap(int *,int,unsigned int,struct page **);
bool gup_must_unshare(struct vm_area_struct *,unsigned int,struct page *);
unsigned long folio_page_idx(struct folio *,struct page *);
u64 get_inode_sequence_number(struct inode *);
void futex_wait_queue(struct futex_hash_bucket *,struct futex_q *,struct hrtimer_sleeper *);
int futex_unqueue(struct futex_q *);
void futex_wake_mark(struct wake_q_head *,struct futex_q *);
/* futex_wake's call of a queued waiter's q->wake, rewritten to a reviewed dispatch model. */
void osrec_futex_q_wake(futex_wake_fn *,struct wake_q_head *,struct futex_q *);
/* FUTEX_REQUEUE, CMP_REQUEUE and WAKE_OP (requeue.c, waitwake.c) run as original source. Both hash-bucket locks are
 * the model's lock words (spin_lock_nested is spin_lock without lockdep). Moving or waking a queued waiter and the
 * PI requeue steps are outside the slice and fault. */
#define SINGLE_DEPTH_NESTING 1
#define spin_lock_nested(lock,subclass) spin_lock(lock)
#define swap(a, b) \
	do { __typeof__(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)
/* get_task_comm and pr_info_ratelimited: a WAKE_OP shift outside 0..31 prints a warning, which the slice cannot. */
#define get_task_comm(buf,tsk) ((void)(tsk),(buf))
#define pr_info_ratelimited(fmt,comm,oparg) ((void)(fmt),(void)(comm),(void)(oparg),(void)linux_assert(1))
/* arch/arm64/include/asm/futex.h: __futex_atomic_op is an LDXR/STLXR loop (inline assembly, with an exception-table
 * fixup). On one CPU it is a load of the admitted user word, the operation and a store, or -EFAULT. It is expanded
 * only in arch_futex_atomic_op_inuser's switch on op, whose case selects the operation (ANDN passes ~oparg). */
#define __futex_atomic_op(insn, ret, oldval, uaddr, tmp, oparg) \
	((void)&(tmp), (ret) = osrec_futex_atomic_op(op, &(oldval), uaddr, oparg))
int osrec_futex_atomic_op(int op,int *oldval,u32 __user *uaddr,int oparg);
/* PI futexes (pi.c) run as original source for an uncontended word: LOCK_PI and TRYLOCK_PI on an unowned or own
 * word, UNLOCK_PI by its owner with no waiter. A waiter or another owner (attaching a pi_state, the rt_mutex proxy
 * lock and queueing) is outside the slice and faults. The task's pi_state cache is a live pointer the slice only
 * tests (opaque_pointers in the live binding); allocating it (a task's first PI lock, kzalloc from kmalloc-96, a
 * cache the slice does not hold) faults. raw spinlocks are the model's lock words. */
typedef struct {atomic_t refs;} refcount_t;
#define refcount_set(r,n) ((r)->refs.counter=(n))
static inline void INIT_LIST_HEAD(struct list_head *list){list->next=list;list->prev=list;}
#define raw_spin_lock_irq(lock) spin_lock(lock)
#define raw_spin_unlock_irq(lock) spin_unlock(lock)
#define EDEADLK 35
/* kernel/locking/rtmutex: raw spinlock, rb_root_cached waiters, owner (the live layout; refill_pi_state_cache's kzalloc size
 * and the fields it stores must be the kernel's, since the object it fills is bound live). */
struct rt_mutex_base {int wait_lock;struct {void *rb_node,*rb_leftmost;} waiters;struct task_struct *owner;};
struct rt_mutex_waiter {struct task_struct *task;};
struct futex_pi_state {struct list_head list;struct rt_mutex_base pi_mutex;struct task_struct *owner;refcount_t refcount;union futex_key key;};
_Static_assert(sizeof(struct rt_mutex_base)==32 && __builtin_offsetof(struct rt_mutex_base,owner)==24,"rt_mutex_base layout (BTF)");
_Static_assert(sizeof(struct futex_pi_state)==88 && __builtin_offsetof(struct futex_pi_state,pi_mutex)==16 && __builtin_offsetof(struct futex_pi_state,owner)==48 &&
    __builtin_offsetof(struct futex_pi_state,refcount)==56 && __builtin_offsetof(struct futex_pi_state,key)==64,"futex_pi_state layout (BTF)");
/* arch/arm64/include/asm/futex.h: an LDXR/STLXR compare-and-exchange loop (inline assembly) with an exception-table
 * fixup, -EAGAIN after FUTEX_MAX_LOOPS failed store-exclusives (none on one CPU without interference). */
int futex_atomic_cmpxchg_inatomic(u32 *uval,u32 __user *uaddr,u32 oldval,u32 newval);
int attach_to_pi_state(u32 __user *,u32,struct futex_pi_state *,struct futex_pi_state **);
int attach_to_pi_owner(u32 __user *,u32,union futex_key *,struct futex_pi_state **,struct task_struct **);
void __attach_to_pi_owner(struct task_struct *,union futex_key *,struct futex_pi_state **);
struct rt_mutex_waiter *rt_mutex_top_waiter(struct rt_mutex_base *);
void __futex_unqueue(struct futex_q *);
int wake_futex_pi(u32 __user *,u32,struct futex_pi_state *,struct rt_mutex_waiter *);
void __futex_queue(struct futex_q *,struct futex_hash_bucket *);
int rt_mutex_futex_trylock(struct rt_mutex_base *);
void rt_mutex_pre_schedule(void);
void rt_mutex_post_schedule(void);
void rt_mutex_init_waiter(struct rt_mutex_waiter *);
int __rt_mutex_start_proxy_lock(struct rt_mutex_base *,struct rt_mutex_waiter *,struct task_struct *);
void hrtimer_sleeper_start_expires(struct hrtimer_sleeper *,enum hrtimer_mode);
int rt_mutex_wait_proxy_lock(struct rt_mutex_base *,struct hrtimer_sleeper *,struct rt_mutex_waiter *);
bool rt_mutex_cleanup_proxy_lock(struct rt_mutex_base *,struct rt_mutex_waiter *);
int fixup_pi_owner(u32 __user *,struct futex_q *,int);
void futex_unqueue_pi(struct futex_q *);
void get_pi_state(struct futex_pi_state *);
void put_pi_state(struct futex_pi_state *);
int futex_proxy_trylock_atomic(u32 __user *,struct futex_hash_bucket *,struct futex_hash_bucket *,union futex_key *,union futex_key *,struct futex_pi_state **,struct task_struct **,int);
int fault_in_user_writeable(u32 __user *);
void wait_for_owner_exiting(int,struct task_struct *);
bool futex_requeue_pi_prepare(struct futex_q *,struct futex_pi_state *);
int rt_mutex_start_proxy_lock(struct rt_mutex_base *,struct rt_mutex_waiter *,struct task_struct *);
void requeue_pi_wake_futex(struct futex_q *,union futex_key *,struct futex_hash_bucket *);
void requeue_futex(struct futex_q *,struct futex_hash_bucket *,struct futex_hash_bucket *,union futex_key *);
void futex_requeue_pi_complete(struct futex_q *,int);
int wake_up_process(struct task_struct *);
void put_task_struct(struct task_struct *);
int futex_wait_requeue_pi(u32 __user *,unsigned int,u32,ktime_t *,u32,u32 __user *);
typedef unsigned int syscall_fn_t;
#define OSREC_SYS_NI 0u /* sys_ni_syscall; syscall 0 (io_setup) is not in the slice */
extern const syscall_fn_t sys_call_table[__NR_syscalls];
long osrec_sys_call(syscall_fn_t syscall_fn, const struct pt_regs *regs);
/* entry-glue.S enters Linux's entry.S as an SVC from EL0; it asks for the current task. */
struct task_struct *osrec_entry_task(void);
void el0t_64_sync_handler(struct pt_regs *regs);
void do_el0_svc(struct pt_regs *regs);
long linux_getpid(void);
long linux_gettid(void);
long linux_getppid(void);
long linux_getuid(void);
long linux_geteuid(void);
long linux_getgid(void);
long linux_getegid(void);
long linux_getresuid(uid_t __user * ruidp, uid_t __user * euidp, uid_t __user * suidp);
long linux_getresgid(gid_t __user * rgidp, gid_t __user * egidp, gid_t __user * sgidp);
long linux_umask(int mask);
long linux_dup(unsigned int fildes);
long linux_dup3(unsigned int oldfd, unsigned int newfd, int flags);
long linux_close(unsigned int fd);
long linux_ftruncate(unsigned int fd, off_t length);
long linux_read(unsigned int fd, char __user * buf, size_t count);
long linux_write(unsigned int fd, const char __user * buf, size_t count);
long linux_writev(unsigned long fd, const struct iovec __user * vec, unsigned long vlen);
long linux_lseek(unsigned int fd, off_t offset, unsigned int whence);
long linux_pread64(unsigned int fd, char __user * buf, size_t count, loff_t pos);
long linux_pwrite64(unsigned int fd, const char __user * buf, size_t count, loff_t pos);
long linux_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg);
long linux_futex(u32 __user * uaddr, int op, u32 val, const struct __kernel_timespec __user * utime, u32 __user * uaddr2, u32 val3);
#endif
