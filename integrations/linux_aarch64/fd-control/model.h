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
struct thread_info {unsigned long flags;};
struct thread_struct {uint64_t sctlr_user;};
/* thread_info first, as on arm64 (THREAD_INFO_IN_TASK); entry.S reads it and thread.sctlr_user. */
/* flags: the PF_KTHREAD bit access_ok reads. */
struct task_struct {struct thread_info thread_info;int32_t pid,tgid;struct task_struct *real_parent;struct fs_struct *fs;struct cred *cred;struct files_struct *files;struct task_io_accounting ioac;int nr_dirtied,nr_dirtied_pause;struct mm_struct *mm;struct thread_struct thread;unsigned int flags;};
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
struct super_block {int write_depth;struct fsnotify_sb_info *s_fsnotify_info;uint64_t s_flags;uint32_t s_time_gran;int64_t s_time_min,s_time_max;struct user_namespace *s_user_ns;const struct super_operations *s_op;int64_t s_maxbytes;struct backing_dev_info *s_bdi;};
/* The shmem_inode_info enclosing a shmem inode, as the model's inode member. */
struct shmem_inode_info {uint32_t seals;struct list_head shrinklist;uint64_t flags;int64_t alloced,swapped;uint64_t fallocend;int lock;};
struct inode {uint32_t i_mode,append;struct super_block *i_sb;uint32_t i_flags;kuid_t i_uid;kgid_t i_gid;int64_t i_size;struct timespec64 __i_atime,__i_mtime,__i_ctime;atomic64_t i_version;uint64_t i_state;int i_lock;struct hlist_node i_hash;uint64_t dirtied_when,dirtied_time_when;const struct inode_operations *i_op;struct address_space *i_mapping;struct address_space i_data;int i_rwsem;struct shmem_inode_info osrec_shmem;struct file_lock_context *i_flctx;};
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
void sb_start_write(struct super_block *);
void sb_end_write(struct super_block *);
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
unsigned long copy_from_user(void *,const void *,unsigned long);
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
typedef struct {int64_t counter;} atomic_long_t;
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
/* osrec_writers balances mnt_get_write_access/mnt_put_write_access within a call. */
struct vfsmount {int mnt_flags;struct mnt_idmap *mnt_idmap;struct super_block *mnt_sb;int osrec_writers;};
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
bool sb_start_write_trylock(struct super_block *);
int mnt_get_write_access(struct vfsmount *);
void mnt_put_write_access(struct vfsmount *);
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
struct folio {uint64_t flags;struct address_space *mapping;uint64_t index;atomic_t _refcount;struct page page;swp_entry_t swap;};
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
void cond_resched(void);
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
#define PTR_ERR(ptr) linux_ptr_err(ptr)
bool linux_is_err(const void *);
long linux_ptr_err(const void *);
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
/* unsafe_get_user: one byte of the admitted user object, or a jump to the fault label. */
#define unsafe_get_user(x,ptr,label) do {if(linux_get_user_byte((const void *)(ptr),(char *)&(x)))goto label;} while(0)
int linux_get_user_byte(const void *,char *);
int fatal_signal_pending(struct task_struct *);
void send_sig(int,struct task_struct *,int);
void down_write(int *);
void up_write(int *);
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
int rwsem_is_locked(int *);
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
/* kernel/bpf/bpf_lsm.c's LSM_HOOK expansions, the nop function each hook gets
 * for BPF programs to attach to: none is attached (the live traces run each as
 * its four-instruction default). Header-local, as the macro-called dispatch
 * below is: the hooks' list walk is a macro the context transform cannot edit. */
static inline int bpf_lsm_file_permission(struct file *file,int mask){(void)file;(void)mask;return 0;}
static inline int bpf_lsm_file_fcntl(struct file *file,unsigned int cmd,unsigned long arg){(void)file;(void)cmd;(void)arg;return 0;}
static inline int bpf_lsm_file_truncate(struct file *file){(void)file;return 0;}
static inline int bpf_lsm_inode_setattr(struct mnt_idmap *idmap,struct dentry *dentry,struct iattr *attr){(void)idmap;(void)dentry;(void)attr;return 0;}
static inline void bpf_lsm_inode_post_setattr(struct mnt_idmap *idmap,struct dentry *dentry,int ia_valid){(void)idmap;(void)dentry;(void)ia_valid;}
/* An entry's function is its LSM's: every entry in the table is BPF's. */
static inline int osrec_lsm_file_permission(const struct security_hook_list *p,struct file *file,int mask){(void)p;return bpf_lsm_file_permission(file,mask);}
static inline int osrec_lsm_file_fcntl(const struct security_hook_list *p,struct file *file,unsigned int cmd,unsigned long arg){(void)p;return bpf_lsm_file_fcntl(file,cmd,arg);}
static inline int osrec_lsm_file_truncate(const struct security_hook_list *p,struct file *file){(void)p;return bpf_lsm_file_truncate(file);}
static inline int osrec_lsm_inode_setattr(const struct security_hook_list *p,struct mnt_idmap *idmap,struct dentry *dentry,struct iattr *attr){(void)p;return bpf_lsm_inode_setattr(idmap,dentry,attr);}
static inline void osrec_lsm_inode_post_setattr(const struct security_hook_list *p,struct mnt_idmap *idmap,struct dentry *dentry,int ia_valid){(void)p;bpf_lsm_inode_post_setattr(idmap,dentry,ia_valid);}void vm_unacct_memory(long);
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
#define THREAD_SCTLR_USER 96
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
long linux_lseek(unsigned int fd, off_t offset, unsigned int whence);
long linux_pread64(unsigned int fd, char __user * buf, size_t count, loff_t pos);
long linux_pwrite64(unsigned int fd, const char __user * buf, size_t count, loff_t pos);
long linux_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg);
#endif
