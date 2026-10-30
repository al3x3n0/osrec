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
struct user_namespace {uint32_t initial;};
struct group_info {int32_t usage,ngroups;uint32_t gid[4];};
struct fs_struct {int umask;};
typedef struct kernel_cap {uint64_t val;} kernel_cap_t;
struct cred {uint32_t uid,euid,suid,gid,egid,sgid,fsgid,fsuid,securebits;kernel_cap_t cap_effective,cap_permitted,cap_inheritable,cap_bset,cap_ambient;struct user_namespace *user_ns;struct group_info *group_info;};
struct files_struct;
struct task_struct {int32_t pid,tgid;struct task_struct *real_parent;struct fs_struct *fs;struct cred *cred;struct files_struct *files;};
extern struct task_struct *current;
int task_tgid_vnr(const struct task_struct *);
int task_pid_vnr(const struct task_struct *);
const struct cred *current_cred(void);
struct user_namespace *current_user_ns(void);
uid_t current_uid(void);
uid_t current_euid(void);
uid_t current_fsuid(void);
gid_t current_gid(void);
gid_t current_egid(void);
gid_t current_fsgid(void);
uid_t from_kuid_munged(const struct user_namespace *,uid_t);
gid_t from_kgid_munged(const struct user_namespace *,gid_t);
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
struct vfsmount {uint32_t object_id;int write_depth;};
struct path {struct dentry *dentry;struct vfsmount *mnt;};
struct file {int64_t f_count;uint32_t f_mode,f_flags,object_id;int64_t f_pos;uint64_t f_version;int f_lock;struct path f_path;};
struct fdtable {unsigned int max_fds;struct file *fd[64];uint64_t close_on_exec[1],open_fds[1],full_fds_bits[1];};
struct files_struct {struct fdtable *fdt;struct fdtable fdtab;unsigned int next_fd;int file_lock,resize_in_progress;};
#define __rcu
#define __releases(p)
#define BITS_PER_LONG 64
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
unsigned long find_next_zero_bit(const unsigned long *,unsigned long,unsigned long);
unsigned long array_index_mask_nospec(unsigned long,unsigned long);
unsigned int array_index_nospec(unsigned int,unsigned int);
struct fdtable *files_fdtable(struct files_struct *);
int expand_files(struct files_struct *,unsigned int);
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
int filp_flush(struct file *,fl_owner_t);
long linux_dup(unsigned int);
long linux_dup3(unsigned int,unsigned int,int);
long linux_close(unsigned int);
typedef int64_t loff_t;
typedef int64_t off_t;
typedef int64_t ssize_t;
struct fd {struct file *file;unsigned int flags;};
struct file_data {int64_t size;uint8_t bytes[64];};
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
struct fd fdget_pos(unsigned int);
void fdput_pos(struct fd);
ssize_t vfs_read(struct file *,char *,size_t,loff_t *);
ssize_t vfs_write(struct file *,const char *,size_t,loff_t *);
loff_t vfs_llseek(struct file *,loff_t,int);
loff_t generic_file_llseek_size(struct file *,loff_t,int,loff_t,loff_t);
int rw_verify_area(int,struct file *,const loff_t *,size_t);
int security_file_permission(struct file *,int);
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
struct super_block {int write_depth;};
struct inode {uint32_t i_mode,append;struct super_block *i_sb;uint32_t dev,rdev,nlink,uid,gid,blksize;uint64_t ino,blocks;int lock_depth;};
struct dentry {struct inode *d_inode;};
#define S_ISREG(mode) (((mode)&0170000)==0100000)
#define IS_APPEND(inode) ((inode)->append)
struct fd fdget(unsigned int);
void fdput(struct fd);
struct inode *file_inode(struct file *);
void sb_start_write(struct super_block *);
void sb_end_write(struct super_block *);
int security_file_truncate(struct file *);
void *file_mnt_idmap(struct file *);
int do_truncate(void *,struct dentry *,loff_t,unsigned int,struct file *);
long linux_ftruncate(unsigned int,off_t);
long linux_pread64(unsigned int,char *,size_t,loff_t);
long linux_pwrite64(unsigned int,const char *,size_t,loff_t);
bool close_on_exec(unsigned int,struct files_struct *);
void set_close_on_exec(unsigned int,int);
bool get_close_on_exec(unsigned int);
int f_dupfd(unsigned int,struct file *,unsigned);
long linux_fcntl(unsigned int,unsigned int,unsigned long);
#define CLOSE_RANGE_UNSHARE (1U<<1)
#define CLOSE_RANGE_CLOEXEC (1U<<2)
#define NR_OPEN_MAX ~0U
#define CLONE_FILES 0x00000400
#define min(a,b) ((a)<(b) ? (a) : (b))
#define swap(a,b) do { __typeof__(a) temporary=(a); (a)=(b); (b)=temporary; } while(0)
void bitmap_set(uint64_t *,unsigned int,unsigned int);
void cond_resched(void);
bool need_resched(void);
int unshare_fd(unsigned long,unsigned int,struct files_struct **);
void task_lock(struct task_struct *);
void task_unlock(struct task_struct *);
void put_files_struct(struct files_struct *);
long linux_close_range(unsigned int,unsigned int,unsigned int);
#include "upstream_stat.h"
typedef uint32_t u32;
struct timespec64 {int64_t tv_sec,tv_nsec;};
struct kstat {uint32_t dev,rdev,mode,nlink,uid,gid,blksize;uint64_t ino,blocks;int64_t size;struct timespec64 atime,mtime,ctime;};
#define STATX_BASIC_STATS 0x7ff
#define AT_GETATTR_NOSEC 0x80000000u
#define INIT_STRUCT_STAT_PADDING(st) memset(&(st),0,sizeof(st))
#define SET_UID(out,value) ((out)=(value))
#define SET_GID(out,value) ((out)=(value))
_Static_assert(sizeof(struct stat)==128 && offsetof(struct stat,st_size)==48 && offsetof(struct stat,st_blocks)==64 && offsetof(struct stat,st_atime)==72 && offsetof(struct stat,__unused4)==120,"AArch64 stat ABI");
void *memset(void *,int,size_t);
bool old_valid_dev(uint32_t);
uint32_t new_encode_dev(uint32_t);
struct fd fdget_raw(unsigned int);
int security_inode_getattr(const struct path *);
int vfs_getattr_nosec(const struct path *,struct kstat *,u32,unsigned int);
unsigned long copy_to_user(void *,const void *,unsigned long);
long linux_newfstat(unsigned int,struct stat *);
typedef uint16_t umode_t;
struct mnt_idmap {uint32_t initial;};
struct iattr {uint32_t ia_mode,ia_valid,ia_vfsuid,ia_vfsgid;};
#define S_IALLUGO 07777
#define ATTR_MODE 1u
int mnt_want_write(struct vfsmount *);
void mnt_drop_write(struct vfsmount *);
struct mnt_idmap *mnt_idmap(struct vfsmount *);
void inode_lock(struct inode *);
void inode_unlock(struct inode *);
int security_path_chmod(const struct path *,umode_t);
int notify_change(struct mnt_idmap *,struct dentry *,struct iattr *,struct inode **);
int break_deleg_wait(struct inode **);
void audit_file(struct file *);
long linux_fchmod(unsigned int,umode_t);
typedef uint32_t kuid_t;
typedef uint32_t kgid_t;
typedef uint32_t vfsuid_t;
typedef uint32_t vfsgid_t;
#define INVALID_VFSUID UINT32_MAX
#define INVALID_VFSGID UINT32_MAX
#define VFSUIDT_INIT(v) (v)
#define VFSGIDT_INIT(v) (v)
#define ATTR_UID (1u<<1)
#define ATTR_GID (1u<<2)
#define ATTR_KILL_SUID (1u<<11)
#define ATTR_KILL_PRIV (1u<<14)
#define S_ISDIR(mode) (((mode)&0170000)==0040000)
#define uid_valid(v) ((v)!=UINT32_MAX)
kuid_t make_kuid(const struct user_namespace *,uid_t);
kgid_t make_kgid(const struct user_namespace *,gid_t);
struct user_namespace *i_user_ns(struct inode *);
int setattr_should_drop_sgid(struct mnt_idmap *,struct inode *);
kuid_t from_vfsuid(struct mnt_idmap *,struct user_namespace *,vfsuid_t);
kgid_t from_vfsgid(struct mnt_idmap *,struct user_namespace *,vfsgid_t);
int security_path_chown(const struct path *,kuid_t,kgid_t);
int mnt_want_write_file(struct file *);
void mnt_drop_write_file(struct file *);
long linux_fchown(unsigned int,uid_t,gid_t);
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t pid_t;
#include "upstream_capability.h"
#define CAP_SETPCAP 8
#define CAP_OPT_NONE 0
#define CAP_VALID_MASK UINT64_C(2199023255551)
#define _KERNEL_CAPABILITY_VERSION _LINUX_CAPABILITY_VERSION_3
#define fallthrough __attribute__((fallthrough))
#define WARN_ON(v) (v)
kernel_cap_t cap_combine(kernel_cap_t,kernel_cap_t);
kernel_cap_t cap_intersect(kernel_cap_t,kernel_cap_t);
bool cap_issubset(kernel_cap_t,kernel_cap_t);
bool cap_ambient_invariant_ok(const struct cred *);
int cap_capable(const struct cred *,const struct user_namespace *,int,unsigned);
int cap_capset(struct cred *,const struct cred *,const kernel_cap_t *,const kernel_cap_t *,const kernel_cap_t *);
int security_capset(struct cred *,const struct cred *,const kernel_cap_t *,const kernel_cap_t *,const kernel_cap_t *);
void audit_log_capset(const struct cred *,const struct cred *);
void warn_legacy_capability_use(void);
void warn_deprecated_v2(void);
unsigned long linux_copy_from_user(void *,const void *,unsigned long);
#define copy_from_user(out,in,n) linux_copy_from_user((out),(in),(n))
#undef get_user
#define get_user(v,p) linux_get_user_u32((uint32_t *)&(v),(const uint32_t *)(p))
long linux_capset(cap_user_header_t,const cap_user_data_t);

#define ENOMEM 12
struct cred *prepare_creds(void);
int commit_creds(struct cred *);
void abort_creds(struct cred *);
int linux_get_user_u32(uint32_t *,const uint32_t *);
#define LSM_SETID_FS 8
bool gid_valid(kgid_t);
bool gid_eq(kgid_t,kgid_t);
bool ns_capable_setid(const struct user_namespace *,int);
int security_task_fix_setgid(struct cred *,const struct cred *,int);
long linux_setfsgid(gid_t);
#define LSM_SETID_ID 1
#define LSM_SETID_RE 2
#define LSM_SETID_RES 4
#include "upstream_securebits.h"
#define issecure(bit) (current_cred()->securebits & issecure_mask(bit))
#define cap_clear(set) ((set).val=0)
#define BIT_ULL(bit) (UINT64_C(1)<<(bit))
#include "upstream_fs_capability.h"
bool uid_eq(kuid_t,kuid_t);
int cap_task_fix_setuid(struct cred *,const struct cred *,int);
int security_task_fix_setuid(struct cred *,const struct cred *,int);
long linux_setfsuid(uid_t);
#define NGROUPS_MAX 65536
bool userns_may_setgroups(const struct user_namespace *);
struct group_info *groups_alloc(int);
void get_group_info(struct group_info *);
void put_group_info(struct group_info *);
void groups_sort(struct group_info *);
int security_task_fix_setgroups(struct cred *,const struct cred *);
void set_groups(struct cred *,struct group_info *);
int set_current_groups(struct group_info *);
bool may_setgroups(void);
long linux_getgroups(int,gid_t *);
long linux_setgroups(int,gid_t *);

bool linux_in_supplementary_group(kgid_t);
#endif
