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
struct fs_struct {int umask;};
struct cred {uint32_t uid,euid,suid,gid,egid,sgid;struct user_namespace *user_ns;};
struct files_struct;
struct task_struct {int32_t pid,tgid;struct task_struct *real_parent;struct fs_struct *fs;struct cred *cred;struct files_struct *files;};
extern struct task_struct *current;
int task_tgid_vnr(const struct task_struct *);
int task_pid_vnr(const struct task_struct *);
const struct cred *current_cred(void);
struct user_namespace *current_user_ns(void);
uid_t current_uid(void);
uid_t current_euid(void);
gid_t current_gid(void);
gid_t current_egid(void);
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
struct iattr {uint32_t ia_mode,ia_valid;};
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
#endif
