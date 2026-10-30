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
/* f_mode projects only the consumed BACKING bit; admitted objects have none. */
struct file {int64_t f_count;uint32_t f_mode,f_flags,object_id;};
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
#endif
