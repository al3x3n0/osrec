#ifndef OSREC_LINUX_MODEL_H
#define OSREC_LINUX_MODEL_H
#include <stdint.h>
#include <stddef.h>
#include "osrec/syscall_slice.h"
typedef uint32_t uid_t;
typedef uint32_t gid_t;
#define __user
#define S_IRWXUGO 0777
struct user_namespace {uint32_t initial;};
struct fs_struct {int umask;};
struct cred {uint32_t uid,euid,suid,gid,egid,sgid;struct user_namespace *user_ns;};
struct task_struct {int32_t pid,tgid;struct task_struct *real_parent;struct fs_struct *fs;struct cred *cred;};
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
#endif
