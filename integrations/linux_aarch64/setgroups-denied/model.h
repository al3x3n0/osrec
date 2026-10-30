#ifndef OSREC_LINUX_MODEL_H
#define OSREC_LINUX_MODEL_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "osrec/syscall_slice.h"
typedef uint32_t uid_t;
typedef uint32_t gid_t;
typedef uint32_t kgid_t;
#define EFAULT 14
#define EINVAL 22
/* Preserve the upstream int/unsigned loop without changing its body. */
#pragma clang diagnostic ignored "-Wsign-compare"
#define EPERM 1
#define ENOMEM 12
#define CAP_SETGID 6
#define LSM_SETID_ID 1
#define LSM_SETID_RE 2
#define LSM_SETID_RES 4
#define LSM_SETID_FS 8
#define __user
#define S_IRWXUGO 0777
struct user_namespace {uint32_t initial,setgroups_allowed;};
struct fs_struct {int umask;};
struct group_info {int32_t usage,ngroups;uint32_t gid[4];};
struct cred {uint32_t uid,euid,suid,fsuid,gid,egid,sgid,fsgid,cap_setgid;struct user_namespace *user_ns;struct group_info *group_info;};
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
kgid_t make_kgid(const struct user_namespace *,gid_t);
bool gid_valid(kgid_t);
bool gid_eq(kgid_t,kgid_t);
bool ns_capable_setid(const struct user_namespace *,int);
struct cred *prepare_creds(void);
int security_task_fix_setgid(struct cred *,const struct cred *,int);
int commit_creds(struct cred *);
void abort_creds(struct cred *);
#define NGROUPS_MAX 65536
int linux_get_user_u32(uint32_t *,const uint32_t *);
#define get_user(v,p) linux_get_user_u32(&(v),(p))
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
#endif
