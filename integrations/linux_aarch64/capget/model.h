#ifndef OSREC_LINUX_MODEL_H
#define OSREC_LINUX_MODEL_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "osrec/syscall_slice.h"
typedef uint32_t uid_t;
typedef uint32_t gid_t;
typedef uint32_t kgid_t;
#define ESRCH 3
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
typedef struct kernel_cap {uint64_t val;} kernel_cap_t;
struct cred {uint32_t uid,euid,suid,fsuid,gid,egid,sgid,fsgid;kernel_cap_t cap_effective,cap_permitted,cap_inheritable,cap_bset,cap_ambient;struct user_namespace *user_ns;struct group_info *group_info;};
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
#define __task_cred(p) ((p)->cred)
struct task_struct *find_task_by_vpid(pid_t);
int cap_capget(const struct task_struct *,kernel_cap_t *,kernel_cap_t *,kernel_cap_t *);
int security_capget(const struct task_struct *,kernel_cap_t *,kernel_cap_t *,kernel_cap_t *);
unsigned long linux_copy_to_user(void *,const void *,unsigned long);
#define copy_to_user(out,in,n) linux_copy_to_user((out),(in),(n))
long linux_capget(cap_user_header_t,cap_user_data_t);
#endif
