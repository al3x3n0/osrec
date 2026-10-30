#include "model.h"
#include "capture.h"
struct user_namespace user_ns={1,1};
struct user_struct user_pool[4]={{1001,1},{0,0},{9001,0},{9002,0}};
struct ucounts ucounts_pool[4]={{&user_ns,1001,1},{&user_ns,0,0},{&user_ns,9001,0},{&user_ns,9002,0}};
struct fs_struct fs={LINUX_INITIAL_UMASK};
struct group_info group_pool[2]={{1,LINUX_INITIAL_NGROUPS,{LINUX_INITIAL_GROUP_0,LINUX_INITIAL_GROUP_1,LINUX_INITIAL_GROUP_2,LINUX_INITIAL_GROUP_3}},{0}};
#define INITIAL_CRED(ns,groups,usr,acct) {LINUX_INITIAL_UID,LINUX_INITIAL_EUID,LINUX_INITIAL_SUID,LINUX_INITIAL_FSUID,LINUX_INITIAL_GID,LINUX_INITIAL_EGID,LINUX_INITIAL_SGID,LINUX_INITIAL_EGID,LINUX_INITIAL_SECUREBITS,{LINUX_INITIAL_CAP_EFFECTIVE},{LINUX_INITIAL_CAP_PERMITTED},{LINUX_INITIAL_CAP_INHERITABLE},{LINUX_INITIAL_CAP_BSET},{LINUX_INITIAL_CAP_AMBIENT},(ns),(groups),(usr),(acct)}
struct cred credential_pool[2]={INITIAL_CRED(&user_ns,&group_pool[0],&user_pool[0],&ucounts_pool[0]),INITIAL_CRED(&user_ns,&group_pool[0],&user_pool[0],&ucounts_pool[0])};
struct task_struct parent={.pid=LINUX_INITIAL_PPID,.tgid=LINUX_INITIAL_PPID};
struct task_struct task={LINUX_INITIAL_PID,LINUX_INITIAL_TGID,&parent,&fs,&credential_pool[0],0};
struct task_struct *current=&task;
struct osrec_user_memory active_memory;
int rcu_depth;
uint64_t credential_generation,credential_slot_generation[2];
struct cred *pending_credential;
struct group_info *allocated_group;
int task_tgid_vnr(const struct task_struct *p){return p->tgid;}
int task_pid_vnr(const struct task_struct *p){return p->pid;}
const struct cred *current_cred(void){return current->cred;}
struct user_namespace *current_user_ns(void){return current_cred()->user_ns;}
uid_t current_uid(void){return current_cred()->uid;}
uid_t current_euid(void){return current_cred()->euid;}
gid_t current_gid(void){return current_cred()->gid;}
gid_t current_egid(void){return current_cred()->egid;}
uid_t from_kuid_munged(const struct user_namespace *ns,uid_t v){return ns->initial ? v : 65534;}
gid_t from_kgid_munged(const struct user_namespace *ns,gid_t v){return ns->initial ? v : 65534;}
kgid_t make_kgid(const struct user_namespace *ns,gid_t v){return ns->initial ? v : UINT32_MAX;}
bool gid_valid(kgid_t v){return v!=UINT32_MAX;}
bool gid_eq(kgid_t a,kgid_t b){return a==b;}
/* Admission observes this effective bit through native capget. */
bool ns_capable_setid(const struct user_namespace *ns,int cap){return ns==current_cred()->user_ns && ns->initial && (cap==CAP_SETGID || cap==CAP_SETUID) && (current_cred()->cap_effective.val&(UINT64_C(1)<<cap))!=0;}
bool userns_may_setgroups(const struct user_namespace *ns){return ns->setgroups_allowed!=0;}
struct cred *prepare_creds(void)
{
    if(pending_credential)return 0;
    struct cred *candidate=current->cred==&credential_pool[0] ? &credential_pool[1] : &credential_pool[0];
    *candidate=*current->cred;get_group_info(candidate->group_info);get_uid(candidate->user);get_ucounts(candidate->ucounts);pending_credential=candidate;return candidate;
}
int security_task_fix_setgroups(struct cred *candidate,const struct cred *old)
{
    return candidate==pending_credential && old==current->cred ? 0 : -EINVAL;
}
int commit_creds(struct cred *candidate)
{
    if(candidate!=pending_credential || candidate==current->cred)return -EINVAL;
    put_group_info(current->cred->group_info);free_uid(current->cred->user);put_ucounts(current->cred->ucounts);current->cred=candidate;++credential_generation;
    credential_slot_generation[candidate==&credential_pool[1]]=credential_generation;
    pending_credential=0;return 0;
}
void abort_creds(struct cred *candidate){if(candidate==pending_credential){put_group_info(candidate->group_info);free_uid(candidate->user);put_ucounts(candidate->ucounts);pending_credential=0;}}
void rcu_read_lock(void){++rcu_depth;}
void rcu_read_unlock(void){--rcu_depth;}
int linux_xchg_int(int *p,int v){int old=*p;*p=v;return old;}
int linux_put_user_u32(uint32_t value,uint32_t *p)
{
    const struct osrec_user_region *r=osrec_user_memory_object(&active_memory,1,32,3);
    if(!r || (uintptr_t)p<r->user_address || (uintptr_t)p-r->user_address>28)return -14;
    unsigned char *target=osrec_user_memory_resolve(&active_memory,(uintptr_t)p,4,OSREC_MEMORY_WRITE);
    if(!target)return -14;
    for(unsigned i=0;i<4;++i)target[i]=(unsigned char)(value>>(8*i));
    return 0;
}

/* Inactive credentials retain non-owning last-copy pointers. Only the active
 * credential, a prepared candidate and a caller allocation own model refs. */
struct group_info *groups_alloc(int count)
{
    if(allocated_group || count<0 || count>4)return 0;
    for(unsigned i=0;i<2;++i)if(!group_pool[i].usage){
        struct group_info *p=&group_pool[i];p->usage=1;p->ngroups=count;
        for(unsigned j=0;j<4;++j)p->gid[j]=0;
        allocated_group=p;return p;
    }
    return 0;
}
void get_group_info(struct group_info *p){++p->usage;}
void put_group_info(struct group_info *p){--p->usage;if(p==allocated_group)allocated_group=0;}
/* Reviewed replacement for Linux sort's indirect comparator dependency. */
void groups_sort(struct group_info *p)
{
    for(int i=1;i<p->ngroups;++i){uint32_t v=p->gid[i];int j=i;
        while(j>0 && p->gid[j-1]>v){p->gid[j]=p->gid[j-1];--j;}p->gid[j]=v;}
}
int linux_get_user_u32(uint32_t *value,const uint32_t *p)
{
    const struct osrec_user_region *r=osrec_user_memory_object(&active_memory,1,32,3);
    if(!r || (uintptr_t)p<r->user_address || (uintptr_t)p-r->user_address>28)return -EFAULT;
    const unsigned char *source=osrec_user_memory_resolve(&active_memory,(uintptr_t)p,4,OSREC_MEMORY_READ);
    if(!source)return -EFAULT;
    uint32_t v=0;for(unsigned i=0;i<4;++i)v|=(uint32_t)source[i]<<(8*i);*value=v;return 0;
}

kernel_cap_t cap_combine(kernel_cap_t a,kernel_cap_t b){return (kernel_cap_t){a.val|b.val};}
kernel_cap_t cap_intersect(kernel_cap_t a,kernel_cap_t b){return (kernel_cap_t){a.val&b.val};}
bool cap_issubset(kernel_cap_t a,kernel_cap_t b){return (a.val&~b.val)==0;}
bool cap_ambient_invariant_ok(const struct cred *p){return (p->cap_ambient.val&~(p->cap_permitted.val&p->cap_inheritable.val))==0;}
int cap_capable(const struct cred *p,const struct user_namespace *ns,int cap,unsigned options)
{
    (void)options;return ns==p->user_ns && ns->initial && cap>=0 && cap<=40 && (p->cap_effective.val&(UINT64_C(1)<<cap)) ? 0 : -EPERM;
}
int security_capset(struct cred *candidate,const struct cred *old,const kernel_cap_t *e,const kernel_cap_t *i,const kernel_cap_t *p)
{
    if(candidate!=pending_credential || old!=current->cred)return -EINVAL;
    return cap_capset(candidate,old,e,i,p);
}
/* Capture/replay has no external audit or warning consumer. */
void audit_log_capset(const struct cred *candidate,const struct cred *old){(void)candidate;(void)old;}
void warn_legacy_capability_use(void){}
void warn_deprecated_v2(void){}
unsigned long linux_copy_from_user(void *out,const void *in,unsigned long n)
{
    const struct osrec_user_region *r=osrec_user_memory_object(&active_memory,1,32,3);
    unsigned char *destination=out;
    for(unsigned long j=0;j<n;++j){
        uintptr_t at=(uintptr_t)in+j;
        const unsigned char *source=r && at>=r->user_address && at-r->user_address<32 ? osrec_user_memory_resolve(&active_memory,at,1,OSREC_MEMORY_READ) : 0;
        if(!source){for(unsigned long k=j;k<n;++k)destination[k]=0;return n-j;}
        destination[j]=*source;
    }
    return 0;
}

/* The admitted foreign PID is INT32_MAX and cannot identify a live task. */
struct task_struct *find_task_by_vpid(pid_t pid){return pid==current->pid ? current : 0;}
int security_capget(const struct task_struct *target,kernel_cap_t *e,kernel_cap_t *i,kernel_cap_t *p)
{
    if(target!=current)return -ESRCH;
    return cap_capget(target,e,i,p);
}
unsigned long linux_copy_to_user(void *out,const void *in,unsigned long n)
{
    const struct osrec_user_region *r=osrec_user_memory_object(&active_memory,1,32,3);
    const unsigned char *source=in;
    for(unsigned long j=0;j<n;++j){
        uintptr_t at=(uintptr_t)out+j;
        unsigned char *destination=r && at>=r->user_address && at-r->user_address<32 ? osrec_user_memory_resolve(&active_memory,at,1,OSREC_MEMORY_WRITE) : 0;
        if(!destination)return n-j;
        *destination=source[j];
    }
    return 0;
}

/* Reviewed initial-namespace effective capability check. Auditing and the
 * PF_SUPERPRIV scheduling hint have no consumer in this sequential domain. */
bool ns_capable(const struct user_namespace *ns,int cap)
{
    return cap_capable(current_cred(),ns,cap,CAP_OPT_NONE)==0;
}

kuid_t make_kuid(const struct user_namespace *ns,uid_t uid){return ns->initial ? uid : UINT32_MAX;}
bool uid_valid(kuid_t uid){return uid!=UINT32_MAX;}
bool uid_eq(kuid_t a,kuid_t b){return a==b;}
int security_task_fix_setuid(struct cred *candidate,const struct cred *old,int flags)
{
    if(candidate!=pending_credential || old!=current->cred || (flags!=LSM_SETID_FS && flags!=LSM_SETID_RES && flags!=LSM_SETID_ID && flags!=LSM_SETID_RE))return -EINVAL;
    return cap_task_fix_setuid(candidate,old,flags);
}

/* Fixed admitted UID identities; counts describe model credential ownership,
 * not native slab/RCU lifetime or physical process counts. */
struct user_struct *alloc_uid(kuid_t uid)
{
    for(unsigned i=0;i<4;++i)if(user_pool[i].uid==uid){get_uid(&user_pool[i]);return &user_pool[i];}
    return 0;
}
void get_uid(struct user_struct *p){++p->usage;}
void free_uid(struct user_struct *p){--p->usage;}
struct ucounts *alloc_ucounts(struct user_namespace *ns,kuid_t uid)
{
    for(unsigned i=0;i<4;++i)if(ucounts_pool[i].ns==ns && ucounts_pool[i].uid==uid){get_ucounts(&ucounts_pool[i]);return &ucounts_pool[i];}
    return 0;
}
void get_ucounts(struct ucounts *p){++p->usage;}
void put_ucounts(struct ucounts *p){--p->usage;}
struct ucounts *current_ucounts(void){return current_cred()->ucounts;}
/* The reviewed sequential task has an unlimited NPROC limit. Exec/fork and
 * external accounting consumers are outside this profile. */
uint64_t rlimit(int resource){(void)resource;return UINT64_MAX;}
bool is_rlimit_overlimit(const struct ucounts *p,int type,uint64_t limit){(void)p;(void)type;(void)limit;return false;}

/* No additional rejecting group-ID LSM hook is admitted. Linux commoncap
 * has no group-ID capability fixup; effective SETGID admission remains live. */
int security_task_fix_setgid(struct cred *candidate,const struct cred *old,int flags)
{
    return candidate==pending_credential && old==current->cred && (flags==LSM_SETID_ID || flags==LSM_SETID_RE || flags==LSM_SETID_RES || flags==LSM_SETID_FS) ? 0 : -EINVAL;
}
