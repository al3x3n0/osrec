#include "model.h"
#include "capture.h"
struct user_namespace user_ns={1};
struct fs_struct fs={LINUX_INITIAL_UMASK};
#define INITIAL_CRED(ns) {LINUX_INITIAL_UID,LINUX_INITIAL_EUID,LINUX_INITIAL_SUID,LINUX_INITIAL_EUID,LINUX_INITIAL_GID,LINUX_INITIAL_EGID,LINUX_INITIAL_SGID,LINUX_INITIAL_EGID,(ns)}
struct cred credential_pool[2]={INITIAL_CRED(&user_ns),INITIAL_CRED(&user_ns)};
struct task_struct parent={.pid=LINUX_INITIAL_PPID,.tgid=LINUX_INITIAL_PPID};
struct task_struct task={LINUX_INITIAL_PID,LINUX_INITIAL_TGID,&parent,&fs,&credential_pool[0]};
struct task_struct *current=&task;
struct osrec_user_memory active_memory;
int rcu_depth;
uint64_t credential_generation,credential_slot_generation[2];
struct cred *pending_credential;
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
/* This profile has no effective CAP_SETGID and no rejecting credential hook. */
bool ns_capable_setid(const struct user_namespace *ns,int cap){(void)ns;(void)cap;return false;}
struct cred *prepare_creds(void)
{
    if(pending_credential)return 0;
    struct cred *candidate=current->cred==&credential_pool[0] ? &credential_pool[1] : &credential_pool[0];
    *candidate=*current->cred;pending_credential=candidate;return candidate;
}
int security_task_fix_setgid(struct cred *candidate,const struct cred *old,int flags)
{
    return candidate==pending_credential && old==current->cred && (flags==LSM_SETID_RES || flags==LSM_SETID_FS || flags==LSM_SETID_ID || flags==LSM_SETID_RE) ? 0 : -EINVAL;
}
int commit_creds(struct cred *candidate)
{
    if(candidate!=pending_credential || candidate==current->cred)return -EINVAL;
    current->cred=candidate;++credential_generation;
    credential_slot_generation[candidate==&credential_pool[1]]=credential_generation;
    pending_credential=0;return 0;
}
void abort_creds(struct cred *candidate){if(candidate==pending_credential)pending_credential=0;}
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
