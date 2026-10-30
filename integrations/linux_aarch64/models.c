#include "model.h"
#include "capture.h"
/* Reviewed state projection; not Linux's physical task_struct layout. */
struct user_namespace user_ns={1};
struct fs_struct fs={LINUX_INITIAL_UMASK};
struct cred creds={LINUX_INITIAL_UID,LINUX_INITIAL_EUID,LINUX_INITIAL_SUID,LINUX_INITIAL_GID,LINUX_INITIAL_EGID,LINUX_INITIAL_SGID,&user_ns};
struct task_struct parent={.pid=LINUX_INITIAL_PPID,.tgid=LINUX_INITIAL_PPID};
struct task_struct task={LINUX_INITIAL_PID,LINUX_INITIAL_TGID,&parent,&fs,&creds};
struct task_struct *current=&task;
struct osrec_user_memory active_memory;
int rcu_depth;
int task_tgid_vnr(const struct task_struct *p){return p->tgid;}
int task_pid_vnr(const struct task_struct *p){return p->pid;}
const struct cred *current_cred(void){return current->cred;}
struct user_namespace *current_user_ns(void){return current_cred()->user_ns;}
uid_t current_uid(void){return current_cred()->uid;}
uid_t current_euid(void){return current_cred()->euid;}
gid_t current_gid(void){return current_cred()->gid;}
gid_t current_egid(void){return current_cred()->egid;}
uid_t from_kuid_munged(const struct user_namespace *ns,uid_t value){return ns->initial ? value : 65534;}
gid_t from_kgid_munged(const struct user_namespace *ns,gid_t value){return ns->initial ? value : 65534;}
void rcu_read_lock(void){++rcu_depth;}
void rcu_read_unlock(void){--rcu_depth;}
int linux_xchg_int(int *p,int value){int old=*p;*p=value;return old;}
int linux_put_user_u32(uint32_t value,uint32_t *p)
{
    const struct osrec_user_region *r=osrec_user_memory_object(&active_memory,1,32,3);
    if(!r || (uintptr_t)p<r->user_address || (uintptr_t)p-r->user_address>28)return -14;
    unsigned char *target=osrec_user_memory_resolve(&active_memory,(uintptr_t)p,4,OSREC_MEMORY_WRITE);
    if(!target)return -14;
    for(unsigned i=0;i<4;++i)target[i]=(unsigned char)(value>>(8*i));
    return 0;
}
