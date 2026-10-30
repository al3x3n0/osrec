#include "model.h"
#include "capture.h"
/* Reviewed state projection; not Linux's physical task_struct layout. */
struct user_namespace user_ns={1};
struct fs_struct fs={LINUX_INITIAL_UMASK};
struct cred creds={LINUX_INITIAL_UID,LINUX_INITIAL_EUID,LINUX_INITIAL_SUID,LINUX_INITIAL_GID,LINUX_INITIAL_EGID,LINUX_INITIAL_SGID,&user_ns};
struct task_struct parent={.pid=LINUX_INITIAL_PPID,.tgid=LINUX_INITIAL_PPID};
struct file file_pool[2]={{3,0,LINUX_INITIAL_FILE_FLAGS_0,1},{1,0,LINUX_INITIAL_FILE_FLAGS_1,2}};
#define INITIAL_FILES(table,console,seed) {table,{64,{console,console,console,seed},{8},{15},{0}},4,0,0}
struct files_struct files=INITIAL_FILES(&files.fdtab,&file_pool[0],&file_pool[1]);
struct task_struct task={LINUX_INITIAL_PID,LINUX_INITIAL_TGID,&parent,&fs,&creds,&files};
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

/* Reviewed sequential ownership/locking/flush boundaries. No host consumers. */
int model_fault;
int linux_assert(int failure){if(failure)model_fault=1;return !!failure;}
void spin_lock(int *lock){linux_assert(*lock!=0);++*lock;}
void spin_unlock(int *lock){linux_assert(*lock!=1);--*lock;}
void lockdep_assert_held(const int *lock){linux_assert(*lock!=1);}
unsigned long find_next_zero_bit(const unsigned long *bits,unsigned long size,unsigned long start){for(unsigned long i=start;i<size;++i)if(!(bits[i/64]&(1ul<<(i%64))))return i;return size;}
unsigned long array_index_mask_nospec(unsigned long index,unsigned long size){return index<size ? ~0ul : 0;}
unsigned int array_index_nospec(unsigned int index,unsigned int size){linux_assert(index>=size);return index<size ? index : 0;}
struct fdtable *files_fdtable(struct files_struct *p){return p->fdt;}
int expand_files(struct files_struct *p,unsigned int fd){linux_assert(p!=current->files || p->resize_in_progress);return fd<64 ? 0 : -EMFILE;}
unsigned long rlimit(unsigned int resource){linux_assert(resource!=RLIMIT_NOFILE);return 8;}
void __set_open_fd(unsigned int fd,struct fdtable *t){t->open_fds[fd/64]|=1ul<<(fd%64);if(t->open_fds[fd/64]==~0ul)t->full_fds_bits[0]|=1ul<<(fd/64);}
void __clear_open_fd(unsigned int fd,struct fdtable *t){t->open_fds[fd/64]&=~(1ul<<(fd%64));t->full_fds_bits[0]&=~(1ul<<(fd/64));}
void __set_close_on_exec(unsigned int fd,struct fdtable *t){t->close_on_exec[fd/64]|=1ul<<(fd%64);}
void __clear_close_on_exec(unsigned int fd,struct fdtable *t){t->close_on_exec[fd/64]&=~(1ul<<(fd%64));}
int fd_is_open(unsigned int fd,const struct fdtable *t){return !!(t->open_fds[fd/64]&(1ul<<(fd%64)));}
struct file *files_lookup_fd_locked(struct files_struct *p,unsigned int fd){lockdep_assert_held(&p->file_lock);return fd<p->fdt->max_fds ? p->fdt->fd[fd] : 0;}
int atomic_long_inc_not_zero(int64_t *count){if(!*count)return 0;linux_assert(*count<0);++*count;return 1;}
struct file *get_file(struct file *p){linux_assert(!p || p->f_count<=0);if(p)++p->f_count;return p;}
void fput(struct file *p){linux_assert(!p || p->f_count<=0);if(p)--p->f_count;}
void __fput_sync(struct file *p){fput(p);}
int filp_flush(struct file *p,fl_owner_t owner){linux_assert(!p || p->f_count<=0 || owner!=current->files);return 0;}

void rcu_read_lock_sched(void){rcu_read_lock();}
void rcu_read_unlock_sched(void){rcu_read_unlock();}
