#include "sys/stat.h"
#include "sys/kstat.h"
#include "stdarg.h"
#include "los_vm_map.h"
#include "los_mux.h"
#include "string.h"
#include "stddef.h"
extern int __real_GetAssociatedSystemFd(int);
extern int __real_AllocProcessFd(void);
extern void __real_AssociateSystemFd(int,int);
extern void __real_FreeProcessFd(int);
extern int __real_DisassociateProcessFd(int);
extern int __real_close(int);
extern void __real_files_refer(int);
extern size_t __real_LOS_ArchCopyFromUser(void *,const void *,size_t);
extern size_t __real_LOS_ArchCopyToUser(void *,const void *,size_t);
extern UINT32 __real_LOS_MemFree(void *,void *);
extern int __real_UserPathCopy(const char *,char **);
extern void __real_SetCloexecFlag(int);
extern void __real_ClearCloexecFlag(int);
extern int __real_CheckProcessFd(int);
extern int __real_AllocSpecifiedProcessFd(int);
extern int __real_do_open(int,const char *,int,mode_t);
extern ssize_t __real_write(int,const void *,size_t);
extern off64_t __real__lseek64(int,int,int,off64_t *,int);
extern int __real_fstat(int,struct stat *);
extern int __real_fstat64(int,struct stat *);
extern int __real_stat(const char *,struct stat *);
extern int __real_CheckRegion(const LosVmSpace *,VADDR_T,size_t);
extern UINT32 __real_LOS_MuxLock(LosMux *,UINT32);
extern UINT32 __real_LOS_MuxUnlock(LosMux *);
extern int __real_SysOpen(const char *,int,...);
extern int __real_SysOpenat(int,const char *,int,...);
extern ssize_t __real_SysWrite(int,const void *,size_t);
extern off64_t __real_SysLseek64(int,int,int,off64_t *,int);
extern int __real_SysFstat64(int,struct kstat *);
extern int __real_SysStat(const char *,struct kstat *);
extern int __real_SysDup2(int,int);
extern int __real_SysClose(int);
/* Reviewed single-process file-session capture. Provider internals are forwarded with tracing suppressed. */
#ifdef OSREC_FILE_CAPTURE
#define FILE_CALL_COUNT 32
#define FILE_EVENT_CAPACITY 192
struct file_event {UINT32 invocation,kind,a,b,c,raw,error,length,before[15],after[15];unsigned char data[192];};
static struct file_event file_events[FILE_EVENT_CAPACITY];
static UINT32 file_steps[FILE_CALL_COUNT][42];
static unsigned file_active,file_busy,file_calls,file_event_count;
static struct file *file_objects[2];
static char *file_allocated_path;
static unsigned file_dep(void){return file_active && !file_busy;}
static unsigned file_run(void){return owner>=0 && index==4 && file_calls<FILE_CALL_COUNT && (int)__real_LOS_GetCurrProcessID()==owner;}
static UINT32 file_pointer(const void *p){return !p ? 0 : (UINTPTR)p==1 ? 2 : 1;}
static UINT32 file_path_kind(const char *path,unsigned user)
{
    if(!path)return 0;if((UINTPTR)path==1)return 3;
    char text[64];unsigned i;
    for(i=0;i<63;++i){if(user)check(__real_LOS_ArchCopyFromUser(text+i,path+i,1)==0);else text[i]=path[i];if(!text[i])break;}
    check(i<63);
    return strcmp(text,"/dev/shm/osrec-file.bin")==0 ? 1 : strcmp(text,"/dev/shm/osrec-missing.bin")==0 ? 2 : 4;
}
static void file_state(UINT32 *out)
{
    int saved=errno;unsigned busy=file_busy;file_busy=1;
    struct fd_table_s *table=GetFdTable();check(table && table->max_fds>6 && table->max_fds<=1024);
    FileTableLock(table);
    for(unsigned i=0;i<3;++i){unsigned fd=4+i;out[3*i]=table->ft_fds[fd].sysFd;out[3*i+1]=FD_ISSET(fd,table->proc_fds) ? 1 : 0;out[3*i+2]=FD_ISSET(fd,table->cloexec_fds) ? 1 : 0;}
    FileTableUnLock(table);
    for(unsigned i=0;i<2;++i){struct file *f=file_objects[i];UINT64 pos=f && f->f_refcount ? (UINT64)f->f_pos : 0;
        out[9+3*i]=f ? f->f_refcount : 0;out[10+3*i]=(UINT32)pos;out[11+3*i]=pos>>32;}
    file_busy=busy;errno=saved;
}
static struct file_event *file_begin(UINT32 kind,UINT32 a,UINT32 b,UINT32 c)
{
    check(file_dep() && file_event_count<FILE_EVENT_CAPACITY && kernel_mode()==0x113);
    struct file_event *e=&file_events[file_event_count++];e->invocation=file_calls;e->kind=kind;e->a=a;e->b=b;e->c=c;file_state(e->before);file_busy=1;return e;
}
static void file_end(struct file_event *e,UINT32 raw,const void *data,unsigned size)
{
    check(size<=192);e->raw=raw;e->error=errno;e->length=size;
    for(unsigned j=0;j<192;++j)e->data[j]=j<size ? ((const unsigned char *)data)[j] : 0;
    file_state(e->after);file_busy=0;
}
static void file_root_begin(UINT32 number,UINT32 a,UINT32 b,UINT32 c,UINT32 d,UINT32 e)
{
    check(file_run() && !file_active);UINT32 *row=file_steps[file_calls];row[0]=number;row[1]=a;row[2]=b;row[3]=c;row[4]=d;row[5]=e;
    file_state(row+12);file_active=1;
}
static UINT32 file_root_end(UINT32 raw)
{
    UINT32 *row=file_steps[file_calls];row[6]=raw;row[7]=errno;row[8]=kernel_mode();
    row[9]=sizeof(struct stat);row[10]=sizeof(struct kstat);row[11]=offsetof(struct stat,st_size);
    file_state(row+27);file_active=0;++file_calls;return raw;
}
static int file_lookup(int fd){struct file_event *e=file_begin(7,fd,0,0);int ret=__real_GetAssociatedSystemFd(fd);file_end(e,ret,NULL,0);return ret;}
static int file_allocate(void){struct file_event *e=file_begin(2,0,0,0);int ret=__real_AllocProcessFd();file_end(e,ret,NULL,0);return ret;}
static void file_associate(int fd,int sys){struct file_event *e=file_begin(5,fd,sys,0);__real_AssociateSystemFd(fd,sys);file_end(e,0,NULL,0);}
static void file_free_fd(int fd){struct file_event *e=file_begin(16,fd,0,0);__real_FreeProcessFd(fd);file_end(e,0,NULL,0);}
static int file_detach(int fd){struct file_event *e=file_begin(14,fd,0,0);int ret=__real_DisassociateProcessFd(fd);file_end(e,ret,NULL,0);return ret;}
static int file_close_provider(int fd){struct file_event *e=file_begin(15,fd,0,0);int ret=__real_close(fd);file_end(e,ret,NULL,0);return ret;}
static void file_reference(int fd){struct file_event *e=file_begin(19,fd,0,0);__real_files_refer(fd);file_end(e,0,NULL,0);}
static size_t file_copy_out(void *out,const void *in,size_t n){struct file_event *e=file_begin(11,file_pointer(out),n,0);size_t ret=__real_LOS_ArchCopyToUser(out,in,n);file_end(e,ret,in,n);return ret;}
static UINT32 file_path_free(void *pool,void *address){check(address==file_allocated_path);struct file_event *e=file_begin(6,1,1,0);UINT32 ret=__real_LOS_MemFree(pool,address);file_allocated_path=NULL;file_end(e,ret,NULL,0);return ret;}
int __wrap_UserPathCopy(const char *path,char **out)
{if(!file_dep())return __real_UserPathCopy(path,out);struct file_event *e=file_begin(1,file_path_kind(path,1),0,0);int ret=__real_UserPathCopy(path,out);if(!ret)file_allocated_path=*out;file_end(e,ret,ret ? NULL : *out,ret ? 0 : strlen(*out)+1);return ret;}
void __wrap_SetCloexecFlag(int fd)
{if(!file_dep()){__real_SetCloexecFlag(fd);return;}struct file_event *e=file_begin(3,fd,0,0);__real_SetCloexecFlag(fd);file_end(e,0,NULL,0);}
void __wrap_ClearCloexecFlag(int fd)
{if(!file_dep()){__real_ClearCloexecFlag(fd);return;}struct file_event *e=file_begin(20,fd,0,0);__real_ClearCloexecFlag(fd);file_end(e,0,NULL,0);}
int __wrap_CheckProcessFd(int fd)
{if(!file_dep())return __real_CheckProcessFd(fd);struct file_event *e=file_begin(17,fd,0,0);int ret=__real_CheckProcessFd(fd);file_end(e,ret,NULL,0);return ret;}
int __wrap_AllocSpecifiedProcessFd(int fd)
{if(!file_dep())return __real_AllocSpecifiedProcessFd(fd);struct file_event *e=file_begin(18,fd,0,0);int ret=__real_AllocSpecifiedProcessFd(fd);file_end(e,ret,NULL,0);return ret;}
int __wrap_do_open(int dir,const char *path,int flags,mode_t mode)
{
    if(!file_dep())return __real_do_open(dir,path,flags,mode);
    struct file_event *e=file_begin(4,dir,file_path_kind(path,0),flags);int ret=__real_do_open(dir,path,flags,mode);
    if(ret>=0){unsigned which=file_objects[0] ? 1 : 0;check(which<2 && !file_objects[which]);check(fs_getfilep(ret,&file_objects[which])==0);}
    file_end(e,ret,&mode,sizeof(mode));return ret;
}
ssize_t __wrap_write(int fd,const void *in,size_t size)
{
    if(!file_dep())return __real_write(fd,in,size);unsigned char data[8];check(size<=8 && __real_LOS_ArchCopyFromUser(data,in,size)==0);
    struct file_event *e=file_begin(8,fd,file_pointer(in),size);ssize_t ret=__real_write(fd,in,size);file_end(e,ret,data,size);return ret;
}
static ssize_t file_read_provider(int fd,void *out,size_t size)
{struct file_event *e=file_begin(9,fd,file_pointer(out),size);ssize_t ret=__real_read(fd,out,size);unsigned char data[192];if(ret>0)check(__real_LOS_ArchCopyFromUser(data,out,ret)==0);file_end(e,ret,ret>0 ? data : NULL,ret>0 ? ret : 0);return ret;}
off64_t __wrap__lseek64(int fd,int high,int low,off64_t *out,int whence)
{if(!file_dep())return __real__lseek64(fd,high,low,out,whence);struct file_event *e=file_begin(10,fd,whence,high);off64_t ret=__real__lseek64(fd,high,low,out,whence);unsigned char data[12];memcpy(data,&low,4);if(!ret)memcpy(data+4,out,8);file_end(e,(UINT32)ret,data,ret ? 4 : 12);return ret;}
int __wrap_fstat(int fd,struct stat *out)
{if(!file_dep())return __real_fstat(fd,out);struct file_event *e=file_begin(12,fd,out ? 1 : 0,0);int ret=__real_fstat(fd,out);file_end(e,ret,!ret ? out : NULL,!ret ? sizeof(*out) : 0);return ret;}
int __wrap_fstat64(int fd,struct stat *out)
{if(!file_dep())return __real_fstat64(fd,out);struct file_event *e=file_begin(12,fd,out ? 1 : 0,0);int ret=__real_fstat64(fd,out);file_end(e,ret,!ret ? out : NULL,!ret ? sizeof(*out) : 0);return ret;}
int __wrap_stat(const char *path,struct stat *out)
{if(!file_dep())return __real_stat(path,out);struct file_event *e=file_begin(13,file_path_kind(path,0),out ? 1 : 0,0);int ret=__real_stat(path,out);file_end(e,ret,!ret ? out : NULL,!ret ? sizeof(*out) : 0);return ret;}
int __wrap_CheckRegion(const LosVmSpace *space,VADDR_T ptr,size_t size)
{if(!file_dep())return __real_CheckRegion(space,ptr,size);struct file_event *e=file_begin(21,file_pointer((void *)ptr),size,0);int ret=__real_CheckRegion(space,ptr,size);file_end(e,ret,NULL,0);return ret;}
UINT32 __wrap_LOS_MuxLock(LosMux *mutex,UINT32 timeout)
{if(!file_dep() || mutex!=&OsCurrProcessGet()->vmSpace->regionMux)return __real_LOS_MuxLock(mutex,timeout);struct file_event *e=file_begin(22,1,timeout,0);UINT32 ret=__real_LOS_MuxLock(mutex,timeout);file_end(e,ret,NULL,0);return ret;}
UINT32 __wrap_LOS_MuxUnlock(LosMux *mutex)
{if(!file_dep() || mutex!=&OsCurrProcessGet()->vmSpace->regionMux)return __real_LOS_MuxUnlock(mutex);struct file_event *e=file_begin(23,1,0,0);UINT32 ret=__real_LOS_MuxUnlock(mutex);file_end(e,ret,NULL,0);return ret;}
#define FILE_ROOT_FINISH(expr) do{int saved=errno;errno=0;int ret=(int)(expr);file_root_end(ret);errno=saved;return ret;}while(0)
int __wrap_SysOpen(const char *path,int flags,...)
{va_list ap;va_start(ap,flags);mode_t mode=va_arg(ap,int);va_end(ap);if(!file_run())return __real_SysOpen(path,flags,mode);file_root_begin(5,file_path_kind(path,1),flags,mode,0,0);FILE_ROOT_FINISH(__real_SysOpen(path,flags,mode));}
int __wrap_SysOpenat(int dir,const char *path,int flags,...)
{va_list ap;va_start(ap,flags);mode_t mode=va_arg(ap,int);va_end(ap);if(!file_run())return __real_SysOpenat(dir,path,flags,mode);file_root_begin(322,dir,file_path_kind(path,1),flags,mode,0);FILE_ROOT_FINISH(__real_SysOpenat(dir,path,flags,mode));}
ssize_t __wrap_SysWrite(int fd,const void *in,size_t n)
{if(!file_run())return __real_SysWrite(fd,in,n);file_root_begin(4,fd,file_pointer(in),n,0,0);FILE_ROOT_FINISH(__real_SysWrite(fd,in,n));}
off64_t __wrap_SysLseek64(int fd,int high,int low,off64_t *out,int whence)
{if(!file_run())return __real_SysLseek64(fd,high,low,out,whence);file_root_begin(140,fd,high,low,file_pointer(out),whence);FILE_ROOT_FINISH(__real_SysLseek64(fd,high,low,out,whence));}
int __wrap_SysFstat64(int fd,struct kstat *out)
{if(!file_run())return __real_SysFstat64(fd,out);file_root_begin(197,fd,file_pointer(out),0,0,0);FILE_ROOT_FINISH(__real_SysFstat64(fd,out));}
int __wrap_SysStat(const char *path,struct kstat *out)
{if(!file_run())return __real_SysStat(path,out);file_root_begin(106,file_path_kind(path,1),file_pointer(out),0,0,0);FILE_ROOT_FINISH(__real_SysStat(path,out));}
int __wrap_SysDup2(int a,int b)
{if(!file_run())return __real_SysDup2(a,b);file_root_begin(63,a,b,0,0,0);FILE_ROOT_FINISH(__real_SysDup2(a,b));}
static int file_close_root(int fd){file_root_begin(6,fd,0,0,0,0);FILE_ROOT_FINISH(__real_SysClose(fd));}
static ssize_t file_read_root(int fd,void *out,size_t n){file_root_begin(3,fd,file_pointer(out),n,0,0);FILE_ROOT_FINISH(__real_SysRead(fd,out,n));}
#undef FILE_ROOT_FINISH
#else
int __wrap_UserPathCopy(const char *p,char **o){return __real_UserPathCopy(p,o);}
void __wrap_SetCloexecFlag(int f){__real_SetCloexecFlag(f);}
void __wrap_ClearCloexecFlag(int f){__real_ClearCloexecFlag(f);}
int __wrap_CheckProcessFd(int f){return __real_CheckProcessFd(f);}
int __wrap_AllocSpecifiedProcessFd(int f){return __real_AllocSpecifiedProcessFd(f);}
int __wrap_do_open(int d,const char *p,int f,mode_t m){return __real_do_open(d,p,f,m);}
ssize_t __wrap_write(int f,const void *p,size_t n){return __real_write(f,p,n);}
off64_t __wrap__lseek64(int f,int h,int l,off64_t *p,int w){return __real__lseek64(f,h,l,p,w);}
int __wrap_fstat(int f,struct stat *p){return __real_fstat(f,p);}
int __wrap_fstat64(int f,struct stat *p){return __real_fstat64(f,p);}
int __wrap_stat(const char *p,struct stat *o){return __real_stat(p,o);}
int __wrap_CheckRegion(const LosVmSpace *s,VADDR_T p,size_t n){return __real_CheckRegion(s,p,n);}
UINT32 __wrap_LOS_MuxLock(LosMux *m,UINT32 t){return __real_LOS_MuxLock(m,t);}
UINT32 __wrap_LOS_MuxUnlock(LosMux *m){return __real_LOS_MuxUnlock(m);}
int __wrap_SysOpen(const char *p,int f,...){va_list a;va_start(a,f);mode_t m=va_arg(a,int);va_end(a);return __real_SysOpen(p,f,m);}
int __wrap_SysOpenat(int d,const char *p,int f,...){va_list a;va_start(a,f);mode_t m=va_arg(a,int);va_end(a);return __real_SysOpenat(d,p,f,m);}
ssize_t __wrap_SysWrite(int f,const void *p,size_t n){return __real_SysWrite(f,p,n);}
off64_t __wrap_SysLseek64(int f,int h,int l,off64_t *p,int w){return __real_SysLseek64(f,h,l,p,w);}
int __wrap_SysFstat64(int f,struct kstat *p){return __real_SysFstat64(f,p);}
int __wrap_SysStat(const char *p,struct kstat *o){return __real_SysStat(p,o);}
int __wrap_SysDup2(int a,int b){return __real_SysDup2(a,b);}
#endif
