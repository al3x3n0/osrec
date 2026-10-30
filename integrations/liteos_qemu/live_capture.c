/* Single-CPU capture for PID 1 reads and its child process/task queries.
 * GNU ld --wrap retains the original SysRead/read bodies. All returned user
 * bytes are copied through the kernel's actual safe-copy API. No recorder
 * output occurs during the read sequence. The report driver exports afterward.
 */
#include "los_typedef.h"
#include "los_process_pri.h"
#include "los_task_pri.h"
#include "los_memory.h"
#include "los_printf.h"
#include "user_copy.h"
#include "fs/file.h"
#include "fs/driver.h"
#include "fs/fd_table.h"
#include "errno.h"
#include "fcntl.h"
#include "unistd.h"
#include "sys/mount.h"
#include "osrec/io_capture.h"
#include "live_config.h"
#include "auto_entry_config.h"
#ifdef OSREC_PARENT_ARGUMENT_SESSION
#include "parent_argument_adapter.h"
#endif
#include "time.h"
#include "sys/resource.h"
#include "sys/utsname.h"
#if defined(OSREC_GETRESUID_CAPTURE) && defined(OSREC_GETRESGID_CAPTURE)
#error "select one credential output capture"
#endif
#if defined(OSREC_GETRESUID_CAPTURE) || defined(OSREC_GETRESGID_CAPTURE)
#define OSREC_CREDENTIAL_OUTPUT_CAPTURE 1
#ifndef OSREC_CREDENTIAL_OUTPUT_0
#define OSREC_CREDENTIAL_OUTPUT_0 0
#define OSREC_CREDENTIAL_OUTPUT_1 4
#define OSREC_CREDENTIAL_OUTPUT_2 8
#endif
static const unsigned res_offsets[3]={OSREC_CREDENTIAL_OUTPUT_0,OSREC_CREDENTIAL_OUTPUT_1,OSREC_CREDENTIAL_OUTPUT_2};
#ifdef OSREC_GETRESGID_CAPTURE
#define RES_REAL_FIELD gid
#define RES_EFFECTIVE_FIELD effGid
#define RES_REAL_VALUE 7001U
#define RES_EFFECTIVE_VALUE 7002U
#define RES_NUMBER 211
#define RES_PREFIX "OSREC_RESGID"
#define RES_WRAPPER __wrap_SysGetRealEffSaveGroupID
#define RES_BODY __real_SysGetRealEffSaveGroupID
#define RES_SNAPSHOT osrec_snapshot_credential_SysGetRealEffSaveGroupID
#else
#define RES_REAL_FIELD userID
#define RES_EFFECTIVE_FIELD effUserID
#define RES_REAL_VALUE 6001U
#define RES_EFFECTIVE_VALUE 6002U
#define RES_NUMBER 209
#define RES_PREFIX "OSREC_RESUID"
#define RES_WRAPPER __wrap_SysGetRealEffSaveUserID
#define RES_BODY __real_SysGetRealEffSaveUserID
#define RES_SNAPSHOT osrec_snapshot_credential_SysGetRealEffSaveUserID
#endif
#if defined(OSREC_CREDENTIAL_REAL_ID) != defined(OSREC_CREDENTIAL_EFFECTIVE_ID)
#error "supply both credential fixture IDs"
#endif
#ifdef OSREC_CREDENTIAL_REAL_ID
#undef RES_REAL_VALUE
#undef RES_EFFECTIVE_VALUE
#define RES_REAL_VALUE OSREC_CREDENTIAL_REAL_ID
#define RES_EFFECTIVE_VALUE OSREC_CREDENTIAL_EFFECTIVE_ID
#endif
#endif
#ifdef OSREC_AUTOMATED_ENTRY_STATE
#include "auto_entry_capture.h"
#include "osrec/object_lifetime.h"
#ifdef OSREC_SHARED_ARGUMENT_CAPTURE
#if !defined(OSREC_ARGUMENT_SESSION) || defined(OSREC_PARENT_ARGUMENT_SESSION)
#error "shared live capture requires the current-process locked helper session"
#endif
#include "shared_entry_capture.h"
static struct osrec_capture_session shared_session;
#ifdef OSREC_SHARED_CONFIGURED_CAPTURE
#include "shared_session_schedule.h"
static char shared_json[2048*OSREC_CAPTURE_CALLS+1];
static UINT32 shared_session_witness[5+6*OSREC_CAPTURE_CALLS];
#else
static char shared_json[16384];
#endif
static size_t shared_json_size;
#ifdef OSREC_SHARED_MIXED_CAPTURE
static UINT32 shared_query_witness[4];
#endif
static int shared_write(void *context,const char *data,size_t bytes)
{
    (void)context;
    if(bytes>=sizeof(shared_json)-shared_json_size)return 0;
    for(size_t i=0;i<bytes;++i)shared_json[shared_json_size++]=data[i];
    return 1;
}
#endif
struct auto_entry { unsigned number,invocation,argument,raw; struct osrec_entry_snapshot state; };
static struct auto_entry auto_entries[14],auto_effects[6];
#ifdef OSREC_ARGUMENT_ENTRY
static struct auto_entry argument_entries[6];
static unsigned argument_count;
#ifdef OSREC_ARGUMENT_WRITE
static struct auto_entry argument_effects[6];
static UINT32 argument_before[6],argument_after[6];
#ifdef OSREC_ARGUMENT_SESSION
static UINT32 argument_session_initial,argument_session_final,argument_session_restored;
static const UINT32 argument_signals[6]={1,2,128,4,0x80000008U,16};
#define ARGUMENT_ROUTE 65539
#else
static UINT32 argument_restored[6];
static const UINT32 argument_signals[6]={0,1,127,128,0x80000001U,0xffffffffU};
#define ARGUMENT_ROUTE 65538
#endif
#define ARGUMENT_SNAPSHOT osrec_snapshot_OsProcessExitCodeSignalSet
#define ARGUMENT_BODY OsProcessExitCodeSignalSet
#define ARGUMENT_FIELD exitCode
#define ARGUMENT_EFFECT_SNAPSHOT osrec_snapshot_effects_OsProcessExitCodeSignalSet
#ifdef OSREC_PARENT_ARGUMENT_SESSION
#undef ARGUMENT_ROUTE
#undef ARGUMENT_SNAPSHOT
#undef ARGUMENT_BODY
#undef ARGUMENT_EFFECT_SNAPSHOT
#define ARGUMENT_ROUTE 65540
#define ARGUMENT_SNAPSHOT osrec_snapshot_OsrecParentExitSignalSet
#define ARGUMENT_BODY OsrecParentExitSignalSet
#define ARGUMENT_EFFECT_SNAPSHOT osrec_snapshot_effects_OsrecParentExitSignalSet
static UINT32 argument_root_pid,argument_parent_pid;
#endif
#elif defined(OSREC_CONST_ARGUMENT_ENTRY)
#define ARGUMENT_SNAPSHOT osrec_snapshot_OsProcessIsPGroupLeader
#define ARGUMENT_BODY OsProcessIsPGroupLeader
#define ARGUMENT_FIELD processStatus
#define ARGUMENT_ROUTE 65537
#else
#define ARGUMENT_SNAPSHOT osrec_snapshot_OsProcessExitCodeSignalIsSet
#define ARGUMENT_BODY OsProcessExitCodeSignalIsSet
#define ARGUMENT_FIELD exitCode
#define ARGUMENT_ROUTE 65536
#endif
#endif
static unsigned auto_effect_count;
/* Transient address table supplies capture-scoped IDs; never serialize addresses. */
static struct osrec_object_lifetimes auto_identities;
static unsigned auto_count;
static struct auto_entry group_entries[3],group_effects[3];
static unsigned group_count,group_active,group_allocations,group_releases;
static unsigned group_address_reused[3][2],group_call_allocations;
static unsigned group_attempt_sizes[3][2],group_attempt_ids[3][2],group_attempt_counts[3];
static int group_inputs[3][2];
static const int *group_source;
#ifdef OSREC_CREDENTIAL_OUTPUT_CAPTURE
static struct auto_entry res_entries[4],res_effects[4];
static unsigned res_count,res_active,res_copies[4],res_results[4][3];
static unsigned char res_before[4][16],res_after[4][16];
static unsigned char *res_output;
#endif
static unsigned group_copy_count[3],group_copy_id[3],group_copy_result[3];
static unsigned char group_copy_data[3][8],group_copy_before[3][8];
#ifdef OSREC_GETGROUPS_CAPTURE
static struct auto_entry getgroup_entries[3],getgroup_effects[3];
static unsigned getgroup_count,getgroup_active,getgroup_alloc_id[3],getgroup_reuse[3],getgroup_copy_count[3],getgroup_copy_result[3],getgroup_alloc_attempts[3];
static int *getgroup_output;
static unsigned char getgroup_before[3][16],getgroup_after[3][16];
#endif
#endif

static struct osrec_buffer recorder;
static unsigned char storage[4096];
static UINTPTR user_base;
static int owner=-1, system_fd=-1;
static unsigned index, read_count;
static unsigned identity_active, identity_calls, identity_events;
static UINT32 identity_transcript[16][4]; /* invocation, dependency kind, argument, result bits */
static struct file *captured_file;
static int task_owner=-1;
static unsigned getpriority_active,getpriority_calls,getpriority_events;
static UINT32 getpriority_transcript[12][5]; /* invocation, kind, which, who, raw */
static unsigned credentials_calls;
static UINT32 credentials_steps[4][6]; /* number, PID, effective UID/GID, raw, mode/MMU */
static unsigned task_calls;
static UINT32 task_steps[4][6]; /* number, current PID, parent PID, task ID, raw, mode/MMU */
static unsigned umask_calls;
static UINT32 umask_steps[6][5]; /* mask, before, raw, after, kernel mode/MMU */
static UINT32 kernel_steps[4][4]; /* raw, errno, cursor, mode + MMU flag */
extern ssize_t __real_read(int,void *,size_t);
extern ssize_t __real_SysRead(int,void *,size_t);

static void fail(void)
{
    PRINT_ERR("OSREC_LIVE_FAILED index=%u\n",index);
    for (;;) {}
}
#define check(condition) do { if (!(condition)) { PRINT_ERR("OSREC_CHECK line=%u\n",(unsigned)__LINE__); fail(); } } while(0)
static UINT32 kernel_mode(void)
{
    UINT32 mode,sctlr;
    __asm__ volatile("mrs %0, cpsr" : "=r"(mode));
    __asm__ volatile("mrc p15,0,%0,c1,c0,0" : "=r"(sctlr));
    return (mode&31) | ((sctlr&1)<<8);
}
extern UINT32 __real_LOS_GetCurrProcessID(void);
#include "file_capture.h"
extern int __real_GetAssociatedSystemFd(int);
extern int __real_AllocProcessFd(void);
extern void __real_files_refer(int);
extern void __real_AssociateSystemFd(int,int);
extern int __real_SysDup(int);
#ifdef OSREC_DUP_CAPTURE
static unsigned dup_active,dup_calls,dup_events;
static struct file *dup_file;
static UINT32 dup_steps[5][26],dup_transcript[12][26];
static void dup_state(UINT32 *out)
{
    struct fd_table_s *table=GetFdTable();check(table && table->max_fds>6 && table->max_fds<=1024 && dup_file);
    FileTableLock(table);
    for(unsigned i=0;i<3;++i){unsigned fd=4+i;out[3*i]=(UINT32)table->ft_fds[fd].sysFd;
        out[3*i+1]=FD_ISSET(fd,table->proc_fds) ? 1 : 0;out[3*i+2]=FD_ISSET(fd,table->cloexec_fds) ? 1 : 0;}
    FileTableUnLock(table);out[9]=dup_file->f_refcount;
}
static UINT32 *dup_begin(UINT32 kind,UINT32 arg,UINT32 arg2)
{
    check(dup_active && dup_events<12 && kernel_mode()==0x113);
    UINT32 *row=dup_transcript[dup_events++];row[0]=dup_calls;row[1]=kind;row[2]=arg;row[3]=arg2;dup_state(row+6);return row;
}
static void dup_end(UINT32 *row,UINT32 raw){row[4]=raw;row[5]=errno;dup_state(row+16);}
int __wrap_GetAssociatedSystemFd(int fd)
{
#ifdef OSREC_FILE_CAPTURE
    if(file_dep())return file_lookup(fd);
#endif

    if(!dup_active)return __real_GetAssociatedSystemFd(fd);
    UINT32 *row=dup_begin(1,fd,0);int ret=__real_GetAssociatedSystemFd(fd);dup_end(row,ret);return ret;
}
int __wrap_AllocProcessFd(void)
{
#ifdef OSREC_FILE_CAPTURE
    if(file_dep())return file_allocate();
#endif

    if(!dup_active)return __real_AllocProcessFd();
    UINT32 *row=dup_begin(2,0,0);
    int ret=dup_calls==0 ? -1 : __real_AllocProcessFd(); /* Scoped allocation failure before changes. */
    dup_end(row,ret);return ret;
}
void __wrap_files_refer(int fd)
{
#ifdef OSREC_FILE_CAPTURE
    if(file_dep()){file_reference(fd);return;}
#endif

    if(!dup_active){__real_files_refer(fd);return;}
    UINT32 *row=dup_begin(3,fd,0);__real_files_refer(fd);dup_end(row,0);
}
static void dup_associate(int fd,int system)
{
    UINT32 *row=dup_begin(4,fd,system);__real_AssociateSystemFd(fd,system);dup_end(row,0);
}
int __wrap_SysDup(int fd)
{
    if((int)__real_LOS_GetCurrProcessID()!=owner)return __real_SysDup(fd);
    check(!dup_active && dup_calls<5);
    unsigned i=dup_calls;check(fd==(i==2 ? 5 : i==3 ? -1 : i==4 ? 1024 : 4));
    if(!dup_file)check(fs_getfilep(__real_GetAssociatedSystemFd(4),&dup_file)==0);
    int saved=errno;errno=0;dup_state(dup_steps[i]+6);dup_active=1;
    int ret=__real_SysDup(fd);
    dup_steps[i][0]=41;dup_steps[i][1]=fd;dup_steps[i][2]=ret;dup_steps[i][3]=errno;
    dup_steps[i][4]=CONFIG_NFILE_DESCRIPTORS;dup_steps[i][5]=kernel_mode();dup_state(dup_steps[i]+16);
    dup_active=0;++dup_calls;errno=saved;return ret;
}
#else
int __wrap_GetAssociatedSystemFd(int fd){
#ifdef OSREC_FILE_CAPTURE
    if(file_dep())return file_lookup(fd);
#endif
return __real_GetAssociatedSystemFd(fd);}
int __wrap_AllocProcessFd(void){
#ifdef OSREC_FILE_CAPTURE
    if(file_dep())return file_allocate();
#endif
return __real_AllocProcessFd();}
void __wrap_files_refer(int fd){
#ifdef OSREC_FILE_CAPTURE
    if(file_dep()){file_reference(fd);return;}
#endif
__real_files_refer(fd);}
int __wrap_SysDup(int fd){return __real_SysDup(fd);}
#endif
extern int __real_DisassociateProcessFd(int);
extern void __real_AssociateSystemFd(int,int);
extern void __real_FreeProcessFd(int);
extern int __real_close(int);
extern int __real_SysClose(int);
#ifdef OSREC_CLOSE_CAPTURE
static unsigned close_active,close_calls,close_events;
static UINT32 close_steps[5][11],close_transcript[15][12];
static void close_state(UINT32 *out)
{
    struct fd_table_s *table=GetFdTable();check(table && table->max_fds>4 && table->max_fds<=1024);
    FileTableLock(table);
    out[0]=(UINT32)table->ft_fds[4].sysFd;out[1]=FD_ISSET(4,table->proc_fds) ? 1 : 0;
    out[2]=FD_ISSET(4,table->cloexec_fds) ? 1 : 0;FileTableUnLock(table);
}
static UINT32 *close_begin(UINT32 kind,UINT32 argument,UINT32 argument2)
{
    check(close_active && close_events<15 && kernel_mode()==0x113);
    UINT32 *row=close_transcript[close_events++];row[0]=close_calls;row[1]=kind;
    row[2]=argument;row[3]=argument2;close_state(row+6);return row;
}
static void close_end(UINT32 *row,UINT32 raw)
{
    row[4]=raw;row[5]=errno;close_state(row+9);
}
int __wrap_DisassociateProcessFd(int fd)
{
#ifdef OSREC_FILE_CAPTURE
    if(file_dep())return file_detach(fd);
#endif

    if(!close_active)return __real_DisassociateProcessFd(fd);
    UINT32 *row=close_begin(1,fd,0);int ret=__real_DisassociateProcessFd(fd);close_end(row,ret);return ret;
}
void __wrap_AssociateSystemFd(int fd,int system)
{
#ifdef OSREC_FILE_CAPTURE
    if(file_dep()){file_associate(fd,system);return;}
#endif

#ifdef OSREC_DUP_CAPTURE
    if(dup_active){dup_associate(fd,system);return;}
#endif
    if(!close_active){__real_AssociateSystemFd(fd,system);return;}
    UINT32 *row=close_begin(4,fd,system);__real_AssociateSystemFd(fd,system);close_end(row,0);
}
void __wrap_FreeProcessFd(int fd)
{
#ifdef OSREC_FILE_CAPTURE
    if(file_dep()){file_free_fd(fd);return;}
#endif

    if(!close_active){__real_FreeProcessFd(fd);return;}
    UINT32 *row=close_begin(5,fd,0);__real_FreeProcessFd(fd);close_end(row,0);
}
int __wrap_close(int fd)
{
#ifdef OSREC_FILE_CAPTURE
    if(file_dep())return file_close_provider(fd);
#endif

    if(!close_active)return __real_close(fd);
    UINT32 *row=close_begin(2,fd,0);int ret;
    if(close_calls==0){errno=EIO;ret=-1;} /* Scoped close failure before releasing the system descriptor. */
    else ret=__real_close(fd);
    close_end(row,ret);return ret;
}
int __wrap_SysClose(int fd)
{
#ifdef OSREC_FILE_CAPTURE
    if(file_run())return file_close_root(fd);
#endif

    if((int)__real_LOS_GetCurrProcessID()!=owner)return __real_SysClose(fd);
    check(!close_active && close_calls<5);
    unsigned i=close_calls;check(fd==(i==3 ? -1 : i==4 ? 1024 : 4));
    int saved=errno;errno=0;close_state(close_steps[i]+4);close_active=1;
    int ret=__real_SysClose(fd);
    close_steps[i][0]=6;close_steps[i][1]=fd;close_steps[i][2]=ret;close_steps[i][3]=errno;
    close_state(close_steps[i]+7);close_steps[i][10]=kernel_mode();
    close_active=0;++close_calls;errno=saved;return ret;
}
#else
int __wrap_DisassociateProcessFd(int fd){
#ifdef OSREC_FILE_CAPTURE
    if(file_dep())return file_detach(fd);
#endif
return __real_DisassociateProcessFd(fd);}
void __wrap_AssociateSystemFd(int fd,int system){
#ifdef OSREC_FILE_CAPTURE
    if(file_dep()){file_associate(fd,system);return;}
#endif

#ifdef OSREC_DUP_CAPTURE
    if(dup_active){dup_associate(fd,system);return;}
#endif
    __real_AssociateSystemFd(fd,system);
}
void __wrap_FreeProcessFd(int fd){
#ifdef OSREC_FILE_CAPTURE
    if(file_dep()){file_free_fd(fd);return;}
#endif
__real_FreeProcessFd(fd);}
int __wrap_close(int fd){
#ifdef OSREC_FILE_CAPTURE
    if(file_dep())return file_close_provider(fd);
#endif
return __real_close(fd);}
int __wrap_SysClose(int fd){
#ifdef OSREC_FILE_CAPTURE
    if(file_run())return file_close_root(fd);
#endif
return __real_SysClose(fd);}
#endif
extern size_t __real_LOS_ArchCopyFromUser(void *,const void *,size_t);
extern int __real_uname(struct utsname *);
extern int __real_SysUname(struct utsname *);
#ifdef OSREC_UNAME_CAPTURE
typedef char uname_native_abi[sizeof(struct utsname)==390 ? 1 : -1];
static unsigned uname_active,uname_calls,uname_events;
#ifdef OSREC_UNAME_FAULTS
#define UNAME_CALLS 8
#define UNAME_EVENTS 17
#else
#define UNAME_CALLS 4
#define UNAME_EVENTS 8
#endif
static UINT32 uname_steps[UNAME_CALLS][4];
static struct { UINT32 invocation,kind,argument,raw,size,mode; unsigned char memory[392]; } uname_transcript[UNAME_EVENTS];
static void uname_event(UINT32 kind,UINT32 arg,UINT32 raw,const void *data)
{
    check(uname_active && uname_events<UNAME_EVENTS && kernel_mode()==0x113);
    unsigned n=uname_events++;
    uname_transcript[n].invocation=uname_calls;uname_transcript[n].kind=kind;
    uname_transcript[n].argument=arg;uname_transcript[n].raw=raw;
    uname_transcript[n].size=390;uname_transcript[n].mode=kernel_mode();
    for(unsigned j=0;j<392;++j)uname_transcript[n].memory[j]=data && j<390 ? ((const unsigned char *)data)[j] : 0;
}
static size_t uname_copy_from(void *out,const void *in,size_t size)
{
    check(size==390);
    size_t ret;
#ifdef OSREC_UNAME_FAULTS
    if(uname_calls==4) {
        unsigned char before[390];
        for(unsigned j=0;j<390;++j)before[j]=((volatile unsigned char *)out)[j];
        check(__real_LOS_ArchCopyFromUser(out,in,195)==0);ret=195;
        for(unsigned j=195;j<390;++j)check(((volatile unsigned char *)out)[j]==before[j]);
    } else
#endif
    ret=__real_LOS_ArchCopyFromUser(out,in,size);
    unsigned char payload[390];
    check(ret<=390);
    for(unsigned j=0;j<390;++j)payload[j]=j<390-ret ? ((unsigned char *)out)[j] : 0;
    uname_event(1,uname_calls==2 ? 1 : uname_calls==3 ? 2 : 0,ret,payload);
    return ret;
}
int __wrap_uname(struct utsname *out)
{
    int ret;
#ifdef OSREC_UNAME_FAULTS
    if(uname_active && uname_calls==5)ret=-EIO; /* Scoped provider failure before writes. */
    else
#endif
    ret=__real_uname(out);
    if(uname_active)uname_event(2,0,(UINT32)ret,out);
    return ret;
}
int __wrap_SysUname(struct utsname *out)
{
    if((int)__real_LOS_GetCurrProcessID()!=owner)return __real_SysUname(out);
    check(!uname_active && uname_calls<UNAME_CALLS);
    unsigned i=uname_calls;check((i==2)==(out==NULL) && (i==3)==((UINTPTR)out==1));
    int saved=errno;errno=0;uname_active=1;
    int ret=__real_SysUname(out);
    uname_steps[i][0]=122;uname_steps[i][1]=i==2 ? 1 : i==3 ? 2 : 0;
    uname_steps[i][2]=(UINT32)ret;uname_steps[i][3]=errno;
    uname_active=0;++uname_calls;errno=saved;return ret;
}
#else
int __wrap_uname(struct utsname *out){return __real_uname(out);}
int __wrap_SysUname(struct utsname *out){return __real_SysUname(out);}
#endif
#ifdef OSREC_RLIMIT_CAPTURE
typedef char rlimit_native_abi[(sizeof(struct rlimit)==16 && sizeof(rlim_t)==8) ? 1 : -1];
static unsigned rlimit_active,rlimit_calls,rlimit_events;
static UINT32 rlimit_transcript[10][9],rlimit_steps[6][4];
static void rlimit_event(UINT32 kind,UINT32 arg,UINT32 raw,UINT32 size,const struct rlimit *value)
{
    check(rlimit_active && rlimit_events<10 && kernel_mode()==0x113);
    UINT32 *row=rlimit_transcript[rlimit_events++];
    row[0]=rlimit_calls;row[1]=kind;row[2]=arg;row[3]=raw;row[4]=size;
    row[5]=value ? (UINT32)value->rlim_cur : 0;row[6]=value ? (UINT32)(value->rlim_cur>>32) : 0;
    row[7]=value ? (UINT32)value->rlim_max : 0;row[8]=value ? (UINT32)(value->rlim_max>>32) : 0;
}
extern int __real_getrlimit(int,struct rlimit *);
int __wrap_getrlimit(int resource,struct rlimit *out)
{
    int ret=__real_getrlimit(resource,out);
    if(rlimit_active)rlimit_event(1,(UINT32)resource,(UINT32)ret,0,ret<0 ? NULL : out);
    return ret;
}
extern int __real_SysUgetrlimit(int,unsigned long long *);
int __wrap_SysUgetrlimit(int resource,unsigned long long *out)
{
    if((int)__real_LOS_GetCurrProcessID()!=owner)return __real_SysUgetrlimit(resource,out);
    check(!rlimit_active && rlimit_calls<6);
    unsigned i=rlimit_calls;check((UINT32)resource==(i==1 ? 1U : i==2 ? 0xffffffffU : i==5 ? 0U : 7U));
    check((i==3 || i==5)==(out==NULL) && (i==4)==((UINTPTR)out==1));
    int saved=errno;errno=0;rlimit_active=1;
    int ret=__real_SysUgetrlimit(resource,out);
    rlimit_steps[i][0]=191;rlimit_steps[i][1]=(UINT32)resource;
    rlimit_steps[i][2]=(UINT32)ret;rlimit_steps[i][3]=errno;
    rlimit_active=0;++rlimit_calls;errno=saved;return ret;
}
#else
extern int __real_getrlimit(int,struct rlimit *);
extern int __real_SysUgetrlimit(int,unsigned long long *);
int __wrap_getrlimit(int resource,struct rlimit *out){return __real_getrlimit(resource,out);}
int __wrap_SysUgetrlimit(int resource,unsigned long long *out){return __real_SysUgetrlimit(resource,out);}
#endif
#ifdef OSREC_CLOCK_CAPTURE
typedef char clock_native_time_abi[(sizeof(struct timespec)==16 && sizeof(((struct timespec *)0)->tv_sec)==8 && sizeof(((struct timespec *)0)->tv_nsec)==4) ? 1 : -1];
static unsigned clock_active,clock_calls,clock_events;
static UINT32 clock_transcript[16][10],clock_steps[10][4];
static void clock_event(UINT32 kind,UINT32 arg,UINT32 raw,UINT32 error,UINT32 lo,UINT32 hi,UINT32 nsec,UINT32 padding,UINT32 size)
{
    check(clock_active && clock_events<16 && kernel_mode()==0x113);
    UINT32 *row=clock_transcript[clock_events++];
    row[0]=clock_calls;row[1]=kind;row[2]=arg;row[3]=raw;row[4]=error;row[5]=lo;row[6]=hi;row[7]=nsec;row[8]=padding;row[9]=size;
}
extern int __real_clock_gettime(clockid_t,struct timespec *);
extern int __real_clock_getres(clockid_t,struct timespec *);
int __wrap_clock_gettime(clockid_t id,struct timespec *out)
{
    int ret=__real_clock_gettime(id,out);
    if(clock_active) clock_event(1,(UINT32)id,(UINT32)ret,errno,ret<0 ? 0 : (UINT32)out->tv_sec,ret<0 ? 0 : (UINT32)((unsigned long long)out->tv_sec>>32),ret<0 ? 0 : (UINT32)out->tv_nsec,0,0);
    return ret;
}
int __wrap_clock_getres(clockid_t id,struct timespec *out)
{
    int ret=__real_clock_getres(id,out);
    if(clock_active) clock_event(2,(UINT32)id,(UINT32)ret,errno,ret<0 ? 0 : (UINT32)out->tv_sec,ret<0 ? 0 : (UINT32)((unsigned long long)out->tv_sec>>32),ret<0 ? 0 : (UINT32)out->tv_nsec,0,0);
    return ret;
}
extern int __real_SysClockGettime(clockid_t,struct timespec *);
extern int __real_SysClockGetres(clockid_t,struct timespec *);
static int capture_clock(unsigned number,clockid_t id,struct timespec *out)
{
    check(!clock_active && clock_calls<10 && (int)__real_LOS_GetCurrProcessID()==owner);
    unsigned local=clock_calls%5;check((UINT32)id==(local==1 ? 1U : local==2 ? 0xffffffffU : 0U));
    check((local==3)==(out==NULL) && (local==4)==((UINTPTR)out==1));
    int saved=errno;errno=0;clock_active=number;
    int ret=number==263 ? __real_SysClockGettime(id,out) : __real_SysClockGetres(id,out);
    clock_steps[clock_calls][0]=number;clock_steps[clock_calls][1]=(UINT32)id;
    clock_steps[clock_calls][2]=(UINT32)ret;clock_steps[clock_calls][3]=errno;
    clock_active=0;++clock_calls;errno=saved;return ret;
}
int __wrap_SysClockGettime(clockid_t id,struct timespec *out)
{
    if((int)__real_LOS_GetCurrProcessID()!=owner)return __real_SysClockGettime(id,out);
    return capture_clock(263,id,out);
}
int __wrap_SysClockGetres(clockid_t id,struct timespec *out)
{
    if((int)__real_LOS_GetCurrProcessID()!=owner)return __real_SysClockGetres(id,out);
    return capture_clock(264,id,out);
}
#else
extern int __real_SysClockGettime(clockid_t,struct timespec *);
extern int __real_SysClockGetres(clockid_t,struct timespec *);
extern int __real_clock_gettime(clockid_t,struct timespec *);
extern int __real_clock_getres(clockid_t,struct timespec *);
int __wrap_SysClockGettime(clockid_t id,struct timespec *out){return __real_SysClockGettime(id,out);}
int __wrap_SysClockGetres(clockid_t id,struct timespec *out){return __real_SysClockGetres(id,out);}
int __wrap_clock_gettime(clockid_t id,struct timespec *out){return __real_clock_gettime(id,out);}
int __wrap_clock_getres(clockid_t id,struct timespec *out){return __real_clock_getres(id,out);}
#endif
#ifdef OSREC_GETSCHEDULER_CAPTURE
static unsigned scheduler_active,scheduler_calls,scheduler_events;
static UINT32 scheduler_transcript[8][6];
static void scheduler_event(UINT32 kind,UINT32 id,UINT32 raw,UINT32 policy,UINT32 written)
{
    if(!scheduler_active) return;
    check(scheduler_events<8 && kernel_mode()==0x113);
    UINT32 *row=scheduler_transcript[scheduler_events++];
    row[0]=scheduler_calls;row[1]=kind;row[2]=id;row[3]=raw;row[4]=policy;row[5]=written;
}
#ifdef OSREC_GETSCHEDULER_TASK_CAPTURE
#ifdef LOSCFG_PID_CONTAINER
#error "task scheduler capture requires physical task IDs"
#endif
static LosTaskCB *scheduler_bound_task;
static const SchedOps *scheduler_original_ops;
static SchedOps scheduler_capture_ops;
static UINT32 scheduler_param_get(const LosTaskCB *task,SchedParam *param)
{
    check(scheduler_active && task==scheduler_bound_task && task->ops==&scheduler_capture_ops && param!=NULL);
    UINT32 result=scheduler_original_ops->schedParamGet(task,param);
    scheduler_event(5,task->taskID,result,param->policy,1);
    scheduler_bound_task->ops=scheduler_original_ops;scheduler_bound_task=NULL;
    return result;
}
extern INT32 __real_OsUserTaskOperatePermissionsCheck(const LosTaskCB *);
INT32 __wrap_OsUserTaskOperatePermissionsCheck(const LosTaskCB *task)
{
    INT32 result=__real_OsUserTaskOperatePermissionsCheck(task);
    if(scheduler_active) {
        check(task!=NULL && scheduler_bound_task==NULL);
        scheduler_event(4,task->taskID,(UINT32)result,0,0);
        if(result==LOS_OK) {
            scheduler_bound_task=(LosTaskCB *)task;scheduler_original_ops=task->ops;
            check(scheduler_original_ops!=NULL && scheduler_original_ops->schedParamGet!=NULL);
            scheduler_capture_ops=*scheduler_original_ops;
            scheduler_capture_ops.schedParamGet=scheduler_param_get;
            scheduler_bound_task->ops=&scheduler_capture_ops;
        }
    }
    return result;
}
#endif
extern INT32 __real_LOS_GetProcessScheduler(INT32,INT32 *,LosSchedParam *);
INT32 __wrap_LOS_GetProcessScheduler(INT32 id,INT32 *policy,LosSchedParam *param)
{
    unsigned selected=scheduler_active;scheduler_active=0;
    INT32 result=__real_LOS_GetProcessScheduler(id,policy,param);
    scheduler_active=selected;
    if(selected) {
        check(policy!=NULL && param==NULL);
        scheduler_event(2,(UINT32)id,(UINT32)result,result>=0 ? (UINT32)*policy : 0,result>=0);
    }
    return result;
}
extern int __real_SysSchedGetScheduler(int,int);
int __wrap_SysSchedGetScheduler(int id,int flag)
{
    if(owner<0 || index!=4 || (int)__real_LOS_GetCurrProcessID()!=owner)
        return __real_SysSchedGetScheduler(id,flag);
    check(!scheduler_active && scheduler_calls<4);
#ifdef OSREC_GETSCHEDULER_TASK_CAPTURE
    check(flag==-1 && g_taskMaxNum==128);
    check((UINT32)id==(scheduler_calls==0 ? OsCurrTaskGet()->taskID : scheduler_calls==1 ? 0xffffffffU : scheduler_calls==2 ? 127U : 0U));
    scheduler_active=1;scheduler_event(3,(UINT32)id,g_taskMaxNum,0,0);
#else
    check(flag==0);
    check((UINT32)id==(scheduler_calls==0 ? 0U : scheduler_calls==1 ? 1U : scheduler_calls==2 ? 0xffffffffU : 63U));
    scheduler_active=1;
#endif
    int result=__real_SysSchedGetScheduler(id,flag);
#ifdef OSREC_GETSCHEDULER_TASK_CAPTURE
    check(scheduler_bound_task==NULL);
#endif
    scheduler_active=0;++scheduler_calls;return result;
}
#else
extern INT32 __real_LOS_GetProcessScheduler(INT32,INT32 *,LosSchedParam *);
INT32 __wrap_LOS_GetProcessScheduler(INT32 id,INT32 *policy,LosSchedParam *param)
{ return __real_LOS_GetProcessScheduler(id,policy,param); }
extern int __real_SysSchedGetScheduler(int,int);
int __wrap_SysSchedGetScheduler(int id,int flag) { return __real_SysSchedGetScheduler(id,flag); }
#endif
#ifndef OSREC_GETSCHEDULER_TASK_CAPTURE
extern INT32 __real_OsUserTaskOperatePermissionsCheck(const LosTaskCB *);
INT32 __wrap_OsUserTaskOperatePermissionsCheck(const LosTaskCB *task)
{ return __real_OsUserTaskOperatePermissionsCheck(task); }
#endif
#ifdef OSREC_AUTOMATED_ENTRY_STATE
static void auto_snapshot(unsigned number,unsigned invocation)
{
    check(auto_count<14);
    if(!auto_count) osrec_lifetime_init(&auto_identities);
    struct osrec_entry_snapshot *state=&auto_entries[auto_count].state;
    auto_entries[auto_count].number=number;auto_entries[auto_count].invocation=invocation;
    osrec_snapshot_init(state);
    int result=number==60 ? osrec_snapshot_SysUmask(state) :
        number==64 ? osrec_snapshot_SysGetPPID(state) : number==224 ? osrec_snapshot_SysGetTid(state) :
        number==201 ? osrec_snapshot_SysGetEffUserID(state) : osrec_snapshot_SysGetEffGID(state);
    check(result && !state->failed);
    check(osrec_snapshot_lifetimes(state,&auto_identities,1));
    ++auto_count;
#ifdef OSREC_ARGUMENT_ENTRY
    if(number==
#ifdef OSREC_PARENT_ARGUMENT_SESSION
       64
#else
       60
#endif
#ifdef OSREC_ARGUMENT_SESSION
       && invocation==0
#endif
    ) {
        check(argument_count<6 && argument_count==invocation);
        LosProcessCB *process=OsCurrProcessGet();
#ifdef OSREC_PARENT_ARGUMENT_SESSION
        LosProcessCB *target=process->parentProcess;
        check(target && target!=process && !OsProcessIsUnused(target));
        argument_root_pid=process->processID;argument_parent_pid=target->processID;
        check(argument_root_pid>1 && argument_parent_pid==1);
#elif defined(OSREC_ARGUMENT_WRITE)
        LosProcessCB *target=process;
#endif
#ifdef OSREC_ARGUMENT_SESSION
        UINT32 session_initial=target->exitCode;
#ifdef OSREC_SHARED_ARGUMENT_CAPTURE
        osrec_capture_init(&shared_session);
#endif
        for(unsigned call=0;call<6;++call) {
#else
        unsigned call=invocation;
#endif
#ifdef OSREC_ARGUMENT_WRITE
        UINT32 before=target->exitCode;
#endif
        struct auto_entry *entry=&argument_entries[argument_count++];
        entry->number=ARGUMENT_ROUTE;entry->invocation=call;
        osrec_snapshot_init(&entry->state);
        check(ARGUMENT_SNAPSHOT(&entry->state,process));
        check(osrec_snapshot_lifetimes(&entry->state,&auto_identities,1));
#ifdef OSREC_ARGUMENT_WRITE
        entry->argument=argument_signals[call];
#if defined(OSREC_SHARED_ARGUMENT_CAPTURE) && !defined(OSREC_SHARED_CONFIGURED_CAPTURE)
        osrec_capture_OsProcessExitCodeSignalSet(&shared_session,process,entry->argument);
        check(!shared_session.failed && shared_session.count==call+1
#ifdef OSREC_SHARED_MIXED_CAPTURE
              +(call>2)
#endif
        );
#else
        ARGUMENT_BODY(process,entry->argument);
#endif
        argument_after[call]=target->exitCode;
        struct auto_entry *effect=&argument_effects[call];
        effect->number=ARGUMENT_ROUTE;effect->invocation=call;effect->argument=entry->argument;
        osrec_snapshot_init(&effect->state);
        check(ARGUMENT_EFFECT_SNAPSHOT(&effect->state,process));
        check(osrec_snapshot_lifetimes(&effect->state,&auto_identities,1));
        argument_before[call]=before;
#ifdef OSREC_SHARED_MIXED_CAPTURE
        if(call==2) {
            shared_query_witness[0]=shared_session.count;
            shared_query_witness[1]=target->exitCode;
            shared_query_witness[2]=osrec_capture_OsProcessExitCodeSignalIsSet(&shared_session,process);
            shared_query_witness[3]=target->exitCode;
            check(!shared_session.failed && shared_session.count==4 && shared_query_witness[1]==shared_query_witness[3]);
        }
#endif
#ifndef OSREC_ARGUMENT_SESSION
        target->exitCode=before;
        argument_restored[call]=target->exitCode;
        check(argument_restored[call]==before);
#endif
#else
        entry->argument=process->ARGUMENT_FIELD;
        entry->raw=ARGUMENT_BODY(process);
        check(process->ARGUMENT_FIELD==entry->argument);
#endif
#ifdef OSREC_ARGUMENT_SESSION
        }
        argument_session_initial=session_initial;
        argument_session_final=target->exitCode;
        target->exitCode=session_initial;
        argument_session_restored=target->exitCode;
#ifdef OSREC_SHARED_CONFIGURED_CAPTURE
        /* The six-call legacy baseline above is separate. This configured
         * session captures only the following original calls and witnesses. */
        check(process==target && process->processID==1);
        osrec_capture_init(&shared_session);
        shared_session_witness[0]=process->processID;
        shared_session_witness[1]=OSREC_CAPTURE_CALLS;
        shared_session_witness[2]=target->exitCode;
        for(unsigned i=0;i<OSREC_CAPTURE_CALLS;++i) {
            UINT32 *row=&shared_session_witness[5+6*i];
            row[0]=i;row[1]=shared_schedule[i].number;row[2]=shared_schedule[i].argument;
            row[3]=target->exitCode;
            if(row[1]==65539) {
                osrec_capture_OsProcessExitCodeSignalSet(&shared_session,process,row[2]);row[4]=0;
            } else {
                check(row[1]==65536 && row[2]==0);
                row[4]=osrec_capture_OsProcessExitCodeSignalIsSet(&shared_session,process);
            }
            row[5]=target->exitCode;
            check(!shared_session.failed && shared_session.count==i+1);
        }
        shared_session_witness[3]=target->exitCode;
        target->exitCode=shared_session_witness[2];
        shared_session_witness[4]=target->exitCode;
        check(shared_session_witness[4]==session_initial);
#endif
#ifdef OSREC_PARENT_ARGUMENT_SESSION
        check(process->parentProcess==target && target->processID==argument_parent_pid);
#endif
        check(argument_count==6 && argument_session_restored==session_initial);
#endif
    }
#endif
}
#endif
/* This reviewed capture adapter is deliberately restricted to lists of 0..2 groups.
 * The real SetGroups body allocates and replaces User; it is never emulated here.
 * All successful allocations/frees reached in the selected syscall are wrapped. */
#ifdef OSREC_AUTOMATED_ENTRY_STATE
static void group_snapshot(struct osrec_entry_snapshot *state)
{
    LosProcessCB *process=OsCurrProcessGet();User *user=process->user;
    osrec_snapshot_init(state);
    check(osrec_snapshot_bind(state,"OsCurrProcessGet()",process,"LosProcessCB"));
    check(osrec_snapshot_edge(state,process,"user",user,"User"));
    check(user!=NULL);
#define GROUP_FIELD(name) check(osrec_snapshot_scalar(state,user,#name,&user->name,sizeof(user->name)))
    GROUP_FIELD(userID);GROUP_FIELD(effUserID);GROUP_FIELD(gid);GROUP_FIELD(effGid);
    GROUP_FIELD(groupNumber);
    check(user->groupNumber>=1 && user->groupNumber<=3);
    const char *names[]={"groups[0]","groups[1]","groups[2]"};
    const unsigned char *groups=(const unsigned char *)&user->groups[0];
    for(unsigned i=0;i<user->groupNumber;++i)
        check(osrec_snapshot_scalar(state,user,names[i],groups+4*i,4));
#undef GROUP_FIELD
    check(osrec_snapshot_lifetimes(state,&auto_identities,0));
}
extern VOID *__real_LOS_MemAlloc(VOID *,UINT32);
VOID *__wrap_LOS_MemAlloc(VOID *pool,UINT32 size)
{

#ifdef OSREC_GETGROUPS_CAPTURE
    if(getgroup_active && (int)LOS_GetCurrProcessID()==owner) {
        check(getgroup_count==2 && kernel_mode()==0x113 && pool==m_aucSysMem1 && size==4*OSREC_GETGROUPS_GROUP_COUNT && !getgroup_alloc_attempts[2]);
        ++getgroup_alloc_attempts[2];
#ifdef OSREC_GETGROUPS_ALLOCATION_FAILURE
        return NULL;
#endif
        VOID *result=__real_LOS_MemAlloc(pool,size);check(result!=NULL);
        for(unsigned i=0;i<OSREC_LIFETIME_SLOTS;++i)
            if(!auto_identities.slots[i].active && auto_identities.slots[i].address==result) getgroup_reuse[2]=1;
        getgroup_alloc_id[2]=osrec_lifetime_allocate(&auto_identities,result,size);check(getgroup_alloc_id[2]);return result;
    }
#endif
    if(group_active && (int)LOS_GetCurrProcessID()==owner) {
        check(kernel_mode()==0x113 && pool==m_aucSysMem1);
        check(group_call_allocations<(group_count ? 2U : 1U));
        /* The original SetGroups appends the primary gid only when absent. */
        unsigned includes_gid=0;
        for(unsigned i=0;i<group_count;++i)
            includes_gid |= group_inputs[group_count][i]==OsCurrUserGet()->gid;
        unsigned credential_size=sizeof(User)+4*(group_count-includes_gid);
        check(size==(group_count && !group_call_allocations ? 4*group_count : credential_size));
        unsigned attempt=group_call_allocations++;
        group_attempt_sizes[group_count][attempt]=size;
#ifdef OSREC_SETGROUPS_FAILURES
        if(group_count<2 || attempt==1) return NULL;
#endif
        VOID *result=__real_LOS_MemAlloc(pool,size);
        if(!result) return NULL;
        for(unsigned i=0;i<OSREC_LIFETIME_SLOTS;++i)
            if(!auto_identities.slots[i].active && auto_identities.slots[i].address==result)
                group_address_reused[group_count][attempt]=1;
        group_attempt_ids[group_count][attempt]=osrec_lifetime_allocate(&auto_identities,result,size);
        check(group_attempt_ids[group_count][attempt]);++group_allocations;
        return result;
    }
    return __real_LOS_MemAlloc(pool,size);
}
extern size_t __real_LOS_ArchCopyFromUser(void *,const void *,size_t);
size_t __wrap_LOS_ArchCopyFromUser(void *out,const void *in,size_t size)
{
#ifdef OSREC_UNAME_CAPTURE
    if(uname_active)return uname_copy_from(out,in,size);
#endif
    if(group_active && (int)LOS_GetCurrProcessID()==owner) {
        check(kernel_mode()==0x113 && group_count && !group_copy_count[group_count]);
        check(in==group_source && size==4*group_count && group_call_allocations==1);
        unsigned id=osrec_lifetime_identity(&auto_identities,out);
        check(id && id==group_attempt_ids[group_count][0]);
        const volatile unsigned char *original=out;
        for(unsigned i=0;i<size;++i) group_copy_before[group_count][i]=original[i];
        group_copy_id[group_count]=id;group_copy_count[group_count]=1;
#ifdef OSREC_SETGROUPS_PARTIAL_COPY_FAILURES
        check(__real_LOS_ArchCopyFromUser(out,in,size/2)==0);
        UINT32 result=size-size/2;
#elif defined(OSREC_SETGROUPS_COPY_FAILURES)
        UINT32 result=size; /* Inject before writing destination bytes. */
#else
        UINT32 result=__real_LOS_ArchCopyFromUser(out,in,size);
        check(result==0); /* Natural faults remain outside the controlled contract. */
#endif
        check(result<=size);
        const unsigned char *copied=out,*expected=(const unsigned char *)group_inputs[group_count];
        for(unsigned i=0;i<size-result;++i) {check(copied[i]==expected[i]);group_copy_data[group_count][i]=copied[i];}
        for(unsigned i=size-result;i<size;++i) check(copied[i]==group_copy_before[group_count][i]);
        group_copy_result[group_count]=result;return result;
    }
    return __real_LOS_ArchCopyFromUser(out,in,size);
}
extern UINT32 __real_LOS_MemFree(VOID *,VOID *);
UINT32 __wrap_LOS_MemFree(VOID *pool,VOID *address)
{
#ifdef OSREC_FILE_CAPTURE
    if(file_dep())return file_path_free(pool,address);
#endif

    if(group_active && (int)LOS_GetCurrProcessID()==owner && group_copy_count[group_count] &&
       osrec_lifetime_identity(&auto_identities,address)==group_copy_id[group_count]) {
        const unsigned char *bytes=address;
        for(unsigned i=0;i<4*group_count-group_copy_result[group_count];++i)
            check(bytes[i]==group_copy_data[group_count][i]);
        for(unsigned i=4*group_count-group_copy_result[group_count];i<4*group_count;++i)
            check(bytes[i]==group_copy_before[group_count][i]);
    }
#ifdef OSREC_GETGROUPS_CAPTURE
    if(getgroup_active && (int)LOS_GetCurrProcessID()==owner) {
        check(getgroup_count==2 && pool==m_aucSysMem1 && osrec_lifetime_identity(&auto_identities,address)==getgroup_alloc_id[2]);
        UINT32 result=__real_LOS_MemFree(pool,address);check(result==LOS_OK);
        check(osrec_lifetime_release(&auto_identities,address));return result;
    }
#endif
    UINT32 result=__real_LOS_MemFree(pool,address);
    if(group_active && (int)LOS_GetCurrProcessID()==owner) {
        check(kernel_mode()==0x113 && pool==m_aucSysMem1 && result==LOS_OK);
        check(osrec_lifetime_release(&auto_identities,address));
        ++group_releases;
    }
    return result;
}
#else
extern size_t __real_LOS_ArchCopyFromUser(void *,const void *,size_t);
size_t __wrap_LOS_ArchCopyFromUser(void *out,const void *in,size_t size) {
#ifdef OSREC_UNAME_CAPTURE
    if(uname_active)return uname_copy_from(out,in,size);
#endif
    return __real_LOS_ArchCopyFromUser(out,in,size);
}
extern VOID *__real_LOS_MemAlloc(VOID *,UINT32);
VOID *__wrap_LOS_MemAlloc(VOID *pool,UINT32 size) { return __real_LOS_MemAlloc(pool,size); }
extern UINT32 __real_LOS_MemFree(VOID *,VOID *);
UINT32 __wrap_LOS_MemFree(VOID *pool,VOID *address) {
#ifdef OSREC_FILE_CAPTURE
    if(file_dep())return file_path_free(pool,address);
#endif
 return __real_LOS_MemFree(pool,address); }
#endif
extern size_t __real_LOS_ArchCopyToUser(void *,const void *,size_t);
size_t __wrap_LOS_ArchCopyToUser(void *out,const void *in,size_t size)
{
#ifdef OSREC_FILE_CAPTURE
    if(file_dep())return file_copy_out(out,in,size);
#endif

#ifdef OSREC_UNAME_CAPTURE
    if(uname_active) {
        check(size==390);
        size_t ret;
#ifdef OSREC_UNAME_FAULTS
        if(uname_calls==6)ret=390; /* Scoped output-copy failure before writes. */
        else if(uname_calls==7) {check(__real_LOS_ArchCopyToUser(out,in,195)==0);ret=195;}
        else
#endif
        ret=__real_LOS_ArchCopyToUser(out,in,size);
        uname_event(3,0,ret,in);return ret;
    }
#endif
#ifdef OSREC_RLIMIT_CAPTURE
    if(rlimit_active) {
        check(size==16);
        size_t ret=__real_LOS_ArchCopyToUser(out,in,size);
        rlimit_event(2,rlimit_calls==3 ? 1 : rlimit_calls==4 ? 2 : 0,(UINT32)ret,size,in);
        return ret;
    }
#endif
#ifdef OSREC_CLOCK_CAPTURE
    if(clock_active) {
        check(size==16);
        size_t ret=__real_LOS_ArchCopyToUser(out,in,size);
        const UINT32 *words=in;
        clock_event(3,clock_calls%5==4 ? 2 : 0,(UINT32)ret,0,words[0],words[1],words[2],words[3],size);
        return ret;
    }
#endif
#ifdef OSREC_CREDENTIAL_OUTPUT_CAPTURE
    if(res_active && (int)LOS_GetCurrProcessID()==owner) {
        unsigned j=res_copies[res_count]++;
        check(j<3 && size==4 && kernel_mode()==0x113);
        check(out==(res_count==j+1 ? NULL : res_output+res_offsets[j]));
        check(*(const unsigned *)in==(j ? RES_EFFECTIVE_VALUE : RES_REAL_VALUE));
        size_t result=__real_LOS_ArchCopyToUser(out,in,size);
        check(result==(out ? 0U : 4U));res_results[res_count][j]=(unsigned)result;
        return result;
    }
#endif
#ifdef OSREC_GETGROUPS_CAPTURE
    if(getgroup_active && (int)LOS_GetCurrProcessID()==owner) {
        check(getgroup_count==2 && kernel_mode()==0x113 && out==(unsigned char *)getgroup_output+OSREC_GETGROUPS_OUTPUT_OFFSET && size==4*OSREC_GETGROUPS_GROUP_COUNT && !getgroup_copy_count[2]);
        check(osrec_lifetime_identity(&auto_identities,in)==getgroup_alloc_id[2]);
        ++getgroup_copy_count[2];
#ifdef OSREC_GETGROUPS_COPY_BYTES
        check(OSREC_GETGROUPS_COPY_BYTES<size);
        if(OSREC_GETGROUPS_COPY_BYTES) check(__real_LOS_ArchCopyToUser(out,in,OSREC_GETGROUPS_COPY_BYTES)==0);
        size_t result=size-OSREC_GETGROUPS_COPY_BYTES;
#elif defined(OSREC_GETGROUPS_PARTIAL_COPY_FAILURES)
        check(__real_LOS_ArchCopyToUser(out,in,size/2)==0);size_t result=size-size/2;
#elif defined(OSREC_GETGROUPS_COPY_FAILURES)
        size_t result=size;
#else
        size_t result=__real_LOS_ArchCopyToUser(out,in,size);check(result==0);
#endif
        getgroup_copy_result[2]=(unsigned)result;return result;
    }
#endif
    return __real_LOS_ArchCopyToUser(out,in,size);
}
#ifdef OSREC_CREDENTIAL_OUTPUT_CAPTURE
extern int RES_BODY(int *,int *,int *);
int RES_WRAPPER(int *real,int *effective,int *saved)
{
    if((int)LOS_GetCurrProcessID()!=owner) return RES_BODY(real,effective,saved);
    check(res_count<4 && group_count==3 && !res_active);
    if(!res_count) res_output=(unsigned char *)real-res_offsets[0];
    int *args[3]={real,effective,saved};
    for(unsigned j=0;j<3;++j) check((void *)args[j]==(res_count==j+1 ? NULL : res_output+res_offsets[j]));
    check(LOS_ArchCopyFromUser(res_before[res_count],res_output,16)==0);
    UINT32 lock;SCHEDULER_LOCK(lock);
    LosProcessCB *process=OsCurrProcessGet();User *user=process->user;
    UINT32 old_real=user->RES_REAL_FIELD,old_effective=user->RES_EFFECTIVE_FIELD;
    /* Scoped fixture makes real/effective field selection observable; restored outside captured calls. */
    user->RES_REAL_FIELD=RES_REAL_VALUE;user->RES_EFFECTIVE_FIELD=RES_EFFECTIVE_VALUE;
    struct auto_entry *frames[2]={&res_entries[res_count],&res_effects[res_count]};
    for(unsigned k=0;k<2;++k) {
        struct auto_entry *e=frames[k];e->number=RES_NUMBER;e->invocation=res_count;
        osrec_snapshot_init(&e->state);
        check(RES_SNAPSHOT(&e->state));
        check(osrec_snapshot_lifetimes(&e->state,&auto_identities,0));
        if(!k) {
            res_active=1;SCHEDULER_UNLOCK(lock);
            int raw=RES_BODY(real,effective,saved);
            SCHEDULER_LOCK(lock);res_active=0;
            check(raw==(res_count ? -EFAULT : 0));
            check(res_copies[res_count]==(res_count ? res_count : 3U));
            frames[0]->raw=frames[1]->raw=(unsigned)raw;
            check(user->RES_REAL_FIELD==RES_REAL_VALUE && user->RES_EFFECTIVE_FIELD==RES_EFFECTIVE_VALUE);
        }
    }
    user->RES_REAL_FIELD=old_real;user->RES_EFFECTIVE_FIELD=old_effective;SCHEDULER_UNLOCK(lock);
    check(LOS_ArchCopyFromUser(res_after[res_count],res_output,16)==0);
    return (int)res_entries[res_count++].raw;
}
#endif
#ifndef OSREC_GETRESUID_CAPTURE
extern int __real_SysGetRealEffSaveUserID(int *,int *,int *);
int __wrap_SysGetRealEffSaveUserID(int *r,int *e,int *s)
{return __real_SysGetRealEffSaveUserID(r,e,s);}
#endif
#ifndef OSREC_GETRESGID_CAPTURE
extern int __real_SysGetRealEffSaveGroupID(int *,int *,int *);
int __wrap_SysGetRealEffSaveGroupID(int *r,int *e,int *s)
{return __real_SysGetRealEffSaveGroupID(r,e,s);}
#endif
extern int __real_SysGetGroups(int,int *);
int __wrap_SysGetGroups(int size,int *list)
{
#ifdef OSREC_GETGROUPS_CAPTURE
    if((int)LOS_GetCurrProcessID()!=owner) return __real_SysGetGroups(size,list);
    unsigned null_output=0;
    int expected_size=getgroup_count==1 ? OSREC_GETGROUPS_GROUP_COUNT-1 : (int)(2*getgroup_count);
    if(getgroup_count==2) expected_size=OSREC_GETGROUPS_OUTPUT_SIZE;
#ifdef OSREC_GETGROUPS_NULL_OUTPUT
    null_output=getgroup_count==1;
#endif
#ifdef OSREC_GETGROUPS_NULL_BOUNDARIES
    null_output=getgroup_count!=0;
    if(getgroup_count==1) expected_size=0;
#endif
#ifdef OSREC_GETGROUPS_NEGATIVE_SIZES
    null_output=getgroup_count==2;
    if(getgroup_count==1) expected_size=-1;
    if(getgroup_count==2) expected_size=(-2147483647-1);
#endif
    check(getgroup_count<3 && size==expected_size && group_count==(OSREC_GETGROUPS_GROUP_COUNT==1 ? 1U : 3U) && !group_active && !getgroup_active);
    if(!getgroup_count) getgroup_output=list;
    unsigned offset=getgroup_count==2 ? OSREC_GETGROUPS_OUTPUT_OFFSET : 0;
    check(getgroup_output!=NULL && list==(null_output ? NULL : (int *)((unsigned char *)getgroup_output+offset)));
    /* The shared user object remains a witness even when not passed to the syscall. */
    check(LOS_ArchCopyFromUser(getgroup_before[getgroup_count],getgroup_output,16)==0);
    UINT32 saved;SCHEDULER_LOCK(saved);
    struct auto_entry *before=&getgroup_entries[getgroup_count],*after=&getgroup_effects[getgroup_count];
    before->number=after->number=205;before->invocation=after->invocation=getgroup_count;
    group_snapshot(&before->state);check(OsCurrUserGet()->groupNumber==OSREC_GETGROUPS_GROUP_COUNT);
    getgroup_active=1;SCHEDULER_UNLOCK(saved);
    int result=__real_SysGetGroups(size,list);
    SCHEDULER_LOCK(saved);getgroup_active=0;
    check(result==(size==0 ? OSREC_GETGROUPS_GROUP_COUNT : null_output ? -EFAULT : size<OSREC_GETGROUPS_GROUP_COUNT ? -EINVAL : !getgroup_alloc_id[2] ? -ENOMEM : getgroup_copy_result[2] ? -EFAULT : OSREC_GETGROUPS_GROUP_COUNT));
    before->raw=after->raw=(unsigned)result;group_snapshot(&after->state);SCHEDULER_UNLOCK(saved);
    check(LOS_ArchCopyFromUser(getgroup_after[getgroup_count],getgroup_output,16)==0);++getgroup_count;return result;
#else
    return __real_SysGetGroups(size,list);
#endif
}
extern int __real_SysSetGroups(int,const int *);
int __wrap_SysSetGroups(int size,const int *list)
{
#ifdef OSREC_AUTOMATED_ENTRY_STATE
    if((int)LOS_GetCurrProcessID()!=owner) return __real_SysSetGroups(size,list);
    check(size==(int)group_count && (size ? list!=NULL : list==NULL) && credentials_calls==4 && getpriority_calls==6 && group_count<3 && !group_active);
    if(size) check(LOS_ArchCopyFromUser(group_inputs[group_count],list,4*size)==0);
    if(size==1) check(group_inputs[group_count][0]==0);
    if(size==2) {
#if defined(OSREC_GETGROUPS_CAPTURE) && OSREC_GETGROUPS_GROUP_COUNT==2
        check(group_inputs[group_count][0]==7 && group_inputs[group_count][1]==0);
#else
        check(group_inputs[group_count][0]==7 && group_inputs[group_count][1]==9);
#endif
    }
    UINT32 saved;SCHEDULER_LOCK(saved);
    struct auto_entry *before=&group_entries[group_count],*after=&group_effects[group_count];
    before->number=after->number=206;before->invocation=after->invocation=group_count;
    group_snapshot(&before->state);
    unsigned allocations=group_allocations,releases=group_releases;
    group_source=list;group_call_allocations=0;group_active=1;SCHEDULER_UNLOCK(saved);
    int result=__real_SysSetGroups(size,list);
    SCHEDULER_LOCK(saved);group_active=0;
    unsigned count=0;
    for(unsigned j=0;j<group_call_allocations;++j) count+=group_attempt_ids[group_count][j]!=0;
    check(result==0 || result==-ENOMEM || result==-EFAULT);
#ifdef OSREC_SETGROUPS_FAILURES
    check(result==-ENOMEM && group_call_allocations==(group_count==2 ? 2U : 1U));
#elif defined(OSREC_SETGROUPS_COPY_FAILURES)
    check(result==(size ? -EFAULT : 0) && group_call_allocations==1);
#else
    if(!result) check(group_call_allocations==(size ? 2U : 1U));
#endif
    check(group_allocations==allocations+count && group_releases==releases+count);
    before->raw=after->raw=(unsigned)result;
    group_attempt_counts[group_count]=group_call_allocations;
    group_snapshot(&after->state);++group_count;
    SCHEDULER_UNLOCK(saved);return result;
#else
    return __real_SysSetGroups(size,list);
#endif
}
ssize_t __wrap_read(int fd,void *buffer,size_t count)
{
#ifdef OSREC_FILE_CAPTURE
    if(file_dep())return file_read_provider(fd,buffer,count);
#endif

    if (owner<0 || (int)LOS_GetCurrProcessID()!=owner || fd!=system_fd || index>=3)
        return __real_read(fd,buffer,count);
    check((UINTPTR)buffer==user_base+2+index*2 && count==(index==0 ? 4 : 2));
    ssize_t result=__real_read(fd,buffer,count);
    int saved_errno=errno;
    unsigned char payload[8];
    check(result>=-1 && result<=(ssize_t)count);
    if (result>0) check(LOS_ArchCopyFromUser(payload,buffer,(size_t)result)==0);
    check(osrec_record_read(&recorder,index,17,count,
        (struct osrec_object_ref){10,2+index*2},(int32_t)result,
        result<0 ? (UINT32)saved_errno : 0,result>0 ? payload : NULL)==0);
    ++read_count;
    errno=saved_errno;
    return result;
}
ssize_t __wrap_SysRead(int fd,void *buffer,size_t count)
{
#ifdef OSREC_FILE_CAPTURE
    if(file_run())return file_read_root(fd,buffer,count);
#endif

    if (owner<0) {
        check(fd==3 && count==4);
        owner=(int)LOS_GetCurrProcessID(); user_base=(UINTPTR)buffer-2;
        system_fd=GetAssociatedSystemFd(fd);
        check(system_fd>=3 && fs_getfilep(system_fd,&captured_file)==0);
        check(captured_file->f_pos==0 && errno==0);
        unsigned char initial[8];
        check(LOS_ArchCopyFromUser(initial,(void *)user_base,8)==0);
        const unsigned char expected[8]={0,0x11,0x22,0x33,0x44,0x55,0x66,0x77};
        for(unsigned i=0;i<8;++i) check(initial[i]==expected[i]);
        check(osrec_begin(&recorder,storage,sizeof(storage),LIVE_CONTEXT)==0);
    }
    if ((int)LOS_GetCurrProcessID()!=owner) return __real_SysRead(fd,buffer,count);
    check(index<4 && (index<3 ? fd==3 && (UINTPTR)buffer==user_base+2+index*2 && count==(index==0 ? 4 : 2) : fd==0 && !buffer && !count));
    ssize_t result=__real_SysRead(fd,buffer,count);
    int saved_errno=errno;
    kernel_steps[index][0]=(UINT32)result; kernel_steps[index][1]=(UINT32)saved_errno;
    kernel_steps[index][2]=(UINT32)captured_file->f_pos; kernel_steps[index][3]=kernel_mode();
    check(kernel_steps[index][3]==0x113); /* SVC mode, MMU enabled */
    ++index;
    errno=saved_errno;
    return result;
}
/* Capture only dependency boundaries reached by the selected identity syscalls.
 * Calls made by VFS/reporting or dependency internals are outside this contract. */
extern UINT32 __real_LOS_GetCurrProcessID(void);
extern INT32 __real_LOS_GetUserID(void);
extern INT32 __real_LOS_GetGroupID(void);
extern INT32 __real_LOS_GetProcessGroupID(UINT32);
extern int __real_SysGetUserID(void);
extern int __real_SysGetGroupID(void);
extern int __real_SysGetProcessGroupID(unsigned int);
static void identity_event(UINT32 kind,UINT32 argument,UINT32 raw)
{
    if (!identity_active || (int)__real_LOS_GetCurrProcessID()!=owner || (kernel_mode()&31)!=0x13) return;
    check(identity_events<16);
    identity_transcript[identity_events][0]=identity_calls;
    identity_transcript[identity_events][1]=kind;
    identity_transcript[identity_events][2]=argument;
    identity_transcript[identity_events++][3]=raw;
}
static void getpriority_event(UINT32 kind,UINT32 which,UINT32 who,UINT32 raw)
{
    if (!getpriority_active || (int)__real_LOS_GetCurrProcessID()!=owner || kernel_mode()!=0x113) return;
    check(getpriority_events<12);
    UINT32 *row=getpriority_transcript[getpriority_events++];
    row[0]=getpriority_calls; row[1]=kind; row[2]=which; row[3]=who; row[4]=raw;
}
extern INT32 __real_OsGetProcessPriority(INT32,INT32);
INT32 __wrap_OsGetProcessPriority(INT32 which,INT32 who)
{
    unsigned selected=getpriority_active;
    getpriority_active=0;
    INT32 result=__real_OsGetProcessPriority(which,who);
    getpriority_active=selected;
    getpriority_event(2,(UINT32)which,(UINT32)who,(UINT32)result);
    return result;
}
extern int __real_SysGetProcessPriority(int,int);
int __wrap_SysGetProcessPriority(int which,int who)
{
    if (owner<0 || index!=4 || (int)__real_LOS_GetCurrProcessID()!=owner)
        return __real_SysGetProcessPriority(which,who);
    check(credentials_calls==4 && !getpriority_active && getpriority_calls<6);
    getpriority_active=1;
    int result=__real_SysGetProcessPriority(which,who);
    getpriority_active=0; ++getpriority_calls;
    return result;
}
UINT32 __wrap_LOS_GetCurrProcessID(void)
{
    UINT32 result=__real_LOS_GetCurrProcessID();
    identity_event(1,0,result); getpriority_event(1,0,0,result);
#ifdef OSREC_GETSCHEDULER_CAPTURE
    scheduler_event(1,0,result,0,0);
#endif
    return result;
}
INT32 __wrap_LOS_GetUserID(void)
{
    INT32 result=__real_LOS_GetUserID();
    identity_event(2,0,(UINT32)result); return result;
}
INT32 __wrap_LOS_GetGroupID(void)
{
    INT32 result=__real_LOS_GetGroupID();
    identity_event(3,0,(UINT32)result); return result;
}
INT32 __wrap_LOS_GetProcessGroupID(UINT32 pid)
{
    INT32 result=__real_LOS_GetProcessGroupID(pid);
    identity_event(4,pid,(UINT32)result); return result;
}
static unsigned identity_begin(void)
{
    if (index!=4 || owner<0 || (int)__real_LOS_GetCurrProcessID()!=owner) return 0;
    check(!identity_active && identity_calls<7);
    identity_active=1; return 1;
}
int __wrap_SysGetUserID(void)
{
    unsigned selected=identity_begin();
    int result=__real_SysGetUserID();
    if (selected) { identity_active=0; ++identity_calls; }
    return result;
}
int __wrap_SysGetGroupID(void)
{
    unsigned selected=identity_begin();
    int result=__real_SysGetGroupID();
    if (selected) { identity_active=0; ++identity_calls; }
    return result;
}
int __wrap_SysGetProcessGroupID(unsigned int pid)
{
    unsigned selected=identity_begin();
    int result=__real_SysGetProcessGroupID(pid);
    if (selected) { identity_active=0; ++identity_calls; }
    return result;
}
extern mode_t __real_SysUmask(mode_t mask);
mode_t __wrap_SysUmask(mode_t mask)
{
    if (owner<0 || index!=4 || (int)LOS_GetCurrProcessID()!=owner)
        return __real_SysUmask(mask);
    check(identity_calls==7 && umask_calls<6 && (kernel_mode()&31)==0x13);
    UINT32 intSave;
    SCHEDULER_LOCK(intSave);
    UINT32 before=(UINT32)OsCurrProcessGet()->umask;
#ifdef OSREC_AUTOMATED_ENTRY_STATE
    auto_snapshot(60,umask_calls);
    auto_entries[auto_count-1].argument=(UINT32)mask;
#endif
    SCHEDULER_UNLOCK(intSave);
    mode_t result=__real_SysUmask(mask);
    SCHEDULER_LOCK(intSave);
    UINT32 after=(UINT32)OsCurrProcessGet()->umask;
#ifdef OSREC_AUTOMATED_ENTRY_STATE
    check(auto_effect_count<6);
    struct auto_entry *effect=&auto_effects[auto_effect_count++];
    effect->number=60;effect->invocation=umask_calls;effect->argument=(UINT32)mask;
    osrec_snapshot_init(&effect->state);
    check(osrec_snapshot_effects_SysUmask(&effect->state));
    check(osrec_snapshot_lifetimes(&effect->state,&auto_identities,1));
#endif
    SCHEDULER_UNLOCK(intSave);
    umask_steps[umask_calls][0]=(UINT32)mask;
    umask_steps[umask_calls][1]=before;
    umask_steps[umask_calls][2]=(UINT32)result;
    umask_steps[umask_calls][3]=after;
    umask_steps[umask_calls++][4]=kernel_mode();
    return result;
}
extern int __real_SysGetEffUserID(void);
extern int __real_SysGetEffGID(void);
static int credentials_query(unsigned int number)
{
    if (owner<0 || index!=4 || (int)LOS_GetCurrProcessID()!=owner)
        return number==201 ? __real_SysGetEffUserID() : __real_SysGetEffGID();
    check(umask_calls==6 && credentials_calls<4 && number==((credentials_calls&1) ? 202U : 201U));
    UINT32 intSave;
    SCHEDULER_LOCK(intSave);
    User *user=OsCurrUserGet();
#ifdef OSREC_AUTOMATED_ENTRY_STATE
    auto_snapshot(number,credentials_calls);
#endif
    check(user!=NULL);
    credentials_steps[credentials_calls][0]=number;
    credentials_steps[credentials_calls][1]=OsCurrProcessGet()->processID;
    credentials_steps[credentials_calls][2]=user->effUserID;
    credentials_steps[credentials_calls][3]=user->effGid;
    SCHEDULER_UNLOCK(intSave);
    int result=number==201 ? __real_SysGetEffUserID() : __real_SysGetEffGID();
    credentials_steps[credentials_calls][4]=(UINT32)result;
    credentials_steps[credentials_calls++][5]=kernel_mode();
    return result;
}
int __wrap_SysGetEffUserID(void) { return credentials_query(201); }
int __wrap_SysGetEffGID(void) { return credentials_query(202); }
/* Entry snapshots contain scalar fields and a parent edge, never pointers. */
extern unsigned int __real_SysGetPPID(void);
extern unsigned int __real_SysGetTid(void);
static unsigned int task_query(unsigned int number)
{
    if (owner<0 || index!=4)
        return number==64 ? __real_SysGetPPID() : __real_SysGetTid();
    check(umask_calls==6 && task_calls<4 && number==((task_calls&1) ? 224U : 64U));
    UINT32 intSave;
    SCHEDULER_LOCK(intSave);
    LosProcessCB *process=OsCurrProcessGet();
#ifdef OSREC_AUTOMATED_ENTRY_STATE
    auto_snapshot(number,task_calls);
#endif
    LosTaskCB *task=OsCurrTaskGet();
    check(process->parentProcess!=NULL);
    if (task_owner<0) task_owner=(int)process->processID;
    check((int)process->processID==task_owner && (int)process->parentProcess->processID==owner);
    task_steps[task_calls][0]=number;
    task_steps[task_calls][1]=process->processID;
    task_steps[task_calls][2]=process->parentProcess->processID;
    task_steps[task_calls][3]=task->taskID;
    SCHEDULER_UNLOCK(intSave);
    unsigned int result=number==64 ? __real_SysGetPPID() : __real_SysGetTid();
    task_steps[task_calls][4]=result;
    task_steps[task_calls++][5]=kernel_mode();
    return result;
}
unsigned int __wrap_SysGetPPID(void) { return task_query(64); }
unsigned int __wrap_SysGetTid(void) { return task_query(224); }
static void hex(const char *name,const void *data,size_t size)
{
    const unsigned char *p=data;
    dprintf("%s ",name);
    for(size_t i=0;i<size;++i) dprintf("%02x",p[i]);
    dprintf("\n");
}
#ifdef OSREC_AUTOMATED_ENTRY_STATE
static void auto_report(void)
{
    check(auto_count==14 && auto_effect_count==6 && group_count==3);
#ifdef OSREC_CREDENTIAL_OUTPUT_CAPTURE
    check(res_count==4);unsigned frame_count=34;
#elif defined(OSREC_GETGROUPS_CAPTURE)
    check(getgroup_count==3);
    unsigned frame_count=32;
#else
    unsigned frame_count=26;
#endif
#ifdef OSREC_ARGUMENT_ENTRY
    check(frame_count==26 && argument_count==6);
    frame_count+=6;
#ifdef OSREC_ARGUMENT_WRITE
    frame_count+=6;
#endif
#endif
    for(unsigned i=0;i<frame_count;++i) {
        struct auto_entry *entry=i<14 ? &auto_entries[i] : i<20 ? &auto_effects[i-14] :
            i<23 ? &group_entries[i-20] : i<26 ? &group_effects[i-23] : NULL;
        const char *prefix=i<14 ? "OSREC_AUTO_ENTRY" : i<20 ? "OSREC_AUTO_EFFECT" :
            i<23 ? "OSREC_GROUP_ENTRY" : i<26 ? "OSREC_GROUP_EFFECT" : NULL;
#ifdef OSREC_ARGUMENT_ENTRY
        if(i>=26 && i<32) {entry=&argument_entries[i-26];prefix="OSREC_ARGUMENT_ENTRY";}
#ifdef OSREC_ARGUMENT_WRITE
        if(i>=32) {entry=&argument_effects[i-32];prefix="OSREC_ARGUMENT_EFFECT";}
#endif
#endif
#ifdef OSREC_GETGROUPS_CAPTURE
        if(i>=26) {entry=i<29 ? &getgroup_entries[i-26] : &getgroup_effects[i-29];prefix=i<29 ? "OSREC_GETGROUP_ENTRY" : "OSREC_GETGROUP_EFFECT";}
#endif
#ifdef OSREC_CREDENTIAL_OUTPUT_CAPTURE
        if(i>=26) {entry=i<30 ? &res_entries[i-26] : &res_effects[i-30];prefix=i<30 ? RES_PREFIX "_ENTRY" : RES_PREFIX "_EFFECT";}
#endif
        struct osrec_entry_snapshot *state=&entry->state;
        dprintf("%s {\"format\":\"osrec-entry-snapshot-v1\",\"syscall\":%u,\"invocation\":%u,\"objects\":[",prefix,entry->number,entry->invocation);
        for(unsigned j=0;j<state->object_count;++j) {
            struct osrec_snapshot_object *object=&state->objects[j];
            UINT32 session_id=object->session_id;
            check(session_id && !auto_identities.failed);
            dprintf("%s{\"id\":%u,\"session_id\":%u,\"type\":\"%s\"}",j ? "," : "",object->id,session_id,object->type);
        }
        dprintf("],\"lifetime_cursor\":%u,\"roots\":[",state->lifetime_cursor);
        for(unsigned j=0;j<state->root_count;++j)
            dprintf("%s{\"name\":\"%s\",\"object_id\":%u}",j ? "," : "",state->roots[j].name,state->roots[j].object_id);
        dprintf("],\"fields\":[");
        for(unsigned j=0;j<state->field_count;++j) {
            struct osrec_snapshot_field *field=&state->fields[j];
            dprintf("%s{\"object_id\":%u,\"name\":\"%s\",",j ? "," : "",field->object_id,field->name);
            if(field->is_edge) dprintf("\"kind\":\"edge\",\"target_id\":%u}",field->target_id);
            else { dprintf("\"kind\":\"scalar\",\"bytes\":%u,\"data\":\"",field->size);
                for(unsigned k=0;k<field->size;++k)dprintf("%02x",field->bytes[k]);
                dprintf("\"}"); }
        }
        dprintf("]");
        if(entry->number==60
#ifdef OSREC_ARGUMENT_WRITE
           || entry->number==ARGUMENT_ROUTE
#endif
        ) {
            dprintf(",\"arguments\":[{\"name\":\"%s\",\"bytes\":4,\"data\":\"",entry->number==60 ? "mask" : "signal");
            const unsigned char *bytes=(const unsigned char *)&entry->argument;
            for(unsigned j=0;j<4;++j)dprintf("%02x",bytes[j]);
            dprintf("\"}]");
        }
        if(entry->number==206) {
            unsigned n=entry->invocation;
            dprintf(",\"arguments\":{\"size\":%u,\"list\":",n);
            if(!n) dprintf("null");
            else {
                dprintf("{\"id\":%u,\"offset\":0,\"bytes\":%u,\"data\":\"",100+n,4*n);
                const unsigned char *bytes=(const unsigned char *)group_inputs[n];
                for(unsigned j=0;j<4*n;++j) dprintf("%02x",bytes[j]);
                dprintf("\"}");
            }
            dprintf("},\"raw\":%u,\"allocation_address_reused\":%s,\"allocation_reuses\":[",entry->raw,
                group_address_reused[n][n ? 1 : 0] ? "true" : "false");
            for(unsigned j=0;j<(n ? 2U : 1U);++j) dprintf("%s%s",j ? "," : "",group_address_reused[n][j] ? "true" : "false");
            dprintf("]");
            dprintf(",\"allocation_attempts\":[");
            for(unsigned j=0;j<group_attempt_counts[n];++j)
                dprintf("%s{\"size\":%u,\"id\":%u,\"reuse\":%s}",j ? "," : "",
                    group_attempt_sizes[n][j],group_attempt_ids[n][j],group_address_reused[n][j] ? "true" : "false");
            dprintf("]");
            dprintf(",\"user_copy_attempts\":[");
            if(group_copy_count[n]) {
                unsigned copied=4*n-group_copy_result[n];
                dprintf("{\"source_id\":%u,\"destination_id\":%u,\"size\":%u,\"result\":%u,\"bytes_copied\":%u,\"suffix_unchanged\":true,\"destination_data\":\"",
                    100+n,group_copy_id[n],4*n,group_copy_result[n],copied);
                for(unsigned j=0;j<copied;++j) dprintf("%02x",group_copy_data[n][j]);
                dprintf("\"}");
            }
            dprintf("]");
        }
#ifdef OSREC_GETGROUPS_CAPTURE
        if(entry->number==205) {
            unsigned n=entry->invocation;
            unsigned null_output=0;
            int size=n==1 ? OSREC_GETGROUPS_GROUP_COUNT-1 : (int)(2*n);
            if(n==2) size=OSREC_GETGROUPS_OUTPUT_SIZE;
#ifdef OSREC_GETGROUPS_NULL_OUTPUT
            null_output=n==1;
#endif
#ifdef OSREC_GETGROUPS_NULL_BOUNDARIES
            null_output=n!=0;
            if(n==1) size=0;
#endif
#ifdef OSREC_GETGROUPS_NEGATIVE_SIZES
            null_output=n==2;
            if(n==1) size=-1;
            if(n==2) size=(-2147483647-1);
#endif
            dprintf(",\"arguments\":{\"size\":%d,\"list\":",size);
            unsigned offset=n==2 ? OSREC_GETGROUPS_OUTPUT_OFFSET : 0;
            if(null_output) dprintf("null");
            else dprintf("{\"id\":201,\"offset\":%u,\"bytes\":%u}",offset,16-offset);
            dprintf("},\"raw\":%u,\"output_data\":\"",entry->raw);
            const unsigned char *bytes=i<29 ? getgroup_before[n] : getgroup_after[n];
            for(unsigned j=0;j<16;++j) dprintf("%02x",bytes[j]);
            dprintf("\",\"allocation_attempts\":[");
            if(getgroup_alloc_attempts[n]) dprintf("{\"size\":%u,\"id\":%u,\"reuse\":%s}",4*OSREC_GETGROUPS_GROUP_COUNT,getgroup_alloc_id[n],getgroup_reuse[n] ? "true" : "false");
            dprintf("],\"user_copy_attempts\":[");
            if(getgroup_copy_count[n]) dprintf("{\"source_id\":%u,\"destination_id\":201,\"destination_offset\":%u,\"size\":%u,\"result\":%u,\"bytes_copied\":%u}",getgroup_alloc_id[n],offset,4*OSREC_GETGROUPS_GROUP_COUNT,getgroup_copy_result[n],4*OSREC_GETGROUPS_GROUP_COUNT-getgroup_copy_result[n]);
            dprintf("]");
        }
#endif
#ifdef OSREC_CREDENTIAL_OUTPUT_CAPTURE
        if(entry->number==RES_NUMBER) {
            unsigned n=entry->invocation;
            dprintf(",\"arguments\":[");
            for(unsigned j=0;j<3;++j) {
                if(j) dprintf(",");
                if(n==j+1) dprintf("null");
                else dprintf("{\"id\":301,\"offset\":%u,\"bytes\":4}",res_offsets[j]);
            }
            dprintf("],\"raw\":%u,\"output_data\":\"",entry->raw);
            const unsigned char *bytes=i<30 ? res_before[n] : res_after[n];
            for(unsigned j=0;j<16;++j) dprintf("%02x",bytes[j]);
            dprintf("\",\"user_copy_attempts\":[");
            for(unsigned j=0;j<res_copies[n];++j)
                dprintf("%s{\"position\":%u,\"value\":%u,\"size\":4,\"result\":%u}",j ? "," : "",j,j ? RES_EFFECTIVE_VALUE : RES_REAL_VALUE,res_results[n][j]);
            dprintf("]");
        }
#endif
        dprintf("}\n");
    }
#ifdef OSREC_ARGUMENT_ENTRY
#ifdef OSREC_ARGUMENT_WRITE
#ifdef OSREC_ARGUMENT_SESSION
#ifdef OSREC_PARENT_ARGUMENT_SESSION
    UINT32 argument_observations[29];
    argument_observations[27]=argument_root_pid;
    argument_observations[28]=argument_parent_pid;
#else
    UINT32 argument_observations[27];
#endif
    for(unsigned i=0;i<6;++i) {
        argument_observations[4*i]=i;
        argument_observations[4*i+1]=argument_signals[i];
        argument_observations[4*i+2]=argument_before[i];
        argument_observations[4*i+3]=argument_after[i];
    }
    argument_observations[24]=argument_session_initial;
    argument_observations[25]=argument_session_final;
    argument_observations[26]=argument_session_restored;
#else
    UINT32 argument_observations[6][5];
    for(unsigned i=0;i<6;++i) {
        argument_observations[i][0]=i;
        argument_observations[i][1]=argument_signals[i];
        argument_observations[i][2]=argument_before[i];
        argument_observations[i][3]=argument_after[i];
        argument_observations[i][4]=argument_restored[i];
    }
#endif
#else
    UINT32 argument_observations[6][3];
    for(unsigned i=0;i<6;++i) {
        argument_observations[i][0]=i;
        argument_observations[i][1]=argument_entries[i].argument;
        argument_observations[i][2]=argument_entries[i].raw;
    }
#endif
    hex("OSREC_ARGUMENT_KERNEL",argument_observations,sizeof(argument_observations));
#ifdef OSREC_SHARED_ARGUMENT_CAPTURE
    shared_json_size=0;
    check(shared_session.count==
#ifdef OSREC_SHARED_CONFIGURED_CAPTURE
          OSREC_CAPTURE_CALLS
#elif defined(OSREC_SHARED_MIXED_CAPTURE)
          7
#else
          6
#endif
          && !shared_session.active && !shared_session.failed);
    check(osrec_capture_json(&shared_session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,shared_write,NULL));
    shared_json[shared_json_size]=0;
    dprintf("OSREC_SHARED_CAPTURE ");
    for(size_t offset=0;offset<shared_json_size;offset+=128) {
        size_t remaining=shared_json_size-offset;
        dprintf("%.*s",(int)(remaining<128 ? remaining : 128),shared_json+offset);
    }
#ifdef OSREC_SHARED_MIXED_CAPTURE
    hex("OSREC_SHARED_QUERY_KERNEL",shared_query_witness,sizeof(shared_query_witness));
#endif
#ifdef OSREC_SHARED_CONFIGURED_CAPTURE
    hex("OSREC_SHARED_SESSION_KERNEL",shared_session_witness,sizeof(shared_session_witness));
#endif
#endif
#endif
    check(!auto_identities.failed);
    dprintf("OSREC_LIFETIMES {\"format\":\"osrec-object-lifetimes-v1\",\"events\":[");
    for(unsigned i=0;i<auto_identities.event_count;++i) {
        struct osrec_lifetime_event *event=&auto_identities.events[i];
        const char *kind=event->kind==OSREC_LIFETIME_EXISTING ? "existing" :
            event->kind==OSREC_LIFETIME_ALLOCATE ? "allocate" : "release";
        dprintf("%s{\"ordinal\":%u,\"id\":%u,\"kind\":\"%s\",\"size\":%u}",
            i ? "," : "",event->ordinal,event->id,kind,(unsigned)event->size);
    }
    dprintf("]}\n");
}
#endif
#include "wait_capture.h"
static ssize_t report_write(struct file *file,const char *buffer,size_t size)
{
    (void)file;
#ifdef OSREC_DUP_CAPTURE
    unsigned char observations[684];
#elif defined(OSREC_CLOSE_CAPTURE)
    unsigned char observations[684];
#elif defined(OSREC_UNAME_CAPTURE)
    unsigned char observations[604+UNAME_CALLS*408];
#elif defined(OSREC_RLIMIT_CAPTURE)
    unsigned char observations[796];
#elif defined(OSREC_CLOCK_CAPTURE)
    unsigned char observations[924];
#elif defined(OSREC_CREDENTIAL_OUTPUT_CAPTURE)
    unsigned char observations[716];
#elif defined(OSREC_GETSCHEDULER_CAPTURE)
    unsigned char observations[668];
#elif defined(OSREC_GETGROUPS_CAPTURE)
    unsigned char observations[688];
#elif defined(OSREC_ASYNC_WAIT_CAPTURE)
    unsigned char observations[612];
#else
    unsigned char observations[604];
#endif
    check(task_owner==(int)LOS_GetCurrProcessID() && index==4 && read_count==3 && identity_calls==7 && !identity_active && umask_calls==6 && task_calls==4 && credentials_calls==4 && getpriority_calls==6 && !getpriority_active && size==sizeof(observations)
#ifdef OSREC_FILE_CAPTURE
    +FILE_CALL_COUNT*224
#endif
    );
    check(LOS_ArchCopyFromUser(observations,buffer,sizeof(observations))==0);
#ifdef OSREC_ASYNC_WAIT_CAPTURE
    wait_report();hex("OSREC_WAIT_USER",observations+604,8);
#endif
    check(osrec_finish(&recorder)==0);
    dprintf("OSREC_LIVE_ENTRY pid=%d user_fd=3 system_fd=%d cursor=0 initial_errno=0\n",owner,system_fd);
    hex("OSREC_READS",storage,recorder.used);
    hex("OSREC_KERNEL",kernel_steps,sizeof(kernel_steps));
    hex("OSREC_USER",observations,112);
    hex("OSREC_PRIORITY",observations+112,36);
    hex("OSREC_PRIORITY_MIN",observations+148,36);
    hex("OSREC_PID",observations+184,8);
    hex("OSREC_IDENTITY",observations+192,112);
    hex("OSREC_IDENTITY_DEPS",identity_transcript,identity_events*16);
    hex("OSREC_UMASK_USER",observations+304,72);
    hex("OSREC_UMASK_KERNEL",umask_steps,sizeof(umask_steps));
    hex("OSREC_TASK_USER",observations+376,48);
    hex("OSREC_TASK_KERNEL",task_steps,sizeof(task_steps));
    hex("OSREC_CREDENTIALS_USER",observations+424,48);
    hex("OSREC_CREDENTIALS_KERNEL",credentials_steps,sizeof(credentials_steps));
    hex("OSREC_GETPRIORITY_USER",observations+472,96);
    hex("OSREC_GETPRIORITY_DEPS",getpriority_transcript,getpriority_events*20);
    hex("OSREC_SETGROUPS_USER",observations+568,36);
#ifdef OSREC_FILE_CAPTURE
    check(file_calls==FILE_CALL_COUNT && !file_active && !file_busy);
    for(unsigned i=0;i<FILE_CALL_COUNT;++i){unsigned char row[224];char label[32];
        check(__real_LOS_ArchCopyFromUser(row,buffer+604+224*i,224)==0);
        (void)sprintf(label,"OSREC_FILES_USER_%u",i);hex(label,row,224);}
    UINT32 file_abi[8]={sizeof(struct stat),sizeof(struct kstat),offsetof(struct stat,st_size),sizeof(((struct stat *)0)->st_size),CONFIG_NFILE_DESCRIPTORS,0,0,0};
#ifdef LOSCFG_FILE_MODE
    file_abi[5]=1;
#endif
#ifdef LOSCFG_PID_CONTAINER
    file_abi[6]=1;
#endif
#ifdef LOSCFG_PROC_PROCESS_DIR
    file_abi[7]=1;
#endif
    hex("OSREC_FILES_ABI",file_abi,sizeof(file_abi));
    hex("OSREC_FILES_KERNEL",file_steps,sizeof(file_steps));
    hex("OSREC_FILES_DEPS",file_events,file_event_count*sizeof(file_events[0]));
#endif
#ifdef OSREC_DUP_CAPTURE
    check(dup_calls==5 && dup_events==12 && !dup_active);
    hex("OSREC_DUP_USER",observations+604,80);
    hex("OSREC_DUP_KERNEL",dup_steps,sizeof(dup_steps));
    hex("OSREC_DUP_DEPS",dup_transcript,sizeof(dup_transcript));
#endif
#ifdef OSREC_CLOSE_CAPTURE
    check(close_calls==5 && close_events==15 && !close_active);
    hex("OSREC_CLOSE_USER",observations+604,80);
    hex("OSREC_CLOSE_KERNEL",close_steps,sizeof(close_steps));
    hex("OSREC_CLOSE_DEPS",close_transcript,sizeof(close_transcript));
#endif
#ifdef OSREC_UNAME_CAPTURE
    check(uname_calls==UNAME_CALLS && uname_events==UNAME_EVENTS && !uname_active);
    hex("OSREC_UNAME_USER",observations+604,UNAME_CALLS*408);
    hex("OSREC_UNAME_KERNEL",uname_steps,sizeof(uname_steps));
    hex("OSREC_UNAME_DEPS",uname_transcript,sizeof(uname_transcript));
#endif
#ifdef OSREC_RLIMIT_CAPTURE
    check(rlimit_calls==6 && rlimit_events==10 && !rlimit_active);
    hex("OSREC_RLIMIT_USER",observations+604,192);
    hex("OSREC_RLIMIT_KERNEL",rlimit_steps,sizeof(rlimit_steps));
    hex("OSREC_RLIMIT_DEPS",rlimit_transcript,rlimit_events*36);
#endif
#ifdef OSREC_CLOCK_CAPTURE
    check(clock_calls==10 && clock_events==14 && !clock_active);
    hex("OSREC_CLOCK_USER",observations+604,320);
    hex("OSREC_CLOCK_KERNEL",clock_steps,sizeof(clock_steps));
    hex("OSREC_CLOCK_DEPS",clock_transcript,clock_events*40);
#endif
#ifdef OSREC_GETSCHEDULER_CAPTURE
    #ifdef OSREC_GETSCHEDULER_TASK_CAPTURE
    check(scheduler_calls==4 && scheduler_events==8 && !scheduler_active);
#else
    check(scheduler_calls==4 && scheduler_events==5 && !scheduler_active);
#endif
    hex("OSREC_GETSCHEDULER_USER",observations+604,64);
    hex("OSREC_GETSCHEDULER_DEPS",scheduler_transcript,scheduler_events*24);
#endif
#ifdef OSREC_CREDENTIAL_OUTPUT_CAPTURE
    hex(RES_PREFIX "_USER",observations+604,112);
#endif
#ifdef OSREC_GETGROUPS_CAPTURE
    hex("OSREC_GETGROUPS_USER",observations+604,84);
#endif
#ifdef OSREC_AUTOMATED_ENTRY_STATE
    auto_report();
#endif
    dprintf("OSREC_LIVE_DONE\n");
    return (ssize_t)size;
}
static const struct file_operations_vfs report_ops={.write=report_write};
void OsrecLiveInit(void)
{
#ifdef OSREC_ASYNC_WAIT_CAPTURE
    wait_hooks_init();
#endif
    struct Vnode *mountpoint=NULL;
    check(VnodeLookup("/dev/shm",&mountpoint,V_CREATE|V_DUMMY)==0);
    mountpoint->mode=0755|S_IFDIR;
    mountpoint->type=VNODE_TYPE_DIR;
    check(mount(NULL,"/dev/shm","ramfs",0,NULL)==0);
    int fd=open("/dev/shm/input.bin",O_CREAT|O_WRONLY|O_TRUNC,0644);
    check(fd>=0);
    const unsigned char data[]=LIVE_PAYLOAD;
    check(write(fd,data,sizeof(data)-1)==(ssize_t)(sizeof(data)-1));
    check(close(fd)==0);
    check(register_driver("/dev/osrec-report",&report_ops,0600,NULL)==0);
    dprintf("OSREC_LIVE_READY RAMFS fixture bytes=%u\n",(unsigned)(sizeof(data)-1));
}
