#define OSREC_FILES_REPLAY 1
#include "files_model.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
unsigned char file_pool;
static uint32_t invocation,cursor,state[15],error,path_allocated,path_kind,opens,lock_depth;
static uint32_t range_checks,errno_reads,copies,copy_bytes,reads,read_bytes,writes,write_bytes,verified;
static unsigned char witness[192] __attribute__((aligned(8))),content[8];
static unsigned length;
static char path_buffer[64];
static const char main_path[]="/dev/shm/osrec-file.bin",missing_path[]="/dev/shm/osrec-missing.bin";
static LosVmSpace space;
static FileProcess process={&space};
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(uint32_t code){osrec_result[0]=0x4f535243;osrec_result[1]=17;osrec_result[3]=code;osrec_result[31]=invocation;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
void *memset(void *out,int value,size_t n){unsigned char *p=out;for(size_t i=0;i<n;++i)p[i]=(unsigned char)value;return out;}
static void bytes(void *out,const void *in,unsigned n){for(unsigned j=0;j<n;++j)((unsigned char *)out)[j]=((const unsigned char *)in)[j];}
static void equal(const void *a,const void *b,unsigned n){for(unsigned j=0;j<n;++j)if(((const unsigned char *)a)[j]!=((const unsigned char *)b)[j])fail(1);}
static uint64_t get64(const unsigned char *p){uint64_t v=0;for(unsigned j=0;j<8;++j)v|=(uint64_t)p[j]<<(8*j);return v;}
static uint32_t pointer(const void *p){return !p ? 0 : p==(void *)(uintptr_t)1 ? 2 : p==witness ? 1 : 3;}
static uint32_t path(const char *p){return !p ? 0 : p==(void *)(uintptr_t)1 ? 3 : p==main_path ? 1 : p==missing_path ? 2 : p==path_buffer && path_allocated ? path_kind : 4;}
static unsigned slot(int fd){if(fd<4 || fd>6)fail(2);return 3*(unsigned)(fd-4);}
static unsigned file(int fd){if((uint32_t)fd==FILE_SYSTEM_A)return 9;if((uint32_t)fd==FILE_SYSTEM_B)return 12;fail(3);return 0;}
static void position(unsigned i,int64_t pos){if(pos<0 || pos>8)fail(4);state[i+1]=(uint32_t)pos;state[i+2]=0;}
static const struct files_event *event(uint32_t kind,uint32_t a,uint32_t b,uint32_t c)
{
    if(cursor>=FILE_EVENT_COUNT)fail(5);
    const struct files_event *e=&files_events[cursor++];
    if(e->invocation!=invocation || e->kind!=kind || e->a!=a || e->b!=b || e->c!=c)fail(6);
    for(unsigned j=0;j<15;++j)if(e->before[j]!=state[j])fail(7);return e;
}
static void effect(const struct files_event *e,uint32_t raw,const void *data,unsigned size)
{
    if(e->raw!=raw || e->error!=error || e->length!=size || size>192)fail(8);
    if(size)equal(e->data,data,size);
    for(unsigned j=0;j<15;++j)if(e->after[j]!=state[j])fail(9);
}
FileProcess *OsCurrProcessGet(void){return &process;}
int LOS_IsUserAddressRange(VADDR_T p,size_t n){++range_checks;return p==(uintptr_t)witness && n>0 && n<=192;}
int LOS_MuxAcquire(int *mutex){const struct files_event *e=event(22,1,UINT32_MAX,0);if(mutex!=&space.regionMux || lock_depth)fail(10);lock_depth=1;effect(e,0,NULL,0);return 0;}
int LOS_MuxRelease(int *mutex){const struct files_event *e=event(23,1,0,0);if(mutex!=&space.regionMux || lock_depth!=1)fail(11);lock_depth=0;effect(e,0,NULL,0);return 0;}
int CheckRegion(const LosVmSpace *vm,VADDR_T p,size_t n){const struct files_event *e=event(21,pointer((void *)p),(uint32_t)n,0);if(vm!=&space || lock_depth!=1 || p!=(uintptr_t)witness || n>8)fail(12);effect(e,0,NULL,0);return 0;}
void set_errno(int value){error=(uint32_t)value;}
int get_errno(void){++errno_reads;return (int)error;}
int UserPathCopy(const char *source,char **out)
{
    uint32_t kind=path(source);const struct files_event *e=event(1,kind,0,0);if(!out || path_allocated)fail(13);
    if(kind==3){*out=NULL;effect(e,UINT32_C(0xfffffff2),NULL,0);return -14;}
    if(kind!=1 && kind!=2)fail(14);
    unsigned n=kind==1 ? sizeof(main_path) : sizeof(missing_path);bytes(path_buffer,source,n);path_allocated=1;path_kind=kind;*out=path_buffer;effect(e,0,source,n);return 0;
}
int AllocProcessFd(void)
{
    const struct files_event *e=event(2,0,0,0);int fd=-1;for(unsigned j=0;j<3;++j)if(!state[3*j+1]){state[3*j+1]=1;fd=(int)j+4;break;}
    if(fd<0)fail(15);effect(e,(uint32_t)fd,NULL,0);return fd;
}
void SetCloexecFlag(int fd){const struct files_event *e=event(3,(uint32_t)fd,0,0);state[slot(fd)+2]=1;effect(e,0,NULL,0);}
int do_open(int dir,const char *name,int flags,mode_t mode)
{
    uint32_t kind=path(name);const struct files_event *e=event(4,(uint32_t)dir,kind,(uint32_t)flags);int ret;
    if(dir!=-100 || !path_allocated)fail(16);
    if(kind==2){error=2;ret=-1;}
    else {
        if(kind!=1 || opens>=2)fail(17);ret=(int)(opens++ ? FILE_SYSTEM_B : FILE_SYSTEM_A);unsigned i=file(ret);state[i]=1;position(i,0);
        if(flags&0x200){length=0;memset(content,0,8);}
    }
    effect(e,(uint32_t)ret,&mode,4);return ret;
}
int do_opendir(const char *p,int flags){(void)p;(void)flags;fail(90);return -1;}
void AssociateSystemFd(int fd,int system){const struct files_event *e=event(5,(uint32_t)fd,(uint32_t)system,0);unsigned i=slot(fd);(void)file(system);if(!state[i+1])fail(18);state[i]=(uint32_t)system;effect(e,0,NULL,0);}
void FreeProcessFd(int fd){const struct files_event *e=event(16,(uint32_t)fd,0,0);unsigned i=slot(fd);state[i]=UINT32_MAX;state[i+1]=0;state[i+2]=0;effect(e,0,NULL,0);}
uint32_t LOS_MemFree(void *pool,void *address){const struct files_event *e=event(6,1,1,0);if(pool!=OS_SYS_MEM_ADDR || address!=path_buffer || !path_allocated)fail(19);path_allocated=0;effect(e,0,NULL,0);return 0;}
int GetAssociatedSystemFd(int fd){const struct files_event *e=event(7,(uint32_t)fd,0,0);uint32_t result=fd>=4 && fd<=6 ? state[slot(fd)] : UINT32_MAX;effect(e,result,NULL,0);return (int32_t)result;}
int DisassociateProcessFd(int fd){const struct files_event *e=event(14,(uint32_t)fd,0,0);unsigned i=slot(fd);uint32_t result=state[i];state[i]=UINT32_MAX;effect(e,result,NULL,0);return (int32_t)result;}
ssize_t write(int fd,const void *in,size_t size)
{
    const struct files_event *e=event(8,(uint32_t)fd,pointer(in),(uint32_t)size);++writes;int ret;
    if(size>8 || in!=witness)fail(20);
    if(fd==-1){error=9;ret=-1;}
    else {unsigned i=file(fd),pos=state[i+1];if(!state[i] || pos+size>8 || state[i+2])fail(21);bytes(content+pos,in,(unsigned)size);if(pos+size>length)length=pos+(unsigned)size;position(i,(int64_t)(pos+size));ret=(int)size;write_bytes+=(unsigned)size;}
    effect(e,(uint32_t)ret,in,(unsigned)size);return ret;
}
ssize_t read(int fd,void *out,size_t size)
{
    const struct files_event *e=event(9,(uint32_t)fd,pointer(out),(uint32_t)size);++reads;int ret;const void *data=NULL;
    if(out!=witness || size>8)fail(22);
    if(fd==-1){error=9;ret=-1;}
    else {unsigned i=file(fd),pos=state[i+1];if(!state[i] || pos>length || state[i+2])fail(23);unsigned n=(unsigned)size;if(n>length-pos)n=length-pos;data=content+pos;bytes(out,data,n);position(i,pos+n);ret=(int)n;read_bytes+=n;}
    effect(e,(uint32_t)ret,data,ret>0 ? (unsigned)ret : 0);return ret;
}
off64_t _lseek64(int fd,int high,int low,off64_t *out,int whence)
{
    const struct files_event *e=event(10,(uint32_t)fd,(uint32_t)whence,(uint32_t)high);unsigned char data[12];bytes(data,&low,4);int ret;
    if(!out)fail(24);
    if(fd==-1){error=9;ret=-9;}
    else {unsigned i=file(fd);int64_t offset=(int64_t)(((uint64_t)(uint32_t)high<<32)|(uint32_t)low);int64_t pos=offset+(whence==1 ? state[i+1] : whence==2 ? length : 0);position(i,pos);*out=pos;bytes(data+4,out,8);ret=0;}
    effect(e,(uint32_t)ret,data,ret ? 4 : 12);return ret;
}
static int metadata(const struct files_event *e,struct stat *out,unsigned valid,uint32_t bad_error)
{
    int ret=valid ? 0 : -1;
    if(valid){if(!out || e->length!=FILE_STAT_SIZE || get64(e->data+FILE_SIZE_OFFSET)!=length)fail(25);bytes(out,e->data,FILE_STAT_SIZE);}
    else error=bad_error;
    effect(e,(uint32_t)ret,valid ? out : NULL,valid ? FILE_STAT_SIZE : 0);return ret;
}
int fstat64(int fd,struct stat *out){const struct files_event *e=event(12,(uint32_t)fd,out ? 1 : 0,0);return metadata(e,out,fd!=-1,9);}
int stat(const char *name,struct stat *out){unsigned kind=path(name);const struct files_event *e=event(13,kind,out ? 1 : 0,0);return metadata(e,out,kind==1 && out,kind==0 || !out ? 14 : 2);}
size_t LOS_ArchCopyToUser(void *out,const void *in,size_t n)
{
    const struct files_event *e=event(11,pointer(out),(uint32_t)n,0);++copies;
    if(!in || n>192 || (out!=witness && out!=(void *)(uintptr_t)1))fail(26);
    uint32_t ret=out==witness ? 0 : (uint32_t)n;effect(e,ret,in,(unsigned)n);
    if(!ret){bytes(out,in,(unsigned)n);copy_bytes+=(uint32_t)n;}return ret;
}
int close(int fd){const struct files_event *e=event(15,(uint32_t)fd,0,0);unsigned i=file(fd);if(!state[i])fail(27);--state[i];if(!state[i])position(i,0);effect(e,0,NULL,0);return 0;}
int CheckProcessFd(int fd){const struct files_event *e=event(17,(uint32_t)fd,0,0);uint32_t ret=fd>=0 && fd<1024 ? 0 : UINT32_MAX;effect(e,ret,NULL,0);return (int32_t)ret;}
int AllocSpecifiedProcessFd(int fd){const struct files_event *e=event(18,(uint32_t)fd,0,0);unsigned i=slot(fd);state[i]=UINT32_MAX;state[i+1]=1;effect(e,0,NULL,0);return 0;}
void files_refer(int fd){const struct files_event *e=event(19,(uint32_t)fd,0,0);unsigned i=file(fd);if(!state[i] || state[i]>=2)fail(28);++state[i];effect(e,0,NULL,0);}
void ClearCloexecFlag(int fd){const struct files_event *e=event(20,(uint32_t)fd,0,0);state[slot(fd)+2]=0;effect(e,0,NULL,0);}
static const char *path_argument(uint32_t kind){return kind==1 ? main_path : kind==2 ? missing_path : kind==3 ? (void *)(uintptr_t)1 : NULL;}
static void *buffer_argument(uint32_t kind){return kind==1 ? witness : kind==2 ? (void *)(uintptr_t)1 : NULL;}
static uint32_t returns_hash(uint32_t hash,uint32_t raw){return (hash^raw)*UINT32_C(16777619);}
void replay_main(void)
{
    osrec_result[0]=0x4f535243;osrec_result[1]=17;osrec_result[2]=1;state[0]=UINT32_MAX;state[3]=UINT32_MAX;state[6]=UINT32_MAX;
    uint32_t hash=UINT32_C(2166136261);
    for(invocation=0;invocation<FILE_CALL_COUNT;++invocation){
        const struct files_call *c=&files_calls[invocation];error=0;
        if(cursor!=c->event_start || path_allocated || lock_depth)fail(29);
        for(unsigned j=0;j<15;++j)if(c->before[j]!=state[j])fail(30);bytes(witness,c->buffer_before,192);
        int ret;const uint32_t *a=c->args;
        switch(c->number){
        case 5:ret=SysOpen(path_argument(a[0]),(int)a[1],(int)a[2]);break;
        case 322:ret=SysOpenat((int32_t)a[0],path_argument(a[1]),(int)a[2],(int)a[3]);break;
        case 4:ret=(int)SysWrite((int32_t)a[0],buffer_argument(a[1]),a[2]);break;
        case 3:ret=(int)SysRead((int32_t)a[0],buffer_argument(a[1]),a[2]);break;
        case 140:ret=(int)SysLseek64((int32_t)a[0],(int32_t)a[1],(int32_t)a[2],buffer_argument(a[3]),(int32_t)a[4]);break;
        case 197:ret=SysFstat64((int32_t)a[0],buffer_argument(a[1]));break;
        case 106:ret=SysStat(path_argument(a[0]),buffer_argument(a[1]));break;
        case 63:ret=SysDup2((int32_t)a[0],(int32_t)a[1]);break;
        case 6:ret=SysClose((int32_t)a[0]);break;
        default:fail(31);ret=0;
        }
        if((uint32_t)ret!=c->raw || error!=c->error || cursor!=c->event_end || path_allocated || lock_depth)fail(32);
        for(unsigned j=0;j<15;++j)if(c->after[j]!=state[j])fail(33);equal(witness,c->buffer_after,192);
        ++verified;hash=returns_hash(hash,(uint32_t)ret);osrec_result[4]=invocation+1;
    }
    if(cursor!=FILE_EVENT_COUNT || verified!=32 || length!=4 || path_allocated || lock_depth)fail(34);
    equal(content,"abXY",4);for(unsigned j=0;j<15;++j)if(state[j]!=(j==0 || j==3 || j==6 ? UINT32_MAX : 0))fail(35);
    osrec_result[5]=cursor;osrec_result[6]=FILE_EVENT_COUNT;osrec_result[7]=verified;osrec_result[8]=verified;osrec_result[9]=path_allocated;
    osrec_result[10]=hash;osrec_result[11]=FILE_RETURN_HASH;osrec_result[12]=range_checks;osrec_result[13]=errno_reads;
    osrec_result[14]=copies;osrec_result[15]=copy_bytes;osrec_result[16]=reads;osrec_result[17]=read_bytes;osrec_result[18]=writes;osrec_result[19]=write_bytes;
    osrec_result[20]=length;osrec_result[21]=(uint32_t)get64((const unsigned char[]){content[0],content[1],content[2],content[3],0,0,0,0});
    osrec_result[22]=state[9];osrec_result[23]=state[12];osrec_result[24]=lock_depth;osrec_result[25]=FILE_SYSTEM_A;osrec_result[26]=FILE_SYSTEM_B;
    osrec_result[27]=FILE_STAT_SIZE;osrec_result[28]=FILE_KSTAT_SIZE;osrec_result[29]=8;osrec_result[30]=3;osrec_result[31]=FILE_CALL_COUNT;
    __asm__ volatile("dsb sy" ::: "memory");osrec_result[2]=2;stop();
}
