/* Repository-owned Linux syscall edge. This is deliberately a small, bounded
 * implementation for one executor thread, not a general C runtime. */
#include "standalone.h"
int errno;
static uint64_t page_size;
long lk_syscall6(long nr,long a,long b,long c,long d,long e,long f)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f;
    register long x8 __asm__("x8")=nr;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");
    if((unsigned long)x0>=(unsigned long)-4095){errno=(int)-x0;return -1;}
    return x0;
}
#define CALL(n,a,b,c,d,e,f) lk_syscall6(__NR_##n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
long syscall(long nr,...)
{
    if(nr==__NR_gettid)return CALL(gettid,0,0,0,0,0,0);
    if(nr==__NR_tgkill) {
        va_list ap;va_start(ap,nr);int pid=va_arg(ap,int);long tid=va_arg(ap,long);int sig=va_arg(ap,int);va_end(ap);
        return CALL(tgkill,pid,tid,sig,0,0,0);
    }
    errno=ENOSYS;return -1;
}
int getpid(void){return CALL(getpid,0,0,0,0,0,0);}
void *mmap(void *p,size_t size,int prot,int flags,int fd,off_t offset)
{return (void *)CALL(mmap,p,size,prot,flags,fd,offset);}
int munmap(void *p,size_t size){return CALL(munmap,p,size,0,0,0,0);}
int mprotect(void *p,size_t size,int prot){return CALL(mprotect,p,size,prot,0,0,0);}
int memfd_create(const char *name,unsigned flags){return CALL(memfd_create,name,flags,0,0,0,0);}
int ftruncate(int fd,off_t size){return CALL(ftruncate,fd,size,0,0,0,0);}
int fstat(int fd,struct stat *st){return CALL(fstat,fd,st,0,0,0,0);}
off_t lseek(int fd,off_t at,int whence){return CALL(lseek,fd,at,whence,0,0,0);}
ssize_t read(int fd,void *p,size_t size){return CALL(read,fd,p,size,0,0,0);}
ssize_t pwrite(int fd,const void *p,size_t size,off_t at){return CALL(pwrite64,fd,p,size,at,0,0);}
int close(int fd){return CALL(close,fd,0,0,0,0,0);}
long sysconf(int name){if(name==_SC_PAGESIZE)return page_size;errno=EINVAL;return -1;}
extern void lk_host_sigreturn(void);
int sigaction(int sig,const struct sigaction *action,struct sigaction *old)
{
    struct sigaction actual;
    if(action){actual=*action;actual.sa_flags|=SA_RESTORER;actual.sa_restorer=lk_host_sigreturn;action=&actual;}
    return CALL(rt_sigaction,sig,action,old,sizeof(sigset_t),0,0);
}
int sigaltstack(const stack_t *stack,stack_t *old){return CALL(sigaltstack,stack,old,0,0,0,0);}
int sigprocmask(int how,const sigset_t *mask,sigset_t *old){return CALL(rt_sigprocmask,how,mask,old,sizeof(sigset_t),0,0);}
int sigfillset(sigset_t *mask){mask->sig[0]=~0ul;return 0;}
int sigdelset(sigset_t *mask,int sig)
{if(sig<1 || sig>64){errno=EINVAL;return -1;}mask->sig[0]&=~(1ul<<(sig-1));return 0;}
void lk_jump_prepare(sigjmp_buf env,int save)
{
    env->saved=save!=0;
    if(save && sigprocmask(SIG_SETMASK,NULL,(sigset_t *)&env->mask))lk_host_exit(125);
}
extern void lk_longjmp(sigjmp_buf,int) __attribute__((noreturn));
void siglongjmp(sigjmp_buf env,int value)
{
    if(env->saved && sigprocmask(SIG_SETMASK,(sigset_t *)&env->mask,NULL))lk_host_exit(125);
    lk_longjmp(env,value);
}
void *memcpy(void *out,const void *in,size_t size)
{unsigned char *d=out;const unsigned char *s=in;for(size_t i=0;i<size;i++)d[i]=s[i];return out;}
void *memset(void *out,int byte,size_t size)
{unsigned char *d=out;for(size_t i=0;i<size;i++)d[i]=(unsigned char)byte;return out;}
int memcmp(const void *a,const void *b,size_t size)
{const unsigned char *x=a,*y=b;for(size_t i=0;i<size;i++)if(x[i]!=y[i])return (int)x[i]-y[i];return 0;}
size_t strlen(const char *s){size_t n=0;while(s[n])n++;return n;}
int strcmp(const char *a,const char *b)
{while(*a && *a==*b){a++;b++;}return (unsigned char)*a-(unsigned char)*b;}
/* Front-end objects live in a separate fixed window, never a guest VMA hole.
 * Each allocation has its own mapping, reclaimed by free. No malloc or brk. */
void *calloc(size_t count,size_t bytes)
{
    static uintptr_t next=0x1c0000000000ull;
    if(bytes && count>SIZE_MAX/bytes){errno=ENOMEM;return NULL;}
    size_t size=count*bytes;
    if(size>SIZE_MAX-4111){errno=ENOMEM;return NULL;}
    size=(size+16+4095)&~(size_t)4095;
    if(size>(64ull<<20) || next>0x1c0004000000ull-size){errno=ENOMEM;return NULL;}
    void *p=mmap((void *)next,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    if(p==MAP_FAILED)return NULL;
    if(p!=(void *)next){munmap(p,size);errno=ENOMEM;return NULL;}
    next+=size;*(size_t *)p=size;return (char *)p+16;
}
void free(void *p){if(p){void *base=(char *)p-16;munmap(base,*(size_t *)base);}}
/* Compiler-generated cache maintenance call; use the host CTR, not guest DCZID. */
void __clear_cache(void *start,void *end)
{
    uint64_t ctr;__asm__ volatile("mrs %0,ctr_el0":"=r"(ctr));
    uintptr_t lo=(uintptr_t)start,hi=(uintptr_t)end;
    if(!(ctr&(1ull<<28))) {
        uintptr_t step=4ull<<((ctr>>16)&15);
        for(uintptr_t p=lo&~(step-1);p<hi;p+=step)__asm__ volatile("dc cvau,%0"::"r"(p):"memory");
    }
    __asm__ volatile("dsb ish":::"memory");
    if(!(ctr&(1ull<<29))) {
        uintptr_t step=4ull<<(ctr&15);
        for(uintptr_t p=lo&~(step-1);p<hi;p+=step)__asm__ volatile("ic ivau,%0"::"r"(p):"memory");
        __asm__ volatile("dsb ish":::"memory");
    }
    __asm__ volatile("isb":::"memory");
}
static FILE standard_out={.fd=1},standard_error={.fd=2},trace_file;
FILE *stdout=&standard_out,*stderr=&standard_error;
static int flush(FILE *out)
{
    size_t at=0;
    while(at<out->used) {
        long n=CALL(write,out->fd,out->bytes+at,out->used-at,0,0,0);
        if(n<0 && errno==EINTR)continue;
        if(n<=0){out->error=1;out->used=0;return -1;}at+=(size_t)n;
    }
    out->used=0;return out->error?-1:0;
}
size_t fwrite(const void *data,size_t size,size_t count,FILE *out)
{
    if(!size)return 0;
    if(size && count>SIZE_MAX/size){out->error=1;return 0;}
    size_t left=size*count;const char *p=data;
    while(left && !out->error) {
        size_t n=sizeof out->bytes-out->used;if(n>left)n=left;
        memcpy(out->bytes+out->used,p,n);out->used+=n;p+=n;left-=n;
        if(out->used==sizeof out->bytes)flush(out);
    }
    return size?(size*count-left)/size:count;
}
FILE *fopen(const char *path,const char *mode)
{
    if(strcmp(mode,"w") || trace_file.owned){errno=EINVAL;return NULL;}
    int fd=CALL(openat,AT_FDCWD,path,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0666,0,0);
    if(fd<0)return NULL;memset(&trace_file,0,sizeof trace_file);trace_file.fd=fd;trace_file.owned=1;return &trace_file;
}
int fclose(FILE *out){int result=flush(out);if(out->owned && close(out->fd))result=-1;out->owned=0;return result;}
int ferror(FILE *out){return flush(out);}
static int format(FILE *out,const char *fmt,va_list ap)
{
    int count=0;
    while(*fmt && !out->error) {
        const char *start=fmt;while(*fmt && *fmt!='%')fmt++;
        size_t n=fmt-start;fwrite(start,1,n,out);count+=(int)n;if(!*fmt)break;
        fmt++;
        if(*fmt=='s'){const char *s=va_arg(ap,const char *);n=strlen(s);fwrite(s,1,n,out);count+=(int)n;fmt++;}
        else if(*fmt=='%'){fwrite("%",1,1,out);fmt++;count++;}
        else {
            int wide=*fmt=='l';if(wide)fmt++;
            unsigned radix=*fmt=='x'?16:10;
            if(*fmt!='u' && *fmt!='x'){out->error=1;break;}fmt++;
            uint64_t value=wide?va_arg(ap,unsigned long):va_arg(ap,unsigned int);
            char digits[32];n=0;
            do{digits[31-n++]="0123456789abcdef"[value%radix];value/=radix;}while(value);
            fwrite(digits+32-n,1,n,out);count+=(int)n;
        }
    }
    /* Stdout/stderr messages are short; deliver even before a failing run. */
    if(out==stdout || out==stderr)flush(out);
    return out->error?-1:count;
}
int fprintf(FILE *out,const char *fmt,...)
{va_list ap;va_start(ap,fmt);int n=format(out,fmt,ap);va_end(ap);return n;}
int printf(const char *fmt,...)
{va_list ap;va_start(ap,fmt);int n=format(stdout,fmt,ap);va_end(ap);return n;}
int puts(const char *s){fwrite(s,1,strlen(s),stdout);fwrite("\n",1,1,stdout);return flush(stdout);}
void lk_host_exit(int status)
{CALL(exit_group,status,0,0,0,0,0);__builtin_trap();}
extern int main(int,char **);
void lk_host_start(uint64_t *stack)
{
    int argc=(int)*stack;char **argv=(char **)(stack+1),**env=argv+argc+1;
    while(*env)env++;
    uint64_t *aux=(uint64_t *)(env+1);
    for(;aux[0];aux+=2)if(aux[0]==6)page_size=aux[1]; /* AT_PAGESZ */
    if(page_size!=4096)lk_host_exit(126);
    int result=main(argc,argv);
    if(flush(stdout) || flush(stderr))result=1;
    lk_host_exit(result);
}
