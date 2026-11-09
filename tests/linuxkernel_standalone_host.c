/* Real Linux ABI checks for the libc-free edge, before loading guest state. */
#include "standalone.h"
#define CHECK(test) do {if(!(test)){fprintf(stderr,"host assertion at line %u\n",(unsigned)__LINE__);return 1;}} while(0)
static sigjmp_buf jump;
static volatile uintptr_t handler_sp;
static volatile int signal_seen;
static void caught(int signal,siginfo_t *info,void *context)
{
    (void)info;
    ucontext_t *u=context;
    struct _aarch64_ctx *head=(void *)u->uc_mcontext.__reserved;
    signal_seen=signal==SIGUSR1 && head->magic==FPSIMD_MAGIC;
    __asm__ volatile("mov %0,sp":"=r"(handler_sp));
    siglongjmp(jump,7);
}
int main(int argc,char **argv)
{
    CHECK(argc>=1 && argv && argv[0]);CHECK(sysconf(_SC_PAGESIZE)==4096);
    void *allocation=calloc(1,65536);CHECK(allocation && (uintptr_t)allocation>=0x1c0000000000ull);
    for(unsigned i=0;i<65536;i++)CHECK(!((unsigned char *)allocation)[i]);
    memset(allocation,0x5a,65536);free(allocation);
    CHECK(!calloc(SIZE_MAX,2) && errno==ENOMEM);
    struct stat st;CHECK(fstat(-1,&st)==-1 && errno==EBADF);
    void *stack=calloc(1,65536);CHECK(stack);
    stack_t alt={.ss_sp=stack,.ss_size=65536},old;
    CHECK(!sigaltstack(&alt,&old));
    struct sigaction action={.sa_sigaction=caught,.sa_flags=SA_SIGINFO|SA_ONSTACK},previous;
    CHECK(!sigaction(SIGUSR1,&action,&previous));
    sigset_t mask={.sig={1ul<<(SIGUSR2-1)}},before,actual;
    CHECK(!sigprocmask(SIG_SETMASK,&mask,&before));
    int returned=sigsetjmp(jump,1);
    if(!returned){syscall(SYS_tgkill,getpid(),syscall(SYS_gettid),SIGUSR1);CHECK(0);}
    CHECK(returned==7 && signal_seen);
    CHECK(handler_sp>=(uintptr_t)stack && handler_sp<(uintptr_t)stack+65536);
    CHECK(!sigprocmask(SIG_SETMASK,NULL,&actual) && actual.sig[0]==mask.sig[0]);
    CHECK(!sigaltstack(&old,NULL));CHECK(!sigaction(SIGUSR1,&previous,NULL));
    CHECK(!sigprocmask(SIG_SETMASK,&before,NULL));free(stack);
    puts("standalone Linux startup, syscalls, signals, alternate stack and jump recovery passed");return 0;
}
