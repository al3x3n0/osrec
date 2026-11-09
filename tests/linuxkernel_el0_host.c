#define _POSIX_C_SOURCE 200809L
/* Library front-door contracts, using an architecture/control-flow fixture.
 * This fixture is NOT a replacement implementation of Linux syscalls. */
#include "osrec/linuxkernel_el0.h"
#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

enum behavior { NORMAL, SIGNAL, RESTART, SIGRETURN, UNKNOWN_REGISTER, TLB,
                BAD_RETURN, BAD_STATUS, NESTED, BLOCK, BACKEND_FAULT, TRANSLATE, SIGNAL_BOUNDARY };
struct fixture {
    enum behavior behavior;
    unsigned runs, platforms;
    struct osrec_context expected;
    struct lk_el0_kernel *self;
    uint64_t *shared_memory;
};
static struct osrec_shadow a,b,saved;
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition=PTHREAD_COND_INITIALIZER;
static unsigned blocked,release_worker;

static enum lk_el0_status execute(void *opaque,struct osrec_shadow *s,
                                  struct osrec_context *c,struct lk_el0_diagnostic *d)
{
    struct fixture *f=opaque;
    f->runs++;
    assert(s->mode==OSREC_KERNEL && c->pc==s->vbar+0x400 && c->sp==0x9000);
    assert(s->elr==f->expected.pc+4 && s->spsr==f->expected.pstate);
    assert(s->sp_el0==f->expected.sp && s->far==0xf00d);
    assert(!memcmp(c->x,f->expected.x,sizeof c->x));
    s->value[1234]++;
    if(f->shared_memory)++*f->shared_memory;
    if(f->behavior==UNKNOWN_REGISTER)osrec_emulate_site(s,c,0xd5380000); // unknown MIDR
    if(f->behavior==TLB)osrec_emulate_site(s,c,0xd508871f);
    if(f->behavior==TRANSLATE){
        c->x[0]=0x1234;osrec_emulate_site(s,c,0xd5087820);
        assert(s->value[0xc3a0]==0x12345000);
    }
    if(f->behavior==BAD_RETURN)return LK_EL0_OK;
    if(f->behavior==BAD_STATUS)return (enum lk_el0_status)999;
    if(f->behavior==BACKEND_FAULT){
        *d=(struct lk_el0_diagnostic){OSREC_STOP_RUNTIME,c->pc,0xface,0xbeef};
        return LK_EL0_FAULT;
    }
    if(f->behavior==NESTED){
        struct lk_el0_result nested;
        assert(lk_el0_veneer(f->self,&f->expected,0xd4000001,&nested)==LK_EL0_BUSY);
        assert(lk_el0_destroy(f->self)==LK_EL0_BUSY);
    }
    if(f->behavior==BLOCK){
        pthread_mutex_lock(&mutex);blocked=1;pthread_cond_broadcast(&condition);
        while(!release_worker)pthread_cond_wait(&condition,&mutex);
        pthread_mutex_unlock(&mutex);
    }
    if(f->behavior==SIGNAL_BOUNDARY)assert(!raise(SIGUSR1));
    c->x[0]=(uint64_t)-14; // keep a Linux-style errno separate from library status
    if(f->behavior==SIGNAL){s->elr=0x6000;s->sp_el0=0x7000;c->x[0]=10;}
    if(f->behavior==RESTART){s->elr-=4;c->x[0]=f->expected.x[0];}
    if(f->behavior==SIGRETURN){
        for(unsigned r=0;r<31;r++)c->x[r]=0xaabbccdd00000000ull+r;
        s->elr=0x8800;s->sp_el0=0x7800;s->spsr=0x60001000;
    }
    osrec_emulate_site(s,c,0xd69f03e0);
    assert(s->mode==OSREC_USER);
    return LK_EL0_OK;
}

static int platform(void *opaque,enum lk_el0_platform_operation op,uint64_t arg,int extra,uint64_t *value)
{
    struct fixture *f=opaque;
    f->platforms++;
    if(op==LK_EL0_TRANSLATE){assert(arg==0x1234 && extra==1);*value=0x12345000;return 0;}
    assert(op==LK_EL0_TLB_FLUSH && arg==0 && extra==0);
    return 0;
}

static struct osrec_context input(unsigned seed)
{
    struct osrec_context c={0};
    for(unsigned r=0;r<31;r++)c.x[r]=0x1020304050607080ull*(r+1)^seed;
    c.sp=0x8000;c.pc=0x4000;c.pstate=(uint64_t)(seed&15)<<28;
    return c;
}

static void reset(struct osrec_shadow *s)
{ memset(s,0,sizeof *s);s->mode=OSREC_USER;s->vbar=0x800000;s->sp_el1=0x9000;s->far=0xf00d; }

static struct lk_el0_kernel *create(struct osrec_shadow *s,struct fixture *f,int hooks)
{
    struct lk_el0_backend backend={LK_EL0_ABI,execute,hooks?platform:NULL};
    struct lk_el0_kernel *k=NULL;
    reset(s);
    assert(lk_el0_create(s,&backend,f,&k)==LK_EL0_OK && k);
    f->self=k;
    return k;
}

static void equivalent_entries(void)
{
    for(unsigned behavior=NORMAL;behavior<=SIGRETURN;behavior++){
        struct fixture fa={0},fb={0};
        fa.behavior=fb.behavior=behavior;
        uint64_t shared=0;fa.shared_memory=&shared;
        struct lk_el0_kernel *ka=create(&a,&fa,0),*kb=create(&b,&fb,0);
        for(unsigned seed=0;seed<32;seed++){
            struct osrec_context user=input(seed),post=user;
            post.pc+=4;
            struct lk_el0_result ra,rb;
            fa.expected=fb.expected=user;
            uint32_t insn=0xd4000001u|((seed*211u&65535u)<<5);
            assert(lk_el0_veneer(ka,&user,insn,&ra)==LK_EL0_OK);
            assert(lk_el0_svc(kb,&post,insn,&rb)==LK_EL0_OK);
            assert(!memcmp(&ra,&rb,sizeof ra) && !memcmp(&a,&b,sizeof a));
            assert(a.esr==(0x56000000u|((insn>>5)&65535)));
            assert(a.value[1234]==seed+1 && a.entries==seed+1 && shared==seed+1);
            assert(!memcmp(&user,&fa.expected,sizeof user));
            if(behavior==NORMAL)assert(ra.context.x[0]==(uint64_t)-14 && ra.context.pc==0x4004);
            if(behavior==SIGNAL)assert(ra.context.pc==0x6000 && ra.context.sp==0x7000 && ra.context.x[0]==10);
            if(behavior==RESTART)assert(ra.context.pc==0x4000 && ra.context.x[0]==user.x[0]);
            if(behavior==SIGRETURN)assert(ra.context.pc==0x8800 && ra.context.sp==0x7800 && ra.context.pstate==0x60001000 && ra.context.x[30]==0xaabbccdd0000001eull);
        }
        assert(lk_el0_destroy(ka)==LK_EL0_OK && lk_el0_destroy(kb)==LK_EL0_OK);
    }
}

static void boundaries(void)
{
    for(unsigned behavior=UNKNOWN_REGISTER;behavior<=BACKEND_FAULT;behavior++){
        if(behavior==BLOCK)continue;
        struct fixture f={0};f.behavior=behavior;f.expected=input(0);
        struct lk_el0_kernel *k=create(&a,&f,0);
        struct lk_el0_result r;
        enum lk_el0_status status=lk_el0_veneer(k,&f.expected,0xd4000001,&r);
        if(behavior==NESTED){assert(status==LK_EL0_OK);}
        else {
            if(behavior==UNKNOWN_REGISTER)assert(status==LK_EL0_BOUNDARY && r.diagnostic.reason==OSREC_STOP_UNKNOWN_SYSREG && r.diagnostic.detail==0xc000);
            if(behavior==TLB)assert(status==LK_EL0_BOUNDARY && r.diagnostic.reason==OSREC_STOP_UNSUPPORTED && r.diagnostic.detail==LK_EL0_TLB_FLUSH);
            if(behavior==BAD_RETURN || behavior==BAD_STATUS)assert(status==LK_EL0_UNSUPPORTED && r.diagnostic.reason==OSREC_STOP_RUNTIME);
            if(behavior==BACKEND_FAULT)assert(status==LK_EL0_FAULT && r.diagnostic.far==0xbeef);
            assert(lk_el0_veneer(k,&f.expected,0xd4000001,&r)==LK_EL0_POISONED);
            assert(f.runs==1);
        }
        assert(lk_el0_destroy(k)==LK_EL0_OK);
    }
    for(unsigned i=0;i<2;i++){
        struct fixture f={0};f.behavior=i?TRANSLATE:TLB;f.expected=input(1);
        struct lk_el0_kernel *k=create(&a,&f,1);struct lk_el0_result r;
        assert(lk_el0_veneer(k,&f.expected,0xd4000001,&r)==LK_EL0_OK && f.platforms==1);
        assert(lk_el0_destroy(k)==LK_EL0_OK);
    }
}

static void invalid_inputs(void)
{
    struct fixture f={0};f.expected=input(0);
    struct lk_el0_kernel *k=create(&a,&f,0);
    struct lk_el0_result r;
    saved=a;
    assert(lk_el0_veneer(k,&f.expected,0xd4000002,&r)==LK_EL0_BAD_ARGUMENT); // HVC
    assert(!memcmp(&a,&saved,sizeof a));
    for(unsigned i=0;i<4;i++){
        struct osrec_context c=f.expected;
        if(i==0)c.pc++;if(i==1)c.pstate=5;if(i==2)c.pc=UINT64_MAX-3;if(i==3)c.pstate|=1ull<<20;
        assert(lk_el0_veneer(k,&c,0xd4000001,&r)==LK_EL0_BAD_ARGUMENT);
        assert(!memcmp(&a,&saved,sizeof a));
    }
    struct osrec_context c=f.expected;c.pc=0;
    assert(lk_el0_svc(k,&c,0xd4000001,&r)==LK_EL0_BAD_ARGUMENT);
    assert(lk_el0_call(NULL,&c,0xd4000001,&r)==LK_EL0_BAD_ARGUMENT);
    assert(lk_el0_call(k,NULL,0xd4000001,&r)==LK_EL0_BAD_ARGUMENT);
    assert(lk_el0_call(k,&c,0xd4000001,NULL)==LK_EL0_BAD_ARGUMENT);
    assert(!f.runs && !memcmp(&a,&saved,sizeof a));
    // Rejected input does not poison the instance; input may alias output.
    r.context=f.expected;
    assert(lk_el0_veneer(k,&r.context,0xd4000001,&r)==LK_EL0_OK);
    assert(lk_el0_destroy(k)==LK_EL0_OK);
    assert(lk_el0_destroy(NULL)==LK_EL0_BAD_ARGUMENT);
    struct lk_el0_backend backend={99,execute,NULL};k=(void *)1;reset(&a);
    assert(lk_el0_create(&a,&backend,&f,&k)==LK_EL0_BAD_ARGUMENT && !k);
}

static void *thread_call(void *opaque)
{
    struct fixture *f=opaque;struct lk_el0_result r;
    assert(lk_el0_veneer(f->self,&f->expected,0xd4000001,&r)==LK_EL0_OK);
    return NULL;
}

static void concurrent_call(void)
{
    struct fixture f={0};f.behavior=BLOCK;f.expected=input(0);
    struct lk_el0_kernel *k=create(&a,&f,0);pthread_t thread;
    assert(!pthread_create(&thread,NULL,thread_call,&f));
    pthread_mutex_lock(&mutex);
    while(!blocked)pthread_cond_wait(&condition,&mutex);
    pthread_mutex_unlock(&mutex);
    struct lk_el0_result r;
    assert(lk_el0_veneer(k,&f.expected,0xd4000001,&r)==LK_EL0_BUSY);
    assert(lk_el0_destroy(k)==LK_EL0_BUSY);
    pthread_mutex_lock(&mutex);release_worker=1;pthread_cond_broadcast(&condition);pthread_mutex_unlock(&mutex);
    assert(!pthread_join(thread,NULL));
    assert(lk_el0_destroy(k)==LK_EL0_OK);
}

static void signal_boundary_handler(int signo)
{ (void)signo;osrec_platform_stop(OSREC_STOP_UNSUPPORTED,0x800400,0xdead,0xbeef); }

static void signal_boundary(void)
{
    struct sigaction action={0},previous;
    sigset_t mask,old_mask;
    sigemptyset(&action.sa_mask);action.sa_handler=signal_boundary_handler;
    assert(!sigaction(SIGUSR1,&action,&previous));
    sigemptyset(&mask);sigaddset(&mask,SIGUSR1);
    assert(!pthread_sigmask(SIG_UNBLOCK,&mask,&old_mask));
    struct fixture f={0};f.behavior=SIGNAL_BOUNDARY;f.expected=input(0);
    struct lk_el0_kernel *k=create(&a,&f,0);struct lk_el0_result r;
    assert(lk_el0_veneer(k,&f.expected,0xd4000001,&r)==LK_EL0_BOUNDARY);
    assert(r.diagnostic.detail==0xdead && r.diagnostic.far==0xbeef);
    assert(!pthread_sigmask(SIG_SETMASK,NULL,&mask));
    assert(!sigismember(&mask,SIGUSR1)); // siglongjmp restored the call mask
    assert(lk_el0_destroy(k)==LK_EL0_OK);
    assert(!sigaction(SIGUSR1,&previous,NULL));
    assert(!pthread_sigmask(SIG_SETMASK,&old_mask,NULL));
}

int main(void)
{
    equivalent_entries();boundaries();invalid_inputs();concurrent_call();signal_boundary();
    puts("library contracts passed: 128 paired entries, persistent memory, boundaries, busy calls");
    return 0;
}
