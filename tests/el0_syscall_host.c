/* Differential reference for logical SVC entry without context gateways. */
#include "program.h"
struct osrec_shadow flat_shadow;
struct flat_full_image flat_program;
struct flat_control control,*flat_active=&control;
struct flat_event flat_events[1024];
struct flat_observer_pending flat_observer_pending;
uint64_t flat_event_count,test_fast,test_target,flat_direct_pc_count;
extern void resume0(void),resume1(void),resume2(void);
const struct flat_pc flat_direct_pcs[]={{0,resume0},{0x5000,resume1},{0xa000,resume2}};
static unsigned char stack[16384] __attribute__((aligned(16)));
typedef void (*probe)(const struct osrec_context *,struct osrec_context *);
struct fixture {uint64_t pc;unsigned word;probe run;};
#include "cases.h"
static void clear(void *v,size_t n){unsigned char *p=v;while(n--)*p++=0;}
static int equal(const void *a,const void *b,size_t n)
{const unsigned char *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
void osrec_platform_stop(uint64_t a,uint64_t b,uint64_t c,uint64_t d)
{(void)a;(void)b;(void)c;(void)d;__builtin_trap();}
int test_main(void)
{
    static struct osrec_shadow reference;
    const uint64_t extras[]={0,1ull<<12,2,1ull<<63};
    const uint64_t vectors[]={0x4c00,0x9c00,0xfc00,~1023ull};
    const uint64_t counts[]={0,7,1023,1024};
    for(unsigned f=0;f<sizeof fixtures/sizeof fixtures[0];f++)
    for(unsigned flags=0;flags<16;flags++)for(unsigned mode=0;mode<2;mode++)
    for(unsigned extra=0;extra<4;extra++)for(unsigned v=0;v<4;v++)
    for(unsigned count=0;count<4;count++)for(unsigned limit=0;limit<4;limit++) {
        clear(&flat_shadow,104);
        flat_shadow.sp_el0=123;flat_shadow.sp_el1=flags&1?0x9000:0x80;
        flat_shadow.vbar=vectors[v];flat_shadow.mode=mode;
        flat_shadow.spsr=456;flat_shadow.esr=789;flat_shadow.far=0x123456789abcdef0ull;
        flat_shadow.daif=flags;flat_shadow.pan=1;
        flat_shadow.entries=flags&1?~0ull:10;flat_shadow.emulated=20;
        control.guest_sp=0xabcdef000ull;control.pstate_extra=extras[extra];
        flat_program.expected_count=0;flat_event_count=counts[count];
        flat_direct_pc_count=limit;
        flat_observer_pending=(struct flat_observer_pending){(void *)0x1234,0x5678};
        struct flat_observer_pending pending=flat_observer_pending;
        struct flat_event event={0};
        if(flat_event_count<1024)flat_events[flat_event_count]=event;
        reference.sp_el0=flat_shadow.sp_el0; /* Copy only fields the entry core can touch. */
        const unsigned char *src=(const void *)&flat_shadow;unsigned char *dst=(void *)&reference;
        for(unsigned i=0;i<104;i++)dst[i]=src[i];
        struct osrec_context before={0},after={0},ref={0};
        for(unsigned r=0;r<31;r++)before.x[r]=0x1020304050607080ull*(r+1);
        before.sp=(uintptr_t)(stack+sizeof stack);before.pstate=(uint64_t)flags<<28;
        ref=before;ref.sp=control.guest_sp;ref.pstate|=extras[extra];ref.pc=fixtures[f].pc;
        int accepted=osrec_enter_syscall(&reference,&ref,fixtures[f].word,OSREC_ENTRY_VENEER);
        int hit=0;for(unsigned t=0;t<limit;t++)if(flat_direct_pcs[t].pc==ref.pc)hit=1;
        int fast=accepted && hit && counts[count]<1024;
        if(!fast)for(unsigned i=0;i<104;i++)dst[i]=src[i];
        test_fast=99;test_target=~0ull;
        fixtures[f].run(&before,&after);
        if(test_fast!=(unsigned)fast)return 10;
        if(!equal(&before,&after,sizeof before))return 20;
        if(!equal(&flat_shadow,&reference,104))return 30;
        if(control.guest_sp!=(fast?ref.sp:0xabcdef000ull) || control.pstate_extra!=extras[extra])return 40;
        if(flat_event_count!=counts[count]+fast)return 50;
        if(test_target!=(fast?ref.pc:~0ull))return 60;
        if(fast) {
            event.number=before.x[8];for(unsigned i=0;i<6;i++)event.args[i]=before.x[i];
            pending.event=flat_events+counts[count];pending.regs=reference.sp_el1-0x150;
        }
        if(!equal(&pending,&flat_observer_pending,sizeof pending))return 70;
        if(counts[count]<1024 && !equal(&event,flat_events+counts[count],sizeof event))return 80;
    }
    return 0;
}
