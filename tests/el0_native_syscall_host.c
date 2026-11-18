/* Differential native-SP syscall entry, including overlapping stack spills. */
#include "program.h"
struct osrec_shadow flat_shadow;
struct flat_control control,*flat_active=&control;
uint64_t test_fast,test_target,test_vector[6] __attribute__((aligned(16)));
unsigned char kernel_stack[16384] __attribute__((section(".kernel_stack"),aligned(16)));
static unsigned char user_stack[16384] __attribute__((aligned(16)));
static unsigned char private_stack[16384] __attribute__((aligned(16)));
typedef void (*probe)(const struct osrec_context *,struct osrec_context *);
struct fixture {uint64_t pc;unsigned word;probe run;};
#include "cases.h"
static int equal(const void *a,const void *b,size_t n)
{const unsigned char *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
void osrec_platform_stop(uint64_t a,uint64_t b,uint64_t c,uint64_t d)
{(void)a;(void)b;(void)c;(void)d;__builtin_trap();}
void osrec_platform_set_tpidrro(uint64_t v){(void)v;}
void osrec_platform_set_ttbr0(uint64_t v){(void)v;}
void osrec_platform_set_ttbr1(uint64_t v){(void)v;}
void osrec_platform_tlb_flush(void){}
void osrec_platform_icache_flush(void){}
void osrec_platform_dcache_clean_invalidate(uint64_t v){(void)v;}
uint64_t osrec_platform_translate(uint64_t v,int op){(void)v;(void)op;return 0;}
int test_main(void)
{
    static struct osrec_shadow reference;
    const uint64_t extras[]={0,1ull<<12,2,1ull<<63};
    const uint64_t vectors[]={0x4c00,0x5c00,0x4c04,0x6c00,0x8c00,0x3c00,0x4c01,~1023ull};
    const uint64_t stacks[]={0x41004000,0x41000040,0x41000030,0x41004010,0x41003ff8,0,~0ull,0x41000200};
    for(unsigned f=0;f<sizeof fixtures/sizeof fixtures[0];f++)
    for(unsigned flags=0;flags<16;flags++)for(unsigned mode=0;mode<3;mode++)
    for(unsigned extra=0;extra<4;extra++)for(unsigned v=0;v<8;v++)
    for(unsigned s=0;s<8;s++)for(unsigned wrap=0;wrap<2;wrap++)for(unsigned alias=0;alias<6;alias++) {
        struct osrec_context before={0},after={0},ref,expected;
        for(unsigned r=0;r<31;r++)before.x[r]=0x1020304050607080ull*(r+1);
        int stack_ok=stacks[s]>=0x41000040 && stacks[s]<=0x41004000 && !(stacks[s]&15);
        before.sp=alias && stack_ok?stacks[s]+16*((int)alias-3):(uintptr_t)(user_stack+sizeof user_stack);
        before.pstate=(uint64_t)flags<<28;
        flat_shadow.sp_el0=123;flat_shadow.sp_el1=stacks[s];flat_shadow.vbar=vectors[v];flat_shadow.mode=mode;
        flat_shadow.elr=0x3333;flat_shadow.spsr=456;flat_shadow.esr=789;flat_shadow.far=0x123456789abcdef0ull;
        flat_shadow.daif=flags;flat_shadow.pan=1;flat_shadow.entries=wrap?~0ull:10;flat_shadow.emulated=20;
        control=(struct flat_control){.guest_sp=0xabcdef,.stack_top=(uintptr_t)(private_stack+sizeof private_stack),
            .pstate_extra=extras[extra],.live=(void *)0x1234};
        const unsigned char *src=(const void *)&flat_shadow;unsigned char *dst=(void *)&reference;
        for(unsigned i=0;i<104;i++)dst[i]=src[i];
        ref=before;ref.pc=fixtures[f].pc;ref.pstate|=extras[extra];
        int accepted=osrec_enter_syscall(&reference,&ref,fixtures[f].word,OSREC_ENTRY_VENEER);
        int fast=accepted && stack_ok && (ref.pc==0x5000 || ref.pc==0x6000);
        expected=fast?ref:before;expected.pc=0;expected.pstate&=0xf0000000ull;
        if(!fast)for(unsigned i=0;i<104;i++)dst[i]=src[i];
        test_fast=99;test_target=~0ull;fixtures[f].run(&before,&after);
        if(test_fast!=(unsigned)fast)return 10;
        if(!equal(&expected,&after,sizeof expected))return 20;
        if(!equal(&reference,&flat_shadow,104))return 30;
        if(control.guest_sp!=(fast?ref.sp:0xabcdef) || control.pstate_extra!=extras[extra] ||
           control.stack_top!=(uintptr_t)(private_stack+sizeof private_stack) || control.live!=(void *)0x1234)return 40;
        if(test_target!=(fast?ref.pc:~0ull))return 50;
        if(test_vector[0]!=0x5a5a5a5a5a5a5a5aull || test_vector[1]!=test_vector[0] ||
           test_vector[2]!=0xa5a5a5a5a5a5a5a5ull || test_vector[3]!=test_vector[2] ||
           test_vector[4]!=0x08000001 || test_vector[5]!=0x400000)return 60;
    }
    return 0;
}
