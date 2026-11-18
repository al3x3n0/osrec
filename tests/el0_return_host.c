/* Differential checks for generated user returns and atomic fallback. */
#include "program.h"
struct osrec_shadow flat_shadow;
struct flat_full_image flat_program;
struct flat_control control,*flat_active=&control;
struct flat_user_return_state flat_user_return_state;
uint64_t flat_pretranslated_root=0x12345000,flat_pretranslated_tcr=16;
static uint64_t descriptors[2];
struct check {const volatile uint64_t *address;uint64_t mask,value;};
const struct check flat_pretranslated_checks[]={{descriptors,0x7ff,0x463},{descriptors+1,0xfff,0x863}};
uint64_t flat_pretranslated_check_count;
uint64_t flat_translation_dirty;
uint64_t test_fast,test_vector[6] __attribute__((aligned(16)));
static unsigned char kernel_stack[16384] __attribute__((aligned(16)));
static unsigned char user_stack[16384] __attribute__((aligned(16)));
const uint64_t flat_user_resume_ranges[][2]={{(uintptr_t)user_stack,(uintptr_t)(user_stack+sizeof user_stack)},{0,0}};
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
    const uint64_t allowed=0xf04013c0ull;
    for(unsigned f=0;f<sizeof fixtures/sizeof fixtures[0];f++)
    for(unsigned flags=0;flags<16;flags++)for(unsigned syscall=0;syscall<2;syscall++)
    for(unsigned scenario=0;scenario<128+31*64;scenario++) {
        struct osrec_context before={0},after={0},expected;
        for(unsigned r=0;r<31;r++)before.x[r]=0x1020304050607080ull*(r+1);
        before.sp=(uintptr_t)(kernel_stack+sizeof kernel_stack);before.pstate=(uint64_t)(flags^15)<<28;
        uint64_t user_sp=(uintptr_t)(user_stack+sizeof user_stack);
        for(unsigned i=sizeof user_stack-64;i<sizeof user_stack;i++)user_stack[i]=0xa5;
        flat_user_return_state=(struct flat_user_return_state){.entry=before,.valid=1,.syscall=syscall};
        flat_user_return_state.entry.sp=user_sp;
        flat_user_return_state.entry.pc=0x2000+(flags&1)*0x1000-4*syscall;
        flat_shadow.sp_el0=user_sp;flat_shadow.sp_el1=0x1234;
        flat_shadow.elr=flat_user_return_state.entry.pc+4*syscall;
        flat_shadow.spsr=((uint64_t)flags<<28)|((flags&1)?0x1000:0)|((flags&2)?1ull<<22:0)|0x3c0;
        flat_shadow.esr=0x5678;flat_shadow.far=0x9876;flat_shadow.daif=123;
        flat_shadow.pan=2;flat_shadow.vbar=0x8000;flat_shadow.mode=1;flat_shadow.emulated=42;flat_shadow.entries=9;
        control=(struct flat_control){.guest_sp=0xabcdef,.pstate_extra=0x1000};
        flat_program.memory.ttbr0=flat_pretranslated_root;flat_program.memory.tcr=flat_pretranslated_tcr;
        descriptors[0]=0x463;descriptors[1]=0x863;flat_pretranslated_check_count=2;
        flat_translation_dirty=1;
        if(scenario>=1 && scenario<=31)flat_user_return_state.entry.x[scenario-1]^=1;
        switch(scenario) {
        case 32:flat_user_return_state.entry.sp^=16;break;
        case 33:flat_user_return_state.entry.pc+=4;break;
        case 34:flat_user_return_state.valid=0;break;
        case 35:flat_program.memory.ttbr0^=0x1000;break;
        case 36:flat_program.memory.tcr^=1;break;
        case 37:descriptors[0]^=1;break;
        case 38:descriptors[1]^=1;break;
        case 39:flat_shadow.elr=0x2004;break; /* instruction hole */
        case 40:flat_shadow.elr=0x4000;break; /* empty page */
        case 41:flat_shadow.elr=0x1ffc;break;
        case 42:flat_shadow.elr=0x6000;break;
        case 43:flat_shadow.elr|=1;break;
        case 44:flat_shadow.sp_el0|=8;flat_user_return_state.entry.sp=flat_shadow.sp_el0;break;
        case 45:flat_shadow.mode=0;break;
        case 46:flat_shadow.spsr|=5;break;
        case 47:flat_shadow.spsr|=1ull<<63;break;
        case 48:flat_pretranslated_check_count=0;descriptors[0]=0;break;
        case 49:flat_program.memory.ttbr0|=1ull<<48;break;
        case 50:descriptors[0]|=1ull<<55;break;
        case 51:flat_shadow.emulated=UINT64_MAX;break;
        case 52:before.x[0]^=1;break;
        case 53:flat_shadow.sp_el0=0;flat_user_return_state.entry.sp=0;break;
        case 54:flat_user_return_state.syscall=syscall?2:0;break;
        case 55:flat_shadow.sp_el0=(uintptr_t)user_stack-16;break;
        case 56:flat_shadow.sp_el0=user_sp+16;break;
        case 57:flat_shadow.sp_el0=(uintptr_t)user_stack+48;break;
        /* Leave space for the fixture's own full-context capture as well. */
        case 58:flat_shadow.sp_el0=(uintptr_t)user_stack+512;break;
        case 59:flat_program.memory.ttbr0^=0x1000;flat_program.memory.tcr^=1;break;
        case 60:flat_translation_dirty=0;break;
        case 61:flat_translation_dirty=0;flat_program.memory.ttbr0^=0x1000;break;
        case 62:flat_translation_dirty=0;flat_program.memory.tcr^=1;break;
        default:break;
        }
        if(scenario>=64 && scenario<128)flat_shadow.spsr^=1ull<<(scenario-64);
        if(scenario>=128)flat_user_return_state.entry.x[(scenario-128)/64]^=1ull<<((scenario-128)%64);
        uint64_t offset=flat_shadow.elr-0x2000;
        int fast=flat_shadow.mode==1 && !(flat_shadow.spsr&~allowed) &&
            (flat_program.memory.ttbr0&0x0000fffffffff000ull)==flat_pretranslated_root &&
            flat_program.memory.tcr==flat_pretranslated_tcr && !(flat_shadow.elr&3) &&
            offset<0x4000 && (flat_shadow.elr==0x2000 || flat_shadow.elr==0x3000) &&
            flat_shadow.sp_el0>=64 && !(flat_shadow.sp_el0&15);
        for(unsigned i=0;i<flat_pretranslated_check_count;i++)
            if((descriptors[i]^flat_pretranslated_checks[i].value)&flat_pretranslated_checks[i].mask)fast=0;
#if OSREC_FLAT_VALIDATION
        if(!flat_user_return_state.valid || flat_shadow.sp_el0!=flat_user_return_state.entry.sp ||
           flat_shadow.elr!=flat_user_return_state.entry.pc+(flat_user_return_state.syscall?4:0))fast=0;
        for(unsigned r=flat_user_return_state.syscall?1:0;r<31;r++)
            if(before.x[r]!=flat_user_return_state.entry.x[r])fast=0;
#else
        if(flat_shadow.sp_el0-64<(uintptr_t)user_stack || flat_shadow.sp_el0>user_sp)fast=0;
#endif
        struct flat_user_return_state remembered=flat_user_return_state;
        /* Only the shared emulator's first 104 bytes are mutable in ERET. */
        const unsigned char *src=(const void *)&flat_shadow;unsigned char *dst=(void *)&reference;
        for(unsigned i=0;i<104;i++)dst[i]=src[i];
        expected=before;
        if(fast) {
            expected.pc=fixtures[f].pc;osrec_emulate_site(&reference,&expected,fixtures[f].word);expected.pc=0;
#if OSREC_FLAT_VALIDATION
            remembered.valid=0;
#endif
        }
        uint64_t expected_extra=expected.pstate&0x1000;
        expected.pstate&=0xf0000000ull; /* The fixture captures hardware NZCV. */
        test_fast=99;fixtures[f].run(&before,&after);
        if(test_fast!=(unsigned)fast)return 10;
        if(!equal(&expected,&after,sizeof expected))return 20;
        if(!equal(&reference,&flat_shadow,104))return 30;
        if(!equal(&remembered,&flat_user_return_state,sizeof remembered))return 40;
        if(control.guest_sp!=(fast?expected.sp:0xabcdef) ||
           control.pstate_extra!=(fast?expected_extra:0x1000))return 50;
        if(test_vector[0]!=0x5a5a5a5a5a5a5a5aull || test_vector[1]!=test_vector[0] ||
           test_vector[2]!=0xa5a5a5a5a5a5a5a5ull || test_vector[3]!=test_vector[2] ||
           test_vector[4]!=0x08000001 || test_vector[5]!=0x400000)return 60;
        if(!fast)for(unsigned i=sizeof user_stack-64;i<sizeof user_stack;i++)if(user_stack[i]!=0xa5)return 70;
    }
    return 0;
}
