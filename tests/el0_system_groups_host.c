/* Sequential shared-emulator oracle; no ABI preservation assumptions. */
#include "program.h"
extern struct osrec_shadow flat_shadow;
uint64_t test_vector[6] __attribute__((aligned(16)));
static unsigned char stack[16384] __attribute__((aligned(16)));
typedef void (*probe)(const struct osrec_context *,struct osrec_context *);
struct fixture {unsigned count,words[8];probe run;};
#include "cases.h"
static struct osrec_shadow reference;
static int equal(const void *a,const void *b,size_t n)
{const unsigned char *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
void osrec_platform_stop(uint64_t a,uint64_t b,uint64_t c,uint64_t d)
{(void)a;(void)b;(void)c;(void)d;__builtin_trap();}
void osrec_platform_set_tpidrro(uint64_t v){(void)v;__builtin_trap();}
void osrec_platform_set_ttbr0(uint64_t v){(void)v;__builtin_trap();}
void osrec_platform_set_ttbr1(uint64_t v){(void)v;__builtin_trap();}
void osrec_platform_tlb_flush(void){}
void osrec_platform_icache_flush(void){}
void osrec_platform_dcache_clean_invalidate(uint64_t v){(void)v;}
uint64_t osrec_platform_translate(uint64_t v,int op){(void)v;(void)op;__builtin_trap();}
int test_main(void)
{
    for(unsigned f=0;f<sizeof fixtures/sizeof fixtures[0];f++)
    for(unsigned flags=0;flags<16;flags++)for(unsigned seed=0;seed<4;seed++) {
        unsigned char *src=(void *)&flat_shadow,*dst=(void *)&reference;
        for(unsigned i=0;i<104;i++)dst[i]=src[i]=(unsigned char)(i*17+seed*73);
        flat_shadow.mode=reference.mode=seed&1;
        flat_shadow.emulated=reference.emulated=seed&1?UINT64_MAX:seed;
        struct osrec_context before={0},after={0},expected;
        for(unsigned r=0;r<31;r++)before.x[r]=0x1020304050607080ull*(r+1)^((uint64_t)seed<<32);
        before.sp=(uintptr_t)(stack+sizeof stack);before.pstate=(uint64_t)flags<<28;
        expected=before;
        for(unsigned i=0;i<fixtures[f].count;i++) {
            expected.pc=0x1000+4*i;osrec_emulate_site(&reference,&expected,fixtures[f].words[i]);
        }
        expected.pc=0;fixtures[f].run(&before,&after);
        if(!equal(&expected,&after,sizeof expected))return 20;
        if(!equal(&reference,&flat_shadow,104))return 30;
        if(test_vector[0]!=0x5a5a5a5a5a5a5a5aull || test_vector[1]!=test_vector[0])return 40;
        if(test_vector[2]!=0xa5a5a5a5a5a5a5a5ull || test_vector[3]!=test_vector[2])return 45;
        if(test_vector[4]!=0x08000001 || test_vector[5]!=0x400000)return 50;
    }
    return 0;
}
