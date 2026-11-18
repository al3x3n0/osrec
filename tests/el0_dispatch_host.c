/* The table index is a hint; only the full live pointer authorizes a branch. */
#include "flat.h"
uint64_t test_fast;
static unsigned char stack[16384] __attribute__((aligned(16)));
typedef void (*probe)(const struct osrec_context *,struct osrec_context *);
struct fixture {unsigned word;uint64_t pc;unsigned index;probe run;};
#include "cases.h"
static int equal(const void *a,const void *b,size_t n)
{const unsigned char *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
int test_main(void)
{
    const uint64_t targets[]={0,0x100,0x200,0x300,0x400,0x101,0x100000100ull,UINT64_MAX};
    const uint64_t hints[]={0,1,2,3,0x7fffffff,0x80000000,0xffffffff,0x100000000ull,0x100000002ull,UINT64_MAX};
    for(unsigned f=0;f<sizeof fixtures/sizeof fixtures[0];f++)for(unsigned flags=0;flags<16;flags++)
    for(unsigned t=0;t<sizeof targets/sizeof targets[0];t++)for(unsigned h=0;h<sizeof hints/sizeof hints[0];h++) {
        const struct fixture *test=fixtures+f;
        struct osrec_context before={0},after={0},expected;
        unsigned rn=test->word>>5&31;
        for(unsigned r=0;r<31;r++)before.x[r]=0x1020304050607080ull*(r+1);
        before.x[rn]=targets[t];
        if(test->index!=31)before.x[test->index]=hints[h];
        before.sp=(uintptr_t)(stack+sizeof stack);before.pstate=(uint64_t)flags<<28;
        uint64_t target=before.x[rn];unsigned index=test->index==31?0:(uint32_t)before.x[test->index];
        int found=(index==0 && target==0x100) || (index==2 && target==0x300);
        expected=before;
        if(found && (test->word&0xfffffc1fu)==0xd63f0000u)expected.x[30]=test->pc+4;
        test_fast=99;test->run(&before,&after);
        if(test_fast!=(unsigned)found)return 10;
        if(!equal(&expected,&after,sizeof expected))return 20;
    }
    return 0;
}
