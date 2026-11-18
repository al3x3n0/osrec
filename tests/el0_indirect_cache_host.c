/* Independent contract for cached original-PC branch lookup. */
#include "flat.h"
uint64_t test_fast;
static unsigned char stack[16384] __attribute__((aligned(16)));
typedef void (*probe)(const struct osrec_context *,struct osrec_context *);
struct fixture {unsigned word;uint64_t pc;unsigned count;probe run;uint64_t *cache;uint64_t base;};
#include "cases.h"
static int equal(const void *a,const void *b,size_t bytes)
{const unsigned char *x=a,*y=b;while(bytes--)if(*x++!=*y++)return 0;return 1;}
int test_main(void)
{
    const uint64_t targets[]={0,0x100,0x100,0x200,0x200,0x300,0x300,0x400,0x300,
                              1,0xff,0x101,0x201,0x401,0xff8,0xffc,0xfff,0x1000,
                              0x1001,0x1ff8,0x1ffc,0x1fff,0x2000,~0ull};
    const uint64_t admitted[]={0x100,0x200,0x300,0xffc,0x1000,0x1ffc};
    for(unsigned f=0;f<sizeof fixtures/sizeof fixtures[0];f++)for(unsigned flags=0;flags<16;flags++) {
        const struct fixture *test=fixtures+f;
        test->cache[0]=test->cache[1]=0;
        for(unsigned phase=0;phase<2;phase++)for(unsigned t=0;t<sizeof targets/sizeof targets[0];t++) {
            struct osrec_context before={0},after={0},expected;
            unsigned rn=test->word>>5&31;
            uint64_t target=rn==31?0:test->base+targets[t];
            for(unsigned r=0;r<31;r++)before.x[r]=0x1020304050607080ull*(r+1);
            if(rn!=31)before.x[rn]=target;
            before.sp=(uintptr_t)(stack+sizeof stack);before.pstate=(uint64_t)flags<<28;
            expected=before;
            uint64_t offset=target-test->base;
            int found=0;
            for(unsigned i=0;i<test->count;i++)if(offset==admitted[i])found=1;
            if(found && (test->word&0xfffffc1fu)==0xd63f0000u)expected.x[30]=test->pc+4;
            /* A matching key with no native value must still resolve afresh. */
            if(phase){test->cache[0]=target;test->cache[1]=0;}
            uint64_t old_key=test->cache[0],old_target=test->cache[1];
            test_fast=99;test->run(&before,&after);
            if(test_fast!=(unsigned)found)return 10;
            if(!equal(&expected,&after,sizeof expected))return 20;
            if(found && (test->cache[0]!=target || !test->cache[1]))return 30;
            if(!found && (test->cache[0]!=old_key || test->cache[1]!=old_target))return 40;
        }
    }
    return 0;
}
