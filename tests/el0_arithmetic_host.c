/* Independent modular-arithmetic oracle; every probe preserves the full context. */
#include "flat.h"
static unsigned char stack[16384] __attribute__((aligned(16)));
typedef void (*probe)(const struct osrec_context *,struct osrec_context *);
struct fixture {unsigned kind,dest,base,offset,extension,shift;uint64_t value,ram_base,ram_bytes,bytes;probe run;};
#include "cases.h"
static int equal(const void *a,const void *b,size_t n)
{const unsigned char *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
int test_main(void)
{
    const uint64_t values[]={0,1,0x7fffffffull,0x80000000ull,0xffffffffull,1ull<<32,
        1ull<<63,UINT64_MAX,0x0123456789abcdefull,0xfedcba9876543210ull};
    for(unsigned i=0;i<sizeof fixtures/sizeof fixtures[0];i++)for(unsigned flags=0;flags<16;flags++)
    for(unsigned v=0;v<sizeof values/sizeof values[0];v++) {
        const struct fixture *test=fixtures+i;
        struct osrec_context before={0},after={0},expected;
        for(unsigned r=0;r<31;r++)before.x[r]=0x1020304050607080ull*(r+1)^values[v];
        before.sp=(uintptr_t)(stack+sizeof stack);before.pstate=(uint64_t)flags<<28;
        if(test->kind==2 && test->offset!=31)before.x[test->offset]=values[v];
        if(test->kind==3)before.x[0]=test->value;
        expected=before;
        uint64_t result=test->value;
        if(test->kind==1)result=before.x[test->base]+test->value;
        if(test->kind==2) {
            uint64_t offset=test->offset==31?0:before.x[test->offset];
            if(test->extension==2)offset=(uint32_t)offset;
            if(test->extension==6)offset=(uint64_t)(int64_t)(int32_t)offset;
            result=before.x[test->base]+(offset<<test->shift);
        }
        if(test->kind==3) {
            uint64_t delta=before.x[0]-test->ram_base;
            result=delta<=test->ram_bytes-test->bytes?delta:UINT64_MAX;
        }
        if(test->dest!=31)expected.x[test->dest]=result;
        test->run(&before,&after);
        if(!equal(&expected,&after,sizeof expected))return 20;
    }
    return 0;
}
