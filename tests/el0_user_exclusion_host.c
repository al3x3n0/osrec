/* Independent linear membership oracle for the generated exclusion lookup. */
#include "flat.h"
static unsigned char stack[16384] __attribute__((aligned(16)));
typedef void (*probe)(const struct osrec_context *,struct osrec_context *);
struct span {uint64_t lo,hi;};
struct fixture {unsigned address;probe run;const struct span *spans;unsigned count;const uint64_t *values;unsigned value_count;};
#include "cases.h"
static int equal(const void *a,const void *b,size_t n)
{const unsigned char *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
int test_main(void)
{
    for(unsigned i=0;i<sizeof fixtures/sizeof fixtures[0];i++)for(unsigned flags=0;flags<16;flags++) {
        const struct fixture *t=fixtures+i;
        for(unsigned v=0;v<t->value_count;v++) {
            uint64_t va=t->values[v];unsigned allowed=(va>>48)==0;
            for(unsigned j=0;j<t->count;j++)if(t->spans[j].lo<=va && va<t->spans[j].hi)allowed=0;
            struct osrec_context before={0},after={0},expected;
            for(unsigned r=0;r<31;r++)before.x[r]=0x1020304050607080ull*(r+1)^va;
            before.x[t->address]=va;before.sp=(uintptr_t)(stack+sizeof stack);before.pstate=(uint64_t)flags<<28;
            expected=before;expected.x[0]=allowed;
            t->run(&before,&after);
            if(!equal(&expected,&after,sizeof expected))return 20;
        }
    }
    return 0;
}
