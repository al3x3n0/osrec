/* Independent branch-condition oracle and full-context preservation checks. */
#include "flat.h"
uint64_t test_taken;
static unsigned char stack[16384] __attribute__((aligned(16)));
typedef void (*probe)(const struct osrec_context *,struct osrec_context *);
struct fixture {unsigned word;int reg;uint64_t value;probe run;};
#include "cases.h"
static int equal(const void *a,const void *b,size_t n)
{const unsigned char *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static unsigned condition(unsigned c,unsigned f)
{
    unsigned n=f>>3&1,z=f>>2&1,carry=f>>1&1,v=f&1,result=0;
    switch(c>>1){case 0:result=z;break;case 1:result=carry;break;case 2:result=n;break;
    case 3:result=v;break;case 4:result=carry&&!z;break;case 5:result=n==v;break;case 6:result=!z&&(n==v);break;}
    return result^(c&1);
}
int test_main(void)
{
    const uint64_t values[]={0,1,0x80000000ull,1ull<<32,1ull<<63,UINT64_MAX};
    for(unsigned i=0;i<sizeof fixtures/sizeof fixtures[0];i++)for(unsigned flags=0;flags<16;flags++)
    for(unsigned v=0;v<sizeof values/sizeof values[0];v++) {
        const struct fixture *test=fixtures+i;
        struct osrec_context before={0},after={0},expected;
        for(unsigned r=0;r<31;r++)before.x[r]=0x1020304050607080ull*(r+1)^values[v];
        before.sp=(uintptr_t)(stack+sizeof stack);before.pstate=(uint64_t)flags<<28;
        unsigned taken=0,w=test->word;
        if(test->reg<0 && (w&0xff000010u)!=0x54000000u) {
            unsigned rn=w&31;
            if(rn!=31)before.x[rn]=values[v];
        }
        expected=before;
        if(test->reg>=0)expected.x[test->reg]=test->value;
        else if((w&0xff000010u)==0x54000000u)taken=condition(w&15,flags);
        else {
            uint64_t value=(w&31)==31?0:before.x[w&31];
            if((w&0x7e000000u)==0x34000000u) {
                if(!(w>>31))value=(uint32_t)value;
                taken=(value==0)^((w>>24)&1);
            } else {
                unsigned bit=(w>>31)*32+((w>>19)&31);
                taken=!(value&(1ull<<bit))^((w>>24)&1);
            }
        }
        test_taken=99;test->run(&before,&after);
        if(test_taken!=taken)return 10;
        if(!equal(&expected,&after,sizeof expected))return 20;
    }
    return 0;
}
