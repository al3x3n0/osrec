/* Original store semantics, checked independently of generated address code. */
#include "flat.h"
unsigned char test_stack[32768] __attribute__((aligned(4096)));
unsigned char flat_shadow[128] __attribute__((aligned(128)));
uint64_t flat_direct_write[6];
struct capture {struct osrec_context cpu;uint64_t fast,pad,vector[4],fpsr,fpcr;};
struct capture test_capture;
struct fixture {unsigned word,size,count;int offset;unsigned post,writeback,vector;void (*run)(const struct osrec_context *);};
#include "cases.h"
static int equal(const void *a,const void *b,size_t n)
{const unsigned char *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
int test_main(void)
{
    const uintptr_t base=(uintptr_t)test_stack;
    flat_direct_write[0]=base;flat_direct_write[1]=base+8192;
    flat_direct_write[2]=base+12288;flat_direct_write[3]=base+sizeof test_stack;
    for(unsigned f=0;f<sizeof fixtures/sizeof fixtures[0];f++)for(unsigned flags=0;flags<16;flags++)
    for(unsigned scenario=0;scenario<9;scenario++) {
        const struct fixture *t=fixtures+f;
        struct osrec_context before={0},expected;
        for(unsigned r=0;r<31;r++)before.x[r]=0x1020304050607080ull*(r+1);
        const unsigned offsets[]={4096,8192,8176,8224,12288,12272,12320,16384,16384};
        before.sp=base+offsets[scenario];before.pstate=(uint64_t)flags<<28;
        *(uint64_t *)(flat_shadow+80)=scenario!=8;
        uintptr_t address=before.sp+(t->post?0:t->offset);
        unsigned bytes=t->size*t->count;
        for(unsigned i=0;i<bytes;i++)((unsigned char *)address)[i]=0xa5;
        int fast=scenario!=8 && ((address>=base && address+bytes<=base+8192) ||
                                  (address>=base+12288 && address+bytes<=base+sizeof test_stack));
        expected=before;if(fast && t->writeback)expected.sp+=t->offset;
        t->run(&before);
        if(test_capture.fast!=(unsigned)fast || !equal(&test_capture.cpu,&expected,sizeof expected))return 10;
        if(test_capture.vector[0]!=0x0303030303030303ull || test_capture.vector[1]!=test_capture.vector[0] ||
           test_capture.vector[2]!=0xdcdcdcdcdcdcdcdcull || test_capture.vector[3]!=test_capture.vector[2] ||
           test_capture.fpsr!=1 || test_capture.fpcr!=0x400000)return 20;
        if(fast)for(unsigned part=0;part<t->count;part++) {
            unsigned reg=part?(t->word>>10&31):(t->word&31);
            for(unsigned i=0;i<t->size;i++) {
                unsigned char value=t->vector?(unsigned char)(reg*7+3):(reg==31?0:before.x[reg]>>(8*i));
                if(*(unsigned char *)(address+part*t->size+i)!=value)return 30;
            }
        }
    }
    return 0;
}
