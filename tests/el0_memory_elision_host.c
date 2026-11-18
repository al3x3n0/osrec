/* Independent full-context oracle for literal loads and fixed kernel pages. */
#include "flat.h"
unsigned char test_data[3*4096] __attribute__((aligned(4096)));
unsigned char flat_shadow[128] __attribute__((aligned(128)));
uint64_t test_fast,test_vector[2] __attribute__((aligned(16)));
static unsigned char stack[16384] __attribute__((aligned(16)));
typedef void (*probe)(const struct osrec_context *,struct osrec_context *);
struct fixture {unsigned word,kind,size;uint64_t lo,hi;probe run;uint64_t *tag;};
#include "cases.h"
static int equal(const void *a,const void *b,size_t n)
{const unsigned char *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static uint64_t load(const unsigned char *p,unsigned n)
{uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)p[i]<<(i*8);return v;}
int test_main(void)
{
    for(unsigned f=0;f<sizeof fixtures/sizeof fixtures[0];f++)for(unsigned flags=0;flags<16;flags++)
    for(unsigned mode=0;mode<(fixtures[f].kind?1:13);mode++)for(unsigned repeat=0;repeat<2;repeat++) {
        const struct fixture *t=fixtures+f;unsigned rt=t->word&31,rn=t->word>>5&31;
        uintptr_t at=(uintptr_t)test_data+512;unsigned kernel=1,fast=1;
        if(!t->kind)switch(mode) {
        case 1:at+=64;break;
        case 2:at+=4096;break;
        case 3:at+=8192;break;
        case 4:at+=128;break;
        case 5:at=(uintptr_t)test_data+4096-t->size;break;
        case 6:at=(uintptr_t)test_data+4096-t->size+1;break;
        case 7:at=(uintptr_t)test_data+12288;break;
        case 8:kernel=0;break;
        case 9:at=0;break;
        case 10:at=(uintptr_t)test_data-1;break;
        case 11:at++;break;
        case 12:at=UINT64_MAX-31;break;
        }
        if(!t->kind && rn==31 && (mode==5||mode==6||mode>=7))continue;
        struct osrec_context before={0},after={0},expected;
        for(unsigned r=0;r<31;r++)before.x[r]=0x1020304050607080ull*(r+1)^((uint64_t)repeat<<63);
        before.sp=(uintptr_t)(stack+sizeof stack);before.pstate=(uint64_t)flags<<28;
        unsigned reading=!!(t->word&(1u<<22));uint64_t tag=0;
        if(!t->kind) {
            for(unsigned i=0;i<sizeof test_data;i++)test_data[i]=(unsigned char)(i*7+f+flags+repeat);
            *(uint64_t *)(flat_shadow+80)=kernel;
            if(rn==31)before.sp=at;else before.x[rn]=at;
            fast=kernel && !(at&(t->size-1)) && at>=(uintptr_t)test_data &&
                at-(uintptr_t)test_data<=sizeof test_data-t->size &&
                (reading || at<(uintptr_t)test_data+4096 || at>=(uintptr_t)test_data+8192);
            tag=*t->tag;
        }
        expected=before;uint64_t previous=0,vector[2]={0x5a5a5a5a5a5a5a5aull,0x5a5a5a5a5a5a5a5aull};
        if(!t->kind && fast) {
            previous=load((const unsigned char *)at,t->size);
            if(reading && rt!=31)expected.x[rt]=previous;
        }
        if(t->kind==1 && rt!=31) {
            uint64_t value=t->lo;
            if(t->size==4)value=(t->word>>30)==2?(uint64_t)(int64_t)(int32_t)value:(uint32_t)value;
            expected.x[rt]=value;
        }
        if(t->kind==2){vector[0]=t->size==4?(uint32_t)t->lo:t->lo;vector[1]=t->size==16?t->hi:0;}
        test_fast=99;t->run(&before,&after);
        if(test_fast!=fast)return 10;
        if(!equal(&expected,&after,sizeof expected))return 20;
        if(!equal(vector,test_vector,sizeof vector))return 30;
        if(!t->kind) {
            if(*t->tag!=(fast?(at|4095):tag))return 40;
            if(fast) {
                uint64_t value=reading?previous:(rt==31?0:before.x[rt]);
                uint64_t mask=t->size==8?UINT64_MAX:(1ull<<(8*t->size))-1;
                if(load((const unsigned char *)at,t->size)!=(value&mask))return 50;
            }
        }
    }
    return 0;
}
