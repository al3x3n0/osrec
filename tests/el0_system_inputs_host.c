/* Compare inline thread state with the shared emulator and input reads with
 * an independent ordered-input oracle, including side-effect-free rejection. */
#include "program.h"
extern struct osrec_shadow flat_shadow;
struct flat_full_image flat_program;
uint64_t flat_counter_used,test_fast,test_vector[2] __attribute__((aligned(16)));
static unsigned char stack[16384] __attribute__((aligned(16)));
typedef void (*probe)(const struct osrec_context *,struct osrec_context *);
struct fixture {uint64_t pc;unsigned word;probe run;};
#include "cases.h"
static struct osrec_shadow expected_shadow;
static int equal(const void *a,const void *b,size_t n)
{const unsigned char *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
/* No admitted thread-register case should stop or invoke a real platform. */
void osrec_platform_stop(uint64_t a,uint64_t b,uint64_t c,uint64_t d)
{(void)a;(void)b;(void)c;(void)d;__asm__ volatile("brk #1");for(;;){}}
void osrec_platform_set_tpidrro(uint64_t v){(void)v;}
void osrec_platform_set_ttbr0(uint64_t v){(void)v;}
void osrec_platform_set_ttbr1(uint64_t v){(void)v;}
void osrec_platform_tlb_flush(void){}
void osrec_platform_icache_flush(void){}
void osrec_platform_dcache_clean_invalidate(uint64_t v){(void)v;}
uint64_t osrec_platform_translate(uint64_t v,int op){(void)v;(void)op;return 0;}
int test_main(void)
{
    struct flat_counter inputs[3];
    for(unsigned f=0;f<sizeof fixtures/sizeof fixtures[0];f++)for(unsigned flags=0;flags<16;flags++)
    for(unsigned known=0;known<2;known++)for(unsigned variant=0;variant<7;variant++) {
        uint32_t w=fixtures[f].word,key=w>>5&65535,rt=w&31;
        int counter=key==0xdf01 || key==0xdf02,read=(w&0xfff00000)==0xd5300000;
        struct osrec_context before={0},after={0},expected;
        for(unsigned r=0;r<31;r++)before.x[r]=0x1020304050607080ull*(r+1);
        before.sp=(uintptr_t)(stack+sizeof stack);before.pstate=(uint64_t)flags<<28;
        expected=before;
        flat_shadow.emulated=variant==6?UINT64_MAX:99;
        flat_shadow.known[key>>3]=(unsigned char)(0xa5&~(1u<<(key&7)));
        if(known)flat_shadow.known[key>>3]|=(unsigned char)(1u<<(key&7));
        flat_shadow.value[key]=0xfedcba9876543210ull;
        expected_shadow.emulated=flat_shadow.emulated;
        expected_shadow.known[key>>3]=flat_shadow.known[key>>3];
        expected_shadow.value[key]=flat_shadow.value[key];
        flat_counter_used=variant==4?3:variant==5?UINT64_MAX:1;
        flat_program.counter_count=variant==3?1:3;
        for(unsigned i=0;i<3;i++)inputs[i]=(struct flat_counter){fixtures[f].pc,key,0xcafebabe12345678ull+i};
        if(variant==1)inputs[1].pc+=4;
        if(variant==2)inputs[1].key^=3;
        flat_program.counters=variant>=3 && variant<=5?0:inputs;
        uint64_t cursor=flat_counter_used;
        int fast=counter?variant==0 || variant==6:!read || known;
        if(fast && counter) {
            if(rt!=31)expected.x[rt]=inputs[cursor].value;
            cursor++;expected_shadow.emulated++;
        } else if(fast) {
            expected.pc=fixtures[f].pc;
            osrec_emulate_site(&expected_shadow,&expected,w);expected.pc=0;
        }
        test_fast=99;fixtures[f].run(&before,&after);
        if(test_fast!=(unsigned)fast)return 10;
        if(!equal(&expected,&after,sizeof expected))return 20;
        if(!equal(&expected_shadow,&flat_shadow,104) ||
           !equal(expected_shadow.known+(key>>3)-1,flat_shadow.known+(key>>3)-1,3) ||
           !equal(expected_shadow.value+key-1,flat_shadow.value+key-1,24))return 30;
        if(flat_counter_used!=cursor)return 40;
        if(test_vector[0]!=0x5a5a5a5a5a5a5a5aull || test_vector[1]!=test_vector[0])return 50;
    }
    /* Also detect any persistent write outside the operation's own fields. */
    return equal(&expected_shadow,&flat_shadow,sizeof flat_shadow)?0:60;
}
