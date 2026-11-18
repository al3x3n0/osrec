#include "program.h"
#include "admission.h"
extern uint64_t checked_context_difference(const struct osrec_context *,const struct osrec_context *,unsigned);
extern uint64_t checked_context_copy(struct osrec_context *,const struct osrec_context *);
static struct osrec_context aligned[2] __attribute__((aligned(16)));
static struct {uint64_t before;struct osrec_context context;uint64_t after;} unaligned[2] __attribute__((aligned(16)));
static int contexts(void)
{
    struct osrec_context *source[]={aligned,&unaligned[0].context};
    struct osrec_context *destination[]={aligned+1,&unaligned[1].context};
    for(unsigned a=0;a<2;a++)for(unsigned b=0;b<2;b++) {
        struct osrec_context *x=source[a],*y=destination[b];
        uint64_t *left=(void *)x,*right=(void *)y;
        unaligned[1].before=unaligned[1].after=0x123456789abcdef0ull;
        for(unsigned i=0;i<34;i++){left[i]=0x1020304050607080ull*(i+1);right[i]=~left[i];}
        uint64_t pstate=y->pstate;
        if(checked_context_copy(y,x))return 10;
        for(unsigned i=0;i<33;i++)if(left[i]!=right[i])return 11;
        if(y->pstate!=pstate || unaligned[1].before!=0x123456789abcdef0ull || unaligned[1].after!=0x123456789abcdef0ull)return 12;
        for(unsigned skip=0;skip<2;skip++) {
            if(checked_context_difference(x,y,skip))return 13;
            for(unsigned word=0;word<34;word++)for(unsigned bit=0;bit<64;bit++) {
                right[word]^=1ull<<bit;
                uint64_t difference=checked_context_difference(x,y,skip);
                int expected=word<32 && (!skip || word!=0);
                if(difference>255 || (!!difference)!=expected)return 14;
                right[word]^=1ull<<bit;
            }
        }
    }
    return 0;
}
static const struct flat_mapping immutable_maps[]={
    {0x1000,0x40000000,0x1000,0x400},{0x4000,0x40001000,0x2000,0x400},
    {0x8000,0x40003000,0x1000,0x480},{0x9000,0x40004000,0x1000,0},
    {0xc000,0x3ffff000,0x2000,0x400},{0x10000,0x4000f000,0x2000,0x400}};
static const struct flat_mapping overlapping[]={
    {0x1000,0x40000000,0x1000,0x400},{0x1000,0x40003000,0x2000,0x400}};
static const struct flat_mapping *reference(const struct flat_memory *m,uint64_t sp)
{
    if(sp<64 || sp%16)return 0;
    for(size_t i=0;i<m->kernel_count;i++) {
        const struct flat_mapping *v=m->kernel+i;
        if(sp-64<v->va || sp-v->va>v->bytes || !(v->attrs&0x400) || v->attrs&0x80)continue;
        uint64_t offset=sp-64-v->va;if(v->pa>UINT64_MAX-offset)continue;
        uint64_t pa=v->pa+offset;
        if(m->ram->bytes>=64 && pa>=m->ram->pa && pa-m->ram->pa<=m->ram->bytes-64)return v;
    }
    return 0;
}
static int mapping_index(void)
{
    struct flat_ram ram={0x40000000,0x10000,0};
    struct flat_memory m={.ram=&ram,.ram_count=1,.kernel=immutable_maps,.kernel_count=6};
    struct flat_stack_index index;
    flat_stack_index_init(&index,&m,immutable_maps);
    if(index.maps!=immutable_maps)return 20;
    for(uint64_t sp=0;sp<0x13000;sp++)if(flat_stack_mapping(&index,&m,sp)!=reference(&m,sp))return 21;
    for(unsigned i=0;i<100;i++)if(flat_stack_mapping(&index,&m,0x5000)!=immutable_maps+1)return 22;
    if(flat_stack_admitted(&index,&m,0x5000))return 33;
    flat_stack_admission_remember(&index,&m,0x5000);
    if(!flat_stack_admitted(&index,&m,0x5000) || flat_stack_admitted(&index,&m,0x5010) || flat_stack_admitted(&index,&m,0x5001))return 34;
    ram.bytes=32;if(flat_stack_admitted(&index,&m,0x5000))return 35;ram.bytes=0x10000;
    ram.pa=0x40001000;if(flat_stack_admitted(&index,&m,0x5000))return 36;ram.pa=0x40000000;
    ram.bytes=32;if(flat_stack_mapping(&index,&m,0x5000))return 23;ram.bytes=0x10000;
    m.kernel=overlapping;m.kernel_count=2;
    if(flat_stack_admitted(&index,&m,0x5000))return 37;
    if(flat_stack_mapping(&index,&m,0x1800)!=overlapping)return 24;
    flat_stack_index_init(&index,&m,overlapping);if(index.maps)return 25;
    if(flat_stack_mapping(&index,&m,0x1800)!=overlapping)return 26;
    struct flat_mapping mutable_maps[2]={overlapping[0],overlapping[1]};
    m.kernel=mutable_maps;flat_stack_index_init(&index,&m,immutable_maps);if(index.maps)return 27;
    if(flat_stack_mapping(&index,&m,0x1800)!=mutable_maps)return 28;
    mutable_maps[0].attrs=0x480;
    if(flat_stack_mapping(&index,&m,0x1800)!=mutable_maps+1)return 29;
    flat_stack_admission_remember(&index,&m,0x1800);if(flat_stack_admitted(&index,&m,0x1800))return 38;
    mutable_maps[1].bytes=64;if(flat_stack_mapping(&index,&m,0x1800))return 30;
    m.kernel=immutable_maps;m.kernel_count=6;flat_stack_index_init(&index,&m,immutable_maps);
    flat_stack_admission_remember(&index,&m,0x5000);
    m.kernel_count=1;if(flat_stack_mapping(&index,&m,0x5000) || flat_stack_admitted(&index,&m,0x5000))return 31;
    m.kernel_count=6;if(flat_stack_mapping(&index,&m,0x5000)!=immutable_maps+1)return 32;
    return 0;
}
static int comparisons(void)
{
    for(unsigned mask=0;mask<16;mask++)for(unsigned bit=0;bit<64;bit++) {
        uint64_t a=0x1020304050607080ull,b=0xabcdef1234567890ull;
        uint64_t c=0xfedcba9876543210ull,d=0x8765432100abcdefull;
        uint64_t aa=a^((mask&1)?1ull<<bit:0),bb=b^((mask&2)?1ull<<bit:0);
        uint64_t cc=c^((mask&4)?1ull<<bit:0),dd=d^((mask&8)?1ull<<bit:0);
        if(flat_equal2(a,aa,b,bb)!=!(mask&3))return 40;
        if(flat_equal3(a,aa,b,bb,c,cc)!=!(mask&7))return 41;
        if(flat_equal4(a,aa,b,bb,c,cc,d,dd)!=!mask)return 42;
    }
    return 0;
}
int test_main(void)
{
    int status=comparisons();if(status)return status;
    status=contexts();return status?status:mapping_index();
}
