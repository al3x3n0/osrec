#include "memory.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static uint64_t pages[6][512];
static unsigned indexed_comparisons;
static void compare_mapping(const struct flat_memory *m,uint64_t va,size_t bytes,enum flat_access op,int user)
{
    /* A distinct live array forces the unchanged linear lookup. The same
     * walker then independently checks permissions, tables, RAM and faults. */
    struct flat_mapping copy[8];assert(m->kernel_count<=8);
    memcpy(copy,m->kernel,m->kernel_count*sizeof *copy);
    struct flat_memory reference=*m;reference.kernel=copy;
    struct flat_translation a=flat_translate(m,va,bytes,op,user),b=flat_translate(&reference,va,bytes,op,user);
    assert(a.data==b.data && a.pa==b.pa && a.attrs==b.attrs && a.far==b.far && a.fault==b.fault);
    indexed_comparisons++;
}
static void indexed_maps(struct flat_memory original)
{
    static const struct flat_mapping ordered[]={
        {0x1000,0x5000,4096,0x740},{0x4000,0x6000,4096,0},
        {0x8000,0x5000,8192,0x480},{0x10000,0x9000000,4096,0x740},
        {0x20000000,0x5000,4096,0x740},{0x20002000,0x5000,4096,(1ull<<53)|0x400},
        {0x800000000000,0x6000,4096,0x740},{0xffffffffffffe000,0x5000,4096,0x740}};
    static const struct flat_mapping invalid[][2]={
        {{0x2000,0x5000,4096,0x740},{0x1000,0x6000,4096,0x400}}, /* unsorted */
        {{0x1000,0x5000,8192,0x740},{0x2000,0x6000,4096,0x400}}, /* overlap */
        {{0x1000,0x5000,0,0x740},{0x2000,0x6000,4096,0x400}}, /* empty */
        {{0x1000,0x5000,4096,0x740},{UINT64_MAX-15,0x6000,32,0x400}}}; /* overflow */
    const size_t sizes[]={0,1,8,16,4096,4097,SIZE_MAX};
    const uint64_t offsets[]={0,1,15,4095,4096,8191,UINT64_MAX};
    struct flat_memory m=original;m.kernel=ordered;m.kernel_count=8;
    assert(flat_memory_index_init(&m,ordered));
    for(unsigned state=0;state<4;state++) {
        m.tcr=state==1?25:state==2?16|(1<<14):16;m.ram_count=state==3?0:1;
        for(unsigned count=0;count<=8;count++) {
            m.kernel_count=count; /* Live count changes invalidate the binding. */
            for(unsigned row=0;row<8;row++)for(unsigned at=0;at<7;at++)
            for(unsigned size=0;size<7;size++)for(unsigned op=0;op<3;op++)for(unsigned user=0;user<2;user++)
                compare_mapping(&m,ordered[row].va+offsets[at],sizes[size],op,user);
        }
    }
    m=original;m.kernel=ordered;m.kernel_count=8;
    for(unsigned bit=0;bit<64;bit++)for(unsigned op=0;op<3;op++)for(unsigned user=0;user<2;user++)
        compare_mapping(&m,1ull<<bit,8,op,user);
    struct flat_mapping live[8];memcpy(live,ordered,sizeof live);
    m=original;m.kernel=live;m.kernel_count=8;
    /* Change the live array while the immutable-array index is still warm. */
    for(unsigned i=0;i<8;i++) {
        live[i].attrs^=0x480;live[i].pa^=0x1000;
        for(unsigned op=0;op<3;op++)for(unsigned user=0;user<2;user++)
            compare_mapping(&m,live[i].va,8,op,user);
    }
    assert(!flat_memory_index_init(&m,ordered));
    for(unsigned table=0;table<4;table++) {
        m=original;m.kernel=invalid[table];m.kernel_count=2;
        assert(!flat_memory_index_init(&m,invalid[table]));
        for(unsigned row=0;row<2;row++)for(unsigned at=0;at<7;at++)
        for(unsigned op=0;op<3;op++)for(unsigned user=0;user<2;user++)
            compare_mapping(&m,invalid[table][row].va+offsets[at],8,op,user);
    }
    m.kernel=ordered;m.kernel_count=0;assert(!flat_memory_index_init(&m,ordered));
    assert(!flat_memory_index_init(0,ordered));assert(!flat_memory_index_init(&m,0));
    printf("ordered map index: %u linear-reference comparisons passed\n",indexed_comparisons);
}
int main(void)
{
    struct flat_ram ram={0x1000,sizeof pages,(unsigned char *)pages};
    struct flat_mapping aliases[]={{0x20000000,0x5000,4096,0x740},{0x30000000,0x5000,4096,0x740}};
    struct flat_memory m={&ram,1,aliases,2,0x1000,16};
    for(unsigned i=0;i<3;i++)pages[i][0]=(0x2000+4096*i)|3;
    pages[3][1]=0x5000|0x743;
    struct flat_translation a=flat_translate(&m,0x1008,8,FLAT_WRITE,1);
    assert(!a.fault && a.pa==0x5008 && a.data==(unsigned char *)pages[4]+8);
    struct flat_translation b=flat_translate(&m,0x20000008,8,FLAT_WRITE,0);
    assert(!b.fault && b.data==a.data);
    b=flat_translate(&m,0x30000008,8,FLAT_READ,0);assert(b.data==a.data);
    *a.data=0x5a;assert(*b.data==0x5a);
    assert(flat_translate(&m,0x20000008,8,FLAT_READ,1).fault==15);
    pages[3][1]|=1ull<<7;assert(flat_translate(&m,0x1008,8,FLAT_WRITE,1).fault==15);
    assert(!flat_translate(&m,0x1008,8,FLAT_READ,1).fault);
    pages[3][1]&=~(1ull<<7);pages[0][0]|=1ull<<62;
    assert(flat_translate(&m,0x1008,8,FLAT_WRITE,1).fault==15);
    pages[0][0]&=~(1ull<<62);pages[0][0]|=1ull<<61;
    assert(flat_translate(&m,0x1008,8,FLAT_READ,1).fault==15);
    pages[0][0]&=~(1ull<<61);pages[0][0]|=1ull<<60;
    assert(flat_translate(&m,0x1008,4,FLAT_EXECUTE,1).fault==15);
    pages[0][0]&=~(1ull<<60);pages[3][1]&=~(1ull<<10);
    assert(flat_translate(&m,0x1008,4,FLAT_READ,1).fault==11);
    pages[3][1]=0;assert(flat_translate(&m,0x1008,4,FLAT_READ,1).fault==7);
    pages[3][1]=0x6000|0x743;a=flat_translate(&m,0x1008,4,FLAT_READ,1);
    assert(!a.fault && a.pa==0x6008); /* PTE additions/remaps are read from RAM. */
    assert(flat_translate(&m,0x1ffe,4,FLAT_READ,1).fault==0x100);
    pages[3][1]=0x5000|0x743;pages[3][2]=0x6000|0x743;
    a=flat_translate(&m,0x1ff8,16,FLAT_WRITE,1);
    assert(!a.fault && a.data==(unsigned char *)pages[4]+4088);
    memset(a.data,0x6b,16);assert(((unsigned char *)pages[5])[0]==0x6b);
    pages[3][2]|=1ull<<7;
    assert(flat_translate(&m,0x1ff8,16,FLAT_WRITE,1).fault==FLAT_CROSS_PAGE);
    pages[3][1]=0x6000|0x743;pages[3][2]=0x5000|0x743;
    assert(flat_translate(&m,0x1ff8,16,FLAT_READ,1).fault==FLAT_CROSS_PAGE);
    assert(flat_translate(&m,1ull<<48,4,FLAT_READ,1).fault==0x102);
    assert(!flat_physical(&m,UINT64_MAX,8));
    indexed_maps(m);
    puts("flat software translation: aliases, live PTE changes, permissions, AF, XN and bounds passed");
}
