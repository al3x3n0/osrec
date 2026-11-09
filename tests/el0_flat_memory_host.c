#include "memory.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static uint64_t pages[6][512];
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
    puts("flat software translation: aliases, live PTE changes, permissions, AF, XN and bounds passed");
}
