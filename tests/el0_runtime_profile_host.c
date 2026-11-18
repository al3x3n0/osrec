#include "profiling.h"
#include <assert.h>
#include <string.h>
static uint64_t actual[4096][3],expected[4096][3];
static struct flat_profile_cache cache;
static void reference(uint64_t word,uint64_t metadata)
{
    unsigned i=0;
    for(;i<4095;i++) {
        uint64_t *row=expected[i];
        if(!row[2]){row[0]=word;row[1]=metadata;break;}
        if(row[0]==word && row[1]==metadata)break;
    }
    if(i==4095)expected[i][0]=expected[i][1]=UINT64_MAX;
    expected[i][2]++;
}
static void visit(uint64_t word,uint64_t metadata)
{
    flat_profile_system(&cache,actual,word,metadata);reference(word,metadata);
}
int main(void)
{
    visit(UINT64_MAX,UINT64_MAX); /* A real key must not alias overflow. */
    for(unsigned i=0;i<1000;i++)visit(0xd69f03e0,0);
    for(unsigned i=0;i<3000;i++){visit(i%37,i%5);visit(i%37,i%5);}
    assert(!memcmp(actual,expected,sizeof actual));
    for(unsigned i=0;i<4200;i++)visit(0x100000000ull+i,0x40000000ull+(i&7));
    for(unsigned i=0;i<100;i++){visit(0x700000000ull+i,0);visit(UINT64_MAX,UINT64_MAX);}
    assert(!memcmp(actual,expected,sizeof actual));
    assert(actual[4095][2] && actual[4095][0]==UINT64_MAX);
    /* A count wrapping to zero has the original first-empty-slot behavior. */
    actual[0][2]=expected[0][2]=UINT64_MAX;
    visit(UINT64_MAX,UINT64_MAX);visit(0xd69f03e0,0);
    assert(!memcmp(actual,expected,sizeof actual));
    memset(actual,0,sizeof actual);memset(expected,0,sizeof expected);cache.row=0;
    visit(0x123,0);visit(0x123,1);visit(0x123,0);
    assert(!memcmp(actual,expected,sizeof actual));
    assert(actual[0][2]==2 && actual[1][2]==1);
    return 0;
}
