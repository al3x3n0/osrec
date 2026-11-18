#ifndef FLAT_PROFILING_H
#define FLAT_PROFILING_H
#include <stdint.h>
#define FLAT_SYSTEM_PROFILE_ROWS 4096
/* One cache per table owned by this helper; clear it if the table is reset. */
struct flat_profile_cache {uint64_t *row;};
static __attribute__((noinline)) uint64_t *flat_profile_find(uint64_t table[FLAT_SYSTEM_PROFILE_ROWS][3],uint64_t word,uint64_t metadata)
{
    unsigned i=0;
    for(;i<FLAT_SYSTEM_PROFILE_ROWS-1;i++) {
        uint64_t *row=table[i];
        if(!row[2]){row[0]=word;row[1]=metadata;break;}
        if(row[0]==word && row[1]==metadata)break;
    }
    if(i==FLAT_SYSTEM_PROFILE_ROWS-1)table[i][0]=table[i][1]=UINT64_MAX;
    return table[i];
}
static inline void flat_profile_system(struct flat_profile_cache *cache,uint64_t table[FLAT_SYSTEM_PROFILE_ROWS][3],uint64_t word,uint64_t metadata)
{
    uint64_t *row=cache->row;
    if(!row || !row[2] || row[0]!=word || row[1]!=metadata) {
        row=flat_profile_find(table,word,metadata);
        /* The overflow row is a sentinel, not a cached source key. */
        cache->row=row==table[FLAT_SYSTEM_PROFILE_ROWS-1]?0:row;
    }
    row[2]++;
}
#endif
