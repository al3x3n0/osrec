#ifndef FLAT_ADMISSION_H
#define FLAT_ADMISSION_H
#include "memory.h"
#include "compare.h"

/* Only the linked immutable map array may use the ordered index. Other map
 * arrays retain the original first-eligible scan, including overlap order. */
struct flat_stack_index {
    const struct flat_mapping *maps;size_t count,hint;
    uint64_t admitted_sp,ram_base,ram_bytes;unsigned admitted;
};
static inline void flat_stack_index_init(struct flat_stack_index *index,const struct flat_memory *memory,
                                         const struct flat_mapping *immutable)
{
    *index=(struct flat_stack_index){0};
    if(!immutable || memory->kernel!=immutable || !memory->kernel_count)return;
    uint64_t end=0;
    for(size_t i=0;i<memory->kernel_count;i++) {
        const struct flat_mapping *m=immutable+i;
        if(!m->bytes || m->bytes>UINT64_MAX-m->va || (i && m->va<end))return;
        end=m->va+m->bytes;
    }
    index->maps=immutable;index->count=memory->kernel_count;
}
static inline __attribute__((always_inline)) int flat_stack_admitted(const struct flat_stack_index *index,const struct flat_memory *memory,uint64_t sp)
{
    /* Retain base pointers for the hot aggregate loads; no machine code is
     * emitted by this register constraint. */
    __asm__("" : "+r"(index), "+r"(memory));
    if(!index->admitted)return 0;
    /* These first comparisons read only the two bounded control objects.
     * Evaluate together so AArch64 can pair loads and chain CCMPs. Keep the
     * RAM dereference after the mapping/count guard, as before. */
    int binding=flat_equal3(sp,index->admitted_sp,(uintptr_t)memory->kernel,(uintptr_t)index->maps,
                            memory->kernel_count,index->count);
    if(!binding)return 0;
    return flat_equal2(memory->ram->pa,index->ram_base,memory->ram->bytes,index->ram_bytes);
}
/* Record only after mapping, physical bounds and immutable-write checks pass.
 * Both map descriptors and protected spans are linked read-only objects. */
static inline void flat_stack_admission_remember(struct flat_stack_index *index,const struct flat_memory *memory,uint64_t sp)
{
    index->admitted=0;
    if(!index->maps || memory->kernel!=index->maps || memory->kernel_count!=index->count)return;
    index->admitted_sp=sp;index->ram_base=memory->ram->pa;index->ram_bytes=memory->ram->bytes;index->admitted=1;
}
static inline int flat_stack_mapping_valid(const struct flat_memory *memory,const struct flat_mapping *m,uint64_t sp)
{
    if(sp-64<m->va || sp-m->va>m->bytes || !(m->attrs&(1ull<<10)) || m->attrs&(1ull<<7))return 0;
    uint64_t offset=sp-64-m->va;
    if(offset>UINT64_MAX-m->pa)return 0;
    uint64_t pa=m->pa+offset;const struct flat_ram *ram=memory->ram;
    return ram->bytes>=64 && pa>=ram->pa && pa-ram->pa<=ram->bytes-64;
}
static inline const struct flat_mapping *flat_stack_mapping(struct flat_stack_index *index,const struct flat_memory *memory,uint64_t sp)
{
    if(sp<64 || (sp&15))return 0;
    if(index->maps && memory->kernel==index->maps && memory->kernel_count==index->count) {
        const struct flat_mapping *m=index->maps+index->hint;
        if(sp-64<m->va || sp-m->va>m->bytes) {
            size_t lo=0,hi=index->count;
            while(lo<hi){size_t mid=lo+(hi-lo)/2;if(index->maps[mid].va<=sp-64)lo=mid+1;else hi=mid;}
            if(!lo)return 0;
            index->hint=lo-1;m=index->maps+index->hint;
        }
        return flat_stack_mapping_valid(memory,m,sp)?m:0;
    }
    for(size_t i=0;i<memory->kernel_count;i++)
        if(flat_stack_mapping_valid(memory,memory->kernel+i,sp))return memory->kernel+i;
    return 0;
}
#endif
