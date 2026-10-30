/* Bounded pointer-member layout for a post-sleep running-timer observation. */
#ifndef OSREC_BTF_TIMER_RETURN_H
#define OSREC_BTF_TIMER_RETURN_H
#include "btf_sleeper.h"
struct timer_return_layout {uint32_t timer_type_id,timer_size,base_type_id,base_size,base_offset,running_offset;};
static uint32_t btf_named_struct(const struct btf_view *v,const char *name)
{
    size_t offset=0;uint32_t id=1,found=0;
    while(offset<v->type_length){
        const unsigned char *p=v->types+offset;
        if(((btf_u32(p+4)>>24)&31)==4 && btf_name(v,btf_u32(p),name)){
            if(found)return 0;found=id;
        }
        offset+=btf_record_size(p);++id;
    }
    return found;
}
static uint32_t btf_pointer_member(const struct btf_view *v,uint32_t id,const char *name,uint32_t *offset)
{
    const unsigned char *p=btf_type(v,id);if(!p)return 0;
    uint32_t info=btf_u32(p+4),size=btf_u32(p+8),found=0;
    if(((info>>24)&31)!=4 || size<8 || size>4096)return 0;
    for(uint32_t i=0;i<(info&65535);++i){
        const unsigned char *m=p+12+12*i;
        if(!btf_name(v,btf_u32(m),name))continue;
        uint32_t bits=btf_u32(m+8);
        if(found || ((info>>31) && (bits>>24)) || bits%64 || (uint64_t)bits/8+8>size)return 0;
        const unsigned char *pointer=btf_type(v,btf_u32(m+4));
        if(!pointer || btf_u32(pointer+4)!=(2U<<24) || !btf_u32(pointer+8))return 0;
        found=btf_u32(pointer+8);*offset=bits/8;
    }
    return found;
}
static int btf_timer_return_layout(const unsigned char *data,size_t length,struct timer_return_layout *out)
{
    /* This first pass validates all record bounds before the member scans. */
    struct sleeper_layout sleeper;if(!btf_sleeper_layout(data,length,&sleeper))return 0;
    uint32_t header=btf_u32(data+4);
    struct btf_view v={data,data+header+btf_u32(data+8),data+header+btf_u32(data+16),btf_u32(data+12),btf_u32(data+20)};
    out->timer_type_id=btf_named_struct(&v,"hrtimer");
    out->base_type_id=btf_named_struct(&v,"hrtimer_clock_base");
    if(!out->timer_type_id || !out->base_type_id ||
       btf_pointer_member(&v,out->timer_type_id,"base",&out->base_offset)!=out->base_type_id ||
       btf_pointer_member(&v,out->base_type_id,"running",&out->running_offset)!=out->timer_type_id)return 0;
    out->timer_size=btf_u32(btf_type(&v,out->timer_type_id)+8);
    out->base_size=btf_u32(btf_type(&v,out->base_type_id)+8);
    return out->timer_size<=sleeper.task_offset;
}
#endif
