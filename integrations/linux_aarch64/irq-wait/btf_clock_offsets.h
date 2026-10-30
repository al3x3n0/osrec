/* Bounded BTF layout for CPU-base sequence and eight clock-base offsets. */
#ifndef OSREC_BTF_CLOCK_OFFSETS_H
#define OSREC_BTF_CLOCK_OFFSETS_H
#include "btf_base_state.h"
struct clock_offsets_layout {uint32_t cpu_type_id,cpu_size,base_type_id,base_size,array_offset,array_count,offset_offset,sequence_offset;};
static int btf_clock_scalar(const struct btf_view *v,uint32_t id,const char *name,unsigned width,unsigned encoding,uint32_t *offset)
{
    const unsigned char *p=btf_type(v,id);if(!p)return 0;
    uint32_t info=btf_u32(p+4),size=btf_u32(p+8),found=0;
    if(((info>>24)&31)!=4 || size<width/8 || size>4096)return 0;
    for(uint32_t i=0;i<(info&65535);++i){
        const unsigned char *m=p+12+12*i;if(!btf_name(v,btf_u32(m),name))continue;
        uint32_t bits=btf_u32(m+8),type=btf_u32(m+4);
        if(found++ || ((info>>31) && (bits>>24)) || bits%width || (uint64_t)bits/8+width/8>size)return 0;
        const unsigned char *t=NULL;
        for(unsigned depth=0;depth<16;++depth){
            t=btf_type(v,type);if(!t)return 0;
            unsigned kind=(btf_u32(t+4)>>24)&31;
            if(kind<8 || kind>11)break;
            type=btf_u32(t+8);t=NULL;
        }
        if(!t || btf_u32(t+4)!=(1U<<24) || btf_u32(t+8)!=width/8 ||
           btf_u32(t+12)!=(encoding<<24|width))return 0;
        *offset=bits/8;
    }
    return found==1;
}
static int btf_clock_offsets_layout(const unsigned char *data,size_t length,struct clock_offsets_layout *out)
{
    struct base_state_layout base;struct timer_return_layout timer;
    if(!btf_base_state_layout(data,length,&base) || !btf_timer_return_layout(data,length,&timer))return 0;
    uint32_t header=btf_u32(data+4);
    struct btf_view v={data,data+header+btf_u32(data+8),data+header+btf_u32(data+16),btf_u32(data+12),btf_u32(data+20)};
    out->cpu_type_id=base.cpu_type_id;out->cpu_size=base.cpu_size;
    out->base_type_id=base.base_type_id;out->base_size=timer.base_size;
    if(!btf_clock_scalar(&v,out->base_type_id,"offset",64,1,&out->offset_offset) ||
       !btf_clock_scalar(&v,out->cpu_type_id,"clock_was_set_seq",32,0,&out->sequence_offset))return 0;
    const unsigned char *p=btf_type(&v,out->cpu_type_id);uint32_t info=btf_u32(p+4),found=0;
    for(uint32_t i=0;i<(info&65535);++i){
        const unsigned char *m=p+12+12*i;if(!btf_name(&v,btf_u32(m),"clock_base"))continue;
        uint32_t bits=btf_u32(m+8);const unsigned char *a=btf_type(&v,btf_u32(m+4));
        if(found++ || ((info>>31) && (bits>>24)) || bits%64 || !a || btf_u32(a+4)!=(3U<<24) ||
           btf_u32(a+12)!=out->base_type_id || btf_u32(a+20)!=8)return 0;
        const unsigned char *index=btf_type(&v,btf_u32(a+16));
        if(!index || btf_u32(index+4)!=(1U<<24) || btf_u32(index+8)!=4 ||
           (btf_u32(index+12)!=32 && btf_u32(index+12)!=(1U<<24|32)))return 0;
        out->array_offset=bits/8;out->array_count=8;
        if((uint64_t)out->array_offset+8*(uint64_t)out->base_size>out->cpu_size ||
           (uint64_t)out->sequence_offset+4>out->array_offset)return 0;
    }
    return found==1;
}
#endif
