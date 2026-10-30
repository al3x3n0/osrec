/* Bounded direct clock-base pointer and 32-bit scalar layout. */
#ifndef OSREC_BTF_BASE_STATE_H
#define OSREC_BTF_BASE_STATE_H
#include "btf_timer_return.h"
struct base_state_layout {uint32_t base_type_id,cpu_type_id,cpu_size,cpu_base_offset,index_offset,active_offset;};
static int btf_scalar32_member(const struct btf_view *v,uint32_t id,const char *name,uint32_t *offset)
{
    const unsigned char *p=btf_type(v,id);if(!p)return 0;
    uint32_t info=btf_u32(p+4),size=btf_u32(p+8),found=0;
    if(((info>>24)&31)!=4 || size<4 || size>4096)return 0;
    for(uint32_t i=0;i<(info&65535);++i){
        const unsigned char *m=p+12+12*i;if(!btf_name(v,btf_u32(m),name))continue;
        uint32_t bits=btf_u32(m+8),type=btf_u32(m+4);
        if(found++ || ((info>>31) && (bits>>24)) || bits%32 || (uint64_t)bits/8+4>size)return 0;
        const unsigned char *t=NULL;
        for(unsigned depth=0;depth<16;++depth){
            t=btf_type(v,type);if(!t)return 0;
            uint32_t kind=(btf_u32(t+4)>>24)&31;
            if(kind<8 || kind>11)break;
            type=btf_u32(t+8);t=NULL;
        }
        if(!t || btf_u32(t+4)!=(1U<<24) || btf_u32(t+8)!=4 ||
           (btf_u32(t+12)&0x00ffffff)!=32 || (btf_u32(t+12)>>24)>1)return 0;
        *offset=bits/8;
    }
    return found==1;
}
static int btf_base_state_layout(const unsigned char *data,size_t length,struct base_state_layout *out)
{
    struct timer_return_layout timer;if(!btf_timer_return_layout(data,length,&timer))return 0;
    uint32_t header=btf_u32(data+4);
    struct btf_view v={data,data+header+btf_u32(data+8),data+header+btf_u32(data+16),btf_u32(data+12),btf_u32(data+20)};
    out->base_type_id=timer.base_type_id;out->cpu_type_id=btf_named_struct(&v,"hrtimer_cpu_base");
    if(!out->cpu_type_id ||
       btf_pointer_member(&v,out->base_type_id,"cpu_base",&out->cpu_base_offset)!=out->cpu_type_id ||
       !btf_scalar32_member(&v,out->base_type_id,"index",&out->index_offset) ||
       !btf_scalar32_member(&v,out->cpu_type_id,"active_bases",&out->active_offset))return 0;
    out->cpu_size=btf_u32(btf_type(&v,out->cpu_type_id)+8);return 1;
}
#endif
