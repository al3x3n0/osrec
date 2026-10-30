/* Bounded structural layout for tk_core symbol-relative boundary reads.
 * This kernel BTF has no tk_core VAR: the unique anonymous {seq,timekeeper}
 * shape is a layout candidate, not an attested symbol/type association. */
#ifndef OSREC_BTF_TIMEKEEPER_H
#define OSREC_BTF_TIMEKEEPER_H
#include "btf_clock_offsets.h"
struct timekeeper_layout {
    uint32_t core_type_id,core_size,timekeeper_type_id,timekeeper_size;
    uint32_t sequence_offset,clock_sequence_offset,mono_base_offset,real_offset,boot_offset,tai_offset,leap_offset;
};
static uint32_t btf_tk_unwrap(const struct btf_view *v,uint32_t id)
{
    for(unsigned depth=0;depth<16;++depth){
        const unsigned char *p=btf_type(v,id);if(!p)return 0;
        unsigned kind=(btf_u32(p+4)>>24)&31;
        if(kind<8 || kind>11)return id;
        id=btf_u32(p+8);
    }
    return 0;
}
static uint32_t btf_tk_member(const struct btf_view *v,uint32_t parent,const char *name,uint32_t *offset)
{
    const unsigned char *p=btf_type(v,btf_tk_unwrap(v,parent));if(!p)return 0;
    uint32_t info=btf_u32(p+4),size=btf_u32(p+8),found=0;
    if(((info>>24)&31)!=4 || !size || size>4096)return 0;
    for(uint32_t i=0;i<(info&65535);++i){
        const unsigned char *m=p+12+12*i;if(!btf_name(v,btf_u32(m),name))continue;
        uint32_t bits=btf_u32(m+8),id=btf_tk_unwrap(v,btf_u32(m+4));
        const unsigned char *t=btf_type(v,id);
        if(found || !t || ((info>>31)&&(bits>>24)) || bits%32 ||
           !btf_u32(t+8) || (uint64_t)bits/8+btf_u32(t+8)>size)return 0;
        unsigned kind=(btf_u32(t+4)>>24)&31;
        if(kind!=1 && kind!=4)return 0;
        found=id;*offset=bits/8;
    }
    return found;
}
static int btf_timekeeper_layout(const unsigned char *data,size_t length,struct timekeeper_layout *out)
{
    struct clock_offsets_layout clocks;
    if(!btf_clock_offsets_layout(data,length,&clocks))return 0;
    uint32_t header=btf_u32(data+4);
    struct btf_view v={data,data+header+btf_u32(data+8),data+header+btf_u32(data+16),btf_u32(data+12),btf_u32(data+20)};
    uint32_t tk=btf_named_struct(&v,"timekeeper"),mono=btf_named_struct(&v,"tk_read_base");
    if(!tk || !mono)return 0;
    uint32_t mo,ba,cs,re,bo,ta,le;
    if(btf_tk_member(&v,tk,"tkr_mono",&mo)!=mono || mo%8 ||
       !btf_clock_scalar(&v,mono,"base",64,1,&ba) ||
       !btf_clock_scalar(&v,tk,"clock_was_set_seq",32,0,&cs) ||
       !btf_clock_scalar(&v,tk,"offs_real",64,1,&re) ||
       !btf_clock_scalar(&v,tk,"offs_boot",64,1,&bo) ||
       !btf_clock_scalar(&v,tk,"offs_tai",64,1,&ta) ||
       !btf_clock_scalar(&v,tk,"next_leap_ktime",64,1,&le))return 0;
    uint32_t positions[]={mo+ba,re,bo,ta,le,cs};
    for(unsigned i=0;i<6;++i)for(unsigned j=0;j<i;++j)
        if(positions[i]<positions[j]+(j==5?4:8) && positions[j]<positions[i]+(i==5?4:8))return 0;
    size_t at=0;uint32_t id=1,found=0;
    while(at<v.type_length){
        const unsigned char *p=v.types+at;uint32_t info=btf_u32(p+4);
        if(((info>>24)&31)==4 && !btf_u32(p) && (info&65535)==2){
            uint32_t to,so,qo,sq;
            uint32_t seq=btf_tk_member(&v,id,"seq",&so);
            if(btf_tk_member(&v,id,"timekeeper",&to)==tk && seq){
                uint32_t qc=btf_tk_member(&v,seq,"seqcount",&qo);
                if(found++ || so || to%8 || !qc || !btf_clock_scalar(&v,qc,"sequence",32,0,&sq) ||
                   (uint64_t)so+qo+sq+4>to)return 0;
                out->core_type_id=id;out->core_size=btf_u32(p+8);
                out->timekeeper_type_id=tk;out->timekeeper_size=btf_u32(btf_type(&v,tk)+8);
                out->sequence_offset=so+qo+sq;out->clock_sequence_offset=to+cs;
                out->mono_base_offset=to+mo+ba;out->real_offset=to+re;out->boot_offset=to+bo;
                out->tai_offset=to+ta;out->leap_offset=to+le;
            }
        }
        at+=btf_record_size(p);++id;
    }
    return found==1;
}
#endif
