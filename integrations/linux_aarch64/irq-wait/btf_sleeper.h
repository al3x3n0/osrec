/* Bounded little-endian BTF reader for the two direct hrtimer_sleeper members. */
#ifndef OSREC_BTF_SLEEPER_H
#define OSREC_BTF_SLEEPER_H
#include <stdint.h>
#include <stddef.h>
struct sleeper_layout {uint32_t type_id,size,task_offset,timer_offset;};
struct btf_view {const unsigned char *data,*types,*strings;size_t type_length,string_length;};
static uint32_t btf_u32(const unsigned char *p)
{return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static int btf_name(const struct btf_view *v,uint32_t offset,const char *name)
{
    if(offset>=v->string_length)return 0;
    size_t i=0;while(offset+i<v->string_length){if(v->strings[offset+i]!=(unsigned char)name[i])return 0;if(!name[i])return 1;++i;}return 0;
}
static size_t btf_record_size(const unsigned char *p)
{
    uint32_t info=btf_u32(p+4),kind=(info>>24)&31,n=info&65535;
    switch(kind){
    case 1:case 14:case 17:return 16;
    case 2:case 7:case 8:case 9:case 10:case 11:case 12:case 16:case 18:return 12;
    case 3:return 24;
    case 4:case 5:case 15:case 19:return 12+(size_t)n*12;
    case 6:case 13:return 12+(size_t)n*8;
    default:return 0;
    }
}
static const unsigned char *btf_type(const struct btf_view *v,uint32_t requested)
{
    size_t offset=0;uint32_t id=1;
    while(offset<v->type_length){
        if(v->type_length-offset<12)return NULL;
        const unsigned char *p=v->types+offset;size_t size=btf_record_size(p);
        if(!size || size>v->type_length-offset)return NULL;
        if(id==requested)return p;
        offset+=size;++id;
    }
    return NULL;
}
static int btf_sleeper_layout(const unsigned char *data,size_t length,struct sleeper_layout *out)
{
    if(length<24 || data[0]!=0x9f || data[1]!=0xeb || data[2]!=1 || data[3])return 0;
    uint32_t header=btf_u32(data+4),to=btf_u32(data+8),tl=btf_u32(data+12),so=btf_u32(data+16),sl=btf_u32(data+20);
    if(header<24 || header>length || !sl || (uint64_t)to+tl>length-header ||
       (uint64_t)so+sl>length-header || (uint64_t)to+tl>so)return 0;
    struct btf_view v={data,data+header+to,data+header+so,tl,sl};
    if(v.strings[0])return 0;
    size_t offset=0;uint32_t id=1,found=0;
    while(offset<v.type_length){
        if(v.type_length-offset<12)return 0;
        const unsigned char *p=v.types+offset;size_t size=btf_record_size(p);
        if(!size || size>v.type_length-offset)return 0;
        uint32_t info=btf_u32(p+4);
        if(((info>>24)&31)==4 && btf_name(&v,btf_u32(p),"hrtimer_sleeper")){
            if(found++ || (info>>31))return 0;
            uint32_t task_found=0,timer_found=0,task_type=0,timer_type=0;
            out->type_id=id;out->size=btf_u32(p+8);
            for(uint32_t i=0;i<(info&65535);++i){
                const unsigned char *member=p+12+12*i;uint32_t bits=btf_u32(member+8);
                if(btf_name(&v,btf_u32(member),"task")){
                    if(task_found++ || bits%64)return 0;
                    out->task_offset=bits/8;task_type=btf_u32(member+4);
                }
                if(btf_name(&v,btf_u32(member),"timer")){
                    if(timer_found++ || bits)return 0;
                    out->timer_offset=0;timer_type=btf_u32(member+4);
                }
            }
            if(task_found!=1 || timer_found!=1 || out->size>4096 || out->task_offset<8 ||
               (uint64_t)out->task_offset+8>out->size)return 0;
            const unsigned char *t=btf_type(&v,timer_type),*pointer=btf_type(&v,task_type);
            if(!t || !pointer || ((btf_u32(t+4)>>24)&31)!=4 || !btf_name(&v,btf_u32(t),"hrtimer") ||
               ((btf_u32(pointer+4)>>24)&31)!=2 || btf_u32(t+8)>out->task_offset)return 0;
            const unsigned char *task=btf_type(&v,btf_u32(pointer+8));
            if(!task || ((btf_u32(task+4)>>24)&31)!=4 || !btf_name(&v,btf_u32(task),"task_struct"))return 0;
        }
        offset+=size;++id;
    }
    return found==1;
}
#endif
