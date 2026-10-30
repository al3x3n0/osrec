#include "osrec/slice_checkpoint.h"
static uint64_t read_le(const unsigned char *p,unsigned n){uint64_t v=0;for(unsigned i=0;i<n;++i)v|=(uint64_t)p[i]<<(8*i);return v;}
static void write_le(unsigned char *p,uint64_t v,unsigned n){for(unsigned i=0;i<n;++i)p[i]=(unsigned char)(v>>(8*i));}
static uint64_t checksum(const unsigned char *p,size_t n){uint64_t h=UINT64_C(14695981039346656037);for(size_t i=0;i<n;++i)if(i<56 || i>=64)h=(h^p[i])*UINT64_C(1099511628211);return h;}
static int overlaps(const void *a,size_t an,const void *b,size_t bn){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return an>UINTPTR_MAX-x || bn>UINTPTR_MAX-y || (x<y+bn && y<x+an);}
static uint32_t ready(const struct osrec_slice_session *s,const struct osrec_slice_checkpoint_codec *c,const void *p,size_t n)
{
    if(!s || s->initialized!=1 || !c || c->abi!=OSREC_SLICE_CHECKPOINT_ABI || c->adapter!=s->adapter || !c->payload_bytes || c->payload_bytes>UINT32_MAX-64u || !c->check || !c->encode || !c->validate || !c->decode || !p || n!=64+c->payload_bytes)return OSREC_SLICE_BAD_INPUT;
    if(s->active)return OSREC_SLICE_BUSY;if(s->poisoned)return OSREC_SLICE_POISONED;
    if(overlaps(p,n,s,sizeof(*s)) || overlaps(p,n,s->state,s->adapter->state_bytes) || overlaps(p,n,c,sizeof(*c)) || overlaps(p,n,s->adapter,sizeof(*s->adapter)))return OSREC_SLICE_BAD_INPUT;
    return OSREC_SLICE_OK;
}
uint32_t osrec_slice_checkpoint_save(const struct osrec_slice_session *s,const struct osrec_slice_checkpoint_codec *c,void *buffer,size_t n)
{
    uint32_t status=ready(s,c,buffer,n);if(status)return status;
    if(s->next>s->adapter->calls || c->check(s->state,s->next))return OSREC_SLICE_BAD_INPUT;
    unsigned char *p=buffer;for(size_t i=0;i<64;++i)p[i]=0;
    write_le(p,UINT64_C(0x31504b434552534f),8);write_le(p+8,1,4);write_le(p+12,n,4);
    for(unsigned i=0;i<32;++i)p[16+i]=c->schema[i];write_le(p+48,s->next,8);
    c->encode(s->state,p+64);write_le(p+56,checksum(p,n),8);return OSREC_SLICE_OK;
}
uint32_t osrec_slice_checkpoint_load(struct osrec_slice_session *s,const struct osrec_slice_checkpoint_codec *c,const void *buffer,size_t n)
{
    uint32_t status=ready(s,c,buffer,n);if(status)return status;const unsigned char *p=buffer;
    if(read_le(p,8)!=UINT64_C(0x31504b434552534f) || read_le(p+8,4)!=1 || read_le(p+12,4)!=n || read_le(p+56,8)!=checksum(p,n))return OSREC_SLICE_BAD_INPUT;
    for(unsigned i=0;i<32;++i)if(p[16+i]!=c->schema[i])return OSREC_SLICE_BAD_INPUT;
    uint64_t next=read_le(p+48,8);if(next>s->adapter->calls || c->validate(p+64,next))return OSREC_SLICE_BAD_INPUT;
    c->decode(s->state,p+64);s->next=next;return OSREC_SLICE_OK;
}
