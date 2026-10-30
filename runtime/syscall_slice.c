#include "osrec/syscall_slice.h"
static int overlap(uint64_t a,uint64_t an,uint64_t b,uint64_t bn){return a<b+bn && b<a+an;}
uint32_t osrec_user_memory_validate(const struct osrec_user_memory *m)
{
    if(!m || (m->count && !m->regions) || m->count>4096)return OSREC_SLICE_BAD_INPUT;
    for(size_t i=0;i<m->count;++i){const struct osrec_user_region *r=&m->regions[i];
        if(!r->bytes || !r->image_address || !r->object_id || !r->permissions || (r->permissions&~3u) || r->bytes>UINT64_MAX-r->user_address || r->bytes>UINTPTR_MAX-(uintptr_t)r->image_address)return OSREC_SLICE_BAD_INPUT;
        for(size_t j=0;j<i;++j){const struct osrec_user_region *p=&m->regions[j];
            if(r->object_id==p->object_id || overlap(r->user_address,r->bytes,p->user_address,p->bytes) || overlap((uintptr_t)r->image_address,r->bytes,(uintptr_t)p->image_address,p->bytes))return OSREC_SLICE_BAD_INPUT;}
    }
    return OSREC_SLICE_OK;
}
void *osrec_user_memory_resolve(const struct osrec_user_memory *m,uint64_t address,size_t n,uint32_t permissions)
{
    if(!m || !n || !permissions || (permissions&~3u) || n>UINT64_MAX-address)return NULL;
    for(size_t i=0;i<m->count;++i){const struct osrec_user_region *r=&m->regions[i];
        if(address>=r->user_address && address-r->user_address<=r->bytes && n<=r->bytes-(size_t)(address-r->user_address) && (r->permissions&permissions)==permissions)return r->image_address+(size_t)(address-r->user_address);}
    return NULL;
}
const struct osrec_user_region *osrec_user_memory_object(const struct osrec_user_memory *m,uint32_t id,size_t n,uint32_t permissions)
{
    if(!m || !id || !n || !permissions || (permissions&~3u))return NULL;
    for(size_t i=0;i<m->count;++i){const struct osrec_user_region *r=&m->regions[i];if(r->object_id==id && r->bytes>=n && (r->permissions&permissions)==permissions)return r;}
    return NULL;
}
uint32_t osrec_slice_session_init(struct osrec_slice_session *s,const struct osrec_slice_adapter *a,void *state,size_t bytes)
{
    if(!s || !a || a->abi!=OSREC_SLICE_ABI || !a->state_bytes || !a->state_alignment || (a->state_alignment&(a->state_alignment-1)) || !state || bytes<a->state_bytes || (uintptr_t)state%a->state_alignment || !a->restore || !a->enter || !a->finish || !a->calls)return OSREC_SLICE_BAD_INPUT;
    s->adapter=a;s->state=state;s->next=0;s->initialized=1;s->active=0;s->poisoned=0;a->restore(state);return OSREC_SLICE_OK;
}
uint32_t osrec_slice_session_restore(struct osrec_slice_session *s)
{
    if(!s || s->initialized!=1)return OSREC_SLICE_BAD_INPUT;if(s->active)return OSREC_SLICE_BUSY;
    s->adapter->restore(s->state);s->next=0;s->poisoned=0;return OSREC_SLICE_OK;
}
uint32_t osrec_slice_execute(struct osrec_slice_session *s,const struct osrec_slice_invocation *in,struct osrec_slice_result *out)
{
    if(!out)return OSREC_SLICE_BAD_INPUT;out->raw=0;out->diagnostic=0;out->ordinal=in ? in->ordinal : 0;
    if(!s || s->initialized!=1 || !in){out->status=OSREC_SLICE_BAD_INPUT;return out->status;}
    if(s->active){out->status=OSREC_SLICE_BUSY;return out->status;}
    if(s->poisoned){out->status=OSREC_SLICE_POISONED;return out->status;}
    if(s->next>=s->adapter->calls){out->status=OSREC_SLICE_COMPLETE;return out->status;}
    if(in->ordinal!=s->next || osrec_user_memory_validate(&in->memory)){out->status=OSREC_SLICE_BAD_INPUT;return out->status;}
    s->active=1;out->status=s->adapter->enter(s->state,in,out);s->active=0;
    if(out->status==OSREC_SLICE_OK)++s->next;
    else if(out->status!=OSREC_SLICE_BAD_INPUT)s->poisoned=1;
    return out->status;
}
uint32_t osrec_slice_finish(const struct osrec_slice_session *s)
{
    if(!s || s->initialized!=1)return OSREC_SLICE_BAD_INPUT;if(s->active)return OSREC_SLICE_BUSY;if(s->poisoned)return OSREC_SLICE_POISONED;
    if(s->next!=s->adapter->calls)return OSREC_SLICE_BAD_INPUT;return s->adapter->finish(s->state);
}
