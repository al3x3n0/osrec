#include "osrec/object_lifetime.h"
void osrec_lifetime_init(struct osrec_object_lifetimes *s)
{
    s->next_id=1;s->event_count=s->failed=s->sealed=0;
    for(unsigned i=0;i<OSREC_LIFETIME_SLOTS;++i) {
        s->slots[i].address=0;s->slots[i].id=s->slots[i].active=0;
    }
}
void osrec_lifetime_seal(struct osrec_object_lifetimes *s) { s->sealed=1; }
static struct osrec_lifetime_slot *find(struct osrec_object_lifetimes *s,const void *address)
{
    for(unsigned i=0;i<OSREC_LIFETIME_SLOTS;++i)
        if(s->slots[i].active && s->slots[i].address==address) return &s->slots[i];
    return 0;
}
static uint32_t add(struct osrec_object_lifetimes *s,const void *address,size_t size,uint32_t kind)
{
    if(s->failed || !address)return 0;
    if(find(s,address) || !s->next_id || s->event_count>=OSREC_LIFETIME_EVENTS) { s->failed=1;return 0; }
    for(unsigned i=0;i<OSREC_LIFETIME_SLOTS;++i) if(!s->slots[i].active) {
        uint32_t id=s->next_id++;
        s->slots[i]=(struct osrec_lifetime_slot){address,id,1};
        s->events[s->event_count]=(struct osrec_lifetime_event){s->event_count,id,kind,size};
        ++s->event_count;return id;
    }
    s->failed=1;return 0;
}
uint32_t osrec_lifetime_observe(struct osrec_object_lifetimes *s,const void *address)
{
    if(s->failed || !address)return 0;
    struct osrec_lifetime_slot *slot=find(s,address);
    if(slot)return slot->id;
    if(s->sealed) { s->failed=1;return 0; }
    return add(s,address,0,OSREC_LIFETIME_EXISTING);
}
uint32_t osrec_lifetime_allocate(struct osrec_object_lifetimes *s,const void *address,size_t size)
{
    if(s->failed || !address)return 0;
    if(!size) { s->failed=1;return 0; }
    return add(s,address,size,OSREC_LIFETIME_ALLOCATE);
}
int osrec_lifetime_release(struct osrec_object_lifetimes *s,const void *address)
{
    if(s->failed)return 0;
    if(!address)return 1;
    struct osrec_lifetime_slot *slot=find(s,address);
    if(!slot || s->event_count>=OSREC_LIFETIME_EVENTS) { s->failed=1;return 0; }
    s->events[s->event_count]=(struct osrec_lifetime_event){s->event_count,slot->id,OSREC_LIFETIME_RELEASE,0};
    ++s->event_count;slot->active=0;return 1;
}
uint32_t osrec_lifetime_identity(struct osrec_object_lifetimes *s,const void *address)
{
    if(s->failed || !address)return 0;
    struct osrec_lifetime_slot *slot=find(s,address);
    if(!slot) { s->failed=1;return 0; }
    return slot->id;
}
int osrec_snapshot_lifetimes(struct osrec_entry_snapshot *snapshot,struct osrec_object_lifetimes *s,int observe_existing)
{
    if(snapshot->failed || s->failed || snapshot->lifetime_cursor) { snapshot->failed=1;return 0; }
    for(unsigned i=0;i<snapshot->object_count;++i) {
        struct osrec_snapshot_object *object=&snapshot->objects[i];
        uint32_t id=observe_existing ? osrec_lifetime_observe(s,object->address) : osrec_lifetime_identity(s,object->address);
        if(!id || (object->session_id && object->session_id!=id)) { snapshot->failed=1;return 0; }
        object->session_id=id;
    }
    snapshot->lifetime_cursor=s->event_count;
    return 1;
}
