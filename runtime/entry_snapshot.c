#include "osrec/entry_snapshot.h"
void osrec_snapshot_init(struct osrec_entry_snapshot *s) { s->object_count=s->root_count=s->field_count=s->failed=s->lifetime_cursor=0; }
static int same_name(const char *a,const char *b)
{
    while(*a && *a==*b) { ++a;++b; }
    return *a==*b;
}
static uint32_t object(struct osrec_entry_snapshot *s,const void *address,const char *type)
{
    if(!address) return 0;
    for(uint32_t i=0;i<s->object_count;++i) if(s->objects[i].address==address) return s->objects[i].id;
    if(!type || s->object_count>=OSREC_SNAPSHOT_OBJECTS) { s->failed=1;return 0; }
    uint32_t id=s->object_count+1;
    s->objects[s->object_count++]=(struct osrec_snapshot_object){address,type,id,0};return id;
}
uint32_t osrec_snapshot_identity(struct osrec_entry_snapshot *s,const void *address,const char *type)
{
    if(s->failed)return 0;
    return object(s,address,type);
}
int osrec_snapshot_bind(struct osrec_entry_snapshot *s,const char *name,const void *address,const char *type)
{
    if(s->failed || !name || s->root_count>=OSREC_SNAPSHOT_ROOTS) { s->failed=1;return 0; }
    uint32_t id=object(s,address,type);if(s->failed)return 0;
    s->roots[s->root_count++]=(struct osrec_snapshot_root){name,id};return 1;
}
static struct osrec_snapshot_field *field(struct osrec_entry_snapshot *s,const void *owner,const char *name)
{
    uint32_t id=0;
    for(uint32_t i=0;i<s->object_count;++i) if(s->objects[i].address==owner) id=s->objects[i].id;
    if(s->failed || !id || !name || s->field_count>=OSREC_SNAPSHOT_FIELDS) { s->failed=1;return 0; }
    for(uint32_t i=0;i<s->field_count;++i)
        if(s->fields[i].object_id==id && same_name(s->fields[i].name,name)) return &s->fields[i];
    struct osrec_snapshot_field *f=&s->fields[s->field_count++];
    f->name=name;f->object_id=id;f->target_id=f->size=f->is_edge=0;
    for(unsigned i=0;i<OSREC_SNAPSHOT_VALUE_BYTES;++i) f->bytes[i]=0;
    return f;
}
int osrec_snapshot_edge(struct osrec_entry_snapshot *s,const void *owner,const char *name,const void *target,const char *type)
{
    struct osrec_snapshot_field *f=field(s,owner,name);if(!f)return 0;
    uint32_t target_id=object(s,target,type);
    if(f->size || (f->is_edge && f->target_id!=target_id)) { s->failed=1;return 0; }
    f->target_id=target_id;f->is_edge=1;return !s->failed;
}
int osrec_snapshot_scalar(struct osrec_entry_snapshot *s,const void *owner,const char *name,const void *value,size_t bytes)
{
    if(!value || !bytes || bytes>OSREC_SNAPSHOT_VALUE_BYTES) { s->failed=1;return 0; }
    struct osrec_snapshot_field *f=field(s,owner,name);if(!f)return 0;
    const unsigned char *p=value;
    if(f->is_edge || (f->size && f->size!=bytes)) { s->failed=1;return 0; }
    if(f->size) { for(size_t i=0;i<bytes;++i) if(f->bytes[i]!=p[i]) { s->failed=1;return 0; }return 1; }
    f->size=(uint32_t)bytes;
    for(size_t i=0;i<bytes;++i)f->bytes[i]=p[i];return 1;
}
