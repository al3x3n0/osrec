#include "osrec/entry_capture.h"
#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "entry capture requires a little-endian target"
#endif
void osrec_capture_init(struct osrec_capture_session *s)
{
    osrec_snapshot_init(&s->identities);s->count=s->active=s->failed=0;
}
struct osrec_capture_call *osrec_capture_begin(struct osrec_capture_session *s,const char *root,uint32_t number)
{
    if(s->failed || s->active || s->count>=OSREC_CAPTURE_CALLS || !root) { s->failed=1;return 0; }
    struct osrec_capture_call *c=&s->calls[s->count];
    c->root=root;c->number=number;c->raw_bits=c->argument_count=0;
    osrec_snapshot_init(&c->entry);osrec_snapshot_init(&c->post);s->active=1;return c;
}
int osrec_capture_argument(struct osrec_capture_session *s,struct osrec_capture_call *c,const char *name,const void *value,size_t bytes)
{
    if(s->count>=OSREC_CAPTURE_CALLS || !s->active || c!=&s->calls[s->count] || !name || !value || bytes!=4 || c->argument_count>=OSREC_CAPTURE_ARGUMENTS) {
        s->failed=1;return 0;
    }
    struct osrec_capture_argument *a=&c->arguments[c->argument_count++];a->name=name;
    const unsigned char *data=value;for(unsigned i=0;i<4;++i)a->bytes[i]=data[i];return 1;
}
static int identities(struct osrec_capture_session *s,struct osrec_entry_snapshot *snapshot)
{
    if(snapshot->failed)return 0;
    for(uint32_t i=0;i<snapshot->object_count;++i) {
        struct osrec_snapshot_object *o=&snapshot->objects[i];
        o->session_id=osrec_snapshot_identity(&s->identities,o->address,o->type);
        if(!o->session_id)return 0;
    }
    return !s->identities.failed;
}
void osrec_capture_end(struct osrec_capture_session *s,struct osrec_capture_call *c,uint32_t raw_bits)
{
    if(s->count>=OSREC_CAPTURE_CALLS || !s->active || c!=&s->calls[s->count]) { s->failed=1;return; }
    c->raw_bits=raw_bits;
    if(!identities(s,&c->entry) || !identities(s,&c->post))s->failed=1;
    ++s->count;s->active=0;
}
struct writer { osrec_capture_write write;void *context;int ok; };
static void bytes(struct writer *w,const char *p,size_t n) { if(w->ok && !w->write(w->context,p,n))w->ok=0; }
static void text(struct writer *w,const char *p) { size_t n=0;while(p[n])++n;bytes(w,p,n); }
static void number(struct writer *w,uint32_t value)
{
    char buffer[10];unsigned n=0;do{buffer[n++]=(char)('0'+value%10);value/=10;}while(value);
    while(n)bytes(w,&buffer[--n],1);
}
static void hex(struct writer *w,const unsigned char *p,size_t n)
{
    const char digits[]="0123456789abcdef";
    for(size_t i=0;i<n;++i){char pair[2]={digits[p[i]>>4],digits[p[i]&15]};bytes(w,pair,2);}
}
static void string(struct writer *w,const char *p)
{
    text(w,"\"");
    for(;*p;++p){unsigned char c=(unsigned char)*p;
        if(c=='"' || c=='\\'){text(w,"\\");bytes(w,p,1);}
        else if(c<32){text(w,"\\u00");hex(w,&c,1);}
        else bytes(w,p,1);
    }
    text(w,"\"");
}
static void snapshot(struct writer *w,const struct osrec_capture_call *call,const struct osrec_entry_snapshot *s,uint32_t invocation)
{
    text(w,"{\"format\":\"osrec-entry-snapshot-v1\",\"syscall\":");number(w,call->number);
    text(w,",\"invocation\":");number(w,invocation);text(w,",\"objects\":[");
    for(uint32_t i=0;i<s->object_count;++i){const struct osrec_snapshot_object *o=&s->objects[i];
        if(i)text(w,",");text(w,"{\"id\":");number(w,o->id);text(w,",\"session_id\":");number(w,o->session_id);
        text(w,",\"type\":");string(w,o->type);text(w,"}");}
    text(w,"],\"roots\":[");
    for(uint32_t i=0;i<s->root_count;++i){if(i)text(w,",");text(w,"{\"name\":");string(w,s->roots[i].name);
        text(w,",\"object_id\":");number(w,s->roots[i].object_id);text(w,"}");}
    text(w,"],\"arguments\":[");
    for(uint32_t i=0;i<call->argument_count;++i){const struct osrec_capture_argument *a=&call->arguments[i];
        if(i)text(w,",");text(w,"{\"name\":");string(w,a->name);text(w,",\"bytes\":4,\"data\":\"");hex(w,a->bytes,4);text(w,"\"}");}
    text(w,"],\"fields\":[");
    for(uint32_t i=0;i<s->field_count;++i){const struct osrec_snapshot_field *f=&s->fields[i];
        if(i)text(w,",");text(w,"{\"object_id\":");number(w,f->object_id);text(w,",\"name\":");string(w,f->name);
        if(f->is_edge){text(w,",\"kind\":\"edge\",\"target_id\":");number(w,f->target_id);}
        else{text(w,",\"kind\":\"scalar\",\"bytes\":");number(w,f->size);text(w,",\"data\":\"");hex(w,f->bytes,f->size);text(w,"\"");}
        text(w,"}");}
    text(w,"]}");
}
int osrec_capture_json(const struct osrec_capture_session *s,const char *plan_sha256,const char *spec_sha256,
                       osrec_capture_write write,void *context)
{
    if(s->failed || s->active || !s->count || s->count>OSREC_CAPTURE_CALLS || !write || !plan_sha256 || !spec_sha256)return 0;
    struct writer w={write,context,1};text(&w,"{\"format\":\"osrec-entry-capture-v1\",\"plan_sha256\":");string(&w,plan_sha256);
    text(&w,",\"spec_sha256\":");string(&w,spec_sha256);text(&w,",\"calls\":[");
    for(uint32_t i=0;i<s->count;++i){const struct osrec_capture_call *c=&s->calls[i];
        if(i)text(&w,",");text(&w,"{\"root\":");string(&w,c->root);text(&w,",\"number\":");number(&w,c->number);
        text(&w,",\"raw_bits\":");number(&w,c->raw_bits);text(&w,",\"entry\":");snapshot(&w,c,&c->entry,i);
        text(&w,",\"post\":");snapshot(&w,c,&c->post,i);text(&w,"}");}
    text(&w,"]}\n");return w.ok;
}
