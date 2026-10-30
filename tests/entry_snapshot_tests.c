#include "osrec/entry_snapshot.h"
#include <assert.h>
#include <stdint.h>
int main(void)
{
    struct osrec_entry_snapshot s;uint32_t a=123,b=456;
    osrec_snapshot_init(&s);
    assert(osrec_snapshot_bind(&s,"current",&a,"process"));
    assert(osrec_snapshot_bind(&s,"alias",&a,"process"));
    assert(osrec_snapshot_bind(&s,"null",0,"process"));
    assert(s.object_count==1 && s.roots[0].object_id==s.roots[1].object_id && s.roots[2].object_id==0);
    assert(osrec_snapshot_edge(&s,&a,"parent",&b,"process"));
    assert(osrec_snapshot_edge(&s,&b,"parent",&a,"process"));
    assert(s.object_count==2 && s.fields[0].target_id==2 && s.fields[1].target_id==1);
    assert(osrec_snapshot_scalar(&s,&b,"pid",&b,sizeof(b)));
    assert(osrec_snapshot_scalar(&s,&b,"pid",&b,sizeof(b)));
    assert(s.field_count==3 && s.fields[2].size==4 && !s.fields[0].size && !s.fields[1].size);
    b=789;assert(!osrec_snapshot_scalar(&s,&b,"pid",&b,sizeof(b)));assert(s.failed);
    osrec_snapshot_init(&s);assert(!osrec_snapshot_scalar(&s,&a,"pid",&a,sizeof(a)));assert(s.failed);
    osrec_snapshot_init(&s);assert(osrec_snapshot_bind(&s,"current",&a,"process"));
    assert(!osrec_snapshot_scalar(&s,&a,"wide",&a,OSREC_SNAPSHOT_VALUE_BYTES+1));assert(s.failed);
    osrec_snapshot_init(&s);
    for(unsigned i=0;i<OSREC_SNAPSHOT_ROOTS;++i) assert(osrec_snapshot_bind(&s,"alias",&a,"process"));
    assert(!osrec_snapshot_bind(&s,"overflow",&a,"process"));assert(s.failed);
    osrec_snapshot_init(&s);
    assert(osrec_snapshot_identity(&s,0,"process")==0 && !s.failed);
    assert(osrec_snapshot_identity(&s,&a,"process")==1);
    assert(osrec_snapshot_identity(&s,&a,"process")==1);
    assert(osrec_snapshot_identity(&s,&b,"process")==2);
    assert(s.root_count==0 && s.field_count==0 && s.object_count==2);
    uint32_t identities[OSREC_SNAPSHOT_OBJECTS+1];osrec_snapshot_init(&s);
    for(unsigned i=0;i<OSREC_SNAPSHOT_OBJECTS;++i)
        assert(osrec_snapshot_identity(&s,&identities[i],"token")==i+1);
    assert(osrec_snapshot_identity(&s,&identities[0],"token")==1);
    assert(osrec_snapshot_identity(&s,&identities[OSREC_SNAPSHOT_OBJECTS],"token")==0 && s.failed);
    return 0;
}
