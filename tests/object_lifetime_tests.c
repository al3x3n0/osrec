#include "osrec/object_lifetime.h"
#include <assert.h>
#include <stdint.h>
int main(void)
{
    struct osrec_object_lifetimes tracker;struct osrec_entry_snapshot before,after;
    unsigned storage=99,other=123;osrec_lifetime_init(&tracker);
    assert(osrec_lifetime_observe(&tracker,&other)==1);
    assert(osrec_lifetime_observe(&tracker,&other)==1 && tracker.event_count==1);
    osrec_lifetime_seal(&tracker);
    assert(osrec_lifetime_allocate(&tracker,0,sizeof(storage))==0 && !tracker.failed);
    assert(osrec_lifetime_release(&tracker,0) && tracker.event_count==1);
    assert(osrec_lifetime_allocate(&tracker,&storage,sizeof(storage))==2);
    osrec_snapshot_init(&before);
    assert(osrec_snapshot_bind(&before,"current()",&storage,"unsigned"));
    assert(osrec_snapshot_bind(&before,"alias()",&storage,"unsigned"));
    assert(osrec_snapshot_scalar(&before,&storage,"value",&storage,sizeof(storage)));
    assert(osrec_snapshot_lifetimes(&before,&tracker,0));
    assert(before.objects[0].session_id==2);
    assert(before.lifetime_cursor==2);
    assert(osrec_lifetime_release(&tracker,&storage));
    assert(osrec_lifetime_allocate(&tracker,&storage,sizeof(storage))==3);
    osrec_snapshot_init(&after);
    assert(osrec_snapshot_bind(&after,"current()",&storage,"unsigned"));
    assert(osrec_snapshot_lifetimes(&after,&tracker,0));
    assert(after.objects[0].id==before.objects[0].id);
    assert(after.objects[0].session_id!=before.objects[0].session_id);
    assert(after.lifetime_cursor==4 && before.lifetime_cursor==2);
    assert(before.objects[0].session_id==2 && !before.failed);
    assert(tracker.event_count==4);
    assert(tracker.events[2].kind==OSREC_LIFETIME_RELEASE && tracker.events[2].id==2);
    assert(tracker.events[3].kind==OSREC_LIFETIME_ALLOCATE && tracker.events[3].id==3);
    for(unsigned i=0;i<tracker.event_count;++i) assert(tracker.events[i].ordinal==i);
    /* A saved snapshot cannot be relabeled with the later allocation's ID. */
    assert(!osrec_snapshot_lifetimes(&before,&tracker,0) && before.failed);
    osrec_lifetime_init(&tracker);
    assert(osrec_lifetime_allocate(&tracker,&storage,4)==1);
    assert(!osrec_lifetime_allocate(&tracker,&storage,4) && tracker.failed);
    assert(!osrec_lifetime_release(&tracker,&storage));
    osrec_lifetime_init(&tracker);
    assert(!osrec_lifetime_release(&tracker,&storage) && tracker.failed);
    osrec_lifetime_init(&tracker);osrec_lifetime_seal(&tracker);
    assert(!osrec_lifetime_observe(&tracker,&storage) && tracker.failed);
    osrec_lifetime_init(&tracker);
    assert(osrec_lifetime_allocate(&tracker,&storage,4)==1);
    assert(osrec_lifetime_release(&tracker,&storage));
    assert(!osrec_lifetime_identity(&tracker,&storage) && tracker.failed);
    osrec_lifetime_init(&tracker);
    assert(!osrec_lifetime_allocate(&tracker,&storage,0) && tracker.failed);
    osrec_lifetime_init(&tracker);tracker.next_id=UINT32_MAX;
    assert(osrec_lifetime_allocate(&tracker,&storage,4)==UINT32_MAX);
    assert(osrec_lifetime_release(&tracker,&storage));
    assert(!osrec_lifetime_allocate(&tracker,&storage,4) && tracker.failed);
    unsigned objects[OSREC_LIFETIME_SLOTS+1];osrec_lifetime_init(&tracker);
    for(unsigned i=0;i<OSREC_LIFETIME_SLOTS;++i)
        assert(osrec_lifetime_allocate(&tracker,&objects[i],4)==i+1);
    assert(!osrec_lifetime_allocate(&tracker,&objects[OSREC_LIFETIME_SLOTS],4) && tracker.failed);
    osrec_lifetime_init(&tracker);
    for(unsigned i=0;i<OSREC_LIFETIME_EVENTS/2;++i) {
        assert(osrec_lifetime_allocate(&tracker,&storage,4)==i+1);
        assert(osrec_lifetime_release(&tracker,&storage));
    }
    assert(tracker.event_count==OSREC_LIFETIME_EVENTS);
    assert(!osrec_lifetime_allocate(&tracker,&storage,4) && tracker.failed);
    return 0;
}
