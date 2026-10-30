#ifndef OSREC_OBJECT_LIFETIME_H
#define OSREC_OBJECT_LIFETIME_H
#include "osrec/entry_snapshot.h"
#define OSREC_LIFETIME_SLOTS 32U
#define OSREC_LIFETIME_EVENTS 128U
enum osrec_lifetime_kind { OSREC_LIFETIME_EXISTING=1, OSREC_LIFETIME_ALLOCATE=2, OSREC_LIFETIME_RELEASE=3 };
/* Addresses are transient. Only event ordinal, ID, kind and size may be exported.
 * Caller must serialize hooks with snapshots and cover every allocation/free in
 * the claimed scope. Failed allocations and free(NULL) produce no event.
 * Observe seeds existing live objects; seal before tracking dynamic lifetimes.
 * Interior pointers and realloc are outside this base-address contract. */
struct osrec_lifetime_slot { const void *address; uint32_t id,active; };
struct osrec_lifetime_event { uint32_t ordinal,id,kind; size_t size; };
struct osrec_object_lifetimes {
    struct osrec_lifetime_slot slots[OSREC_LIFETIME_SLOTS];
    struct osrec_lifetime_event events[OSREC_LIFETIME_EVENTS];
    uint32_t next_id,event_count,failed,sealed;
};
void osrec_lifetime_init(struct osrec_object_lifetimes *);
void osrec_lifetime_seal(struct osrec_object_lifetimes *);
uint32_t osrec_lifetime_observe(struct osrec_object_lifetimes *,const void *);
uint32_t osrec_lifetime_allocate(struct osrec_object_lifetimes *,const void *,size_t);
int osrec_lifetime_release(struct osrec_object_lifetimes *,const void *);
uint32_t osrec_lifetime_identity(struct osrec_object_lifetimes *,const void *);
/* Annotate once while the captured objects are live, under the same exclusion
 * as the snapshot. Do not postpone this operation until report serialization. */
int osrec_snapshot_lifetimes(struct osrec_entry_snapshot *,struct osrec_object_lifetimes *,int observe_existing);
#endif
