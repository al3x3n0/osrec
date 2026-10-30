#ifndef OSREC_ENTRY_SNAPSHOT_H
#define OSREC_ENTRY_SNAPSHOT_H
#include <stddef.h>
#include <stdint.h>
#define OSREC_SNAPSHOT_OBJECTS 32
#define OSREC_SNAPSHOT_FIELDS 128
#define OSREC_SNAPSHOT_ROOTS 16
#define OSREC_SNAPSHOT_VALUE_BYTES 16
/* Address table is transient capture state. Serialize only IDs/field bytes. */
struct osrec_snapshot_object { const void *address; const char *type; uint32_t id,session_id; };
struct osrec_snapshot_root { const char *name; uint32_t object_id; };
struct osrec_snapshot_field { const char *name; uint32_t object_id,target_id,size,is_edge; unsigned char bytes[OSREC_SNAPSHOT_VALUE_BYTES]; };
struct osrec_entry_snapshot {
    struct osrec_snapshot_object objects[OSREC_SNAPSHOT_OBJECTS];
    struct osrec_snapshot_root roots[OSREC_SNAPSHOT_ROOTS];
    struct osrec_snapshot_field fields[OSREC_SNAPSHOT_FIELDS];
    uint32_t object_count,root_count,field_count,failed,lifetime_cursor;
};
uint32_t osrec_snapshot_identity(struct osrec_entry_snapshot *,const void *address,const char *type);
void osrec_snapshot_init(struct osrec_entry_snapshot *snapshot);
int osrec_snapshot_bind(struct osrec_entry_snapshot *,const char *name,const void *address,const char *type);
int osrec_snapshot_edge(struct osrec_entry_snapshot *,const void *owner,const char *field,const void *target,const char *type);
int osrec_snapshot_scalar(struct osrec_entry_snapshot *,const void *owner,const char *field,const void *value,size_t bytes);
#endif
