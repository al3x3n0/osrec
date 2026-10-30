#ifndef OSREC_CHECKPOINT_H
#define OSREC_CHECKPOINT_H
#include <stddef.h>
#include <stdint.h>

/* Caller-owned object table. Register live, disjoint allocations while their
 * contents and lifetimes are stable. This API maps references; it neither
 * freezes writers nor discovers pointers or copies arbitrary kernel memory.
 * ID zero denotes null. Every error invalidates the table until reinitialized.
 */
struct osrec_object {
    uint64_t id;
    uint32_t schema;
    void *base;
    size_t size;
};
struct osrec_object_table {
    struct osrec_object *objects;
    size_t capacity;
    size_t count;
    int failed;
};
struct osrec_object_ref {
    uint64_t object;
    uint64_t offset;
};

int osrec_objects_init(struct osrec_object_table *table,
                       struct osrec_object *storage, size_t capacity);
int osrec_object_add(struct osrec_object_table *table, uint64_t id,
                      uint32_t schema, void *base, size_t size);
int osrec_object_reference(struct osrec_object_table *table, const void *pointer,
                           size_t extent, uint32_t schema, struct osrec_object_ref *reference);
int osrec_object_resolve(struct osrec_object_table *table, struct osrec_object_ref reference,
                         size_t extent, uint32_t schema, void **pointer);
#endif
