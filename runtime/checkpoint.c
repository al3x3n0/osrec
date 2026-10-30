#include "osrec/checkpoint.h"

static int invalid(struct osrec_object_table *table)
{
    if (table) table->failed = 1;
    return 0;
}

int osrec_objects_init(struct osrec_object_table *table,
                       struct osrec_object *storage, size_t capacity)
{
    if (!table) return 0;
    table->objects = storage;
    table->capacity = capacity;
    table->count = 0;
    table->failed = !storage || !capacity;
    return !table->failed;
}

int osrec_object_add(struct osrec_object_table *table, uint64_t id,
                      uint32_t schema, void *base, size_t size)
{
    if (!table || table->failed) return 0;
    uintptr_t start = (uintptr_t)base;
    if (!id || !schema || !base || !size || size > UINTPTR_MAX - start ||
        table->count == table->capacity) return invalid(table);
    for (size_t i = 0; i < table->count; ++i) {
        const struct osrec_object *object = &table->objects[i];
        uintptr_t previous = (uintptr_t)object->base;
        if (object->id == id || (start < previous + object->size && previous < start + size))
            return invalid(table);
    }
    table->objects[table->count++] = (struct osrec_object){id, schema, base, size};
    return 1;
}

int osrec_object_reference(struct osrec_object_table *table, const void *pointer,
                           size_t extent, uint32_t schema, struct osrec_object_ref *reference)
{
    if (!table || table->failed) return 0;
    if (!reference || !schema || !extent) return invalid(table);
    if (!pointer) {
        *reference = (struct osrec_object_ref){0, 0};
        return 1;
    }
    uintptr_t address = (uintptr_t)pointer;
    for (size_t i = 0; i < table->count; ++i) {
        const struct osrec_object *object = &table->objects[i];
        uintptr_t base = (uintptr_t)object->base;
        if (address >= base && address - base < object->size) {
            size_t offset = (size_t)(address - base);
            if (object->schema != schema || extent > object->size - offset)
                return invalid(table);
            *reference = (struct osrec_object_ref){object->id, offset};
            return 1;
        }
    }
    return invalid(table);
}

int osrec_object_resolve(struct osrec_object_table *table, struct osrec_object_ref reference,
                         size_t extent, uint32_t schema, void **pointer)
{
    if (!table || table->failed) return 0;
    if (!pointer || !schema || !extent) return invalid(table);
    if (!reference.object) {
        if (reference.offset) return invalid(table);
        *pointer = NULL;
        return 1;
    }
    for (size_t i = 0; i < table->count; ++i) {
        const struct osrec_object *object = &table->objects[i];
        if (object->id == reference.object) {
            if (object->schema != schema || reference.offset >= object->size ||
                extent > object->size - reference.offset) return invalid(table);
            *pointer = (unsigned char *)object->base + (size_t)reference.offset;
            return 1;
        }
    }
    return invalid(table);
}
