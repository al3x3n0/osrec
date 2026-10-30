#include "osrec/checkpoint.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

int main(void)
{
    unsigned char original[8] = {0}, restored[8] = {0}, outside[2] = {0};
    struct osrec_object storage[2];
    struct osrec_object_table table;
    struct osrec_object_ref first, alias, null;
    void *pointer = outside;
    assert(osrec_objects_init(&table, storage, 2));
    assert(osrec_object_add(&table, 71, 2, original, sizeof(original)));
    assert(osrec_object_reference(&table, original + 3, 5, 2, &first));
    assert(osrec_object_reference(&table, original + 3, 1, 2, &alias));
    assert(first.object == 71 && first.offset == 3);
    assert(alias.object == first.object && alias.offset == first.offset);
    assert(osrec_object_reference(&table, NULL, 1, 2, &null));
    assert(null.object == 0 && null.offset == 0);
    assert(osrec_objects_init(&table, storage, 2));
    assert(osrec_object_add(&table, 71, 2, restored, sizeof(restored)));
    assert(osrec_object_resolve(&table, first, 5, 2, &pointer));
    assert(pointer == restored + 3 && pointer != original + 3);
    assert(osrec_object_resolve(&table, null, 1, 2, &pointer) && pointer == NULL);

    assert(!osrec_object_resolve(&table, first, 6, 2, &pointer));
    assert(table.failed && !osrec_object_resolve(&table, first, 1, 2, &pointer));
    assert(osrec_objects_init(&table, storage, 2));
    assert(osrec_object_add(&table, 71, 2, original, sizeof(original)));
    assert(!osrec_object_reference(&table, outside, 1, 2, &first));
    assert(osrec_objects_init(&table, storage, 2));
    assert(osrec_object_add(&table, 71, 2, original, sizeof(original)));
    assert(!osrec_object_reference(&table, original, 1, 3, &first));
    assert(osrec_objects_init(&table, storage, 2));
    assert(osrec_object_add(&table, 71, 2, original, sizeof(original)));
    assert(!osrec_object_add(&table, 72, 2, original + 2, 2));
    assert(osrec_objects_init(&table, storage, 2));
    assert(osrec_object_add(&table, 71, 2, original, sizeof(original)));
    assert(!osrec_object_add(&table, 71, 2, restored, sizeof(restored)));
    assert(osrec_objects_init(&table, storage, 2));
    assert(!osrec_object_resolve(&table, (struct osrec_object_ref){0, 1}, 1, 2, &pointer));
    assert(osrec_objects_init(&table, storage, 2));
    assert(!osrec_object_resolve(&table, (struct osrec_object_ref){99, 0}, 1, 2, &pointer));
    assert(osrec_objects_init(&table, storage, 1));
    assert(osrec_object_add(&table, 71, 2, original, sizeof(original)));
    assert(!osrec_object_add(&table, 72, 2, restored, sizeof(restored)));
    assert(!osrec_objects_init(&table, NULL, 1));
    return 0;
}
