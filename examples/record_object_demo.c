#include "object_region.h"
#include "osrec/checkpoint.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef OSREC_OBJECT_BUILD_ID
#error "object schema/source fingerprint required"
#endif

static int number(const char *text, uint32_t *value)
{
    char *end;
    if (!text[0] || text[0] == '-') return 0;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (*end || parsed > UINT32_MAX) return 0;
    *value = (uint32_t)parsed;
    return 1;
}

static void emit_reference(FILE *file, struct osrec_object_ref reference)
{
    fprintf(file, "{\"object\":%" PRIu64 ",\"offset\":%" PRIu64 "}", reference.object, reference.offset);
}

static void emit_bytes(FILE *file, const uint8_t *buffer, size_t size)
{
    fputc('"', file);
    for (size_t i = 0; i < size; ++i) fprintf(file, "%02x", buffer[i]);
    fputc('"', file);
}

int main(int argc, char **argv)
{
    uint32_t first = 5, second = 3, demand = 7;
    if (argc != 2 && argc != 5) return 2;
    if (argc == 5 && (!number(argv[2], &first) || !number(argv[3], &second) || !number(argv[4], &demand)))
        return 2;
    struct completion_object a = {first, NULL}, b = {second, &a};
    a.next = &b;
    uint8_t buffer[8] = {0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5};
    struct task_object task = {&a, &a, buffer + 2, buffer + 4};
    struct osrec_object storage[4];
    struct osrec_object_table table;
    struct osrec_object_ref refs[7];
    if (!osrec_objects_init(&table, storage, 4) ||
        !osrec_object_add(&table, 1, 1, &a, sizeof(a)) ||
        !osrec_object_add(&table, 2, 1, &b, sizeof(b)) ||
        !osrec_object_add(&table, 3, 2, buffer, sizeof(buffer)) ||
        !osrec_object_add(&table, 4, 3, &task, sizeof(task)) ||
        !osrec_object_reference(&table, a.next, sizeof(a), 1, &refs[0]) ||
        !osrec_object_reference(&table, b.next, sizeof(b), 1, &refs[1]) ||
        !osrec_object_reference(&table, task.wait, sizeof(a), 1, &refs[2]) ||
        !osrec_object_reference(&table, task.alias, sizeof(a), 1, &refs[3]) ||
        !osrec_object_reference(&table, task.cursor, 3, 2, &refs[4]) ||
        !osrec_object_reference(&table, task.view, 1, 2, &refs[5]) ||
        !osrec_object_reference(&table, &task, sizeof(task), 3, &refs[6])) return 1;

    /* No other writer exists in this fixture. Serialize at entry, before the
     * original computation changes credits or the buffer. */
    FILE *file = fopen(argv[1], "wb");
    if (!file) return 1;
    fprintf(file, "{\"format\":\"osrec-object-checkpoint-v1\",\"schema\":\"completion-demo-v1\","
                  "\"source_sha256\":\"%s\",\"boundary\":\"object_scenario entry\",\"demand\":%" PRIu32 ","
                  "\"roots\":{\"current_task\":", OSREC_OBJECT_BUILD_ID, demand);
    emit_reference(file, refs[6]);
    fprintf(file, "},\"objects\":[{\"id\":1,\"type\":\"completion\",\"fields\":{\"credits\":%" PRIu32 ",\"next\":", a.credits);
    emit_reference(file, refs[0]);
    fprintf(file, "}},{\"id\":2,\"type\":\"completion\",\"fields\":{\"credits\":%" PRIu32 ",\"next\":", b.credits);
    emit_reference(file, refs[1]);
    fputs("}},{\"id\":3,\"type\":\"bytes\",\"data\":", file);
    emit_bytes(file, buffer, sizeof(buffer));
    fputs("},{\"id\":4,\"type\":\"task\",\"fields\":{\"wait\":", file);
    emit_reference(file, refs[2]);
    fputs(",\"alias\":", file); emit_reference(file, refs[3]);
    fputs(",\"cursor\":", file); emit_reference(file, refs[4]);
    fputs(",\"view\":", file); emit_reference(file, refs[5]);
    fputs("}}],\"expected\":{", file);
    uint32_t result = object_scenario(&task, demand);
    fprintf(file, "\"return\":%" PRIu32 ",\"credits\":{\"1\":%" PRIu32 ",\"2\":%" PRIu32 "},\"buffers\":{\"3\":",
            result, a.credits, b.credits);
    emit_bytes(file, buffer, sizeof(buffer));
    fputs("}}}\n", file);
    int failed = ferror(file);
    if (fclose(file) || failed) return 1;
    printf("object checkpoint captured: return=%" PRIu32 "\n", result);
    return 0;
}
