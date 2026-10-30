#ifndef OSREC_RECORDER_H
#define OSREC_RECORDER_H

#include <stddef.h>
#include <stdint.h>

/* Caller-owned, single-writer buffer. No interrupt, migration or SMP safety.
 * Export only after finish succeeds. Any failure invalidates the whole capture.
 * Recorder hooks and their callees must be excluded from instrumentation.
 * Pass a valid buffer pointer to every API; begin requires a readable 64-byte
 * SHA256 string. Do not overlap storage with the buffer or input payloads.
 */
enum osrec_kind {
    OSREC_BEGIN = 1,
    OSREC_INPUT = 2,
    OSREC_EXTERNAL = 3,
    OSREC_OUTPUT = 4,
    OSREC_END = 5,
    OSREC_CONTEXT = 6
};

struct osrec_buffer {
    unsigned char *data;
    size_t capacity;
    size_t used;
    int failed;
    int finished;
};

int osrec_begin(struct osrec_buffer *buffer, void *storage, size_t capacity,
                const char source_sha256[64]);
int osrec_append(struct osrec_buffer *buffer, uint32_t kind, uint32_t site,
                 const void *payload, size_t size);
int osrec_values(struct osrec_buffer *buffer, uint32_t kind, uint32_t site,
                 const uint64_t *values, size_t count);
int osrec_finish(struct osrec_buffer *buffer);

#endif
