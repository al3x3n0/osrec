#include "osrec/recorder.h"

static void put32(unsigned char *out, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) {
        out[i] = (unsigned char)(value >> (i * 8));
    }
}

/* Reserve a complete record before writing. Sticky failure prevents exporting
 * an apparently valid prefix after an overflow. No allocation or I/O here.
 */
static unsigned char *reserve(struct osrec_buffer *b, uint32_t kind,
                              uint32_t site, size_t size)
{
    if (b->failed || b->finished) {
        b->failed = 1;
        return NULL;
    }
    if (size > UINT32_MAX || b->used > b->capacity ||
        b->capacity - b->used < 12 || size > b->capacity - b->used - 12) {
        b->failed = 1;
        return NULL;
    }
    unsigned char *record = b->data + b->used;
    put32(record, kind);
    put32(record + 4, site);
    put32(record + 8, (uint32_t)size);
    b->used += 12 + size;
    return record + 12;
}

int osrec_append(struct osrec_buffer *b, uint32_t kind, uint32_t site,
                 const void *payload, size_t size)
{
    if (size && !payload) {
        b->failed = 1;
        return -1;
    }
    unsigned char *out = reserve(b, kind, site, size);
    if (!out) {
        return -1;
    }
    const unsigned char *in = payload;
    for (size_t i = 0; i < size; ++i) {
        out[i] = in[i];
    }
    return 0;
}

int osrec_values(struct osrec_buffer *b, uint32_t kind, uint32_t site,
                 const uint64_t *values, size_t count)
{
    if (count > UINT32_MAX / 8 || (count && !values)) {
        b->failed = 1;
        return -1;
    }
    unsigned char *out = reserve(b, kind, site, count * 8);
    if (!out) {
        return -1;
    }
    for (size_t i = 0; i < count; ++i) {
        for (unsigned j = 0; j < 8; ++j) {
            out[i * 8 + j] = (unsigned char)(values[i] >> (j * 8));
        }
    }
    return 0;
}

int osrec_begin(struct osrec_buffer *b, void *storage, size_t capacity,
                const char source_sha256[64])
{
    b->data = storage;
    b->capacity = capacity;
    b->used = 0;
    b->failed = 0;
    b->finished = 0;
    if (!storage || !source_sha256 || capacity < 8) {
        b->failed = 1;
        return -1;
    }
    const unsigned char header[8] = {'O', 'S', 'R', 'C', 1, 0, 0, 0};
    for (size_t i = 0; i < sizeof(header); ++i) {
        b->data[i] = header[i];
    }
    b->used = sizeof(header);
    return osrec_append(b, OSREC_BEGIN, 0, source_sha256, 64);
}

int osrec_finish(struct osrec_buffer *b)
{
    if (osrec_append(b, OSREC_END, 0, NULL, 0)) {
        return -1;
    }
    b->finished = 1;
    return 0;
}
