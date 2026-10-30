#include "osrec/io_capture.h"

int osrec_record_read(struct osrec_buffer *buffer, uint64_t invocation,
                      int32_t backend_fd, uint32_t requested,
                      struct osrec_object_ref destination,
                      int32_t result, uint32_t error, const void *returned_bytes)
{
    if (!buffer) return -1;
    if (result < -1 || result > (int64_t)requested || result > (int32_t)OSREC_READ_BYTES ||
        (result < 0 ? !error || error > 4095 : error != 0) ||
        (result > 0 && (!returned_bytes || !destination.object)) || (!destination.object && destination.offset)) {
        buffer->failed = 1;
        return -1;
    }
    unsigned char record[64 + OSREC_READ_BYTES];
    uint64_t values[8] = {invocation, (uint32_t)backend_fd, requested, destination.object,
                         destination.offset, (uint32_t)result, error, result > 0 ? (uint32_t)result : 0};
    for (unsigned i = 0; i < 8; ++i)
        for (unsigned j = 0; j < 8; ++j) record[i*8+j] = (unsigned char)(values[i] >> (j*8));
    unsigned size = result > 0 ? (unsigned)result : 0;
    for (unsigned i = 0; i < size; ++i) record[64+i] = ((const unsigned char *)returned_bytes)[i];
    return osrec_append(buffer, OSREC_EXTERNAL, OSREC_READ_SITE, record, 64+size);
}
