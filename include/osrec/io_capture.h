#ifndef OSREC_IO_CAPTURE_H
#define OSREC_IO_CAPTURE_H
#include "osrec/recorder.h"
#include "osrec/checkpoint.h"

#define OSREC_READ_SITE UINT32_C(0x535244)
#define OSREC_READ_BYTES 64U
/* Call after the backend read completes, with a stable accessible view of
 * exactly its returned bytes. Caller supplies normalized pointer identity,
 * invocation number and saved errno (zero on success). Caller owns safe user
 * copying, coherent entry state, writer exclusion and transport to the host.
 * Begin/finish use the existing recorder; begin binds an offline context hash.
 * Any failed hook invalidates the capture. No allocation, logging or I/O here.
 */
int osrec_record_read(struct osrec_buffer *buffer, uint64_t invocation,
                      int32_t backend_fd, uint32_t requested,
                      struct osrec_object_ref destination,
                      int32_t result, uint32_t error, const void *returned_bytes);
#endif
