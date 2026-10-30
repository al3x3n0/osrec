#ifndef OSREC_ENTRY_CAPTURE_H
#define OSREC_ENTRY_CAPTURE_H
#include "osrec/entry_snapshot.h"
#ifndef OSREC_CAPTURE_CALLS
#define OSREC_CAPTURE_CALLS 7
#endif
#if OSREC_CAPTURE_CALLS < 1 || OSREC_CAPTURE_CALLS > 256
#error "entry capture capacity must be between 1 and 256"
#endif
#define OSREC_CAPTURE_ARGUMENTS 16
struct osrec_capture_argument { const char *name; unsigned char bytes[4]; };
struct osrec_capture_call {
    const char *root;
    uint32_t number,raw_bits,argument_count;
    struct osrec_capture_argument arguments[OSREC_CAPTURE_ARGUMENTS];
    struct osrec_entry_snapshot entry,post;
};
/* Caller-owned storage; keep large sessions off a kernel stack. One owner,
 * fixed object lifetimes and caller-provided synchronization are required. */
struct osrec_capture_session {
    struct osrec_entry_snapshot identities;
    struct osrec_capture_call calls[OSREC_CAPTURE_CALLS];
    uint32_t count,active,failed;
};
void osrec_capture_init(struct osrec_capture_session *);
struct osrec_capture_call *osrec_capture_begin(struct osrec_capture_session *,const char *root,uint32_t number);
int osrec_capture_argument(struct osrec_capture_session *,struct osrec_capture_call *,const char *name,const void *value,size_t bytes);
void osrec_capture_end(struct osrec_capture_session *,struct osrec_capture_call *,uint32_t raw_bits);
typedef int (*osrec_capture_write)(void *context,const char *data,size_t bytes);
/* No address bytes or host I/O. A transport adapter owns buffering/output.
 * Do not capture into or reset the session during serialization. */
int osrec_capture_json(const struct osrec_capture_session *,const char *plan_sha256,const char *spec_sha256,
                       osrec_capture_write,void *context);
#endif
