#ifndef OSREC_SLICE_CHECKPOINT_H
#define OSREC_SLICE_CHECKPOINT_H
#include "syscall_slice.h"
#define OSREC_SLICE_CHECKPOINT_ABI 1u
#define OSREC_SLICE_CHECKPOINT_HEADER_BYTES 64u
/* The codec owns field selection, pointer rebinding and quiescent-state checks.
 * Payloads are pinned to a construction identity, not arbitrary kernel dumps. */
struct osrec_slice_checkpoint_codec {
    uint32_t abi;
    unsigned char schema[32];
    size_t payload_bytes;
    const struct osrec_slice_adapter *adapter;
    uint32_t (*check)(const void *,uint64_t);
    void (*encode)(const void *,unsigned char *);
    uint32_t (*validate)(const unsigned char *,uint64_t);
    void (*decode)(void *,const unsigned char *);
};
extern const struct osrec_slice_checkpoint_codec osrec_kernel_checkpoint_codec;
uint32_t osrec_slice_checkpoint_save(const struct osrec_slice_session *,const struct osrec_slice_checkpoint_codec *,void *,size_t);
/* Failure leaves the session and state untouched. Success rebinds references
 * to the destination context, then installs the saved ordinal. */
uint32_t osrec_slice_checkpoint_load(struct osrec_slice_session *,const struct osrec_slice_checkpoint_codec *,const void *,size_t);
#endif
