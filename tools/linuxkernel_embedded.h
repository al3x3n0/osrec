#ifndef LK_EMBEDDED_CHECKPOINT_H
#define LK_EMBEDDED_CHECKPOINT_H
#include "osrec/linuxkernel_el0_native.h"
struct checkpoint_expected_event { uint64_t exception,number,arguments[6],result,completed; };
struct checkpoint_bundle {
    struct lk_el0_image image;
    const struct checkpoint_expected_event *expected;
    uint64_t event_count,stop_pc,stop_reason;
    struct lk_el0_blob provenance;
    const char *identity;
};
extern const struct checkpoint_bundle osrec_checkpoint;
#endif
