#ifndef OSREC_FLAT_IMAGE_H
#define OSREC_FLAT_IMAGE_H
#include "flat.h"
#include "memory.h"
struct flat_image {
    struct flat_memory memory;
    struct osrec_shadow *shadow;
    struct flat_frame initial;
    uint64_t task_slot,entry,regs;
};
extern struct flat_image flat_image;
struct flat_result {
    uint64_t magic,version,status,calls,gateway_checks,transitions,reason,pc,detail,far;
    uint64_t initial_mask,final_mask,fault_checks,reserved[3];
    struct {uint64_t input,returned,mask,pc;} call[6];
};
extern volatile struct flat_result flat_result;
#endif
