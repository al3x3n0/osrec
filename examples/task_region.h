#ifndef OSREC_TASK_REGION_H
#define OSREC_TASK_REGION_H
#include <stdint.h>

/* Portable task/completion model, NOT OHOS kernel code. A real kernel adapter
 * must establish ownership, ordering and atomic semantics separately.
 */
struct completion_state {
    uint64_t available;
};

static inline void complete_irq(struct completion_state *state, uint64_t input)
{
    state->available = input > UINT64_MAX - state->available ?
                       UINT64_MAX : state->available + input;
}

/* Models a task continuation at a supported wait boundary. */
static inline int task_step(struct completion_state *state, uint64_t demand,
                            uint64_t *result)
{
    if (state->available < demand) {
        return 0;
    }
    state->available -= demand;
    *result = demand;
    return 1;
}
#endif
