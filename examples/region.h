#ifndef OSREC_EXAMPLE_REGION_H
#define OSREC_EXAMPLE_REGION_H
#include <stdint.h>

struct budget {
    uint64_t credits;
    uint64_t deadline;
};

typedef uint64_t (*clock_read)(void *context);

/* A portable model of a kernel policy helper, not OpenHarmony source.
 * The clock is the only external dependency; state is exclusively owned.
 */
static inline uint64_t take_budget(struct budget *state, uint64_t demand,
                                   clock_read clock, void *context)
{
    if (clock(context) > state->deadline) {
        return 0;
    }
    uint64_t granted = demand < state->credits ? demand : state->credits;
    state->credits -= granted;
    return granted;
}
#endif
