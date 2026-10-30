#ifndef OSREC_CONTEXT_H
#define OSREC_CONTEXT_H

#include "osrec/recorder.h"

#define OSREC_MAX_CPUS 4
#define OSREC_MAX_IRQ_DEPTH 4
#define OSREC_IRQ_ID_BASE (UINT64_C(1) << 63)

enum osrec_context_kind {
    OSREC_TASK_BLOCK = 1,
    OSREC_TASK_SWITCH = 2,
    OSREC_IRQ_ENTER = 3,
    OSREC_IRQ_EXIT = 4,
    OSREC_DEVICE_VALUE = 5,
    OSREC_MEMORY_EFFECT = 6,
    OSREC_TASK_WAKE = 7,
    OSREC_TASK_RETURN = 8
};

/* Host protocol model. All calls MUST be externally serialized, including
 * bookkeeping and writes. This is NOT a kernel IRQ/SMP-safe logger. Tasks use
 * nonzero IDs below OSREC_IRQ_ID_BASE; IDs include lifetime generation.
 */
struct osrec_context_session {
    struct osrec_buffer *trace;
    uint64_t tasks[OSREC_MAX_CPUS];
    uint64_t irqs[OSREC_MAX_CPUS][OSREC_MAX_IRQ_DEPTH];
    unsigned depths[OSREC_MAX_CPUS];
    unsigned cpu_count;
    uint64_t selected_task;
    uint64_t sequence;
    uint64_t next_irq;
    uint64_t wait_object;
    uint64_t wait_generation;
    int blocked;
    int returned;
};

int osrec_context_init(struct osrec_context_session *session,
                       struct osrec_buffer *trace, unsigned cpu_count,
                       const uint64_t *current_tasks, uint64_t selected_task);
int osrec_task_block(struct osrec_context_session *s, unsigned cpu,
                     uint32_t site, uint64_t object, uint64_t generation);
int osrec_task_switch(struct osrec_context_session *s, unsigned cpu,
                      uint32_t site, uint64_t previous, uint64_t next);
uint64_t osrec_irq_enter(struct osrec_context_session *s, unsigned cpu,
                         uint32_t site);
int osrec_irq_exit(struct osrec_context_session *s, unsigned cpu,
                   uint32_t site, uint64_t irq);
int osrec_context_value(struct osrec_context_session *s, unsigned cpu,
                        uint32_t site, enum osrec_context_kind kind,
                        uint64_t object, uint64_t value);
int osrec_task_wake(struct osrec_context_session *s, unsigned cpu,
                    uint32_t site, uint64_t object, uint64_t generation);
int osrec_task_return(struct osrec_context_session *s, unsigned cpu,
                      uint32_t site, uint64_t result);
int osrec_context_finish(struct osrec_context_session *s);

#endif
