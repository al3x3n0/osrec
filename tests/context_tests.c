#include "osrec/context.h"
#include <stdio.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #expr); \
    return 1; } } while (0)

static unsigned char storage[4096];
static struct osrec_buffer trace;
static struct osrec_context_session session;
static const char hash[65] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static int reset(size_t size)
{
    const uint64_t tasks[2] = {101, 103};
    if (osrec_begin(&trace, storage, size, hash)) {
        return -1;
    }
    return osrec_context_init(&session, &trace, 2, tasks, 101);
}

int main(void)
{
    CHECK(reset(sizeof(storage)) == 0);
    CHECK(osrec_task_block(&session, 0, 1, 1, 1) == 0);
    CHECK(osrec_task_switch(&session, 0, 2, 101, 102) == 0);
    uint64_t outer = osrec_irq_enter(&session, 0, 3);
    uint64_t nested = osrec_irq_enter(&session, 0, 4);
    CHECK(outer >= OSREC_IRQ_ID_BASE && nested == outer + 1);
    CHECK(osrec_context_value(&session, 0, 5, OSREC_DEVICE_VALUE, 9, 2) == 0);
    CHECK(osrec_irq_exit(&session, 0, 6, nested) == 0);
    CHECK(osrec_task_wake(&session, 0, 7, 1, 1) == 0);
    CHECK(osrec_irq_exit(&session, 0, 8, outer) == 0);
    CHECK(osrec_task_switch(&session, 1, 9, 103, 101) == 0);
    CHECK(osrec_task_return(&session, 1, 10, 7) == 0);
    CHECK(osrec_context_finish(&session) == 0);
    CHECK(trace.finished && !trace.failed);

    CHECK(reset(sizeof(storage)) == 0);
    CHECK(osrec_context_finish(&session) == -1); /* Selected task has not returned. */
    CHECK(trace.failed && !trace.finished);

    CHECK(reset(sizeof(storage)) == 0);
    CHECK(osrec_task_switch(&session, 1, 1, 103, 101) == -1); /* Already on CPU 0. */
    CHECK(trace.failed);

    CHECK(reset(sizeof(storage)) == 0);
    CHECK(osrec_task_block(&session, 0, 1, 1, 1) == 0);
    CHECK(osrec_task_switch(&session, 0, 2, 101, 102) == 0);
    CHECK(osrec_task_switch(&session, 1, 3, 103, 101) == -1); /* Still blocked. */

    CHECK(reset(sizeof(storage)) == 0);
    CHECK(osrec_task_block(&session, 0, 1, 1, 1) == 0);
    CHECK(osrec_task_wake(&session, 0, 2, 1, 2) == -1); /* Reused object generation. */
    CHECK(trace.failed);

    CHECK(reset(sizeof(storage)) == 0);
    outer = osrec_irq_enter(&session, 0, 1);
    nested = osrec_irq_enter(&session, 0, 2);
    CHECK(nested != 0);
    CHECK(osrec_irq_exit(&session, 0, 3, outer) == -1); /* Not the stack top. */

    CHECK(reset(sizeof(storage)) == 0);
    CHECK(osrec_irq_enter(&session, 0, 1) != 0);
    CHECK(osrec_task_switch(&session, 0, 2, 101, 102) == -1); /* Inside IRQ. */

    CHECK(reset(sizeof(storage)) == 0);
    CHECK(osrec_irq_enter(&session, 1, 1) != 0);
    CHECK(osrec_task_return(&session, 0, 2, 0) == -1); /* Unfinished dependency. */

    CHECK(reset(sizeof(storage)) == 0);
    for (unsigned i = 0; i < OSREC_MAX_IRQ_DEPTH; ++i) {
        CHECK(osrec_irq_enter(&session, 0, 1) != 0);
    }
    CHECK(osrec_irq_enter(&session, 0, 1) == 0);
    CHECK(trace.failed);

    CHECK(reset(sizeof(storage)) == 0);
    CHECK(osrec_irq_enter(&session, OSREC_MAX_CPUS, 1) == 0); /* Bounds. */
    CHECK(trace.failed);

    CHECK(reset(128 + 76) == 0); /* BEGIN + config + exactly one event. */
    CHECK(osrec_task_block(&session, 0, 1, 1, 1) == 0);
    CHECK(osrec_task_switch(&session, 0, 2, 101, 102) == -1);
    CHECK(trace.failed && !trace.finished);
    CHECK(osrec_context_finish(&session) == -1);

    const uint64_t duplicate_tasks[2] = {101, 101};
    CHECK(osrec_begin(&trace, storage, sizeof(storage), hash) == 0);
    CHECK(osrec_context_init(&session, &trace, 2, duplicate_tasks, 101) == -1);
    CHECK(trace.failed);
    const uint64_t absent_task[1] = {102};
    CHECK(osrec_begin(&trace, storage, sizeof(storage), hash) == 0);
    CHECK(osrec_context_init(&session, &trace, 1, absent_task, 101) == -1);
    CHECK(trace.failed);
    return 0;
}
