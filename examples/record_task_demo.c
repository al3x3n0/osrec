#include "osrec/context.h"
#include "task_region.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int number(const char *text, uint64_t *out)
{
    if (!*text) {
        return -1;
    }
    for (const char *p = text; *p; ++p) {
        if (*p < '0' || *p > '9') {
            return -1;
        }
    }
    char *end;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || *end || value > UINT64_MAX) {
        return -1;
    }
    *out = (uint64_t)value;
    return 0;
}

#define RECORD(call) do { if ((call) != 0) { \
    fputs("task capture invalid\n", stderr); return 1; } } while (0)

int main(int argc, char **argv)
{
    int single_cpu = argc == 7 && strcmp(argv[6], "--single-cpu") == 0;
    if (argc != 6 && !single_cpu) {
        fputs("usage: record_task_demo TRACE AVAILABLE DEMAND OUTER_IRQ NESTED_IRQ [--single-cpu]\n", stderr);
        return 2;
    }
    uint64_t args[4];
    for (int i = 0; i < 4; ++i) {
        if (number(argv[i + 2], &args[i])) {
            fputs("invalid unsigned value\n", stderr);
            return 2;
        }
    }
    struct completion_state state = {args[0]};
    uint64_t result = 0;
    if (task_step(&state, args[1], &result)) {
        fputs("this scenario requires a blocking first task step\n", stderr);
        return 2;
    }
    struct completion_state check = state;
    complete_irq(&check, args[3]);
    if (check.available >= args[1]) {
        fputs("this scenario requires wakeup by the outer IRQ\n", stderr);
        return 2;
    }
    complete_irq(&check, args[2]);
    if (check.available < args[1]) {
        fputs("interrupt inputs do not satisfy the blocked request\n", stderr);
        return 2;
    }

    unsigned char storage[4096];
    struct osrec_buffer trace;
    RECORD(osrec_begin(&trace, storage, sizeof(storage), OSREC_TASK_BUILD_ID));
    const uint64_t tasks[2] = {101, 103};
    struct osrec_context_session s;
    RECORD(osrec_context_init(&s, &trace, single_cpu ? 1 : 2, tasks, 101));
    RECORD(osrec_values(&trace, OSREC_INPUT, 110, args, 2));
    RECORD(osrec_task_block(&s, 0, 200, 1, 1));
    RECORD(osrec_task_switch(&s, 0, 210, 101, 102));
    uint64_t outer = osrec_irq_enter(&s, 0, 220);
    if (!outer) {
        return 1;
    }
    RECORD(osrec_context_value(&s, 0, 230, OSREC_DEVICE_VALUE, 9, args[2]));
    uint64_t nested = osrec_irq_enter(&s, 0, 240);
    if (!nested) {
        return 1;
    }
    RECORD(osrec_context_value(&s, 0, 250, OSREC_DEVICE_VALUE, 10, args[3]));
    complete_irq(&state, args[3]);
    RECORD(osrec_context_value(&s, 0, 260, OSREC_MEMORY_EFFECT, 1, state.available));
    RECORD(osrec_irq_exit(&s, 0, 270, nested));
    complete_irq(&state, args[2]);
    RECORD(osrec_context_value(&s, 0, 280, OSREC_MEMORY_EFFECT, 1, state.available));
    RECORD(osrec_task_wake(&s, 0, 290, 1, 1));
    RECORD(osrec_irq_exit(&s, 0, 300, outer));
    unsigned resume_cpu = single_cpu ? 0 : 1;
    RECORD(osrec_task_switch(&s, resume_cpu, 310, single_cpu ? 102 : 103, 101));
    if (!task_step(&state, args[1], &result)) {
        fputs("task did not resume successfully\n", stderr);
        return 1;
    }
    RECORD(osrec_task_return(&s, resume_cpu, 320, result));
    const uint64_t outputs[2] = {state.available, result};
    RECORD(osrec_values(&trace, OSREC_OUTPUT, 330, outputs, 2));
    RECORD(osrec_context_finish(&s));

    FILE *file = fopen(argv[1], "wb");
    if (!file) {
        perror("trace");
        return 1;
    }
    int ok = fwrite(storage, 1, trace.used, file) == trace.used;
    if (fclose(file)) {
        ok = 0;
    }
    if (!ok) {
        return 1;
    }
    printf("task capture: %zu bytes, %llu events, CPU 0 -> CPU %u\n",
           trace.used, (unsigned long long)s.sequence, resume_cpu);
    return 0;
}
