#include "osrec/context.h"

static int fail(struct osrec_context_session *s)
{
    s->trace->failed = 1;
    return -1;
}

static int valid(struct osrec_context_session *s, unsigned cpu)
{
    if (s->trace->failed || s->trace->finished || s->returned || cpu >= s->cpu_count) {
        return fail(s);
    }
    return 0;
}

static uint64_t context(const struct osrec_context_session *s, unsigned cpu)
{
    unsigned depth = s->depths[cpu];
    return depth ? s->irqs[cpu][depth - 1] : s->tasks[cpu];
}

static int emit(struct osrec_context_session *s, unsigned cpu, uint32_t site,
                 enum osrec_context_kind kind, uint64_t a, uint64_t b)
{
    unsigned depth = s->depths[cpu];
    uint64_t parent = depth > 1 ? s->irqs[cpu][depth - 2] :
                      depth ? s->tasks[cpu] : 0;
    if (!site || s->sequence == UINT64_MAX) {
        return fail(s);
    }
    uint64_t fields[8] = {s->sequence, cpu, context(s, cpu), parent,
                          s->tasks[cpu], kind, a, b};
    if (osrec_values(s->trace, OSREC_CONTEXT, site, fields, 8)) {
        return -1;
    }
    ++s->sequence;
    return 0;
}

int osrec_context_init(struct osrec_context_session *s,
                       struct osrec_buffer *trace, unsigned cpu_count,
                       const uint64_t *tasks, uint64_t selected)
{
    *s = (struct osrec_context_session){0};
    s->trace = trace;
    if (trace->failed || trace->finished || cpu_count == 0 ||
        cpu_count > OSREC_MAX_CPUS || !tasks || !selected || selected >= OSREC_IRQ_ID_BASE) {
        return fail(s);
    }
    unsigned found = 0;
    for (unsigned i = 0; i < cpu_count; ++i) {
        if (!tasks[i] || tasks[i] >= OSREC_IRQ_ID_BASE) {
            return fail(s);
        }
        for (unsigned j = 0; j < i; ++j) {
            if (tasks[i] == tasks[j]) {
                return fail(s);
            }
        }
        s->tasks[i] = tasks[i];
        found += tasks[i] == selected;
    }
    if (found != 1) {
        return fail(s);
    }
    s->cpu_count = cpu_count;
    s->selected_task = selected;
    s->next_irq = OSREC_IRQ_ID_BASE;
    uint64_t config[2 + OSREC_MAX_CPUS] = {cpu_count, selected};
    for (unsigned i = 0; i < cpu_count; ++i) {
        config[i + 2] = tasks[i];
    }
    return osrec_values(trace, OSREC_INPUT, 100, config, 2 + cpu_count);
}

int osrec_task_block(struct osrec_context_session *s, unsigned cpu,
                     uint32_t site, uint64_t object, uint64_t generation)
{
    if (valid(s, cpu) || s->depths[cpu] || s->tasks[cpu] != s->selected_task ||
        s->blocked || !object || !generation) {
        return fail(s);
    }
    if (emit(s, cpu, site, OSREC_TASK_BLOCK, object, generation)) {
        return -1;
    }
    s->blocked = 1;
    s->wait_object = object;
    s->wait_generation = generation;
    return 0;
}

int osrec_task_switch(struct osrec_context_session *s, unsigned cpu,
                      uint32_t site, uint64_t previous, uint64_t next)
{
    if (valid(s, cpu) || s->depths[cpu] || previous != s->tasks[cpu] ||
        !next || next >= OSREC_IRQ_ID_BASE || previous == next ||
        (next == s->selected_task && s->blocked)) {
        return fail(s);
    }
    for (unsigned i = 0; i < s->cpu_count; ++i) {
        if (i != cpu && s->tasks[i] == next) {
            return fail(s);
        }
    }
    if (emit(s, cpu, site, OSREC_TASK_SWITCH, previous, next)) {
        return -1;
    }
    s->tasks[cpu] = next;
    return 0;
}

uint64_t osrec_irq_enter(struct osrec_context_session *s, unsigned cpu,
                         uint32_t site)
{
    if (valid(s, cpu) || s->depths[cpu] == OSREC_MAX_IRQ_DEPTH ||
        s->next_irq == UINT64_MAX) {
        fail(s);
        return 0;
    }
    uint64_t id = s->next_irq++;
    s->irqs[cpu][s->depths[cpu]++] = id;
    if (emit(s, cpu, site, OSREC_IRQ_ENTER, 0, 0)) {
        return 0;
    }
    return id;
}

int osrec_irq_exit(struct osrec_context_session *s, unsigned cpu,
                   uint32_t site, uint64_t irq)
{
    if (valid(s, cpu) || !s->depths[cpu] || context(s, cpu) != irq) {
        return fail(s);
    }
    if (emit(s, cpu, site, OSREC_IRQ_EXIT, 0, 0)) {
        return -1;
    }
    --s->depths[cpu];
    return 0;
}

int osrec_context_value(struct osrec_context_session *s, unsigned cpu,
                        uint32_t site, enum osrec_context_kind kind,
                        uint64_t object, uint64_t value)
{
    if (valid(s, cpu) || !object ||
        (kind != OSREC_DEVICE_VALUE && kind != OSREC_MEMORY_EFFECT)) {
        return fail(s);
    }
    return emit(s, cpu, site, kind, object, value);
}

int osrec_task_wake(struct osrec_context_session *s, unsigned cpu,
                    uint32_t site, uint64_t object, uint64_t generation)
{
    if (valid(s, cpu) || !s->blocked || object != s->wait_object ||
        generation != s->wait_generation) {
        return fail(s);
    }
    if (emit(s, cpu, site, OSREC_TASK_WAKE, object, generation)) {
        return -1;
    }
    s->blocked = 0;
    return 0;
}

int osrec_task_return(struct osrec_context_session *s, unsigned cpu,
                      uint32_t site, uint64_t result)
{
    if (valid(s, cpu) || s->blocked || s->tasks[cpu] != s->selected_task ||
        s->depths[cpu]) {
        return fail(s);
    }
    for (unsigned i = 0; i < s->cpu_count; ++i) {
        if (s->depths[i]) {
            return fail(s);
        }
    }
    if (emit(s, cpu, site, OSREC_TASK_RETURN, result, 0)) {
        return -1;
    }
    s->returned = 1;
    return 0;
}

int osrec_context_finish(struct osrec_context_session *s)
{
    if (!s->returned || s->blocked) {
        return fail(s);
    }
    return osrec_finish(s->trace);
}
