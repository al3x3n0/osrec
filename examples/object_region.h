#ifndef OSREC_OBJECT_REGION_H
#define OSREC_OBJECT_REGION_H
#include <stdint.h>

/* Portable, exclusively owned completion model; not LiteOS-A scheduler code.
 * A typed checkpoint restores these fields rather than native struct bytes.
 */
struct completion_object {
    uint32_t credits;
    struct completion_object *next;
};
struct task_object {
    struct completion_object *wait;
    struct completion_object *alias;
    uint8_t *cursor;
    uint8_t *view;
};

static inline uint32_t object_scenario(struct task_object *task, uint32_t demand)
{
    /* The replay contract supplies two live completion objects and an 8-byte
     * buffer. These checks observe restored aliases and the cyclic link. */
    if (!task->wait || !task->wait->next || task->alias != task->wait ||
        task->wait->next->next != task->wait || task->view != task->cursor + 2)
        return UINT32_MAX;
    uint32_t first = demand < task->wait->credits ? demand : task->wait->credits;
    task->wait->credits -= first;
    uint32_t left = demand - first;
    uint32_t second = left < task->wait->next->credits ? left : task->wait->next->credits;
    task->wait->next->credits -= second;
    uint32_t granted = first + second;
    task->cursor[0] = (uint8_t)granted;
    task->view[0] = (uint8_t)task->alias->credits;
    return granted;
}
#endif
