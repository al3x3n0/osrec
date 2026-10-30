#ifndef OSREC_SYSCALL_CHECKPOINT_H
#define OSREC_SYSCALL_CHECKPOINT_H
#include <stdint.h>
#include "osrec/checkpoint.h"

/* Explicit host model state, not the binary layout of LiteOS-A kernel objects. */
enum { SESSION_BUFFER = 1, SESSION_FILE = 2, SESSION_PROCESS = 3,
       SESSION_RANGE = 1, SESSION_FD = 2, SESSION_READ = 3, SESSION_ERRNO = 4,
       SESSION_BYTES = 8, SESSION_EVENTS = 4 };
struct session_file { uint32_t backend_fd, position; };
struct session_process {
    unsigned char *memory;
    uint32_t memory_size;
    struct session_file *fd3, *fd4;
    uint32_t kernel_errno, user_errno;
};
struct session_call {
    uint32_t fd, count;
    struct osrec_object_ref buffer;
};
struct session_read_input {
    int32_t result;
    uint32_t error, size;
    unsigned char payload[SESSION_BYTES];
};
struct session_event {
    uint32_t kind;
    int32_t fd;
    uint32_t count;
    struct osrec_object_ref buffer;
    int32_t result;
    uint32_t error, position_before, position_after, size;
    unsigned char payload[SESSION_BYTES];
};
struct session_result {
    int32_t raw, result;
    uint32_t error, recognized, event_count, failed;
    struct session_event events[SESSION_EVENTS];
};
extern int32_t SysRead(int fd, void *buf, uint32_t count);
/* read_input != NULL captures a modeled execution. Otherwise only transcript
 * read observations supply external outcomes. Both paths execute the syscall,
 * address/descriptor models, file-position update and user errno adapter.
 * Calls are sequential; state/objects must remain exclusively owned and live.
 */
struct session_result osrec_session_run(struct session_process *process,
    struct osrec_object_table *objects, struct session_call call,
    const struct session_read_input *read_input,
    const struct session_event *transcript, uint32_t transcript_count);
int osrec_session_same_event(struct session_event a, struct session_event b);
void osrec_session_print_result(struct session_result result);
#endif
