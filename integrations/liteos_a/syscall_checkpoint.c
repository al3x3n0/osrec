#include "syscall_checkpoint.h"

struct execution {
    struct session_process *process;
    struct session_result *out;
    const struct session_read_input *input;
    const struct session_event *transcript;
    uint32_t transcript_count, cursor;
    struct osrec_object_ref buffer;
    void *pointer;
};
static struct execution active;

int osrec_session_same_event(struct session_event a, struct session_event b)
{
    int equal = (a.kind == b.kind) & (a.fd == b.fd) & (a.count == b.count) &
        (a.buffer.object == b.buffer.object) & (a.buffer.offset == b.buffer.offset) &
        (a.result == b.result) & (a.error == b.error) &
        (a.position_before == b.position_before) & (a.position_after == b.position_after) & (a.size == b.size);
    for (unsigned i = 0; i < SESSION_BYTES; ++i) equal &= a.payload[i] == b.payload[i];
    return equal;
}

static void emit(struct session_event event)
{
    if (active.out->event_count >= SESSION_EVENTS) { active.out->failed = 1; return; }
    active.out->events[active.out->event_count++] = event;
    if (!active.input) {
        if (active.cursor >= active.transcript_count ||
            !osrec_session_same_event(event, active.transcript[active.cursor])) active.out->failed = 1;
        else ++active.cursor;
    }
}

int osrec_user_address_range(uintptr_t address, uint32_t size)
{
    uintptr_t base = (uintptr_t)active.process->memory;
    int valid = address >= base && address - base <= active.process->memory_size &&
                size <= active.process->memory_size - (address - base);
    if (address != (uintptr_t)active.pointer) active.out->failed = 1;
    struct session_event event = {0};
    event.kind = SESSION_RANGE; event.count = size; event.buffer = active.buffer; event.result = valid;
    emit(event);
    return valid;
}

int osrec_associated_fd(int fd)
{
    struct session_file *file = fd == 3 ? active.process->fd3 : fd == 4 ? active.process->fd4 : NULL;
    int mapped = file ? (int)file->backend_fd : -1;
    struct session_event event = {0};
    event.kind = SESSION_FD; event.fd = fd; event.result = mapped;
    emit(event);
    return mapped;
}

int osrec_vfs_read(int fd, void *buffer, uint32_t count)
{
    struct session_file *file = NULL;
    if (active.process->fd3 && (int)active.process->fd3->backend_fd == fd) file = active.process->fd3;
    else if (active.process->fd4 && (int)active.process->fd4->backend_fd == fd) file = active.process->fd4;
    struct session_read_input input = {-1, 9, 0, {0}};
    if (file) {
        if (active.input) input = *active.input;
        else if (active.cursor < active.transcript_count && active.transcript[active.cursor].kind == SESSION_READ) {
            const struct session_event *record = &active.transcript[active.cursor];
            input.result = record->result; input.error = record->error; input.size = record->size;
            for (unsigned i = 0; i < SESSION_BYTES; ++i) input.payload[i] = record->payload[i];
        } else active.out->failed = 1;
    }
    if (buffer != active.pointer || input.result < -1 || input.result > (int32_t)count ||
        input.size > SESSION_BYTES || input.size != (input.result > 0 ? (uint32_t)input.result : 0) ||
        (input.result < 0 ? !input.error || input.error > 4095 : input.error != 0)) {
        active.out->failed = 1; input = (struct session_read_input){-1, 5, 0, {0}};
    }
    struct session_event event = {0};
    event.kind = SESSION_READ; event.fd = fd; event.count = count; event.buffer = active.buffer;
    event.result = input.result; event.error = input.error; event.size = input.size;
    if (file) event.position_before = file->position;
    if (input.result < 0) active.process->kernel_errno = input.error;
    else {
        for (unsigned i = 0; i < input.size; ++i) ((unsigned char *)buffer)[i] = input.payload[i];
        if (file) file->position += (uint32_t)input.result;
    }
    if (file) event.position_after = file->position;
    for (unsigned i = 0; i < input.size; ++i) event.payload[i] = input.payload[i];
    emit(event);
    return input.result;
}

int osrec_get_errno(void)
{
    struct session_event event = {0};
    event.kind = SESSION_ERRNO; event.result = (int32_t)active.process->kernel_errno;
    emit(event);
    return (int)active.process->kernel_errno;
}

struct session_result osrec_session_run(struct session_process *process,
    struct osrec_object_table *objects, struct session_call call,
    const struct session_read_input *read_input,
    const struct session_event *transcript, uint32_t transcript_count)
{
    struct session_result out = {0};
    active = (struct execution){process, &out, read_input, transcript, transcript_count, 0, call.buffer, NULL};
    if (!process || !objects || !process->memory || process->memory_size != SESSION_BYTES ||
        call.fd > 4 || call.count > 9 || transcript_count > SESSION_EVENTS ||
        (!read_input && transcript_count && !transcript)) { out.failed = 1; return out; }
    /* Request pointers may be one-past-end so the actual SysRead range check
     * can reproduce EFAULT. Never construct pointers outside an allocation. */
    struct osrec_object_ref base = call.buffer;
    uint32_t one_past = base.object && base.offset == process->memory_size;
    if (one_past) --base.offset;
    if (!osrec_object_resolve(objects, base, 1, SESSION_BUFFER, &active.pointer)) { out.failed = 1; return out; }
    if (one_past) active.pointer = (unsigned char *)active.pointer + 1;
    out.raw = SysRead((int)call.fd, active.pointer, call.count);
    out.result = out.raw < 0 ? -1 : out.raw;
    if (out.raw < 0) process->user_errno = (uint32_t)-out.raw;
    out.error = process->user_errno;
    if (out.raw > 0) out.recognized = ((unsigned char *)active.pointer)[0] == 'A';
    if (!read_input && active.cursor != transcript_count) out.failed = 1;
    return out;
}
