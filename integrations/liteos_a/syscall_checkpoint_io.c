#include "syscall_checkpoint.h"
#include <inttypes.h>
#include <stdio.h>

void osrec_session_print_result(struct session_result out)
{
    printf("{\"raw\":%" PRId32 ",\"return\":%" PRId32 ",\"errno\":%" PRIu32 ",\"recognized\":%" PRIu32 ",\"events\":[",
           out.raw, out.result, out.error, out.recognized);
    for (unsigned i = 0; i < out.event_count; ++i) {
        struct session_event event = out.events[i];
        if (i) putchar(',');
        printf("{\"kind\":%" PRIu32 ",\"fd\":%" PRId32 ",\"count\":%" PRIu32
               ",\"buffer\":{\"object\":%" PRIu64 ",\"offset\":%" PRIu64 "},\"result\":%" PRId32
               ",\"errno\":%" PRIu32 ",\"position_before\":%" PRIu32 ",\"position_after\":%" PRIu32 ",\"payload\":\"",
               event.kind, event.fd, event.count, event.buffer.object, event.buffer.offset,
               event.result, event.error, event.position_before, event.position_after);
        for (unsigned j = 0; j < event.size; ++j) printf("%02x", event.payload[j]);
        fputs("\"}", stdout);
    }
    fputs("]}", stdout);
}
