#include "osrec/recorder.h"
#include "region.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

struct clock_context {
    struct osrec_buffer *trace;
    uint64_t now;
};

static uint64_t recorded_clock(void *opaque)
{
    struct clock_context *context = opaque;
    osrec_values(context->trace, OSREC_EXTERNAL, 20, &context->now, 1);
    return context->now;
}

static int parse_u64(const char *text, uint64_t *out)
{
    char *end;
    errno = 0;
    if (!text[0]) {
        return -1;
    }
    for (const char *digit = text; *digit; ++digit) {
        if (*digit < '0' || *digit > '9') {
            return -1;
        }
    }
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || end == text || *end || value > UINT64_MAX) {
        return -1;
    }
    *out = (uint64_t)value;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr, "usage: record_demo TRACE CREDITS DEADLINE DEMAND NOW\n");
        return 2;
    }
    uint64_t values[4];
    for (int i = 0; i < 4; ++i) {
        if (parse_u64(argv[i + 2], &values[i])) {
            fprintf(stderr, "invalid unsigned value\n");
            return 2;
        }
    }
    unsigned char storage[512];
    struct osrec_buffer trace;
    if (osrec_begin(&trace, storage, sizeof(storage), OSREC_BUILD_ID)) {
        return 1;
    }
    struct budget state = {values[0], values[1]};
    osrec_values(&trace, OSREC_INPUT, 10, values, 3);
    struct clock_context context = {&trace, values[3]};
    uint64_t result = take_budget(&state, values[2], recorded_clock, &context);
    uint64_t outputs[2] = {state.credits, result};
    osrec_values(&trace, OSREC_OUTPUT, 30, outputs, 2);
    if (osrec_finish(&trace)) {
        fprintf(stderr, "capture incomplete\n");
        return 1;
    }
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
    printf("captured %zu bytes\n", trace.used);
    return 0;
}
