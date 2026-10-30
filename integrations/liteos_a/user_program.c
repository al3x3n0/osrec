#include "scenario.h"

#ifdef OSREC_KLEE
#include <klee/klee.h>
#else
#include <stdio.h>
#include <stdlib.h>
#endif

static void require(int condition, const char *message)
{
    if (condition)
        return;
#ifdef OSREC_KLEE
    klee_report_error(__FILE__, __LINE__, message, "postcondition.err");
#else
    fprintf(stderr, "scenario failed: %s\n", message);
    abort();
#endif
}

/* A user-side read/errno adapter and application. Direct C dispatch substitutes
 * for SVC/assembly entry; this is not the target's musl syscall wrapper.
 */
struct user_outcome osrec_application(struct user_request request)
{
    void *buffer = request.null_buffer ? NULL : osrec_user_memory;
    int32_t raw = SysRead((int)request.fd, buffer, request.count);
    struct user_outcome out = {raw, 0, 0};
    if (raw < 0) {
        out.result = -1;
        out.error = (uint32_t)-raw;
    } else if (raw > 0) {
        out.recognized = osrec_user_memory[0] == 'A';
    }
    return out;
}

void osrec_check(struct user_request request, struct user_outcome out)
{
    uint32_t error = 0;
    uint32_t count = 0;
    if (request.count != 0) {
        if (request.null_buffer || request.count > OSREC_USER_MEMORY_BYTES)
            error = OSREC_EFAULT;
        else if (request.fd != OSREC_USER_FD)
            error = OSREC_EBADF;
        else if (osrec_environment.mode)
            error = osrec_environment.mode == 1 ? OSREC_EINTR : OSREC_EIO;
        else
            count = request.count < osrec_environment.success_limit ? request.count : osrec_environment.success_limit;
    }
    require(out.result == (error ? -1 : (int32_t)count), "user return value");
    require(out.error == error, "user errno translation");
    require(out.recognized == (count ? osrec_environment.payload[0] == 'A' : 0),
            "application processes returned bytes only");
    for (unsigned i = 0; i < OSREC_USER_MEMORY_BYTES; ++i)
        require(osrec_user_memory[i] == (i < count ? osrec_environment.payload[i] : 0xa5),
                "user memory effects and untouched suffix");
    require(osrec_environment.range_calls == (request.count ? 1U : 0U),
            "zero-length syscall bypasses address check");
    uint32_t backend = request.count && !request.null_buffer &&
                       request.count <= OSREC_USER_MEMORY_BYTES;
    require(osrec_environment.fd_calls == backend, "descriptor mapping boundary");
    require(osrec_environment.read_calls == backend, "VFS boundary");
    require(osrec_environment.errno_calls == (backend && error ? 1U : 0U),
            "errno boundary on backend failure only");
}

#ifndef OSREC_NO_SCENARIO_MAIN
#ifdef OSREC_KLEE
int main(void)
{
    struct user_request request;
    unsigned char payload[OSREC_PAYLOAD_BYTES] = OSREC_SEED_PAYLOAD;
    uint32_t mode = OSREC_SEED_MODE;
    klee_make_symbolic(&request, sizeof(request), "user_request");
    klee_assume(request.fd <= OSREC_FD_MAX);
    klee_assume(request.count <= OSREC_COUNT_MAX);
    klee_assume(request.null_buffer <= 1);
#ifdef OSREC_EXPLORE_ENVIRONMENT
    klee_make_symbolic(&mode, sizeof(mode), "environment_mode");
    klee_assume(mode <= 2);
    klee_make_symbolic(payload, sizeof(payload), "device_payload");
#endif
    osrec_reset(mode, payload);
    struct user_outcome outcome = osrec_application(request);
    osrec_check(request, outcome);
    return 0;
}
#else
static int argument(const char *text, uint32_t maximum, uint32_t *out)
{
    if (!*text)
        return -1;
    for (const char *p = text; *p; ++p)
        if (*p < '0' || *p > '9')
            return -1;
    char *end;
    unsigned long value = strtoul(text, &end, 10);
    if (*end || value > maximum)
        return -1;
    *out = (uint32_t)value;
    return 0;
}

static int hex_digit(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

int main(int argc, char **argv)
{
    unsigned char payload[OSREC_PAYLOAD_BYTES] = OSREC_SEED_PAYLOAD;
    if (argc == 6) {
        struct user_request request;
        uint32_t mode;
        if (argument(argv[1], OSREC_FD_MAX, &request.fd) ||
            argument(argv[2], OSREC_COUNT_MAX, &request.count) ||
            argument(argv[3], 1, &request.null_buffer) ||
            argument(argv[4], 2, &mode) || sizeof(payload) != 4) return 2;
        const char *hex = argv[5];
        for (unsigned i = 0; i < sizeof(payload); ++i) {
            if (!hex[0] || !hex[1]) return 2;
            int high = hex_digit(hex[0]), low = hex_digit(hex[1]);
            if (high < 0 || low < 0) return 2;
            payload[i] = (unsigned char)((high << 4) | low);
            hex += 2;
        }
        if (*hex) return 2;
        osrec_reset(mode, payload);
        struct user_outcome out = osrec_application(request);
        osrec_check(request, out);
        printf("return=%d errno=%u recognized=%u\n", out.result, out.error, out.recognized);
        return 0;
    }
    if (argc != 1) return 2;
    unsigned cases = 0;
    for (uint32_t fd = 0; fd <= OSREC_FD_MAX; ++fd)
        for (uint32_t count = 0; count <= OSREC_COUNT_MAX; ++count)
            for (uint32_t null = 0; null <= 1; ++null)
                for (uint32_t mode = 0; mode <= 2; ++mode) {
                    struct user_request request = {fd, count, null};
                    osrec_reset(mode, payload);
                    osrec_check(request, osrec_application(request));
                    ++cases;
                }
    printf("native combined scenario: %u cases verified\n", cases);
    return 0;
}
#endif
#endif /* OSREC_NO_SCENARIO_MAIN */
