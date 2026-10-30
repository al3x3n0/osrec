/* Bounded, relational trace sufficiency check and transcript-driven replay. */
#include "scenario.h"

#ifdef OSREC_KLEE
#include <klee/klee.h>
#ifndef OSREC_TRACE_MASK
#error "compile with a candidate trace mask"
#endif
#else
#include <stdio.h>
#include <stdlib.h>
#endif

#define TRACE_READ_RESULT 1U
#define TRACE_ERRNO 2U
#define TRACE_PAYLOAD 60U

struct environment_input {
    uint32_t mode;
    uint32_t success_limit;
    unsigned char payload[OSREC_PAYLOAD_BYTES];
};
_Static_assert(sizeof(struct environment_input) == 12, "KTest environment layout");

struct snapshot {
    struct user_outcome out;
    unsigned char memory[OSREC_USER_MEMORY_BYTES];
    uint32_t range_calls, fd_calls, read_calls, errno_calls;
    int32_t read_result, error;
    uint32_t written;
};

/* Presence is part of a selected observation's encoding. Omitted values and
 * presence bits are zeroed; replay cannot consult the original environment.
 */
struct observation_trace {
    uint32_t mask, read_present, errno_present, payload_present;
    int32_t read_result, error;
    unsigned char payload[OSREC_PAYLOAD_BYTES];
};

static struct snapshot execute(struct user_request request, struct environment_input env)
{
    osrec_reset(env.mode, env.payload);
    osrec_environment.success_limit = env.success_limit;
    struct snapshot out = {0};
    out.out = osrec_application(request);
    osrec_check(request, out.out);
    for (unsigned i = 0; i < OSREC_USER_MEMORY_BYTES; ++i)
        out.memory[i] = osrec_user_memory[i];
    out.range_calls = osrec_environment.range_calls;
    out.fd_calls = osrec_environment.fd_calls;
    out.read_calls = osrec_environment.read_calls;
    out.errno_calls = osrec_environment.errno_calls;
    out.read_result = osrec_environment.read_result;
    out.error = osrec_environment.error;
    out.written = out.read_calls && out.read_result > 0 ? (uint32_t)out.read_result : 0;
    return out;
}

static struct observation_trace capture(struct snapshot run, uint32_t mask)
{
    struct observation_trace trace = {0};
    trace.mask = mask;
    if ((mask & TRACE_READ_RESULT) && run.read_calls) {
        trace.read_present = 1;
        trace.read_result = run.read_result;
    }
    if ((mask & TRACE_ERRNO) && run.errno_calls) {
        trace.errno_present = 1;
        trace.error = run.error;
    }
    for (unsigned i = 0; i < OSREC_PAYLOAD_BYTES; ++i)
        if ((mask & (4U << i)) && i < run.written) {
            trace.payload_present |= 1U << i;
            trace.payload[i] = run.memory[i];
        }
    return trace;
}

static int same_trace(struct observation_trace a, struct observation_trace b)
{
    int equal = (a.mask == b.mask) & (a.read_present == b.read_present) &
        (a.read_result == b.read_result) & (a.errno_present == b.errno_present) &
        (a.error == b.error) & (a.payload_present == b.payload_present);
    for (unsigned i = 0; i < OSREC_PAYLOAD_BYTES; ++i)
        equal &= a.payload[i] == b.payload[i];
    return equal;
}

static int same_contract(struct snapshot a, struct snapshot b)
{
    int equal = (a.out.result == b.out.result) & (a.out.error == b.out.error) &
        (a.out.recognized == b.out.recognized) & (a.range_calls == b.range_calls) &
        (a.fd_calls == b.fd_calls) & (a.read_calls == b.read_calls) &
        (a.errno_calls == b.errno_calls);
    for (unsigned i = 0; i < OSREC_USER_MEMORY_BYTES; ++i)
        equal &= a.memory[i] == b.memory[i];
    return equal;
}

/* Reconstruct a representative modeled environment from the checkpoint and
 * retained boundary observations, then execute the original syscall again.
 * This decoder supports the full plan and the discovered reduced plan.
 */
#if !defined(OSREC_KLEE) || defined(OSREC_TRACE_REPLAY_CHECK)
static int replay(struct user_request request, struct observation_trace trace,
                  struct snapshot *out)
{
    struct environment_input env = {0};
    env.success_limit = OSREC_PAYLOAD_BYTES;
    uint32_t backend = request.count && !request.null_buffer &&
                       request.count <= OSREC_USER_MEMORY_BYTES;
    if (backend && request.fd == OSREC_USER_FD) {
        if (trace.errno_present) {
            if (trace.error == OSREC_EINTR) env.mode = 1;
            else if (trace.error == OSREC_EIO) env.mode = 2;
            else return 0;
        } else if (trace.read_present && trace.read_result < 0) {
            return 0; /* Negative return alone does not reconstruct errno. */
        } else if (!trace.read_present && !(trace.mask & TRACE_ERRNO)) {
            return 0;
        }
        uint32_t written = 0;
        if (!env.mode) {
            if (trace.read_present) {
                if (trace.read_result < 0 || trace.read_result > (int32_t)OSREC_PAYLOAD_BYTES)
                    return 0;
                written = (uint32_t)trace.read_result;
            } else {
                if ((trace.mask & TRACE_PAYLOAD) != TRACE_PAYLOAD) return 0;
                while (written < OSREC_PAYLOAD_BYTES &&
                       (trace.payload_present & (1U << written))) ++written;
            }
            if (written > request.count) return 0;
        }
        for (unsigned i = 0; i < OSREC_PAYLOAD_BYTES; ++i) {
            if (i < written) {
                if (!(trace.payload_present & (1U << i))) return 0;
                env.payload[i] = trace.payload[i];
            } else if (trace.payload_present & (1U << i)) return 0;
        }
        env.success_limit = written;
    }
    *out = execute(request, env);
    return same_trace(trace, capture(*out, trace.mask));
}
#endif

#ifdef OSREC_KLEE
static void symbolic_environment(struct environment_input *env, const char *name)
{
    klee_make_symbolic(env, sizeof(*env), name);
    klee_assume(env->mode <= 2);
    klee_assume(env->success_limit <= OSREC_PAYLOAD_BYTES);
}

int main(void)
{
    struct user_request request;
    struct environment_input env_a;
    klee_make_symbolic(&request, sizeof(request), "user_request");
    klee_assume(request.fd <= OSREC_FD_MAX);
    klee_assume(request.count <= OSREC_COUNT_MAX);
    klee_assume(request.null_buffer <= 1);
    symbolic_environment(&env_a, "environment_a");
    struct snapshot a = execute(request, env_a);
    struct observation_trace trace_a = capture(a, OSREC_TRACE_MASK);
#ifdef OSREC_TRACE_REPLAY_CHECK
    struct snapshot reconstructed;
    if (!replay(request, trace_a, &reconstructed) || !same_contract(a, reconstructed))
        klee_report_error(__FILE__, __LINE__, "retained trace cannot drive replay", "replay.err");
#else
    struct environment_input env_b;
    symbolic_environment(&env_b, "environment_b");
    struct snapshot b = execute(request, env_b);
    struct observation_trace trace_b = capture(b, OSREC_TRACE_MASK);
    /* Unequal traces finish normally: no discarded search paths are counted as
     * partial exploration. Only equal traces can demonstrate insufficiency.
     */
    if (same_trace(trace_a, trace_b) && !same_contract(a, b))
        klee_report_error(__FILE__, __LINE__, "same trace, different slice contract", "trace.err");
#endif
    return 0;
}
#else
static int number(const char *text, uint32_t max, uint32_t *out)
{
    if (!*text) return 0;
    for (const char *p = text; *p; ++p)
        if (*p < '0' || *p > '9') return 0;
    char *end;
    unsigned long value = strtoul(text, &end, 10);
    if (*end || value > max) return 0;
    *out = (uint32_t)value;
    return 1;
}

static int hex_digit(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static int parse_environment(char **args, struct environment_input *env)
{
    if (!number(args[0], 2, &env->mode) ||
        !number(args[1], OSREC_PAYLOAD_BYTES, &env->success_limit)) return 0;
    const char *hex = args[2];
    for (unsigned i = 0; i < OSREC_PAYLOAD_BYTES; ++i) {
        if (!hex[0] || !hex[1]) return 0;
        int high = hex_digit(hex[0]), low = hex_digit(hex[1]);
        if (high < 0 || low < 0) return 0;
        env->payload[i] = (unsigned char)((high << 4) | low);
        hex += 2;
    }
    return !*hex;
}

static void print_hex(const unsigned char *bytes, unsigned size)
{
    putchar('"');
    for (unsigned i = 0; i < size; ++i) printf("%02x", bytes[i]);
    putchar('"');
}

static void print_snapshot(struct snapshot s)
{
    printf("{\"return\":%d,\"errno\":%u,\"recognized\":%u,\"memory\":",
           s.out.result, s.out.error, s.out.recognized);
    print_hex(s.memory, OSREC_USER_MEMORY_BYTES);
    printf(",\"boundary_counts\":[%u,%u,%u,%u]}",
           s.range_calls, s.fd_calls, s.read_calls, s.errno_calls);
}

static void print_trace(struct observation_trace t)
{
    printf("{\"mask\":%u,\"read_present\":%u,\"read_result\":%d,"
           "\"errno_present\":%u,\"errno\":%d,\"payload_present\":%u,\"payload\":",
           t.mask, t.read_present, t.read_result, t.errno_present, t.error, t.payload_present);
    print_hex(t.payload, OSREC_PAYLOAD_BYTES);
    putchar('}');
}

int main(int argc, char **argv)
{
    uint32_t mask;
    struct user_request request;
    struct environment_input env_a, env_b;
    if (argc != 11 || !number(argv[1], 63, &mask) ||
        !number(argv[2], OSREC_FD_MAX, &request.fd) ||
        !number(argv[3], OSREC_COUNT_MAX, &request.count) ||
        !number(argv[4], 1, &request.null_buffer) ||
        !parse_environment(argv + 5, &env_a) || !parse_environment(argv + 8, &env_b)) return 2;
    struct snapshot a = execute(request, env_a), b = execute(request, env_b), reconstructed;
    struct observation_trace ta = capture(a, mask), tb = capture(b, mask);
    int supported = replay(request, ta, &reconstructed);
    printf("{\"trace_equal\":%s,\"contract_equal\":%s,\"replay_supported\":%s,\"replay_equal\":%s,\"left\":",
           same_trace(ta, tb) ? "true" : "false", same_contract(a, b) ? "true" : "false",
           supported ? "true" : "false", supported && same_contract(a, reconstructed) ? "true" : "false");
    print_snapshot(a);
    printf(",\"right\":"); print_snapshot(b);
    printf(",\"left_trace\":"); print_trace(ta);
    printf(",\"right_trace\":"); print_trace(tb);
    puts("}");
    return 0;
}
#endif
