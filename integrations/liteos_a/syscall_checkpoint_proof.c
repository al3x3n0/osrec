#include "syscall_checkpoint.h"
#ifdef OSREC_KLEE
#include <klee/klee.h>
#else
#include <stdio.h>
#include <string.h>
#endif

struct proof_input {
    uint32_t position, user_errno, kernel_errno;
    unsigned char memory[8];
    int32_t result[2];
    uint32_t errors[2];
    unsigned char payload[2][2];
};
_Static_assert(sizeof(struct proof_input) == 40, "proof KTest layout");
struct proof_snapshot {
    struct session_result out;
    unsigned char memory[8];
    uint32_t position, kernel_errno, user_errno;
};

static int execute(struct proof_input input, const struct proof_snapshot *recorded,
                   struct proof_snapshot output[2])
{
    unsigned char memory[8];
    for (unsigned i = 0; i < 8; ++i) memory[i] = input.memory[i];
    struct session_file file = {17, input.position};
    struct session_process process = {memory, 8, &file, &file, input.kernel_errno, input.user_errno};
    struct osrec_object objects[3]; struct osrec_object_table table;
    if (!osrec_objects_init(&table, objects, 3) || !osrec_object_add(&table, 10, SESSION_BUFFER, memory, 8) ||
        !osrec_object_add(&table, 20, SESSION_FILE, &file, sizeof(file)) ||
        !osrec_object_add(&table, 30, SESSION_PROCESS, &process, sizeof(process))) return 0;
    for (unsigned i = 0; i < 2; ++i) {
        struct session_call call = {3+i, i ? 2 : 4, {10, i ? 4 : 2}};
        struct session_read_input env = {input.result[i], input.result[i] < 0 ? 4+input.errors[i] : 0,
                                       input.result[i] > 0 ? (uint32_t)input.result[i] : 0, {0}};
        env.payload[0] = input.payload[i][0]; env.payload[1] = input.payload[i][1];
        output[i].out = osrec_session_run(&process, &table, call, recorded ? NULL : &env,
            recorded ? recorded[i].out.events : NULL, recorded ? recorded[i].out.event_count : 0);
        if (output[i].out.failed) return 0;
        for (unsigned j = 0; j < 8; ++j) output[i].memory[j] = memory[j];
        output[i].position = file.position; output[i].kernel_errno = process.kernel_errno; output[i].user_errno = process.user_errno;
    }
    return 1;
}

static int check(struct proof_input input)
{
    struct proof_snapshot reference[2], replay[2];
    if (!execute(input, NULL, reference) || !execute(input, reference, replay)) return 0;
    int equal = 1;
    for (unsigned i = 0; i < 2; ++i) {
        struct session_result a = reference[i].out, b = replay[i].out;
        equal &= (a.raw == b.raw) & (a.result == b.result) & (a.error == b.error) &
                 (a.recognized == b.recognized) & (a.event_count == b.event_count) &
                 (reference[i].position == replay[i].position) &
                 (reference[i].kernel_errno == replay[i].kernel_errno) & (reference[i].user_errno == replay[i].user_errno);
        for (unsigned j = 0; j < 8; ++j) equal &= reference[i].memory[j] == replay[i].memory[j];
        for (unsigned j = 0; j < SESSION_EVENTS; ++j) equal &= osrec_session_same_event(a.events[j], b.events[j]);
    }
    return equal;
}

#ifdef OSREC_KLEE
int main(void)
{
    struct proof_input input;
    klee_make_symbolic(&input, sizeof(input), "checkpoint_and_inputs");
    klee_assume(input.user_errno <= 4095); klee_assume(input.kernel_errno <= 4095);
    for (unsigned i = 0; i < 2; ++i) {
        klee_assume(input.result[i] >= -1); klee_assume(input.result[i] <= 2); klee_assume(input.errors[i] <= 1);
    }
    if (!check(input)) klee_report_error(__FILE__, __LINE__, "syscall checkpoint replay differs", "checkpoint.err");
    return 0;
}
#else
static int digit(char value)
{
    return value >= '0' && value <= '9' ? value-'0' : value >= 'a' && value <= 'f' ? value-'a'+10 : -1;
}
int main(int argc, char **argv)
{
    struct proof_input input = {0};
    if (argc != 2 || strlen(argv[1]) != sizeof(input)*2) return 2;
    for (unsigned i = 0; i < sizeof(input); ++i) {
        int high = digit(argv[1][i*2]), low = digit(argv[1][i*2+1]);
        if (high < 0 || low < 0) return 2;
        ((unsigned char *)&input)[i] = (unsigned char)(high*16+low);
    }
    if (input.user_errno > 4095 || input.kernel_errno > 4095) return 2;
    for (unsigned i = 0; i < 2; ++i)
        if (input.result[i] < -1 || input.result[i] > 2 || input.errors[i] > 1) return 2;
    if (!check(input)) return 1;
    puts("syscall checkpoint proof case verified");
    return 0;
}
#endif
