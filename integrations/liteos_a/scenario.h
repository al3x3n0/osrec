#ifndef OSREC_LITEOS_A_SCENARIO_H
#define OSREC_LITEOS_A_SCENARIO_H
#include <stdint.h>
#include <stddef.h>
#include "seed_config.h"

enum {
    OSREC_EINTR = 4,
    OSREC_EIO = 5,
    OSREC_EBADF = 9,
    OSREC_EFAULT = 14
};

struct user_request {
    uint32_t fd;
    uint32_t count;
    uint32_t null_buffer;
};
_Static_assert(sizeof(struct user_request) == 12, "KTest request layout");

struct user_outcome {
    int32_t result;
    uint32_t error;
    uint32_t recognized;
};

struct model_state {
    uint32_t mode;
    uint32_t range_calls;
    uint32_t fd_calls;
    uint32_t read_calls;
    uint32_t errno_calls;
    uint32_t success_limit;
    int32_t read_result;
    int32_t error;
    unsigned char payload[OSREC_PAYLOAD_BYTES];
};

extern unsigned char osrec_user_memory[OSREC_USER_MEMORY_BYTES];
extern struct model_state osrec_environment;
extern int32_t SysRead(int fd, void *buf, uint32_t nbytes);
void osrec_reset(uint32_t mode, const unsigned char *payload);
struct user_outcome osrec_application(struct user_request request);
void osrec_check(struct user_request request, struct user_outcome outcome);

#endif
