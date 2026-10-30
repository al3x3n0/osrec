#include "scenario.h"

unsigned char osrec_user_memory[OSREC_USER_MEMORY_BYTES];
struct model_state osrec_environment;

void osrec_reset(uint32_t mode, const unsigned char *payload)
{
    osrec_environment = (struct model_state){0};
    osrec_environment.mode = mode;
    osrec_environment.success_limit = OSREC_PAYLOAD_BYTES;
    for (unsigned i = 0; i < OSREC_PAYLOAD_BYTES; ++i)
        osrec_environment.payload[i] = payload[i];
    for (unsigned i = 0; i < OSREC_USER_MEMORY_BYTES; ++i)
        osrec_user_memory[i] = 0xa5;
}

/* A single registered user range, with host-normalized addresses. This is an
 * explicit abstraction, not LiteOS-A's MMU or full virtual-address predicate.
 */
int osrec_user_address_range(uintptr_t address, uint32_t size)
{
    ++osrec_environment.range_calls;
    uintptr_t base = (uintptr_t)osrec_user_memory;
    if (address < base || address - base > OSREC_USER_MEMORY_BYTES)
        return 0;
    return size <= OSREC_USER_MEMORY_BYTES - (address - base);
}

/* Snapshot abstraction of one process descriptor mapping. */
int osrec_associated_fd(int fd)
{
    ++osrec_environment.fd_calls;
    return fd == OSREC_USER_FD ? OSREC_SYSTEM_FD : -1;
}

/* Explicit VFS/device model: finite data, EBADF, EINTR or EIO. It does not
 * execute the kernel's VFS, wait queue, scheduler, driver or hardware.
 */
int osrec_vfs_read(int fd, void *buf, uint32_t size)
{
    ++osrec_environment.read_calls;
    if (fd != OSREC_SYSTEM_FD) {
        osrec_environment.error = OSREC_EBADF;
        osrec_environment.read_result = -1;
        return -1;
    }
    if (osrec_environment.mode) {
        osrec_environment.error = osrec_environment.mode == 1 ? OSREC_EINTR : OSREC_EIO;
        osrec_environment.read_result = -1;
        return -1;
    }
    uint32_t count = size < osrec_environment.success_limit ? size : osrec_environment.success_limit;
    unsigned char *output = buf;
    for (uint32_t i = 0; i < count; ++i)
        output[i] = osrec_environment.payload[i];
    osrec_environment.read_result = (int32_t)count;
    return (int)count;
}

int osrec_get_errno(void)
{
    ++osrec_environment.errno_calls;
    return osrec_environment.error;
}
