/* Buffered nonblocking IPC through raw Linux AArch64 syscalls. */
#include <stdint.h>
#include "syscall.h"

enum {
    SYS_EVENTFD2 = 19,
    SYS_CLOSE = 57,
    SYS_PIPE2 = 59,
    SYS_READ = 63,
    SYS_WRITE = 64,
    SYS_READV = 65,
    SYS_WRITEV = 66,
    NONBLOCK = 0x800,
    CLOEXEC = 0x80000,
    AGAIN = 11,
    INVALID = 22,
};

struct iovec {
    const void *base;
    unsigned long bytes;
};

static long call(long nr, long a, long b, long c)
{
    return syscall6(nr, a, b, c, 0, 0, 0);
}

static int check_pipe(void)
{
    int fds[2];
    char first[2], second[4];
    const struct iovec output[] = {{"PI", 2}, {"PE42", 4}};
    const struct iovec input[] = {{first, sizeof first}, {second, sizeof second}};

    if (call(SYS_PIPE2, (long)fds, NONBLOCK | CLOEXEC, 0))
        return 10;
    if (call(SYS_READ, fds[0], (long)first, sizeof first) != -AGAIN)
        return 11;
    if (call(SYS_WRITEV, fds[1], (long)output, 2) != 6)
        return 12;
    if (call(SYS_CLOSE, fds[1], 0, 0))
        return 13;
    if (call(SYS_READV, fds[0], (long)input, 2) != 6)
        return 14;
    if (first[0] != 'P' || first[1] != 'I' || second[0] != 'P' ||
        second[1] != 'E' || second[2] != '4' || second[3] != '2')
        return 15;
    if (call(SYS_READ, fds[0], (long)first, sizeof first) || call(SYS_CLOSE, fds[0], 0, 0))
        return 16;
    return 0;
}

static int check_eventfd(void)
{
    long fd = call(SYS_EVENTFD2, 2, NONBLOCK | CLOEXEC, 0);
    uint64_t increment = 5;
    uint64_t value;

    if (fd < 0)
        return 20;
    if (call(SYS_READ, fd, (long)&value, 4) != -INVALID)
        return 21;
    if (call(SYS_WRITE, fd, (long)&increment, sizeof increment) != sizeof increment)
        return 22;
    if (call(SYS_READ, fd, (long)&value, sizeof value) != sizeof value || value != 7)
        return 23;
    if (call(SYS_READ, fd, (long)&value, sizeof value) != -AGAIN)
        return 24;
    if (call(SYS_CLOSE, fd, 0, 0))
        return 25;
    return 0;
}

static unsigned iterations(long argc, char **argv)
{
    if (argc == 1)
        return 1;
    if (argc != 2 || !*argv[1])
        return 0;
    unsigned count = 0;
    for (const char *digit = argv[1]; *digit; digit++) {
        if (*digit < '0' || *digit > '9')
            return 0;
        count = count * 10 + (unsigned)(*digit - '0');
        if (count > 4096)
            return 0;
    }
    return count;
}

int program_main(long argc, char **argv)
{
    unsigned count = iterations(argc, argv);
    if (!count)
        return 31;
    for (unsigned i = 0; i < count; i++) {
        int result = check_pipe();
        if (result)
            return result;
        result = check_eventfd();
        if (result)
            return result;
    }
    static const char message[] = "OSREC_IPC_PASS\n";
    return call(SYS_WRITE, 1, (long)message, sizeof message - 1) == sizeof message - 1 ? 0 : 30;
}
