/* Publish a file-backed record through a shared mapping and seal it. */
#include <stdint.h>
#include "syscall.h"

enum {
    SYS_DUP = 23, SYS_FCNTL = 25, SYS_FTRUNCATE = 46, SYS_CLOSE = 57,
    SYS_LSEEK = 62, SYS_WRITE = 64, SYS_PREAD64 = 67, SYS_PWRITE64 = 68,
    SYS_MUNMAP = 215, SYS_MMAP = 222, SYS_MPROTECT = 226, SYS_MEMFD_CREATE = 279,
    MFD_CLOEXEC = 1, MFD_ALLOW_SEALING = 2, MAP_SHARED = 1,
    PROT_READ = 1, PROT_WRITE = 2, SEEK_SET = 0, SEEK_CUR = 1,
    F_ADD_SEALS = 1033, F_GET_SEALS = 1034, F_SEAL_WRITE = 8,
    EPERM = 1, EBADF = 9, EFAULT = 14,
    FILE_BYTES = 8192, RECORD_OFFSET = 4093,
};

static long call(long nr, long a, long b, long c)
{
    return syscall6(nr, a, b, c, 0, 0, 0);
}

static long read_at(long fd, volatile void *buffer, long bytes)
{
    return syscall6(SYS_PREAD64, fd, (long)buffer, bytes, RECORD_OFFSET, 0, 0);
}

static long write_at(long fd, const void *buffer, long bytes)
{
    return syscall6(SYS_PWRITE64, fd, (long)buffer, bytes, RECORD_OFFSET, 0, 0);
}

static int matches(const volatile char *actual, const char *expected, unsigned bytes)
{
    for (unsigned i = 0; i < bytes; i++)
        if (actual[i] != expected[i])
            return 0;
    return 1;
}

int program_main(void)
{
    static const char initial[] = "queue:01";
    static const char updated[] = "queue:42";
    static const char message[] = "OSREC_FILE_HANDOFF_PASS\n";
    enum { RECORD_BYTES = sizeof initial - 1 };
    char readback[RECORD_BYTES];

    long writer = call(SYS_MEMFD_CREATE, (long)"job-record", MFD_CLOEXEC | MFD_ALLOW_SEALING, 0);
    if (writer < 0 || call(SYS_FTRUNCATE, writer, FILE_BYTES, 0))
        return 10;
    if (write_at(writer, initial, RECORD_BYTES) != RECORD_BYTES)
        return 11;
    long reader = call(SYS_DUP, writer, 0, 0);
    if (reader < 0 || call(SYS_LSEEK, writer, 23, SEEK_SET) != 23 ||
        call(SYS_LSEEK, reader, 0, SEEK_CUR) != 23)
        return 12;

    long address = syscall6(SYS_MMAP, 0, FILE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, writer, 0);
    if (address < 0)
        return 13;
    volatile char *mapping = (void *)(uintptr_t)address;
    volatile char *record = mapping + RECORD_OFFSET;
    if (call(SYS_CLOSE, writer, 0, 0) || !matches(record, initial, RECORD_BYTES) ||
        read_at(writer, readback, RECORD_BYTES) != -EBADF)
        return 14;

    record[7] = '2';
    if (read_at(reader, readback, RECORD_BYTES) != RECORD_BYTES ||
        !matches(readback, "queue:02", RECORD_BYTES) || call(SYS_LSEEK, reader, 0, SEEK_CUR) != 23)
        return 15;
    if (write_at(reader, updated, RECORD_BYTES) != RECORD_BYTES || !matches(record, updated, RECORD_BYTES))
        return 16;
    if (call(SYS_MPROTECT, address, FILE_BYTES, PROT_READ) || read_at(reader, mapping, RECORD_BYTES) != -EFAULT)
        return 17;

    if (call(SYS_MUNMAP, address, FILE_BYTES, 0) || call(SYS_FCNTL, reader, F_ADD_SEALS, F_SEAL_WRITE) ||
        call(SYS_FCNTL, reader, F_GET_SEALS, 0) != F_SEAL_WRITE)
        return 18;
    if (write_at(reader, initial, RECORD_BYTES) != -EPERM ||
        read_at(reader, readback, RECORD_BYTES) != RECORD_BYTES || !matches(readback, updated, RECORD_BYTES))
        return 19;
    if (call(SYS_CLOSE, reader, 0, 0))
        return 20;
    return call(SYS_WRITE, 1, (long)message, sizeof message - 1) == sizeof message - 1 ? 0 : 21;
}
