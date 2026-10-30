#ifndef OSREC_CLOCK_MODEL_H
#define OSREC_CLOCK_MODEL_H
#include <stdint.h>
#include <stddef.h>
typedef int32_t clockid_t;
struct timespec { int64_t tv_sec; int32_t tv_nsec; uint32_t padding; };
_Static_assert(sizeof(struct timespec)==16 && offsetof(struct timespec,tv_nsec)==8,"captured OHOS clock ABI");
#define EINVAL 22
#define EFAULT 14
extern int clock_errno;
#define errno clock_errno
int get_errno(void);
int clock_gettime(clockid_t,struct timespec *);
int clock_getres(clockid_t,struct timespec *);
size_t LOS_ArchCopyToUser(void *,const void *,size_t);
int SysClockGettime(clockid_t,struct timespec *);
int SysClockGetres(clockid_t,struct timespec *);
#endif
