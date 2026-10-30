#ifndef OSREC_RLIMIT_MODEL_H
#define OSREC_RLIMIT_MODEL_H
#include <stdint.h>
#include <stddef.h>
typedef unsigned long long rlim_t;
struct rlimit { rlim_t rlim_cur,rlim_max; };
_Static_assert(sizeof(struct rlimit)==16 && sizeof(rlim_t)==8 && offsetof(struct rlimit,rlim_max)==8,"captured OHOS resource-limit ABI");
#define EFAULT 14
int getrlimit(int,struct rlimit *);
size_t LOS_ArchCopyToUser(void *,const void *,size_t);
int SysUgetrlimit(int,unsigned long long [2]);
#endif
