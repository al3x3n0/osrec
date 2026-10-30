#ifndef OSREC_UNAME_MODEL_H
#define OSREC_UNAME_MODEL_H
#include <stdint.h>
#include <stddef.h>
struct utsname {char sysname[65],nodename[65],release[65],version[65],machine[65],domainname[65];};
_Static_assert(sizeof(struct utsname)==390 && offsetof(struct utsname,domainname)==325,"captured OHOS uname ABI");
#define EFAULT 14
int uname(struct utsname *);
size_t LOS_ArchCopyFromUser(void *,const void *,size_t);
size_t LOS_ArchCopyToUser(void *,const void *,size_t);
int SysUname(struct utsname *);
#endif
