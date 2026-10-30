#ifndef OSREC_SETGROUPS_MODEL_H
#define OSREC_SETGROUPS_MODEL_H
#include <stdint.h>
#include <stddef.h>
typedef uint32_t UINT32;
typedef unsigned char UINT8;
typedef void VOID;
typedef struct { UINT32 userID,effUserID,gid,effGid,groupNumber,groups[1]; } User;
typedef struct { User *user; } LosProcessCB;
_Static_assert(sizeof(User)==24,"captured User scalar ABI");
#define LOSCFG_SECURITY_CAPABILITY 1
#define LOS_OK 0
#define OS_GROUPS_NUMBER_MAX 256
#define CAP_SETGID 6
#define ENOMEM 12
#define EFAULT 14
#define EINVAL 22
#define EPERM 1
#define SCHEDULER_LOCK(saved) OsrecSchedulerLock(&(saved))
#define SCHEDULER_UNLOCK(saved) OsrecSchedulerUnlock(saved)
extern UINT8 *m_aucSysMem1;
VOID *LOS_MemAlloc(VOID *,UINT32);
UINT32 LOS_MemFree(VOID *,VOID *);
int memcpy_s(void *,size_t,const void *,size_t);
int LOS_ArchCopyFromUser(void *,const void *,size_t);
int IsCapPermit(unsigned);
User *OsCurrUserGet(void);
LosProcessCB *OsCurrProcessGet(void);
void OsrecSchedulerLock(UINT32 *);
void OsrecSchedulerUnlock(UINT32);
extern volatile uint32_t osrec_result[32];
#endif
