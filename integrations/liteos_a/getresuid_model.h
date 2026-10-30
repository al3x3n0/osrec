#ifndef OSREC_GETRESUID_MODEL_H
#define OSREC_GETRESUID_MODEL_H
#define OSREC_QUERY_FUNCTION SysGetRealEffSaveUserID
#define OSREC_REAL_FIELD userID
#define OSREC_EFFECTIVE_FIELD effUserID
#define OSREC_QUERY_KIND 23
#define OSREC_QUERY_NUMBER 209
#include <stdint.h>
#include <stddef.h>
typedef uint32_t UINT32;
typedef struct {UINT32 userID,effUserID;} User;
typedef struct {User *user;} LosProcessCB;
#define LOSCFG_SECURITY_CAPABILITY 1
#define EFAULT 14
#define SCHEDULER_LOCK(saved) OsrecSchedulerLock(&(saved))
#define SCHEDULER_UNLOCK(saved) OsrecSchedulerUnlock(saved)
User *OsCurrUserGet(void);
void OsrecSchedulerLock(UINT32 *);
void OsrecSchedulerUnlock(UINT32);
size_t LOS_ArchCopyToUser(void *,const void *,size_t);
extern volatile uint32_t osrec_result[32];
#endif
