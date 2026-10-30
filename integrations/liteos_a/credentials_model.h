#ifndef OSREC_CREDENTIALS_MODEL_H
#define OSREC_CREDENTIALS_MODEL_H
#include <stdint.h>
typedef uint32_t UINT32;
typedef struct { UINT32 effUserID,effGid; } User;
#define LOSCFG_SECURITY_CAPABILITY 1
#ifdef LOSCFG_USER_CONTAINER
#error Unsupported user container configuration
#endif
User *OsCurrUserGet(void);
UINT32 osrec_credentials_lock(void);
void osrec_credentials_unlock(UINT32 token);
#define SCHEDULER_LOCK(token) ((token)=osrec_credentials_lock())
#define SCHEDULER_UNLOCK(token) osrec_credentials_unlock(token)
#endif
