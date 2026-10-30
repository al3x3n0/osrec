/* Reviewed process-mode boundary ABI. Task-mode paths terminate explicitly. */
#ifndef OSREC_GETSCHEDULER_MODEL_H
#define OSREC_GETSCHEDULER_MODEL_H
#include <stdint.h>
#include <stddef.h>
_Static_assert(sizeof(int)==4 && sizeof(unsigned int)==4,"requires 32-bit scalar ABI");
#define EINVAL 22
#define LOS_OK 0
/* Only the unreachable task branch refers to these logical types. */
typedef struct { unsigned int policy; } SchedParam;
typedef struct LosTaskCB LosTaskCB;
struct task_ops { void (*schedParamGet)(LosTaskCB *,SchedParam *); };
struct LosTaskCB { struct task_ops *ops; };
__attribute__((noreturn)) void osrec_unsupported_task(void);
#define OS_TID_CHECK_INVALID(id) (osrec_unsupported_task(),(void)(id),1)
#define OS_TCB_FROM_TID(id) (osrec_unsupported_task(),(void)(id),(LosTaskCB *)0)
#define SCHEDULER_LOCK(saved) do { (saved)=0;osrec_unsupported_task(); } while(0)
#define SCHEDULER_UNLOCK(saved) do { (void)(saved);osrec_unsupported_task(); } while(0)
static inline int OsUserTaskOperatePermissionsCheck(LosTaskCB *task)
{ (void)task;osrec_unsupported_task(); }
unsigned int LOS_GetCurrProcessID(void);
int LOS_GetProcessScheduler(int id,int *policy,void *param);
#endif
