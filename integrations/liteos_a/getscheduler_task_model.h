/* Reviewed logical task projection and typed scheduler-policy callback ABI. */
#ifndef OSREC_GETSCHEDULER_TASK_MODEL_H
#define OSREC_GETSCHEDULER_TASK_MODEL_H
#include <stdint.h>
#include <stddef.h>
_Static_assert(sizeof(int)==4 && sizeof(unsigned int)==4,"requires 32-bit scalars");
#define EINVAL 22
#define LOS_OK 0
typedef struct {
    uint16_t policy,basePrio,priority;
    uint32_t timeSlice;
    int32_t runTimeUs;
    uint32_t deadlineUs,periodUs;
} SchedParam;
_Static_assert(sizeof(((SchedParam *)0)->policy)==2,"requires 16-bit policy");
typedef struct LosTaskCB LosTaskCB;
typedef struct { unsigned int (*schedParamGet)(const LosTaskCB *,SchedParam *); } SchedOps;
struct LosTaskCB { uint32_t id; const SchedOps *ops; };
int osrec_task_invalid(int id);
LosTaskCB *osrec_task_lookup(int id);
void osrec_scheduler_lock(unsigned int *saved);
void osrec_scheduler_unlock(unsigned int saved);
#define OS_TID_CHECK_INVALID(id) osrec_task_invalid(id)
#define OS_TCB_FROM_TID(id) osrec_task_lookup(id)
#define SCHEDULER_LOCK(saved) osrec_scheduler_lock(&(saved))
#define SCHEDULER_UNLOCK(saved) osrec_scheduler_unlock(saved)
int OsUserTaskOperatePermissionsCheck(const LosTaskCB *task);
unsigned int LOS_GetCurrProcessID(void);
int LOS_GetProcessScheduler(int id,int *policy,void *param);
#endif
