/* Semantic fields only; no dependency on native LiteOS object layout. */
#ifndef OSREC_TASK_MODEL_H
#define OSREC_TASK_MODEL_H
#include <stdint.h>
typedef struct osrec_process { uint32_t processID; struct osrec_process *parentProcess; } LosProcessCB;
typedef struct osrec_task { uint32_t taskID; } LosTaskCB;
LosProcessCB *OsCurrProcessGet(void);
LosTaskCB *OsCurrTaskGet(void);
#endif
