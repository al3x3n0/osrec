#ifndef LK_EL0_INTERNAL_H
#define LK_EL0_INTERNAL_H
#include "osrec/linuxkernel_el0.h"
#ifdef OSREC_FREESTANDING
/* The standalone executor owns one Linux thread and has no TLS runtime. */
#define LK_THREAD_LOCAL
#else
#define LK_THREAD_LOCAL _Thread_local
#endif
/* A backend may unwind its own signal/mapping scope before returning a core
 * stop to the public front end. Internal, thread-local, and never a host trap. */
typedef void (*lk_stop_handler)(uint64_t, uint64_t, uint64_t, uint64_t);
__attribute__((visibility("hidden")))
extern LK_THREAD_LOCAL lk_stop_handler lk_backend_stop;
/* Enter an already restored user continuation under the same guarded instance.
 * Only backends supporting USER startup may expose this through their API. */
__attribute__((visibility("hidden")))
enum lk_el0_status lk_el0_run_user(struct lk_el0_kernel *,const struct osrec_context *,struct lk_el0_result *);
#endif
