/* EL0-only native execution edge. No OS, host exceptions, TLS or privileged
 * state. Handlers use a private stack. Logical-stack blocks lower guest SP;
 * native-kernel-stack blocks switch actual SP at the context edges. */
#ifndef OSREC_FLAT_H
#define OSREC_FLAT_H
#include <stddef.h>
#include <stdint.h>
#include "el0.h"
enum flat_status {FLAT_OK,FLAT_BAD_ARGUMENT,FLAT_BUSY,FLAT_BOUNDARY,FLAT_FAULT};
struct flat_frame {
    struct osrec_context cpu;
    uint8_t v[32][16];
    uint32_t fpsr,fpcr;
    uint64_t padding;
};
struct flat_site {uint64_t pc;uint32_t word,kind;};
/* A generated target thunk restores x16/x17 and selects the block's logical
 * or native stack before a static branch. No guest register is lost to the
 * indirect context-resume branch. */
typedef void (*flat_target)(void);
typedef flat_target (*flat_handler)(void *,struct flat_frame *,const struct flat_site *);
struct flat_control {
    uint64_t guest_sp,stack_top,host_sp;
    struct flat_frame *frame;
    flat_handler handler;
    void *opaque;
    uint64_t transitions,status,pstate_extra,limit;
    struct flat_frame *live;
};
extern struct flat_control *flat_active;
enum flat_status flat_run(struct flat_frame *,flat_target,void *stack,size_t stack_bytes,
                          uint64_t limit,flat_handler,void *opaque,uint64_t *transitions);
void flat_fail(enum flat_status) __attribute__((noreturn));
flat_target flat_dispatch(struct flat_frame *,const struct flat_site *);
void flat_enter(struct flat_control *,const struct flat_frame *,flat_target);
void flat_escape(void) __attribute__((noreturn));
_Static_assert(sizeof(struct flat_frame)==800,"flat gateway frame ABI");
_Static_assert(offsetof(struct flat_frame,v)==272,"flat gateway SIMD ABI");
_Static_assert(offsetof(struct flat_frame,fpsr)==784,"flat gateway FP ABI");
_Static_assert(offsetof(struct flat_control,host_sp)==16,"flat gateway control ABI");
_Static_assert(offsetof(struct flat_control,frame)==24,"flat gateway control ABI");
#endif
