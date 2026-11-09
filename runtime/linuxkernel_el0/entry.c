#define _POSIX_C_SOURCE 200809L
#include "osrec/linuxkernel_el0.h"
#include "internal.h"
#ifdef OSREC_FREESTANDING
#include "standalone.h"
#else
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#endif
#include <stdatomic.h>

struct lk_el0_kernel {
    struct osrec_shadow *shadow;
    struct lk_el0_backend backend;
    void *opaque;
    atomic_uint active;
    unsigned poisoned;
    /* Guarded-call state is in heap storage, not non-volatile automatic
     * variables whose values become indeterminate after longjmp. */
    sigjmp_buf stop;
    struct osrec_context context;
    struct lk_el0_diagnostic diagnostic;
};

static LK_THREAD_LOCAL struct lk_el0_kernel *current;
LK_THREAD_LOCAL lk_stop_handler lk_backend_stop;
enum { RESUME_USER_CONTEXT = 2 }; /* internal entry; no synthetic SVC */

enum lk_el0_status lk_el0_create(struct osrec_shadow *shadow,
                               const struct lk_el0_backend *backend, void *opaque,
                               struct lk_el0_kernel **out)
{
    if (!out) return LK_EL0_BAD_ARGUMENT;
    *out = NULL;
    if (!shadow || !backend || backend->abi != LK_EL0_ABI || !backend->run ||
        shadow->mode != OSREC_USER) return LK_EL0_BAD_ARGUMENT;
    struct lk_el0_kernel *k = calloc(1, sizeof *k);
    if (!k) return LK_EL0_FAULT;
    k->shadow = shadow; k->backend = *backend; k->opaque = opaque;
    atomic_init(&k->active, 0);
    *out = k;
    return LK_EL0_OK;
}

enum lk_el0_status lk_el0_destroy(struct lk_el0_kernel *k)
{
    if (!k) return LK_EL0_BAD_ARGUMENT;
    unsigned expected = 0;
    if (!atomic_compare_exchange_strong(&k->active, &expected, 1)) return LK_EL0_BUSY;
    free(k);
    return LK_EL0_OK;
}

static enum lk_el0_status enter(struct lk_el0_kernel *k, const struct osrec_context *user,
                               uint32_t insn, enum osrec_syscall_entry source,
                               struct lk_el0_result *out)
{
    if (!out) return LK_EL0_BAD_ARGUMENT;
    /* Support a caller reusing its previous result.context as input. */
    struct osrec_context input = {0};
    if (user) input = *user;
    memset(out, 0, sizeof *out);
    out->context = input;
    if (!k || !user) return out->status = LK_EL0_BAD_ARGUMENT;
    unsigned expected = 0;
    if (current || !atomic_compare_exchange_strong(&k->active, &expected, 1))
        return out->status = LK_EL0_BUSY;
    if (k->poisoned) out->status = LK_EL0_POISONED;
    else {
        k->context = input;
        memset(&k->diagnostic, 0, sizeof k->diagnostic);
        int valid;
        if ((int)source==RESUME_USER_CONTEXT)
            valid=k->shadow->mode==OSREC_USER && !(input.pc&3) &&
                  !(input.pstate&~(0xf0000000ull|(1ull<<12)));
        else valid=osrec_enter_syscall(k->shadow, &k->context, insn, source);
        if (!valid)
            out->status = LK_EL0_BAD_ARGUMENT;
        else {
            current = k;
            if (sigsetjmp(k->stop,1)) out->status = LK_EL0_BOUNDARY;
            else out->status = k->backend.run(k->opaque, k->shadow, &k->context, &k->diagnostic);
            current = NULL;
            if ((unsigned)out->status > LK_EL0_UNSUPPORTED ||
                (out->status == LK_EL0_OK && (k->shadow->mode != OSREC_USER ||
                  k->context.pc & 3 || k->context.pstate & ~(0xf0000000ull | (1ull << 12))))) {
                out->status = LK_EL0_UNSUPPORTED;
                k->diagnostic = (struct lk_el0_diagnostic){OSREC_STOP_RUNTIME,k->context.pc,0,0};
            }
            out->context = k->context;
            out->diagnostic = k->diagnostic;
            if (out->status != LK_EL0_OK) k->poisoned = 1;
        }
    }
    atomic_store(&k->active, 0);
    return out->status;
}

enum lk_el0_status lk_el0_call(struct lk_el0_kernel *k, const struct osrec_context *user,
                             uint32_t insn, struct lk_el0_result *out)
{ return enter(k,user,insn,OSREC_ENTRY_VENEER,out); }

enum lk_el0_status lk_el0_svc(struct lk_el0_kernel *k, const struct osrec_context *user,
                            uint32_t insn, struct lk_el0_result *out)
{ return enter(k,user,insn,OSREC_ENTRY_SVC,out); }

enum lk_el0_status lk_el0_run_user(struct lk_el0_kernel *k,const struct osrec_context *user,struct lk_el0_result *out)
{ return enter(k,user,0,(enum osrec_syscall_entry)RESUME_USER_CONTEXT,out); }

#if !defined(__aarch64__) || !defined(__linux__)
/* Portable contract tests only; the arm64 build uses the linked B veneer. */
enum lk_el0_status lk_el0_veneer(struct lk_el0_kernel *k, const struct osrec_context *user,
                               uint32_t insn, struct lk_el0_result *out)
{ return lk_el0_call(k,user,insn,out); }
#endif

static uint64_t platform(enum lk_el0_platform_operation operation, uint64_t argument, int extra)
{
    uint64_t value = 0;
    if (!current || !current->backend.platform ||
        current->backend.platform(current->opaque,operation,argument,extra,&value))
        osrec_platform_stop(OSREC_STOP_UNSUPPORTED,current ? current->context.pc : 0,
                            operation,argument);
    return value;
}

void osrec_platform_set_ttbr0(uint64_t v) { (void)platform(LK_EL0_SET_TTBR0,v,0); }
void osrec_platform_set_ttbr1(uint64_t v) { (void)platform(LK_EL0_SET_TTBR1,v,0); }
void osrec_platform_tlb_flush(void) { (void)platform(LK_EL0_TLB_FLUSH,0,0); }
void osrec_platform_icache_flush(void) { (void)platform(LK_EL0_ICACHE_FLUSH,0,0); }
void osrec_platform_dcache_clean_invalidate(uint64_t v) { (void)platform(LK_EL0_DCACHE_CLEAN_INVALIDATE,v,0); }
uint64_t osrec_platform_translate(uint64_t v,int op) { return platform(LK_EL0_TRANSLATE,v,op); }
void osrec_platform_set_tpidrro(uint64_t v) { (void)platform(LK_EL0_SET_TPIDRRO,v,0); }

void osrec_platform_stop(uint64_t reason,uint64_t pc,uint64_t detail,uint64_t far)
{
    if (lk_backend_stop) lk_backend_stop(reason,pc,detail,far);
    /* The core/platform entry points are internal to a guarded call. Calling
     * them directly outside the library/backend contract is a programming bug. */
    if (!current) __builtin_trap();
    current->diagnostic = (struct lk_el0_diagnostic){reason,pc,detail,far};
    siglongjmp(current->stop,1);
}
