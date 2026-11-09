/* Callable checkpoint-to-kernel front end. Install el0.h beside this header. */
#ifndef OSREC_LINUXKERNEL_EL0_H
#define OSREC_LINUXKERNEL_EL0_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "el0.h"

#define LK_EL0_ABI 1u

enum lk_el0_status {
    LK_EL0_OK = 0,
    LK_EL0_BAD_ARGUMENT = 1,
    LK_EL0_BUSY = 2,
    LK_EL0_POISONED = 3,
    LK_EL0_BOUNDARY = 4,
    LK_EL0_FAULT = 5,
    LK_EL0_UNSUPPORTED = 6
};

struct lk_el0_diagnostic { uint64_t reason, pc, detail, far; };
struct lk_el0_result {
    enum lk_el0_status status;
    struct lk_el0_diagnostic diagnostic;
    /* Resumable USER context only on OK; diagnostic context otherwise.
     * Linux return values (including -errno) remain in context.x[0]. */
    struct osrec_context context;
};

enum lk_el0_platform_operation {
    LK_EL0_SET_TTBR0, LK_EL0_SET_TTBR1, LK_EL0_TLB_FLUSH,
    LK_EL0_ICACHE_FLUSH, LK_EL0_DCACHE_CLEAN_INVALIDATE,
    LK_EL0_TRANSLATE, LK_EL0_SET_TPIDRRO
};

struct lk_el0_backend {
    uint32_t abi;
    /* Execute captured kernel instructions from context until logical ERET
     * yields USER mode, or return a structured failure. No host exit/abort.
     * Backend owns CPU execution, mapping/fault handling and host TLS safety.
     * There is deliberately no default backend substituting host syscalls. */
    enum lk_el0_status (*run)(void *opaque, struct osrec_shadow *shadow,
                             struct osrec_context *context, struct lk_el0_diagnostic *diagnostic);
    /* Return zero only when the requested architecture action is supported.
     * Missing actions become named boundaries, not successful no-ops. */
    int (*platform)(void *opaque, enum lk_el0_platform_operation operation,
                    uint64_t argument, int extra, uint64_t *value);
};

struct lk_el0_kernel;

/* Shadow, its matching kernel RAM/mappings and opaque remain caller-owned.
 * Backend description is copied. Calls are synchronous and non-reentrant.
 * A boundary/fault poisons the instance: restore the checkpoint before creating
 * another instance. Destroy does not destroy the supplied kernel state.
 * C pointers must name valid memory; arbitrary host faults are not caught by
 * this front end. linuxkernel_el0_native.h selects the native CPU/fault backend.
 * The caller must synchronize destruction with all users of the instance. */
enum lk_el0_status lk_el0_create(struct osrec_shadow *shadow,
                               const struct lk_el0_backend *backend, void *opaque,
                               struct lk_el0_kernel **out);
enum lk_el0_status lk_el0_destroy(struct lk_el0_kernel *kernel);

/* Explicit-context ABI. The input context is copied, never modified in place.
 * call/veneer: user.pc is the ORIGINAL syscall instruction address.
 * svc: user.pc is the post-SVC address reported by the interception backend.
 * insn is the original SVC word, including its immediate. The veneer is a
 * single B tail call into lk_el0_call on arm64, using the ordinary function ABI;
 * transparent rewriting of arbitrary user instructions needs its own gateway. */
enum lk_el0_status lk_el0_call(struct lk_el0_kernel *kernel,
                             const struct osrec_context *user, uint32_t insn,
                             struct lk_el0_result *out);
enum lk_el0_status lk_el0_veneer(struct lk_el0_kernel *kernel,
                               const struct osrec_context *user, uint32_t insn,
                               struct lk_el0_result *out);
enum lk_el0_status lk_el0_svc(struct lk_el0_kernel *kernel,
                            const struct osrec_context *user, uint32_t insn,
                            struct lk_el0_result *out);

#ifdef __cplusplus
}
#endif
#endif
