#ifndef OSREC_AARCH64_FRAME_H
#define OSREC_AARCH64_FRAME_H
#include "syscall_slice.h"
#define OSREC_AARCH64_FRAME_ABI 1u
#define OSREC_AARCH64_FRAME_BYTES 808u
/* A loader-owned saved image, not a hardware exception-frame layout. */
struct osrec_aarch64_frame {
    uint64_t x[31],sp,pc,pstate;
    struct {uint64_t lo,hi;} v[32];
    uint32_t fpcr,fpsr;
    uint64_t tpidr_el0,tpidrro_el0;
};
/* Recipes are sorted by syscall number; unused argument registers stay opaque. */
struct osrec_aarch64_syscall_recipe {uint64_t number;uint32_t argument_count;};
struct osrec_aarch64_syscall_abi {
    uint32_t abi,number_register,argument_registers[6],result_register;
    const struct osrec_aarch64_syscall_recipe *syscalls;size_t syscall_count;
};
extern const struct osrec_aarch64_syscall_abi osrec_application_abi;
struct osrec_aarch64_site {
    uint64_t ordinal,svc_pc,continuation_pc;
    struct osrec_user_memory memory;
};
uint32_t osrec_aarch64_abi_validate(const struct osrec_aarch64_syscall_abi *);
/* On OK only result-register and PC change. On failure the frame is untouched.
 * Trusted container metadata/state must be separate from writable app regions.
 * SIMD/FP fields are preserved as bytes; this function does not load CPU state. */
uint32_t osrec_aarch64_syscall(struct osrec_slice_session *,
    const struct osrec_aarch64_syscall_abi *,struct osrec_aarch64_frame *,
    const struct osrec_aarch64_site *,struct osrec_slice_result *);
#endif
