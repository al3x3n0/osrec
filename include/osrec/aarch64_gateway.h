#ifndef OSREC_AARCH64_GATEWAY_H
#define OSREC_AARCH64_GATEWAY_H
#include "aarch64_frame.h"
#define OSREC_AARCH64_GATEWAY_ABI 2u
#define OSREC_AARCH64_GATEWAY_STACK_MIN 16384u
#define OSREC_AARCH64_ROUTE_BRK 0x5353u
#define OSREC_AARCH64_EXIT_BRK 0x5354u
/* Baseline Cortex-A53 execution: sequential EL1h container -> EL0t app,
 * MMU off, DAIF masked, FP/SIMD enabled
 * temporarily. Original code bytes belong in each site's memory view; executable
 * code contains reviewed BRK replacements. Entry PC may precede the first site.
 * No process isolation or SVE/SME state contract is provided. */
struct osrec_aarch64_gateway {
    uint32_t abi,status,diagnostic,active;
    struct osrec_slice_session *session;
    const struct osrec_aarch64_syscall_abi *registers;
    struct osrec_aarch64_frame *application;
    const struct osrec_aarch64_site *sites;size_t site_count;
    struct osrec_user_region executable;
    uint64_t exit_pc;
    unsigned char *stack;size_t stack_bytes;
    uint64_t cursor,entries,exits,kernel_sp;
    struct osrec_slice_result result;
    /* Private, regenerated target offsets are used by the assembly gateway. */
    struct osrec_aarch64_frame container;
    uint64_t saved_vbar,saved_tpidr_el1,saved_cpacr,saved_sp_el0,saved_elr,saved_spsr;
    /* ABI 2: optional disjoint executable spans; otherwise use executable. */
    const struct osrec_user_region *executables;size_t executable_count;
};
uint32_t osrec_aarch64_gateway_run(struct osrec_aarch64_gateway *);
/* Run a nonfinal window. exit_pc is the next patched SVC; on OK its live
 * pre-syscall frame is saved without executing that call or advancing its PC.
 * Retain the session, memory and frame and bind the next window before resuming.
 * active is a private nonzero busy flag; its internal bits are not an ABI. */
uint32_t osrec_aarch64_gateway_run_window(struct osrec_aarch64_gateway *);
#endif
