/* Native arm64 Linux backend for a lowered captured-kernel package.
 * Execution stays in this process. Explicit calls yield at logical ERET;
 * execute resumes actual user instructions through branch-to-BRK gateways.
 * Only one native instance can own the fixed mappings in a process. */
#ifndef OSREC_LINUXKERNEL_EL0_NATIVE_H
#define OSREC_LINUXKERNEL_EL0_NATIVE_H
#include "linuxkernel_el0.h"
#ifdef __cplusplus
extern "C" {
#endif
struct lk_el0_native;
struct lk_el0_fp { uint8_t v[32][16]; uint32_t fpsr, fpcr; };
struct lk_el0_counter { uint64_t pc, encoding, value; };
struct lk_el0_mmio { uint64_t pc,address,size,write,value; };
struct lk_el0_event {
    uint64_t exception; /* zero: syscall; one: user exception */
    uint64_t number, arguments[6], result, completed, pc;
};
/* An executable may link these read-only assets directly. Offsets are relative
 * to the physical store's beginning, not host addresses or physical PAs. Gaps
 * between sorted, nonoverlapping extents are reconstructed as zero bytes. */
#define LK_EL0_IMAGE_ABI 1u
struct lk_el0_blob { const void *data; uint64_t size; };
struct lk_el0_extent { uint64_t offset; struct lk_el0_blob bytes; };
struct lk_el0_image {
    uint32_t abi, reserved;
    struct lk_el0_blob native, application, vma;
    uint64_t memory_size;
    const struct lk_el0_extent *extents;
    uint64_t extent_count;
    struct lk_el0_blob counters, mmio;
};
enum lk_el0_status lk_el0_native_open(const char *directory,
                                     struct lk_el0_native **out,
                                     struct lk_el0_diagnostic *diagnostic);
/* Copies linked assets into private instance state; creates only anonymous
 * memfds, with no package-directory or temporary-file dependency. Installs the
 * embedded hardware transcripts. Assets remain borrowed for this call only.
 * C pointers, like other native API inputs, must identify valid storage. */
enum lk_el0_status lk_el0_native_open_image(const struct lk_el0_image *,
                                           struct lk_el0_native **,
                                           struct lk_el0_diagnostic *);
enum lk_el0_status lk_el0_native_close(struct lk_el0_native *native);
struct lk_el0_kernel *lk_el0_native_kernel(struct lk_el0_native *native);
/* Initial application registers, at the original SVC instruction. */
const struct osrec_context *lk_el0_native_initial(struct lk_el0_native *native);
/* In/out FP/SIMD context, persistent across calls. Set before explicit entry
 * when the checkpoint application has changed its FP/SIMD registers. */
struct lk_el0_fp *lk_el0_native_fp(struct lk_el0_native *native);
/* Construction tools only: prepare another process through the captured
 * kernel's real mmap/memfd/execve paths. Call only between entries. Copies use
 * captured translations and validate the entire range before changing bytes.
 * kernel_space allows inspecting kernel objects. Host buffers must be valid. */
enum lk_el0_status lk_el0_native_memory(struct lk_el0_native *,uint64_t address,
                                       void *bytes,uint64_t size,int write,int kernel_space,
                                       struct lk_el0_diagnostic *);
/* Deterministic construction inputs: record counters base+step*index and PL011
 * FR reads (0x90), DR/IMSC writes. Caller-owned bounded arrays must stay valid
 * until reset/close. No host clock or device access; transcript setters select
 * ordinary strict replay again. */
enum lk_el0_status lk_el0_native_record_inputs(struct lk_el0_native *,uint64_t counter_base,
                                              uint64_t counter_step,uint64_t uart_va,
                                              struct lk_el0_counter *,uint64_t counter_capacity,
                                              struct lk_el0_mmio *,uint64_t mmio_capacity);
/* Save an unpatched USER checkpoint to distinct, empty caller-owned output
 * files. The snapshot contains no native host context or mappings. */
enum lk_el0_status lk_el0_native_snapshot(struct lk_el0_native *,const struct osrec_context *,
                                         int native_fd,int memory_fd);
/* Optional ordered external inputs, copied by the backend. Default: counter
 * reads stop explicitly. Each read must match both its original PC and register
 * encoding; missing/mismatched events stop and poison the kernel instance.
 * Set only between calls. consumed exposes full-transcript validation. */
enum lk_el0_status lk_el0_native_counters(struct lk_el0_native *native,
                                         const struct lk_el0_counter *events,uint64_t count);
uint64_t lk_el0_native_counters_consumed(struct lk_el0_native *native);
/* Ordered hardware-edge accesses. Reads supply recorded values; writes must
 * reproduce their recorded values. No device or host syscall substitutes. */
enum lk_el0_status lk_el0_native_mmio(struct lk_el0_native *,const struct lk_el0_mmio *,uint64_t count);
uint64_t lk_el0_native_mmio_consumed(struct lk_el0_native *);
/* Configure a caller-owned bounded trace before execution. Entries are filled
 * without allocation in signal handlers. Syscall results are observed before
 * signal delivery. An incomplete final syscall has completed == 0. */
enum lk_el0_status lk_el0_native_trace(struct lk_el0_native *,struct lk_el0_event *,uint64_t capacity);
/* Allocate trace storage in the runtime's separate VA arena. Owned by the
 * instance; do not free it. Avoids host heap allocations in guest VMA holes. */
enum lk_el0_status lk_el0_native_trace_allocate(struct lk_el0_native *,uint64_t capacity,struct lk_el0_event **);
uint64_t lk_el0_native_events(struct lk_el0_native *);
/* Resume actual checkpoint application instructions, starting at user (NULL
 * selects the captured initial context), through captured kernel code until a
 * named boundary. Requires the matching application.bin package extension.
 * Syscall sites branch to register-preserving BRK entry veneers; the host
 * signal frame captures all raw registers, flags and FP state. No host SVC. */
enum lk_el0_status lk_el0_native_execute(struct lk_el0_native *,const struct osrec_context *,struct lk_el0_result *);
#ifdef __cplusplus
}
#endif
#endif
