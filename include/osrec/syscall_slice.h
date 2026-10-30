#ifndef OSREC_SYSCALL_SLICE_H
#define OSREC_SYSCALL_SLICE_H
#include <stdint.h>
#include <stddef.h>
#define OSREC_SLICE_ABI 1u
#define OSREC_MEMORY_READ 1u
#define OSREC_MEMORY_WRITE 2u
#define OSREC_SLICE_OK 0u
#define OSREC_SLICE_BAD_INPUT 1u
#define OSREC_SLICE_BUSY 2u
#define OSREC_SLICE_DIVERGED 3u
#define OSREC_SLICE_POISONED 4u
#define OSREC_SLICE_COMPLETE 5u
struct osrec_user_region {
    uint64_t user_address;
    unsigned char *image_address;
    size_t bytes;
    uint32_t permissions,object_id;
};
struct osrec_user_memory {const struct osrec_user_region *regions;size_t count;};
struct osrec_slice_invocation {uint64_t ordinal,number,args[6];struct osrec_user_memory memory;};
struct osrec_slice_result {int64_t raw;uint32_t status,diagnostic;uint64_t ordinal;};
struct osrec_slice_adapter {
    uint32_t abi;const char *kernel_abi;size_t state_bytes,state_alignment;uint64_t calls;
    void (*restore)(void *);
    uint32_t (*enter)(void *,const struct osrec_slice_invocation *,struct osrec_slice_result *);
    uint32_t (*finish)(const void *);
};
extern const struct osrec_slice_adapter osrec_kernel_adapter;
struct osrec_slice_session {
    const struct osrec_slice_adapter *adapter;void *state;uint64_t next;
    uint32_t initialized,active,poisoned;
};
uint32_t osrec_user_memory_validate(const struct osrec_user_memory *);
void *osrec_user_memory_resolve(const struct osrec_user_memory *,uint64_t,size_t,uint32_t);
const struct osrec_user_region *osrec_user_memory_object(const struct osrec_user_memory *,uint32_t,size_t,uint32_t);
uint32_t osrec_slice_session_init(struct osrec_slice_session *,const struct osrec_slice_adapter *,void *,size_t);
uint32_t osrec_slice_session_restore(struct osrec_slice_session *);
uint32_t osrec_slice_execute(struct osrec_slice_session *,const struct osrec_slice_invocation *,struct osrec_slice_result *);
uint32_t osrec_slice_finish(const struct osrec_slice_session *);
/* The freestanding AArch64 build uses -mgeneral-regs-only. No host exception runtime. */
struct osrec_slice_guard {uint64_t saved[13];uint32_t diagnostic;};
int osrec_slice_checkpoint(struct osrec_slice_guard *) __attribute__((returns_twice));
void osrec_slice_abort(struct osrec_slice_guard *,uint32_t) __attribute__((noreturn));
#endif
