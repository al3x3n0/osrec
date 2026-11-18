#ifndef FLAT_PROGRAM_H
#define FLAT_PROGRAM_H
#include "flat.h"
#include "memory.h"
#include "validation.h"
extern const uint64_t flat_validation_enabled;
enum {P_NATIVE,P_MEMORY,P_STACK,P_SYSTEM,P_INDIRECT,P_SVC,P_BOUNDARY,P_UNSUPPORTED,P_OBSERVE,P_COVERAGE};
struct flat_op {uint64_t pc;flat_target native,following;uint64_t word,metadata,kind,info,immediate;};
struct flat_pc {uint64_t pc;flat_target target;};
struct flat_pc_index_entry {flat_target direct,context;};
struct flat_pc_index {uint64_t base,bytes;const struct flat_pc_index_entry *const *pages;};
_Static_assert(sizeof(struct flat_pc_index_entry)==16,"indexed PC entry ABI");
_Static_assert(sizeof(struct flat_pc_index)==24,"indexed PC descriptor ABI");
extern const struct flat_pc_index flat_pc_indices[];
struct flat_event {uint64_t exception,number,args[6],result,completed;};
/* Shared with generated result observation code. */
struct flat_observer_pending {struct flat_event *event;uint64_t regs;};
extern struct flat_observer_pending flat_observer_pending;
/* Generated ERET paths share the context recorded at syscall/fault entry. */
struct flat_user_return_state {struct osrec_context entry;uint64_t valid,syscall;};
extern struct flat_user_return_state flat_user_return_state;
_Static_assert(offsetof(struct flat_user_return_state,valid)==272 &&
               offsetof(struct flat_user_return_state,syscall)==280,"inline user return ABI");
_Static_assert(offsetof(struct osrec_shadow,sp_el1)==8 && offsetof(struct osrec_shadow,elr)==16 &&
               offsetof(struct osrec_shadow,spsr)==24 && offsetof(struct osrec_shadow,daif)==48 &&
               offsetof(struct osrec_shadow,pan)==56 && offsetof(struct osrec_shadow,mode)==80 &&
               offsetof(struct osrec_shadow,emulated)==88,"inline return shadow ABI");
_Static_assert(offsetof(struct flat_observer_pending,regs)==8,"observer registers ABI");
_Static_assert(offsetof(struct flat_event,result)==64,"observer result ABI");
_Static_assert(offsetof(struct flat_event,completed)==72,"observer completion ABI");
/* Shared with generated memory completion code. */
struct flat_memory_pending {uint64_t temp,value,writeback,base,info,uart;};
extern struct flat_memory_pending flat_memory_pending;
_Static_assert(offsetof(struct flat_memory_pending,value)==8,"memory completion value ABI");
_Static_assert(offsetof(struct flat_memory_pending,writeback)==16,"memory completion writeback ABI");
_Static_assert(offsetof(struct flat_memory_pending,uart)==40,"memory completion UART ABI");
struct flat_counter {uint64_t pc,key,value;};
extern uint64_t flat_counter_used;
_Static_assert(sizeof(struct flat_counter)==24 && offsetof(struct flat_counter,key)==8 &&
               offsetof(struct flat_counter,value)==16,"ordered counter ABI");
struct flat_text_span {uint64_t address,bytes;};
struct flat_execmap {uint64_t va,pa,bytes;};
extern const struct flat_text_span flat_immutable_text[];
extern const uint64_t flat_immutable_text_count;
extern const struct flat_execmap flat_user_text[];
extern const uint64_t flat_user_text_count;
struct flat_full_image {
    struct flat_memory memory;
    struct osrec_shadow *shadow;
    const struct flat_pc *pcs;uint64_t pc_count;
    const struct flat_op *ops;
    const struct flat_event *expected;uint64_t expected_count;
    const struct flat_counter *counters;uint64_t counter_count;
    uint64_t stop_pc,uart_va;
};
_Static_assert(offsetof(struct flat_full_image,memory)+offsetof(struct flat_memory,ttbr0)==32,"user translation TTBR ABI");
_Static_assert(offsetof(struct flat_full_image,memory)+offsetof(struct flat_memory,tcr)==40,"user translation TCR ABI");
_Static_assert(offsetof(struct flat_full_image,shadow)==48,"shadow header binding ABI");
struct flat_full_result {
    uint64_t magic,version,status,events,expected,transitions,reason,pc,detail,far;
    uint64_t counters,uart_bytes,first_mismatch,missing_pc,elapsed,reserved;
    uint64_t debug[24];
};
extern struct flat_full_image flat_program;
extern struct flat_frame flat_initial;
extern volatile struct flat_full_result flat_full_result;
extern struct flat_event flat_events[];
extern uint64_t flat_event_count,flat_uart_used;
_Static_assert(offsetof(struct flat_full_image,uart_va)==120,"UART address ABI");
_Static_assert(offsetof(struct flat_control,pstate_extra)==64,"syscall PSTATE ABI");
_Static_assert(offsetof(struct flat_full_image,expected_count)==88,"syscall event capacity ABI");
_Static_assert(offsetof(struct flat_full_image,counters)==96 &&
               offsetof(struct flat_full_image,counter_count)==104,"ordered counter table ABI");
_Static_assert(sizeof(struct flat_event)==80,"syscall event stride ABI");
extern unsigned char flat_uart[],flat_uart_registers[];
extern const unsigned char flat_expected_uart[];
extern const uint64_t flat_expected_uart_bytes;
void flat_program_initialize(void);
/* Runtime scratch SIMD is caller-saved and guest state is already captured. */
void flat_copy_user_context(struct osrec_context *,const struct osrec_context *);
uint64_t flat_user_context_difference(const struct osrec_context *,const struct osrec_context *,unsigned skip_x0);
_Static_assert(offsetof(struct osrec_context,sp)==248 && offsetof(struct osrec_context,pc)==256 &&
               offsetof(struct osrec_context,pstate)==264,"user context helper ABI");
#endif
