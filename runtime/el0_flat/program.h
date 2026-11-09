#ifndef FLAT_PROGRAM_H
#define FLAT_PROGRAM_H
#include "flat.h"
#include "memory.h"
enum {P_NATIVE,P_MEMORY,P_STACK,P_SYSTEM,P_INDIRECT,P_SVC,P_BOUNDARY,P_UNSUPPORTED,P_OBSERVE,P_COVERAGE};
struct flat_op {uint64_t pc;flat_target native,following;uint64_t word,metadata,kind,info,immediate;};
struct flat_pc {uint64_t pc;flat_target target;};
struct flat_event {uint64_t exception,number,args[6],result,completed;};
struct flat_counter {uint64_t pc,key,value;};
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
struct flat_full_result {
    uint64_t magic,version,status,events,expected,transitions,reason,pc,detail,far;
    uint64_t counters,uart_bytes,first_mismatch,missing_pc,elapsed,reserved;
    uint64_t debug[24];
};
extern struct flat_full_image flat_program;
extern struct flat_frame flat_initial;
extern volatile struct flat_full_result flat_full_result;
extern struct flat_event flat_events[];
extern unsigned char flat_uart[],flat_uart_registers[];
extern const unsigned char flat_expected_uart[];
extern const uint64_t flat_expected_uart_bytes;
void flat_program_initialize(void);
#endif
