/* Host-independent checkpoint validation. All inputs and output live in RAM. */
#ifndef OSREC_MONITOR_CHECKPOINT_H
#define OSREC_MONITOR_CHECKPOINT_H
#include "el0.h"
#define OSREC_CHECKPOINT_MAGIC 0x31544c555345524full /* ORESULT1 */
#define OSREC_RESULT_BRK 0xf05u
#define OSREC_RETURN_BRK 0xf06u
struct osrec_checkpoint_event {uint64_t exception,number,args[6],result,completed;};
struct osrec_checkpoint_counter {uint64_t pc,key,value;};
struct osrec_checkpoint_config {
    uint64_t hook,hook_word,post_word,write_alias;
    uint64_t stop_pc,stop_reason,events,counters,capacity;
};
struct osrec_checkpoint_result {
    uint64_t magic,version,status,reason,pc,detail,far;
    uint64_t events,expected_events,counters,expected_counters,first_mismatch;
    uint64_t measurement_started,measurement_finished,reserved[2];
};
extern const struct osrec_checkpoint_config osrec_checkpoint_config;
extern const struct osrec_checkpoint_event osrec_checkpoint_expected[];
extern const struct osrec_checkpoint_counter osrec_checkpoint_counters[];
extern struct osrec_checkpoint_event osrec_checkpoint_events[];
extern volatile struct osrec_checkpoint_result osrec_checkpoint_result;
void osrec_checkpoint_start(void);
int osrec_checkpoint_before(struct osrec_context *,uint64_t,uint64_t);
uint64_t osrec_checkpoint_counter(uint64_t,unsigned);
void osrec_checkpoint_finish(uint64_t,uint64_t,uint64_t,uint64_t);
#endif
