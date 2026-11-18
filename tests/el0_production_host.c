/* Run the actual terminal path with independently wrong validation evidence. */
#include <assert.h>
#include <string.h>
#undef memcpy
#include "../runtime/el0_flat/program.c"

static void entry(void){}
static const struct flat_pc pcs[]={{0x2000,entry}};
static const struct flat_ram ram[]={{0x40000000,4096,0}};
const struct flat_mapping flat_maps[1]={{0}};
static struct flat_event expected;
struct flat_event flat_events[1];
unsigned char flat_uart[4096],flat_uart_registers[4096];
const unsigned char flat_expected_uart[]={42};
const uint64_t flat_expected_uart_bytes=1,flat_user_text_count=0;
const struct flat_execmap flat_user_text[1]={{0}};
struct flat_frame flat_initial;
struct flat_full_image flat_program;
static unsigned execution_fails;

void flat_program_initialize(void){}
enum flat_status flat_run(struct flat_frame *frame,flat_target target,void *stack,size_t bytes,
                          uint64_t limit,flat_handler handler,void *opaque,uint64_t *transitions)
{
    (void)frame;(void)stack;(void)bytes;(void)limit;(void)handler;(void)opaque;
    assert(target==entry);*transitions=9;
    flat_full_result.reason=execution_fails?OSREC_STOP_UNSUPPORTED:OSREC_STOP_BOUNDARY;
    flat_full_result.pc=flat_program.stop_pc;
    return FLAT_BOUNDARY;
}

int main(void)
{
    assert(flat_validation_enabled==OSREC_FLAT_VALIDATION);
    for(unsigned scenario=0;scenario<6;scenario++) {
        memset((void *)&flat_full_result,0,sizeof flat_full_result);
        expected=(struct flat_event){.number=1};flat_events[0]=expected;
        flat_uart[0]=42;flat_uart_used=1;flat_counter_used=1;flat_event_count=1;
        flat_program=(struct flat_full_image){.memory={.ram=ram},.pcs=pcs,.pc_count=1,
            .expected=&expected,.expected_count=1,.counter_count=1,.stop_pc=0x3000};
        flat_initial.cpu.pc=0x2000;execution_fails=scenario==5;
        if(scenario==1)flat_events[0].number=2;
        if(scenario==2)flat_uart[0]=43;
        if(scenario==3)flat_counter_used=0;
        if(scenario==4)flat_event_count=0;
        int should_fail=execution_fails || (OSREC_FLAT_VALIDATION && scenario!=0);
        assert(flat_main()==should_fail);
        assert(flat_full_result.status==(should_fail?2u:1u));
        assert(flat_full_result.transitions==9);
    }
    return 0;
}
