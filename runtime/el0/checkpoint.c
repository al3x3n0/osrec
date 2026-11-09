/* No libc, syscalls, allocation, filesystem, host signals or semihosting.
 * UART stays a real memory-mapped device. Only timer reads are injected here.
 * Acceptance values are inspected after execution and never supply results. */
#include "checkpoint.h"
extern struct osrec_shadow osrec_shadow;
static struct osrec_checkpoint_event *pending;
static uint64_t pending_regs,event_count,counter_count,disarmed;
volatile struct osrec_checkpoint_result osrec_checkpoint_result;

static void patch(uint64_t pc,uint32_t word)
{
    uint64_t alias=osrec_checkpoint_config.write_alias;
    if(pc!=osrec_checkpoint_config.hook) {
        if(pc!=osrec_checkpoint_config.hook+4)osrec_platform_stop(OSREC_STOP_RUNTIME,pc,word,0);
        alias+=4096;
    }
    volatile uint32_t *p=(void *)(alias+(pc&4095));*p=word;
    osrec_platform_dcache_clean_invalidate((uint64_t)p);
    osrec_platform_icache_flush();
}
void osrec_checkpoint_start(void)
{
    osrec_checkpoint_result.magic=OSREC_CHECKPOINT_MAGIC;
    osrec_checkpoint_result.version=1;
    osrec_checkpoint_result.first_mismatch=~0ull;
    patch(osrec_checkpoint_config.hook,0xd4200000u|(OSREC_RESULT_BRK<<5));
    osrec_checkpoint_result.measurement_started=1;
}
uint64_t osrec_checkpoint_counter(uint64_t pc,unsigned key)
{
    if(counter_count==osrec_checkpoint_config.counters ||
       osrec_checkpoint_counters[counter_count].pc!=pc || osrec_checkpoint_counters[counter_count].key!=key)
        osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,key,counter_count);
    return osrec_checkpoint_counters[counter_count++].value;
}
static struct osrec_checkpoint_event *append(uint64_t pc)
{
    if(event_count==osrec_checkpoint_config.capacity)
        osrec_platform_stop(OSREC_STOP_RUNTIME,pc,event_count,0);
    return osrec_checkpoint_events+event_count++;
}
int osrec_checkpoint_before(struct osrec_context *c,uint64_t esr,uint64_t far)
{
    unsigned ec=esr>>26;
    if(osrec_shadow.mode==OSREC_KERNEL && ec==0x3c) {
        if(c->pc==osrec_checkpoint_config.hook && (esr&65535)==OSREC_RESULT_BRK && !disarmed) {
            if(pending){pending->result=*(const uint64_t *)pending_regs;pending->completed=1;pending=0;}
            patch(c->pc+4,0xd4200000u|(OSREC_RETURN_BRK<<5));
            patch(c->pc,(uint32_t)osrec_checkpoint_config.hook_word);
            disarmed=1;return 1; /* CPU executes the original BL itself. */
        }
        if(c->pc==osrec_checkpoint_config.hook+4 && (esr&65535)==OSREC_RETURN_BRK && disarmed) {
            patch(c->pc,(uint32_t)osrec_checkpoint_config.post_word);
            patch(c->pc-4,0xd4200000u|(OSREC_RESULT_BRK<<5));
            disarmed=0;return 1; /* CPU executes the original continuation. */
        }
    }
    if(osrec_shadow.mode!=OSREC_USER)return 0;
    struct osrec_checkpoint_event *e=append(c->pc);
    if(ec==0x15) {
        e->number=c->x[8];for(unsigned i=0;i<6;i++)e->args[i]=c->x[i];
        pending=e;pending_regs=osrec_shadow.sp_el1-0x150;
    } else {
        e->exception=1;e->number=~0ull;e->args[0]=esr;
        e->args[1]=(ec==0x3c || ec==0)?osrec_shadow.far:far;e->args[2]=c->pc;
    }
    return 0;
}
static int same(const struct osrec_checkpoint_event *a,const struct osrec_checkpoint_event *b)
{
    if(a->exception!=b->exception || a->number!=b->number || a->completed!=b->completed ||
       (a->completed && a->result!=b->result))return 0;
    for(unsigned i=0;i<6;i++)if(a->args[i]!=b->args[i])return 0;
    return 1;
}
void osrec_checkpoint_finish(uint64_t reason,uint64_t pc,uint64_t detail,uint64_t far)
{
    volatile struct osrec_checkpoint_result *r=&osrec_checkpoint_result;
    int okay=reason==osrec_checkpoint_config.stop_reason && pc==osrec_checkpoint_config.stop_pc &&
             counter_count==osrec_checkpoint_config.counters;
    uint64_t expected=0;
    for(uint64_t i=0;i<event_count;i++) {
        const struct osrec_checkpoint_event *a=osrec_checkpoint_events+i;
        if(i && a->exception && a[-1].exception && a->args[0]==a[-1].args[0] &&
           a->args[1]==a[-1].args[1] && a->args[2]==a[-1].args[2])continue;
        if(expected>=osrec_checkpoint_config.events || !same(a,osrec_checkpoint_expected+expected)) {
            if(r->first_mismatch==~0ull)r->first_mismatch=i;
            okay=0;
        }
        expected++;
    }
    if(expected!=osrec_checkpoint_config.events)okay=0;
    r->reason=reason;r->pc=pc;r->detail=detail;r->far=far;
    r->events=event_count;r->expected_events=osrec_checkpoint_config.events;
    r->counters=counter_count;r->expected_counters=osrec_checkpoint_config.counters;
    r->measurement_finished=1;
    /* Publish status last, after making results visible to the testbench. */
    __asm__ volatile("dsb sy":::"memory");r->status=okay?1:2;__asm__ volatile("dsb sy":::"memory");
}
