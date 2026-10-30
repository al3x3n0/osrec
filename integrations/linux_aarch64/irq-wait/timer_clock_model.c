/* Injected timekeeper boundary: optional native entry fields, native outputs
 * in clock-state mode and synthetic outputs otherwise.
 * Initial soft offsets remain omission guards; extra timer bases are not admitted. */
struct clock_witness {uint64_t kind,calls,sequence;ktime_t now,real,boot,tai,soft_real,soft_boot,soft_tai;};
_Static_assert(sizeof(struct clock_witness)==80,"clock witness layout");
struct clock_witness osrec_linux_irq_clock[2];
static unsigned clock_witness_count,native_clock_return_count,native_clock_entry_count;
static void emit_clock_entry(const struct clock_input *input)
{
    check(checkpoint_clock_entry && irq_depth==1 && native_clock_entry_count==delivered && delivered<checkpoint_irqs);
    emit(22,input->sequence,1,0);
    emit(23,(uint64_t)input->real,(uint64_t)input->boot,(uint64_t)input->tai);
    ++native_clock_entry_count;
}
static void emit_clock_return(const struct clock_input *input)
{
    check(checkpoint_clock_state && irq_depth==1 && native_clock_return_count==delivered && delivered<checkpoint_irqs);
    emit(19,(uint64_t)input->now,input->sequence,1);
    emit(20,(uint64_t)input->real,(uint64_t)input->boot,(uint64_t)input->tai);
    ++native_clock_return_count;
}
static void replay_context_clock(void)
{
    unsigned prefix=checkpoint_clock_entry?4:2;
    check(checkpoint_clock_state && !timer_cpu.lock && position+prefix<checkpoint_count &&
          checkpoint_events[position+prefix-1].kind==20 && checkpoint_events[position+prefix].kind==11);
    if(checkpoint_clock_entry)emit_clock_entry(&checkpoint_clock_entries[delivered]);
    emit_clock_return(&checkpoint_clocks[delivered]);
}
static void clock_snapshot(unsigned kind,ktime_t now)
{
    check(kind==clock_witness_count+1 && clock_witness_count<2);
    struct hrtimer_clock_base *b=timer_cpu.clock_base;
    osrec_linux_irq_clock[clock_witness_count++]=(struct clock_witness){kind,outer_updates,
        timer_cpu.clock_was_set_seq,now,b[1].offset,b[2].offset,b[3].offset,
        b[5].offset,b[6].offset,b[7].offset};
}
static void seed_clock_offsets(void)
{
    check(!clock_witness_count && !timer_cpu.clock_was_set_seq);
    if(checkpoint_clock_entry){
        const struct clock_input *entry=&checkpoint_clock_entries[delivered];
        timer_cpu.clock_was_set_seq=entry->sequence;
        timer_cpu.clock_base[1].offset=entry->real;
        timer_cpu.clock_base[2].offset=entry->boot;
        timer_cpu.clock_base[3].offset=entry->tai;
    }
    timer_cpu.clock_base[5].offset=-11;
    timer_cpu.clock_base[6].offset=-22;
    timer_cpu.clock_base[7].offset=-33;
}
#include "timekeeper_model.c"
static ktime_t ktime_get_update_offsets_now(unsigned *seq,ktime_t *real,ktime_t *boot,ktime_t *tai)
{
    check(outer_active && timer_cpu.lock==1 && !outer_updates &&
          seq==&timer_cpu.clock_was_set_seq && real==&timer_cpu.clock_base[1].offset &&
          boot==&timer_cpu.clock_base[2].offset && tai==&timer_cpu.clock_base[3].offset);
    if(checkpoint_clock_entry){
        const struct clock_input *entry=&checkpoint_clock_entries[delivered];
        check(*seq==entry->sequence && *real==entry->real && *boot==entry->boot && *tai==entry->tai);
        struct clock_input actual={0,*seq,*real,*boot,*tai};emit_clock_entry(&actual);
    }else check(!*seq);
    const struct clock_input *input=&checkpoint_clocks[checkpoint_clock_state?delivered:0];
    ktime_t provider_now=(ktime_t)observed_now;
    if(checkpoint_timekeeper_source)provider_now=run_source_timekeeper(seq,real,boot,tai);
    else{
    if(!checkpoint_clock_entry || *seq!=input->sequence)*seq=checkpoint_clock_state?input->sequence:1;
    if(!checkpoint_clock_entry || *real!=input->real)*real=checkpoint_clock_state?input->real:11;
    if(!checkpoint_clock_entry || *boot!=input->boot)*boot=checkpoint_clock_state?input->boot:22;
    if(!checkpoint_clock_entry || *tai!=input->tai)*tai=checkpoint_clock_state?input->tai:33;
    }
    check(provider_now==(ktime_t)observed_now);
    if(checkpoint_clock_state){
        check(input->now==(ktime_t)observed_now);
        struct clock_input fetched={(ktime_t)observed_now,*seq,*real,*boot,*tai};emit_clock_return(&fetched);
    }
    ++outer_updates;outer_snapshot(5);clock_snapshot(1,(ktime_t)observed_now);
    return (ktime_t)observed_now;
}
#include "timer_clock.c"
static void verify_clock_update(ktime_t now)
{
    check(clock_witness_count==1 && now==(ktime_t)observed_now && timer_cpu.clock_was_set_seq==(checkpoint_clock_state?checkpoint_clocks[delivered].sequence:1) &&
          !timer_cpu.clock_base[0].offset && !timer_cpu.clock_base[4].offset && !timer_base.offset);
    const struct clock_input *input=&checkpoint_clocks[checkpoint_clock_state?delivered:0];
    check(timer_cpu.clock_base[1].offset==input->real && timer_cpu.clock_base[2].offset==input->boot && timer_cpu.clock_base[3].offset==input->tai);
    for(unsigned i=1;i<4;++i)check(
        timer_cpu.clock_base[i+4].offset==timer_cpu.clock_base[i].offset);
    clock_snapshot(2,now);
}

static unsigned native_propagated_offset_count;
static void emit_propagated_offsets(void)
{
    check(checkpoint_clock_offsets && !native_propagated_offset_count && outer_active && outer_updates==1 &&
          irq_depth==1 && phase==3 && !timer_cpu.lock && !callback_count && timer_base.cpu_base==&timer_cpu &&
          timer_cpu.clock_was_set_seq==checkpoint_clocks[delivered].sequence);
    emit(21,(uint64_t)timer_cpu.clock_base[5].offset,(uint64_t)timer_cpu.clock_base[6].offset,(uint64_t)timer_cpu.clock_base[7].offset);
    ++native_propagated_offset_count;
}
