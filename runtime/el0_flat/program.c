/* General checkpoint execution. Every original instruction runs as native
 * code or through an architecture/address adaptation. No syscall models. */
#include "program.h"
#define MASK64 (~0ull)
#define LOAD (1ull<<19)
#define WB (1ull<<21)
#define POST (1ull<<22)
#define USER (1ull<<23)
#define REGISTER (1ull<<40)
#define SRC_SP (1ull<<41)
#define DST_SP (1ull<<42)
#define HINT (1ull<<43)
#define PCREL (1ull<<44)
#define EXCLUSIVE (1ull<<45)
#define ALIGNED (1ull<<46)
volatile struct flat_full_result flat_full_result;
static unsigned char runtime_stack[131072] __attribute__((aligned(16)));
struct flat_memory_pending flat_memory_pending;
struct flat_observer_pending flat_observer_pending;
static uint64_t event_count,counter_used,uart_used;
#ifdef OSREC_FLAT_PROFILE
static uint64_t gateway_kinds[10];
uint64_t flat_memory_profile[8];
uint64_t flat_system_profile[4096][3];
static void profile_system(const struct flat_op *op)
{
    unsigned i=0;
    for(;i<4095;i++) {
        uint64_t *row=flat_system_profile[i];
        if(!row[2]){row[0]=op->word;row[1]=op->metadata;break;}
        if(row[0]==op->word && row[1]==op->metadata)break;
    }
    if(i==4095){flat_system_profile[i][0]=MASK64;flat_system_profile[i][1]=MASK64;}
    flat_system_profile[i][2]++;
}
#endif
extern void *memcpy(void *,const void *,size_t);
static uint64_t reg(struct osrec_context *c,unsigned r){return r==31?0:c->x[r];}
static uint64_t u64(const unsigned char *p){uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static void writable_data(uint64_t pc,uint64_t pa,uint64_t bytes)
{
    uint64_t lo=0,hi=flat_immutable_text_count;
    while(lo<hi){uint64_t mid=(lo+hi)/2;
        if(flat_immutable_text[mid].address+flat_immutable_text[mid].bytes<=pa)lo=mid+1;else hi=mid;}
    if(lo<flat_immutable_text_count && flat_immutable_text[lo].address<pa+bytes)
        osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,0x101,pa);
}
static uint64_t changed_user_text(void)
{
    /* AOT text is immutable. Remapping or changing permissions on any
     * admitted user code page requires new lowering, even if not yet fetched. */
    for(uint64_t i=0;i<flat_user_text_count;i++)for(uint64_t off=0;off<flat_user_text[i].bytes;off+=4096) {
        uint64_t va=flat_user_text[i].va+off;
        struct flat_translation t=flat_translate(&flat_program.memory,va,4,FLAT_EXECUTE,1);
        if(t.fault || t.pa!=flat_user_text[i].pa+off)
            return va;
    }
    return MASK64;
}
static void admit_user_text(uint64_t pc)
{
    uint64_t bad=changed_user_text();
    if(bad!=MASK64)osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,0x102,bad);
}
static flat_target target(uint64_t pc)
{
    uint64_t lo=0,hi=flat_program.pc_count;
    while(lo<hi){uint64_t mid=(lo+hi)/2;if(flat_program.pcs[mid].pc<pc)lo=mid+1;else hi=mid;}
    if(lo<flat_program.pc_count && flat_program.pcs[lo].pc==pc)return flat_program.pcs[lo].target;
    flat_full_result.missing_pc=pc;osrec_platform_stop(0x100,pc,0,0);return 0;
}
static struct flat_event *event(uint64_t pc)
{
    if(event_count==flat_program.expected_count+1024)osrec_platform_stop(OSREC_STOP_RUNTIME,pc,event_count,0);
    return flat_events+event_count++;
}
static void enter_fault(struct flat_frame *f,unsigned fault,uint64_t va,int write)
{
    if(fault>=64 && fault!=FLAT_ADDRESS_SIZE)osrec_platform_stop(OSREC_STOP_UNSUPPORTED,f->cpu.pc,fault,va);
    if(fault==FLAT_ADDRESS_SIZE)fault=0;
    uint64_t esr=(0x24ull<<26)|(1ull<<25)|((uint64_t)write<<6)|fault;
    osrec_lowered_exception(flat_program.shadow,&f->cpu,esr,va);
    if(flat_program.shadow->mode==OSREC_USER){struct flat_event *e=event(f->cpu.pc);e->exception=1;e->number=MASK64;e->args[0]=esr;e->args[1]=va;e->args[2]=f->cpu.pc;}
    osrec_enter_kernel(flat_program.shadow,&f->cpu,esr,va,flat_program.shadow->mode==OSREC_USER);
}
static flat_target step(void *opaque,struct flat_frame *f,const struct flat_site *site)
{
    (void)opaque;
    const struct flat_op *o=flat_program.ops+(site->kind>>1);unsigned post=site->kind&1;
#ifdef OSREC_FLAT_PROFILE
    if(o->kind<10)gateway_kinds[o->kind]++;
    if(o->kind==P_SYSTEM)profile_system(o);
    if(o->kind==P_MEMORY)flat_memory_profile[post?7:o->info&EXCLUSIVE?3:o->info&HINT?4:
                                          o->info&USER?2:flat_program.shadow->mode==OSREC_USER?0:1]++;
#endif
    struct osrec_context *c=&f->cpu;uint64_t info=o->info;
    unsigned rn=info&31,temp=info>>10&31;
    if(post) {
        if(o->kind==P_STACK && info&DST_SP)c->sp=c->x[temp];
        c->x[flat_memory_pending.temp]=flat_memory_pending.value;
        if(flat_memory_pending.info&WB){if(flat_memory_pending.base==31)c->sp=flat_memory_pending.writeback;else c->x[flat_memory_pending.base]=flat_memory_pending.writeback;}
        if(flat_memory_pending.uart) {
            if(uart_used==4096)osrec_platform_stop(OSREC_STOP_RUNTIME,o->pc,uart_used,0);
            flat_uart[uart_used++]=flat_uart_registers[0];
        }
        c->pc=site->pc;return site->pc==o->pc+o->metadata*4?o->following:target(site->pc);
    }
    switch(o->kind) {
    case P_MEMORY: {
        uint64_t base=info&PCREL?o->pc:rn==31?c->sp:c->x[rn],offset=o->immediate;
        if(info&REGISTER) {
            offset=reg(c,info>>5&31);unsigned ext=info>>24&7;
            if(ext==2)offset=(uint32_t)offset;
            if(ext==6)offset=(uint64_t)(int64_t)(int32_t)offset;
            offset<<=info>>27&7;
        }
        uint64_t address=base+((info&POST)?0:offset);
        unsigned bytes=(1u<<(info>>15&7))*((info&(1ull<<18))?2:1),write=!(info&LOAD);
        int user=flat_program.shadow->mode==OSREC_USER || !!(info&USER);
        if((info&(EXCLUSIVE|ALIGNED)) && (address&(bytes-1))) {
#ifdef OSREC_FLAT_PROFILE
            flat_memory_profile[6]++;
#endif
            enter_fault(f,0x21,address,info&EXCLUSIVE?0:write);return target(c->pc);
        }
        if(flat_program.uart_va && address>=flat_program.uart_va && address-flat_program.uart_va<4096) {
#ifdef OSREC_FLAT_PROFILE
            flat_memory_profile[5]++;
#endif
            uint64_t off=address-flat_program.uart_va;
            if(user || (off!=0 && off!=0x18 && off!=0x38) || bytes>4 || (!write && off!=0x18) || (write && off==0x18))
                osrec_platform_stop(OSREC_STOP_UNSUPPORTED,c->pc,o->word,address);
            flat_memory_pending.uart=write && !off;
        } else flat_memory_pending.uart=0;
        struct flat_translation t=flat_translate(&flat_program.memory,address,bytes,info&EXCLUSIVE?FLAT_READ:write?FLAT_WRITE:FLAT_READ,user);
        if(t.fault) {
#ifdef OSREC_FLAT_PROFILE
            flat_memory_profile[6]++;
#endif
            if(info&HINT){c->pc=o->pc+o->metadata*4;return o->following;}
            enter_fault(f,t.fault,address,info&EXCLUSIVE?0:write);return target(c->pc);
        }
        if(info&EXCLUSIVE) {
            struct flat_translation writable=flat_translate(&flat_program.memory,address,bytes,FLAT_WRITE,user);
            /* A comparison may skip STXR. Do not invent a store permission
             * fault before executing that comparison; stop for more lowering. */
            if(writable.fault)osrec_platform_stop(OSREC_STOP_UNSUPPORTED,c->pc,writable.fault,address);
        }
        if(write && !(info&HINT))writable_data(c->pc,t.pa,bytes);
        flat_memory_pending.temp=temp;flat_memory_pending.value=c->x[temp];flat_memory_pending.base=rn;flat_memory_pending.info=info;flat_memory_pending.writeback=base+offset;
        c->x[temp]=(uintptr_t)t.data;return o->native;
    }
    case P_STACK:
        flat_memory_pending.temp=temp;flat_memory_pending.value=c->x[temp];flat_memory_pending.info=0;flat_memory_pending.uart=0;
        c->x[temp]=info&SRC_SP?c->sp:0;return o->native;
    case P_SYSTEM:
        if(o->metadata&0x40000000ull){struct osrec_site s={o->pc,(uint32_t)o->word,(uint32_t)o->metadata};osrec_lowered_site(flat_program.shadow,c,&s);}
        else osrec_emulate_site(flat_program.shadow,c,(uint32_t)o->word);
        if(flat_program.shadow->mode==OSREC_USER)admit_user_text(c->pc);
        return target(c->pc);
    case P_INDIRECT: {
        uint64_t pc=reg(c,rn);
        if((o->word&0xfffffc1full)==0xd63f0000)c->x[30]=o->pc+4;
        c->pc=pc;return target(pc);
    }
    case P_SVC: {
        if(flat_program.shadow->mode!=OSREC_USER)osrec_platform_stop(OSREC_STOP_UNSUPPORTED,c->pc,o->word,0);
        flat_observer_pending.event=event(c->pc);flat_observer_pending.event->number=c->x[8];for(unsigned i=0;i<6;i++)flat_observer_pending.event->args[i]=c->x[i];
        flat_observer_pending.regs=flat_program.shadow->sp_el1-0x150;
        if(!osrec_enter_syscall(flat_program.shadow,c,(uint32_t)o->word,OSREC_ENTRY_VENEER))osrec_platform_stop(OSREC_STOP_RUNTIME,c->pc,o->word,0);
        return target(c->pc);
    }
    case P_OBSERVE:
        if(flat_observer_pending.event){struct flat_translation t=flat_translate(&flat_program.memory,flat_observer_pending.regs,8,FLAT_READ,0);
            if(t.fault)osrec_platform_stop(OSREC_STOP_RUNTIME,c->pc,t.fault,flat_observer_pending.regs);
            flat_observer_pending.event->result=u64(t.data);flat_observer_pending.event->completed=1;flat_observer_pending.event=0;}
        return o->native;
    case P_BOUNDARY:osrec_platform_stop(OSREC_STOP_BOUNDARY,c->pc,o->word,0);break;
    case P_COVERAGE:flat_full_result.missing_pc=c->pc;osrec_platform_stop(0x100,c->pc,o->word,0);break;
    default:osrec_platform_stop(OSREC_STOP_UNSUPPORTED,c->pc,o->word,0);
    }
    return 0;
}
uint64_t lk_native_counter(uint64_t pc,unsigned key)
{
    if(counter_used==flat_program.counter_count || flat_program.counters[counter_used].pc!=pc || flat_program.counters[counter_used].key!=key)
        osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,key,counter_used);
    return flat_program.counters[counter_used++].value;
}
void lk_native_zero(uint64_t pc,uint64_t address)
{
    uint64_t dczid=flat_program.shadow->value[0xd807];
    if(dczid&16 || (dczid&15)>9)osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,dczid,address);
    unsigned bytes=4u<<(dczid&15);address&=~(uint64_t)(bytes-1);
    struct flat_translation t=flat_translate(&flat_program.memory,address,bytes,FLAT_WRITE,0);
    if(t.fault)osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,t.fault,address);
    writable_data(pc,t.pa,bytes);
    for(unsigned i=0;i<bytes;i++)t.data[i]=0;
}
void osrec_platform_set_ttbr0(uint64_t v){flat_program.memory.ttbr0=v;}
void osrec_platform_set_ttbr1(uint64_t v){(void)v;}
void osrec_platform_tlb_flush(void){}
void osrec_platform_icache_flush(void){} /* Immutable AOT text; no generated target code. */
void osrec_platform_dcache_clean_invalidate(uint64_t v){(void)v;}
void osrec_platform_set_tpidrro(uint64_t v){(void)v;}
uint64_t osrec_platform_translate(uint64_t va,int op)
{
    struct flat_translation t=flat_translate(&flat_program.memory,va,1,op&1?FLAT_WRITE:FLAT_READ,op>=2);
    return t.fault?1|((uint64_t)(t.fault<64?t.fault:0)<<1):t.pa&~4095ull;
}
void osrec_platform_stop(uint64_t reason,uint64_t pc,uint64_t detail,uint64_t far)
{flat_full_result.reason=reason;flat_full_result.pc=pc;flat_full_result.detail=detail;flat_full_result.far=far;flat_fail(FLAT_BOUNDARY);}
static int equal(const struct flat_event *a,const struct flat_event *b)
{
    if(a->exception!=b->exception || a->number!=b->number || a->completed!=b->completed || (a->completed && a->result!=b->result))return 0;
    for(unsigned i=0;i<6;i++)if(a->args[i]!=b->args[i])return 0;return 1;
}
int flat_main(void)
{
    flat_full_result.magic=0x324c55464652534full;flat_full_result.version=2;flat_full_result.first_mismatch=MASK64;
    flat_program_initialize();
    uint64_t bad=changed_user_text();
    if(bad!=MASK64){flat_full_result.status=2;flat_full_result.reason=OSREC_STOP_UNSUPPORTED;
        flat_full_result.pc=flat_initial.cpu.pc;flat_full_result.detail=0x102;flat_full_result.far=bad;return 1;}
    /* Resolve before entering: the builder always includes the initial PC. */
    flat_target entry=0;for(uint64_t i=0;i<flat_program.pc_count;i++)if(flat_program.pcs[i].pc==flat_initial.cpu.pc){entry=flat_program.pcs[i].target;break;}
    if(!entry){flat_full_result.status=2;return 1;}
    uint64_t transitions=0;
    enum flat_status status=flat_run(&flat_initial,entry,runtime_stack,sizeof runtime_stack,100000000,step,0,&transitions);
    int okay=status==FLAT_BOUNDARY && flat_full_result.reason==OSREC_STOP_BOUNDARY && flat_full_result.pc==flat_program.stop_pc;
    uint64_t expected=0;
    for(uint64_t i=0;i<event_count;i++) {
        if(i && flat_events[i].exception && flat_events[i-1].exception && flat_events[i].args[0]==flat_events[i-1].args[0] &&
           flat_events[i].args[1]==flat_events[i-1].args[1] && flat_events[i].args[2]==flat_events[i-1].args[2])continue;
        if(expected>=flat_program.expected_count || !equal(flat_events+i,flat_program.expected+expected)){
            if(flat_full_result.first_mismatch==MASK64)flat_full_result.first_mismatch=i;okay=0;}
        expected++;
    }
    if(expected!=flat_program.expected_count || counter_used!=flat_program.counter_count || uart_used!=flat_expected_uart_bytes)okay=0;
    for(uint64_t i=0;i<uart_used && i<flat_expected_uart_bytes;i++)if(flat_uart[i]!=flat_expected_uart[i])okay=0;
    flat_full_result.events=event_count;flat_full_result.expected=flat_program.expected_count;flat_full_result.transitions=transitions;
    flat_full_result.counters=counter_used;flat_full_result.uart_bytes=uart_used;
    flat_full_result.debug[0]=flat_initial.cpu.pc;for(unsigned i=0;i<12;i++)flat_full_result.debug[i+1]=flat_initial.cpu.x[i];
#ifdef OSREC_FLAT_PROFILE
    flat_full_result.debug[13]=0x31464f525052534full;
    for(unsigned i=0;i<10;i++)flat_full_result.debug[14+i]=gateway_kinds[i];
#endif
    flat_full_result.status=okay?1:2;return okay?0:1;
}
