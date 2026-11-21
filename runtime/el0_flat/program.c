/* General checkpoint execution. Every original instruction runs as native
 * code or through an architecture/address adaptation. No syscall models. */
#include "program.h"
#include "admission.h"
#include "translation_watch.h"
#ifndef OSREC_FLAT_IMMUTABLE_BITMAP
/* Older exports and host fixtures select this optional table at link time. */
#define OSREC_FLAT_IMMUTABLE_BITMAP 1
#endif
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
const uint64_t flat_validation_enabled=OSREC_FLAT_VALIDATION;
const uint64_t flat_translation_tracking=OSREC_TRACK_PRETRANSLATED_WRITES;
#if OSREC_TRACK_PRETRANSLATED_WRITES
uint64_t flat_translation_dirty=1;
#endif
static unsigned char runtime_stack[131072] __attribute__((aligned(16)));
struct flat_memory_pending flat_memory_pending;
#if OSREC_FLAT_VALIDATION
struct flat_observer_pending flat_observer_pending;
#endif
uint64_t flat_event_count;
uint64_t flat_uart_used;
uint64_t flat_counter_used;
static struct flat_stack_index stack_index;
/* PC indices and domain ranges are linked read-only. Never cache the legacy
 * caller-supplied PC table; live stack admission remains mandatory on a hit. */
struct flat_cached_resume {
    uint64_t pc,mode,native_stack,range_count,index_count;
    flat_target resume;
};
static struct flat_cached_resume target_cache;
extern const struct flat_mapping flat_maps[] __attribute__((weak));
#if OSREC_FLAT_IMMUTABLE_BITMAP
static uint64_t bitmap_ram_base,bitmap_ram_bytes;
extern const unsigned char flat_immutable_page_bits[] __attribute__((weak));
#endif
/* Old exports select the logical-SP backend. New exports can override these
 * weak defaults without changing the flat_full_image ABI. */
__attribute__((weak)) uint64_t flat_native_kernel_stack;
__attribute__((weak)) uint64_t flat_native_stack_range_count;
__attribute__((weak)) uint64_t flat_pc_index_count;
extern const uint64_t flat_native_stack_ranges[][2];
__attribute__((weak)) uint64_t flat_pretranslated_memory;
__attribute__((weak)) uint64_t flat_pretranslated_binding_count;
struct pretranslated_binding {uint64_t va,pa,bytes,attrs;};
extern const struct pretranslated_binding flat_pretranslated_bindings[];
__attribute__((weak)) uint64_t flat_pretranslated_root,flat_pretranslated_tcr,flat_pretranslated_check_count;
extern const struct pretranslated_check flat_pretranslated_checks[];
#if !OSREC_FLAT_VALIDATION
extern const uint64_t flat_user_resume_ranges[][2];
#endif
#if OSREC_FLAT_VALIDATION
struct flat_user_return_state flat_user_return_state;
static void remember_user(const struct osrec_context *c,int syscall)
{
    if(!flat_pretranslated_memory)return;
    flat_copy_user_context(&flat_user_return_state.entry,c);
    flat_user_return_state.valid=1;flat_user_return_state.syscall=syscall;
}
#endif
static int native_stack_pc(uint64_t pc)
{
    for(uint64_t i=0;i<flat_native_stack_range_count;i++)
        if(pc>=flat_native_stack_ranges[i][0] && pc<flat_native_stack_ranges[i][1])return 1;
    return 0;
}
#ifdef OSREC_FLAT_PROFILE
#include "profiling.h"
static uint64_t gateway_kinds[10];
uint64_t flat_memory_profile[8];
uint64_t flat_system_profile[4096][3];
static struct flat_profile_cache system_profile_cache;
static void profile_system(const struct flat_op *op)
{
    flat_profile_system(&system_profile_cache,flat_system_profile,op->word,op->metadata);
}
#endif
extern void *memcpy(void *,const void *,size_t);
static uint64_t reg(struct osrec_context *c,unsigned r){return r==31?0:c->x[r];}
#if OSREC_FLAT_VALIDATION
static uint64_t u64(const unsigned char *p){uint64_t v;__builtin_memcpy(&v,p,sizeof v);return v;}
#endif
static void writable_data(uint64_t pc,uint64_t pa,uint64_t bytes)
{
#if OSREC_TRACK_PRETRANSLATED_WRITES || OSREC_FLAT_IMMUTABLE_BITMAP
    const struct flat_ram *ram=flat_program.memory.ram;
#endif
#if OSREC_TRACK_PRETRANSLATED_WRITES
    if(!flat_translation_dirty && pa>=ram->pa && bytes<=ram->bytes && pa-ram->pa<=ram->bytes-bytes &&
       flat_translation_write_overlaps(flat_pretranslated_checks,flat_pretranslated_check_count,
                                        (uintptr_t)ram->data+pa-ram->pa,bytes))flat_translation_dirty=1;
#endif
#if OSREC_FLAT_IMMUTABLE_BITMAP
    if(flat_immutable_page_bits && ram->pa==bitmap_ram_base && ram->bytes==bitmap_ram_bytes &&
       bytes && pa>=ram->pa && bytes<=ram->bytes && pa-ram->pa<=ram->bytes-bytes) {
        uint64_t first=(pa-ram->pa)>>12,last=(pa-ram->pa+bytes-1)>>12;
        if(last-first<=1) {
            if(!(flat_immutable_page_bits[first>>3]>>(first&7)&1) &&
               !(flat_immutable_page_bits[last>>3]>>(last&7)&1))return;
        }
    }
#endif
    uint64_t lo=0,hi=flat_immutable_text_count;
    while(lo<hi){uint64_t mid=(lo+hi)/2;
        if(flat_immutable_text[mid].address+flat_immutable_text[mid].bytes<=pa)lo=mid+1;else hi=mid;}
    if(lo<flat_immutable_text_count && flat_immutable_text[lo].address<pa+bytes)
        osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,0x101,pa);
}
#if !OSREC_FLAT_MACOS_DIRECT_MEMORY
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
#endif
static int changed_pretranslated_binding(uint64_t *detail)
{
    if((flat_program.memory.ttbr0&0x0000fffffffff000ull)!=flat_pretranslated_root || flat_program.memory.tcr!=flat_pretranslated_tcr) {
        *detail=flat_program.memory.ttbr0;
        return 1;
    }
#if OSREC_TRACK_PRETRANSLATED_WRITES
    if(flat_translation_dirty) {
#endif
    for(uint64_t i=0;i<flat_pretranslated_check_count;i++) {
        const struct pretranslated_check *check=flat_pretranslated_checks+i;
        if((*check->address^check->value)&check->mask){*detail=i;return 1;}
    }
#if OSREC_TRACK_PRETRANSLATED_WRITES
    flat_translation_dirty=0;
    }
#endif
    return 0;
}
static void admit_user_text(uint64_t pc)
{
#if !OSREC_FLAT_MACOS_DIRECT_MEMORY
    if(!flat_pretranslated_memory) {
        uint64_t bad=changed_user_text();
        if(bad!=MASK64)osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,0x102,bad);
        return;
    }
#endif
    uint64_t changed;
    if(changed_pretranslated_binding(&changed))osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,0x105,changed);
#if !OSREC_FLAT_VALIDATION
    uint64_t sp=flat_active->live->cpu.sp;int admitted=0;
    if(sp>=64 && !(sp&15))for(uint64_t i=0;flat_user_resume_ranges[i][1];i++)
        if(sp-64>=flat_user_resume_ranges[i][0] && sp<=flat_user_resume_ranges[i][1]){admitted=1;break;}
    if(!admitted)osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,0x104,sp);
#endif
#if OSREC_FLAT_VALIDATION
    if(flat_user_return_state.valid) {
        const struct osrec_context *c=&flat_active->live->cpu;
        if(flat_user_context_difference(c,&flat_user_return_state.entry,flat_user_return_state.syscall)) {
            for(unsigned r=flat_user_return_state.syscall?1:0;r<31;r++)
                if(c->x[r]!=flat_user_return_state.entry.x[r])osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,0x106,r);
            osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,0x107,c->sp);
        }
        if(c->pc!=flat_user_return_state.entry.pc+(flat_user_return_state.syscall?4:0))
            osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,0x107,c->sp);
        flat_user_return_state.valid=0;
    }
#endif
}
static __attribute__((noinline)) flat_target target_slow(uint64_t pc)
{
    if(flat_native_kernel_stack && native_stack_pc(pc)!=(flat_program.shadow->mode==OSREC_KERNEL))
        osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,0x103,flat_program.shadow->mode);
    if(flat_native_kernel_stack && flat_program.shadow->mode==OSREC_KERNEL) {
        uint64_t sp=flat_active->live->cpu.sp;
        if(!flat_stack_admitted(&stack_index,&flat_program.memory,sp)) {
            const struct flat_mapping *m=flat_stack_mapping(&stack_index,&flat_program.memory,sp);
            if(!m)osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,0x104,sp);
            writable_data(pc,m->pa+sp-64-m->va,64);
            flat_stack_admission_remember(&stack_index,&flat_program.memory,sp);
        }
    }
    if(flat_pc_index_count) {
        if(!(pc&3))for(uint64_t i=0;i<flat_pc_index_count;i++) {
            const struct flat_pc_index *index=flat_pc_indices+i;
            uint64_t offset=pc-index->base;
            if(offset>=index->bytes)continue;
            const struct flat_pc_index_entry *page=index->pages[offset>>12];
            if(page && page[offset>>2&1023].context) {
                flat_target resume=page[offset>>2&1023].context;
                if(flat_program.shadow) {
                    target_cache.pc=pc;target_cache.mode=flat_program.shadow->mode;
                    target_cache.native_stack=flat_native_kernel_stack;
                    target_cache.range_count=flat_native_stack_range_count;
                    target_cache.index_count=flat_pc_index_count;target_cache.resume=resume;
                }
                return resume;
            }
        }
    } else {
        uint64_t lo=0,hi=flat_program.pc_count;
        while(lo<hi){uint64_t mid=(lo+hi)/2;if(flat_program.pcs[mid].pc<pc)lo=mid+1;else hi=mid;}
        if(lo<flat_program.pc_count && flat_program.pcs[lo].pc==pc)return flat_program.pcs[lo].target;
    }
    flat_full_result.missing_pc=pc;osrec_platform_stop(0x100,pc,0,0);return 0;
}
static flat_target target(uint64_t pc)
{
    struct flat_cached_resume *cache=&target_cache;
    /* Keep one address operand for this aggregate's loads. This emits no
     * instruction and avoids a separate global relocation for every field. */
    __asm__("" : "+r"(cache));
    if(!cache->resume || !cache->index_count)return target_slow(pc);
    /* All four inputs are scalar fields in live internal control objects.
     * Eager scalar comparisons avoid a branch between each field load; no
     * guest pointer is dereferenced until this binding guard succeeds. */
    int binding=flat_equal4(cache->pc,pc,cache->native_stack,flat_native_kernel_stack,
                            cache->range_count,flat_native_stack_range_count,
                            cache->index_count,flat_pc_index_count);
    if(binding && flat_program.shadow &&
       cache->mode==flat_program.shadow->mode &&
       (!flat_native_kernel_stack || flat_program.shadow->mode!=OSREC_KERNEL ||
        flat_stack_admitted(&stack_index,&flat_program.memory,flat_active->live->cpu.sp)))
        return cache->resume;
    return target_slow(pc);
}
#if OSREC_FLAT_VALIDATION
static struct flat_event *event(uint64_t pc)
{
    if(flat_event_count==flat_program.expected_count+1024)osrec_platform_stop(OSREC_STOP_RUNTIME,pc,flat_event_count,0);
    return flat_events+flat_event_count++;
}
#endif
static void enter_fault(struct flat_frame *f,unsigned fault,uint64_t va,int write)
{
    if(fault>=64 && fault!=FLAT_ADDRESS_SIZE)osrec_platform_stop(OSREC_STOP_UNSUPPORTED,f->cpu.pc,fault,va);
    if(fault==FLAT_ADDRESS_SIZE)fault=0;
    uint64_t esr=(0x24ull<<26)|(1ull<<25)|((uint64_t)write<<6)|fault;
    osrec_lowered_exception(flat_program.shadow,&f->cpu,esr,va);
#if OSREC_FLAT_VALIDATION
    if(flat_program.shadow->mode==OSREC_USER){remember_user(&f->cpu,0);struct flat_event *e=event(f->cpu.pc);e->exception=1;e->number=MASK64;e->args[0]=esr;e->args[1]=va;e->args[2]=f->cpu.pc;}
#endif
    osrec_enter_kernel(flat_program.shadow,&f->cpu,esr,va,flat_program.shadow->mode==OSREC_USER);
}
static __attribute__((noinline)) flat_target step_memory(struct flat_frame *f,const struct flat_op *o)
{
    struct osrec_context *c=&f->cpu;uint64_t info=o->info;
    unsigned rn=info&31,temp=info>>10&31;
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
    int uart=flat_program.uart_va && address>=flat_program.uart_va && address-flat_program.uart_va<4096;
    if(uart) {
#ifdef OSREC_FLAT_PROFILE
        flat_memory_profile[5]++;
#endif
        uint64_t off=address-flat_program.uart_va;
        if(user || (off!=0 && off!=0x18 && off!=0x38) || bytes>4 || (!write && off!=0x18) || (write && off==0x18))
            osrec_platform_stop(OSREC_STOP_UNSUPPORTED,c->pc,o->word,address);
        flat_memory_pending.uart=write && !off;
    } else flat_memory_pending.uart=0;
#if OSREC_FLAT_MACOS_DIRECT_MEMORY
    if(!uart)osrec_platform_stop(OSREC_STOP_UNSUPPORTED,c->pc,0x109,address);
    struct flat_translation t={.data=flat_uart_registers+address-flat_program.uart_va};
#else
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
#endif
    flat_memory_pending.temp=temp;flat_memory_pending.value=c->x[temp];flat_memory_pending.base=rn;flat_memory_pending.info=info;flat_memory_pending.writeback=base+offset;
    c->x[temp]=(uintptr_t)t.data;return o->native;
}
static __attribute__((noinline)) flat_target step_system(struct flat_frame *f,const struct flat_op *o)
{
    struct osrec_context *c=&f->cpu;
#ifdef OSREC_FLAT_PROFILE
    gateway_kinds[P_SYSTEM]++;profile_system(o);
#endif
    if(o->metadata&0x40000000ull){struct osrec_site s={o->pc,(uint32_t)o->word,(uint32_t)o->metadata};osrec_lowered_site(flat_program.shadow,c,&s);}
    else osrec_emulate_site(flat_program.shadow,c,(uint32_t)o->word);
    if(flat_program.shadow->mode==OSREC_USER)admit_user_text(c->pc);
    return target(c->pc);
}
static __attribute__((noinline)) flat_target step_syscall(struct flat_frame *f,const struct flat_op *o)
{
    struct osrec_context *c=&f->cpu;
#ifdef OSREC_FLAT_PROFILE
    gateway_kinds[P_SVC]++;
#endif
    if(flat_program.shadow->mode!=OSREC_USER)osrec_platform_stop(OSREC_STOP_UNSUPPORTED,c->pc,o->word,0);
#if OSREC_FLAT_VALIDATION
    flat_observer_pending.event=event(c->pc);flat_observer_pending.event->number=c->x[8];
    __builtin_memcpy(flat_observer_pending.event->args,c->x,sizeof flat_observer_pending.event->args);
    flat_observer_pending.regs=flat_program.shadow->sp_el1-0x150;
    remember_user(c,1);
#endif
    if(!osrec_enter_syscall(flat_program.shadow,c,(uint32_t)o->word,OSREC_ENTRY_VENEER))osrec_platform_stop(OSREC_STOP_RUNTIME,c->pc,o->word,0);
    return target(c->pc);
}
static __attribute__((noinline)) flat_target step_other(struct flat_frame *f,const struct flat_site *site,const struct flat_op *o)
{
    unsigned post=site->kind&1;
#ifdef OSREC_FLAT_PROFILE
    if(o->kind<10)gateway_kinds[o->kind]++;
    if(o->kind==P_SYSTEM)profile_system(o);
    if(o->kind==P_MEMORY)flat_memory_profile[post?7:o->info&EXCLUSIVE?3:o->info&HINT?4:
                                          o->info&USER?2:flat_program.shadow->mode==OSREC_USER?0:1]++;
#endif
    struct osrec_context *c=&f->cpu;
    if(post) {
        uint64_t info=o->info;unsigned temp=info>>10&31;
        if(o->kind==P_STACK && info&DST_SP)c->sp=c->x[temp];
        c->x[flat_memory_pending.temp]=flat_memory_pending.value;
        if(flat_memory_pending.info&WB){if(flat_memory_pending.base==31)c->sp=flat_memory_pending.writeback;else c->x[flat_memory_pending.base]=flat_memory_pending.writeback;}
        if(flat_memory_pending.uart) {
            if(flat_uart_used==4096)osrec_platform_stop(OSREC_STOP_RUNTIME,o->pc,flat_uart_used,0);
            flat_uart[flat_uart_used++]=flat_uart_registers[0];
        }
        c->pc=site->pc;return site->pc==o->pc+o->metadata*4?o->following:target(site->pc);
    }
    switch(o->kind) {
    case P_MEMORY:return step_memory(f,o);
    case P_STACK: {
        uint64_t info=o->info;unsigned temp=info>>10&31;
        flat_memory_pending.temp=temp;flat_memory_pending.value=c->x[temp];flat_memory_pending.info=0;flat_memory_pending.uart=0;
        c->x[temp]=info&SRC_SP?c->sp:0;return o->native;
    }
    case P_INDIRECT: {
        uint64_t pc=reg(c,o->info&31);
        if((o->word&0xfffffc1full)==0xd63f0000)c->x[30]=o->pc+4;
        c->pc=pc;return target(pc);
    }
    case P_OBSERVE:
#if OSREC_FLAT_VALIDATION
        if(flat_observer_pending.event){
#if OSREC_FLAT_MACOS_DIRECT_MEMORY
            const unsigned char *data=(const void *)(uintptr_t)flat_observer_pending.regs;
#else
            struct flat_translation t=flat_translate(&flat_program.memory,flat_observer_pending.regs,8,FLAT_READ,0);
            if(t.fault)osrec_platform_stop(OSREC_STOP_RUNTIME,c->pc,t.fault,flat_observer_pending.regs);
            const unsigned char *data=t.data;
#endif
            flat_observer_pending.event->result=u64(data);flat_observer_pending.event->completed=1;flat_observer_pending.event=0;}
#endif
        return o->native;
    case P_BOUNDARY:osrec_platform_stop(OSREC_STOP_BOUNDARY,c->pc,o->word,0);break;
    case P_COVERAGE:flat_full_result.missing_pc=c->pc;osrec_platform_stop(0x100,c->pc,o->word,0);break;
    default:osrec_platform_stop(OSREC_STOP_UNSUPPORTED,c->pc,o->word,0);
    }
    return 0;
}
static flat_target step(void *opaque,struct flat_frame *f,const struct flat_site *site)
{
    (void)opaque;
    const struct flat_op *o=flat_program.ops+(site->kind>>1);
    if(!(site->kind&1)) {
        if(o->kind==P_SYSTEM)return step_system(f,o);
        if(o->kind==P_SVC)return step_syscall(f,o);
    }
    return step_other(f,site,o);
}
uint64_t lk_native_counter(uint64_t pc,unsigned key)
{
    if(flat_counter_used>=flat_program.counter_count || flat_program.counters[flat_counter_used].pc!=pc || flat_program.counters[flat_counter_used].key!=key)
        osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,key,flat_counter_used);
    return flat_program.counters[flat_counter_used++].value;
}
void lk_native_zero(uint64_t pc,uint64_t address)
{
    uint64_t dczid=flat_program.shadow->value[0xd807];
    if(dczid&16 || (dczid&15)>9)osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,dczid,address);
#if OSREC_FLAT_MACOS_DIRECT_MEMORY
    __asm__ volatile("dc zva, %0" : : "r"(address) : "memory");
#else
    unsigned bytes=4u<<(dczid&15);address&=~(uint64_t)(bytes-1);
    struct flat_translation t=flat_translate(&flat_program.memory,address,bytes,FLAT_WRITE,0);
    if(t.fault)osrec_platform_stop(OSREC_STOP_UNSUPPORTED,pc,t.fault,address);
    writable_data(pc,t.pa,bytes);
    for(unsigned i=0;i<bytes;i++)t.data[i]=0;
#endif
}
void osrec_platform_set_ttbr0(uint64_t v){flat_program.memory.ttbr0=v;
#if OSREC_TRACK_PRETRANSLATED_WRITES
    flat_translation_dirty=1;
#endif
}
void osrec_platform_set_ttbr1(uint64_t v){(void)v;}
void osrec_platform_tlb_flush(void){}
void osrec_platform_icache_flush(void){} /* Immutable AOT text; no generated target code. */
void osrec_platform_dcache_clean_invalidate(uint64_t v){(void)v;}
void osrec_platform_set_tpidrro(uint64_t v){(void)v;}
uint64_t osrec_platform_translate(uint64_t va,int op)
{
#if OSREC_FLAT_MACOS_DIRECT_MEMORY
    osrec_platform_stop(OSREC_STOP_UNSUPPORTED,flat_active->live->cpu.pc,0x10a+(unsigned)op,va);
#else
    struct flat_translation t=flat_translate(&flat_program.memory,va,1,op&1?FLAT_WRITE:FLAT_READ,op>=2);
    return t.fault?1|((uint64_t)(t.fault<64?t.fault:0)<<1):t.pa&~4095ull;
#endif
}
void osrec_platform_stop(uint64_t reason,uint64_t pc,uint64_t detail,uint64_t far)
{flat_full_result.reason=reason;flat_full_result.pc=pc;flat_full_result.detail=detail;flat_full_result.far=far;flat_fail(FLAT_BOUNDARY);}
#if OSREC_FLAT_VALIDATION
static int equal(const struct flat_event *a,const struct flat_event *b)
{
    if(a->exception!=b->exception || a->number!=b->number || a->completed!=b->completed || (a->completed && a->result!=b->result))return 0;
    for(unsigned i=0;i<6;i++)if(a->args[i]!=b->args[i])return 0;return 1;
}
#endif
int flat_main(void)
{
    flat_full_result.magic=0x324c55464652534full;flat_full_result.version=2;flat_full_result.first_mismatch=MASK64;
    flat_program_initialize();
    flat_stack_index_init(&stack_index,&flat_program.memory,flat_maps);
    flat_memory_index_init(&flat_program.memory,flat_maps);
#if OSREC_FLAT_IMMUTABLE_BITMAP
    bitmap_ram_base=flat_program.memory.ram->pa;bitmap_ram_bytes=flat_program.memory.ram->bytes;
#endif
#if OSREC_FLAT_MACOS_DIRECT_MEMORY
    uint64_t bad;
    int changed=changed_pretranslated_binding(&bad);
#else
    uint64_t bad=changed_user_text();
    int changed=bad!=MASK64;
#endif
    if(changed){flat_full_result.status=2;flat_full_result.reason=OSREC_STOP_UNSUPPORTED;
        flat_full_result.pc=flat_initial.cpu.pc;flat_full_result.detail=0x102;flat_full_result.far=bad;return 1;}
    /* Resolve before entering: the builder always includes the initial PC. */
    flat_target entry=0;for(uint64_t i=0;i<flat_program.pc_count;i++)if(flat_program.pcs[i].pc==flat_initial.cpu.pc){entry=flat_program.pcs[i].target;break;}
    if(!entry){flat_full_result.status=2;return 1;}
    uint64_t transitions=0;
    enum flat_status status=flat_run(&flat_initial,entry,runtime_stack,sizeof runtime_stack,100000000,step,0,&transitions);
    int okay=status==FLAT_BOUNDARY && flat_full_result.reason==OSREC_STOP_BOUNDARY && flat_full_result.pc==flat_program.stop_pc;
#if OSREC_FLAT_VALIDATION
    uint64_t expected=0;
    for(uint64_t i=0;i<flat_event_count;i++) {
        if(i && flat_events[i].exception && flat_events[i-1].exception && flat_events[i].args[0]==flat_events[i-1].args[0] &&
           flat_events[i].args[1]==flat_events[i-1].args[1] && flat_events[i].args[2]==flat_events[i-1].args[2])continue;
        if(expected>=flat_program.expected_count || !equal(flat_events+i,flat_program.expected+expected)){
            if(flat_full_result.first_mismatch==MASK64)flat_full_result.first_mismatch=i;okay=0;}
        expected++;
    }
    if(expected!=flat_program.expected_count || flat_counter_used!=flat_program.counter_count || flat_uart_used!=flat_expected_uart_bytes)okay=0;
    for(uint64_t i=0;i<flat_uart_used && i<flat_expected_uart_bytes;i++)if(flat_uart[i]!=flat_expected_uart[i])okay=0;
#endif
    flat_full_result.events=flat_event_count;flat_full_result.expected=flat_program.expected_count;flat_full_result.transitions=transitions;
    flat_full_result.counters=flat_counter_used;flat_full_result.uart_bytes=flat_uart_used;
    flat_full_result.debug[0]=flat_initial.cpu.pc;for(unsigned i=0;i<12;i++)flat_full_result.debug[i+1]=flat_initial.cpu.x[i];
#ifdef OSREC_FLAT_PROFILE
    flat_full_result.debug[13]=0x31464f525052534full;
    for(unsigned i=0;i<10;i++)flat_full_result.debug[14+i]=gateway_kinds[i];
#endif
    flat_full_result.status=okay?1:2;return okay?0:1;
}
