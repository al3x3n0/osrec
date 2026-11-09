/* A bounded first native kernel checkpoint for the EL0-only backend.
 * The generated islands contain the captured kernel's actual instructions.
 * Only MRS, address adaptation and logical return enter this C runtime.
 * No adapter runs between the original LDXR and STLXR instructions. */
#include "el0_flat_image.h"
extern int flat_gateway_selftest(void);
extern void flat_image_initialize(void);
extern void umask_entry(void),umask_load_arg(void),umask_load_fs(void),umask_arithmetic(void),umask_atomic(void),umask_tail(void);
static unsigned char stack[65536] __attribute__((aligned(16)));
volatile struct flat_result flat_result;
static uint64_t saved_arg,saved_atomic;

static uint64_t loadq(const unsigned char *p)
{uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static uint64_t loadw(const unsigned char *p)
{uint64_t v=0;for(unsigned i=0;i<4;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static unsigned char *access(struct flat_frame *f,uint64_t va,size_t bytes,enum flat_access op)
{
    struct flat_translation t=flat_translate(&flat_image.memory,va,bytes,op,0);
    if(t.fault){flat_result.reason=FLAT_FAULT;flat_result.pc=f->cpu.pc;flat_result.far=va;flat_result.detail=t.fault;flat_fail(FLAT_FAULT);}
    return t.data;
}
static flat_target step(void *opaque,struct flat_frame *f,const struct flat_site *site)
{
    (void)opaque;
    switch(site->kind) {
    case 1: /* Original MRS SP_EL0, through the shared architecture emulator. */
        osrec_emulate_site(flat_image.shadow,&f->cpu,site->word);
        saved_arg=f->cpu.x[0];f->cpu.x[0]=(uintptr_t)access(f,saved_arg,4,FLAT_READ);
        return umask_load_arg;
    case 2:
        f->cpu.x[0]=saved_arg;
        f->cpu.x[8]=(uintptr_t)access(f,f->cpu.x[8]+0x638,8,FLAT_READ)-0x638;
        return umask_load_fs;
    case 3:return umask_arithmetic;
    case 4:
        saved_atomic=f->cpu.x[8];
        (void)access(f,saved_atomic,4,FLAT_READ);
        f->cpu.x[8]=(uintptr_t)access(f,saved_atomic,4,FLAT_WRITE);
        if(f->cpu.x[8]&3)flat_fail(FLAT_BOUNDARY);
        return umask_atomic;
    case 5:f->cpu.x[8]=saved_atomic;return umask_tail;
    case 6:f->cpu.pc=f->cpu.x[30];return 0;
    default:flat_fail(FLAT_BOUNDARY);
    }
}
/* Shared-core platform hooks change software state only. Unused architecture
 * actions stop explicitly rather than reaching hardware or a host service. */
void osrec_platform_set_ttbr0(uint64_t v){flat_image.memory.ttbr0=v;}
void osrec_platform_set_ttbr1(uint64_t v){osrec_platform_stop(OSREC_STOP_UNSUPPORTED,0,v,0);}
void osrec_platform_tlb_flush(void){} /* No hardware TLB is used by the software walker. */
void osrec_platform_icache_flush(void){osrec_platform_stop(OSREC_STOP_UNSUPPORTED,0,0,0);}
void osrec_platform_dcache_clean_invalidate(uint64_t v){osrec_platform_stop(OSREC_STOP_UNSUPPORTED,0,v,0);}
uint64_t osrec_platform_translate(uint64_t va,int op)
{
    struct flat_translation t=flat_translate(&flat_image.memory,va,1,op&1?FLAT_WRITE:FLAT_READ,op>=2);
    return t.fault?1|((uint64_t)(t.fault<64?t.fault:0)<<1):t.pa&~4095ull;
}
void osrec_platform_set_tpidrro(uint64_t v){(void)v;} /* The core already stored the logical register in RAM. */
void osrec_platform_stop(uint64_t reason,uint64_t pc,uint64_t detail,uint64_t far)
{flat_result.reason=reason;flat_result.pc=pc;flat_result.detail=detail;flat_result.far=far;flat_fail(FLAT_BOUNDARY);}
static unsigned char *lookup(uint64_t va,size_t bytes,enum flat_access op)
{struct flat_translation t=flat_translate(&flat_image.memory,va,bytes,op,0);return t.fault?0:t.data;}
static int run(void)
{
    int check=flat_gateway_selftest();if(check){flat_result.gateway_checks=check;return 1;}
    flat_result.gateway_checks=1;
    unsigned char *p=lookup(flat_image.task_slot,8,FLAT_READ);if(!p)return 2;
    uint64_t task=loadq(p);p=lookup(task+0x638,8,FLAT_READ);if(!p)return 3;
    uint64_t fs=loadq(p),mask_at=fs+12;
    p=lookup(mask_at,4,FLAT_READ);if(!p)return 4;
    uint64_t expected=loadw(p);if(expected>511)return 5;
    flat_result.initial_mask=expected;
    flat_image.shadow->sp_el0=task;flat_image.shadow->mode=OSREC_KERNEL;
    unsigned char *argument=lookup(flat_image.regs,8,FLAT_WRITE);if(!argument)return 6;
    const uint64_t inputs[6]={077,0,01777,UINT64_MAX,0x1234,022};
    for(unsigned i=0;i<6;i++) {
        for(unsigned j=0;j<8;j++)argument[j]=(unsigned char)(inputs[i]>>(8*j));
        struct flat_frame f=flat_image.initial;
        f.cpu.pc=flat_image.entry;f.cpu.x[0]=flat_image.regs;f.cpu.x[30]=0x200100;
        f.cpu.sp=flat_image.regs;uint64_t transitions=0;
        if(flat_run(&f,umask_entry,stack,sizeof stack,32,step,0,&transitions)!=FLAT_OK)return 7;
        flat_result.transitions+=transitions;
        p=lookup(mask_at,4,FLAT_READ);if(!p)return 8;
        uint64_t actual=loadw(p),next=inputs[i]&511;
        flat_result.call[i].input=inputs[i];flat_result.call[i].returned=f.cpu.x[0];
        flat_result.call[i].mask=actual;flat_result.call[i].pc=f.cpu.pc;
        if(f.cpu.x[0]!=expected || actual!=next || f.cpu.pc!=0x200100 || f.cpu.sp!=flat_image.regs ||
           f.cpu.x[8]!=mask_at || f.cpu.x[9]!=next || f.cpu.x[10] || f.cpu.x[11]!=expected ||
           f.cpu.pstate!=flat_image.initial.cpu.pstate || f.fpsr!=flat_image.initial.fpsr || f.fpcr!=flat_image.initial.fpcr)return 9;
        for(unsigned r=1;r<31;r++)if((r<8 || r>11) && r!=30 && f.cpu.x[r]!=flat_image.initial.cpu.x[r])return 10;
        for(unsigned r=0;r<32;r++)for(unsigned j=0;j<16;j++)if(f.v[r][j]!=flat_image.initial.v[r][j])return 11;
        expected=next;flat_result.calls++;
    }
    flat_result.final_mask=expected;
    /* A missing logical mapping must stop before a native memory instruction,
     * and leave the persistent kernel state unchanged. No host signal occurs. */
    struct flat_frame bad=flat_image.initial;bad.cpu.x[0]=0x12340000;
    if(flat_run(&bad,umask_entry,stack,sizeof stack,32,step,0,0)!=FLAT_FAULT || flat_active ||
       bad.cpu.pc!=flat_image.entry+16 || flat_result.far!=0x12340000)return 12;
    p=lookup(mask_at,4,FLAT_READ);if(!p || loadw(p)!=expected)return 13;
    flat_result.fault_checks=1;
    return 0;
}
int flat_main(void)
{
    flat_result.magic=0x3154414c4652534full;flat_result.version=1;
    flat_image_initialize();
    int failure=run();flat_result.reserved[0]=(uint64_t)failure;
    flat_result.status=failure?2:1;return failure;
}
