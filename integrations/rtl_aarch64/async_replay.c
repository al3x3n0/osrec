/* QEMU virt GICv2 + physical timer. All recorder calls are serialized with IRQs
 * masked. The outer handler unmasks only after committing its input event.
 * Task switches are explicit continuation boundaries, not saved kernel stacks.
 */
#include <stdint.h>
#include <stddef.h>
#include "osrec/context.h"
#include "task_region.h"
#include "async_checkpoint.h"

volatile uint32_t osrec_result[32] __attribute__((section(".result")));
static struct completion_state completion;
static struct osrec_context_session session;
static struct osrec_buffer trace;
unsigned char osrec_async_trace[4096];
static volatile unsigned nested_done, awakened, irq_depth, max_depth, irq_count;
static uint64_t outer_id;

void *memset(void *p, int v, size_t n)
{ unsigned char *q=p; for(size_t i=0;i<n;++i)q[i]=(unsigned char)v;return p; }
void *memcpy(void *p, const void *s, size_t n)
{ unsigned char *q=p;const unsigned char *r=s;for(size_t i=0;i<n;++i)q[i]=r[i];return p; }
static void mask(void){__asm__ volatile("msr daifset, #2" ::: "memory");}
static void unmask(void){__asm__ volatile("msr daifclr, #2\n isb" ::: "memory");}
static void barrier(void){__asm__ volatile("dsb sy\n isb" ::: "memory");}
static uint64_t ticks(void){uint64_t v;__asm__ volatile("mrs %0, cntpct_el0":"=r"(v));return v;}
static uint64_t frequency(void){uint64_t v;__asm__ volatile("mrs %0, cntfrq_el0":"=r"(v));return v;}
static volatile uint32_t *reg(uintptr_t address){return (volatile uint32_t *)address;}
#define GICD UINT64_C(0x08000000)
#define GICC UINT64_C(0x08010000)
__attribute__((noreturn)) static void finish(unsigned error)
{
    mask();
    osrec_result[0]=0x4f535243;osrec_result[1]=27;osrec_result[3]=error;
    osrec_result[4]=(uint32_t)session.sequence;osrec_result[5]=irq_count;
    osrec_result[6]=max_depth;osrec_result[7]=nested_done;osrec_result[8]=awakened;
    osrec_result[9]=(uint32_t)trace.used;osrec_result[10]=(uint32_t)completion.available;
    osrec_result[11]=(uint32_t)(completion.available>>32);
    barrier();osrec_result[2]=error?3:2;barrier();
    for(;;)__asm__ volatile("wfi");
}
static void check(int ok){if(!ok)finish(1);}
#define RECORD(call) check((call)==0)
void replay_fault(void){finish(100);}

void replay_irq(void)
{
    uint32_t acknowledged=*reg(GICC+0x0c), id=acknowledged&1023;
    ++irq_count;++irq_depth;if(irq_depth>max_depth)max_depth=irq_depth;
    if(id==30){
        check(irq_depth==1 && !awakened);
        __asm__ volatile("msr cntp_ctl_el0, %0\n isb"::"r"(UINT64_C(0)):"memory");
        outer_id=osrec_irq_enter(&session,0,220);check(outer_id!=0);
        RECORD(osrec_context_value(&session,0,230,OSREC_DEVICE_VALUE,9,checkpoint_outer));
        /* SGI 1 has higher priority than timer PPI 30; target this CPU only. */
        *reg(GICD+0xf00)=(2u<<24)|1u;barrier();
        uint64_t deadline=ticks()+frequency();
        unmask();
        while(!nested_done){if(ticks()>deadline)finish(2);__asm__ volatile("yield");}
        mask();
        complete_irq(&completion,checkpoint_outer);
        RECORD(osrec_context_value(&session,0,280,OSREC_MEMORY_EFFECT,1,completion.available));
        check(completion.available>=checkpoint_demand);
        RECORD(osrec_task_wake(&session,0,290,checkpoint_wait,checkpoint_generation));
        awakened=1;
        RECORD(osrec_irq_exit(&session,0,300,outer_id));
    }else if(id==1){
        check(irq_depth==2 && !nested_done);
        uint64_t nested_id=osrec_irq_enter(&session,0,240);check(nested_id!=0);
        RECORD(osrec_context_value(&session,0,250,OSREC_DEVICE_VALUE,10,checkpoint_nested));
        complete_irq(&completion,checkpoint_nested);
        RECORD(osrec_context_value(&session,0,260,OSREC_MEMORY_EFFECT,1,completion.available));
        check(completion.available<checkpoint_demand);
        RECORD(osrec_irq_exit(&session,0,270,nested_id));
        nested_done=1;
    }else finish(3);
    --irq_depth;*reg(GICC+0x10)=acknowledged;barrier();
}

void replay_main(void)
{
    completion.available=checkpoint_available;
    RECORD(osrec_begin(&trace,osrec_async_trace,sizeof(osrec_async_trace),checkpoint_source));
    const uint64_t tasks[1]={checkpoint_selected};
    RECORD(osrec_context_init(&session,&trace,1,tasks,checkpoint_selected));
    const uint64_t inputs[2]={checkpoint_available,checkpoint_demand};
    RECORD(osrec_values(&trace,OSREC_INPUT,110,inputs,2));
    uint64_t result=0;
    check(!task_step(&completion,checkpoint_demand,&result));
    RECORD(osrec_task_block(&session,0,200,checkpoint_wait,checkpoint_generation));
    RECORD(osrec_task_switch(&session,0,210,checkpoint_selected,checkpoint_background));
    *reg(GICD)=0;*reg(GICC)=0;
    *reg(GICD+0x180)=0xffffffff;*reg(GICD+0x280)=0xffffffff;
    *(volatile unsigned char *)(GICD+0x400+30)=0x80;
    *(volatile unsigned char *)(GICD+0x400+1)=0x20;
    *reg(GICD+0x100)=(1u<<30)|(1u<<1);
    *reg(GICC+4)=0xff;*reg(GICC+8)=0;
    *reg(GICD)=1;*reg(GICC)=1;barrier();
    uint64_t interval=frequency()/1000;check(interval>0);
    __asm__ volatile("msr cntp_tval_el0, %0\n msr cntp_ctl_el0, %1\n isb"
                     ::"r"(interval),"r"(UINT64_C(1)):"memory");
    uint64_t deadline=ticks()+frequency();
    unmask();
    while(!awakened){if(ticks()>deadline)finish(4);__asm__ volatile("yield");}
    mask();check(irq_depth==0);
    RECORD(osrec_task_switch(&session,0,310,checkpoint_background,checkpoint_selected));
    check(task_step(&completion,checkpoint_demand,&result));
    RECORD(osrec_task_return(&session,0,320,result));
    const uint64_t outputs[2]={completion.available,result};
    RECORD(osrec_values(&trace,OSREC_OUTPUT,330,outputs,2));
    RECORD(osrec_context_finish(&session));
    check(trace.used==sizeof(checkpoint_trace));
    for(size_t i=0;i<trace.used;++i)check(osrec_async_trace[i]==checkpoint_trace[i]);
    osrec_result[12]=(uint32_t)result;osrec_result[13]=(uint32_t)(result>>32);
    osrec_result[14]=1; /* Full trace byte comparison passed. */
    finish(0);
}
