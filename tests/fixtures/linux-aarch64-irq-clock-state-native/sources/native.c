/* Libc-free PID 1. Tracefs observes real Linux scheduling and timer IRQs. */
#include <stdint.h>
#include <stddef.h>
static int64_t call(uint64_t nr,uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f)
{
    register uint64_t x8 __asm__("x8")=nr,x0 __asm__("x0")=a,x1 __asm__("x1")=b,
        x2 __asm__("x2")=c,x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory","cc");
    return (int64_t)x0;
}
static size_t length(const char *s){size_t n=0;while(s[n])++n;return n;}
static void output(const char *s,size_t n)
{while(n){int64_t r=call(64,1,(uintptr_t)s,n,0,0,0);if(r<=0)for(;;)__asm__ volatile("wfe");s+=r;n-=(size_t)r;}}
static void text(const char *s){output(s,length(s));}
static void number(uint64_t n){char digits[20];unsigned i=0;do{digits[i++]=(char)('0'+n%10);n/=10;}while(n);while(i)output(&digits[--i],1);}
__attribute__((noreturn)) static void shutdown(void)
{call(142,0xfee1dead,0x28121969,0x4321fedc,0,0,0);for(;;)__asm__ volatile("wfe");}
__attribute__((noreturn)) static void fail(unsigned code)
{text("OSREC_LINUX_IRQ_FAILED ");number(code);text("\n");shutdown();}
static int open_file(const char *path,unsigned flags)
{int64_t fd=call(56,(uint64_t)-100,(uintptr_t)path,flags,0,0,0);if(fd<0){text(path);text("\n");fail((unsigned)-fd);}return (int)fd;}
static size_t read_file(const char *path,char *data,size_t capacity);
static void control(const char *path,const char *value)
{
    int fd=open_file(path,0x201);size_t n=length(value);
    if(call(64,(unsigned)fd,(uintptr_t)value,n,0,0,0)!=(int64_t)n){
        char error[4096];text(path);text("\n");
        size_t used=read_file("/dev/error_log",error,sizeof(error));output(error,used);fail(1001);
    }
    if(call(57,(unsigned)fd,0,0,0,0,0))fail(1002);
}
static size_t read_file(const char *path,char *data,size_t capacity)
{
    int fd=open_file(path,0);size_t used=0;
    while(used<capacity){int64_t n=call(63,(unsigned)fd,(uintptr_t)(data+used),capacity-used,0,0,0);if(n<0)fail(1003);if(!n)break;used+=(size_t)n;}
    char extra;if(used==capacity && call(63,(unsigned)fd,(uintptr_t)&extra,1,0,0,0)!=0)fail(1004);
    if(call(57,(unsigned)fd,0,0,0,0,0))fail(1005);return used;
}
#ifdef OSREC_SLEEPER_STATE
#include "btf_sleeper.h"
static unsigned char btf_data[8*1024*1024];
static struct sleeper_layout layout;
#ifdef OSREC_TIMER_RETURN
#include "btf_timer_return.h"
static struct timer_return_layout return_layout;
#ifdef OSREC_BASE_STATE
#include "btf_base_state.h"
static struct base_state_layout base_layout;
#endif
#endif
static void capture_layout(void)
{
    if(call(40,(uintptr_t)"sysfs",(uintptr_t)"/dev",(uintptr_t)"sysfs",0,0,0))fail(1020);
    size_t n=read_file("/dev/kernel/btf/vmlinux",(char *)btf_data,sizeof(btf_data));
    if(!btf_sleeper_layout(btf_data,n,&layout))fail(1021);
#ifdef OSREC_TIMER_RETURN
    if(!btf_timer_return_layout(btf_data,n,&return_layout))fail(1024);
    text("OSREC_LINUX_IRQ_TIMER_LAYOUT {\"source\":\"native-sysfs-btf\",\"timer_type_id\":");number(return_layout.timer_type_id);
    text(",\"timer_size\":");number(return_layout.timer_size);text(",\"base_type_id\":");number(return_layout.base_type_id);
    text(",\"base_size\":");number(return_layout.base_size);text(",\"base_offset\":");number(return_layout.base_offset);
    text(",\"running_offset\":");number(return_layout.running_offset);text("}\n");
#endif
#ifdef OSREC_BASE_STATE
    if(!btf_base_state_layout(btf_data,n,&base_layout))fail(1025);
    text("OSREC_LINUX_IRQ_BASE_LAYOUT {\"source\":\"native-sysfs-btf\",\"base_type_id\":");number(base_layout.base_type_id);
    text(",\"cpu_type_id\":");number(base_layout.cpu_type_id);text(",\"cpu_size\":");number(base_layout.cpu_size);
    text(",\"cpu_base_offset\":");number(base_layout.cpu_base_offset);text(",\"index_offset\":");number(base_layout.index_offset);
    text(",\"active_offset\":");number(base_layout.active_offset);text("}\n");
#endif
    if(call(39,(uintptr_t)"/dev",0,0,0,0,0))fail(1022);
    text("OSREC_LINUX_IRQ_LAYOUT {\"source\":\"native-sysfs-btf\",\"btf_bytes\":");number(n);
    text(",\"type_id\":");number(layout.type_id);text(",\"size\":");number(layout.size);
    text(",\"task_offset\":");number(layout.task_offset);text(",\"timer_offset\":0}\n");
}
#endif
static char trace[262144],stats[4096],format[4096];
static const char *const names[]={"syscalls/sys_enter_nanosleep","syscalls/sys_exit_nanosleep",
    "sched/sched_switch","sched/sched_waking","sched/sched_wakeup",
    "timer/hrtimer_init","timer/hrtimer_start","timer/hrtimer_expire_entry",
    "timer/hrtimer_expire_exit","timer/hrtimer_cancel","irq/irq_handler_entry","irq/irq_handler_exit"
#ifdef OSREC_TASK_STATE
    ,"osrec/osrec_task_dequeue","osrec/osrec_task_wake",
    "osrec/osrec_task_activate","osrec/osrec_task_preempt"
#endif
#ifdef OSREC_SLEEPER_STATE
    ,"osrec/osrec_sleeper_entry","osrec/osrec_sleeper_callback","osrec/osrec_sleeper_callback_return","osrec/osrec_sleeper_return"
#endif
#ifdef OSREC_TIMER_STATE
    ,"osrec/osrec_timer_callback"
#endif
#ifdef OSREC_TIMER_RETURN
    ,"osrec/osrec_timer_return"
#endif
#ifdef OSREC_BASE_STATE
    ,"osrec/osrec_base_callback","osrec/osrec_base_return"
#endif
#ifdef OSREC_OUTER_STATE
    ,"osrec/osrec_outer_callback"
#endif
#ifdef OSREC_CLOCK_STATE
    ,"osrec/osrec_clock_return"
#endif
};
#ifdef OSREC_TASK_STATE
#define TASK_FIELDS " task=p:x64 pid=p->pid:s32 state=p->__state:u32 saved=p->saved_state:u32 on_rq=p->on_rq:u32 on_cpu=p->on_cpu:u32\n"
static const char task_probes[]=
    "p:osrec/osrec_task_dequeue dequeue_task_fair" TASK_FIELDS
    "p:osrec/osrec_task_wake wake_up_process" TASK_FIELDS
    "p:osrec/osrec_task_activate activate_task" TASK_FIELDS
    "p:osrec/osrec_task_preempt wakeup_preempt" TASK_FIELDS;
#ifdef OSREC_SLEEPER_STATE
static char probes[4096];
static void make_probes(void)
{
    size_t at=0;unsigned offset_index=0;
    const uint32_t offsets[]={layout.task_offset,layout.task_offset,layout.task_offset
#ifdef OSREC_TIMER_RETURN
        ,return_layout.base_offset,return_layout.running_offset,return_layout.base_offset
#endif
#ifdef OSREC_BASE_STATE
        ,return_layout.base_offset,base_layout.cpu_base_offset,return_layout.base_offset,
        base_layout.index_offset,return_layout.base_offset,
        base_layout.active_offset,base_layout.cpu_base_offset,return_layout.base_offset
#endif
    };
    const char *parts[]={task_probes,
        "p:osrec/osrec_sleeper_entry do_nanosleep object=t:x64 task=t->task:x64\n",
        "p:osrec/osrec_sleeper_callback hrtimer_wakeup object=$arg1:x64 task=+",
        NULL,"($arg1):x64\nr8:osrec/osrec_sleeper_callback_return hrtimer_wakeup object=$arg1:x64 task=+",
        NULL,"($arg1):x64 result=$retval:s32\nr8:osrec/osrec_sleeper_return do_nanosleep object=$arg1:x64 task=+",
        NULL,"($arg1):x64 result=$retval:s32\n"
#ifdef OSREC_TIMER_STATE
        ,"p:osrec/osrec_timer_callback hrtimer_wakeup object=timer:x64 base=timer->base:x64 running=timer->base->running:x64 state=timer->state:u8\n"
#endif
#ifdef OSREC_TIMER_RETURN
        ,"r8:osrec/osrec_timer_return do_nanosleep object=$arg1:x64 base=+",NULL,
        "($arg1):x64 running=+",NULL,"(+",NULL,"($arg1)):x64 result=$retval:s32\n"
#endif
#ifdef OSREC_BASE_STATE
        ,"p:osrec/osrec_base_callback hrtimer_wakeup object=timer:x64 base=timer->base:x64 cpu_base=timer->base->cpu_base:x64 index=timer->base->index:u32 active=timer->base->cpu_base->active_bases:u32\n",
        "r8:osrec/osrec_base_return do_nanosleep object=$arg1:x64 base=+",NULL,
        "($arg1):x64 cpu_base=+",NULL,"(+",NULL,"($arg1)):x64 index=+",NULL,"(+",NULL,
        "($arg1)):u32 active=+",NULL,"(+",NULL,"(+",NULL,"($arg1))):u32 result=$retval:s32\n"
#endif
#ifdef OSREC_OUTER_STATE
        ,"p:osrec/osrec_outer_callback hrtimer_wakeup object=timer:x64 cpu_base=timer->base->cpu_base:x64 deadline=timer->base->cpu_base->softirq_expires_next:s64 activated=timer->base->cpu_base->softirq_activated\n"
#endif
#ifdef OSREC_CLOCK_STATE
        ,"r8:osrec/osrec_clock_return ktime_get_update_offsets_now seq=$arg1:x64 real=$arg2:x64 boot=$arg3:x64 tai=$arg4:x64 sequence=+0($arg1):u32 offs_real=+0($arg2):s64 offs_boot=+0($arg3):s64 offs_tai=+0($arg4):s64 now=$retval:s64\n"
#endif
    };
    for(unsigned i=0;i<sizeof(parts)/sizeof(parts[0]);++i){
        if(parts[i]){for(size_t j=0;parts[i][j];++j){if(at+1>=sizeof(probes))fail(1023);probes[at++]=parts[i][j];}}
        else{char digits[10];unsigned n=0;uint32_t value=offsets[offset_index++];do{digits[n++]=(char)('0'+value%10);value/=10;}while(value);while(n)probes[at++]=digits[--n];}
    }
    probes[at]=0;
}
#else
#define probes task_probes
#endif
#endif
static void event_path(char *out,const char *name,const char *suffix)
{
    const char *parts[]={"/dev/events/",name,suffix};size_t at=0;
    for(unsigned p=0;p<3;++p)for(size_t j=0;parts[p][j];++j)out[at++]=parts[p][j];out[at]=0;
}
void osrec_native_main(void)
{
    if(call(172,0,0,0,0,0,0)!=1 || call(178,0,0,0,0,0,0)!=1)fail(1006);
    if(call(167,30,0,0,0,0,0)!=50000)fail(1010);
#ifdef OSREC_SLEEPER_STATE
    capture_layout();make_probes();
#endif
    if(call(40,(uintptr_t)"tracefs",(uintptr_t)"/dev",(uintptr_t)"tracefs",0,0,0))fail(1007);
    control("/dev/tracing_on","0");control("/dev/current_tracer","nop");
    control("/dev/events/enable","0");control("/dev/buffer_size_kb","256");
    control("/dev/trace_clock","mono");
#ifdef OSREC_TASK_STATE
    control("/dev/kprobe_events",probes);
    for(unsigned i=12;i<sizeof(names)/sizeof(names[0]);++i){
        char path[128];event_path(path,names[i],"/filter");if(i<16)control(path,"pid == 1");
        else if(i==16 || i==19 || i==21 || i==23)control(path,"common_pid == 1");
    }
    size_t definitions=read_file("/dev/kprobe_events",trace,sizeof(trace));
    text("OSREC_LINUX_IRQ_PROBES_BEGIN\n");output(trace,definitions);text("\nOSREC_LINUX_IRQ_PROBES_END\n");
#endif
    for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);++i){
        char path[128];event_path(path,names[i],"/format");size_t n=read_file(path,format,sizeof(format));
        text("OSREC_LINUX_IRQ_FORMAT_BEGIN ");text(names[i]);text("\n");output(format,n);
        text("\nOSREC_LINUX_IRQ_FORMAT_END ");text(names[i]);text("\n");
        event_path(path,names[i],"/enable");control(path,"1");
    }
    control("/dev/trace","\n");
    struct {int64_t seconds,nanoseconds;} request={0,20000000},before,after;
    if(call(113,1,(uintptr_t)&before,0,0,0,0))fail(1008);
    control("/dev/tracing_on","1");
    int64_t result=call(101,(uintptr_t)&request,0,0,0,0,0);
    control("/dev/tracing_on","0");
    if(call(113,1,(uintptr_t)&after,0,0,0,0))fail(1009);
    size_t n=read_file("/dev/trace",trace,sizeof(trace));
    size_t sn=read_file("/dev/per_cpu/cpu0/stats",stats,sizeof(stats));
#ifdef OSREC_TASK_STATE
    size_t pn=read_file("/dev/kprobe_profile",format,sizeof(format));
    text("OSREC_LINUX_IRQ_PROFILE_BEGIN\n");output(format,pn);text("\nOSREC_LINUX_IRQ_PROFILE_END\n");
#endif
    text("OSREC_LINUX_IRQ_RESULT {"
#ifdef OSREC_TASK_STATE
         "\"task_state_capture\":true,"
#endif
#ifdef OSREC_SLEEPER_STATE
         "\"sleeper_state_capture\":true,"
#endif
#ifdef OSREC_TIMER_STATE
         "\"timer_state_capture\":true,"
#endif
#ifdef OSREC_TIMER_RETURN
         "\"timer_return_capture\":true,"
#endif
#ifdef OSREC_BASE_STATE
         "\"base_state_capture\":true,"
#endif
#ifdef OSREC_OUTER_STATE
         "\"outer_state_capture\":true,"
#endif
#ifdef OSREC_CLOCK_STATE
         "\"clock_state_capture\":true,"
#endif
         "\"pid\":1,\"tid\":1,\"syscall\":101,\"request_ns\":20000000,\"timer_slack_ns\":50000,\"raw\":");
    number((uint64_t)result);text(",\"before_ns\":");number((uint64_t)before.seconds*1000000000+(uint64_t)before.nanoseconds);
    text(",\"after_ns\":");number((uint64_t)after.seconds*1000000000+(uint64_t)after.nanoseconds);text("}\n");
    text("OSREC_LINUX_IRQ_TRACE_BEGIN\n");output(trace,n);text("\nOSREC_LINUX_IRQ_TRACE_END\n");
    text("OSREC_LINUX_IRQ_STATS_BEGIN\n");output(stats,sn);text("\nOSREC_LINUX_IRQ_STATS_END\n");
    text("OSREC_LINUX_IRQ_DONE\n");shutdown();
}
