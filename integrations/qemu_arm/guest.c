/* Freestanding ARMv7 capture harness; not a complete LiteOS-A image.
 * Single CPU, IRQ/FIQ masked, MMU off. Real user/SVC modes, modeled process
 * and fd slots, QEMU semihost file backend. Input/output paths are fixed and
 * the runner confines semihosting to a temporary directory it creates.
 */
#include "syscall_checkpoint.h"
#include "osrec/io_capture.h"
#include "guest_config.h"

static struct session_process *process;
static struct session_call calls[GUEST_CALLS];
static struct osrec_buffer recorder;
static unsigned char trace[4096];
static int host_fd;
static uint32_t invocation, svc_calls, backend_reads;
/* Wire observations: six u32 words followed by eight bytes, per invocation. */
static unsigned char observations[GUEST_CALLS * 32];

static int semihost(uint32_t operation, const void *arguments)
{
    register uint32_t r0 __asm__("r0") = operation;
    register const void *r1 __asm__("r1") = arguments;
    __asm__ volatile("svc #0x123456" : "+r"(r0) : "r"(r1) : "r2","r3","r12","lr","cc","memory");
    return (int)r0;
}
static uint32_t mode(void)
{
    uint32_t value; __asm__ volatile("mrs %0, cpsr" : "=r"(value)); return value & 31;
}
static void stop(uint32_t status)
{
    uint32_t args[2]={0x20026,status}; semihost(0x20,args);
    for (;;) __asm__ volatile("wfi");
}
void unexpected_exception(void) { semihost(4,"unexpected guest exception\n"); stop(1); }
static void require(int condition) { if (!condition) unexpected_exception(); }
static int open_file(const char *path, uint32_t length, uint32_t flags)
{
    uint32_t args[3]={(uint32_t)(uintptr_t)path,flags,length}; return semihost(1,args);
}
static void save(const char *path, uint32_t length, const void *data, uint32_t size)
{
    int fd=open_file(path,length,5); require(fd>=0);
    uint32_t args[3]={(uint32_t)fd,(uint32_t)(uintptr_t)data,size};
    require(semihost(5,args)==0); require(semihost(2,&fd)==0);
}
int osrec_user_address_range(uintptr_t address, uint32_t size)
{
    uintptr_t base=(uintptr_t)process->memory;
    return address>=base && address-base<=process->memory_size && size<=process->memory_size-(address-base);
}
int osrec_associated_fd(int fd)
{
    struct session_file *file=fd==3 ? process->fd3 : fd==4 ? process->fd4 : 0;
    return file ? (int)file->backend_fd : -1;
}
int osrec_get_errno(void) { return (int)process->kernel_errno; }
int osrec_vfs_read(int fd, void *destination, uint32_t count)
{
    require(mode()==0x13 && invocation<GUEST_CALLS);
    struct session_file *file=process->fd3 && (int)process->fd3->backend_fd==fd ? process->fd3 :
        process->fd4 && (int)process->fd4->backend_fd==fd ? process->fd4 : 0;
    int result=-1; uint32_t error=9;
    if (file) {
        uint32_t args[3]={(uint32_t)host_fd,(uint32_t)(uintptr_t)destination,count};
        int unread=semihost(6,args);
        if (unread>=0 && (uint32_t)unread<=count) { result=(int)count-unread; error=0; file->position+=(uint32_t)result; }
        else { error=(uint32_t)semihost(0x13,0); require(error>0 && error<=4095); }
    }
    if (result<0) process->kernel_errno=error;
    require(osrec_record_read(&recorder,invocation,fd,count,calls[invocation].buffer,result,error,
                              result>0 ? destination : 0)==0);
    ++backend_reads;
    return result;
}
static void put32(unsigned char *out,uint32_t value)
{
    for(unsigned j=0;j<4;++j) out[j]=(unsigned char)(value>>(8*j));
}
int svc_dispatch(uint32_t *registers)
{
    require(mode()==0x13);
    if (registers[7]==2) {
        require(invocation==GUEST_CALLS && svc_calls==GUEST_CALLS && !recorder.failed);
        require(osrec_finish(&recorder)==0);
        require(semihost(2,&host_fd)==0);
        save("reads.osrec",11,trace,(uint32_t)recorder.used);
        save("observations.bin",16,observations,sizeof(observations));
        require(backend_reads==GUEST_BACKEND_READS);
        semihost(4,"QEMU capture verified: user -> SVC -> pinned SysRead -> semihost read\n");
        stop(0);
    }
    require(registers[7]==1 && invocation<GUEST_CALLS);
    struct session_call call=calls[invocation];
    uintptr_t expected=call.buffer.object ? (uintptr_t)process->memory+call.buffer.offset : 0;
    require(registers[0]==call.fd && registers[1]==expected && registers[2]==call.count);
    ++svc_calls;
    return SysRead((int)registers[0],(void *)(uintptr_t)registers[1],registers[2]);
}
static int user_syscall(uint32_t number,uint32_t fd,void *buffer,uint32_t count)
{
    register uint32_t r0 __asm__("r0")=fd;
    register void *r1 __asm__("r1")=buffer;
    register uint32_t r2 __asm__("r2")=count;
    register uint32_t r7 __asm__("r7")=number;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1),"r"(r2),"r"(r7) : "memory","cc");
    return (int)r0;
}
void user_main(void)
{
    /* No semihosting or privileged instructions from user mode. */
    for (invocation=0;invocation<GUEST_CALLS;++invocation) {
        struct session_call call=calls[invocation];
        void *buffer=call.buffer.object ? process->memory+call.buffer.offset : 0;
        int raw=user_syscall(1,call.fd,buffer,call.count);
        int result=raw<0 ? -1 : raw;
        if (raw<0) process->user_errno=(uint32_t)-raw;
        unsigned char *step=observations+invocation*32;
        put32(step,(uint32_t)raw); put32(step+4,(uint32_t)result);
        put32(step+8,process->user_errno); put32(step+12,raw>0 && ((unsigned char *)buffer)[0]=='A');
        put32(step+16,process->kernel_errno); put32(step+20,process->fd3->position);
        for(unsigned j=0;j<8;++j) step[24+j]=process->memory[j];
        /* Store mode as a checked invariant without making a user-side kernel call. */
        if (mode()!=0x10) for(;;) {}
    }
    user_syscall(2,0,0,0);
    for(;;) {}
}
extern void enter_user(void);
void guest_main(void)
{
    require(mode()==0x13);
    GUEST_SETUP
    /* Generated locals remain alive on the supervisor stack through user execution. */
    process=guest_process;
    for(unsigned i=0;i<GUEST_CALLS;++i) calls[i]=guest_calls[i];
    host_fd=open_file("input.bin",9,1); require(host_fd>=0);
    uint32_t seek[2]={(uint32_t)host_fd,process->fd3->position}; require(semihost(0x0a,seek)==0);
    require(osrec_begin(&recorder,trace,sizeof(trace),GUEST_CONTEXT)==0);
    enter_user();
    unexpected_exception();
}
/* Compiler-generated structure copies may call these freestanding routines. */
void *memcpy(void *destination,const void *source,size_t size)
{
    unsigned char *d=destination; const unsigned char *s=source;
    for(size_t i=0;i<size;++i) d[i]=s[i]; return destination;
}
void *memset(void *destination,int value,size_t size)
{
    unsigned char *d=destination; for(size_t i=0;i<size;++i) d[i]=(unsigned char)value; return destination;
}
void __aeabi_memcpy(void *d,const void *s,size_t n) { memcpy(d,s,n); }
void __aeabi_memcpy4(void *d,const void *s,size_t n) { memcpy(d,s,n); }
void __aeabi_memclr(void *d,size_t n) { memset(d,0,n); }
void __aeabi_memclr4(void *d,size_t n) { memset(d,0,n); }
