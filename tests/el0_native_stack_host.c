/* Verify real kernel SP, private handler SP, logical user SP and full context. */
#include "flat.h"
extern void native_entry(void),native_second(void),user_entry(void),native_last(void);
extern void private_entry(void),native_final(void);
static unsigned char runtime_stack[65536] __attribute__((aligned(16)));
static unsigned char kernel_stack[2][32768] __attribute__((aligned(16)));
static struct flat_frame expected;
static unsigned phase,failed;
static uint64_t saved_x16;
static int equal(const struct flat_frame *a,const struct flat_frame *b)
{
    for(unsigned r=0;r<31;r++)if(a->cpu.x[r]!=b->cpu.x[r])return 0;
    if(a->cpu.sp!=b->cpu.sp || a->cpu.pstate!=b->cpu.pstate || a->fpsr!=b->fpsr || a->fpcr!=b->fpcr)return 0;
    for(unsigned r=0;r<32;r++)for(unsigned j=0;j<16;j++)if(a->v[r][j]!=b->v[r][j])return 0;
    return 1;
}
static flat_target handle(void *opaque,struct flat_frame *frame,const struct flat_site *site)
{
    (void)opaque;
    uintptr_t sp;__asm__ volatile("mov %0,sp":"=r"(sp));
    if(sp<(uintptr_t)runtime_stack || sp>=(uintptr_t)(runtime_stack+sizeof runtime_stack))failed=1;
    if(site->pc!=0x1000+phase*0x1000 || !equal(frame,&expected))failed=1;
    switch(phase++) {
    case 0:
        if(flat_run(frame,native_entry,runtime_stack,sizeof runtime_stack,9,handle,0,0)!=FLAT_BUSY)failed=1;
        frame->cpu.sp=(uintptr_t)(kernel_stack[1]+sizeof kernel_stack[1]-64);
        frame->cpu.x[16]^=0x1234;frame->cpu.x[17]^=0x5678;
        frame->cpu.x[18]^=0x9abc;frame->cpu.x[30]^=0xdef0;
        frame->fpsr=0x8000001;frame->fpcr=0x800000;
        for(unsigned j=0;j<16;j++)frame->v[0][j]^=0xa5;
        expected=*frame;expected.cpu.sp-=64;
        expected.cpu.x[0]^=expected.cpu.x[30];expected.cpu.x[16]+=expected.cpu.x[17];
        for(unsigned j=0;j<16;j++)expected.v[31][j]^=expected.v[0][j];
        return native_second;
    case 1:
        frame->cpu.sp=0xdead000000000015ull;expected=*frame;
        return user_entry;
    case 2:
        frame->cpu.sp=(uintptr_t)(kernel_stack[0]+sizeof kernel_stack[0]-128);expected=*frame;
        return native_last;
    case 3:
        saved_x16=frame->cpu.x[16];frame->cpu.x[16]=frame->cpu.sp-16;expected=*frame;
        return private_entry;
    case 4: {
        const uint64_t *stored=(const void *)(uintptr_t)(frame->cpu.sp-16);
        if(stored[0]!=frame->cpu.x[29] || stored[1]!=frame->cpu.x[30])failed=1;
        frame->cpu.x[16]=saved_x16;frame->cpu.sp-=16;expected=*frame;
        return native_final;
    }
    case 5: {
        const uint64_t *stored=(const void *)(uintptr_t)frame->cpu.sp;
        if(stored[0]!=frame->cpu.x[29] || stored[1]!=frame->cpu.x[30])failed=1;
        return 0;
    }
    default:return 0;
    }
}
int test_main(void)
{
    for(unsigned flags=0;flags<16;flags++) {
        for(unsigned s=0;s<2;s++)for(unsigned i=0;i<sizeof kernel_stack[s];i++)kernel_stack[s][i]=0xa5;
        struct flat_frame frame={0};
        for(unsigned r=0;r<31;r++)frame.cpu.x[r]=0x13579bdf02468000ull+0x01010101010101ull*r;
        for(unsigned r=0;r<32;r++)for(unsigned b=0;b<16;b++)frame.v[r][b]=(unsigned char)(17*r+3*b);
        frame.cpu.sp=(uintptr_t)(kernel_stack[0]+sizeof kernel_stack[0]-64);
        frame.cpu.pstate=(uint64_t)flags<<28;frame.fpsr=1;frame.fpcr=0x400000;
        expected=frame;phase=failed=0;uint64_t transitions=0;
        if(flat_run(&frame,native_entry,runtime_stack,sizeof runtime_stack,9,handle,0,&transitions)!=FLAT_OK ||
           phase!=6 || transitions!=6 || failed || !equal(&frame,&expected) || flat_active)return 1;
        for(unsigned s=0;s<2;s++)for(unsigned i=0;i<64;i++)
            if(kernel_stack[s][i]!=0xa5 || kernel_stack[s][sizeof kernel_stack[s]-64+i]!=0xa5)return 2;
    }
    return 0;
}
