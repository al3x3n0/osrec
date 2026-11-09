#include "flat.h"
extern void flat_probe_resume(void),flat_probe_resume2(void);
static unsigned char stack[65536] __attribute__((aligned(16)));
static struct flat_frame expected;
static unsigned phase,failed;
static int equal(const struct flat_frame *a,const struct flat_frame *b)
{
    for(unsigned i=0;i<31;i++)if(a->cpu.x[i]!=b->cpu.x[i])return 0;
    if(a->cpu.sp!=b->cpu.sp || a->cpu.pstate!=b->cpu.pstate || a->fpsr!=b->fpsr || a->fpcr!=b->fpcr)return 0;
    for(unsigned i=0;i<32;i++)for(unsigned j=0;j<16;j++)if(a->v[i][j]!=b->v[i][j])return 0;
    return 1;
}
static flat_target handle(void *opaque,struct flat_frame *frame,const struct flat_site *site)
{
    (void)opaque;
    if(!equal(frame,&expected) || site->pc!=(phase?0x2000:0x1000))failed=1;
    if(!phase++) {
        /* Nested entry must reject before changing the active gateway. */
        if(flat_run(frame,flat_probe_resume,stack,sizeof stack,4,handle,0,0)!=FLAT_BUSY)failed=1;
        frame->cpu.x[16]^=0x1234;frame->cpu.x[17]^=0xabcd;frame->cpu.x[18]^=0x9988;
        frame->cpu.x[30]^=0x7766;frame->cpu.sp=0xffff000000000013ull;
        frame->cpu.pstate=0x90000000;frame->fpsr=0x8000001;frame->fpcr=0x800000;
        for(unsigned j=0;j<16;j++)frame->v[0][j]^=0xa5;
        expected=*frame;expected.cpu.x[0]^=expected.cpu.x[30];expected.cpu.x[16]+=expected.cpu.x[17];
        for(unsigned j=0;j<16;j++)expected.v[31][j]^=expected.v[0][j];
        return flat_probe_resume2;
    }
    return 0;
}
static flat_target aborting(void *p,struct flat_frame *f,const struct flat_site *s)
{(void)p;(void)f;(void)s;flat_fail(FLAT_BOUNDARY);}
static flat_target looping(void *p,struct flat_frame *f,const struct flat_site *s)
{(void)p;(void)f;(void)s;return flat_probe_resume;}
int flat_gateway_selftest(void)
{
    struct flat_frame frame={0};
    for(unsigned i=0;i<31;i++)frame.cpu.x[i]=0x13579bdf02468000ull+0x01010101010101ull*i;
    for(unsigned i=0;i<32;i++)for(unsigned j=0;j<16;j++)frame.v[i][j]=(unsigned char)(17*i+3*j);
    frame.cpu.sp=0xdead000000000015ull;frame.cpu.pstate=0xa0000000;frame.fpsr=1;frame.fpcr=0x400000;
    expected=frame;phase=failed=0;uint64_t transitions=0;
    if(flat_run(&frame,flat_probe_resume,stack,sizeof stack,4,handle,0,&transitions)!=FLAT_OK ||
       phase!=2 || transitions!=2 || failed || !equal(&frame,&expected) || flat_active)return 1;
    if(flat_run(&frame,flat_probe_resume,stack,sizeof stack,4,aborting,0,0)!=FLAT_BOUNDARY || flat_active)return 2;
    if(flat_run(&frame,flat_probe_resume,stack,sizeof stack,2,looping,0,&transitions)!=FLAT_BOUNDARY || flat_active)return 3;
    if(flat_run(&frame,flat_probe_resume,&frame,sizeof frame,1,handle,0,0)!=FLAT_BAD_ARGUMENT)return 4;
    /* A new run after both forms of stop must remain usable. */
    frame.cpu.pstate=0xa0000000;expected=frame;phase=failed=0;
    if(flat_run(&frame,flat_probe_resume,stack,sizeof stack,4,handle,0,0)!=FLAT_OK || failed)return 5;
    return 0;
}
