#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "el0.h"
const uint64_t osrec_kernel_ranges[][2]={{0x200000000000ull,0x200020000000ull},{0x800080000000ull,0x800082000000ull}};
const uint64_t osrec_kernel_range_count=2;
const uint64_t osrec_veneer_base=0x800084000000ull,osrec_veneer_count=1;
const uint64_t osrec_veneer_origins[]={0x800080010000ull};
static jmp_buf stopped;
static uint64_t reason,where,fault;
void osrec_platform_stop(uint64_t r,uint64_t pc,uint64_t d,uint64_t far) { (void)d;reason=r;where=pc;fault=far;longjmp(stopped,1); }
int main(void)
{
    struct osrec_shadow s={0};struct osrec_context c={0};
    struct osrec_site site={0x800080010000ull,0xf8408820,0x80000000u};
    c.pc=site.va;c.x[1]=0x1000;
    osrec_lowered_site(&s,&c,&site);assert(c.pc==osrec_veneer_base && c.x[1]==0x1000);
    c.pc=site.va;c.x[1]=osrec_kernel_ranges[0][0]-8;
    if (!setjmp(stopped)) { osrec_lowered_site(&s,&c,&site);assert(!"kernel alias must stop"); }
    assert(reason==OSREC_STOP_USER_KERNEL && where==site.va && fault==osrec_kernel_ranges[0][0]);
    site.insn=0x885f7c20;c.pc=site.va;c.x[1]=0x1000;
    osrec_lowered_site(&s,&c,&site);assert(c.pc==osrec_veneer_base); // original LDXR executes after the trap
    site.reserved=0x40000000;site.insn=0xb6000000u|(23<<19)|(2<<5); // TBZ X0,#55,+8
    c.pc=site.va;c.x[0]=0x1000;osrec_lowered_site(&s,&c,&site);assert(c.pc==site.va+8);
    c.pc=site.va;c.x[0]=osrec_kernel_ranges[0][0];osrec_lowered_site(&s,&c,&site);assert(c.pc==site.va+4);
    site.insn=0xb6000000u|(31<<19)|(2<<5);c.pc=site.va;
    if (!setjmp(stopped)) { osrec_lowered_site(&s,&c,&site);assert(!"ambiguous signed test must stop"); }
    assert(reason==OSREC_STOP_LOWERING);
    c.pc=site.va;c.x[0]=1ull<<63;osrec_lowered_site(&s,&c,&site);assert(c.pc==site.va+4);
    c.pc=osrec_veneer_base;s.mode=OSREC_KERNEL;
    osrec_lowered_exception(&s,&c,0x92000005,0x1234);assert(c.pc==osrec_veneer_origins[0]);
    c.pc=0x1000;s.mode=OSREC_USER;
    if (!setjmp(stopped)) { osrec_lowered_exception(&s,&c,0x9200000f,osrec_kernel_ranges[0][0]);assert(!"user kernel access must stop"); }
    assert(reason==OSREC_STOP_USER_KERNEL);
    puts("lowered address contracts passed");
}
