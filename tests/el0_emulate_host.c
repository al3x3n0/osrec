/* Host-side architectural contracts; no AArch64 assembler or QEMU required. */
#include <assert.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include "el0.h"

_Static_assert(sizeof(struct osrec_context) == 272, "assembly context size");
_Static_assert(offsetof(struct osrec_context, sp) == 248, "assembly SP offset");
_Static_assert(offsetof(struct osrec_context, pc) == 256, "assembly PC offset");
_Static_assert(offsetof(struct osrec_context, pstate) == 264, "assembly PSTATE offset");
_Static_assert(offsetof(struct osrec_shadow, known) == 104, "builder shadow header");
_Static_assert(offsetof(struct osrec_shadow, value) == 8296, "veneer shadow value offset");
_Static_assert(sizeof(struct osrec_site) == 16, "builder site stride");
static struct osrec_shadow s;
static struct osrec_context c;
static jmp_buf stopped;
static uint64_t reason, detail, stop_pc, stop_far;
static uint64_t ttbr0, ttbr1, tpidrro, clean, translated;
static int tlbs, icaches, at_op;
void osrec_platform_set_ttbr0(uint64_t v) { ttbr0 = v; }
void osrec_platform_set_ttbr1(uint64_t v) { ttbr1 = v; }
void osrec_platform_set_tpidrro(uint64_t v) { tpidrro = v; }
void osrec_platform_tlb_flush(void) { tlbs++; }
void osrec_platform_icache_flush(void) { icaches++; }
void osrec_platform_dcache_clean_invalidate(uint64_t v) { clean = v; }
uint64_t osrec_platform_translate(uint64_t v, int op) { translated = v; at_op = op; return 0x12345000; }
void osrec_platform_stop(uint64_t r, uint64_t pc, uint64_t d, uint64_t far)
{ reason = r; stop_pc = pc; detail = d; stop_far = far; longjmp(stopped, 1); }
#define KEY(op0,op1,crn,crm,op2) (((op0)<<14)|((op1)<<11)|((crn)<<7)|((crm)<<3)|(op2))
#define MRS(k,r) (0xd5200000u|((k)<<5)|(r))
#define MSR(k,r) (0xd5000000u|((k)<<5)|(r))
static void reset(void) { memset(&s,0,sizeof(s)); memset(&c,0,sizeof(c)); c.pc=0x1000; reason=0; }
static void expect_stop(uint32_t insn, unsigned r)
{ if (!setjmp(stopped)) { osrec_emulate_site(&s,&c,insn); assert(!"expected stop"); } assert(reason==r); assert(stop_pc==0x1000); }
static void sysregs(void)
{
    reset(); unsigned sp=KEY(3,0,4,1,0), t0=KEY(3,0,2,0,0), t1=KEY(3,0,2,0,1);
    c.x[3]=0xfeed; osrec_emulate_site(&s,&c,MSR(sp,3)); assert(s.sp_el0==0xfeed);
    osrec_emulate_site(&s,&c,MRS(sp,4)); assert(c.x[4]==0xfeed); assert(c.pc==0x1008);
    osrec_emulate_site(&s,&c,MSR(sp,31)); assert(s.sp_el0==0); // XZR, not SP
    osrec_emulate_site(&s,&c,MRS(KEY(3,0,4,2,2),0)); assert(c.x[0]==4);
    c.x[0]=0x1122; osrec_emulate_site(&s,&c,MSR(t0,0)); assert(ttbr0==0x1122 && s.ttbr0==ttbr0);
    osrec_emulate_site(&s,&c,MSR(t1,0)); assert(ttbr1==0x1122);
    osrec_emulate_site(&s,&c,MRS(t1,1)); assert(c.x[1]==0x1122);
    osrec_emulate_site(&s,&c,MSR(KEY(3,3,13,0,3),0)); assert(tpidrro==0x1122);
    unsigned tls=KEY(3,3,13,0,2);
    s.known[tls>>3]|=1<<(tls&7);
    c.x[2]=0x123456789abcdef0ull;
    osrec_emulate_site(&s,&c,MSR(tls,2)); assert(s.value[tls]==c.x[2]);
    osrec_emulate_site(&s,&c,MRS(tls,3)); assert(c.x[3]==c.x[2]);
    reset(); s.known[t1>>3]|=1<<(t1&7); s.value[t1]=0x12345000; c.x[0]=0x56789000;
    expect_stop(MSR(t1,0),OSREC_STOP_UNSUPPORTED);
    reset(); s.known[t1>>3]|=1<<(t1&7); s.value[t1]=0x12345000; c.x[0]=0xabcd000012345000ull;
    osrec_emulate_site(&s,&c,MSR(t1,0)); assert(ttbr1==c.x[0]);
    reset(); expect_stop(MRS(KEY(3,0,0,0,0),1),OSREC_STOP_UNKNOWN_SYSREG);
    assert(detail==KEY(3,0,0,0,0)); assert(stop_far==0);
    reset(); expect_stop(MSR(KEY(3,0,0,0,0),1),OSREC_STOP_UNKNOWN_SYSREG);
    reset(); unsigned tcr=KEY(3,0,2,0,2); s.known[tcr>>3]|=1<<(tcr&7); c.x[1]=1;
    expect_stop(MSR(tcr,1),OSREC_STOP_UNSUPPORTED);
    reset(); unsigned key=KEY(3,0,0,0,0); s.known[key>>3]|=1<<(key&7); s.value[key]=123;
    osrec_emulate_site(&s,&c,MRS(key,31)); assert(c.sp==0 && s.emulated==1);
}
static void pstate(void)
{
    reset(); osrec_emulate_site(&s,&c,0xd5034fdf); assert(s.daif==0x3c0); // DAIFSet #15
    osrec_emulate_site(&s,&c,0xd50342ff); assert(s.daif==0x340); // DAIFClr #2
    osrec_emulate_site(&s,&c,0xd500419f); assert(s.pan==1);
    osrec_emulate_site(&s,&c,MRS(KEY(3,0,4,2,3),0)); assert(c.x[0]==(1<<22));
    reset(); expect_stop(0xd500401f,OSREC_STOP_UNSUPPORTED); // SPSel cannot silently succeed
}
static void exceptions(void)
{
    reset(); c.sp=0x2000; c.pc=0x4004; c.pstate=0xa0000000; s.sp_el1=0x9000; s.vbar=0x800000;
    c.x[0]=55; osrec_enter_kernel(&s,&c,0x56000000,0x777,1);
    assert(s.sp_el0==0x2000 && c.sp==0x9000 && s.elr==0x4004);
    assert(c.pc==0x800400 && s.esr==0x56000000 && s.far==0x777);
    assert(s.spsr==0xa0000000 && s.mode==OSREC_KERNEL && s.daif==0x3c0);
    assert(c.x[0]==55 && s.entries==1);
    s.pan=1; osrec_emulate_site(&s,&c,0xd69f03e0);
    assert(s.mode==OSREC_USER && c.sp==0x2000 && c.pc==0x4004 && c.pstate==0xa0000000 && s.pan==0);
    // A nested kernel abort uses the current-EL EC and leaves both SPs intact.
    reset(); s.vbar=0x800000; s.mode=OSREC_KERNEL; s.daif=0x80; s.pan=1; c.sp=0x8000; c.pstate=0x60000000;
    osrec_enter_kernel(&s,&c,0x92000045,0xbad,0);
    assert(s.esr==0x96000045 && s.spsr==(0x60000005|0x80|(1<<22)) && c.sp==0x8000);
    assert(c.pc==0x800200);
    s.pan=0; s.daif=0; osrec_emulate_site(&s,&c,0xd69f03e0);
    assert(c.pc==0x1000 && s.pan==1 && s.daif==0x80 && s.mode==OSREC_KERNEL);
    reset(); s.spsr=4; expect_stop(0xd69f03e0,OSREC_STOP_UNSUPPORTED);
    reset(); s.spsr=0x60001000; s.elr=0x4000; s.sp_el0=0x2000;
    osrec_emulate_site(&s,&c,0xd69f03e0); assert(c.pstate==0x60001000);
}
static void syscall_entries(void)
{
    static struct osrec_shadow before,expected;
    const uint64_t pcs[]={0,4,0x1000,0x1001,UINT64_MAX-7,UINT64_MAX-3,UINT64_MAX};
    const uint64_t extras[]={0,1ull<<12,1,0x3c0,1ull<<22,1ull<<63};
    const uint32_t words[]={0xd4000001,0xd41fffe1,0xd4024681,0xd4000002,0xd4000000};
    const int entries[]={OSREC_ENTRY_VENEER,OSREC_ENTRY_SVC,-1,2};
    reset();s.known[123]=0xa5;s.value[123]=0x0123456789abcdefull;
    for(unsigned flags=0;flags<16;flags++)for(unsigned extra=0;extra<6;extra++)
    for(unsigned pc=0;pc<7;pc++)for(unsigned entry=0;entry<4;entry++)
    for(unsigned word=0;word<5;word++)for(unsigned mode=0;mode<3;mode++) {
        /* Only the architecture header can change; avoid copying the 512 KiB
         * generic sysreg table for every boundary case. */
        before.sp_el0=123;before.sp_el1=0x9000;before.elr=456;before.spsr=789;
        before.esr=0x1234;before.far=0xfedcba9876543210ull;
        before.daif=0x80;before.pan=1;before.vbar=0x800000;before.ttbr0=0x2345;
        before.mode=mode;before.emulated=25;before.entries=flags&1?UINT64_MAX:10;
        memcpy(&s,&before,104);memcpy(&expected,&before,104);
        struct osrec_context original={0};
        for(unsigned r=0;r<31;r++)original.x[r]=0x1020304050607080ull*(r+1);
        original.pc=pcs[pc];original.sp=0x2000;original.pstate=((uint64_t)flags<<28)|extras[extra];
        c=original;struct osrec_context result=original;
        int valid=mode==OSREC_USER && !(original.pc&3) &&
            !(original.pstate&~0xf0001000ull) && (words[word]&0xffe0001f)==0xd4000001 &&
            ((entries[entry]==OSREC_ENTRY_VENEER && original.pc<=UINT64_MAX-4) ||
             (entries[entry]==OSREC_ENTRY_SVC && original.pc>=4));
        if(valid) {
            expected.entries++;
            expected.elr=original.pc+(entries[entry]==OSREC_ENTRY_VENEER?4:0);
            expected.spsr=original.pstate;expected.sp_el0=original.sp;
            expected.esr=0x56000000ull|((words[word]>>5)&65535);
            expected.mode=OSREC_KERNEL;expected.daif=0x3c0;
            result.pc=before.vbar+0x400;result.sp=before.sp_el1;
        }
        assert(osrec_enter_syscall(&s,&c,words[word],entries[entry])==valid);
        assert(!memcmp(&s,&expected,104));assert(!memcmp(&c,&result,sizeof c));
        assert(!osrec_enter_syscall(NULL,&c,words[word],entries[entry]));
        assert(!osrec_enter_syscall(&s,NULL,words[word],entries[entry]));
        assert(!memcmp(&s,&expected,104));assert(!memcmp(&c,&result,sizeof c));
    }
    assert(s.known[123]==0xa5 && s.value[123]==0x0123456789abcdefull);
    reset();c.pstate=1;
    memcpy(&before,&s,104);struct osrec_context original=c;
    if(!setjmp(stopped)){osrec_enter_kernel(&s,&c,0x92000005,0x1234,1);assert(!"invalid user PSTATE must stop");}
    assert(reason==OSREC_STOP_UNSUPPORTED && stop_pc==original.pc && detail==1 && stop_far==0x1234);
    assert(!memcmp(&s,&before,104) && !memcmp(&c,&original,sizeof c));
}
static void operations(void)
{
    reset();c.x[0]=0x1234;c.sp=0x2000;c.pstate=0xa0000000;
    osrec_emulate_site(&s,&c,0xd503229f); /* CSDB does not change architectural registers. */
    assert(c.pc==0x1004 && c.x[0]==0x1234 && c.sp==0x2000 && c.pstate==0xa0000000);
    reset(); osrec_emulate_site(&s,&c,0xd508871f); assert(tlbs==1);
    osrec_emulate_site(&s,&c,0xd508751f); assert(icaches==1);
    c.x[0]=0x2340; osrec_emulate_site(&s,&c,0xd50b7e20); assert(clean==0x2340);
    c.x[3]=0x3450; osrec_emulate_site(&s,&c,0xd50b7b23); assert(clean==0x3450);
    osrec_emulate_site(&s,&c,0xd50b7523); assert(icaches==2);
    reset(); expect_stop(0xd50b7b40,OSREC_STOP_UNSUPPORTED); // neighboring SYS encoding is not CVAU
    c.pc=0x1000;c.x[0]=0x2340;
    osrec_emulate_site(&s,&c,0xd5087820); assert(translated==0x2340 && at_op==1);
    osrec_emulate_site(&s,&c,MRS(KEY(3,0,7,4,0),1)); assert(c.x[1]==0x12345000);
    reset(); expect_stop(0xd5087880,OSREC_STOP_UNSUPPORTED); // unsupported AT variant
    reset(); c.x[0]=0xffff800080000000ull;
    expect_stop(0xd5087840,OSREC_STOP_UNSUPPORTED); // artificial upper-half EL0 permissions
    reset(); expect_stop(0xd503207f,OSREC_STOP_UNSUPPORTED); // WFI
    reset(); expect_stop(0xd4000002,OSREC_STOP_UNSUPPORTED); // HVC
}
static void lookup(void)
{
    struct osrec_site sites[]={{0x1000,1,0},{0x2000,2,0},{0x8000,3,0}};
    assert(!osrec_find_site(sites,0,0x1000));
    assert(!osrec_find_site(sites,3,0xfff));
    assert(!osrec_find_site(sites,3,0x1004));
    assert(!osrec_find_site(sites,3,0x9000));
    for(unsigned i=0;i<3;i++) assert(osrec_find_site(sites,3,sites[i].va)==&sites[i]);
}
static void dispatch(void)
{
    // Real SVC entry shares the library normalizer; FAR is guest state, not
    // an unrelated fault address left behind by the monitor/host handler.
    reset(); s.sp_el1=0x9000; s.vbar=0x800000; s.far=0x1234;
    c.pc=0x1004; c.sp=0x2000; c.pstate=0xa0000000;
    osrec_handle_exception(&s,&c,0,0,0x560000ab,0xbad);
    assert(s.mode==OSREC_KERNEL && c.pc==0x800400 && c.sp==0x9000);
    assert(s.elr==0x1004 && s.esr==0x560000ab && s.far==0x1234);
    assert(s.sp_el0==0x2000 && s.spsr==0xa0000000);
    // The program's reserved BRK must be reflected, without site lookup.
    reset(); s.sp_el1=0x9000; s.vbar=0x800000;
    osrec_handle_exception(&s,&c,0,0,0xf2000f00,0);
    assert(s.mode==OSREC_KERNEL && c.pc==0x800400 && s.esr==0xf2000f00);
    reset();
    if (!setjmp(stopped)) { osrec_handle_exception(&s,&c,0,0,0x9200000f,0xffff800080000000ull); assert(!"user kernel access must stop"); }
    assert(reason==OSREC_STOP_USER_KERNEL && s.mode==OSREC_USER && c.pc==0x1000);
    reset(); s.mode=OSREC_KERNEL;
    struct osrec_site site={0x1000,MRS(KEY(3,0,4,2,2),0),0};
    osrec_handle_exception(&s,&c,&site,1,0xf2000f00,0);
    assert(c.x[0]==4 && c.pc==0x1004);
    reset(); s.mode=OSREC_KERNEL;
    if (!setjmp(stopped)) { osrec_handle_exception(&s,&c,0,0,0xf2000f00,0); assert(!"missing site must stop"); }
    assert(reason==OSREC_STOP_NO_SITE);
    reset(); s.mode=OSREC_KERNEL;
    if (!setjmp(stopped)) { osrec_handle_exception(&s,&c,0,0,0xf2000f01,0); assert(!"boundary must stop"); }
    assert(reason==OSREC_STOP_BOUNDARY);
    reset(); s.mode=OSREC_KERNEL;
    if (!setjmp(stopped)) { osrec_handle_exception(&s,&c,0,0,0,0); assert(!"undefined instruction must stop"); }
    assert(reason==OSREC_STOP_UNDEFINED);
}
int main(void) { sysregs(); pstate(); exceptions(); syscall_entries(); operations(); lookup(); dispatch(); puts("EL0 emulation contracts passed"); }
