/* The research mini-OS: an EL1 monitor that runs a captured kernel's code at EL0.
 *
 * Every exception from EL0 arrives here (minios_sync). A `brk #OSREC_BRK_SITE` from kernel code is an emulated
 * instruction site; a boundary trap stops; any other exception is reflected into the kernel code through its own
 * vectors: as a lower-EL exception while the user program runs, as a current-EL exception while kernel code
 * runs. The platform actions are the EL1 instructions themselves. */
#include "el0.h"
#ifdef OSREC_CHECKPOINT
#include "checkpoint.h"
#endif

extern struct osrec_shadow osrec_shadow;
extern const struct osrec_site osrec_sites[];
extern const uint64_t osrec_site_count;
extern const uint64_t osrec_ttbr1_root;  /* our TTBR1 tables (physical) */
extern const uint64_t osrec_ttbr1_user_root; /* original upper-half EL0 permissions */
struct osrec_context *osrec_active_context; /* saved kernel frame for stop diagnostics */

#ifndef OSREC_LOWERED
static uint64_t upper_root(void)
{
    return osrec_shadow.mode == OSREC_KERNEL ? osrec_ttbr1_root : osrec_ttbr1_user_root;
}
#endif

static void apply_mode(int force)
{
#ifdef OSREC_LOWERED
    osrec_lowered_mmu(force);
#else
    (void)force;
    uint64_t old;
    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(old));
    uint64_t next = (old & 0xffff000000000000ull) | upper_root();
    if (old != next) {
        __asm__ volatile("msr ttbr1_el1, %0\n\tisb" :: "r"(next) : "memory");
        osrec_platform_tlb_flush();
    }
#endif
}

void osrec_platform_set_ttbr0(uint64_t v) {
#ifdef OSREC_LOWERED
    (void)v;osrec_lowered_mmu(1);
#else
    __asm__ volatile("msr ttbr0_el1, %0\n\tisb" :: "r"(v) : "memory");
#endif
}
void osrec_platform_set_ttbr1(uint64_t v)
{
    uint64_t t = (v & 0xffff000000000000ull);
#ifndef OSREC_LOWERED
    t |= upper_root();
#endif
    __asm__ volatile("msr ttbr1_el1, %0\n\tisb" :: "r"(t) : "memory");
}
void osrec_platform_tlb_flush(void) {
#ifdef OSREC_LOWERED
    osrec_lowered_mmu(1);
#else
    __asm__ volatile("dsb ishst\n\ttlbi vmalle1\n\tdsb ish\n\tisb" ::: "memory");
#endif
}
void osrec_platform_icache_flush(void) { __asm__ volatile("ic iallu\n\tdsb ish\n\tisb" ::: "memory"); }
void osrec_platform_dcache_clean_invalidate(uint64_t va) { __asm__ volatile("dc civac, %0" :: "r"(va) : "memory"); }
void osrec_platform_set_tpidrro(uint64_t v) { __asm__ volatile("msr tpidrro_el0, %0" :: "r"(v)); }
uint64_t osrec_platform_translate(uint64_t va, int op)
{
    uint64_t par;
    switch (op) {
    case 1: __asm__ volatile("at s1e1w, %0" :: "r"(va)); break;
    case 2: __asm__ volatile("at s1e0r, %0" :: "r"(va)); break;
    case 3: __asm__ volatile("at s1e0w, %0" :: "r"(va)); break;
    default: __asm__ volatile("at s1e1r, %0" :: "r"(va)); break;
    }
    __asm__ volatile("isb\n\tmrs %0, par_el1" : "=r"(par));
    return par;
}

/* The start: the user program's address space; returns to the assembly, which enters the program. */
void minios_start(void)
{
    osrec_platform_set_ttbr0(osrec_shadow.ttbr0);
    apply_mode(1);
    osrec_platform_tlb_flush();
#ifdef OSREC_CHECKPOINT
    osrec_checkpoint_start();
#endif
}

void minios_sync(struct osrec_context *c, uint64_t esr, uint64_t far)
{
    osrec_active_context = c;
#ifdef OSREC_CHECKPOINT
    if(osrec_checkpoint_before(c,esr,far))return;
#endif
    int refresh=0;
#ifdef OSREC_LOWERED
    /* A kernel user-copy fault may allocate a new user table without a TLB
     * invalidation. Contested branches of our merged root are copies: refresh
     * them on logical ERET to kernel code, even if TTBR0 and mode are unchanged. */
    if(esr>>26==0x3c && (esr&65535)==OSREC_BRK_SITE) {
        const struct osrec_site *site=osrec_find_site(osrec_sites,osrec_site_count,c->pc);
        refresh=site && site->insn==0xd69f03e0u;
    }
    osrec_lowered_exception(&osrec_shadow,c,esr,far);
#endif
    osrec_handle_exception(&osrec_shadow, c, osrec_sites, osrec_site_count, esr, far);
    apply_mode(refresh && osrec_shadow.mode==OSREC_KERNEL);
}

void minios_runtime_fault(uint64_t esr, uint64_t elr, uint64_t far)
{
    osrec_platform_stop(OSREC_STOP_RUNTIME, elr, esr, far);
}
