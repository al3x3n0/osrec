/* Emulation of EL1-only instructions and of exception entry/return for kernel code running at EL0.
 * Freestanding: no libc, no floating point (built with -mgeneral-regs-only). */
#include "el0.h"
#ifdef OSREC_CHECKPOINT
#include "checkpoint.h"
#endif
#ifdef OSREC_NATIVE
extern void lk_native_zero(uint64_t pc,uint64_t address);
extern uint64_t lk_native_counter(uint64_t pc,unsigned key);
#endif

/* System-register encodings the core interprets (MRS/MSR field [20:5]). */
#define SYSREG(op0, op1, crn, crm, op2) ((1u << 15) | (((op0) & 1) << 14) | ((op1) << 11) | ((crn) << 7) | ((crm) << 3) | (op2))
#define R_SP_EL0     SYSREG(3, 0, 4, 1, 0)
#define R_DAIF       SYSREG(3, 3, 4, 2, 1)
#define R_CURRENTEL  SYSREG(3, 0, 4, 2, 2)
#define R_ELR_EL1    SYSREG(3, 0, 4, 0, 1)
#define R_SPSR_EL1   SYSREG(3, 0, 4, 0, 0)
#define R_ESR_EL1    SYSREG(3, 0, 5, 2, 0)
#define R_FAR_EL1    SYSREG(3, 0, 6, 0, 0)
#define R_VBAR_EL1   SYSREG(3, 0, 12, 0, 0)
#define R_TTBR0_EL1  SYSREG(3, 0, 2, 0, 0)
#define R_TTBR1_EL1  SYSREG(3, 0, 2, 0, 1)
#define R_PAR_EL1    SYSREG(3, 0, 7, 4, 0)
#define R_PAN        SYSREG(3, 0, 4, 2, 3)
#define R_TPIDRRO    SYSREG(3, 3, 13, 0, 3)
#define R_SP_EL1     SYSREG(3, 4, 4, 1, 0)

#define EC(esr) ((esr) >> 26)
#define DAIF_ALL 0x3c0u
#define NZCV 0xf0000000u
#define USER_PSTATE ((uint64_t)NZCV | (1u << 12)) /* SSBS: ERET applies the CPU's RES0 rule */
#define M_EL0T 0u
#define M_EL1H 5u

static inline int known(const struct osrec_shadow *s, unsigned key) { return s->known[key >> 3] >> (key & 7) & 1; }
static inline void set(struct osrec_shadow *s, unsigned key, uint64_t v) { s->value[key] = v; s->known[key >> 3] |= (uint8_t)(1u << (key & 7)); }
static inline uint64_t reg(const struct osrec_context *c, unsigned r) { return r == 31 ? 0 : c->x[r]; }
static inline void put(struct osrec_context *c, unsigned r, uint64_t v) { if (r != 31) c->x[r] = v; }

static uint64_t read_sysreg(struct osrec_shadow *s, struct osrec_context *c, unsigned key)
{
#ifdef OSREC_CHECKPOINT
    if(key==SYSREG(3,3,14,0,1) || key==SYSREG(3,3,14,0,2))
        return osrec_checkpoint_counter(c->pc,key);
#endif
#ifdef OSREC_NATIVE
    /* A host counter is neither the captured timer nor a captured input. */
    if (key==SYSREG(3,3,14,0,1) || key==SYSREG(3,3,14,0,2))
        return lk_native_counter(c->pc,key);
#endif
    switch (key) {
    case R_SP_EL0: return s->sp_el0;
    case R_SP_EL1: return s->sp_el1;
    case R_DAIF: return s->daif;
    case R_CURRENTEL: return 1u << 2;  /* the kernel code believes it runs at EL1 */
    case R_ELR_EL1: return s->elr;
    case R_SPSR_EL1: return s->spsr;
    case R_ESR_EL1: return s->esr;
    case R_FAR_EL1: return s->far;
    case R_VBAR_EL1: return s->vbar;
    case R_TTBR0_EL1: return s->ttbr0;
    case R_PAN: return s->pan << 22;
    }
    if (!known(s, key)) osrec_platform_stop(OSREC_STOP_UNKNOWN_SYSREG, c->pc, key, 0);
    return s->value[key];
}

static void write_sysreg(struct osrec_shadow *s, struct osrec_context *c, unsigned key, uint64_t v)
{
    switch (key) {
    case R_SP_EL0: s->sp_el0 = v; return;
    case R_SP_EL1: s->sp_el1 = v; return;
    case R_DAIF: s->daif = v & DAIF_ALL; return;
    case R_ELR_EL1: s->elr = v; return;
    case R_SPSR_EL1: s->spsr = v; return;
    case R_ESR_EL1: s->esr = v; return;
    case R_FAR_EL1: s->far = v; return;
    case R_VBAR_EL1: s->vbar = v; return;
    case R_PAN: s->pan = v >> 22 & 1; return;
    case R_TTBR0_EL1: s->ttbr0 = v; osrec_platform_set_ttbr0(v); return;
    case R_TTBR1_EL1:
        if (known(s, key) && ((s->value[key] ^ v) & 0x0000fffffffff000ull))
            osrec_platform_stop(OSREC_STOP_UNSUPPORTED, c->pc, key, 0);
        set(s, key, v); osrec_platform_set_ttbr1(v); return;
    case R_TPIDRRO: set(s, key, v); osrec_platform_set_tpidrro(v); return;
    }
    if (!known(s, key)) osrec_platform_stop(OSREC_STOP_UNKNOWN_SYSREG, c->pc, key, 0);
    /* A changed MMU/FP/debug regime needs platform support, not just a new
     * shadow value. Per-CPU and context identifiers are plain stored state. */
    if (key != SYSREG(3, 0, 13, 0, 4) && key != SYSREG(3, 0, 13, 0, 1) &&
        key != SYSREG(3, 3, 13, 0, 2) && /* virtual TPIDR_EL0; never host TLS */
        key != R_PAR_EL1 && s->value[key] != v)
        osrec_platform_stop(OSREC_STOP_UNSUPPORTED, c->pc, key, 0);
    set(s, key, v);
}

/* ERET from kernel code: to the user program (SPSR.M = EL0t) or back into kernel code (EL1h). */
static void exception_return(struct osrec_shadow *s, struct osrec_context *c)
{
    uint64_t spsr = s->spsr;
    if (((spsr & 0xf) != M_EL0T && (spsr & 0xf) != M_EL1H) ||
        (spsr & ~(USER_PSTATE | DAIF_ALL | (1ull << 22) | 0xf)))
        osrec_platform_stop(OSREC_STOP_UNSUPPORTED, c->pc, spsr, 0);
    s->daif = spsr & DAIF_ALL;
    s->pan = spsr >> 22 & 1;
    c->pc = s->elr;
    c->pstate = (spsr & USER_PSTATE) | M_EL0T;
    if ((spsr & 0xf) == M_EL0T) {
        s->sp_el1 = c->sp;     /* the kernel stack pointer the next exception starts from */
        c->sp = s->sp_el0;     /* kernel_exit left the user stack pointer in SP_EL0 */
        s->mode = OSREC_USER;
    } else {
        s->mode = OSREC_KERNEL; /* EL1h: the stack pointer continues */
    }
}

void osrec_enter_kernel(struct osrec_shadow *s, struct osrec_context *c, uint64_t esr, uint64_t far, int from_user)
{
    if (from_user && (c->pstate & ~USER_PSTATE))
        osrec_platform_stop(OSREC_STOP_UNSUPPORTED, c->pc, c->pstate, far);
    s->entries++;
    s->elr = c->pc;
    s->far = far;
    if (from_user) {
        s->spsr = c->pstate & USER_PSTATE;   /* the user's PSTATE (EL0t) */
        s->esr = esr;
        s->sp_el0 = c->sp;                    /* the user stack pointer; kernel_entry saves it and loads current */
        c->sp = s->sp_el1;
        s->mode = OSREC_KERNEL;
        c->pc = s->vbar + 0x400;              /* lower EL, AArch64, synchronous */
    } else {
        s->spsr = (c->pstate & USER_PSTATE) | s->daif | (s->pan << 22) | M_EL1H;
        /* The hardware reported a lower-EL exception; the kernel code must see one from its own level. */
        uint64_t ec = EC(esr);
        if (ec == 0x24 || ec == 0x20) esr += 1ull << 26;  /* data/instruction abort: lower EL -> same EL */
        s->esr = esr;
        c->pc = s->vbar + 0x200;              /* current EL with SP_ELx, synchronous */
    }
    s->daif = DAIF_ALL;
    c->pstate = c->pstate & USER_PSTATE;       /* EL0t underneath */
}

int osrec_enter_syscall(struct osrec_shadow *s, struct osrec_context *c,
                        uint32_t insn, enum osrec_syscall_entry entry)
{
    if (!s || !c || s->mode != OSREC_USER || c->pc & 3 ||
        c->pstate & ~USER_PSTATE || (insn & 0xffe0001fu) != 0xd4000001u)
        return 0;
    if (entry == OSREC_ENTRY_VENEER) {
        if (c->pc > UINT64_MAX - 4) return 0;
    } else if (entry != OSREC_ENTRY_SVC || c->pc < 4) return 0;
    if (entry == OSREC_ENTRY_VENEER) c->pc += 4;
    /* SVC does not produce a new FAR value. Keep the captured architecture's
     * FAR, rather than importing a monitor/host handler's unrelated FAR. */
    osrec_enter_kernel(s, c, (0x15ull << 26) | (1ull << 25) |
                        ((insn >> 5) & 0xffff), s->far, 1);
    return 1;
}

void osrec_emulate_site(struct osrec_shadow *s, struct osrec_context *c, uint32_t insn)
{
    s->emulated++;
    unsigned rt = insn & 31;
    if ((insn & 0xfff00000u) == 0xd5300000u) {            /* MRS Xt, <sysreg> */
        put(c, rt, read_sysreg(s, c, (insn >> 5) & 0xffff));
    } else if ((insn & 0xfff00000u) == 0xd5100000u) {     /* MSR <sysreg>, Xt */
        write_sysreg(s, c, (insn >> 5) & 0xffff, reg(c, rt));
    } else if ((insn & 0xfff8f01fu) == 0xd500401fu) {     /* MSR <pstatefield>, #imm */
        unsigned op1 = insn >> 16 & 7, op2 = insn >> 5 & 7, imm = insn >> 8 & 15;
        if (op1 == 3 && op2 == 6) s->daif |= imm << 6;                   /* DAIFSet */
        else if (op1 == 3 && op2 == 7) s->daif &= ~(uint64_t)(imm << 6); /* DAIFClr */
        else if (op1 == 0 && op2 == 4) s->pan = imm & 1;                 /* PAN */
        else if (!((op1 == 0 && op2 == 3) || (op1 == 3 && (op2 == 1 || op2 == 2 || op2 == 4))))
            osrec_platform_stop(OSREC_STOP_UNSUPPORTED, c->pc, insn, 0);
    } else if ((insn & 0xfff80000u) == 0xd5080000u) {     /* SYS: TLB, cache and address-translation operations */
        unsigned op1 = insn >> 16 & 7, crn = insn >> 12 & 15, crm = insn >> 8 & 15, op2 = insn >> 5 & 7;
#ifdef OSREC_NATIVE
        if (op1 == 3 && crn == 7 && crm == 4 && op2 == 1) lk_native_zero(c->pc,reg(c,rt));
        else
#endif
        if (crn == 8) osrec_platform_tlb_flush();
        else if (op1 == 0 && crn == 7 && (crm == 1 || crm == 5) && op2 == 0) osrec_platform_icache_flush();
        else if (crn == 7 && (crm == 6 || crm == 10 || crm == 14)) osrec_platform_dcache_clean_invalidate(reg(c, rt));
        else if (op1 == 0 && crn == 7 && crm == 8) {
            uint64_t va = reg(c, rt);
            /* Our upper-half AP bits grant EL0 access to kernel code. Do not
             * report those artificial permissions as the captured kernel's. */
            if (op2 > 3 || (op2 >= 2 && va >> 48 == 0xffff))
                osrec_platform_stop(OSREC_STOP_UNSUPPORTED, c->pc, insn, va);
            set(s, R_PAR_EL1, osrec_platform_translate(va, op2));
        }
        else osrec_platform_stop(OSREC_STOP_UNSUPPORTED, c->pc, insn, 0);
    } else if (insn == 0xd503229fu) {                     /* CSDB: no register state */
#ifdef __aarch64__
        __asm__ volatile("hint #20" ::: "memory");
#endif
    } else if (insn == 0xd69f03e0u) {                     /* ERET */
        exception_return(s, c);
        return;
    } else {                                              /* HVC, SMC, WFI and anything else */
        osrec_platform_stop(OSREC_STOP_UNSUPPORTED, c->pc, insn, 0);
    }
    c->pc += 4;
}

const struct osrec_site *osrec_find_site(const struct osrec_site *sites, uint64_t count, uint64_t va)
{
    uint64_t lo = 0, hi = count;
    while (lo < hi) {
        uint64_t mid = lo + (hi - lo) / 2;
        if (sites[mid].va < va) lo = mid + 1;
        else hi = mid;
    }
    return lo < count && sites[lo].va == va ? &sites[lo] : 0;
}

void osrec_handle_exception(struct osrec_shadow *s, struct osrec_context *c,
                            const struct osrec_site *sites, uint64_t count, uint64_t esr, uint64_t far)
{
    uint64_t ec = EC(esr);
    if (s->mode == OSREC_USER && (ec == 0x20 || ec == 0x24) && far >> 48 == 0xffff)
        osrec_platform_stop(OSREC_STOP_USER_KERNEL, c->pc, esr, far);
    /* A user BRK, including these immediates, belongs to the captured kernel.
     * Only its own rewritten instruction sites invoke the monitor protocol. */
    if (ec == 0x3c && s->mode == OSREC_KERNEL) {
        if ((esr & 0xffff) == OSREC_BRK_SITE) {
            const struct osrec_site *site = osrec_find_site(sites, count, c->pc);
            if (!site) osrec_platform_stop(OSREC_STOP_NO_SITE, c->pc, esr, far);
#ifdef OSREC_LOWERED
            if (site->reserved) { osrec_lowered_site(s, c, site); return; }
#endif
            osrec_emulate_site(s, c, site->insn);
            return;
        }
        if ((esr & 0xffff) == OSREC_BRK_BOUNDARY)
            osrec_platform_stop(OSREC_STOP_BOUNDARY, c->pc, esr, far);
    }
    if (s->mode == OSREC_USER) {
        if (ec == 0x15) {
            uint32_t insn = 0xd4000001u | ((esr & 0xffffu) << 5);
            if (!osrec_enter_syscall(s, c, insn, OSREC_ENTRY_SVC))
                osrec_platform_stop(OSREC_STOP_UNSUPPORTED, c->pc, esr, far);
            return;
        }
        osrec_enter_kernel(s, c, esr, far, 1);
        return;
    }
    if (ec == 0x24 || ec == 0x20 || ec == 0x3c || ec == 0x22 || ec == 0x26) {
        osrec_enter_kernel(s, c, esr, far, 0);
        return;
    }
    osrec_platform_stop(ec == 0 ? OSREC_STOP_UNDEFINED : OSREC_STOP_EXCEPTION, c->pc, esr, far);
}
