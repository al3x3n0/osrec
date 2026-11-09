/* Kernel code at EL0: the shared emulation core's interface.
 *
 * The kernel's own instructions run at EL0. Every instruction that EL0 may not execute (or whose meaning
 * differs there) was replaced at build time by `brk #OSREC_BRK_SITE`, or by a branch to a linked shadow-register
 * veneer when enabled; the original word is kept in a sorted site table. The core emulates the original against a shadow of the EL1 system registers, and emulates
 * exception entry and return between the user program and the kernel code. A runtime (the mini-OS monitor,
 * or a host-process runtime) delivers traps to the core and supplies the few platform actions below.
 */
#ifndef OSREC_EL0_H
#define OSREC_EL0_H
#include <stdint.h>

#define OSREC_BRK_SITE 0xF00u      /* an emulated instruction site */
#define OSREC_BRK_BOUNDARY 0xF01u  /* a word of a boundary function (explicit stop) */

/* The interrupted EL0 context, as a runtime saves it (layout shared with the assembly). */
struct osrec_context {
    uint64_t x[31];
    uint64_t sp;      /* SP_EL0: the user's or the kernel code's stack pointer */
    uint64_t pc;
    uint64_t pstate;  /* SPSR of the trap: NZCV and EL0t */
};

/* One emulated site: the virtual address and the original instruction word. */
struct osrec_site {
    uint64_t va;
    uint32_t insn;
    uint32_t reserved;
};

enum osrec_mode { OSREC_USER = 0, OSREC_KERNEL = 1 };
enum osrec_syscall_entry { OSREC_ENTRY_VENEER = 0, OSREC_ENTRY_SVC = 1 };

enum osrec_stop {
    OSREC_STOP_BOUNDARY = 1,        /* a boundary function was entered */
    OSREC_STOP_UNKNOWN_SYSREG = 2,  /* read of a system register with no captured value */
    OSREC_STOP_UNSUPPORTED = 3,     /* an original instruction the core does not emulate (hvc, smc, wfi...) */
    OSREC_STOP_NO_SITE = 4,         /* brk #OSREC_BRK_SITE at an address missing from the site table */
    OSREC_STOP_UNDEFINED = 5,       /* an undefined-instruction exception from kernel code */
    OSREC_STOP_EXCEPTION = 6,       /* an exception from kernel code the core does not reflect */
    OSREC_STOP_RUNTIME = 7,         /* the runtime itself faulted */
    OSREC_STOP_USER_KERNEL = 8,     /* user code tried to access the kernel address space */
    OSREC_STOP_LOWERING = 9,        /* an address operation needs a reviewed lowering rule */
};

/* Shadow EL1 state. Registers with a meaning to the core have fields; every other system register lives in
 * the table indexed by its 16-bit MRS/MSR encoding (op0:op1:CRn:CRm:op2). */
struct osrec_shadow {
    uint64_t sp_el0;   /* `current` inside the kernel, the user stack pointer outside it */
    uint64_t sp_el1;   /* the kernel stack pointer at the next exception from the user program */
    uint64_t elr, spsr, esr, far;
    uint64_t daif;     /* DAIF format: bits 9:6 */
    uint64_t pan;
    uint64_t vbar;
    uint64_t ttbr0;
    uint64_t mode;     /* enum osrec_mode */
    uint64_t emulated; /* sites emulated */
    uint64_t entries;  /* exceptions reflected into the kernel code */
    uint8_t known[65536 / 8];
    uint64_t value[65536];
};

/* Platform actions a runtime provides. */
void osrec_platform_set_ttbr0(uint64_t ttbr0);
void osrec_platform_set_ttbr1(uint64_t ttbr1);  /* the ASID (TCR.A1); the runtime keeps its own table root */
void osrec_platform_tlb_flush(void);
void osrec_platform_icache_flush(void);
void osrec_platform_dcache_clean_invalidate(uint64_t va);
uint64_t osrec_platform_translate(uint64_t va, int op);  /* AT S1E1R/W; returns PAR_EL1 format */
void osrec_platform_set_tpidrro(uint64_t value);
__attribute__((noreturn)) void osrec_platform_stop(uint64_t reason, uint64_t pc, uint64_t esr, uint64_t far);

/* The core. */
void osrec_emulate_site(struct osrec_shadow *s, struct osrec_context *c, uint32_t insn);
void osrec_enter_kernel(struct osrec_shadow *s, struct osrec_context *c, uint64_t esr, uint64_t far, int from_user);
/* VENEER supplies the original instruction PC; SVC supplies the post-SVC PC.
 * False means invalid input, with both structures unchanged. */
int osrec_enter_syscall(struct osrec_shadow *s, struct osrec_context *c,
                        uint32_t insn, enum osrec_syscall_entry entry);
const struct osrec_site *osrec_find_site(const struct osrec_site *sites, uint64_t count, uint64_t va);
void osrec_handle_exception(struct osrec_shadow *s, struct osrec_context *c,
                            const struct osrec_site *sites, uint64_t count, uint64_t esr, uint64_t far);
#ifdef OSREC_LOWERED
int osrec_lowered_address(uint64_t va);
void osrec_lowered_site(struct osrec_shadow *s, struct osrec_context *c, const struct osrec_site *site);
void osrec_lowered_exception(struct osrec_shadow *s, struct osrec_context *c, uint64_t esr, uint64_t far);
void osrec_lowered_mmu(int force);
#endif

#endif
