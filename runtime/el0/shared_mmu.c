/* Replay a low-linked kernel using its live user subtree and fixed kernel views. */
#include "el0.h"

#define ADDRESS 0x0000fffffffff000ull
#define ASID 0xffff000000000000ull

extern struct osrec_shadow osrec_shadow;
extern const uint64_t osrec_shared_ram_pa, osrec_shared_ram_size, osrec_shared_ram_va;
extern const uint64_t osrec_shared_monitor_pa, osrec_shared_monitor_va;
extern const uint64_t osrec_shared_guest_kernel, osrec_shared_monitor, osrec_shared_kernel[2];

static uint64_t tables[2][512] __attribute__((aligned(4096)));
static uint64_t active_bank, active_guest = UINT64_MAX, active_mode = UINT64_MAX;

void osrec_shared_mmu(int force)
{
    uint64_t guest = osrec_shadow.ttbr0;
    uint64_t mode = osrec_shadow.mode;
    if (!force && active_guest == guest && active_mode == mode)
        return;

    uint64_t pa = guest & ADDRESS;
    if (pa < osrec_shared_ram_pa || pa - osrec_shared_ram_pa >= osrec_shared_ram_size)
        osrec_platform_stop(OSREC_STOP_RUNTIME, osrec_shadow.elr, guest, pa);
    const uint64_t *source = (const uint64_t *)(osrec_shared_ram_va + pa - osrec_shared_ram_pa);
    if (source[1] != osrec_shared_guest_kernel)
        osrec_platform_stop(OSREC_STOP_RUNTIME, osrec_shadow.elr, guest, source[1]);

    active_bank ^= 1;
    uint64_t *next = tables[active_bank];
    next[0] = source[0];
    next[1] = osrec_shared_kernel[mode == OSREC_KERNEL];
    next[2] = osrec_shared_monitor;
    uint64_t ttbr = (guest & ASID) | ((uint64_t)next - osrec_shared_monitor_va + osrec_shared_monitor_pa);
    __asm__ volatile("dsb ishst\n\tmsr ttbr0_el1, %0\n\tisb\n\ttlbi vmalle1\n\tdsb ish\n\tisb"
                     :: "r"(ttbr) : "memory");
    active_guest = guest;
    active_mode = mode;
}
