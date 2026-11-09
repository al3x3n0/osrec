/* A TTBR0 view of kernel pages plus the captured program's live page tables.
 * Uncontested subtrees remain shared with the kernel's own tables. Only shared
 * paths are merged. Colliding leaves stop before exposing either domain. */
#include "el0.h"

#define MASK_PA 0x0000fffffffff000ull
#define MONITOR_VA 0x00008000f0000000ull
#define MONITOR_PA 0x71000000ull
#define TABLE_VA 0x00008000e0000000ull
#define TABLE_PA 0x70000000ull
#define LINEAR_VA 0x0000200000000000ull
#define RAM_PA 0x40000000ull
#define RAM_END 0x60000000ull
#define ARENA_PAGES 128
extern struct osrec_shadow osrec_shadow;
extern const uint64_t osrec_ttbr1_root,osrec_ttbr1_user_root;
static uint64_t arena[2][ARENA_PAGES][512] __attribute__((aligned(4096)));
static uint64_t used,bank,last_root=~0ull,last_mode=~0ull;

static uint64_t *physical(uint64_t pa)
{
#ifdef OSREC_MMU_TEST
    extern uint64_t *osrec_test_physical(uint64_t);
    return osrec_test_physical(pa);
#else
    if (pa>=RAM_PA && pa<RAM_END) return (uint64_t *)(LINEAR_VA+pa-RAM_PA);
    if (pa>=TABLE_PA && pa<MONITOR_PA) return (uint64_t *)(TABLE_VA+pa-TABLE_PA);
    if (pa>=MONITOR_PA && pa<MONITOR_PA+(16<<20)) return (uint64_t *)(MONITOR_VA+pa-MONITOR_PA);
    osrec_platform_stop(OSREC_STOP_LOWERING,osrec_shadow.elr,pa,0);
#endif
}

static uint64_t allocate(void)
{
    if (used==ARENA_PAGES) osrec_platform_stop(OSREC_STOP_LOWERING,osrec_shadow.elr,used,0);
    uint64_t *p=arena[bank][used++];
    for (unsigned i=0;i<512;i++) p[i]=0;
#ifdef OSREC_MMU_TEST
    extern uint64_t osrec_test_pa(void *);
    return osrec_test_pa(p);
#else
    return (uint64_t)p-MONITOR_VA+MONITOR_PA;
#endif
}

static uint64_t merge(uint64_t kernel,uint64_t user,unsigned level,uint64_t prefix)
{
    if (!(kernel&1)) return user;
    if (!(user&1)) return kernel;
    if (level==3 || !(kernel&2) || !(user&2))
        osrec_platform_stop(OSREC_STOP_LOWERING,osrec_shadow.elr,user,prefix);
    uint64_t out=allocate();
    uint64_t *dst=physical(out),*k=physical(kernel&MASK_PA),*u=physical(user&MASK_PA);
    unsigned shift=12+9*(2-level);
    for (unsigned i=0;i<512;i++) {
        uint64_t child[2]={k[i],u[i]},parent[2]={kernel,user};
        for (unsigned j=0;j<2;j++) {
            if (!(child[j]&1)) continue;
            uint64_t restrictions=parent[j]&0xf800000000000000ull;
            if (level+1<3 && (child[j]&2)) child[j]|=restrictions;
            else {
                if (restrictions&(1ull<<59)) child[j]|=1ull<<53;
                if (restrictions&(1ull<<60)) child[j]|=1ull<<54;
                if (restrictions&(1ull<<61)) child[j]&=~(1ull<<6);
                if (restrictions&(1ull<<62)) child[j]|=1ull<<7;
                if (restrictions&(1ull<<63)) child[j]|=1ull<<5;
            }
        }
        dst[i]=merge(child[0],child[1],level+1,prefix|((uint64_t)i<<shift));
    }
    return out|3;
}

void osrec_lowered_mmu(int force)
{
    uint64_t root=osrec_shadow.ttbr0&MASK_PA,mode=osrec_shadow.mode;
    if (!force && root==last_root && mode==last_mode) return;
    used=0;bank^=1; /* never edit the hardware's currently active root */
    uint64_t out=allocate(),kernel=mode==OSREC_KERNEL?osrec_ttbr1_root:osrec_ttbr1_user_root;
    uint64_t *dst=physical(out),*k=physical(kernel),*u=physical(root);
    for (unsigned i=0;i<512;i++) dst[i]=merge(k[i],u[i],0,(uint64_t)i<<39);
#ifdef OSREC_MMU_TEST
    extern void osrec_test_install(uint64_t);
    osrec_test_install(out);
#else
    __asm__ volatile("dsb ishst\n\tmsr ttbr0_el1, %0\n\tisb\n\ttlbi vmalle1\n\tdsb ish\n\tisb" :: "r"(out) : "memory");
#endif
    last_root=root;last_mode=mode;
}
