/* Native arm64 differential test of linked veneers versus full context saves. */
#include "el0.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK_OFFSET(field, offset) _Static_assert(offsetof(struct osrec_shadow, field)==offset, #field)
CHECK_OFFSET(sp_el0,0); CHECK_OFFSET(sp_el1,8); CHECK_OFFSET(elr,16);
CHECK_OFFSET(spsr,24); CHECK_OFFSET(esr,32); CHECK_OFFSET(far,40);
CHECK_OFFSET(daif,48); CHECK_OFFSET(pan,56); CHECK_OFFSET(vbar,64);
CHECK_OFFSET(ttbr0,72); CHECK_OFFSET(emulated,88);
_Static_assert(sizeof(struct osrec_shadow)==532584, "fixture shadow allocation");
extern struct osrec_shadow osrec_shadow;
static struct osrec_shadow initial, fast_shadow;
static unsigned char stack[65536] __attribute__((aligned(16)));
typedef void (*run_fn)(const struct osrec_context *,struct osrec_context *);
struct fixture { const char *name; run_fn fast, reference; };
#include "cases.h"

/* The whitelist must never invoke platform actions or stop. */
void osrec_platform_set_ttbr0(uint64_t v) { (void)v; abort(); }
void osrec_platform_set_ttbr1(uint64_t v) { (void)v; abort(); }
void osrec_platform_tlb_flush(void) { abort(); }
void osrec_platform_icache_flush(void) { abort(); }
void osrec_platform_dcache_clean_invalidate(uint64_t v) { (void)v; abort(); }
uint64_t osrec_platform_translate(uint64_t v,int op) { (void)v; (void)op; abort(); }
void osrec_platform_set_tpidrro(uint64_t v) { (void)v; abort(); }
void osrec_platform_stop(uint64_t reason,uint64_t pc,uint64_t detail,uint64_t far)
{ fprintf(stderr,"unexpected stop %lu %lx %lx %lx\n",reason,pc,detail,far); abort(); }

int main(void)
{
    struct osrec_context before,fast,reference;
    unsigned runs=0;
    for (unsigned seed=0;seed<32;seed++) {
        memset(&initial,0,sizeof initial);
        initial.sp_el0=0x123456789abcdef0ull ^ seed;
        initial.sp_el1=0xfedcba9876543210ull ^ seed;
        initial.elr=0x1122334455667788ull;
        initial.spsr=0x8877665544332211ull;
        initial.esr=0x1234567890abcdefull;
        initial.far=0xabcdef0123456789ull;
        initial.daif=(seed&15)<<6;
        initial.pan=seed&1;
        initial.vbar=0x800000008000ull;
        initial.ttbr0=0x40000000;
        initial.mode=OSREC_KERNEL;
        initial.emulated=seed&1 ? ~0ull : seed;
        for (unsigned r=0;r<31;r++)
            before.x[r]=(0x1020304050607080ull*(r+1)) ^ ((uint64_t)seed*0x9e3779b97f4a7c15ull);
        before.sp=(uint64_t)(stack+sizeof stack-16);
        before.pc=0;
        before.pstate=(uint64_t)(seed&15)<<28;
        for (unsigned i=0;i<sizeof fixtures/sizeof fixtures[0];i++) {
            osrec_shadow=initial;
            fixtures[i].fast(&before,&fast);
            fast_shadow=osrec_shadow;
            osrec_shadow=initial;
            fixtures[i].reference(&before,&reference);
            if (memcmp(&fast,&reference,sizeof fast) || memcmp(&fast_shadow,&osrec_shadow,sizeof fast_shadow)) {
                fprintf(stderr,"veneer mismatch %s seed=%u\n",fixtures[i].name,seed);
                for (unsigned r=0;r<31;r++) if(fast.x[r]!=reference.x[r])
                    fprintf(stderr,"x%u fast=%lx reference=%lx\n",r,fast.x[r],reference.x[r]);
                return 1;
            }
            runs++;
        }
    }
    printf("%u native veneer/full-save comparisons passed\n",runs);
    return 0;
}
