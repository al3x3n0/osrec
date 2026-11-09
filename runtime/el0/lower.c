/* Address checks for the lowered layout. Kernel instructions execute themselves
 * in veneers; this code checks the address domain and preserves fault PCs. */
#include "el0.h"

#ifdef OSREC_NATIVE
#include "native_lower.h"
#else
extern const uint64_t osrec_kernel_ranges[][2], osrec_kernel_range_count;
extern const uint64_t osrec_veneer_base, osrec_veneer_count, osrec_veneer_origins[];
#endif

int osrec_lowered_address(uint64_t va)
{
    uint64_t lo=0,hi=osrec_kernel_range_count;
    while (lo<hi) {
        uint64_t mid=lo+(hi-lo)/2;
        if (va<osrec_kernel_ranges[mid][0]) hi=mid;
        else if (va>=osrec_kernel_ranges[mid][1]) lo=mid+1;
        else return 1;
    }
    return 0;
}

void osrec_lowered_site(struct osrec_shadow *s, struct osrec_context *c, const struct osrec_site *site)
{
    uint32_t word=site->insn,kind=site->reserved;
    s->emulated++;
    if (kind&0x80000000u) {
        uint64_t index=kind&0x7fffffffu;
        unsigned rn=word>>5&31;
        uint64_t address=rn==31?c->sp:c->x[rn];
        unsigned bytes=1u<<(word>>30);
        if ((word&0x3f200c00u)==0x38000800u) { /* LDTR/STTR */
            int64_t imm=(word>>12)&511;
            if (imm&256) imm-=512;
            address+=imm;
        } else if ((word&0x3f000000u)!=0x08000000u) {
            osrec_platform_stop(OSREC_STOP_LOWERING,c->pc,word,address);
        }
        if (index>=osrec_veneer_count)
            osrec_platform_stop(OSREC_STOP_LOWERING,c->pc,index,address);
        if (address>>48==0xffff || osrec_lowered_address(address) ||
            osrec_lowered_address(address+bytes-1))
            osrec_platform_stop(OSREC_STOP_USER_KERNEL,c->pc,word,address);
#ifdef OSREC_NATIVE
        /* Host mappings are not the captured process's page tables. A host
         * library/stack at this VA must never make an absent guest PTE valid. */
        if (lk_native_user_access(s,c,word,address,bytes)) return;
#endif
        c->pc=osrec_veneer_base+16*index;
        return;
    }
    if (kind&0x40000000u) {
        unsigned bit=(word>>31)*32+(word>>19&31),rt=word&31;
        uint64_t value=rt==31?0:c->x[rt];
        int set=(value>>bit)&1;
        if (osrec_lowered_address(value)) {
            /* Bit 55 is the architecture's address-space discriminator.
             * Bit 63 also tests ordinary signed scalars: require review when
             * its operand could be either an address or a large integer. */
            if (bit==63 && !(kind&1))
                osrec_platform_stop(OSREC_STOP_LOWERING,c->pc,word,value);
            set=1;
        }
        int64_t offset=(word>>5)&0x3fff;
        if (offset&0x2000) offset-=0x4000;
        c->pc+=set==(int)(word>>24&1)?4*offset:4;
        return;
    }
    osrec_platform_stop(OSREC_STOP_LOWERING,c->pc,word,0);
}

void osrec_lowered_exception(struct osrec_shadow *s, struct osrec_context *c, uint64_t esr, uint64_t far)
{
    unsigned ec=esr>>26;
    if (s->mode==OSREC_USER && (ec==0x20 || ec==0x24) && osrec_lowered_address(far))
        osrec_platform_stop(OSREC_STOP_USER_KERNEL,c->pc,esr,far);
    if (s->mode==OSREC_KERNEL && c->pc>=osrec_veneer_base &&
        c->pc<osrec_veneer_base+16*osrec_veneer_count && (ec==0x20 || ec==0x24)) {
        uint64_t index=(c->pc-osrec_veneer_base)/16;
        c->pc=osrec_veneer_origins[index];
    }
}
