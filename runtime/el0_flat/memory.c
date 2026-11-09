#include "memory.h"
#define MASK 0x0000fffffffff000ull
void *flat_physical(const struct flat_memory *m,uint64_t pa,size_t bytes)
{
    if(!m || (bytes && pa>UINT64_MAX-(bytes-1)))return 0;
    for(size_t i=0;i<m->ram_count;i++) {
        const struct flat_ram *r=m->ram+i;
        if(pa>=r->pa && bytes<=r->bytes && pa-r->pa<=r->bytes-bytes)return r->data+pa-r->pa;
    }
    return 0;
}
static uint64_t qword(const void *p)
{const unsigned char *s=p;uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)s[i]<<(8*i);return v;}
static unsigned permission(uint64_t d,enum flat_access op,int user,unsigned level)
{
    if(!(d&(1ull<<10)))return 8+level;
    if((user && !(d&(1ull<<6))) || (op==FLAT_WRITE && (d&(1ull<<7))) ||
       (op==FLAT_EXECUTE && (d&(1ull<<(user?54:53)))))return 12+level;
    return 0;
}
static struct flat_translation page(const struct flat_memory *m,uint64_t va,size_t bytes,enum flat_access op,int user)
{
    struct flat_translation r={.far=va,.fault=FLAT_CROSS_PAGE};
    if(!m || !bytes || op>FLAT_EXECUTE || va>UINT64_MAX-(bytes-1) || (va&4095)+bytes>4096)return r;
    for(size_t i=0;i<m->kernel_count;i++) {
        const struct flat_mapping *k=m->kernel+i;
        if(va<k->va || va-k->va>=k->bytes)continue;
        if(bytes>k->bytes-(va-k->va))return r;
        r.attrs=k->attrs;r.pa=k->pa+va-k->va;
        r.fault=user?15:permission(r.attrs,op,0,3);
        if(!r.fault && !(r.data=flat_physical(m,r.pa,bytes)))r.fault=FLAT_MISSING_RAM;
        return r;
    }
    unsigned bits=64-(m->tcr&63);
    if((m->tcr>>14&3) || bits<25 || bits>48)return r;
    if(va>>bits){r.fault=FLAT_ADDRESS_SIZE;return r;}
    unsigned start=3-(bits-13)/9;
    uint64_t table=m->ttbr0&MASK,parent=0;
    for(unsigned level=start;level<4;level++) {
        unsigned shift=12+9*(3-level);
        const void *p=flat_physical(m,table+8*(va>>shift&511),8);
        if(!p){r.fault=FLAT_MISSING_RAM;return r;}
        uint64_t d=qword(p);
        if(!(d&1) || (level==3 && !(d&2)) || (level==0 && !(d&2))){r.fault=4+level;return r;}
        if(level<3 && (d&2)){parent|=d;table=d&MASK;continue;}
        if(parent&(1ull<<59))d|=1ull<<53;
        if(parent&(1ull<<60))d|=1ull<<54;
        if(parent&(1ull<<61))d&=~(1ull<<6);
        if(parent&(1ull<<62))d|=1ull<<7;
        r.attrs=d;r.pa=((d&MASK)&~((1ull<<shift)-1))+(va&((1ull<<shift)-1));
        r.fault=permission(d,op,user,level);
        if(!r.fault && !(r.data=flat_physical(m,r.pa,bytes)))r.fault=FLAT_MISSING_RAM;
        return r;
    }
    return r;
}
struct flat_translation flat_translate(const struct flat_memory *m,uint64_t va,size_t bytes,enum flat_access op,int user)
{
    if(!bytes || bytes<=4096-(va&4095))return page(m,va,bytes,op,user);
    struct flat_translation stopped={.far=va,.fault=FLAT_CROSS_PAGE};
    if(va>UINT64_MAX-(bytes-1))return stopped;
    size_t first=4096-(va&4095);
    struct flat_translation r=page(m,va,first,op,user);
    /* A faulting split transfer may have architectural partial effects.
     * Leave it as an explicit boundary until that case has its own lowering. */
    if(r.fault)return stopped;
    for(size_t done=first;done<bytes;) {
        size_t part=bytes-done;if(part>4096)part=4096;
        struct flat_translation next=page(m,va+done,part,op,user);
        if(next.fault || next.pa!=r.pa+done || (uintptr_t)next.data!=(uintptr_t)r.data+done)return stopped;
        done+=part;
    }
    return r;
}
