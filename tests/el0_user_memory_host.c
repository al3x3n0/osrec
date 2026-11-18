/* Freestanding differential reference for the emitted live-PTE fast path. */
#include "program.h"
#define BASE 0x40000000ull
unsigned char flat_phys[65536] __attribute__((aligned(4096)));
struct osrec_shadow flat_shadow;
struct flat_full_image flat_program;
struct flat_control control,*flat_active=&control;
const struct flat_text_span flat_immutable_text[]={{BASE,4096},{BASE+0x7000,4096},{BASE+0xf000,4096}};
const uint64_t flat_immutable_text_count=3;
const unsigned char flat_immutable_page_bits[]={0x81,0x80};
const uint64_t flat_user_excluded[]={1,1ull<<40,(1ull<<40)+4096};
uint64_t test_fast;
uint64_t test_vector[2] __attribute__((aligned(16)));
static unsigned char stack[16384] __attribute__((aligned(16)));
typedef void (*probe)(const struct osrec_context *,struct osrec_context *);
struct fixture {unsigned word,tcr,group;probe run;};
#include "cases.h"
static void clear(void *v,size_t n){unsigned char *p=v;while(n--)*p++=0;}
static void put(unsigned offset,uint64_t v){for(unsigned i=0;i<8;i++)flat_phys[offset+i]=(unsigned char)(v>>(8*i));}
static uint64_t get(unsigned offset){uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)flat_phys[offset+i]<<(8*i);return v;}
int test_main(void)
{
    struct flat_ram ram={BASE,sizeof flat_phys,flat_phys};
    const struct flat_mapping kernel={1ull<<40,BASE+0x4000,4096,(1<<6)|(1<<10)};
    flat_program.memory=(struct flat_memory){.ram=&ram,.ram_count=1,.kernel=&kernel,.kernel_count=1,.tcr=16};
    /* Repeat after table changes: no cached translation can satisfy this test. */
    for(unsigned pass=0;pass<2;pass++)for(unsigned f=0;f<sizeof fixtures/sizeof fixtures[0];f++)for(unsigned mode=0;mode<32;mode++) {
        const unsigned w=fixtures[f].word,rn=w>>5&31,rt=w&31;
        int write=!(w&(1u<<22));
        int vector=w==0x3dc00020u || w==0x3d800020u;
        unsigned bytes=vector || w==0xa9400820u || fixtures[f].group?16:w==0xb862d820u?4:8;
        int explicit_user=(w&0x3f200c00u)==0x38000800u || fixtures[f].group;
        uint64_t va=0x8000,leaf=BASE+0x4000+4096*pass;
        clear(flat_phys,sizeof flat_phys);clear(&flat_shadow,sizeof flat_shadow);
        flat_shadow.mode=explicit_user?OSREC_KERNEL:OSREC_USER;
        flat_program.memory.ttbr0=BASE;
        flat_program.memory.tcr=fixtures[f].tcr;
        unsigned start=3-(64-fixtures[f].tcr-13)/9,ptleaf=(3-start)*4096;
        for(unsigned i=0;i<3-start;i++)put(i*4096,BASE+(i+1)*4096+3);
        put(ptleaf+8*8,leaf+3+(1<<6)+(1<<10));
        switch(mode) {
        case 1:put(ptleaf+8*8,0);break;                       /* demand fault */
        case 2:put(ptleaf+8*8,leaf+3+(1<<10));break;         /* no EL0 access */
        case 3:put(ptleaf+8*8,leaf+3+(1<<6));break;          /* AF clear */
        case 4:put(ptleaf+8*8,leaf+3+(1<<6)+(1<<7)+(1<<10));break;
        case 5:put(0,BASE+0x1000+3+(1ull<<61));break;        /* table no-user */
        case 6:put(0,BASE+0x1000+3+(1ull<<62));break;        /* table read-only */
        case 7:put(ptleaf+8*8,0x9000000+3+(1<<6)+(1<<10));break;
        case 8:put(0,0x9000000+3);break;                    /* missing table */
        case 9:va=(1ull<<40);break;                         /* kernel domain */
        case 10:va=(1ull<<48);break;                        /* address size */
        case 11:leaf=BASE+0x7000;put(ptleaf+8*8,leaf+3+(1<<6)+(1<<10));break;
        case 12:va=0x8ffc;break;                            /* split transfer */
        case 13:put(0,BASE+0x1000+3+(1ull<<59)+(1ull<<60));break; /* XN is not data AP */
        case 14:put(ptleaf+8*8,leaf+1+(1<<6)+(1<<10));break;/* invalid L3 */
        case 15:flat_program.memory.ttbr0=BASE+0x6000;break; /* changed root */
        case 16:flat_program.memory.tcr=fixtures[f].tcr^1;break;           /* unsupported geometry */
        case 17:flat_shadow.mode=OSREC_KERNEL;break;         /* mode guard */
        case 18:put(0,BASE+1+(1<<6)+(1<<10));break;          /* invalid L0 block */
        case 20:if(start<=1)put((1-start)*4096,BASE+1+(1<<6)+(1<<10));break;
        case 21:put((2-start)*4096,BASE+1+(1<<6)+(1<<10));break;
        case 22:put(0x6000,get(0));flat_program.memory.ttbr0=BASE+0x6000;break;
        case 24:va=(1ull<<40)+0x8000;if(start==0)put(16,get(0));break;
        case 25:leaf=BASE+0xf000;put(ptleaf+8*8,leaf+3+(1<<6)+(1<<10));break;
        case 26:leaf=BASE;put(ptleaf+8*8,leaf+3+(1<<6)+(1<<10));break;
        case 27:leaf=BASE+sizeof flat_phys;put(ptleaf+8*8,leaf+3+(1<<6)+(1<<10));break;
        case 28:put(0,get(0)|(1ull<<61));put(ptleaf+8*8,0);break; /* parent AP plus invalid leaf */
        case 29:put(0,get(0)|(1ull<<62));put(ptleaf+8*8,0);break; /* table RO plus invalid leaf */
        case 30:put(0,0x9000000+3+(1ull<<61));break;             /* parent AP plus missing child RAM */
        case 31:put(0,get(0)|(1ull<<62));put(ptleaf+8*8,leaf+3+(1<<6));break; /* table RO plus AF clear */
        case 19:va=0x8004;break;                            /* alignment fallback */
        }
        struct osrec_context before={0},after={0},expected;
        for(unsigned r=0;r<31;r++)before.x[r]=100+r;
        before.sp=(uintptr_t)(stack+sizeof stack);before.pstate=(uint64_t)(mode&15)<<28;
        before.x[0]=777;before.x[rn==31?1:rn]=va;
        control.guest_sp=va;
        if(w==0xb862d820u){before.x[2]=mode==23?~1ull:2;before.x[1]=mode==23?va+8:va-8;}
        if((w&0x3b000000u)==0x38000000u && (w>>10&3)==3) {
            if(rn==31)control.guest_sp=va-8;else before.x[rn]=va-8;
        }
        struct flat_translation t=flat_translate(&flat_program.memory,va,bytes,write?FLAT_WRITE:FLAT_READ,1);
        int fast=!t.fault && (va&4095)<=4096-(bytes) &&
            flat_program.memory.tcr==fixtures[f].tcr && (explicit_user || flat_shadow.mode==OSREC_USER) &&
            !(write && (mode==11 || mode==25 || mode==26)) && !(w==0xc8dffc20u && (va&7));
        expected=before;
        if(!t.fault && t.pa>BASE && t.pa-BASE+16<=sizeof flat_phys) {
            put((unsigned)(t.pa-BASE),123);put((unsigned)(t.pa-BASE)+8,456);
        }
        unsigned slot=t.fault?0:(unsigned)(t.pa-BASE);
        uint64_t old=slot<sizeof flat_phys-8?get(slot):0;
        uint64_t first=slot<sizeof flat_phys-8?get(slot):0;
        uint64_t second=slot<sizeof flat_phys-16?get(slot+8):0;
        if(fast && !write && !vector) {
            expected.x[rt]=first;
            if(w==0xa9400820u || fixtures[f].group)expected.x[2]=second;
        }
        if(fast && (w==0xf8408420u || w==0xf8408c20u))expected.x[1]=va+((w==0xf8408420u)?8:0);
        test_fast=99;
        fixtures[f].run(&before,&after);
        if(test_fast!=(unsigned)fast)return 10+mode;
        const uint64_t *a=(const void *)&after,*b=(const void *)&expected;
        for(unsigned i=0;i<34;i++)if(a[i]!=b[i])return 40+mode;
        uint64_t expected_sp=va;
        if(w==0xf84087e0u && fast)expected_sp=va+8;
        if(control.guest_sp!=expected_sp)return 70+mode;
        for(unsigned lane=0;lane<2;lane++)if(test_vector[lane]!=(vector && fast && !write?(lane?second:first):0x5a5a5a5a5a5a5a5aull))return 125+mode;
        if(vector && fast && write && get(slot+8)!=0x5a5a5a5a5a5a5a5aull)return 150+mode;
        if(slot<sizeof flat_phys-8 && get(slot)!=(fast && write?(vector?0x5a5a5a5a5a5a5a5aull:before.x[0]):old))return 100+mode;
    }
    return 0;
}
