#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "el0.h"
struct osrec_shadow osrec_shadow;
const uint64_t osrec_ttbr1_root=0x50000000,osrec_ttbr1_user_root=0x50001000;
static uint64_t kernel[4][512],user[4][512],unpriv[4][512];
static struct {uint64_t pa;uint64_t *p;} pages[512];
static unsigned count,installs;
static uint64_t installed,reason,fault;
static jmp_buf stopped;
uint64_t *osrec_test_physical(uint64_t pa) { for(unsigned i=0;i<count;i++) if(pages[i].pa==pa) return pages[i].p;assert(!"unknown PA");return 0; }
uint64_t osrec_test_pa(void *p) { for(unsigned i=0;i<count;i++) if(pages[i].p==p) return pages[i].pa;uint64_t pa=0x70000000ull+4096*count;pages[count].pa=pa;pages[count++].p=p;return pa; }
void osrec_test_install(uint64_t pa) { installed=pa;installs++; }
void osrec_platform_stop(uint64_t r,uint64_t pc,uint64_t d,uint64_t far) { (void)pc;(void)d;reason=r;fault=far;longjmp(stopped,1); }
static void add(uint64_t pa,uint64_t *p) { pages[count].pa=pa;pages[count++].p=p; }
static uint64_t leaf(uint64_t va) { uint64_t *p=osrec_test_physical(installed);for(unsigned shift=39;shift>12;shift-=9)p=osrec_test_physical(p[va>>shift&511]&0x0000fffffffff000ull);return p[va>>12&511]; }
int main(void)
{
    for(unsigned j=0;j<4;j++) { add(0x50000000+4096*j,kernel[j]);add(0x51000000+4096*j,user[j]);add(0x52000000+4096*j,unpriv[j]); }
    // Separate user/kernel roots; make their common PGD and two further levels
    // share a path so table-level permissions must be pushed to leaves.
    kernel[0][1]=0x50001003;kernel[1][0]=0x50002003;kernel[2][0]=0x50003003;
    kernel[3][1]=0x44000443; // kernel page, RW at EL0
    user[0][1]=0x51001003ull|(1ull<<59);user[1][0]=0x51002003;user[2][0]=0x51003003;
    user[3][2]=0x45000443;
    // The user-mode kernel root uses the original privileged-only permissions.
    memcpy(unpriv,kernel,sizeof(kernel));unpriv[0][1]=0x52001003;unpriv[1][0]=0x52002003;unpriv[2][0]=0x52003003;unpriv[3][1]&=~64ull;
    // osrec_ttbr1_user_root is 0x50001000, also mapped above as kernel[1].
    // Override that PA with a dedicated root while retaining kernel child PAs.
    static uint64_t user_kernel_root[512];user_kernel_root[1]=0x52001003;
    for(unsigned i=0;i<count;i++) if(pages[i].pa==0x50001000)pages[i].pa=0x53001000;
    add(0x50001000,user_kernel_root);kernel[0][1]=0x53001003;
    osrec_shadow.ttbr0=0x51000000;osrec_shadow.mode=OSREC_KERNEL;
    osrec_lowered_mmu(1);
    uint64_t u=leaf(0x8000002000ull),k=leaf(0x8000001000ull);
    assert(u&(1ull<<53));assert(!(k&(1ull<<53)));assert(k&64);
    unsigned before=installs;uint64_t previous=installed;
    osrec_lowered_mmu(0);assert(installs==before);
    osrec_lowered_mmu(1);assert(installs==before+1 && installed!=previous);
    // Kernel uaccess can populate a previously absent PTE without changing
    // the root or mode. Its exception return must request a forced refresh.
    assert(!leaf(0x8000003000ull));user[3][3]=0x45001443;
    osrec_lowered_mmu(0);assert(!leaf(0x8000003000ull));
    osrec_lowered_mmu(1);assert(leaf(0x8000003000ull)==(0x45001443ull|(1ull<<53)));
    osrec_shadow.mode=OSREC_USER;osrec_lowered_mmu(0);assert(!(leaf(0x8000001000ull)&64));
    // Additional user-only restrictions propagate without restricting kernel leaves.
    user[0][1]|=(1ull<<60)|(1ull<<61)|(1ull<<62)|(1ull<<63);
    osrec_shadow.mode=OSREC_KERNEL;osrec_lowered_mmu(1);u=leaf(0x8000002000ull);k=leaf(0x8000001000ull);
    assert(u&(1ull<<54));assert(!(u&64));assert(u&128);assert(u&32);assert(k&64);
    previous=installed;before=installs;user[3][1]=0x46000443;
    if(!setjmp(stopped)) { osrec_lowered_mmu(1);assert(!"overlapping leaf must stop"); }
    assert(reason==OSREC_STOP_LOWERING && fault==0x8000001000ull && installs==before && installed==previous);
    puts("lowered MMU contracts passed");
}
