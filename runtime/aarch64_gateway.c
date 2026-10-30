#include "osrec/aarch64_gateway.h"
extern uint32_t osrec_aarch64_gateway_enter(struct osrec_aarch64_gateway *);
/* Private run mode, carried across exception entry in the existing busy flag. */
#define PAUSE_AT_SVC 2u
static int overlap(const void *a,size_t an,const void *b,size_t bn)
{uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return x<=y ? y-x<an : x-y<bn;}
static uint32_t word(const unsigned char *p)
{return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static size_t spans(const struct osrec_aarch64_gateway *g)
{return g->executables ? g->executable_count : 1;}
static const struct osrec_user_region *span(const struct osrec_aarch64_gateway *g,size_t i)
{return g->executables ? &g->executables[i] : &g->executable;}
static const unsigned char *code(const struct osrec_aarch64_gateway *g,uint64_t pc)
{
    for(size_t i=0;i<spans(g);++i){const struct osrec_user_region *r=span(g,i);
        if(pc>=r->user_address && pc-r->user_address<=r->bytes && 4<=r->bytes-(size_t)(pc-r->user_address))
            return r->image_address+(size_t)(pc-r->user_address);
    }return 0;
}
static int brk(const struct osrec_aarch64_gateway *g,uint64_t pc,uint32_t immediate)
{const unsigned char *p=code(g,pc);return p && word(p)==(UINT32_C(0xd4200000)|(immediate<<5));}
/* Application addresses are image addresses, so the MMU must be off or translate
 * through start_mmu.S's identity map (VA == PA), recognized by its level-1 table
 * and translation control. start_mmu.S defines the table; in other images this
 * empty weak placeholder stands in, and an empty table maps nothing. */
__attribute__((weak)) const uint64_t osrec_level1[1];
static int identity_mapped(void)
{
    uint64_t ttbr,tcr;__asm__ volatile("mrs %0, TTBR0_EL1\nmrs %1, TCR_EL1":"=r"(ttbr),"=r"(tcr));
    return ttbr==(uintptr_t)osrec_level1 && osrec_level1[0] && tcr==UINT64_C(0x800020);
}
static int preflight(struct osrec_aarch64_gateway *g,int pause)
{
    if(g->abi!=OSREC_AARCH64_GATEWAY_ABI || !g->session || g->session->initialized!=1 || !g->application ||
       osrec_aarch64_abi_validate(g->registers) || !g->sites || !g->site_count || g->site_count>65536 ||
       !g->stack || g->stack_bytes<OSREC_AARCH64_GATEWAY_STACK_MIN || ((uintptr_t)g->stack&15) ||
       (g->stack_bytes&15) || g->stack_bytes>UINTPTR_MAX-(uintptr_t)g->stack)return 0;
    if(g->site_count>g->session->adapter->calls-g->session->next || g->site_count>UINT64_MAX-g->session->next)return 0;
    if(pause && g->site_count==g->session->adapter->calls-g->session->next)return 0;
    struct osrec_aarch64_frame *f=g->application;
    if((f->pstate&~UINT64_C(0xf00003c0)) || (f->pstate&0x3c0)!=0x3c0 || (f->sp&15) || f->sp<16 ||
       !f->pc || (f->pc&3) || !g->exit_pc || (g->exit_pc&3))return 0;
    if((g->executables && (!g->executable_count || g->executable_count>4096)) || (!g->executables && g->executable_count))return 0;
    for(size_t i=0;i<spans(g);++i){const struct osrec_user_region *r=span(g,i);
        if(!r->bytes || !r->image_address || r->user_address!=(uintptr_t)r->image_address || (r->user_address&3) ||
           r->bytes>UINT64_MAX-r->user_address || r->permissions!=OSREC_MEMORY_READ ||
           overlap(r->image_address,r->bytes,g,sizeof(*g)) || overlap(r->image_address,r->bytes,f,sizeof(*f)) ||
           overlap(r->image_address,r->bytes,g->stack,g->stack_bytes))return 0;
        for(size_t j=0;j<i;++j)if(overlap(r->image_address,r->bytes,span(g,j)->image_address,span(g,j)->bytes))return 0;
    }
    if(!code(g,f->pc) || !brk(g,g->exit_pc,pause ? OSREC_AARCH64_ROUTE_BRK : OSREC_AARCH64_EXIT_BRK))return 0;
    if(overlap(g,sizeof(*g),f,sizeof(*f)) || overlap(g,sizeof(*g),g->stack,g->stack_bytes) ||
       overlap(f,sizeof(*f),g->stack,g->stack_bytes))return 0;
    uint64_t el,select,daif,sctlr;
    __asm__ volatile("mrs %0, CurrentEL\nmrs %1, SPSel\nmrs %2, DAIF\nmrs %3, SCTLR_EL1":"=r"(el),"=r"(select),"=r"(daif),"=r"(sctlr));
    if(el!=4 || select!=1 || (daif&0x3c0)!=0x3c0 || ((sctlr&1) && !identity_mapped()))return 0;
    for(size_t i=0;i<g->site_count;++i){const struct osrec_aarch64_site *s=&g->sites[i];
        if(s->ordinal!=g->session->next+i || (s->svc_pc&3) || s->svc_pc>UINT64_MAX-4 || s->continuation_pc!=s->svc_pc+4 ||
           !brk(g,s->svc_pc,OSREC_AARCH64_ROUTE_BRK) || !code(g,s->continuation_pc) || osrec_user_memory_validate(&s->memory))return 0;
        const unsigned char *original=osrec_user_memory_resolve(&s->memory,s->svc_pc,4,OSREC_MEMORY_READ);
        if(!original || (word(original)&UINT32_C(0xffe0001f))!=UINT32_C(0xd4000001) ||
           !osrec_user_memory_resolve(&s->memory,s->continuation_pc,4,OSREC_MEMORY_READ))return 0;
        if(pause){
            const unsigned char *boundary=osrec_user_memory_resolve(&s->memory,g->exit_pc,4,OSREC_MEMORY_READ);
            if(!boundary || (word(boundary)&UINT32_C(0xffe0001f))!=UINT32_C(0xd4000001) ||
               g->exit_pc>UINT64_MAX-4 || !code(g,g->exit_pc+4) ||
               !osrec_user_memory_resolve(&s->memory,g->exit_pc+4,4,OSREC_MEMORY_READ))return 0;
        }
        if(!osrec_user_memory_resolve(&s->memory,f->sp-16,16,OSREC_MEMORY_READ|OSREC_MEMORY_WRITE))return 0;
        for(size_t j=0;j<s->memory.count;++j){const struct osrec_user_region *m=&s->memory.regions[j];
            if(!(m->permissions&OSREC_MEMORY_WRITE))continue;
            if(m->user_address!=(uintptr_t)m->image_address || overlap(m->image_address,m->bytes,g,sizeof(*g)) ||
               overlap(m->image_address,m->bytes,g->stack,g->stack_bytes) || overlap(m->image_address,m->bytes,f,sizeof(*f)))return 0;
            for(size_t k=0;k<spans(g);++k)if(overlap(m->image_address,m->bytes,span(g,k)->image_address,span(g,k)->bytes))return 0;
        }
    }
    return 1;
}
static uint32_t run(struct osrec_aarch64_gateway *g,int pause)
{
    if(!g)return OSREC_SLICE_BAD_INPUT;if(g->active)return OSREC_SLICE_BUSY;
    if(g->session && g->session->initialized==1){
        if(g->session->active){g->status=OSREC_SLICE_BUSY;return g->status;}
        if(g->session->poisoned){g->status=OSREC_SLICE_POISONED;return g->status;}
        if(g->session->next>=g->session->adapter->calls){g->status=OSREC_SLICE_COMPLETE;return g->status;}
    }
    if(!preflight(g,pause)){g->status=OSREC_SLICE_BAD_INPUT;g->diagnostic=0;return g->status;}
    g->active=1u|(pause ? PAUSE_AT_SVC : 0u);g->status=OSREC_SLICE_OK;g->diagnostic=0;g->cursor=0;g->entries=0;g->exits=0;
    g->kernel_sp=(uintptr_t)g->stack+g->stack_bytes-16;
    uint32_t status=osrec_aarch64_gateway_enter(g);g->active=0;return status;
}
uint32_t osrec_aarch64_gateway_run(struct osrec_aarch64_gateway *g){return run(g,0);}
uint32_t osrec_aarch64_gateway_run_window(struct osrec_aarch64_gateway *g){return run(g,1);}
/* Called only by embedded vectors, with a complete hardware-saved app frame. */
uint32_t osrec_aarch64_gateway_trap(struct osrec_aarch64_gateway *g,const struct osrec_aarch64_frame *f,uint64_t esr)
{
    /* A fault inside the slice is not an application register checkpoint. */
    if((f->pstate&15)!=0){g->status=OSREC_SLICE_DIVERGED;g->diagnostic=(uint32_t)esr;g->session->active=0;g->session->poisoned=1;return 1;}
    *g->application=*f;
    uint32_t exit_immediate=(g->active&PAUSE_AT_SVC) ? OSREC_AARCH64_ROUTE_BRK : OSREC_AARCH64_EXIT_BRK;
    if((esr>>26)==0x3c && (esr&0xffff)==exit_immediate && f->pc==g->exit_pc && g->cursor==g->site_count){++g->exits;return 1;}
    if((esr>>26)!=0x3c || (esr&0xffff)!=OSREC_AARCH64_ROUTE_BRK || g->cursor>=g->site_count || f->pc!=g->sites[g->cursor].svc_pc){
        g->status=OSREC_SLICE_DIVERGED;g->diagnostic=(uint32_t)esr;g->session->poisoned=1;return 1;
    }
    ++g->entries;
    g->status=osrec_aarch64_syscall(g->session,g->registers,g->application,&g->sites[g->cursor],&g->result);
    g->diagnostic=g->result.diagnostic;
    if(g->status!=OSREC_SLICE_OK)return 1;
    ++g->cursor;return 0;
}
