#define _GNU_SOURCE
#include "osrec/linuxkernel_el0_native.h"
#include "internal.h"
#include "native_lower.h"
#ifdef OSREC_FREESTANDING
#include "standalone.h"
#else
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <stdatomic.h>
#if defined(__linux__) && defined(__aarch64__)
#include <asm/sigcontext.h>
#ifndef OSREC_FREESTANDING
#include <sys/syscall.h>
#include <ucontext.h>
#endif

#define PAGE 4096ull
#define PA_MASK 0x0000fffffffff000ull
#define MAGIC 0x3145564954414e4cull /* LNATIVE1 */
struct package_header {
    uint64_t magic, version, base, size, tcr, ranges, sites, veneer, veneers, maps;
};
struct mapping { uint64_t va, pa, size, attrs; };
struct application_header { uint64_t magic,version,count,base,size,hook,word,target,text_lo,text_hi; };
struct application_site { uint64_t pc; uint32_t word,kind; uint64_t gateway; };
struct vma_config { uint64_t magic,version,root,start,end,flags,r_pivot,r_slot,a_pivot,a_slot; };
struct interval {uint64_t start,end;};
_Static_assert(sizeof(struct osrec_context)==272,"native package context ABI");
_Static_assert(sizeof(struct lk_el0_fp)==520,"native package FP ABI");
_Static_assert(sizeof(struct osrec_shadow)==532584,"native package shadow ABI");
struct lk_el0_native {
    struct package_header h;
    struct lk_el0_kernel *kernel;
    struct osrec_shadow shadow;
    struct osrec_context initial, *context;
    struct lk_el0_fp fp;
    struct lk_native_lower lower;
    struct osrec_site *sites;
    struct mapping *maps, *user, *next, *pending;
    size_t mapped, users, capacity, pendings;
    void *physical, *altstack;
    int fd;
    struct sigaction previous[4];
    unsigned handlers;
    struct lk_el0_diagnostic *diagnostic;
    enum lk_el0_status status;
    sigjmp_buf jump;
    volatile sig_atomic_t starting, handling, executing;
    struct lk_el0_counter *counters;
    uint64_t counter_count,counter_used;
    unsigned record_counters,record_mmio;
    uint64_t counter_base,counter_step,uart_va;
    struct lk_el0_mmio *mmio;
    uint64_t mmio_count,mmio_used;
    struct application_header app;
    struct application_site *app_sites;
    void *gateways;
    struct mapping *executable;
    unsigned char *executable_bytes;
    size_t executables;
    unsigned application,prepared,kernel_visible;
    struct lk_el0_event *events,*pending_event;
    uint64_t event_capacity,event_count,pending_regs;
    struct vma_config vma;
    struct interval *vmas;
    size_t vma_count;
    struct mapping *vma_pages;
    uint32_t hook_post_word;
    unsigned hook_disarmed;
};
static const int signals[4]={SIGTRAP,SIGILL,SIGSEGV,SIGBUS};
static atomic_flag owned=ATOMIC_FLAG_INIT;
/* Signal forwarding must remain valid on unrelated host threads even while
 * the owner restores dispositions and releases its mapping state. */
static struct sigaction forwarded[4];
static LK_THREAD_LOCAL struct lk_el0_native *running;
#define METADATA_BASE 0x180000000000ull
#define METADATA_SIZE (256ull<<20)
static void *metadata;
static size_t metadata_used;
static void *metadata_alloc(size_t bytes)
{
    if(bytes>METADATA_SIZE-metadata_used || bytes>SIZE_MAX-15)return NULL;
    size_t size=(bytes+15)&~(size_t)15;
    if(size>METADATA_SIZE-metadata_used)return NULL;
    void *p=(char *)metadata+metadata_used;metadata_used+=size;return p;
}
static void *metadata_calloc(size_t count,size_t bytes)
{if(bytes && count>SIZE_MAX/bytes)return NULL;return metadata_alloc(count*bytes);}
static void metadata_free(void *p){(void)p;} /* arena reclaimed at close */

const struct lk_native_lower *lk_native_lowering(void) { return &running->lower; }

static void stop(uint64_t reason,uint64_t pc,uint64_t detail,uint64_t far)
{
    struct lk_el0_native *n=running;
    *n->diagnostic=(struct lk_el0_diagnostic){reason,pc,detail,far};
    n->status=reason==OSREC_STOP_RUNTIME?LK_EL0_FAULT:LK_EL0_BOUNDARY;
    siglongjmp(n->jump,1);
}
__attribute__((visibility("hidden"))) uint64_t lk_native_counter(uint64_t pc,unsigned key)
{
    struct lk_el0_native *n=running;
    if(n->record_counters) {
        if(n->counter_used==n->counter_count || (key!=0xdf01 && key!=0xdf02))
            stop(OSREC_STOP_UNSUPPORTED,pc,key,n->counter_used);
        uint64_t value=n->counter_base+n->counter_step*n->counter_used;
        n->counters[n->counter_used++]=(struct lk_el0_counter){pc,key,value};return value;
    }
    if(n->counter_used==n->counter_count || n->counters[n->counter_used].pc!=pc ||
       n->counters[n->counter_used].encoding!=key)
        stop(OSREC_STOP_UNSUPPORTED,pc,key,n->counter_used);
    return n->counters[n->counter_used++].value;
}
enum lk_el0_status lk_el0_native_counters(struct lk_el0_native *n,const struct lk_el0_counter *events,uint64_t count)
{
    if(!n || (count && !events) || count>1000000)return LK_EL0_BAD_ARGUMENT;
    if(n->executing)return LK_EL0_BUSY;
    for(uint64_t i=0;i<count;i++)if(events[i].pc%4 ||
       (events[i].encoding!=0xdf01 && events[i].encoding!=0xdf02))return LK_EL0_BAD_ARGUMENT;
    struct lk_el0_counter *copy=count?metadata_alloc(count*sizeof *copy):NULL;
    if(count && !copy)return LK_EL0_FAULT;
    if(count)memcpy(copy,events,count*sizeof *copy);
    metadata_free(n->counters);n->counters=copy;n->counter_count=count;n->counter_used=0;n->record_counters=0;
    return LK_EL0_OK;
}
uint64_t lk_el0_native_counters_consumed(struct lk_el0_native *n){return n?n->counter_used:0;}
enum lk_el0_status lk_el0_native_mmio(struct lk_el0_native *n,const struct lk_el0_mmio *events,uint64_t count)
{
    if(!n || (count && !events) || count>1000000)return LK_EL0_BAD_ARGUMENT;
    if(n->executing)return LK_EL0_BUSY;
    for(uint64_t i=0;i<count;i++)if(events[i].pc%4 || events[i].write>1 ||
       (events[i].size!=1 && events[i].size!=2 && events[i].size!=4 && events[i].size!=8))return LK_EL0_BAD_ARGUMENT;
    struct lk_el0_mmio *copy=count?metadata_alloc(count*sizeof *copy):NULL;
    if(count && !copy)return LK_EL0_FAULT;
    if(count)memcpy(copy,events,count*sizeof *copy);
    metadata_free(n->mmio);n->mmio=copy;n->mmio_count=count;n->mmio_used=0;n->record_mmio=0;return LK_EL0_OK;
}
enum lk_el0_status lk_el0_native_record_inputs(struct lk_el0_native *n,uint64_t base,uint64_t step,uint64_t uart,
                                              struct lk_el0_counter *c,uint64_t nc,struct lk_el0_mmio *m,uint64_t nm)
{
    if(!n || !c || !nc || nc>1000000 || !m || !nm || nm>1000000 || uart%PAGE)return LK_EL0_BAD_ARGUMENT;
    if(n->executing)return LK_EL0_BUSY;
    n->record_counters=n->record_mmio=1;n->counter_base=base;n->counter_step=step;n->uart_va=uart;
    n->counters=c;n->counter_count=nc;n->counter_used=0;n->mmio=m;n->mmio_count=nm;n->mmio_used=0;
    return LK_EL0_OK;
}
uint64_t lk_el0_native_mmio_consumed(struct lk_el0_native *n){return n?n->mmio_used:0;}
enum lk_el0_status lk_el0_native_trace(struct lk_el0_native *n,struct lk_el0_event *events,uint64_t capacity)
{
    if(!n || (capacity && !events) || capacity>1000000)return LK_EL0_BAD_ARGUMENT;
    if(n->executing)return LK_EL0_BUSY;
    n->events=events;n->event_capacity=capacity;n->event_count=0;return LK_EL0_OK;
}
uint64_t lk_el0_native_events(struct lk_el0_native *n){return n?n->event_count:0;}
enum lk_el0_status lk_el0_native_trace_allocate(struct lk_el0_native *n,uint64_t capacity,struct lk_el0_event **out)
{
    if(!n || !out || !capacity || capacity>1000000)return LK_EL0_BAD_ARGUMENT;
    *out=NULL;if(n->executing)return LK_EL0_BUSY;
    struct lk_el0_event *events=metadata_calloc(capacity,sizeof *events);
    if(!events)return LK_EL0_FAULT;
    *out=events;return lk_el0_native_trace(n,events,capacity);
}
enum lk_el0_status lk_el0_native_execute(struct lk_el0_native *n,const struct osrec_context *user,struct lk_el0_result *out)
{
    if(!out)return LK_EL0_BAD_ARGUMENT;
    if(!n || !n->app_sites) {
        struct osrec_context input={0};if(user)input=*user;
        memset(out,0,sizeof *out);out->context=input;
        return out->status=n?LK_EL0_UNSUPPORTED:LK_EL0_BAD_ARGUMENT;
    }
    return lk_el0_run_user(n->kernel,user?user:&n->initial,out);
}
static void *physical(struct lk_el0_native *n,uint64_t pa,size_t bytes)
{
    if(pa<n->h.base || bytes>n->h.size || pa-n->h.base>n->h.size-bytes)
        return NULL;
    return (char *)n->physical+pa-n->h.base;
}
static uint64_t restrictions(uint64_t d,uint64_t parent)
{
    if(parent&(1ull<<59))d|=1ull<<53;
    if(parent&(1ull<<60))d|=1ull<<54;
    if(parent&(1ull<<61))d&=~(1ull<<6);
    if(parent&(1ull<<62))d|=1ull<<7;
    return d;
}
static int protection(uint64_t d,int user)
{
    if(!(d&(1ull<<10)) || (user && !(d&(1ull<<6))))return PROT_NONE;
    int p=PROT_READ;
    if(!(d&(1ull<<7)))p|=PROT_WRITE;
    if(!(d&(1ull<<(user?54:53))))p|=PROT_EXEC;
    return p;
}
static int is_kernel(struct lk_el0_native *n,uint64_t va)
{
    for(uint64_t i=0;i<n->lower.count;i++)
        if(va>=n->lower.ranges[i][0] && va<n->lower.ranges[i][1])return 1;
    return 0;
}
static int in_gateways(struct lk_el0_native *n,uint64_t va)
{return n->gateways && va>=n->app.base && va-n->app.base<n->app.size;}
static void visibility(struct lk_el0_native *n,int kernel)
{
    if(n->kernel_visible==(unsigned)kernel)return;
    if(kernel && mprotect(n->physical,n->h.size,PROT_READ|PROT_WRITE))
        stop(OSREC_STOP_RUNTIME,n->context->pc,errno,0);
    for(uint64_t i=0;i<n->h.maps;i++) {
        struct mapping *m=n->maps+i;
        if(mprotect((void *)(uintptr_t)m->va,m->size,kernel?protection(m->attrs,0):PROT_NONE))
            stop(OSREC_STOP_RUNTIME,n->context->pc,errno,m->va);
    }
    if(!kernel && mprotect(n->physical,n->h.size,PROT_NONE))stop(OSREC_STOP_RUNTIME,n->context->pc,errno,0);
    n->kernel_visible=kernel;
}
/* Walk the captured tables, including table restrictions, rather than using
 * host fault syndromes or treating a host mmap as evidence of guest access. */
static uint64_t translate(struct lk_el0_native *n,uint64_t va,int op,uint64_t *attrs)
{
    int user=op>=2,write=op&1;
    if(is_kernel(n,va)) {
        if(user)return 0x1full; /* permission fault, level 3 */
        for(uint64_t i=0;i<n->h.maps;i++) {
            struct mapping *m=n->maps+i;
            if(va>=m->va && va-m->va<m->size) {
                *attrs=m->attrs;
                if(!(m->attrs&(1ull<<10)))return 0x17;
                if(write && (m->attrs&(1ull<<7)))return 0x1f;
                return (m->pa+va-m->va)&PA_MASK;
            }
        }
        return 0xf;
    }
    unsigned bits=64-(n->h.tcr&63),start=3-(bits-13)/9;
    if(va>>bits)return 0x1; /* address-size fault */
    uint64_t table=n->shadow.ttbr0&PA_MASK,parent=0;
    for(unsigned level=start;level<4;level++) {
        uint64_t *p=physical(n,table,PAGE);
        if(!p)return 0x1;
        unsigned shift=12+9*(3-level);
        uint64_t d=p[(va>>shift)&511];
        if(!(d&1) || (level==3 && !(d&2)))return 1|((4+level)<<1);
        if(level<3 && (d&2)){parent|=d;table=d&PA_MASK;continue;}
        d=restrictions(d,parent);*attrs=d;
        if(!(d&(1ull<<10)))return 1|((8+level)<<1);
        if((user && !(d&(1ull<<6))) || (write && (d&(1ull<<7))))
            return 1|((12+level)<<1);
        return ((d&PA_MASK)&~((1ull<<shift)-1))|(va&((1ull<<shift)-1)&~4095ull);
    }
    return 1;
}
static int walk(struct lk_el0_native *n,uint64_t table,unsigned level,uint64_t prefix,uint64_t parent)
{
    uint64_t *p=physical(n,table,PAGE);
    if(!p)return -1;
    unsigned shift=12+9*(3-level);
    unsigned bits=64-(n->h.tcr&63),start=3-(bits-13)/9;
    unsigned count=level==start?1u<<(bits-shift):512;
    for(unsigned i=0;i<count;i++) {
        uint64_t d=p[i],va=prefix|((uint64_t)i<<shift);
        if(!(d&1))continue;
        if(level<3 && (d&2)) {
            if(walk(n,d&PA_MASK,level+1,va,parent|d))return -1;
        } else {
            if(level==3 && !(d&2))continue;
            d=restrictions(d,parent);
            /* Privileged leaves are not application mappings. */
            if(!(d&(1ull<<6)))continue;
            uint64_t pa=(d&PA_MASK)&~((1ull<<shift)-1);
            for(uint64_t k=0;k<(1ull<<shift);k+=PAGE) {
                if(n->users==n->capacity || is_kernel(n,va+k) || in_gateways(n,va+k) ||
                   !physical(n,pa+k,PAGE))return -1;
                n->next[n->users++]=(struct mapping){va+k,pa+k,PAGE,d};
            }
        }
    }
    return 0;
}
static int map(struct lk_el0_native *n,const struct mapping *m,int user,int replace)
{
    int reserved=m->pa==UINT64_MAX;
    void *p=mmap((void *)(uintptr_t)m->va,m->size,reserved?PROT_NONE:protection(m->attrs,user),
                 (reserved?MAP_PRIVATE|MAP_ANONYMOUS:MAP_SHARED)|(replace?MAP_FIXED:MAP_FIXED_NOREPLACE),
                 reserved?-1:n->fd,reserved?0:m->pa-n->h.base);
    if(p==MAP_FAILED)return -1;
    /* Old kernels may ignore NOREPLACE. Never accept an unrelated mapping. */
    if(p!=(void *)(uintptr_t)m->va){munmap(p,m->size);return -1;}
    return 0;
}
static int kernel_qword(struct lk_el0_native *n,uint64_t address,uint64_t *value)
{
    uint64_t attrs=0,pa=translate(n,address,0,&attrs);
    if(pa&1 || (address&4095)>4088)return -1;
    uint64_t *p=physical(n,pa+(address&4095),8);if(!p)return -1;*value=*p;return 0;
}
static int vma_leaf(struct lk_el0_native *n,uint64_t pointer)
{
    uint64_t start,end;
    if(n->vma_count==2048 || kernel_qword(n,pointer+n->vma.start,&start) ||
       kernel_qword(n,pointer+n->vma.end,&end) || start%PAGE || end%PAGE || start>=end || end>(1ull<<48) ||
       (n->vma_count && n->vmas[n->vma_count-1].end>start))return -1;
    n->vmas[n->vma_count++]=(struct interval){start,end};return 0;
}
static int vma_tree(struct lk_el0_native *n,uint64_t entry,uint64_t lo,uint64_t hi,unsigned depth)
{
    if(!entry)return 0;
    if((entry&3)!=2 || entry<=4096)return vma_leaf(n,entry);
    if(depth>8)return -1;
    uint64_t node=entry&~255ull,kind=(entry>>3)&15;
    unsigned count;uint64_t pivots,slots;
    if(kind==1 || kind==2){count=16;pivots=n->vma.r_pivot;slots=n->vma.r_slot;}
    else if(kind==3){count=10;pivots=n->vma.a_pivot;slots=n->vma.a_slot;}
    else return -1;
    uint64_t first=lo;
    for(unsigned i=0;i<count;i++) {
        uint64_t pivot=hi,slot;
        if(i<count-1 && kernel_qword(n,node+pivots+8*i,&pivot))return -1;
        if(i && !pivot)break;
        uint64_t last=pivot<hi?pivot:hi;
        if(kernel_qword(n,node+slots+8*i,&slot))return -1;
        if(slot && (kind==1?vma_leaf(n,slot):vma_tree(n,slot,first,last,depth+1)))return -1;
        if(last>=hi)break;first=last+1;
    }
    return 0;
}
static int reserve_vmas(struct lk_el0_native *n,size_t ptes,size_t *count)
{
    uint64_t root;n->vma_count=0;
    if(kernel_qword(n,n->vma.root,&root) || vma_tree(n,root,0,UINT64_MAX,0))return -1;
    size_t used=0,p=0;
    for(size_t i=0;i<n->vma_count;i++) {
        for(uint64_t va=n->vmas[i].start;va<n->vmas[i].end;va+=PAGE) {
            if(used==n->capacity || is_kernel(n,va) || in_gateways(n,va) ||
               (va>=METADATA_BASE && va-METADATA_BASE<METADATA_SIZE) ||
               (va>=0x100000000000ull && va-0x100000000000ull<n->h.size))return -1;
            if(p<ptes && n->next[p].va<va)return -1;
            n->vma_pages[used++]=p<ptes && n->next[p].va==va?n->next[p++]:
                (struct mapping){va,UINT64_MAX,PAGE,0};
        }
    }
    if(p!=ptes)return -1;
    struct mapping *swap=n->next;n->next=n->vma_pages;n->vma_pages=swap;*count=used;return 0;
}
static int sync_user(struct lk_el0_native *n)
{
    size_t old=n->users;
    n->users=0;
    unsigned bits=64-(n->h.tcr&63),level=3-(bits-13)/9;
    if(walk(n,n->shadow.ttbr0&PA_MASK,level,0,0)){n->users=old;return -1;}
    size_t fresh=n->users,i=0,j=0;
    n->users=old;
    if(n->vma.magic && reserve_vmas(n,fresh,&fresh))return -1;
    if(n->application && n->prepared)for(size_t a=0;a<fresh;a++) {
        struct mapping *m=n->next+a;int exec=protection(m->attrs,1)&PROT_EXEC;
        int found=0;
        for(size_t b=0;b<n->executables;b++) {
            struct mapping *e=n->executable+b;
            if(m->pa==e->pa && (protection(m->attrs,1)&PROT_WRITE))return -1;
            if(m->va==e->va && m->pa==e->pa)found=1;
        }
        if(exec && !found)return -1; /* new or replaced executable text */
    }
    while(i<old || j<fresh) {
        if(j==fresh || (i<old && n->user[i].va<n->next[j].va)) {
            if(munmap((void *)(uintptr_t)n->user[i].va,PAGE))return -1;
            n->user[i++].size=0;
        } else if(i==old || n->next[j].va<n->user[i].va) {
            if(map(n,n->next+j,1,0))return -1;
            /* Record ownership even if a later operation fails. */
            n->pending[n->pendings++]=n->next[j++];
        } else {
            if(n->user[i].pa!=n->next[j].pa || protection(n->user[i].attrs,1)!=protection(n->next[j].attrs,1))
                if(map(n,n->next+j,1,1))return -1;
            i++;j++;
        }
    }
    struct mapping *swap=n->user;n->user=n->next;n->next=swap;n->users=fresh;n->pendings=0;
    return 0;
}
static struct lk_el0_event *event(struct lk_el0_native *n)
{
    if(n->event_count==1000000 || (n->events && n->event_count==n->event_capacity))
        stop(OSREC_STOP_UNSUPPORTED,n->context->pc,0x45564e54,n->event_count);
    struct lk_el0_event *e=n->events?n->events+n->event_count:NULL;
    if(e)memset(e,0,sizeof *e);
    n->event_count++;return e;
}
static void syscall_entry(struct lk_el0_native *n,uint32_t word)
{
    struct osrec_context *c=n->context;
    n->pending_event=event(n);
    if(n->pending_event) {
        n->pending_event->pc=c->pc;n->pending_event->number=c->x[8];
        memcpy(n->pending_event->arguments,c->x,6*8);
    }
    if(!osrec_enter_syscall(&n->shadow,c,word,OSREC_ENTRY_VENEER))stop(OSREC_STOP_RUNTIME,c->pc,word,0);
    n->pending_regs=c->sp-0x150;
}
static void patch_instruction(struct lk_el0_native *n,uint64_t pc,uint32_t word)
{
    uint64_t attrs=0,pa=translate(n,pc,0,&attrs);
    uint32_t *p=pa&1?NULL:physical(n,pa+(pc&4095),4);
    if(!p)stop(OSREC_STOP_RUNTIME,pc,word,pa);
    *p=word;__builtin___clear_cache((char *)(uintptr_t)pc,(char *)(uintptr_t)(pc+4));
}
static void prepare_application(struct lk_el0_native *n)
{
    if(n->prepared)return;
    if(!n->app_sites || !n->vma.magic)stop(OSREC_STOP_UNSUPPORTED,n->context->pc,0x415050,0);
    void *g=mmap((void *)(uintptr_t)n->app.base,n->app.size,PROT_READ|PROT_WRITE,
                 MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    if(g==MAP_FAILED)stop(OSREC_STOP_UNSUPPORTED,n->context->pc,errno,n->app.base);
    if(g!=(void *)(uintptr_t)n->app.base){munmap(g,n->app.size);stop(OSREC_STOP_UNSUPPORTED,n->context->pc,0,n->app.base);}
    n->gateways=g;
    for(size_t i=0;i<n->users;i++)if(protection(n->user[i].attrs,1)&PROT_EXEC) {
        if(n->user[i].va<n->app.text_lo || n->user[i].va>=n->app.text_hi)
            stop(OSREC_STOP_UNSUPPORTED,n->context->pc,0x45584543,n->user[i].va);
        if(protection(n->user[i].attrs,1)&PROT_WRITE)stop(OSREC_STOP_UNSUPPORTED,n->context->pc,0x5758,n->user[i].va);
        n->executable[n->executables++]=n->user[i];
    }
    for(uint64_t i=0;i<n->app.count;i++) {
        struct application_site *a=n->app_sites+i;
        uint64_t attrs=0,pa=translate(n,a->pc,2,&attrs);
        uint32_t *p=pa&1?NULL:physical(n,pa+(a->pc&4095),4);
        if(!p || *p!=a->word || !(protection(attrs,1)&PROT_EXEC))stop(OSREC_STOP_UNSUPPORTED,a->pc,a->word,pa);
        uint32_t replacement;
        if(a->kind==0) {
            int64_t delta=(int64_t)(a->gateway-a->pc);
            if(delta%4 || delta<-(1ll<<27) || delta>=(1ll<<27))stop(OSREC_STOP_RUNTIME,a->pc,a->gateway,0);
            replacement=0x14000000u|((uint32_t)(delta/4)&0x3ffffffu);
        } else replacement=a->kind==1?0xd4200000u|(0xf04u<<5):0xd503201fu;
        *p=replacement;
        ((uint32_t *)g)[i]=0xd4200000u|(0xf03u<<5);
        __builtin___clear_cache((char *)(uintptr_t)a->pc,(char *)(uintptr_t)(a->pc+4));
    }
    if(mprotect(g,n->app.size,PROT_READ|PROT_EXEC))stop(OSREC_STOP_RUNTIME,n->context->pc,errno,n->app.base);
    __builtin___clear_cache(g,(char *)g+n->app.size);
    uint64_t attrs=0,pa=translate(n,n->app.hook,0,&attrs);
    uint32_t *p=pa&1?NULL:physical(n,pa+(n->app.hook&4095),4);
    if(!p || *p!=(uint32_t)n->app.word)stop(OSREC_STOP_UNSUPPORTED,n->app.hook,n->app.word,pa);
    uint64_t post=translate(n,n->app.hook+4,0,&attrs);
    uint32_t *next=post&1?NULL:physical(n,post+((n->app.hook+4)&4095),4);
    if(!next)stop(OSREC_STOP_RUNTIME,n->app.hook,0,post);
    n->hook_post_word=*next;
    patch_instruction(n,n->app.hook,0xd4200000u|(0xf05u<<5));
    n->executable_bytes=metadata_alloc(n->executables*PAGE);
    if(!n->executable_bytes)stop(OSREC_STOP_RUNTIME,n->context->pc,ENOMEM,0);
    for(size_t i=0;i<n->executables;i++)
        memcpy(n->executable_bytes+i*PAGE,physical(n,n->executable[i].pa,PAGE),PAGE);
    n->prepared=1;
}
static void validate_application(struct lk_el0_native *n)
{
    for(size_t i=0;i<n->executables;i++)
        if(memcmp(n->executable_bytes+i*PAGE,physical(n,n->executable[i].pa,PAGE),PAGE))
            stop(OSREC_STOP_UNSUPPORTED,n->context->pc,0x54455854,n->executable[i].va);
}
static int emulate_mmio(struct lk_el0_native *n,uint64_t far)
{
    struct osrec_context *c=n->context;
    if(n->mmio_used==n->mmio_count)return 0;
    struct lk_el0_mmio *e=n->mmio+n->mmio_used;
    if(!n->record_mmio && (e->pc!=c->pc || e->address!=far))return 0;
    uint32_t word=*(uint32_t *)(uintptr_t)c->pc;
    if((word&0x3b000000)!=0x39000000 || word&(1u<<26) || (word>>22&3)>1)
        stop(OSREC_STOP_UNSUPPORTED,c->pc,word,far);
    unsigned size=1u<<(word>>30),rn=word>>5&31,rt=word&31,write=!(word&(1u<<22));
    uint64_t address=(rn==31?c->sp:c->x[rn])+((word>>10&4095)*size);
    uint64_t mask=size==8?UINT64_MAX:(1ull<<(size*8))-1;
    if(n->record_mmio) {
        uint64_t offset=far-n->uart_va;
        if(address!=far || size>4 || (!write && offset!=0x18) || (write && offset!=0 && offset!=0x38))return 0;
        *e=(struct lk_el0_mmio){c->pc,far,size,write,write?(rt==31?0:c->x[rt]&mask):0x90};
    }
    if(address!=far || e->size!=size || e->write!=write ||
       (write && (rt==31?0:c->x[rt]&mask)!=e->value))
        stop(OSREC_STOP_UNSUPPORTED,c->pc,n->mmio_used,far);
    if(!write && rt!=31)c->x[rt]=e->value&mask;
    n->mmio_used++;c->pc+=4;return 1;
}
int lk_native_user_access(struct osrec_shadow *s,struct osrec_context *c,uint32_t word,uint64_t address,unsigned bytes)
{
    struct lk_el0_native *n=running;
    if(address>>48 || (address+bytes-1)>>48)
        stop(OSREC_STOP_UNSUPPORTED,c->pc,word,address); /* tagged pointers */
    int write=!(word&(1u<<22));
    for(unsigned k=0;k<bytes;) {
        uint64_t va=address+k,attrs=0,par=translate(n,va,2+write,&attrs);
        if(par&1) {
            if((address&4095)+bytes>PAGE)
                stop(OSREC_STOP_UNSUPPORTED,c->pc,word,va); /* partial-store semantics */
            uint64_t esr=(0x24ull<<26)|(1ull<<25)|((uint64_t)write<<6)|((par>>1)&63);
            osrec_enter_kernel(s,c,esr,va,0);return 1;
        }
        int mirrored=0;
        for(size_t i=0;i<n->users;i++)if(n->user[i].va==(va&~4095ull)) {
            mirrored=n->user[i].pa==par && protection(n->user[i].attrs,1)==protection(attrs,1);break;
        }
        if(!mirrored && sync_user(n))stop(OSREC_STOP_UNSUPPORTED,c->pc,LK_EL0_SET_TTBR0,va);
        unsigned count=PAGE-(va&4095);k+=count<bytes-k?count:bytes-k;
    }
    return 0;
}
/* DC ZVA is legal at EL0, but the host's zero-block size may differ from the
 * captured CPU. Emulate that architecture edge using the captured DCZID. */
__attribute__((visibility("hidden"))) void lk_native_zero(uint64_t pc,uint64_t address)
{
    struct lk_el0_native *n=running;
    const unsigned key=0xd807;
    if(!(n->shadow.known[key/8]&(1u<<(key%8))))stop(OSREC_STOP_UNKNOWN_SYSREG,pc,key,address);
    uint64_t dczid=n->shadow.value[key],bytes=4ull<<(dczid&15);
    address&=~(bytes-1);
    uint64_t attrs=0,pa=translate(n,address,1,&attrs);
    if((dczid&16) || bytes>PAGE || !is_kernel(n,address) || (pa&1))
        stop(OSREC_STOP_UNSUPPORTED,pc,0xd50b7420,address);
    volatile unsigned char *p=(void *)(uintptr_t)address;
    for(uint64_t i=0;i<bytes;i++)p[i]=0;
}
static int platform(void *opaque,enum lk_el0_platform_operation op,uint64_t arg,int extra,uint64_t *value)
{
    struct lk_el0_native *n=opaque;
    switch(op) {
    case LK_EL0_SET_TTBR0: case LK_EL0_TLB_FLUSH:return sync_user(n);
    case LK_EL0_SET_TTBR1: case LK_EL0_SET_TPIDRRO:return 0; /* shadow-only registers */
    case LK_EL0_TRANSLATE: {
        uint64_t attrs=0;*value=translate(n,arg,extra,&attrs);
        if(!(*value&1)) {
            if(!(n->shadow.known[0xc510/8]&(1u<<(0xc510%8))))return -1;
            /* PAR_EL1 long-descriptor result: ATTR, NS, SH and RES1. */
            unsigned index=(attrs>>2)&7;
            uint64_t attr=(n->shadow.value[0xc510]>>(index*8))&255;
            uint64_t share=(attrs>>8)&3;
            if(!(attr&0xf0) || attr==0x44)share=2;
            *value|=(attr<<56)|(1ull<<11)|(1ull<<9)|(share<<7);
        }
        return 0;
    }
    case LK_EL0_ICACHE_FLUSH:
        for(uint64_t i=0;i<n->h.maps;i++)
            if(protection(n->maps[i].attrs,0)&PROT_EXEC)
                __builtin___clear_cache((char *)(uintptr_t)n->maps[i].va,(char *)(uintptr_t)(n->maps[i].va+n->maps[i].size));
        return 0;
    case LK_EL0_DCACHE_CLEAN_INVALIDATE:
        /* Shared, normal-memory aliases are coherent. No device/cache model. */
        {uint64_t attrs=0;return translate(n,arg,0,&attrs)&1?-1:0;}
    }
    return -1;
}
static struct fpsimd_context *fpsimd(ucontext_t *u,uint64_t *esr)
{
    unsigned char *p=u->uc_mcontext.__reserved;
    size_t size=sizeof u->uc_mcontext.__reserved;
    struct fpsimd_context *fp=NULL;
    while(size>=sizeof(struct _aarch64_ctx)) {
        struct _aarch64_ctx *h=(void *)p;
        if(!h->magic && !h->size)break;
        if(h->size<16 || h->size%16 || h->size>size)return NULL;
        if(h->magic==FPSIMD_MAGIC && h->size>=sizeof *fp)fp=(void *)p;
        if(h->magic==ESR_MAGIC && h->size>=sizeof(struct esr_context))*esr=((struct esr_context *)p)->esr;
        p+=h->size;size-=h->size;
    }
    return fp;
}
static void from_signal(struct lk_el0_native *n,ucontext_t *u,struct fpsimd_context *fp)
{
    memcpy(n->context->x,u->uc_mcontext.regs,sizeof n->context->x);
    n->context->sp=u->uc_mcontext.sp;n->context->pc=u->uc_mcontext.pc;
    n->context->pstate=u->uc_mcontext.pstate&(0xf0000000ull|(1ull<<12));
    memcpy(n->fp.v,fp->vregs,sizeof n->fp.v);n->fp.fpsr=fp->fpsr;n->fp.fpcr=fp->fpcr;
}
static void to_signal(struct lk_el0_native *n,ucontext_t *u)
{
    memcpy(u->uc_mcontext.regs,n->context->x,sizeof n->context->x);
    u->uc_mcontext.sp=n->context->sp;u->uc_mcontext.pc=n->context->pc;
    u->uc_mcontext.pstate=n->context->pstate;
    /* Drop optional host SVE/SME records: this backend's CPU contract is FPSIMD.
     * Linux accepts the FPSIMD record alone and resets the extra vector state. */
    memset(u->uc_mcontext.__reserved,0,sizeof u->uc_mcontext.__reserved);
    struct fpsimd_context *fp=(void *)u->uc_mcontext.__reserved;
    fp->head.magic=FPSIMD_MAGIC;fp->head.size=sizeof *fp;
    memcpy(fp->vregs,n->fp.v,sizeof n->fp.v);fp->fpsr=n->fp.fpsr;fp->fpcr=n->fp.fpcr;
}
static void forward(int sig,siginfo_t *info,void *context)
{
    struct sigaction *p=NULL;
    for(unsigned i=0;i<4;i++)if(signals[i]==sig)p=&forwarded[i];
    if(p->sa_handler==SIG_IGN)return;
    if(p->sa_handler==SIG_DFL){sigaction(sig,p,NULL);syscall(SYS_tgkill,getpid(),syscall(SYS_gettid),sig);return;}
    if(p->sa_flags&SA_SIGINFO)p->sa_sigaction(sig,info,context);else p->sa_handler(sig);
}
static void handler(int sig,siginfo_t *info,void *context)
{
    struct lk_el0_native *n=running;
    if(!n || !n->executing){forward(sig,info,context);return;}
    ucontext_t *u=context;
    if(n->handling)stop(OSREC_STOP_RUNTIME,u->uc_mcontext.pc,sig,(uintptr_t)info->si_addr);
    n->handling=1;
    visibility(n,1);
    uint64_t esr=0;
    struct fpsimd_context *fp=fpsimd(u,&esr);
    if(!fp)stop(OSREC_STOP_RUNTIME,u->uc_mcontext.pc,0x4650,0);
    if(n->starting){n->starting=0;visibility(n,n->shadow.mode==OSREC_KERNEL);to_signal(n,u);n->handling=0;return;}
    from_signal(n,u,fp);
    struct osrec_context *c=n->context;
    uint64_t far=(uintptr_t)info->si_addr;
    int user=n->shadow.mode==OSREC_USER;
    if(sig==SIGTRAP) {
        if(user && in_gateways(n,c->pc)) {
            uint64_t index=(c->pc-n->app.base)/4;
            if(c->pc%4 || index>=n->app.count || n->app_sites[index].kind!=0)
                stop(OSREC_STOP_UNSUPPORTED,c->pc,sig,far);
            struct application_site *a=n->app_sites+index;
            c->pc=a->pc;syscall_entry(n,a->word);goto resume;
        }
        uint64_t attrs=0,pa=translate(n,c->pc,user?2:0,&attrs);
        if(pa&1 || !(protection(attrs,user)&PROT_EXEC))stop(OSREC_STOP_RUNTIME,c->pc,sig,far);
        uint32_t word=*(uint32_t *)(uintptr_t)c->pc;
        if((word&0xffe0001fu)!=0xd4200000u)stop(OSREC_STOP_EXCEPTION,c->pc,word,far);
        if(user && (word>>5&65535)==0xf04) {
            for(uint64_t i=0;i<n->app.count;i++)if(n->app_sites[i].pc==c->pc && n->app_sites[i].kind==1) {
                osrec_emulate_site(&n->shadow,c,n->app_sites[i].word);goto resume;
            }
            stop(OSREC_STOP_NO_SITE,c->pc,word,far);
        }
        if(!user && n->prepared && c->pc==n->app.hook && (word>>5&65535)==0xf05) {
            if(n->pending_regs) {
                uint64_t d=0,p=translate(n,n->pending_regs,0,&d);
                uint64_t *value=p&1?NULL:physical(n,p+(n->pending_regs&4095),8);
                if(!value)stop(OSREC_STOP_RUNTIME,c->pc,n->pending_regs,p);
                if(n->pending_event){n->pending_event->result=*value;n->pending_event->completed=1;}
                n->pending_regs=0;n->pending_event=NULL;
            }
            /* Execute the original BL at its original address. A temporary
             * return-site trap rearms this observation without emulating any
             * ordinary kernel instruction or changing its LR/FP/flags. */
            patch_instruction(n,n->app.hook,(uint32_t)n->app.word);
            patch_instruction(n,n->app.hook+4,0xd4200000u|(0xf06u<<5));
            n->hook_disarmed=1;goto resume;
        }
        if(!user && n->prepared && n->hook_disarmed && c->pc==n->app.hook+4 && (word>>5&65535)==0xf06) {
            patch_instruction(n,n->app.hook,0xd4200000u|(0xf05u<<5));
            patch_instruction(n,n->app.hook+4,n->hook_post_word);
            n->hook_disarmed=0;goto resume;
        }
        far=n->shadow.far; /* BRK leaves the architectural FAR unchanged. */
        esr=(0x3cull<<26)|(1ull<<25)|((word>>5)&65535);
    } else if(sig==SIGSEGV || sig==SIGBUS) {
        if((esr>>26)!=0x24 && (esr>>26)!=0x20)
            stop(OSREC_STOP_EXCEPTION,c->pc,esr,far);
        if(user && (is_kernel(n,far) || in_gateways(n,far) ||
           (far>=(uint64_t)(uintptr_t)n->physical && far-(uintptr_t)n->physical<n->h.size)))
            stop(OSREC_STOP_USER_KERNEL,c->pc,esr,far);
        uint64_t attrs=0,par=translate(n,far,(user?2:0)+((esr>>6)&1),&attrs);
        if(!user && (par&1) && is_kernel(n,far)) {
            if(emulate_mmio(n,far))goto resume;
            stop(OSREC_STOP_UNSUPPORTED,c->pc,esr,far);
        }
        if(!(par&1) && esr>>26==0x20 && !(protection(attrs,user)&PROT_EXEC))par=0x1f;
        if(!(par&1)) {
            /* A new PTE may precede the TLB invalidation. Mirror it once. */
            int changed=1;
            for(size_t i=0;i<n->users;i++)if(n->user[i].va==(far&~4095ull)) {
                changed=n->user[i].pa!=par || protection(n->user[i].attrs,1)!=protection(attrs,1);
                break;
            }
            if(is_kernel(n,far) || !changed)stop(OSREC_STOP_EXCEPTION,c->pc,esr,far);
            if(sync_user(n))stop(OSREC_STOP_RUNTIME,c->pc,errno,far);
            goto resume;
        }
        esr=(esr&~63ull)|((par>>1)&63);
    } else {esr=0;far=n->shadow.far;} /* undefined instructions do not set FAR */
    if(user && n->application) {
        struct lk_el0_event *e=event(n);
        if(e){e->exception=1;e->number=UINT64_MAX;e->pc=c->pc;e->arguments[0]=esr;e->arguments[1]=far;e->arguments[2]=c->pc;}
    }
    osrec_lowered_exception(&n->shadow,c,esr,far);
    osrec_handle_exception(&n->shadow,c,n->sites,n->h.sites,esr,far);
resume:
    if(n->shadow.mode==OSREC_USER) {
        if(!n->application){n->status=LK_EL0_OK;siglongjmp(n->jump,1);}
        if(sync_user(n))stop(OSREC_STOP_UNSUPPORTED,c->pc,LK_EL0_SET_TTBR0,0);
        validate_application(n);
        visibility(n,0);
    }
    to_signal(n,u);n->handling=0;
}
static enum lk_el0_status run(void *opaque,struct osrec_shadow *s,struct osrec_context *c,struct lk_el0_diagnostic *d)
{
    struct lk_el0_native *n=opaque;
    if(running)return LK_EL0_BUSY;
    stack_t old,alt={.ss_sp=n->altstack,.ss_size=256*1024};
    if(sigaltstack(&alt,&old))return LK_EL0_FAULT;
    sigset_t mask,previous;
    sigfillset(&mask);
    for(unsigned i=0;i<4;i++)sigdelset(&mask,signals[i]);
    if(sigprocmask(SIG_SETMASK,&mask,&previous)){sigaltstack(&old,NULL);return LK_EL0_FAULT;}
    uint64_t host_fpcr,host_fpsr;
    __asm__ volatile(".arch_extension fp\n\tmrs %0,fpcr\n\tmrs %1,fpsr\n\t.arch_extension nofp":"=r"(host_fpcr),"=r"(host_fpsr));
    n->context=c;n->diagnostic=d;n->status=LK_EL0_FAULT;n->handling=0;n->starting=1;
    n->application=s->mode==OSREC_USER;
    running=n;
    lk_stop_handler old_stop=lk_backend_stop;lk_backend_stop=stop;
    if(!sigsetjmp(n->jump,1)) {
        if(n->application)prepare_application(n);
        n->executing=1;
        __asm__ volatile("brk #0xf02" ::: "memory");
        stop(OSREC_STOP_RUNTIME,c->pc,0xf02,0);
    }
    visibility(n,1);
    n->executing=0;n->application=0;lk_backend_stop=old_stop;running=NULL;
    __asm__ volatile(".arch_extension fp\n\tmsr fpcr,%0\n\tmsr fpsr,%1\n\t.arch_extension nofp"::"r"(host_fpcr),"r"(host_fpsr));
    sigaltstack(&old,NULL);sigprocmask(SIG_SETMASK,&previous,NULL);
    return n->status;
}
static int read_exact(int fd,void *p,size_t size)
{
    while(size){ssize_t r=read(fd,p,size);if(r<0 && errno==EINTR)continue;if(r<=0)return -1;p=(char *)p+r;size-=r;}
    return 0;
}
static int open_file(void *opaque,const char *name)
{
#ifdef OSREC_FREESTANDING
    (void)opaque;(void)name;errno=ENOSYS;return -1;
#else
    const char *directory=opaque;
    char path[4096];int k=snprintf(path,sizeof path,"%s/%s",directory,name);
    return k<0 || (size_t)k>=sizeof path?-1:open(path,O_RDONLY|O_CLOEXEC);
#endif
}
static void release(struct lk_el0_native *n)
{
    if(n->gateways)munmap(n->gateways,n->app.size);
    for(size_t i=0;i<n->users;i++)if(n->user[i].size)munmap((void *)(uintptr_t)n->user[i].va,n->user[i].size);
    for(size_t i=0;i<n->pendings;i++)munmap((void *)(uintptr_t)n->pending[i].va,PAGE);
    for(size_t i=0;i<n->mapped;i++)munmap((void *)(uintptr_t)n->maps[i].va,n->maps[i].size);
    for(unsigned i=0;i<n->handlers;i++)sigaction(signals[i],&n->previous[i],NULL);
    if(n->physical && n->physical!=MAP_FAILED)munmap(n->physical,n->h.size);
    if(n->fd>=0)close(n->fd);
    metadata_free((void *)n->lower.ranges);metadata_free((void *)n->lower.origins);metadata_free(n->sites);metadata_free(n->maps);
    metadata_free(n->user);metadata_free(n->next);metadata_free(n->pending);metadata_free(n->altstack);metadata_free(n->counters);metadata_free(n->mmio);
    metadata_free(n->app_sites);metadata_free(n->executable);metadata_free(n->executable_bytes);metadata_free(n);
    munmap(metadata,METADATA_SIZE);metadata=NULL;metadata_used=0;atomic_flag_clear(&owned);
}
static enum lk_el0_status open_source(void *opaque,int (*source_open)(void *,const char *),struct lk_el0_native **out,struct lk_el0_diagnostic *d)
{
    if(!opaque || !out || !d)return LK_EL0_BAD_ARGUMENT;
    *out=NULL;memset(d,0,sizeof *d);
    if(sysconf(_SC_PAGESIZE)!=PAGE)return LK_EL0_UNSUPPORTED;
    if(atomic_flag_test_and_set(&owned))return LK_EL0_BUSY;
    metadata=mmap((void *)(uintptr_t)METADATA_BASE,METADATA_SIZE,PROT_READ|PROT_WRITE,
                  MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    if(metadata==MAP_FAILED || metadata!=(void *)(uintptr_t)METADATA_BASE) {
        if(metadata!=MAP_FAILED)munmap(metadata,METADATA_SIZE);
        metadata=NULL;atomic_flag_clear(&owned);return LK_EL0_UNSUPPORTED;
    }
    metadata_used=0;
    struct lk_el0_native *n=metadata_calloc(1,sizeof *n);
    if(!n){munmap(metadata,METADATA_SIZE);metadata=NULL;atomic_flag_clear(&owned);return LK_EL0_FAULT;}
    n->fd=-1;
    int fd=source_open(opaque,"native.bin"),source=-1;
    if(fd<0 || read_exact(fd,&n->h,sizeof n->h))goto fail;
    struct package_header *h=&n->h;
    if(h->magic!=MAGIC || h->version!=1 || h->base%PAGE || h->size%PAGE ||
       !h->size || h->size>(1ull<<31) || h->base>UINT64_MAX-h->size ||
       !h->ranges || h->ranges>1000000 || h->sites>1000000 || h->maps>1000000 || h->veneers>1000000 ||
       (h->tcr>>14&3) || (h->tcr&63)<16 || (h->tcr&63)>39)goto fail;
    n->lower.count=h->ranges;n->lower.base=h->veneer;n->lower.veneers=h->veneers;
    n->lower.ranges=metadata_calloc(h->ranges,16);n->lower.origins=metadata_calloc(h->veneers? h->veneers:1,8);
    n->sites=metadata_calloc(h->sites?h->sites:1,sizeof *n->sites);n->maps=metadata_calloc(h->maps?h->maps:1,sizeof *n->maps);
    n->capacity=h->size/PAGE;n->user=metadata_calloc(n->capacity,sizeof *n->user);n->next=metadata_calloc(n->capacity,sizeof *n->next);
    n->pending=metadata_calloc(n->capacity,sizeof *n->pending);
    n->executable=metadata_calloc(n->capacity,sizeof *n->executable);
    n->vma_pages=metadata_calloc(n->capacity,sizeof *n->vma_pages);
    n->vmas=metadata_calloc(2048,sizeof *n->vmas);
    n->altstack=metadata_alloc(256*1024);
    if(!n->lower.ranges || !n->lower.origins || !n->sites || !n->maps || !n->user || !n->next || !n->pending || !n->executable || !n->vma_pages || !n->vmas || !n->altstack)goto fail;
    if(read_exact(fd,&n->initial,sizeof n->initial) || read_exact(fd,&n->fp,sizeof n->fp) ||
       read_exact(fd,&n->shadow,sizeof n->shadow) || read_exact(fd,(void *)n->lower.ranges,h->ranges*16) ||
       read_exact(fd,n->sites,h->sites*16) || read_exact(fd,(void *)n->lower.origins,h->veneers*8) ||
       read_exact(fd,n->maps,h->maps*32))goto fail;
    char extra;if(read(fd,&extra,1)!=0)goto fail;
    close(fd);fd=-1;
    for(uint64_t i=0;i<h->ranges;i++)if(n->lower.ranges[i][0]>=n->lower.ranges[i][1] ||
       n->lower.ranges[i][1]>(1ull<<48) || (i && n->lower.ranges[i-1][1]>n->lower.ranges[i][0]))goto fail;
    for(uint64_t i=0;i<h->sites;i++)if(n->sites[i].va%4 || (i && n->sites[i-1].va>=n->sites[i].va))goto fail;
    source=source_open(opaque,"memory.bin");
    struct stat st;if(source<0 || fstat(source,&st) || (uint64_t)st.st_size!=h->size)goto fail;
    n->fd=memfd_create("osrec-captured-ram",MFD_CLOEXEC);
    if(n->fd<0 || ftruncate(n->fd,h->size))goto fail;
    /* Keep the runtime's physical alias away from the checkpoint's normal
     * high user mmap area. Never let mmap silently choose a different VA. */
    void *backing=(void *)(uintptr_t)0x100000000000ull;
    n->physical=mmap(backing,h->size,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_FIXED_NOREPLACE,n->fd,0);
    if(n->physical==MAP_FAILED)goto fail;
    if(n->physical!=backing)goto fail;
    /* Preserve sparsity and avoid committing hundreds of MiB of zero RAM. */
    off_t at=0;
    while((uint64_t)at<h->size) {
        off_t data=lseek(source,at,SEEK_DATA);
        if(data<0){if(errno==ENXIO)break;goto fail;}
        off_t end=lseek(source,data,SEEK_HOLE);
        if(end<data || (uint64_t)end>h->size || lseek(source,data,SEEK_SET)<0 ||
           read_exact(source,(char *)n->physical+data,end-data))goto fail;
        at=end;
    }
    close(source);source=-1;
    for(uint64_t i=0;i<h->maps;i++) {
        struct mapping *m=n->maps+i;
        if(m->va%PAGE || m->pa%PAGE || !m->size || m->size%PAGE ||
           m->size>(1ull<<48) || m->va> (1ull<<48)-m->size || !physical(n,m->pa,m->size) ||
           (i && n->maps[i-1].va+n->maps[i-1].size>m->va) || map(n,m,0,0))goto fail;
        n->mapped++;
    }
    n->kernel_visible=1;
    if(sync_user(n))goto fail;
    fd=source_open(opaque,"application.bin");
    if(fd>=0) {
        struct application_header *a=&n->app;
        if(read_exact(fd,a,sizeof *a) || a->magic!=0x315050414b4cull || a->version!=2 ||
           !a->count || a->count>100000 || a->size%PAGE || a->base%PAGE ||
           a->size<4*a->count || a->size>(4<<20) || a->base>(1ull<<48)-a->size ||
           a->hook%4 || a->target%4 || (a->word&0xfc000000)!=0x94000000 ||
           a->text_lo%PAGE || a->text_hi%PAGE || a->text_lo>=a->text_hi || a->text_hi>(1ull<<48))goto fail;
        n->app_sites=metadata_calloc(a->count,sizeof *n->app_sites);
        if(!n->app_sites || read_exact(fd,n->app_sites,a->count*sizeof *n->app_sites) || read(fd,&extra,1)!=0)goto fail;
        for(uint64_t i=0;i<a->count;i++) {
            struct application_site *p=n->app_sites+i;
            if(p->pc%4 || p->pc<a->text_lo || p->pc>=a->text_hi || p->kind>2 || p->gateway!=a->base+4*i ||
               (i && n->app_sites[i-1].pc>=p->pc) ||
               (!p->kind && (p->word&0xffe0001f)!=0xd4000001))goto fail;
        }
        close(fd);fd=-1;
    } else if(errno!=ENOENT)goto fail;
    fd=source_open(opaque,"vma.bin");
    if(fd>=0) {
        struct vma_config *v=&n->vma;
        if(read_exact(fd,v,sizeof *v) || read(fd,&extra,1)!=0 || v->magic!=0x31414d564b4cull || v->version!=1 ||
           v->root%8 || !is_kernel(n,v->root) || v->start>4096 || v->end>4096 || v->flags>4096 ||
           v->r_pivot>4096 || v->r_slot>4096 || v->a_pivot>4096 || v->a_slot>4096)goto fail;
        close(fd);fd=-1;
        if(sync_user(n))goto fail;
    } else if(errno!=ENOENT)goto fail;
    struct sigaction action={0};action.sa_sigaction=handler;action.sa_flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER;
    sigfillset(&action.sa_mask);
    /* Nested runtime faults must be diagnosed, rather than killing the host. */
    for(unsigned i=0;i<4;i++)sigdelset(&action.sa_mask,signals[i]);
    for(unsigned i=0;i<4;i++) {
        if(sigaction(signals[i],NULL,&n->previous[i]))goto fail;
        forwarded[i]=n->previous[i];
        if(sigaction(signals[i],&action,NULL))goto fail;
        n->handlers++;
    }
    struct lk_el0_backend backend={LK_EL0_ABI,run,platform};
    enum lk_el0_status status=lk_el0_create(&n->shadow,&backend,n,&n->kernel);
    if(status!=LK_EL0_OK)goto fail;
    *out=n;return LK_EL0_OK;
fail:
    *d=(struct lk_el0_diagnostic){OSREC_STOP_RUNTIME,0,(uint64_t)errno,0};
    if(fd>=0)close(fd);if(source>=0)close(source);release(n);return LK_EL0_FAULT;
}
enum lk_el0_status lk_el0_native_open(const char *directory,struct lk_el0_native **out,struct lk_el0_diagnostic *d)
{return open_source((void *)directory,open_file,out,d);}

static int write_at(int fd,const void *bytes,uint64_t size,uint64_t offset)
{
    const unsigned char *p=bytes;
    while(size) {
        size_t chunk=size>(1u<<20)?1u<<20:(size_t)size;
        ssize_t result=pwrite(fd,p,chunk,(off_t)offset);
        if(result<0 && errno==EINTR)continue;
        if(result<=0)return -1;
        p+=result;size-=result;offset+=result;
    }
    return 0;
}
enum lk_el0_status lk_el0_native_memory(struct lk_el0_native *n,uint64_t address,void *bytes,uint64_t size,
                                       int write,int kernel_space,struct lk_el0_diagnostic *d)
{
    if(!n || !d || (size && !bytes) || size>(1ull<<31) || address>UINT64_MAX-size ||
       (write!=0 && write!=1) || (kernel_space!=0 && kernel_space!=1))return LK_EL0_BAD_ARGUMENT;
    *d=(struct lk_el0_diagnostic){0};if(n->executing)return LK_EL0_BUSY;
    for(unsigned pass=0;pass<2;pass++)for(uint64_t offset=0;offset<size;) {
        uint64_t va=address+offset,attrs=0,pa=translate(n,va,(kernel_space?0:2)+write,&attrs);
        uint64_t count=PAGE-(va&4095);if(count>size-offset)count=size-offset;
        void *p=pa&1?NULL:physical(n,pa+(va&4095),count);
        if(!p){*d=(struct lk_el0_diagnostic){OSREC_STOP_EXCEPTION,0,pa,va};return LK_EL0_FAULT;}
        if(pass){if(write)memcpy(p,(unsigned char *)bytes+offset,count);else memcpy((unsigned char *)bytes+offset,p,count);}
        offset+=count;
    }
    return LK_EL0_OK;
}
enum lk_el0_status lk_el0_native_snapshot(struct lk_el0_native *n,const struct osrec_context *context,int native_fd,int memory_fd)
{
    if(!n || !context || native_fd<0 || memory_fd<0 || native_fd==memory_fd || native_fd==n->fd || memory_fd==n->fd)
        return LK_EL0_BAD_ARGUMENT;
    if(n->executing)return LK_EL0_BUSY;
    if(n->prepared || n->shadow.mode!=OSREC_USER || context->pc%4)return LK_EL0_UNSUPPORTED;
    struct stat a,b;if(fstat(native_fd,&a) || fstat(memory_fd,&b) || a.st_size || b.st_size ||
       (a.st_dev==b.st_dev && a.st_ino==b.st_ino))return LK_EL0_BAD_ARGUMENT;
    uint64_t offset=0;
#define SAVE(pointer,bytes) do {uint64_t amount=(bytes);if(write_at(native_fd,(pointer),amount,offset))return LK_EL0_FAULT;offset+=amount;} while(0)
    SAVE(&n->h,sizeof n->h);SAVE(context,sizeof *context);SAVE(&n->fp,sizeof n->fp);SAVE(&n->shadow,sizeof n->shadow);
    SAVE(n->lower.ranges,n->h.ranges*16);SAVE(n->sites,n->h.sites*16);SAVE(n->lower.origins,n->h.veneers*8);SAVE(n->maps,n->h.maps*32);
#undef SAVE
    if(ftruncate(memory_fd,(off_t)n->h.size))return LK_EL0_FAULT;
    for(uint64_t at=0;at<n->h.size;at+=PAGE) {
        const uint64_t *p=(const void *)((const unsigned char *)n->physical+at);unsigned nonzero=0;
        for(unsigned i=0;i<PAGE/8;i++)if(p[i]){nonzero=1;break;}
        if(nonzero && write_at(memory_fd,p,PAGE,at))return LK_EL0_FAULT;
    }
    return LK_EL0_OK;
}
static int open_asset(void *opaque,const char *name)
{
    const struct lk_el0_image *image=opaque;
    const struct lk_el0_blob *blob=NULL;
    if(!strcmp(name,"native.bin"))blob=&image->native;
    else if(!strcmp(name,"application.bin"))blob=&image->application;
    else if(!strcmp(name,"vma.bin"))blob=&image->vma;
    int memory=!strcmp(name,"memory.bin");
    if(!memory && (!blob || !blob->size)){errno=ENOENT;return -1;}
    int fd=memfd_create("osrec-linked-asset",MFD_CLOEXEC);
    if(fd<0)return -1;
    if(memory) {
        if(ftruncate(fd,(off_t)image->memory_size))goto fail;
        for(uint64_t i=0;i<image->extent_count;i++) {
            const struct lk_el0_extent *e=image->extents+i;
            if(write_at(fd,e->bytes.data,e->bytes.size,e->offset))goto fail;
        }
    } else if(write_at(fd,blob->data,blob->size,0))goto fail;
    return fd;
fail:
    {int error=errno;close(fd);errno=error;return -1;}
}
static int valid_blob(const struct lk_el0_blob *b)
{return (!b->size || b->data) && b->size<=(1ull<<31);}
enum lk_el0_status lk_el0_native_open_image(const struct lk_el0_image *image,struct lk_el0_native **out,struct lk_el0_diagnostic *d)
{
    if(!out || !d)return LK_EL0_BAD_ARGUMENT;
    *out=NULL;*d=(struct lk_el0_diagnostic){0};
    if(!image || image->abi!=LK_EL0_IMAGE_ABI || image->reserved ||
       !valid_blob(&image->native) || !image->native.size ||
       !valid_blob(&image->application) || !valid_blob(&image->vma) ||
       !valid_blob(&image->counters) || !valid_blob(&image->mmio) ||
       !image->memory_size || image->memory_size>(1ull<<31) || image->memory_size%PAGE ||
       image->extent_count>1000000 || (image->extent_count && !image->extents) ||
       image->counters.size%sizeof(struct lk_el0_counter) || image->mmio.size%sizeof(struct lk_el0_mmio))
        return LK_EL0_BAD_ARGUMENT;
    uint64_t end=0;
    for(uint64_t i=0;i<image->extent_count;i++) {
        const struct lk_el0_extent *e=image->extents+i;
        if(!valid_blob(&e->bytes) || !e->bytes.size || e->offset<end ||
           e->offset>image->memory_size || e->bytes.size>image->memory_size-e->offset)
            return LK_EL0_BAD_ARGUMENT;
        end=e->offset+e->bytes.size;
    }
    struct lk_el0_native *n=NULL;
    enum lk_el0_status status=open_source((void *)image,open_asset,&n,d);
    if(status!=LK_EL0_OK)return status;
    if(image->counters.size) {
        /* memcpy into aligned arena storage before treating linked bytes as
         * records; a caller need not align its byte blobs to the C ABI. */
        void *copy=metadata_alloc(image->counters.size);
        if(!copy){status=LK_EL0_FAULT;goto fail;}
        memcpy(copy,image->counters.data,image->counters.size);
        status=lk_el0_native_counters(n,copy,image->counters.size/sizeof(struct lk_el0_counter));
        if(status!=LK_EL0_OK)goto fail;
    }
    if(image->mmio.size) {
        void *copy=metadata_alloc(image->mmio.size);
        if(!copy){status=LK_EL0_FAULT;goto fail;}
        memcpy(copy,image->mmio.data,image->mmio.size);
        status=lk_el0_native_mmio(n,copy,image->mmio.size/sizeof(struct lk_el0_mmio));
        if(status!=LK_EL0_OK)goto fail;
    }
    *out=n;return LK_EL0_OK;
fail:
    *d=(struct lk_el0_diagnostic){OSREC_STOP_RUNTIME,0,(uint64_t)status,0};
    lk_el0_native_close(n);return status;
}
enum lk_el0_status lk_el0_native_close(struct lk_el0_native *n)
{
    if(!n)return LK_EL0_BAD_ARGUMENT;
    enum lk_el0_status s=lk_el0_destroy(n->kernel);
    if(s!=LK_EL0_OK)return s;
    release(n);return LK_EL0_OK;
}
struct lk_el0_kernel *lk_el0_native_kernel(struct lk_el0_native *n){return n?n->kernel:NULL;}
const struct osrec_context *lk_el0_native_initial(struct lk_el0_native *n){return n?&n->initial:NULL;}
struct lk_el0_fp *lk_el0_native_fp(struct lk_el0_native *n){return n?&n->fp:NULL;}
#else
/* Buildable discovery on other hosts, with no pretend instruction executor. */
const struct lk_native_lower *lk_native_lowering(void){return NULL;}
int lk_native_user_access(struct osrec_shadow *s,struct osrec_context *c,uint32_t w,uint64_t a,unsigned b)
{(void)s;(void)c;(void)w;(void)a;(void)b;return 1;}
void lk_native_zero(uint64_t pc,uint64_t address){(void)pc;(void)address;__builtin_trap();}
uint64_t lk_native_counter(uint64_t pc,unsigned key){(void)pc;(void)key;__builtin_trap();}
enum lk_el0_status lk_el0_native_counters(struct lk_el0_native *n,const struct lk_el0_counter *e,uint64_t c)
{(void)n;(void)e;(void)c;return LK_EL0_UNSUPPORTED;}
uint64_t lk_el0_native_counters_consumed(struct lk_el0_native *n){(void)n;return 0;}
enum lk_el0_status lk_el0_native_mmio(struct lk_el0_native *n,const struct lk_el0_mmio *e,uint64_t c)
{(void)n;(void)e;(void)c;return LK_EL0_UNSUPPORTED;}
uint64_t lk_el0_native_mmio_consumed(struct lk_el0_native *n){(void)n;return 0;}
enum lk_el0_status lk_el0_native_trace(struct lk_el0_native *n,struct lk_el0_event *e,uint64_t c)
{(void)n;(void)e;(void)c;return LK_EL0_UNSUPPORTED;}
enum lk_el0_status lk_el0_native_trace_allocate(struct lk_el0_native *n,uint64_t c,struct lk_el0_event **e)
{(void)n;(void)c;if(e)*e=NULL;return LK_EL0_UNSUPPORTED;}
uint64_t lk_el0_native_events(struct lk_el0_native *n){(void)n;return 0;}
enum lk_el0_status lk_el0_native_execute(struct lk_el0_native *n,const struct osrec_context *c,struct lk_el0_result *r)
{(void)n;(void)c;(void)r;return LK_EL0_UNSUPPORTED;}
enum lk_el0_status lk_el0_native_open(const char *p,struct lk_el0_native **n,struct lk_el0_diagnostic *d)
{(void)p;if(!n || !d)return LK_EL0_BAD_ARGUMENT;*n=NULL;*d=(struct lk_el0_diagnostic){OSREC_STOP_UNSUPPORTED,0,0,0};return LK_EL0_UNSUPPORTED;}
enum lk_el0_status lk_el0_native_open_image(const struct lk_el0_image *i,struct lk_el0_native **n,struct lk_el0_diagnostic *d)
{(void)i;if(!n || !d)return LK_EL0_BAD_ARGUMENT;*n=NULL;*d=(struct lk_el0_diagnostic){OSREC_STOP_UNSUPPORTED,0,0,0};return LK_EL0_UNSUPPORTED;}
enum lk_el0_status lk_el0_native_close(struct lk_el0_native *n){(void)n;return LK_EL0_BAD_ARGUMENT;}
struct lk_el0_kernel *lk_el0_native_kernel(struct lk_el0_native *n){(void)n;return NULL;}
const struct osrec_context *lk_el0_native_initial(struct lk_el0_native *n){(void)n;return NULL;}
struct lk_el0_fp *lk_el0_native_fp(struct lk_el0_native *n){(void)n;return NULL;}
enum lk_el0_status lk_el0_native_memory(struct lk_el0_native *n,uint64_t a,void *b,uint64_t s,int w,int k,struct lk_el0_diagnostic *d)
{(void)n;(void)a;(void)b;(void)s;(void)w;(void)k;(void)d;return LK_EL0_UNSUPPORTED;}
enum lk_el0_status lk_el0_native_record_inputs(struct lk_el0_native *n,uint64_t b,uint64_t s,uint64_t u,
                                              struct lk_el0_counter *c,uint64_t nc,struct lk_el0_mmio *m,uint64_t nm)
{(void)n;(void)b;(void)s;(void)u;(void)c;(void)nc;(void)m;(void)nm;return LK_EL0_UNSUPPORTED;}
enum lk_el0_status lk_el0_native_snapshot(struct lk_el0_native *n,const struct osrec_context *c,int a,int b)
{(void)n;(void)c;(void)a;(void)b;return LK_EL0_UNSUPPORTED;}
#endif
