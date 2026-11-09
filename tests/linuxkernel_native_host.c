#define _GNU_SOURCE
#include "osrec/linuxkernel_el0_native.h"
#include <assert.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static struct osrec_context user;
static struct lk_el0_native *native;
static unsigned calls;
static uint64_t oracle[22][8];
static struct lk_el0_counter counters[1024];
static size_t counter_count;
static unsigned char expected_page[4096];
static size_t load(const char *directory,const char *name,void *data,size_t bytes,size_t item)
{
    char path[4096];assert(snprintf(path,sizeof path,"%s/%s",directory,name)>0);
    FILE *file=fopen(path,"rb");assert(file);
    assert(!fseek(file,0,SEEK_END));long size=ftell(file);assert(size>=0 && (size_t)size<=bytes && (size_t)size%item==0);
    rewind(file);assert(fread(data,1,size,file)==(size_t)size);assert(!fclose(file));return size/item;
}
static int64_t invoke(uint64_t number,uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f)
{
    user.x[8]=number;user.x[0]=a;user.x[1]=b;user.x[2]=c;user.x[3]=d;user.x[4]=e;user.x[5]=f;
    struct lk_el0_result r;
    enum lk_el0_status status;
    /* Alternate the library's equivalent entry paths, preserving state. */
    if(calls++&1){struct osrec_context post=user;post.pc+=4;status=lk_el0_svc(lk_el0_native_kernel(native),&post,0xd4000001,&r);}
    else status=lk_el0_veneer(lk_el0_native_kernel(native),&user,0xd4000001,&r);
    if(status!=LK_EL0_OK)fprintf(stderr,"nr=%"PRIu64" status=%u reason=%"PRIu64" pc=%"PRIx64" detail=%"PRIx64" far=%"PRIx64"\n",number,status,r.diagnostic.reason,r.diagnostic.pc,r.diagnostic.detail,r.diagnostic.far);
    assert(status==LK_EL0_OK && r.context.pc==user.pc+4 && r.context.sp==user.sp);
    if(calls<=22) {
        uint64_t row[]={number,a,b,c,d,e,f,r.context.x[0]};
        assert(!memcmp(row,oracle[calls-1],sizeof row));
    }
    return (int64_t)r.context.x[0];
}
int main(int argc,char **argv)
{
    assert(argc==3);
    assert(load(argv[2],"calls.bin",oracle,sizeof oracle,64)==22);
    counter_count=load(argv[2],"counters.bin",counters,sizeof counters,sizeof *counters);
    assert(load(argv[2],"user-page.bin",expected_page,sizeof expected_page,1)==4096);
    struct sigaction before[4],after;
    int signals[]={SIGTRAP,SIGILL,SIGSEGV,SIGBUS};
    for(unsigned i=0;i<4;i++)assert(!sigaction(signals[i],NULL,&before[i]));
    struct lk_el0_diagnostic diag;
    assert(lk_el0_native_open(argv[1],&native,&diag)==LK_EL0_OK);
    assert(lk_el0_native_counters(native,counters,counter_count)==LK_EL0_OK);
    user=*lk_el0_native_initial(native);
    /* Independent native-Linux recording, first nine calls from this exact
     * checkpoint (also verified by both QEMU EL0 images). */
    assert(invoke(25,3,1,0,0,0,0)==1);
    assert(invoke(25,4,2,1,0,0,0)==0);
    assert(invoke(25,4,1,0,0,0,0)==1);
    assert(invoke(25,3,2,0,0,0,0)==0);
    assert(invoke(25,3,3,0,0,0,0)==131074);
    assert(invoke(25,3,0,6,0,0,0)==6);
    assert(invoke(25,3,0,10,0,0,0)==-22);
    assert(invoke(25,4,1030,0,0,0,0)==5);
    assert(invoke(25,99,1,0,0,0,0)==-9);
    assert(invoke(172,0,0,0,0,0,0)==1); /* captured PID, never the host PID */
    struct lk_el0_fp fp;
    for(unsigned i=0;i<sizeof fp.v;i++)((unsigned char *)fp.v)[i]=(unsigned char)(i*17+3);
    fp.fpcr=0;fp.fpsr=0x08000001;
    *lk_el0_native_fp(native)=fp;
    assert(invoke(178,0,0,0,0,0,0)==1);
    assert(!memcmp(&fp,lk_el0_native_fp(native),sizeof fp));
    int64_t mask=invoke(166,077,0,0,0,0,0);
    assert(mask>=0 && mask<=0777);
    assert(invoke(166,022,0,0,0,0,0)==077);
    assert(invoke(166,mask,0,0,0,0,0)==022);
    assert(invoke(65,3,0,1,0,0,0)==-14); /* writev: actual kernel uaccess fault */
    assert(invoke(63,99,0,1,0,0,0)==-9);
    assert(invoke(9999,0,0,0,0,0,0)==-38);
    int64_t address=invoke(222,0,4096,3,0x22,UINT64_MAX,0);
    assert(address>0);
    /* Demand allocation occurs inside original Linux, on a kernel user-copy
     * fault. The host backend mirrors the resulting PTE and shared alias. */
    assert(invoke(63,3,address,1,0,0,0)==1);
    assert(!memcmp((void *)(uintptr_t)address,expected_page,4096));
    assert(invoke(226,address,4096,1,0,0,0)==0);
    int64_t protected_read=invoke(63,3,address,1,0,0,0);
    assert(protected_read==-14);
    assert(invoke(215,address,4096,0,0,0,0)==0);
    assert(lk_el0_native_counters_consumed(native)==counter_count);
    /* A real kernel boundary unwinds the signal frame, restores the caller's
     * mask/alternate stack, and poisons further entry into modified state. */
    sigset_t mask_before,mask_after;
    stack_t stack_before,stack_after;
    assert(!sigprocmask(SIG_SETMASK,NULL,&mask_before));
    assert(!sigaltstack(NULL,&stack_before));
    user.x[8]=142;user.x[0]=0xfee1dead;user.x[1]=0x28121969;user.x[2]=0x4321fedc;
    struct lk_el0_result stopped;
    assert(lk_el0_call(lk_el0_native_kernel(native),&user,0xd4000001,&stopped)==LK_EL0_BOUNDARY);
    assert(stopped.diagnostic.reason==OSREC_STOP_BOUNDARY);
    assert(lk_el0_call(lk_el0_native_kernel(native),&user,0xd4000001,&stopped)==LK_EL0_POISONED);
    assert(!sigprocmask(SIG_SETMASK,NULL,&mask_after));
    assert(!sigaltstack(NULL,&stack_after));
    for(int i=1;i<NSIG;i++)assert(sigismember(&mask_before,i)==sigismember(&mask_after,i));
    assert(stack_before.ss_flags==stack_after.ss_flags && stack_before.ss_sp==stack_after.ss_sp && stack_before.ss_size==stack_after.ss_size);
    assert(lk_el0_native_close(native)==LK_EL0_OK);
    for(unsigned i=0;i<4;i++){
        assert(!sigaction(signals[i],NULL,&after));
        assert(before[i].sa_handler==after.sa_handler && before[i].sa_flags==after.sa_flags);
    }
    /* A host mapping at an unallocated guest address must never satisfy the
     * kernel's user-copy. Reject the collision without touching its contents. */
    unsigned char *sentinel=mmap((void *)(uintptr_t)address,4096,PROT_READ|PROT_WRITE,
                                MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    assert(sentinel==(void *)(uintptr_t)address);memset(sentinel,0x5a,4096);
    assert(lk_el0_native_open(argv[1],&native,&diag)==LK_EL0_OK);
    assert(lk_el0_native_counters(native,counters,counter_count)==LK_EL0_OK);
    user=*lk_el0_native_initial(native);
    assert(invoke(222,0,4096,3,0x22,UINT64_MAX,0)==address);
    user.x[8]=63;user.x[0]=3;user.x[1]=address;user.x[2]=1;
    assert(lk_el0_call(lk_el0_native_kernel(native),&user,0xd4000001,&stopped)==LK_EL0_BOUNDARY);
    assert(stopped.diagnostic.reason==OSREC_STOP_UNSUPPORTED && stopped.diagnostic.far==(uint64_t)address);
    for(unsigned i=0;i<4096;i++)assert(sentinel[i]==0x5a);
    assert(lk_el0_native_close(native)==LK_EL0_OK);
    assert(sentinel[0]==0x5a && !munmap(sentinel,4096));
    assert(counter_count);
    for(unsigned mismatch=0;mismatch<2;mismatch++) {
        assert(lk_el0_native_open(argv[1],&native,&diag)==LK_EL0_OK);
        if(mismatch) {
            struct lk_el0_counter wrong=counters[0];wrong.pc+=4;
            assert(lk_el0_native_counters(native,&wrong,1)==LK_EL0_OK);
        }
        user=*lk_el0_native_initial(native);
        user.x[8]=222;user.x[0]=0;user.x[1]=4096;user.x[2]=3;user.x[3]=0x22;user.x[4]=UINT64_MAX;user.x[5]=0;
        assert(lk_el0_call(lk_el0_native_kernel(native),&user,0xd4000001,&stopped)==LK_EL0_BOUNDARY);
        assert(stopped.diagnostic.reason==OSREC_STOP_UNSUPPORTED && stopped.diagnostic.detail==0xdf02);
        assert(!lk_el0_native_counters_consumed(native));
        assert(lk_el0_native_close(native)==LK_EL0_OK);
    }
    printf("native captured Linux passed: %u calls, 22 QEMU oracle results and one user page, %zu recorded counters, persistent state, FP/SIMD, uaccess, mmap protections, boundaries and collision rejection\n",calls,counter_count);
    return 0;
}
