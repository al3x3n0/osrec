#define _GNU_SOURCE
#include "osrec/linuxkernel_el0_native.h"
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
static int collision(const char *package,const char *counter_file,const char *target_text)
{
    uint64_t target=strtoull(target_text,NULL,0);
    unsigned char *sentinel=mmap((void *)(uintptr_t)target,4096,PROT_READ|PROT_WRITE,
                                MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    assert(sentinel==(void *)(uintptr_t)target);memset(sentinel,0x5a,4096);
    struct lk_el0_counter counters[1024];FILE *file=fopen(counter_file,"rb");assert(file);
    size_t count=fread(counters,sizeof *counters,1024,file);assert(feof(file));fclose(file);
    struct lk_el0_native *native;struct lk_el0_diagnostic d;struct lk_el0_result result;
    assert(lk_el0_native_open(package,&native,&d)==LK_EL0_OK);
    assert(lk_el0_native_counters(native,counters,count)==LK_EL0_OK);
    struct lk_el0_event *events=NULL;
    assert(lk_el0_native_trace_allocate(native,30000,&events)==LK_EL0_OK);
    assert(lk_el0_native_execute(native,NULL,&result)==LK_EL0_BOUNDARY);
    assert(result.diagnostic.reason==OSREC_STOP_UNSUPPORTED);
    uint64_t seen=lk_el0_native_events(native);assert(seen);
    assert(!events[seen-1].exception && events[seen-1].number==222 && events[seen-1].completed && events[seen-1].result==target);
    for(unsigned i=0;i<4096;i++)assert(sentinel[i]==0x5a);
    assert(lk_el0_native_close(native)==LK_EL0_OK);
    assert(sentinel[0]==0x5a && !munmap(sentinel,4096));
    puts("native unpopulated VMA collision rejected before user access");return 0;
}
int main(int argc,char **argv)
{
    if(argc==5 && !strcmp(argv[1],"collision"))return collision(argv[2],argv[3],argv[4]);
    assert(argc==6);
    struct lk_el0_native *native;struct lk_el0_diagnostic d;
    assert(lk_el0_native_open(argv[1],&native,&d)==LK_EL0_OK);
    struct osrec_context user=*lk_el0_native_initial(native);
    user.pc=strtoull(argv[2],NULL,0);
    unsigned rn=(unsigned)strtoul(argv[3],NULL,0);
    uint64_t offset=strtoull(argv[4],NULL,0),target=strtoull(argv[5],NULL,0);
    if(rn==31)user.sp=target-offset;else user.x[rn]=target-offset;
    struct osrec_context before=user;
    sigset_t mask_before,mask_after;stack_t stack_before,stack_after;
    assert(!sigprocmask(SIG_SETMASK,NULL,&mask_before));assert(!sigaltstack(NULL,&stack_before));
    struct lk_el0_result result;
    assert(lk_el0_native_execute(native,&user,&result)==LK_EL0_BOUNDARY);
    assert(result.diagnostic.reason==OSREC_STOP_USER_KERNEL && result.diagnostic.pc==user.pc && result.diagnostic.far==target);
    assert(!memcmp(&user,&before,sizeof user));
    assert(lk_el0_native_execute(native,&user,&result)==LK_EL0_POISONED);
    assert(!sigprocmask(SIG_SETMASK,NULL,&mask_after));assert(!sigaltstack(NULL,&stack_after));
    for(int i=1;i<64;i++)assert(sigismember(&mask_before,i)==sigismember(&mask_after,i));
    assert(stack_before.ss_sp==stack_after.ss_sp && stack_before.ss_size==stack_after.ss_size && stack_before.ss_flags==stack_after.ss_flags);
    assert(lk_el0_native_close(native)==LK_EL0_OK);
    puts("native user/kernel access guard and recovery passed");return 0;
}
