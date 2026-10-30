/*
 * Copyright (c) 2013-2019 Huawei Technologies Co., Ltd. All rights reserved.
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used
 *    to endorse or promote products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Minimal user workload embedded using LiteOS-A's normal user-init sections.
 * Calls the existing OHOS SVC ABI; no replacement exception dispatcher.
 */
#include "los_user_init.h"
#include "los_syscall.h"
#include "fcntl.h"
#include "auto_entry_config.h"
#ifdef OSREC_ASYNC_WAIT_CAPTURE
#include "time.h"
#endif

static const char input_path[] __attribute__((section(".user.rodata"))) = "/dev/shm/input.bin";
static const char report_path[] __attribute__((section(".user.rodata"))) = "/dev/osrec-report";
static const int duplicate_group[] __attribute__((section(".user.rodata"))) = {0};
#if defined(OSREC_GETGROUPS_CAPTURE) && OSREC_GETGROUPS_GROUP_COUNT==2
static const int distinct_groups[] __attribute__((section(".user.rodata"))) = {7,0};
#else
static const int distinct_groups[] __attribute__((section(".user.rodata"))) = {7,9};
#endif

LITE_USER_SEC_TEXT static UINT32 call3(UINT32 number, UINT32 a, UINT32 b, UINT32 c)
{
    register UINT32 r7 __asm__("r7")=number;
    register UINT32 r0 __asm__("r0")=a;
    register UINT32 r1 __asm__("r1")=b;
    register UINT32 r2 __asm__("r2")=c;
    __asm__ volatile("svc %1" : "+r"(r0) : "i"(0x900001),"r"(r7),"r"(r1),"r"(r2) : "memory","r14","cc");
    return r0;
}
#ifdef OSREC_FILE_CAPTURE
#include "file_workload.h"
#endif
struct user_step { UINT32 raw, result, error, recognized, mode; unsigned char memory[8]; };
struct priority_step { UINT32 policy, raw, mode; };
struct identity_step { UINT32 number, argument, raw, mode; };
struct getpriority_step { UINT32 which, who, raw, mode; };
struct output_step {UINT32 size,raw,mode,memory[4];};
struct workload_report { struct user_step reads[4]; struct priority_step priorities[3]; struct priority_step minima[3]; UINT32 pid, pid_mode; struct identity_step identities[7]; struct priority_step masks[6]; struct priority_step tasks[4]; struct priority_step credentials[4]; struct getpriority_step process_priorities[6]; struct priority_step groups[3];
#ifdef OSREC_ASYNC_WAIT_CAPTURE
struct {UINT32 raw,mode;} wait;
#endif
#ifdef OSREC_UNAME_CAPTURE
struct { UINT32 number,pointer_kind,raw,mode; unsigned char memory[392]; } names[
#ifdef OSREC_UNAME_FAULTS
8
#else
4
#endif
];
#endif
#ifdef OSREC_FILE_CAPTURE
struct {UINT32 number,args[5],raw,mode;unsigned char memory[192];} files[FILE_CALL_COUNT];
#endif
#ifdef OSREC_DUP_CAPTURE
struct {UINT32 number,fd,raw,mode;} duplicates[5];
#endif
#ifdef OSREC_CLOSE_CAPTURE
struct {UINT32 number,fd,raw,mode;} closes[5];
#endif
#ifdef OSREC_RLIMIT_CAPTURE
struct { UINT32 number,resource,raw,mode,memory[4]; } limits[6];
#endif
#ifdef OSREC_CLOCK_CAPTURE
struct { UINT32 number,id,raw,mode,memory[4]; } clocks[10];
#endif
#ifdef OSREC_GETGROUPS_CAPTURE
struct output_step getgroups[3];
#endif
#if defined(OSREC_GETRESUID_CAPTURE) || defined(OSREC_GETRESGID_CAPTURE)
struct output_step credential_outputs[4];
#endif
#ifdef OSREC_GETSCHEDULER_CAPTURE
struct getpriority_step schedulers[4];
#endif
};
#ifdef OSREC_GETGROUPS_CAPTURE
LITE_USER_SEC_TEXT static void capture_getgroups(struct workload_report *report)
{
    volatile UINT32 group_output[4];
    group_output[0]=0x11223344U;group_output[1]=0x55667788U;
    group_output[2]=0x99aabbccU;group_output[3]=0xddeeff00U;
    for(unsigned i=0;i<3;++i) {
        unsigned size=i==1 ? OSREC_GETGROUPS_GROUP_COUNT-1 : 2*i;
        if(i==2) size=OSREC_GETGROUPS_OUTPUT_SIZE;
        UINTPTR output_address=(UINTPTR)group_output;
        if(i==2) output_address+=OSREC_GETGROUPS_OUTPUT_OFFSET;
#ifdef OSREC_GETGROUPS_NULL_OUTPUT
        if(i==1) output_address=0;
#endif
#ifdef OSREC_GETGROUPS_NULL_BOUNDARIES
        if(i) output_address=0;
        if(i==1) size=0;
#endif
#ifdef OSREC_GETGROUPS_NEGATIVE_SIZES
        if(i==1) size=0xffffffffU;
        if(i==2) {size=0x80000000U;output_address=0;}
#endif
        report->getgroups[i].size=size;
        report->getgroups[i].raw=call3(__NR_getgroups32,size,output_address,0);
        __asm__ volatile("mrs %0, cpsr" : "=r"(report->getgroups[i].mode));report->getgroups[i].mode &=31;
        for(unsigned j=0;j<4;++j) report->getgroups[i].memory[j]=group_output[j];
    }
}
#endif
#if defined(OSREC_GETRESUID_CAPTURE) || defined(OSREC_GETRESGID_CAPTURE)
#ifndef OSREC_CREDENTIAL_OUTPUT_0
#define OSREC_CREDENTIAL_OUTPUT_0 0
#define OSREC_CREDENTIAL_OUTPUT_1 4
#define OSREC_CREDENTIAL_OUTPUT_2 8
#endif
LITE_USER_SEC_TEXT static void capture_credential_outputs(struct workload_report *report)
{
    volatile UINT32 output[4],offsets[3];
    offsets[0]=OSREC_CREDENTIAL_OUTPUT_0;offsets[1]=OSREC_CREDENTIAL_OUTPUT_1;offsets[2]=OSREC_CREDENTIAL_OUTPUT_2;
    output[0]=0x11223344U;output[1]=0x55667788U;output[2]=0x99aabbccU;output[3]=0xddeeff00U;
    for(unsigned i=0;i<4;++i) {
        UINTPTR args[3];
        for(unsigned j=0;j<3;++j) args[j]=i==j+1 ? 0 : (UINTPTR)((volatile unsigned char *)output+offsets[j]);
        report->credential_outputs[i].size=i;
#ifdef OSREC_GETRESGID_CAPTURE
        report->credential_outputs[i].raw=call3(__NR_getresgid32,args[0],args[1],args[2]);
#else
        report->credential_outputs[i].raw=call3(__NR_getresuid32,args[0],args[1],args[2]);
#endif
        __asm__ volatile("mrs %0, cpsr" : "=r"(report->credential_outputs[i].mode));
        report->credential_outputs[i].mode &=31;
        for(unsigned j=0;j<4;++j) report->credential_outputs[i].memory[j]=output[j];
    }
}
#endif
LITE_USER_SEC_ENTRY VOID OsUserInit(VOID *args)
{
    (void)args;
    volatile unsigned char buffer[8];
    buffer[0]=0;buffer[1]=0x11;buffer[2]=0x22;buffer[3]=0x33;
    buffer[4]=0x44;buffer[5]=0x55;buffer[6]=0x66;buffer[7]=0x77;
#ifdef OSREC_GETSCHEDULER_TASK_CAPTURE
    UINT32 scheduler_tid=call3(__NR_gettid,0,0,0);
#endif
    struct workload_report report;
    struct user_step *steps=report.reads;
    UINT32 user_errno=0;
    int fd=(int)call3(__NR_open,(UINTPTR)input_path,O_RDONLY,0);
    if (fd>=0 && fd!=3) {
        int mapped=(int)call3(__NR_dup2,fd,3,0);
        call3(__NR_close,fd,0,0); fd=mapped;
    }
    for (unsigned i=0;i<3;++i) {
        UINT32 policy=i==0 ? 2U : i==1 ? 1U : (UINT32)-1;
        report.priorities[i].policy=policy;
        report.priorities[i].raw=call3(__NR_sched_get_priority_max,policy,0,0);
        __asm__ volatile("mrs %0, cpsr" : "=r"(report.priorities[i].mode));
        report.priorities[i].mode &=31;
    }
    for (unsigned i=0;i<3;++i) {
        UINT32 policy=i==0 ? 2U : i==1 ? 1U : (UINT32)-1;
        report.minima[i].policy=policy;
        report.minima[i].raw=call3(__NR_sched_get_priority_min,policy,0,0);
        __asm__ volatile("mrs %0, cpsr" : "=r"(report.minima[i].mode));
        report.minima[i].mode &=31;
    }
    report.pid=call3(__NR_getpid,0,0,0);
    __asm__ volatile("mrs %0, cpsr" : "=r"(report.pid_mode)); report.pid_mode &=31;
    if (fd!=3) for (;;) {}
    for (unsigned i=0;i<4;++i) {
        UINT32 count=i==0 ? 4 : i==3 ? 0 : 2;
        UINTPTR destination=i==3 ? 0 : (UINTPTR)&buffer[2+i*2];
        int raw=(int)call3(__NR_read,i==3 ? 0 : 3,destination,count);
        if (raw<0) user_errno=(UINT32)-raw;
        steps[i].raw=(UINT32)raw; steps[i].result=(UINT32)(raw<0 ? -1 : raw);
        steps[i].error=user_errno;
        steps[i].recognized=i<3 && raw>0 && buffer[2+i*2]=='A';
        __asm__ volatile("mrs %0, cpsr" : "=r"(steps[i].mode)); steps[i].mode &=31;
        for(unsigned j=0;j<8;++j) steps[i].memory[j]=buffer[j];
    }
    for (unsigned i=0;i<7;++i) {
        UINT32 number=i==0 ? __NR_getuid32 : i==1 ? __NR_getgid32 : i==2 ? __NR_getpgrp : __NR_getpgid;
        UINT32 argument=i==4 ? 1U : i==5 ? (UINT32)-1 : 0U;
        report.identities[i].number=number;
        report.identities[i].argument=argument;
        report.identities[i].raw=call3(number,argument,0,0);
        __asm__ volatile("mrs %0, cpsr" : "=r"(report.identities[i].mode));
        report.identities[i].mode &=31;
    }
    for (unsigned i=0;i<6;++i) {
        UINT32 mask=i==0 ? 0U : i==1 ? 022U : i==2 ? (UINT32)-1 : i==3 ? 0x80000000U : i==4 ? 077U : 0U;
        report.masks[i].policy=mask;
        report.masks[i].raw=call3(__NR_umask,mask,0,0);
        __asm__ volatile("mrs %0, cpsr" : "=r"(report.masks[i].mode));
        report.masks[i].mode &=31;
    }
    for (unsigned i=0;i<4;++i) {
        UINT32 number=(i&1) ? __NR_getegid32 : __NR_geteuid32;
        report.credentials[i].policy=number;
        report.credentials[i].raw=call3(number,0,0,0);
        __asm__ volatile("mrs %0, cpsr" : "=r"(report.credentials[i].mode));
        report.credentials[i].mode &=31;
    }
    for (unsigned i=0;i<6;++i) {
        UINT32 which=i==3 ? 1U : i==4 ? (UINT32)-1 : 0U;
        UINT32 who=i==1 ? 1U : i==2 ? (UINT32)-1 : 0U;
        report.process_priorities[i].which=which;
        report.process_priorities[i].who=who;
        report.process_priorities[i].raw=call3(__NR_getpriority,which,who,0);
        __asm__ volatile("mrs %0, cpsr" : "=r"(report.process_priorities[i].mode));
        report.process_priorities[i].mode &=31;
    }
    for(unsigned i=0;i<3;++i) {
        report.groups[i].policy=i;
        UINTPTR list=i==0 ? 0 : i==1 ? (UINTPTR)duplicate_group : (UINTPTR)distinct_groups;
        report.groups[i].raw=call3(__NR_setgroups32,i,list,0);
        __asm__ volatile("mrs %0, cpsr" : "=r"(report.groups[i].mode));
        report.groups[i].mode &=31;
#ifdef OSREC_GETGROUPS_CAPTURE
        if(i==(OSREC_GETGROUPS_GROUP_COUNT==1 ? 0U : 2U)) capture_getgroups(&report);
#endif
    }
#if defined(OSREC_GETRESUID_CAPTURE) || defined(OSREC_GETRESGID_CAPTURE)
    capture_credential_outputs(&report);
#endif
#ifdef OSREC_GETSCHEDULER_CAPTURE
    for(unsigned i=0;i<4;++i) {
        UINT32 id=i==0 ? 0U : i==1 ? 1U : i==2 ? 0xffffffffU : 63U;
        UINT32 flag=0;
#ifdef OSREC_GETSCHEDULER_TASK_CAPTURE
        id=i==0 ? scheduler_tid : i==1 ? 0xffffffffU : i==2 ? 127U : 0U;
        flag=0xffffffffU;
#endif
        report.schedulers[i].which=id;report.schedulers[i].who=flag;
        report.schedulers[i].raw=call3(__NR_sched_getscheduler,id,flag,0);
        __asm__ volatile("mrs %0, cpsr" : "=r"(report.schedulers[i].mode));
        report.schedulers[i].mode &=31;
    }
#endif
#ifdef OSREC_CLOCK_CAPTURE
    for(unsigned i=0;i<10;++i) {
        volatile UINT32 output[4];
        output[0]=0x11223344U;output[1]=0x55667788U;
        output[2]=0x99aabbccU;output[3]=0xddeeff00U;
        unsigned local=i%5,number=i<5 ? __NR_clock_gettime32 : __NR_clock_getres_time32;
        UINT32 id=local==1 ? 1U : local==2 ? 0xffffffffU : 0U;
        UINTPTR address=local==3 ? 0 : local==4 ? 1 : (UINTPTR)output;
        report.clocks[i].number=number;report.clocks[i].id=id;
        report.clocks[i].raw=call3(number,id,address,0);
        __asm__ volatile("mrs %0, cpsr" : "=r"(report.clocks[i].mode));report.clocks[i].mode &=31;
        report.clocks[i].memory[0]=output[0];report.clocks[i].memory[1]=output[1];
        report.clocks[i].memory[2]=output[2];report.clocks[i].memory[3]=output[3];
    }
#endif
#ifdef OSREC_RLIMIT_CAPTURE
    for(unsigned i=0;i<6;++i) {
        volatile UINT32 output[4];
        output[0]=0x11223344U;output[1]=0x55667788U;
        output[2]=0x99aabbccU;output[3]=0xddeeff00U;
        UINT32 resource=i==1 ? 1U : i==2 ? 0xffffffffU : i==5 ? 0U : 7U;
        UINTPTR address=i==3 || i==5 ? 0 : i==4 ? 1 : (UINTPTR)output;
        report.limits[i].number=__NR_ugetrlimit;report.limits[i].resource=resource;
        report.limits[i].raw=call3(__NR_ugetrlimit,resource,address,0);
        __asm__ volatile("mrs %0, cpsr" : "=r"(report.limits[i].mode));report.limits[i].mode &=31;
        for(unsigned j=0;j<4;++j)report.limits[i].memory[j]=output[j];
    }
#endif
#ifdef OSREC_UNAME_CAPTURE
    for(unsigned i=0;i<sizeof(report.names)/sizeof(report.names[0]);++i) {
        volatile unsigned char output[392];
        for(unsigned j=0;j<390;++j)output[j]=0xa1+i;
        output[390]=0x5a;output[391]=0xc3;
        UINTPTR address=i==2 ? 0 : i==3 ? 1 : (UINTPTR)output;
        report.names[i].number=__NR_uname;report.names[i].pointer_kind=i==2 ? 1 : i==3 ? 2 : 0;
        report.names[i].raw=call3(__NR_uname,address,0,0);
        __asm__ volatile("mrs %0, cpsr" : "=r"(report.names[i].mode));report.names[i].mode &=31;
        for(unsigned j=0;j<392;++j)report.names[i].memory[j]=output[j];
    }
#endif
#ifdef OSREC_CLOSE_CAPTURE
    int close_fd=(int)call3(__NR_open,(UINTPTR)input_path,O_RDONLY|O_CLOEXEC,0);
    if(close_fd!=4)for (;;) {}
    for(unsigned i=0;i<5;++i) {
        UINT32 descriptor=i==3 ? 0xffffffffU : i==4 ? 1024 : close_fd;
        report.closes[i].number=__NR_close;report.closes[i].fd=descriptor;
        report.closes[i].raw=call3(__NR_close,descriptor,0,0);
        __asm__ volatile("mrs %0, cpsr" : "=r"(report.closes[i].mode));report.closes[i].mode &=31;
    }
#endif
#ifdef OSREC_DUP_CAPTURE
    int dup_fd=(int)call3(__NR_open,(UINTPTR)input_path,O_RDONLY|O_CLOEXEC,0);
    if(dup_fd!=4)for (;;) {}
    for(unsigned i=0;i<5;++i){
        UINT32 descriptor=i==2 ? 5 : i==3 ? 0xffffffffU : i==4 ? 1024 : dup_fd;
        report.duplicates[i].number=__NR_dup;report.duplicates[i].fd=descriptor;
        report.duplicates[i].raw=call3(__NR_dup,descriptor,0,0);
        __asm__ volatile("mrs %0, cpsr" : "=r"(report.duplicates[i].mode));report.duplicates[i].mode &=31;
    }
#endif
#ifdef OSREC_FILE_CAPTURE
    for(unsigned i=0;i<FILE_CALL_COUNT;++i){
        volatile unsigned char output[192];for(unsigned j=0;j<192;++j)output[j]=0x90+i;
        if(i==2){output[0]='a';output[1]='b';output[2]='c';output[3]='d';}
        if(i==8){output[0]='X';output[1]='Y';}if(i==21)output[0]='Z';
        UINT32 number=file_specs[i][0],args[5];
        for(unsigned j=0;j<5;++j){args[j]=file_specs[i][1+j];report.files[i].args[j]=args[j];}
        if(number==5 || number==106)args[0]=file_path(args[0]);
        if(number==322)args[1]=file_path(args[1]);
        if(number==3 || number==4 || number==106 || number==197)args[1]=file_buffer(args[1],output);
        if(number==140)args[3]=file_buffer(args[3],output);
        report.files[i].number=number;report.files[i].raw=file_svc(number,args[0],args[1],args[2],args[3],args[4]);
        __asm__ volatile("mrs %0, cpsr" : "=r"(report.files[i].mode));report.files[i].mode &=31;
        for(unsigned j=0;j<192;++j)report.files[i].memory[j]=output[j];
    }
#endif
#ifdef OSREC_ASYNC_WAIT_CAPTURE
    volatile struct timespec wait_request;
    wait_request.tv_sec=0;wait_request.tv_nsec=20000000;
    report.wait.raw=call3(__NR_nanosleep,(UINTPTR)&wait_request,0,0);
    __asm__ volatile("mrs %0, cpsr":"=r"(report.wait.mode));report.wait.mode&=31;
#endif
    int child=(int)call3(__NR_fork,0,0,0);
    if (child!=0) for (;;) {}
    for (unsigned i=0;i<4;++i) {
        UINT32 number=(i&1) ? __NR_gettid : __NR_getppid;
        report.tasks[i].policy=number;
        report.tasks[i].raw=call3(number,0,0,0);
        __asm__ volatile("mrs %0, cpsr" : "=r"(report.tasks[i].mode));
        report.tasks[i].mode &=31;
    }
    fd=(int)call3(__NR_open,(UINTPTR)report_path,O_WRONLY,0);
    if (fd>=0) call3(__NR_write,fd,(UINTPTR)&report,sizeof(report));
    for (;;) {}
}
