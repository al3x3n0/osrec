/* Construction/reference tool only. Real captured kernel syscalls initialize
 * a new ELF process; none of this host loader is linked into delivery images. */
#define _GNU_SOURCE
#include "osrec/linuxkernel_el0_native.h"
#include "linuxkernel_checkpoint_report.h"
#include <asm/unistd.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
static struct lk_el0_native *native;
static struct lk_el0_counter counters[4096];
static struct lk_el0_mmio mmio[16384];
static unsigned calls;
/* Read from the ELF symbol by capsule construction; old helpers lack it. */
__attribute__((used)) const uint64_t osrec_prepare_application_abi=2;
static void json_string(FILE *f,const char *s)
{
    fputc('"',f);
    for(const unsigned char *p=(const void *)s;*p;p++) {
        if(*p=='"' || *p=='\\')fputc('\\',f);
        if(*p<32)fprintf(f,"\\u%04x",*p);else fputc(*p,f);
    }
    fputc('"',f);
}
/* Independent construction check: the supplied ELF runs under the Linux host
 * kernel, with no captured-kernel instance, patches or syscall substitution. */
static int baseline(int argc,char **argv)
{
    if(argc<4 || argc>132)return 2;
    FILE *report=fopen(argv[3],"wx");if(!report)return 2;
    struct utsname system;if(uname(&system)){fclose(report);return 2;}
    int errors[2];if(pipe2(errors,O_CLOEXEC)){fclose(report);return 2;}
    pid_t child=fork();if(child<0){fclose(report);close(errors[0]);close(errors[1]);return 2;}
    if(!child) {
        close(errors[0]);fclose(report);
        char *arguments[130]={"program"},*environment[]={NULL};
        for(int i=4;i<argc;i++)arguments[i-3]=argv[i];
        execve(argv[2],arguments,environment);
        int error=errno;(void)write(errors[1],&error,sizeof error);_exit(127);
    }
    close(errors[1]);int error=0,status=0;size_t got=0;
    while(got<sizeof error) {
        ssize_t n=read(errors[0],(unsigned char *)&error+got,sizeof error-got);
        if(n<0 && errno==EINTR)continue;
        if(n<0){close(errors[0]);fclose(report);return 2;}
        if(!n)break;got+=(size_t)n;
    }
    close(errors[0]);pid_t waited;
    do {waited=waitpid(child,&status,0);}while(waited<0 && errno==EINTR);
    if(waited!=child || (got && got!=sizeof error)){fclose(report);return 2;}
    fprintf(report,"{\"format\":\"osrec-linux-user-baseline-v1\",\"exec_errno\":%d,\"exit_status\":",error);
    if(WIFEXITED(status))fprintf(report,"%d",WEXITSTATUS(status));else fputs("null",report);
    fprintf(report,",\"signal\":%d,\"machine\":",WIFSIGNALED(status)?WTERMSIG(status):0);json_string(report,system.machine);
    fputs(",\"kernel_release\":",report);json_string(report,system.release);fputs("}\n",report);
    int failed=ferror(report);if(fclose(report))failed=1;return failed?2:0;
}
static void fatal(const char *stage,const struct lk_el0_diagnostic *d)
{
    fprintf(stderr,"%s: reason=%"PRIu64" pc=0x%"PRIx64" detail=0x%"PRIx64" far=0x%"PRIx64"\n",
            stage,d->reason,d->pc,d->detail,d->far);exit(1);
}
static uint64_t syscall_guest(struct osrec_context *c,uint64_t nr,uint64_t a,uint64_t b,uint64_t d,uint64_t e,uint64_t f,uint64_t g)
{
    struct osrec_context input=*c;input.x[8]=nr;input.x[0]=a;input.x[1]=b;input.x[2]=d;input.x[3]=e;input.x[4]=f;input.x[5]=g;
    struct lk_el0_result result;calls++;
    fprintf(stderr,"bootstrap syscall %u: nr=%"PRIu64" pc=0x%"PRIx64"\n",calls,nr,c->pc);fflush(stderr);
    if(lk_el0_call(lk_el0_native_kernel(native),&input,0xd4000001,&result)!=LK_EL0_OK) {
        struct lk_el0_diagnostic diagnostic;char text[160]={0};
        fprintf(stderr,"  x0=0x%"PRIx64" x1=0x%"PRIx64" x2=0x%"PRIx64" lr=0x%"PRIx64" sp=0x%"PRIx64"\n",
                result.context.x[0],result.context.x[1],result.context.x[2],result.context.x[30],result.context.sp);
        if(lk_el0_native_memory(native,result.context.x[0],text,sizeof text-1,0,1,&diagnostic)==LK_EL0_OK)
            fprintf(stderr,"  diagnostic format: %s\n",text);
        uint64_t frame=result.context.x[29];
        for(unsigned i=0;i<12 && frame;i++) {
            uint64_t record[2];if(lk_el0_native_memory(native,frame,record,sizeof record,0,1,&diagnostic)!=LK_EL0_OK)break;
            fprintf(stderr,"  frame %u: 0x%"PRIx64"\n",i,record[1]);if(record[0]<=frame)break;frame=record[0];
        }
        fatal("captured syscall",&result.diagnostic);
    }
    *c=result.context;fprintf(stderr,"  returned=0x%"PRIx64" pc=0x%"PRIx64"\n",c->x[0],c->pc);fflush(stderr);return c->x[0];
}
static void copy_memory(uint64_t va,void *bytes,uint64_t size,int write,int kernel)
{
    struct lk_el0_diagnostic d;
    if(lk_el0_native_memory(native,va,bytes,size,write,kernel,&d)!=LK_EL0_OK)fatal("checked memory copy",&d);
}
static uint64_t qword(uint64_t va){uint64_t v;copy_memory(va,&v,8,0,1);return v;}
static FILE *output(const char *directory,const char *name,const char *mode)
{
    char path[4096];if(snprintf(path,sizeof path,"%s/%s",directory,name)>=(int)sizeof path)exit(2);
    FILE *f=fopen(path,mode);if(!f){perror(path);exit(2);}return f;
}
static void inputs(uint64_t base,uint64_t step,uint64_t uart)
{
    if(lk_el0_native_record_inputs(native,base,step,uart,counters,4096,mmio,16384)!=LK_EL0_OK)exit(2);
}
static int record(int argc,char **argv)
{
    if(argc!=8)return 2;
    struct lk_el0_diagnostic d;if(lk_el0_native_open(argv[2],&native,&d)!=LK_EL0_OK)fatal("open",&d);
    inputs(strtoull(argv[4],0,0),strtoull(argv[5],0,0),strtoull(argv[6],0,0));
    struct lk_el0_event *events;if(lk_el0_native_trace_allocate(native,30000,&events)!=LK_EL0_OK)return 2;
    struct lk_el0_result result;enum lk_el0_status status=lk_el0_native_execute(native,NULL,&result);
    uint64_t count=lk_el0_native_events(native),nc=lk_el0_native_counters_consumed(native),nm=lk_el0_native_mmio_consumed(native);
    FILE *f=output(argv[3],"calls.json","w");int failed=checkpoint_report(f,"prepared-application-native-reference",events,count,&result,nc,nm);fclose(f);
    f=output(argv[3],"counters.bin","wb");failed|=fwrite(counters,sizeof counters[0],nc,f)!=nc;fclose(f);
    f=output(argv[3],"mmio.bin","wb");failed|=fwrite(mmio,sizeof mmio[0],nm,f)!=nm;fclose(f);
    f=output(argv[3],"console.txt","wb");uint64_t uart=strtoull(argv[6],0,0);
    for(uint64_t i=0;i<nm;i++)if(mmio[i].write && mmio[i].address==uart)fputc(mmio[i].value&255,f);fclose(f);
    printf("{\"events\":%"PRIu64",\"status\":%u,\"reason\":%"PRIu64",\"pc\":\"0x%"PRIx64"\",\"detail\":\"0x%"PRIx64"\",\"far\":\"0x%"PRIx64"\",\"counters\":%"PRIu64",\"mmio\":%"PRIu64"}\n",
           count,status,result.diagnostic.reason,result.diagnostic.pc,result.diagnostic.detail,result.diagnostic.far,nc,nm);
    lk_el0_native_close(native);
    return failed || status!=LK_EL0_BOUNDARY || result.diagnostic.reason!=OSREC_STOP_BOUNDARY || result.diagnostic.pc!=strtoull(argv[7],0,0);
}
int main(int argc,char **argv)
{
    if(argc>1 && !strcmp(argv[1],"baseline"))return baseline(argc,argv);
    if(argc>1 && !strcmp(argv[1],"record"))return record(argc,argv);
    if(argc<10 || argc>138 || strcmp(argv[1],"prepare")){
        fprintf(stderr,"usage: %s prepare PACKAGE USER_ELF OUT TASK_SLOT TASK_MM MM_MT UART BASE [ARG ...]\n",argv[0]);return 2;}
    FILE *file=fopen(argv[3],"rb");if(!file)return 2;
    if(fseek(file,0,SEEK_END))return 2;long length=ftell(file);rewind(file);
    if(length<(long)sizeof(Elf64_Ehdr) || length>(16<<20))return 2;
    unsigned char *elf=malloc(length);if(!elf || fread(elf,1,length,file)!=(size_t)length)return 2;fclose(file);
    Elf64_Ehdr *header=(void *)elf;
    if(memcmp(header->e_ident,ELFMAG,SELFMAG) || header->e_ident[EI_CLASS]!=ELFCLASS64 || header->e_ident[EI_DATA]!=ELFDATA2LSB ||
       header->e_type!=ET_EXEC || header->e_machine!=EM_AARCH64 || header->e_entry%4 ||
       header->e_phentsize!=sizeof(Elf64_Phdr) || header->e_phoff>(uint64_t)length ||
       header->e_phnum>((uint64_t)length-header->e_phoff)/sizeof(Elf64_Phdr))return 2;
    const Elf64_Phdr *segments=(const void *)(elf+header->e_phoff);
    struct lk_el0_diagnostic d;if(lk_el0_native_open(argv[2],&native,&d)!=LK_EL0_OK)fatal("open",&d);
    inputs(strtoull(argv[9],0,0),1024,strtoull(argv[8],0,0));
    struct osrec_context context=*lk_el0_native_initial(native);
    char name[]="osrec-program";uint64_t name_va=context.sp-256;copy_memory(name_va,name,sizeof name,1,0);
    if((int64_t)syscall_guest(&context,__NR_close_range,3,UINT64_MAX,0,0,0,0)<0)return 1;
    unsigned arguments=1+(unsigned)(argc-10);size_t extras=4096;
    for(int i=10;i<argc;i++){if(strlen(argv[i])>65536)return 2;extras+=strlen(argv[i])+1;}
    size_t blob_size=((size_t)length+extras+4095)&~4095ull;
    uint64_t address=syscall_guest(&context,__NR_mmap,0,blob_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE,UINT64_MAX,0);
    if((int64_t)address<0)return 1;
    unsigned char *blob=calloc(1,blob_size);if(!blob)return 2;memcpy(blob,elf,length);
    uint64_t argv_offset=((uint64_t)length+15)&~15ull,env_offset=argv_offset+8*(arguments+1),strings=env_offset+8;
    uint64_t *args=(void *)(blob+argv_offset);args[0]=address+strings;memcpy(blob+strings,"program",8);strings+=8;
    for(int i=10;i<argc;i++){size_t size=strlen(argv[i])+1;args[1+i-10]=address+strings;memcpy(blob+strings,argv[i],size);strings+=size;}
    copy_memory(address,blob,blob_size,1,0);
    uint64_t fd=syscall_guest(&context,__NR_memfd_create,name_va,1,0,0,0,0);if((int64_t)fd<0)return 1;
    for(uint64_t done=0;done<(uint64_t)length;) {
        uint64_t wrote=syscall_guest(&context,__NR_write,fd,address+done,(uint64_t)length-done,0,0,0);
        if((int64_t)wrote<=0 || wrote>(uint64_t)length-done)return 1;done+=wrote;
    }
    uint64_t empty=address+((strings+15)&~15ull);
    syscall_guest(&context,__NR_execveat,fd,empty,address+argv_offset,address+env_offset,AT_EMPTY_PATH,0);
    if(context.pc!=header->e_entry){fprintf(stderr,"execveat did not reach supplied ELF entry\n");return 1;}
    struct osrec_context initial=context;
    for(unsigned i=0;i<header->e_phnum;i++)if(segments[i].p_type==PT_LOAD && segments[i].p_flags&PF_X) {
        uint64_t start=segments[i].p_vaddr&~4095ull,end=(segments[i].p_vaddr+segments[i].p_memsz+4095)&~4095ull;
        if((int64_t)syscall_guest(&context,__NR_madvise,start,end-start,MADV_POPULATE_READ,0,0,0)<0)return 1;
    }
    memset(lk_el0_native_fp(native),0,sizeof(struct lk_el0_fp));
    uint64_t task=qword(strtoull(argv[5],0,0)),mm=qword(task+strtoull(argv[6],0,0)),root=mm+strtoull(argv[7],0,0);
    FILE *a=output(argv[4],"native.bin","wbx"),*b=output(argv[4],"memory.bin","wbx");
    if(lk_el0_native_snapshot(native,&initial,fileno(a),fileno(b))!=LK_EL0_OK)return 1;fclose(a);fclose(b);
    printf("{\"entry\":\"0x%"PRIx64"\",\"sp\":\"0x%"PRIx64"\",\"vma_root\":\"0x%"PRIx64"\",\"bootstrap_syscalls\":%u,\"counter_reads\":%"PRIu64"}\n",
           initial.pc,initial.sp,root,calls,lk_el0_native_counters_consumed(native));
    lk_el0_native_close(native);free(blob);free(elf);return 0;
}
