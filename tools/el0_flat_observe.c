/* Linux validation tool only; never linked into the delivery image.
 * Exec stops before the image's first instruction. Syscall tracing then stops
 * at the first host service request, which must be the terminal exit. Read the
 * completed RAM result there, then allow termination. No per-gateway stops. */
#define _GNU_SOURCE
#include <asm/ptrace.h>
#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
static int regs(pid_t child,struct user_pt_regs *r)
{struct iovec io={r,sizeof *r};return ptrace(PTRACE_GETREGSET,child,(void *)NT_PRSTATUS,&io)<0;}
int main(int argc,char **argv)
{
    if(argc!=3)return 2;
    uint64_t address=strtoull(argv[2],0,0);pid_t child=fork();
    if(child<0)return 2;
    if(!child) {
        char *arguments[]={argv[1],NULL},*environment[]={NULL};
        if(ptrace(PTRACE_TRACEME,0,0,0)<0)_exit(125);
        execve(argv[1],arguments,environment);_exit(126);
    }
    int status;struct user_pt_regs initial,terminal;
    if(waitpid(child,&status,0)!=child || !WIFSTOPPED(status) || WSTOPSIG(status)!=SIGTRAP || regs(child,&initial))goto fail;
    if(ptrace(PTRACE_SETOPTIONS,child,0,(void *)(PTRACE_O_TRACESYSGOOD|PTRACE_O_EXITKILL))<0 ||
       ptrace(PTRACE_SYSCALL,child,0,0)<0 || waitpid(child,&status,0)!=child ||
       !WIFSTOPPED(status) || WSTOPSIG(status)!=(SIGTRAP|0x80) || regs(child,&terminal))goto fail;
    if(terminal.regs[8]!=93 || (initial.pstate&15) || (terminal.pstate&15))goto fail;
    uint64_t words[40];
    for(unsigned i=0;i<40;i++) {
        errno=0;long value=ptrace(PTRACE_PEEKDATA,child,(void *)(uintptr_t)(address+8*i),0);
        if(errno)goto fail;words[i]=(uint64_t)value;
    }
    if(ptrace(PTRACE_CONT,child,0,0)<0 || waitpid(child,&status,0)!=child || !WIFEXITED(status))goto fail;
    printf("{\"entry_pc\":%"PRIu64",\"exit_pc\":%"PRIu64",\"syscall\":%"PRIu64",\"exit_argument\":%"PRIu64",\"exit_status\":%u,\"pstate\":%"PRIu64",\"words\":[",
           (uint64_t)initial.pc,(uint64_t)terminal.pc,(uint64_t)terminal.regs[8],(uint64_t)terminal.regs[0],
           (unsigned)WEXITSTATUS(status),(uint64_t)terminal.pstate);
    for(unsigned i=0;i<40;i++)printf("%s%"PRIu64,i?",":"",words[i]);puts("]}");return 0;
fail:
    fprintf(stderr,"EL0 image made an unexpected service request, faulted, or could not be traced (errno=%d)\n",errno);
    kill(child,SIGKILL);waitpid(child,&status,0);return 1;
}
