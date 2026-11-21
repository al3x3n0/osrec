/* A separately supplied static ELF. Linux constructs argc/argv/auxv; the
 * application then exercises real captured-kernel memory and file syscalls. */
#include <stdint.h>
#include "syscall.h"
extern void _start(void);
static int equal(const char *a,const char *b){while(*a && *a==*b){a++;b++;}return *a==*b;}
int program_main(long argc,char **argv)
{
    if(argc!=2 || !equal(argv[1],"demo") || argv[argc])return 10;
    char **env=argv+argc+1;while(*env)env++;
    const uint64_t *aux=(const void *)(env+1);unsigned pages=0,entry=0;
    for(;aux[0];aux+=2){if(aux[0]==6)pages=aux[1]==4096;if(aux[0]==9)entry=aux[1]==(uintptr_t)_start;}
    if(!pages || !entry)return 11;
    long pid=syscall6(172,0,0,0,0,0,0);if(pid<=0)return 12;
    long address=syscall6(222,0,8192,3,0x22,-1,0);if(address<0)return 13;
    volatile unsigned char *p=(void *)(uintptr_t)address;
    unsigned sum=0;for(unsigned i=0;i<8192;i++){if(p[i])return 14;p[i]=(unsigned char)(i*17+3);sum+=p[i];}
    if(sum!=1044480)return 15;
    long fd=syscall6(279,(long)"new-user",1,0,0,0,0);if(fd<0)return 16;
    if(syscall6(64,fd,(long)"ELF!",4,0,0,0)!=4 || syscall6(62,fd,0,0,0,0,0))return 17;
    char data[4];if(syscall6(63,fd,(long)data,4,0,0,0)!=4)return 18;
    for(unsigned i=0;i<4;i++)if(data[i]!="ELF!"[i])return 19;
    if(syscall6(57,fd,0,0,0,0,0) || syscall6(215,address,8192,0,0,0,0))return 20;
    static const char message[]="OSREC_USER_ELF_PASS\n";
    if(syscall6(64,1,(long)message,sizeof message-1,0,0,0)!=(long)sizeof message-1)return 21;
    return 0;
}
