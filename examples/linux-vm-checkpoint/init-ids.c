/* PID 1 witness: direct SVC calls into the unmodified running Linux kernel.
   This variant calls the remaining identity queries, umask twice, and error paths of the descriptor calls after the checkpoint.
   RLIMIT_NOFILE is lowered to 8 before the checkpoint. */
#include <stdint.h>
#include <stddef.h>
static long call(long n,long a,long b,long c,long d)
{
    register long x0 __asm__("x0")=a, x1 __asm__("x1")=b;
    register long x2 __asm__("x2")=c, x3 __asm__("x3")=d;
    register long x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x8):"memory","cc");
    return x0;
}
static void text(const char *s){size_t n=0;while(s[n])++n;while(n){long r=call(64,1,(long)s,n,0);if(r<=0)for(;;){}s+=r;n-=(size_t)r;}}
static void hex(uint64_t n){char b[17];for(unsigned i=0;i<16;++i)b[i]="0123456789abcdef"[(n>>(60-4*i))&15];b[16]=0;text(b);}
static void poweroff(void){call(142,0xfee1dead,0x28121969,0x4321fedc,0);for(;;){}}
static void fail(unsigned n){text("OSREC_VM_FAIL ");hex(n);text("\n");poweroff();}
void osrec_native_main(void)
{
    text("OSREC_VM_BOOT\n");
    char uts[6][65];if(call(160,(long)uts,0,0,0))fail(1);
    long fd=call(279,(long)"checkpoint",1,0,0);if(fd<0)fail(2);
    long alias=call(23,fd,0,0,0);if(alias<0 || alias==fd)fail(3);
    /* The descriptor models hold RLIMIT_NOFILE at 8; run inside that domain (the bindings check it). */
    unsigned long limit[2]={8,8};if(call(164,7,(long)limit,0,0))fail(15);
    if(call(64,fd,(long)"abcdefgh",8,0)!=8 || call(62,fd,2,0,0)!=2)fail(4);
    unsigned char prefix[3];if(call(63,alias,(long)prefix,3,0)!=3)fail(5);
    volatile uint64_t carry=0x1234;
    for(unsigned i=0;i<3;++i){if(prefix[i]!=(unsigned char)('c'+i))fail(6);carry=carry*33+prefix[i];}
    if(call(62,fd,0,1,0)!=5)fail(7);
    text("OSREC_VM_READY ");text(uts[2]);text("\n");
    /* Host sends one line only after the full machine checkpoint is saved. */
    char input;do{if(call(63,0,(long)&input,1,0)!=1)fail(8);}while(input!='\n');
    /* Calls observed after the checkpoint besides the file transfer: identity queries, umask, error paths. */
    if(call(173,0,0,0,0)!=0 || call(175,0,0,0,0)!=0 || call(176,0,0,0,0)!=0 || call(177,0,0,0,0)!=0 || call(178,0,0,0,0)!=1)fail(20);
    unsigned ids[3]={7,7,7};if(call(150,(long)&ids[0],(long)&ids[1],(long)&ids[2],0) || ids[0] || ids[1] || ids[2])fail(21);
    if(call(166,077,0,0,0)!=022 || call(166,022,0,0,0)!=077)fail(22);
    /* EBADF on an unused descriptor; EINVAL for a bad whence, dup3 onto itself and unknown dup3 flags. */
    if(call(23,99,0,0,0)!=-9 || call(57,99,0,0,0)!=-9 || call(62,99,0,0,0)!=-9)fail(23);
    if(call(62,fd,0,99,0)!=-22 || call(24,fd,fd,0,0)!=-22 || call(24,fd,9,1,0)!=-22)fail(24);
    if(call(63,alias,(long)prefix,0,0) || call(64,alias,(long)prefix,0,0))fail(25);
    if(call(62,alias,0,1,0)!=5)fail(9);
    unsigned char suffix[2]={'X'+(carry&1),'0'+(carry%10)};
    if(call(64,alias,(long)suffix,2,0)!=2 || call(62,fd,0,1,0)!=7)fail(10);
    if(call(57,fd,0,0,0) || call(62,alias,0,0,0))fail(11);
    unsigned char result[8];if(call(63,alias,(long)result,8,0)!=8)fail(12);
    for(unsigned i=0;i<8;++i){unsigned char expected=i==5?suffix[0]:i==6?suffix[1]:(unsigned char)('a'+i);if(result[i]!=expected)fail(13);carry=carry*33+result[i];}
    if(call(62,alias,0,1,0)!=8 || call(57,alias,0,0,0) || call(63,alias,(long)result,1,0)!=-9)fail(14);
    text("OSREC_VM_PASS checksum=");hex(carry);text(" bytes=");
    for(unsigned i=0;i<8;++i){char b[3]={"0123456789abcdef"[result[i]>>4],"0123456789abcdef"[result[i]&15],0};text(b);}
    text(" offset=8 closed=-9 ids=ok\n");poweroff();
}
