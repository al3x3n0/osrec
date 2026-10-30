/* PID 1 for tools/linux_kallsyms.py: print /proc/kallsyms on the console through a detached proc mount, then power off. */
#include <stdint.h>
#include <stddef.h>
static long call(long n,long a,long b,long c,long d,long e)
{
    register long x0 __asm__("x0")=a, x1 __asm__("x1")=b, x2 __asm__("x2")=c, x3 __asm__("x3")=d, x4 __asm__("x4")=e;
    register long x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x8):"memory","cc");
    return x0;
}
static void out(const char *s,long n){while(n>0){long r=call(64,1,(long)s,n,0,0);if(r<=0)return;s+=r;n-=r;}}
static void text(const char *s){long n=0;while(s[n])++n;out(s,n);}
static void poweroff(void){call(142,0xfee1dead,0x28121969,0x4321fedc,0,0);for(;;){}}
static char buf[65536];
void osrec_native_main(void)
{
    long fs=call(430,(long)"proc",0,0,0,0);                 /* fsopen */
    if(fs<0){text("KALLSYMS_FAIL fsopen\n");poweroff();}
    if(call(431,fs,6,0,0,0)<0){text("KALLSYMS_FAIL fsconfig\n");poweroff();}   /* FSCONFIG_CMD_CREATE */
    long mnt=call(432,fs,0,0,0,0);                           /* fsmount */
    if(mnt<0){text("KALLSYMS_FAIL fsmount\n");poweroff();}
    long fd=call(56,mnt,(long)"kallsyms",0,0,0);             /* openat */
    if(fd<0){text("KALLSYMS_FAIL open\n");poweroff();}
    text("KALLSYMS_BEGIN\n");
    for(;;){long n=call(63,fd,(long)buf,sizeof buf,0,0);if(n<=0)break;out(buf,n);}
    text("KALLSYMS_END\n");poweroff();
}
