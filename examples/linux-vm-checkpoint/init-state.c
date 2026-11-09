/* PID 1 witness: direct SVC calls into the unmodified running Linux kernel.
   This variant lowers RLIMIT_NOFILE to 8, then changes descriptor and file state after the checkpoint (fcntl, pread64, pwrite64, ftruncate, writev with 2, 1, 0 and 9 segments)
   and makes futex calls that return at once: private and shared wait/wake, bitset variants, timeouts that do not fire,
   error returns, requeue and wake-op without waiters, and uncontended PI lock, trylock and unlock,
   then restores the file, so the original transfer sequence and PASS line follow unchanged. */
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
static long call6(long n,long a,long b,long c,long d,long e,long f)
{
    register long x0 __asm__("x0")=a, x1 __asm__("x1")=b;
    register long x2 __asm__("x2")=c, x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=e, x5 __asm__("x5")=f;
    register long x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");
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
    /* The fd-control model holds RLIMIT_NOFILE at 8; run inside that domain (its binding checks it). */
    unsigned long limit[2]={8,8};if(call(164,7,(long)limit,0,0))fail(15);
    if(call(64,fd,(long)"abcdefgh",8,0)!=8 || call(62,fd,2,0,0)!=2)fail(4);
    unsigned char prefix[3];if(call(63,alias,(long)prefix,3,0)!=3)fail(5);
    volatile uint64_t carry=0x1234;
    for(unsigned i=0;i<3;++i){if(prefix[i]!=(unsigned char)('c'+i))fail(6);carry=carry*33+prefix[i];}
    if(call(62,fd,0,1,0)!=5)fail(7);
    text("OSREC_VM_READY ");text(uts[2]);text("\n");
    /* Host sends one line only after the full machine checkpoint is saved. */
    char input;do{if(call(63,0,(long)&input,1,0)!=1)fail(8);}while(input!='\n');
    /* fcntl: close-on-exec flags (fd was created with MFD_CLOEXEC, its dup alias without), status flags, duplication. */
    if(call(25,fd,1,0,0)!=1 || call(25,alias,2,1,0) || call(25,alias,1,0,0)!=1 || call(25,fd,2,0,0))fail(30);
    if((call(25,fd,3,0,0)&3)!=2)fail(31);
    if(call(25,fd,0,6,0)!=6 || call(25,fd,0,10,0)!=-22 || call(25,alias,1030,0,0)!=5 || call(25,99,1,0,0)!=-9)fail(32);
    /* Positioned I/O leaves the shared f_pos at 5; ftruncate shrinks and zero-extends. */
    unsigned char buf[16];
    if(call(67,alias,(long)buf,4,2)!=4 || buf[0]!='c' || buf[3]!='f')fail(33);
    if(call(68,fd,(long)"XY",2,6)!=2 || call(46,fd,4,0,0) || call(46,alias,6,0,0) || call(68,fd,(long)"Z",1,9)!=1)fail(34);
    if(call(46,fd,-1,0,0)!=-22 || call(46,0,0,0,0)!=-22 || call(67,fd,(long)buf,1,-1)!=-22)fail(35);
    if(call(67,fd,(long)buf,16,0)!=10)fail(36);
    for(unsigned i=0;i<10;++i){unsigned char expected=i<4?(unsigned char)('a'+i):i==9?'Z':0;if(buf[i]!=expected)fail(37);}
    /* writev at the shared position 5: two segments, one segment (the single-range path) and none;
       the restore below rewrites bytes 4..7 and the position returns to 5. */
    struct {const void *base;unsigned long len;} iov[2]={{"PQ",2},{"R",1}};
    if(call(66,fd,(long)iov,2,0)!=3 || call(66,alias,(long)&iov[1],1,0)!=1 || call(66,fd,(long)iov,0,0) || call(62,fd,5,0,0)!=5)fail(39);
    /* Nine segments exceed UIO_FASTIOV (8): the kernel kmallocs the iovec array and kfrees it.
       They write bytes 5..13; the restore below truncates them away. */
    struct {const void *base;unsigned long len;} many[9];
    for(unsigned i=0;i<9;++i){many[i].base=&"STUVWXYZ!"[i];many[i].len=1;}
    if(call(66,fd,(long)many,9,0)!=9 || call(62,fd,5,0,0)!=5)fail(41);
    /* Private futex calls that return at once: a wake with no waiter, a wait on a changed value. */
    volatile int word=7;
    if(call(98,(long)&word,129,1,0)!=0 || call(98,(long)&word,128,6,0)!=-11)fail(40);
    /* Futex scenarios that return at once. Each differs in some argument register, so one can be selected.
       Private (|128): WAIT_BITSET changed value, bitset 0, absolute timeout; WAKE_BITSET; WAIT with a relative
       and an invalid timeout; an unknown command; an unaligned and an unmapped word. */
    struct {long sec,nsec;} later={1000000,0},bad={0,1000000000};
    volatile int word2=3;
    if(call6(98,(long)&word,137,6,0,0,-1)!=-11 || call6(98,(long)&word,137,7,0,0,0)!=-22 || call6(98,(long)&word,138,1,0,0,1)!=0 ||
       call6(98,(long)&word,137,8,(long)&later,0,-1)!=-11 || call(98,(long)&word,128,9,(long)&later)!=-11 ||
       call(98,(long)&word,128,10,(long)&bad)!=-22 || call(98,(long)&word,142,0,0)!=-38 ||
       call(98,(long)&word+1,129,2,0)!=-22 || call(98,16,128,11,0)!=-14)fail(42);
    /* REQUEUE and CMP_REQUEUE (mismatch, then match) and WAKE_OP (word2 += 1) without waiters. */
    if(call6(98,(long)&word,131,1,1,(long)&word2,0)!=0 || call6(98,(long)&word,132,1,1,(long)&word2,99)!=-11 ||
       call6(98,(long)&word,132,1,1,(long)&word2,7)!=0 || call6(98,(long)&word,133,1,1,(long)&word2,0x10001000)!=0 || word2!=4)fail(43);
    /* Uncontended PI: lock a free word (it then holds our TID), trylock it again (EDEADLK), unlock, trylock, unlock. */
    volatile unsigned pi=0;long tid=call(178,0,0,0,0);
    if(call(98,(long)&pi,134,0,0)!=0 || pi!=(unsigned)tid || call(98,(long)&pi,136,0,0)!=-35 || call(98,(long)&pi,135,0,0)!=0 || pi!=0 ||
       call(98,(long)&pi,136,0,0)!=0 || pi!=(unsigned)tid || call(98,(long)&pi,135,0,0)!=0 || pi!=0)fail(44);
    /* Shared (no private flag) WAKE and WAIT on the stack word: the key comes from the page. */
    if(call(98,(long)&word,1,1,0)!=0 || call(98,(long)&word,0,6,0)!=-11)fail(45);
    /* Restore the file and descriptor table for the transfer sequence below. */
    if(call(68,alias,(long)"efgh",4,4)!=4 || call(46,fd,8,0,0) || call(57,6,0,0,0) || call(57,5,0,0,0) || call(25,alias,2,0,0))fail(38);
    if(call(62,alias,0,1,0)!=5)fail(9);
    unsigned char suffix[2]={'X'+(carry&1),'0'+(carry%10)};
    if(call(64,alias,(long)suffix,2,0)!=2 || call(62,fd,0,1,0)!=7)fail(10);
    if(call(57,fd,0,0,0) || call(62,alias,0,0,0))fail(11);
    unsigned char result[8];if(call(63,alias,(long)result,8,0)!=8)fail(12);
    for(unsigned i=0;i<8;++i){unsigned char expected=i==5?suffix[0]:i==6?suffix[1]:(unsigned char)('a'+i);if(result[i]!=expected)fail(13);carry=carry*33+result[i];}
    if(call(62,alias,0,1,0)!=8 || call(57,alias,0,0,0) || call(63,alias,(long)result,1,0)!=-9)fail(14);
    text("OSREC_VM_PASS checksum=");hex(carry);text(" bytes=");
    for(unsigned i=0;i<8;++i){char b[3]={"0123456789abcdef"[result[i]>>4],"0123456789abcdef"[result[i]&15],0};text(b);}
    text(" offset=8 closed=-9 state=ok\n");poweroff();
}
