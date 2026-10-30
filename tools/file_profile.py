"""Reviewed native file-session workload; arguments use normalized pointer classes."""
MAIN=b'/dev/shm/osrec-file.bin\0'
MISSING=b'/dev/shm/osrec-missing.bin\0'
# path: 0=NULL, 1=main, 2=missing, 3=address 1; buffer: 0=NULL, 1=witness, 2=address 1.
# number, five normalized arguments, expected signed raw result, input prefix.
CASES=[
 (5,[1,0x80242,420,0,0],4,b''),
 (63,[4,4,0,0,0],4,b''),
 (4,[4,1,4,0,0],4,b'abcd'),
 (322,[0xffffff9c,1,2,420,0],5,b''),
 (140,[4,0,0,1,0],0,b''),
 (3,[4,1,4,0,0],4,b''),
 (63,[4,5,0,0,0],5,b''),
 (140,[5,0,2,1,0],0,b''),
 (4,[5,1,2,0,0],2,b'XY'),
 (140,[4,0,0,1,0],0,b''),
 (3,[4,1,4,0,0],4,b''),
 (197,[5,1,0,0,0],0,b''),
 (106,[1,1,0,0,0],0,b''),
 (6,[4,0,0,0,0],0,b''),
 (140,[5,0,0,1,1],0,b''),
 (6,[5,0,0,0,0],0,b''),
 (3,[5,1,4,0,0],-9,b''),
 (5,[2,0,420,0,0],-2,b''),
 (322,[0xffffff9c,2,0,420,0],-2,b''),
 (197,[0xffffffff,1,0,0,0],-9,b''),
 (106,[0,1,0,0,0],-14,b''),
 (4,[5,1,1,0,0],-9,b'Z'),
 (4,[5,2,1,0,0],-14,b''),
 (4,[0xffffffff,0,0,0,0],0,b''),
 (63,[0xffffffff,6,0,0,0],-9,b''),
 (140,[5,0,0,1,0],-9,b''),
 (106,[1,2,0,0,0],-14,b''),
 (106,[2,1,0,0,0],-2,b''),
 (3,[0xffffffff,0,0,0,0],0,b''),
 (5,[3,0,420,0,0],-14,b''),
 (322,[0xffffff9c,3,0,420,0],-14,b''),
 (3,[5,0,1,0,0],-14,b''),
]
COUNT=len(CASES)

def before(index):
    prefix=CASES[index][3]
    return prefix+bytes([0x90+index])*(192-len(prefix))


def workload():
    rows=[]
    for nr,args,_,prefix in CASES:rows.append('{'+','.join(str(v)+'U' for v in (nr,*args))+'}')
    return '''#define FILE_CALL_COUNT %d
static const unsigned char file_main[] __attribute__((section(".user.rodata")))="/dev/shm/osrec-file.bin";
static const unsigned char file_missing[] __attribute__((section(".user.rodata")))="/dev/shm/osrec-missing.bin";
static const UINT32 file_specs[FILE_CALL_COUNT][6] __attribute__((section(".user.rodata")))={%s};
LITE_USER_SEC_TEXT static UINT32 file_svc(UINT32 number,UINT32 a,UINT32 b,UINT32 c,UINT32 d,UINT32 e)
{
    register UINT32 r7 __asm__("r7")=number;register UINT32 r0 __asm__("r0")=a;
    register UINT32 r1 __asm__("r1")=b;register UINT32 r2 __asm__("r2")=c;
    register UINT32 r3 __asm__("r3")=d;register UINT32 r4 __asm__("r4")=e;
    __asm__ volatile("svc %%1" : "+r"(r0) : "i"(0x900001),"r"(r7),"r"(r1),"r"(r2),"r"(r3),"r"(r4) : "memory","r14","cc");return r0;
}
LITE_USER_SEC_TEXT static UINT32 file_path(UINT32 kind)
{return kind==1 ? (UINTPTR)file_main : kind==2 ? (UINTPTR)file_missing : kind==3 ? 1 : 0;}
LITE_USER_SEC_TEXT static UINT32 file_buffer(UINT32 kind,volatile unsigned char *out)
{return kind==1 ? (UINTPTR)out : kind==2 ? 1 : 0;}
''' % (COUNT,','.join(rows))
