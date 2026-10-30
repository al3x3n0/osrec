"""start_mmu.S: the identity map makes RAM Normal memory and keeps the image's text read-only."""
import subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from freestanding_elf import prepare_target,target_metadata,describe
from gdb_remote import Remote
from svc_boundary import free_port
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'

# The checks memset.S needs (an unaligned 8-byte store, DC ZVA), then, if asked, a store into .text.
PROGRAM=r'''
#include <stdint.h>
__attribute__((section(".result"),used)) uint32_t osrec_result[32];
volatile uint64_t outcome[4];
static uint8_t buffer[256] __attribute__((aligned(64)));
__attribute__((noinline)) void probe_done(void){for(;;)__asm__ volatile("");}
void replay_fault(void){uint64_t esr;__asm__ volatile("mrs %0, esr_el1":"=r"(esr));outcome[0]=0xfa;outcome[3]=esr>>26;probe_done();}
void replay_main(void)
{
    volatile uint64_t *unaligned=(volatile uint64_t *)(buffer+3);
    for(int i=0;i<256;++i)buffer[i]=0xa5;
    *unaligned=UINT64_C(0x1122334455667788);
    __asm__ volatile("dc zva, %0"::"r"(buffer+64):"memory");
    outcome[1]=*unaligned;outcome[2]=buffer[64]|(uint64_t)buffer[127]<<8|(uint64_t)buffer[128]<<16;
    if(WRITE_TEXT)*(volatile uint32_t *)(uintptr_t)&replay_main=0;
    outcome[0]=1;probe_done();
}
'''

def build(stage,mmu,write_text=False):
    sources=stage/'sources';sources.mkdir(parents=True)
    flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40200000,result_address=0x40180000),sources,mmu)
    (sources/'probe.c').write_text(PROGRAM.replace('WRITE_TEXT','1' if write_text else '0'))
    elf=stage/'probe.elf'
    subprocess.run([LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined',
        '-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'probe.c','-o',elf],check=True,capture_output=True)
    return elf

def run(elf):
    symbols={r.split()[0]:int(r.split()[2],16) for r in subprocess.run([LLVM/'llvm-nm','--defined-only','--format=posix',elf],check=True,capture_output=True,text=True).stdout.splitlines() if len(r.split())>=3}
    port=free_port()
    qemu=subprocess.Popen([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53','-accel','tcg','-smp','1','-m','64M','-nodefaults','-display','none',
        '-monitor','none','-serial','none','-semihosting-config','enable=off','-device','loader,file=%s,cpu-num=0'%elf,'-S','-gdb','tcp:127.0.0.1:%d'%port],
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        r=Remote(port,timeout=30);r.breakpoint(symbols['probe_done']);r.resume()
        if r.wait(30)!=symbols['probe_done']:raise AssertionError('probe stopped elsewhere')
        return [r.u(symbols['outcome']+8*i) for i in range(4)],symbols
    finally:qemu.kill();qemu.wait()

class IdentityMmuTests(unittest.TestCase):
    def test_mmu_off_start_faults_where_memset_needs_normal_memory(self):
        with tempfile.TemporaryDirectory() as name:
            outcome,_=run(build(Path(name),None))
            # Data abort from EL1 (EC 0x25): the unaligned store hits Device memory.
            self.assertEqual((outcome[0],outcome[3]),(0xfa,0x25))

    def test_identity_map_allows_unaligned_stores_and_dc_zva(self):
        with tempfile.TemporaryDirectory() as name:
            outcome,symbols=run(build(Path(name),'identity'))
            self.assertEqual(outcome[0],1);self.assertEqual(outcome[1],0x1122334455667788)
            # DC ZVA zeroed one 64-byte block: buffer[64..127] is zero, buffer[128] is not.
            self.assertEqual(outcome[2],0xa50000)
            self.assertEqual(symbols['__text_start'],0x40200000);self.assertEqual(symbols['__text_end']%4096,0)

    def test_identity_map_keeps_text_read_only(self):
        with tempfile.TemporaryDirectory() as name:
            outcome,_=run(build(Path(name),'identity',write_text=True))
            # Permission fault on the store into replay_main: data abort, current EL.
            self.assertEqual((outcome[0],outcome[3]),(0xfa,0x25));self.assertEqual(outcome[1],0x1122334455667788)

    def test_modes_are_checked_and_recorded(self):
        with tempfile.TemporaryDirectory() as name:
            sources=Path(name)
            for arch,mode in (('aarch64','paging'),('armv7','identity')):
                with self.subTest(arch=arch,mode=mode),self.assertRaises(ValueError):
                    prepare_target(SimpleNamespace(arch=arch),sources,mode)
            prepare_target(SimpleNamespace(arch='aarch64'),sources,'identity')
            self.assertIn('osrec_identity_map',(sources/'start.S').read_text())
            self.assertIn('__text_end = .;',(sources/'image.ld').read_text())
        with tempfile.TemporaryDirectory() as name:
            elf=build(Path(name),'identity')
            self.assertEqual(target_metadata(describe(elf),26)['mmu_enabled'],False)
            metadata=target_metadata(describe(elf),26,'identity')
            self.assertTrue(metadata['mmu_enabled']);self.assertEqual(metadata['mmu']['ram'],'Normal Non-cacheable')

if __name__=='__main__':unittest.main()
