"""Binary kernel boundaries: table walks, trace parsing, the replay image and stub, and a live capture/replay."""
import json,struct,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from kernel_boundary_capture import walk,parse_trace,PLUGIN,capture
from kernel_boundary_replay import elf,stub_source,RESTORE,replay
from kernel_authenticity import measure,LLVM

class Physical:
    """Physical memory of 8-byte descriptors, as the gdbstub reads it in physical mode."""
    def __init__(self):self.words={}
    def put(self,address,value):self.words[address]=value
    def read(self,address,size):assert size==8;return self.words.get(address,0).to_bytes(8,'little')

def table(level_shift,va,bits):return (va>>level_shift)&((1<<bits)-1)

class WalkTests(unittest.TestCase):
    def test_four_level_kernel_and_user_walks_with_blocks(self):
        m=Physical();regs={'TCR_EL1':16|(16<<16)|(2<<30),'TTBR1_EL1':(5<<48)|0x1000,'TTBR0_EL1':(7<<48)|0x9000}
        kva=0xffff800080012345
        l0,l1,l2,l3=0x1000,0x2000,0x3000,0x4000
        m.put(l0+8*table(39,kva,9),l1|3);m.put(l1+8*table(30,kva,9),l2|3);m.put(l2+8*table(21,kva,9),l3|3)
        m.put(l3+8*table(12,kva,9),0x40a12000|0x703)
        pa,tables,descriptor=walk(m,regs,kva&~0xfff)
        self.assertEqual((pa,tables),(0x40a12000,[l0,l1,l2,l3]));self.assertEqual(descriptor&0xfff,0x703)
        # A 2 MiB block at level 2 resolves the page inside it.
        lva=0xffff000002e53000;b1,b2=0x5000,0x6000
        m.put(l0+8*table(39,lva,9),b1|3);m.put(b1+8*table(30,lva,9),b2|3);m.put(b2+8*table(21,lva,9),0x42e00000|0x701)
        self.assertEqual(walk(m,regs,lva)[0],0x42e53000)
        # User addresses use TTBR0 (the ASID in bits 63:48 is not part of the base).
        uva=0x201000;u0,u1,u2,u3=0x9000,0xa000,0xb000,0xc000
        m.put(u0+8*table(39,uva,9),u1|3);m.put(u1+8*table(30,uva,9),u2|3);m.put(u2+8*table(21,uva,9),u3|3);m.put(u3+8*table(12,uva,9),0x41234000|0x7c3)
        self.assertEqual(walk(m,regs,uva),(0x41234000,[u0,u1,u2,u3],0x41234000|0x7c3))
        with self.assertRaisesRegex(ValueError,'not mapped'):walk(m,regs,0x7000000000)

    def test_three_level_walk_and_granule_check(self):
        m=Physical();regs={'TCR_EL1':25|(25<<16)|(2<<30),'TTBR1_EL1':0x1000,'TTBR0_EL1':0x2000}
        va=0x12345000;m.put(0x2000+8*table(30,va,9),0x3000|3);m.put(0x3000+8*table(21,va,9),0x4000|3);m.put(0x4000+8*table(12,va,9),0x40000000|0x403)
        self.assertEqual(walk(m,regs,va)[1],[0x2000,0x3000,0x4000])
        with self.assertRaisesRegex(ValueError,'granule'):walk(m,dict(regs,TCR_EL1=25|(1<<14)),va)

class TraceTests(unittest.TestCase):
    def test_accesses_belong_to_the_preceding_instruction(self):
        instructions,accesses=parse_trace('I ffff800080010c00\nI ffff800080011340\nM ffff000002e53eb0 42e53eb0 16 S\nM 9000000 - 4 L\n')
        self.assertEqual(instructions,[0xffff800080010c00,0xffff800080011340])
        self.assertEqual(accesses,[dict(index=1,va=0xffff000002e53eb0,pa=0x42e53eb0,size=16,store=True),dict(index=1,va=0x9000000,pa=None,size=4,store=False)])

class AuthenticityTests(unittest.TestCase):
    def test_slice_credits_only_functions_its_own_root_reaches(self):
        with tempfile.TemporaryDirectory() as name:
            d=Path(name);(d/'capture.json').write_text(json.dumps(dict(call=dict(number=63))))
            # Live read: entry, the syscall body, the fd lookup, a model's callee, exit.
            (d/'trace.txt').write_text(''.join('I %x\n'%pc for pc in [0x100,0x200,0x204,0x300,0x400,0x500]))
            symbols=lambda pc:{0x100:'el0_svc',0x200:'__arm64_sys_read',0x204:'__arm64_sys_read',0x300:'__fget_light',0x400:'vfs_read',0x500:'ret_to_user'}[pc]
            (d/'syscalls.c').write_text('long osrec_kernel_linux_read(int fd)\n{\n\treturn osrec_kernel_vfs_read(osrec_kernel_fdget_pos(fd));\n}\n'
                'static unsigned long osrec_kernel___fget_light(int fd)\n{\n\treturn fd;\n}\n'
                'long osrec_kernel_linux_fcntl(int fd)\n{\n\treturn osrec_kernel___fget_light(fd);\n}\n')
            (d/'models.c').write_text('int osrec_kernel_fdget_pos(int fd){return fd;}\nlong osrec_kernel_vfs_read(int f){return f;}\n')
            s=measure(d,symbols,d)['source_slice']
            # __fget_light is original in the slice, but only fcntl's root reaches it.
            self.assertEqual((s['original']['instructions'],s['model']['instructions'],s['absent']['instructions']),(2,1,3))

    def test_original_assembly_counts_when_a_reachable_function_calls_it(self):
        with tempfile.TemporaryDirectory() as name:
            d=Path(name);(d/'capture.json').write_text(json.dumps(dict(call=dict(number=46))))
            (d/'trace.txt').write_text(''.join('I %x\n'%pc for pc in [0x200,0x600,0x604,0x700]))
            symbols=lambda pc:{0x200:'__arm64_sys_ftruncate',0x600:'__pi_memset',0x604:'__pi_memset',0x700:'memcpy'}[pc]
            (d/'syscalls.c').write_text('long osrec_kernel_linux_ftruncate(char *p)\n{\n\tmemset(p, 0, 8);\n\treturn 0;\n}\n')
            (d/'models.c').write_text('')
            # memset.S defines __pi_memset with memset as its weak alias; memcpy.S is not called.
            (d/'linux-memset.S').write_text('SYM_FUNC_START(__pi_memset)\nret\nSYM_FUNC_END(__pi_memset)\nSYM_FUNC_ALIAS_WEAK(memset, __pi_memset)\n')
            (d/'linux-memcpy.S').write_text('SYM_FUNC_START(memcpy)\nret\nSYM_FUNC_END(memcpy)\n')
            s=measure(d,symbols,d)['source_slice']
            self.assertEqual((s['original']['instructions'],s['absent']['instructions']),(3,1))

    def test_macro_and_compiled_calls_reach_their_callees(self):
        # cond_resched() is a model.h macro calling _cond_resched; a call only the compiled image shows (a macro
        # local to the source) is found in slices.elf beside the sources.
        with tempfile.TemporaryDirectory() as name:
            d=Path(name)/'sources';d.mkdir();(d/'capture.json').write_text(json.dumps(dict(call=dict(number=64))))
            (d/'trace.txt').write_text(''.join('I %x\n'%pc for pc in [0x200,0x300,0x400,0x500]))
            symbols=lambda pc:{0x200:'__arm64_sys_write',0x300:'_cond_resched',0x400:'hidden',0x500:'unreached'}[pc]
            (d/'model.h').write_text('#define cond_resched() ({\\\n\tosrec_kernel__cond_resched();\\\n})\n')
            body='#define CALL_HIDDEN() osrec_kernel_ ## hidden()\nint osrec_kernel__cond_resched(void)\n{\n\treturn 0;\n}\nint osrec_kernel_hidden(void)\n{\n\treturn 1;\n}\nint osrec_kernel_unreached(void)\n{\n\treturn 2;\n}\n'
            (d/'syscalls.c').write_text(body+'long osrec_kernel_linux_write(void)\n{\n\tcond_resched();\n\treturn CALL_HIDDEN();\n}\n');(d/'models.c').write_text('')
            s=measure(d,symbols,d)['source_slice']
            self.assertEqual((s['original']['instructions'],s['absent']['instructions']),(2,2))
            source=Path(name)/'image.c';source.write_text('volatile int state;\n__attribute__((noinline)) int osrec_kernel_hidden(void){return state;}\nint osrec_kernel_linux_write(void){return osrec_kernel_hidden()+1;}\n')
            subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-O1','-ffreestanding','-nostdlib','-fuse-ld=lld','-Wl,-e,osrec_kernel_linux_write',str(source),'-o',str(Path(name)/'slices.elf')],check=True,capture_output=True)
            s=measure(d,symbols,d)['source_slice']
            self.assertEqual((s['original']['instructions'],s['absent']['instructions']),(3,1))

    def test_entry_root_reaches_only_the_calls_own_root(self):
        with tempfile.TemporaryDirectory() as name:
            d=Path(name);(d/'capture.json').write_text(json.dumps(dict(call=dict(number=63))))
            pcs=[0x100,0x110,0x120,0x200,0x300,0x400,0x130]
            (d/'trace.txt').write_text(''.join('I %x\n'%pc for pc in pcs))
            symbols=lambda pc:{0x100:'vectors',0x110:'el0t_64_sync',0x120:'el0t_64_sync_handler',0x200:'__arm64_sys_read',0x300:'vfs_read',0x400:'vfs_write',0x130:'ret_to_user'}[pc]
            (d/'syscalls.c').write_text('void osrec_kernel_el0t_64_sync_handler(void *ctx)\n{\n\tosrec_kernel_osrec_sys_call(ctx);\n}\n'
                'long osrec_kernel_linux_read(int fd)\n{\n\treturn osrec_kernel_vfs_read(fd);\n}\n'
                'long osrec_kernel_vfs_read(int fd)\n{\n\treturn fd;\n}\n'
                'long osrec_kernel_linux_write(int fd)\n{\n\treturn osrec_kernel_vfs_write(fd);\n}\n'
                'long osrec_kernel_vfs_write(int fd)\n{\n\treturn fd;\n}\n')
            (d/'models.c').write_text('long osrec_kernel_osrec_sys_call(void *ctx)\n{\n\treturn osrec_kernel_linux_read(0)+osrec_kernel_linux_write(0);\n}\n')
            s=measure(d,symbols,d)['source_slice']
            # Without the entry assembly, vectors, el0t_64_sync and ret_to_user are absent.
            self.assertEqual((s['original']['instructions'],s['absent']['instructions']),(3,4))
            (d/'linux-entry.S').write_text('SYM_CODE_START(vectors)\nSYM_CODE_END(vectors)\n\tentry_handler\t0, t, 64, sync\nSYM_CODE_START_LOCAL(ret_to_user)\nSYM_CODE_END(ret_to_user)\n')
            r=measure(d,symbols,d)
            self.assertEqual(r['source_slice']['original']['instructions'],6)
            # The table call reaches linux_write too, but a read never runs it: vfs_write stays absent.
            self.assertEqual({f['function']:f['kind'] for f in r['functions']}['vfs_write'],'absent')

class ImageTests(unittest.TestCase):
    def test_elf_segments_land_at_their_physical_addresses(self):
        image=elf([(0x40000000,b'a'*4096),(0x5fffe000,b'stub')],0x5fffe000)
        self.assertEqual(image[:4],b'\x7fELF');self.assertEqual(struct.unpack_from('<Q',image,24)[0],0x5fffe000)
        phnum=struct.unpack_from('<H',image,56)[0];self.assertEqual(phnum,2)
        for i,(address,data) in enumerate([(0x40000000,b'a'*4096),(0x5fffe000,b'stub')]):
            kind,flags,offset,vaddr,paddr,filesz,memsz,_=struct.unpack_from('<IIQQQQQQ',image,64+56*i)
            self.assertEqual((kind,vaddr,paddr,filesz,memsz),(1,address,address,len(data),len(data)));self.assertEqual(image[offset:offset+filesz],data)

    def test_stub_restores_every_register_and_erets_to_the_trap(self):
        sysregs={name:0x1000+i for i,(name,_) in enumerate(RESTORE)}
        capture=dict(entry=dict(sysregs=sysregs,sp=0xffff8000801c3ff0,gprs={'x%d'%i:i for i in range(31)},fp=dict(v={'v%d'%i:'%032x'%(i+1) for i in range(32)},fpsr=0,fpcr=0)),
                     trap=dict(site=0x201480))
        text=stub_source(capture)
        for _,reg in RESTORE:self.assertIn('msr %s,x0'%reg,text)
        # SCTLR (the MMU) is restored last, so earlier registers are written with EL1 translation off.
        self.assertEqual(RESTORE[-1][0],'SCTLR');self.assertTrue(text.index('msr sctlr_el1')>text.index('msr ttbr1_el1'))
        self.assertIn('    .quad 0x201480',text);self.assertTrue(text.rstrip().endswith('.quad 0x1e'))
        self.assertLess(text.index('ldr x30,[x30,#240]'),text.index('eret'))

CHECKPOINT=ROOT/'build/linux-svc-machine-checkpoint-state-20261029b/checkpoint'

@unittest.skipUnless(PLUGIN.exists() and CHECKPOINT.exists(),'needs the footprint plugin and the state checkpoint')
class LiveTests(unittest.TestCase):
    def test_fcntl_replays_with_the_kernels_own_instructions(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            c=capture(CHECKPOINT,ROOT/'integrations/linux_aarch64/svc-boundary.json',dict(number=25,x0=4,x1=2,x2=1),stage/'capture')
            self.assertEqual(c['returned']['gprs']['x0'],0);self.assertGreater(c['trace']['instructions'],100)
            r=replay(stage/'capture',stage/'replay',Path('/opt/homebrew/opt/llvm@16/bin'),'qemu-system-aarch64')
            self.assertEqual(r['status'],'equivalent',r['checks']);self.assertEqual(r['kernel_instructions']['authentic_share'],1.0)
            # A changed pre-state of a page the call writes diverges.
            stack=next(p for p in (stage/'capture/pages').glob('*.post') if p.read_bytes()!=(stage/'capture/pages'/(p.name[:-5]+'.pre')).read_bytes())
            pre=stage/'capture/pages'/(stack.name[:-5]+'.pre');(pre).write_bytes(bytes(b^0xff for b in pre.read_bytes()))
            bad=replay(stage/'capture',stage/'bad',Path('/opt/homebrew/opt/llvm@16/bin'),'qemu-system-aarch64')
            self.assertEqual(bad['status'],'diverged')

if __name__=='__main__':unittest.main()
