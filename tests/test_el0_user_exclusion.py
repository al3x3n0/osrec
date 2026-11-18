"""Execute the coarse static lookup against an independent range-scan oracle."""
from pathlib import Path
import hashlib,json,os,random,shutil,struct,subprocess,sys,tempfile,unittest
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from el0_user_exclusion import exclusion_buckets,exclusion_path,validate_exclusion_buckets
from el0_calls_fixture import save_context
CC=Path('/opt/homebrew/opt/llvm@16/bin/clang');QEMU=shutil.which('qemu-system-aarch64')


MAPS=([],[(0,1)],[(0,(1<<39)+5)],
    [(0x1000,0x2000),(0x3000,0x4000),((1<<39)-8,(1<<39)+8),((1<<48)-3,1<<48)],
    [(0x7000,0x9000),(0x1000,0x2000),(0x1800,0x8000),(1<<60,(1<<60)+4096)],
    [(0,1<<48)],
    [(1<<45,(1<<45)+(1<<29)),(0x800080002000,0x800080003000),
     (0x800080004000,0x800080005000),(0x800080010000,0x800081780000),
     (0xffffff5fe000,0xffffff6fe000)])


class Construction(unittest.TestCase):
    def test_lookup_requires_readonly_bound_kernel_maps_ranges_geometry_and_hash(self):
        raw=struct.pack('<4Q',0x10000,0x40000000,4096,0)
        table=exclusion_buckets([(0x10000,0x11000)])
        data={0x1000:struct.pack('<Q',1),0x2000:raw,0x3010:struct.pack('<2Q',0x2000,1),
            0x4000:struct.pack('<3Q',1,0x10000,0x11000),0x5000:table}
        elf=SimpleNamespace(symbols=[dict(name=n,value=v,shndx=1) for n,v in
            (('flat_user_exclusion_bucket_mode',0x1000),('flat_maps',0x2000),('flat_program',0x3000),
             ('flat_user_excluded',0x4000),('flat_user_exclusion_buckets',0x5000))],
            sections=[{},dict(flags=2)],read=lambda at,size:data[at][:size])
        checked=dict(load_segments=[dict(address=0x1000,memory_bytes=0x6000,flags=4)])
        config=dict(shift=39,entries=512,entry_bytes=16,sha256=hashlib.sha256(table).hexdigest())
        meta=dict(user_exclusion_buckets=config)
        validate_exclusion_buckets(elf,checked,meta)
        data[0x5000]=bytes((table[0]^1,))+table[1:]
        with self.assertRaisesRegex(ValueError,'buckets differ'):validate_exclusion_buckets(elf,checked,meta)
        data[0x5000]=table;data[0x4000]=struct.pack('<3Q',1,0x10001,0x11000)
        with self.assertRaisesRegex(ValueError,'ranges differ'):validate_exclusion_buckets(elf,checked,meta)
        data[0x4000]=struct.pack('<3Q',1,0x10000,0x11000);data[0x3010]=struct.pack('<2Q',0x2001,1)
        with self.assertRaisesRegex(ValueError,'binding differs'):validate_exclusion_buckets(elf,checked,meta)
        data[0x3010]=struct.pack('<2Q',0x2000,1);checked['load_segments'][0]['flags']=6
        with self.assertRaisesRegex(ValueError,'writable'):validate_exclusion_buckets(elf,checked,meta)
        checked['load_segments'][0]['flags']=4;config['entries']=513
        with self.assertRaisesRegex(ValueError,'geometry'):validate_exclusion_buckets(elf,checked,meta)
        config['entries']=512;meta.pop('user_exclusion_buckets')
        with self.assertRaisesRegex(ValueError,'mode differs'):validate_exclusion_buckets(elf,checked,meta)

    def test_empty_exact_mixed_merged_clipped_and_invalid_ranges(self):
        self.assertEqual(exclusion_buckets([]),bytes(8192))
        rows=list(struct.iter_unpack('<2Q',exclusion_buckets([(0x1000,0x2000),(0x3000,0x4000)])))
        self.assertEqual(rows[0],(0x1000,0x3001));self.assertEqual(rows[1:],[(0,0)]*511)
        self.assertEqual(exclusion_buckets([(0x1000,0x3000),(0x2000,0x4000)]),exclusion_buckets([(0x1000,0x4000)]))
        self.assertEqual(exclusion_buckets([(0,1<<64)]),exclusion_buckets([(0,1<<48)]))
        for spans in ([(-1,2)],[(2,1)],[(0,(1<<64)+1)]):
            with self.assertRaises(ValueError):exclusion_buckets(spans)


@unittest.skipUnless(CC.exists() and QEMU,'AArch64 compiler and QEMU required')
class Instructions(unittest.TestCase):
    def test_all_buckets_edges_holes_odd_lengths_aliases_and_flags(self):
        lines=['.text','.global _start','_start:','adrp x0,host_stack_end','add x0,x0,:lo12:host_stack_end',
            'mov sp,x0','bl test_main','adrp x1,exit_status','add x1,x1,:lo12:exit_status','str x0,[x1,#8]',
            'mov x0,#0x20','hlt #0xf000','b .'];header=[];fixtures=[];comparisons=0
        registers=((0,16,17,15,14),(16,17,0,14,30),(30,0,16,17,15),(17,30,15,0,16))
        for m,spans in enumerate(MAPS):
            values={0,1,(1<<48)-1,1<<48,(1<<64)-1,1<<63,0xffffc39f7a30}
            for i in range(512):values.update((i<<39,(i<<39)+(1<<38),((i+1)<<39)-1))
            for lo,hi in spans:
                values.update(v for v in (lo-1,lo,lo+1,hi-1,hi,hi+1) if 0<=v<1<<64)
            rng=random.Random(m);values.update(rng.getrandbits(48) for _ in range(256))
            values=sorted(values);comparisons+=len(values)*16*len(registers)
            header+=['static const struct span spans%d[]={%s};'%(m,','.join('{0x%xull,0x%xull}'%row for row in spans) or '{0,0}'),
                'static const uint64_t values%d[]={%s};'%(m,','.join('0x%xull'%v for v in values))]
            for r,regs in enumerate(registers):
                i=m*len(registers)+r;a,p,d,s,q=regs
                lines+=['.global probe%d'%i,'probe%d:'%i,'sub sp,sp,#96']
                lines+=['stp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
                lines+=['adrp x9,test_host_sp','mov x10,sp','str x10,[x9,:lo12:test_host_sp]',
                    'adrp x9,test_after','str x1,[x9,:lo12:test_after]','mov x30,x0','ldr x9,[x30,#264]',
                    'msr nzcv,x9','ldr x9,[x30,#248]','mov sp,x9']
                lines+=['ldp x%d,x%d,[x30,#%d]'%(r,r+1,r*8) for r in range(0,30,2)]+['ldr x30,[x30,#240]']
                lines+=['stp x%d,x%d,[sp,#-64]!'%(a,p),'stp x%d,x%d,[sp,#16]'%(d,s),'str x%d,[sp,#32]'%q,
                    'mrs x%d,nzcv'%s,'str x%d,[sp,#40]'%s,'lsr x%d,x%d,#48'%(s,a),'cbnz x%d,reject%d'%(s,i)]
                path='\n'.join(exclusion_path(*regs,'reject%d'%i,'allow%d'%i,'.Ltest%d_'%i,True))
                lines+=path.replace('flat_user_exclusion_buckets','buckets%d'%m).replace('flat_user_excluded','excluded%d'%m).splitlines()
                lines+=['allow%d:'%i,'mov x%d,#1'%s,'b done%d'%i,'reject%d:'%i,'mov x%d,#0'%s,
                    'done%d:'%i,'str x%d,[sp,#48]'%s,'ldr x%d,[sp,#40]'%s,'msr nzcv,x%d'%s,
                    'ldr x%d,[sp,#32]'%q,'ldp x%d,x%d,[sp,#16]'%(d,s),'ldp x%d,x%d,[sp]'%(a,p),
                    'ldr x0,[sp,#48]','add sp,sp,#64','b capture']
                header+=['extern void probe%d(const struct osrec_context *,struct osrec_context *);'%i]
                fixtures+=['{%d,probe%d,spans%d,%d,values%d,%d},'%(a,i,m,len(spans),m,len(values))]
        lines+=['capture:']+save_context()+['mov x0,sp','adrp x1,test_after','ldr x1,[x1,:lo12:test_after]','mov x2,#34',
            '1: ldr x3,[x0],#8','str x3,[x1],#8','subs x2,x2,#1','b.ne 1b','adrp x9,test_host_sp',
            'ldr x9,[x9,:lo12:test_host_sp]','mov sp,x9']
        lines+=['ldp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
        lines+=['add sp,sp,#96','ret','.section .rodata,"a"']
        for m,spans in enumerate(MAPS):
            lines+=['.balign 16','buckets%d:'%m]
            lines+=['.quad 0x%x,0x%x'%row for row in struct.iter_unpack('<2Q',exclusion_buckets(spans))]
            lines+=['.balign 16','excluded%d: .quad %d'%(m,len(spans))]
            lines+=['.quad 0x%x,0x%x'%row for row in sorted(spans)]
        lines+=['.data','.balign 16','exit_status: .quad 0x20026,1','.bss','.balign 16',
            'test_host_sp: .zero 8','test_after: .zero 8','.space 65536','host_stack_end:']
        header+=['static const struct fixture fixtures[]={']+fixtures+['};']
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'test.S').write_text('\n'.join(lines)+'\n');(root/'cases.h').write_text('\n'.join(header)+'\n')
            built=subprocess.run([str(CC),'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                '-ffreestanding','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
                '-I'+str(ROOT/'runtime/el0_flat'),'-I'+str(ROOT/'runtime/el0'),'-I'+str(root),
                '-Wl,-Ttext=0x40200000,-e,_start',str(root/'test.S'),str(ROOT/'tests/el0_user_exclusion_host.c'),
                str(ROOT/'runtime/el0_flat/bytes.c'),'-o',str(root/'test.elf')],capture_output=True)
            self.assertEqual(built.returncode,0,built.stderr.decode())
            result=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                '-accel','tcg','-nodefaults','-display','none','-monitor','none','-serial','none',
                '-semihosting-config','enable=on,target=native','-device','loader,file=%s,cpu-num=0'%(root/'test.elf')],capture_output=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stderr.decode())
        print('%d independent full-context comparisons'%comparisons)


@unittest.skipUnless(os.environ.get('OSREC_EL0_USER_EXCLUSION_IMAGE'),'set user-exclusion image for admission checks')
class FullImage(unittest.TestCase):
    def test_corrupt_lookup_ranges_map_binding_and_missing_metadata_are_rejected(self):
        from el0_hardware_model import prepare
        from kernel_source_verify import Elf
        image=Path(os.environ['OSREC_EL0_USER_EXCLUSION_IMAGE']).resolve();elf=Elf(image/'checkpoint')
        syms={s['name']:s for s in elf.symbols if s['shndx']}
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for label,name,delta,message in (
                    ('table','flat_user_exclusion_buckets',0,'buckets differ'),
                    ('ranges','flat_user_excluded',8,'ranges differ'),
                    ('binding','flat_program',16,'binding differs'),
                    ('metadata',None,0,'mode differs')):
                changed=root/label;changed.mkdir();data=bytearray(elf.data)
                metadata=json.loads((image/'hardware-memory.json').read_text())
                if name:
                    symbol=syms[name];section=elf.sections[symbol['shndx']]
                    data[section['offset']+symbol['value']-section['addr']+delta]^=1
                else:metadata.pop('user_exclusion_buckets')
                (changed/'checkpoint').write_bytes(data)
                raw=(json.dumps(metadata,indent=2)+'\n').encode();(changed/'hardware-memory.json').write_bytes(raw)
                manifest=json.loads((image/'manifest.json').read_text());manifest['hardware_memory_sha256']=hashlib.sha256(raw).hexdigest()
                (changed/'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError,message):prepare(changed,root/(label+'-model'))


if __name__=='__main__':unittest.main()
