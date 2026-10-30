"""ELF/checkpoint routing without symbols, with original OHOS slices in QEMU."""
import copy
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from import_application_checkpoint import FORMAT, digest, elf_layout, plan, import_checkpoint,verify_package
from build_file_application_fixture import build
from export_application_replay import export as compose
from export_syscall_slices import export
from test_callable_slices import options, LLVM, QEMU
from verify_syscall_slices import verify_matrix
from run_freestanding_armv7 import observe, require_success
from freestanding_armv7 import run, audit
from compile_c_application import compile_application

RAM=[(0x40000000,64*1024*1024)]
RESERVED=[(0x40000000,16*1024*1024),(0x43f00000,65536)]

def minimal():
    raw=bytearray(0x280)
    ident=b'\x7fELF\x02\x01\x01'+bytes(9)
    struct.pack_into('<16sHHIQQQIHHHHHH',raw,0,ident,2,183,1,0x41000000,64,0,0,64,56,2,0,0,0)
    struct.pack_into('<IIQQQQQQ',raw,64,1,5,0x200,0x41000000,0x41000000,16,16,4)
    struct.pack_into('<IIQQQQQQ',raw,120,1,6,0x240,0x41001000,0x41001000,8,128,4)
    struct.pack_into('<4I',raw,0x200,0xd503201f,0xd4000001,0xd65f03c0,0xd503201f)
    cp=dict(format=FORMAT,elf_sha256=digest(raw),frame=dict(sp=0x41001080),calls=[dict(pc=0x41000004),dict(pc=0x41000004)],exit=dict(pc=0x4100000c,original='1f2003d5'),snapshots=[dict(address=0x41001000,data='2a00000000000000')],objects=[dict(address=0x41001000,bytes=8,id=1)])
    return bytes(raw),cp

class ApplicationImportTests(unittest.TestCase):
    def test_c_frontend_named_sites_and_bad_recipes(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);source=root/'app.c'
            source.write_text('#include "osrec_application.h"\nvoid osrec_application_main(void){osrec_app_syscall_prefix(5,0,0,0,0,0,0);osrec_app_syscall_suffix(6,0,0,0,0,0,0);}\n')
            port=ROOT/'integrations/liteos_a/files-slice-port.json';spec=dict(call_sites=['prefix','suffix'])
            cp=compile_application([source],port,root/'compiled',LLVM,spec,calls=2)
            self.assertNotEqual(cp['calls'][0]['pc'],cp['calls'][1]['pc'])
            route=import_checkpoint(root/'compiled/application.elf',root/'compiled/checkpoint.json',root/'routes')
            self.assertEqual(len(route['patches']),3);verify_package(root/'routes')
            for sites in (['prefix'],['prefix','../suffix'],['prefix',True],'prefix'):
                with self.subTest(sites=sites):
                    with self.assertRaisesRegex(ValueError,'call_sites'):compile_application([source],port,root/'bad',LLVM,dict(call_sites=sites),calls=2)

    def test_completed_sites_are_patched_but_not_dispatched(self):
        raw,cp=minimal();raw=bytearray(raw);struct.pack_into('<I',raw,0x200,0xd4000001)
        cp.update(elf_sha256=digest(raw),first_ordinal=1,completed_calls=[dict(pc=0x41000000)],calls=[dict(pc=0x41000004)])
        cp['frame']['pc']=0x41000004
        p=plan(raw,cp,RAM,RESERVED)
        self.assertEqual(len(p['patches']),3);self.assertEqual(len(p['sites']),1)
        self.assertEqual(p['sites'][0]['ordinal'],1);self.assertEqual(p['completed_sites'][0]['ordinal'],0)
        self.assertNotIn(p['completed_sites'][0]['svc_pc'],{s['svc_pc'] for s in p['sites']})
        for value,message in [(None,'history'),([], 'history'),([dict(pc=0x41000008)],'not SVC'),([dict(pc=0x41000001)],'executable'),([dict(pc=0x41002000)],'executable'),([True],'invalid completed')]:
            with self.subTest(value=value):
                bad=copy.deepcopy(cp);bad['completed_calls']=value
                with self.assertRaisesRegex(ValueError,message):plan(raw,bad,RAM,RESERVED)
        missing=copy.deepcopy(cp);del missing['completed_calls']
        with self.assertRaisesRegex(ValueError,'unrouted'):plan(raw,missing,RAM,RESERVED)
        # The same PC may legitimately occur before and after the pause.
        shared=copy.deepcopy(cp);shared['completed_calls'][0]['pc']=0x41000004
        only=bytearray(raw);struct.pack_into('<I',only,0x200,0xd503201f);shared['elf_sha256']=digest(only)
        self.assertEqual(len(plan(only,shared,RAM,RESERVED)['patches']),2)
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/'app.elf').write_bytes(raw);(root/'cp.json').write_text(json.dumps(cp))
            import_checkpoint(root/'app.elf',root/'cp.json',root/'routes',RAM,RESERVED);verify_package(root/'routes')
            metadata=root/'routes/route-plan.json';route=json.loads(metadata.read_text());route['completed_sites'][0]['svc_pc']+=4;metadata.write_text(json.dumps(route))
            with self.assertRaisesRegex(ValueError,'differs'):verify_package(root/'routes')

    def test_sectionless_validation_snapshots_and_repeated_routes(self):
        raw,cp=minimal(); p=plan(raw,cp,RAM,RESERVED)
        self.assertEqual(p['layout']['entry'],0x41000000)
        self.assertEqual(len(p['patches']),2);self.assertEqual(len(p['sites']),2)
        self.assertEqual(p['loads'][1]['data'][:8],struct.pack('<Q',42))
        self.assertEqual(p['loads'][1]['data'][8:],bytes(120))
        self.assertEqual(p['loads'][0]['original'],raw[0x200:0x210])
        def reject(document,pattern):
            with self.assertRaisesRegex(ValueError,pattern):plan(raw,document,RAM,RESERVED)
        bad=copy.deepcopy(cp);bad['elf_sha256']='0'*64;reject(bad,'identity')
        bad=copy.deepcopy(cp);bad['calls'][0]['pc']+=1;reject(bad,'executable')
        bad=copy.deepcopy(cp);bad['calls'][0]['pc']=0x41000000;reject(bad,'not SVC')
        bad=copy.deepcopy(cp);bad['exit']['original']='00000000';reject(bad,'identity')
        bad=copy.deepcopy(cp);bad['frame']['pc']=0x41001000;reject(bad,'saved PC')
        bad=copy.deepcopy(cp);bad['frame']['sp']+=1;reject(bad,'aligned SP')
        bad=copy.deepcopy(cp);bad['frame']['pstate']=5;reject(bad,'EL0t')
        bad=copy.deepcopy(cp);bad['snapshots'].append(dict(address=0x41000000,data='00000000'));reject(bad,'overlaps code')
        bad=copy.deepcopy(cp);bad['snapshots']*=2;reject(bad,'another snapshot')
        bad=copy.deepcopy(cp);bad['objects']*=2;reject(bad,'memory object')
        bad=copy.deepcopy(cp);bad['extra_memory']=[dict(address=0x41001000,bytes=32,permissions=3)];reject(bad,'overlapping')
        bad=copy.deepcopy(cp);bad['assertions']=[dict(address=0xdead,data='00')];reject(bad,'assertion')
        bad=copy.deepcopy(cp);bad['first_ordinal']=2**64-1;reject(bad,'ordinal overflow')
        with self.assertRaisesRegex(ValueError,'RAM'):plan(raw,cp,[(0x42000000,4096)])
        with self.assertRaisesRegex(ValueError,'reserved'):plan(raw,cp,RAM,[(0x41000000,4)])
        mutations=[(16,'<H',3,'ET_EXEC'),(64,'<I',3,'dynamic'),(64+24,'<Q',0x42000000,'nonidentity'),(64+32,'<Q',17,'bounds|nonidentity'),(64+4,'<I',7,'writable executable'),(120+16,'<Q',0x41000000,'nonidentity'),(64+48,'<Q',3,'alignment'),(120+8,'<Q',0x200,'file ranges')]
        for off,fmt,value,message in mutations:
            with self.subTest(offset=off,value=value):
                b=bytearray(raw);struct.pack_into(fmt,b,off,value)
                with self.assertRaisesRegex(ValueError,message):elf_layout(b)
        b=bytearray(raw);struct.pack_into('<QQ',b,120+16,0x41000000,0x41000000)
        with self.assertRaisesRegex(ValueError,'overlapping ELF load'):elf_layout(b)
        for offset,value,message in [(0x208,0xd4000001,'unrouted'),(0x208,0xd4200000,'unreviewed')]:
            b=bytearray(raw);struct.pack_into('<I',b,offset,value);document=copy.deepcopy(cp);document['elf_sha256']=digest(b)
            with self.assertRaisesRegex(ValueError,message):plan(b,document,RAM,RESERVED)
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/'app.elf').write_bytes(raw);(root/'cp.json').write_text(json.dumps(cp))
            result=import_checkpoint(root/'app.elf',root/'cp.json',root/'routes',RAM,RESERVED)
            self.assertEqual((root/'routes/original.elf').read_bytes(),raw)
            patched=(root/'routes/patched.elf').read_bytes()
            differences={i for i,(a,b) in enumerate(zip(raw,patched)) if a!=b}
            self.assertTrue(differences <= set(range(0x204,0x208))|set(range(0x20c,0x210)))
            self.assertFalse(result['runtime_host_interaction'])
            with self.assertRaises(FileExistsError):import_checkpoint(root/'app.elf',root/'cp.json',root/'routes')

    def test_supplied_application_elf_calls_original_file_slices_and_restarts(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name); args=options(stage); export(args)
            document=build(args.out,stage/'fixture',LLVM)
            # Remove the section table entirely: entry and segments are sufficient.
            elf=stage/'fixture/application.elf'; raw=bytearray(elf.read_bytes())
            struct.pack_into('<Q',raw,40,0);struct.pack_into('<HHH',raw,58,0,0,0)
            elf.write_bytes(raw);document['elf_sha256']=digest(raw)
            checkpoint=stage/'fixture/checkpoint.json';checkpoint.write_text(json.dumps(document,indent=2)+'\n')
            routes=stage/'routes';r=import_checkpoint(elf,checkpoint,routes,RAM,RESERVED)
            self.assertEqual(len(r['sites']),32);self.assertEqual(len(r['patches']),2)
            self.assertEqual(sum(bool(s['flags']&1) for s in r['loads']),2)
            a=SimpleNamespace(slices=args.out,application=routes,out=stage/'application-replay',llvm_bin=LLVM,qemu=QEMU,arch='aarch64',entry_address=0x40400000,result_address=0x40380000)
            report=compose(a);self.assertTrue(report['app_checkpoint_loader_integrated'])
            self.assertEqual(report['target_observations']['completed_calls'],64)
            self.assertEqual(report['target_observations']['assertions'],4)
            self.assertFalse(report['runtime_host_interaction'])
            matrix=verify_matrix(a.out,stage/'matrix',qemu=QEMU,llvm_bin=LLVM)
            self.assertEqual(matrix['status'],'verified');self.assertEqual(len(matrix['executions']),4)
            self.assertEqual(matrix['embedded_breakpoints'],2);self.assertEqual(matrix['application_embedded_breakpoints'],2)
            sources=a.out/'sources';driver=sources/'slice_driver.c';original=driver.read_text()
            # A kernel reset alone must not stand in for application restoration.
            driver.write_text(original.replace('osrec_import_restore(&frame);','if(!run)osrec_import_restore(&frame);'))
            bad=stage/'bad.elf'
            flags=[LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-mstrict-align','-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-I'+str(sources)]
            def compile_bad():
                run([*flags,'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',driver,sources/'application_checkpoint.c',a.out/'slices.a','-o',bad]);audit(bad,LLVM)
            compile_bad();observed,_=observe(bad,QEMU);self.assertEqual(observed['status'],3)
            with self.assertRaises(ValueError):require_success(observed)
            driver.write_text(original)
            loader=sources/'application_checkpoint.c';text=loader.read_text()
            # Drop the recorded snapshot byte in the embedded initial image.
            address=r['frame']['sp'];self.assertGreater(address,0)
            load_index=next(i for i,s in enumerate(r['loads']) if s['address']<=document['snapshots'][0]['address']<s['address']+s['memory_bytes'])
            offset=document['snapshots'][0]['address']-r['loads'][load_index]['address']
            needle='out[j]=load_'+str(load_index)+'[j];'
            self.assertIn(needle,text);loader.write_text(text.replace(needle,'out[j]=j=='+str(offset)+' ? 0 : load_'+str(load_index)+'[j];',1))
            compile_bad();observed,_=observe(bad,QEMU);self.assertEqual(observed['status'],3);self.assertEqual(observed['error'],3)
            loader.write_text(text)
            for old,new in [('.executable_count=sizeof(executable)/sizeof(executable[0])','.executable_count=0'),('.executables=executable','.executables=0')]:
                with self.subTest(gateway_validation=new):
                    self.assertIn(old,text);loader.write_text(text.replace(old,new,1))
                    compile_bad();observed,_=observe(bad,QEMU)
                    self.assertEqual(observed['status'],3);self.assertEqual(observed['error'],4)
            loader.write_text(text)
            # Corrupt an actual EL0 return store while retaining a valid route.
            assembly=stage/'fixture/app.S';source=assembly.read_text()
            assembly.write_text(source.replace('str x0,[x23,x19,lsl #3]','str x1,[x23,x19,lsl #3]',1))
            mutant=stage/'mutant.elf'
            run([LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-nostdlib','-static','-fuse-ld=lld','-Wl,-T,'+str(stage/'fixture/app.ld'),assembly,'-o',mutant])
            raw=mutant.read_bytes();document['elf_sha256']=digest(raw)
            checkpoint.write_text(json.dumps(document))
            import_checkpoint(mutant,checkpoint,stage/'mutant-routes',RAM,RESERVED)
            altered=SimpleNamespace(**vars(a));altered.application=stage/'mutant-routes';altered.out=stage/'mutant-replay'
            with self.assertRaisesRegex(ValueError,'diverged'):compose(altered)
            self.assertFalse(altered.out.exists())
            # Published importer evidence is pinned along with the container.
            (a.out/'application/patched.elf').write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError,'identity'):verify_matrix(a.out,stage/'bad-matrix',qemu=QEMU,llvm_bin=LLVM)

if __name__=='__main__':unittest.main()
