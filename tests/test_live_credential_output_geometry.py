"""Native UID/GID aliases and byte overlaps match continuous AArch64 replay."""
import copy,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from getresuid_capture import PROFILES,validate_credential_query,output_offsets
from getgroups_capture import output_bytes
from klee_liteos import digest
from freestanding_elf import prepare_target
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success
LLVM=Path('/opt/homebrew/opt/llvm@16/bin')

class LiveCredentialOutputGeometryTests(unittest.TestCase):
    def test_cli_rejects_invalid_geometry(self):
        for value in ('0,4','0,4,8,12','-1,4,8','0,4,13','0,false,8','0,4,1.5'):
            with self.subTest(value=value):
                p=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--getresgid','--credential-output-offsets',value,'--out',str(ROOT/'build/rejected-geometry')],capture_output=True,text=True,timeout=10)
                self.assertEqual(p.returncode,2,p.stdout+p.stderr)
        p=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--credential-output-offsets','0,0,0','--out',str(ROOT/'build/rejected-geometry')],capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,2,p.stdout+p.stderr)

    def test_alias_overlap_and_boundary_profiles(self):
        profiles=(('getresuid',[0,0,0]),('getresuid',[12,8,4]),('getresgid',[0,4,0]),('getresgid',[1,3,5]),('getresgid',[12,12,12]))
        for kind,offsets in profiles:
            with self.subTest(kind=kind,offsets=offsets),tempfile.TemporaryDirectory() as name:
                stage=Path(name);capture=stage/'capture';output=stage/'image'
                p=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--'+kind,'--credential-output-offsets',','.join(map(str,offsets)),'--out',str(capture)],capture_output=True,text=True,timeout=240)
                self.assertEqual(p.returncode,0,p.stdout+p.stderr)
                bundle=json.loads((capture/(kind+'-capture.json')).read_text());life=json.loads((capture/'entry-state-lifetimes.json').read_text())
                calls=validate_credential_query(bundle,life,kind);self.assertEqual(output_offsets(bundle,kind),offsets)
                self.assertEqual(bundle['format'],'osrec-live-'+kind+'-v2')
                values=PROFILES[kind]['values'];expected=bytearray(output_bytes(calls[0]['entry']))
                for i,c in enumerate(calls):
                    self.assertEqual(output_bytes(c['entry']),expected)
                    for j in range(i if i else 3):
                        if i!=j+1:expected[offsets[j]:offsets[j]+4]=values[bool(j)].to_bytes(4,'little')
                    self.assertEqual(output_bytes(c['exit']),expected)
                    self.assertEqual(len(c['exit']['user_copy_attempts']),i if i else 3)
                for fault in ('boolean','negative','outside','short','legacy','default_v2','missing','arguments','output','continuity','write_after_null'):
                    bad=copy.deepcopy(bundle)
                    if fault in ('boolean','negative','outside'):bad['output_offsets'][0]={'boolean':False,'negative':-1,'outside':13}[fault]
                    elif fault=='short':bad['output_offsets'].pop()
                    elif fault=='legacy':bad['format']='osrec-live-'+kind+'-v1'
                    elif fault=='default_v2':bad['output_offsets']=[0,4,8]
                    elif fault=='missing':bad.pop('output_offsets')
                    elif fault=='arguments':bad['calls'][0]['entry']['arguments'][0]['offset']=(offsets[0]+1)%13
                    elif fault in ('output','continuity'):
                        c=bad['calls'][0 if fault=='output' else 1];key='exit' if fault=='output' else 'entry';data=bytearray(output_bytes(c[key]));data[0]^=1;c[key]['output_data']=data.hex()
                    else:
                        for key in ('entry','exit'):bad['calls'][1][key]['user_copy_attempts'].append({'position':1,'size':4,'value':values[1],'result':0})
                    with self.subTest(capture_fault=fault),self.assertRaises(ValueError):validate_credential_query(bad,life,kind)
                p=subprocess.run([sys.executable,str(ROOT/('tools/export_freestanding_'+kind+'.py')),'--arch','aarch64','--capture',str(capture),'--out',str(output)],capture_output=True,text=True,timeout=60)
                self.assertEqual(p.returncode,0,p.stdout+p.stderr)
                manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations']
                self.assertEqual(manifest['output_offsets'],offsets);self.assertEqual(manifest['format'],'osrec-freestanding-'+kind+'-v2')
                self.assertTrue(manifest['raw_image_execution_match']);self.assertFalse(manifest['runtime_host_interaction'])
                self.assertEqual((observed['states_restored'],observed['entry_states_checked'],observed['states_verified']),(1,4,4))
                self.assertEqual((observed['user_copy_attempts'],observed['user_copy_bytes']),(9,24));require_success(observed)
                if offsets!=[1,3,5]:continue
                # Rehashing a different capture geometry cannot authorize publication.
                bad=stage/'bad';shutil.copytree(capture,bad);config=bad/'auto-entry-config.h'
                config.write_text(config.read_text().replace('#define OSREC_CREDENTIAL_OUTPUT_0 1','#define OSREC_CREDENTIAL_OUTPUT_0 2'))
                report=json.loads((bad/'report.json').read_text());report['auto_entry_config_sha256']=digest(config.read_bytes());(bad/'report.json').write_text(json.dumps(report))
                p=subprocess.run([sys.executable,str(ROOT/('tools/export_freestanding_'+kind+'.py')),'--arch','aarch64','--capture',str(bad),'--out',str(stage/'rejected')],capture_output=True,text=True,timeout=60)
                self.assertNotEqual(p.returncode,0);self.assertIn('output configuration differs',p.stderr);self.assertFalse((stage/'rejected').exists())
                # Wrong byte order, omitted writes, lost geometry and writing after NULL fail on target.
                sources=stage/'faults';shutil.copytree(output/'sources',sources)
                flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
                image=stage/'fault.elf';adapter=(sources/'entry_adapter.h').read_text();header=(sources/'entry_checkpoint.h').read_text();body=(sources/(kind+'.c')).read_text()
                build=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/(kind+'.c'),'-o',image]
                for fault,error in (('endian',20),('skip',20),('geometry',20),('continue',107)):
                    a=adapter;h=header;b=body
                    if fault=='endian':a=a.replace('((const unsigned char *)in)[k]','((const unsigned char *)in)[3-k]')
                    elif fault=='skip':a=a.replace('for(unsigned k=0;k<4;++k) ((volatile unsigned char *)out)[k]=((const unsigned char *)in)[k];','(void)out;(void)in;')
                    elif fault=='geometry':h=h.replace('checkpoint_offsets[3]={UINT32_C(1),UINT32_C(3),UINT32_C(5)}','checkpoint_offsets[3]={UINT32_C(0),UINT32_C(4),UINT32_C(8)}')
                    else:b=b.replace('if (ret != 0)','if (ret < 0)')
                    self.assertTrue(a!=adapter or h!=header or b!=body)
                    (sources/'entry_adapter.h').write_text(a);(sources/'entry_checkpoint.h').write_text(h);(sources/(kind+'.c')).write_text(b)
                    with self.subTest(target_fault=fault):
                        run(build);audit(image,LLVM);failed,_=observe(image);self.assertEqual(failed['error'],error)
                        with self.assertRaises(ValueError):require_success(failed)

if __name__=='__main__':unittest.main()
