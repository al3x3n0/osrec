"""Configurable 32-bit UID/GID fixtures retain native output bit patterns."""
import copy,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from getresuid_capture import credential_values,credential_state,validate_credential_query,PROFILES
from getgroups_capture import output_bytes
from klee_liteos import digest
from run_freestanding_armv7 import require_success

class LiveCredentialIDsTests(unittest.TestCase):
    def test_cli_rejects_invalid_ids(self):
        for value in ('-1,0','4294967296,0','0,0x100000000','0','0,1,2','false,0','0,1.5','0x,1'):
            with self.subTest(value=value):
                p=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--getresgid','--credential-ids',value,'--out',str(ROOT/'build/rejected-ids')],capture_output=True,text=True,timeout=10)
                self.assertEqual(p.returncode,2,p.stdout+p.stderr)
        p=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--credential-ids','0,0','--out',str(ROOT/'build/rejected-ids')],capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,2,p.stdout+p.stderr)

    def test_zero_equal_and_full_width_profiles(self):
        profiles=(('getresuid',[0,0],[0,4,8]),('getresuid',[0xffffffff,0],[0,4,0]),('getresgid',[0x80000000,0xffffffff],[1,3,5]),('getresgid',[0x12345678,0x12345678],[12,12,12]))
        for kind,values,offsets in profiles:
            with self.subTest(kind=kind,values=values),tempfile.TemporaryDirectory() as name:
                stage=Path(name);capture=stage/'capture';output=stage/'image'
                p=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--'+kind,'--credential-ids',','.join(hex(v) for v in values),'--credential-output-offsets',','.join(map(str,offsets)),'--out',str(capture)],capture_output=True,text=True,timeout=240)
                self.assertEqual(p.returncode,0,p.stdout+p.stderr)
                bundle=json.loads((capture/(kind+'-capture.json')).read_text());life=json.loads((capture/'entry-state-lifetimes.json').read_text());calls=validate_credential_query(bundle,life,kind)
                self.assertEqual(bundle['format'],'osrec-live-'+kind+'-v3');self.assertEqual(credential_values(bundle,kind),values)
                expected=bytearray(output_bytes(calls[0]['entry']))
                for i,c in enumerate(calls):
                    self.assertEqual(credential_state(c['entry'],kind)[0],values);self.assertEqual(credential_state(c['exit'],kind)[0],values)
                    self.assertEqual(output_bytes(c['entry']),expected)
                    for j in range(i if i else 3):
                        if i!=j+1:expected[offsets[j]:offsets[j]+4]=values[bool(j)].to_bytes(4,'little')
                    self.assertEqual(output_bytes(c['exit']),expected)
                    self.assertEqual(c['raw'],0 if not i else 0xfffffff2)
                for fault in ('boolean','negative','overflow','string','field_mismatch','scope','legacy_v1','legacy_v2','default_v3','generation'):
                    bad=copy.deepcopy(bundle)
                    if fault in ('boolean','negative','overflow','string'):bad['credential_fixture']['real']={'boolean':False,'negative':-1,'overflow':1<<32,'string':'0'}[fault]
                    elif fault=='field_mismatch':bad['credential_fixture']['real']^=1
                    elif fault=='scope':bad['credential_fixture']['scope']='natural credentials'
                    elif fault.startswith('legacy_'):bad['format']='osrec-live-'+kind+'-'+fault.rsplit('_',1)[1]
                    elif fault=='default_v3':bad['credential_fixture'].update(real=PROFILES[kind]['values'][0],effective=PROFILES[kind]['values'][1])
                    else:bad.pop('entry_state_generation')
                    with self.subTest(capture_fault=fault),self.assertRaises(ValueError):validate_credential_query(bad,life,kind)
                p=subprocess.run([sys.executable,str(ROOT/('tools/export_freestanding_'+kind+'.py')),'--arch','aarch64','--capture',str(capture),'--out',str(output)],capture_output=True,text=True,timeout=90)
                self.assertEqual(p.returncode,0,p.stdout+p.stderr)
                manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations'];require_success(observed)
                self.assertEqual(manifest['format'],'osrec-freestanding-'+kind+'-v3');self.assertEqual(manifest['credential_fixture'],bundle['credential_fixture']);self.assertEqual(manifest['output_offsets'],offsets)
                self.assertTrue(manifest['entry_state_generation']['independent_source_reanalysis']);self.assertTrue(manifest['raw_image_execution_match']);self.assertFalse(manifest['runtime_host_interaction'])
                self.assertEqual((observed['states_restored'],observed['entry_states_checked'],observed['states_verified']),(1,4,4))
                self.assertEqual((observed['user_copy_attempts'],observed['user_copy_bytes']),(9,24))
                if values!=[0x80000000,0xffffffff]:continue
                for fault in ('value','missing','duplicate','malformed'):
                    bad=stage/('bad-'+fault);shutil.copytree(capture,bad);config=bad/'auto-entry-config.h';text=config.read_text()
                    if fault=='value':text=text.replace('OSREC_CREDENTIAL_EFFECTIVE_ID 4294967295U','OSREC_CREDENTIAL_EFFECTIVE_ID 2147483647U')
                    elif fault=='missing':text=text.replace('#define OSREC_CREDENTIAL_EFFECTIVE_ID 4294967295U\n','')
                    elif fault=='duplicate':text+='#define OSREC_CREDENTIAL_EFFECTIVE_ID 4294967295U\n'
                    else:text=text.replace('OSREC_CREDENTIAL_EFFECTIVE_ID 4294967295U','OSREC_CREDENTIAL_EFFECTIVE_ID 0xffffffffU')
                    config.write_text(text);report=json.loads((bad/'report.json').read_text());report['auto_entry_config_sha256']=digest(config.read_bytes());(bad/'report.json').write_text(json.dumps(report));rejected=stage/('rejected-'+fault)
                    p=subprocess.run([sys.executable,str(ROOT/('tools/export_freestanding_'+kind+'.py')),'--arch','aarch64','--capture',str(bad),'--out',str(rejected)],capture_output=True,text=True,timeout=90)
                    self.assertNotEqual(p.returncode,0);self.assertIn('credential configuration differs',p.stderr);self.assertFalse(rejected.exists())
if __name__=='__main__':unittest.main()
