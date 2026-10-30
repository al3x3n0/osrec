"""Original getresgid, ordered native NULL failures, and host-free target faults."""
import copy,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from getresuid_capture import validate_getresgid
from getgroups_capture import output_bytes
from klee_liteos import digest
from freestanding_elf import prepare_target
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success
LLVM=Path('/opt/homebrew/opt/llvm@16/bin')

class LiveGetResGIDTests(unittest.TestCase):
    def test_capture_export_and_ordered_faults(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture';output=stage/'image'
            result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--getresgid','--out',str(capture)],capture_output=True,text=True,timeout=240)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            bundle=json.loads((capture/'getresgid-capture.json').read_text());life=json.loads((capture/'entry-state-lifetimes.json').read_text())
            calls=validate_getresgid(bundle,life)
            self.assertEqual([c['raw'] for c in calls],[0,0xfffffff2,0xfffffff2,0xfffffff2])
            self.assertEqual([len(c['exit']['user_copy_attempts']) for c in calls],[3,1,2,3])
            self.assertEqual(output_bytes(calls[0]['exit'])[:12],b''.join(v.to_bytes(4,'little') for v in (7001,7002,7002)))
            for c in calls:
                self.assertEqual(len(c['entry']['fields']),3);self.assertEqual(c['entry']['fields'],c['exit']['fields']);self.assertEqual(c['events'],[])
                self.assertEqual(output_bytes(c['exit'])[12:],output_bytes(c['entry'])[12:])
            for fault in ('saved_value','copy_order','copy_after_failure','return','guard','credential','alias','boolean_pointer','boolean_copy','nested_boolean_pointer','wrong_syscall','lifetime','allocation'):
                bad=copy.deepcopy(bundle);c=bad['calls'][2]
                if fault=='saved_value':
                    for key in ('entry','exit'):bad['calls'][0][key]['user_copy_attempts'][2]['value']=7001
                elif fault=='copy_order':
                    for key in ('entry','exit'):c[key]['user_copy_attempts'].reverse()
                elif fault=='copy_after_failure':
                    for key in ('entry','exit'):c[key]['user_copy_attempts'].append({'position':2,'value':7002,'size':4,'result':0})
                elif fault=='return':
                    c['raw']=0
                    for key in ('entry','exit'):c[key]['raw']=0
                elif fault=='guard':
                    data=bytearray(output_bytes(c['exit']));data[15]^=1;c['exit']['output_data']=data.hex()
                elif fault=='credential':c['exit']['fields'][-1]['data']='00000000'
                elif fault in ('alias','boolean_pointer'):
                    c['arguments'][0]['offset']=4 if fault=='alias' else False
                    for key in ('entry','exit'):c[key]['arguments']=copy.deepcopy(c['arguments'])
                elif fault=='nested_boolean_pointer':c['entry']['arguments'][0]['offset']=False
                elif fault=='wrong_syscall':c['entry']['syscall']=211 if c['entry']['syscall']==209 else 209
                elif fault=='boolean_copy':
                    for key in ('entry','exit'):c[key]['user_copy_attempts'][0]['position']=False
                elif fault=='lifetime':c['exit']['lifetime_cursor']-=1
                else:c['entry']['allocation_attempts']=[]
                with self.subTest(capture_fault=fault),self.assertRaises(ValueError):validate_getresgid(bad,life)
            result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getresgid.py'),'--arch','aarch64','--capture',str(capture),'--out',str(output)],capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations']
            self.assertTrue(manifest['entry_state_generation']['independent_source_reanalysis'])
            self.assertTrue(observed['getresgid_replay']);self.assertTrue(manifest['raw_image_execution_match']);self.assertFalse(manifest['runtime_host_interaction'])
            self.assertEqual((observed['states_restored'],observed['entry_states_checked'],observed['states_verified']),(1,4,4))
            self.assertEqual((observed['user_copy_attempts'],observed['user_copy_bytes'],observed['locks'],observed['unlocks'],observed['credential_accesses']),(9,24,4,4,12))
            # A rehashed discovery plan or generated header must still match fresh source analysis.
            for fault in ('plan','hook','claim'):
                forged=stage/('forged-'+fault);shutil.copytree(capture,forged)
                report=json.loads((forged/'report.json').read_text());plan_path=forged/'entry-state-plan.json';plan=json.loads(plan_path.read_text())
                if fault=='plan':next(p for p in plan['plans'] if p['root']=='SysGetRealEffSaveGroupID')['entry_reads'].pop()
                elif fault=='hook':
                    hook=forged/'entry-state-capture.h';hook.write_text(hook.read_text().replace('sizeof(object_0->user->effGid)','1'))
                    report['automated_capture_hashes']['generated_hooks']=digest(hook.read_bytes());plan['capture_header_sha256']=digest(hook.read_bytes())
                else:
                    report['getresgid_capture'].pop('generated_entry_fields')
                    bundle_path=forged/'getresgid-capture.json';b=json.loads(bundle_path.read_text());b.pop('entry_state_generation');bundle_path.write_text(json.dumps(b));report['getresgid_capture']['sha256']=digest(bundle_path.read_bytes())
                plan_path.write_text(json.dumps(plan));report['automated_capture_hashes']['plan']=digest(plan_path.read_bytes());(forged/'report.json').write_text(json.dumps(report))
                rejected=stage/('rejected-'+fault)
                p=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getresgid.py'),'--arch','aarch64','--capture',str(forged),'--out',str(rejected)],capture_output=True,text=True,timeout=90)
                self.assertNotEqual(p.returncode,0,p.stdout+p.stderr);self.assertIn('generated field',p.stderr);self.assertFalse(rejected.exists())
            bad=stage/'bad';shutil.copytree(capture,bad);config=bad/'auto-entry-config.h'
            config.write_text(config.read_text().replace('#define OSREC_GETRESGID_CAPTURE 1','/* omitted */'))
            report=json.loads((bad/'report.json').read_text());report['auto_entry_config_sha256']=digest(config.read_bytes());(bad/'report.json').write_text(json.dumps(report))
            result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getresgid.py'),'--arch','aarch64','--capture',str(bad),'--out',str(stage/'rejected')],capture_output=True,text=True,timeout=60)
            self.assertNotEqual(result.returncode,0);self.assertIn('capture construction differs',result.stderr);self.assertFalse((stage/'rejected').exists())
            sources=stage/'faults';shutil.copytree(output/'sources',sources)
            flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
            image=stage/'fault.elf';body=(sources/'getresgid.c').read_text();adapter=(sources/'entry_adapter.h').read_text()
            build=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'getresgid.c','-o',image]
            for fault,error in (('saved',105),('continue',107),('false_success',11),('unlock',104),('stub',20),('guard',20),('wrong_pointer',105)):
                b=body;a=adapter
                if fault=='saved':b=b.replace('saveGroupID = OsCurrUserGet()->effGid;','saveGroupID = OsCurrUserGet()->gid;')
                elif fault=='continue':b=b.replace('if (ret != 0)', 'if (ret < 0)')
                elif fault=='false_success':b=b.replace('return -EFAULT;', 'return 0;')
                elif fault=='unlock':b=b.replace('SCHEDULER_UNLOCK(intSave);','(void)intSave;')
                elif fault=='stub':a=a.replace('for(unsigned k=0;k<4;++k) ((volatile unsigned char *)out)[k]=((const unsigned char *)in)[k];','(void)out;(void)in;')
                elif fault=='guard':a=a.replace('osrec_result[28]+=4;return 0;', 'output[3]^=1;osrec_result[28]+=4;return 0;')
                else:a=a.replace('OSREC_QUERY_FUNCTION(args[0],args[1],args[2])','OSREC_QUERY_FUNCTION(args[1],args[0],args[2])')
                self.assertTrue(b!=body or a!=adapter);(sources/'getresgid.c').write_text(b);(sources/'entry_adapter.h').write_text(a)
                with self.subTest(target_fault=fault):
                    run(build);audit(image,LLVM);failed,_=observe(image);self.assertEqual(failed['error'],error)
                    with self.assertRaises(ValueError):require_success(failed)

if __name__=='__main__':unittest.main()
