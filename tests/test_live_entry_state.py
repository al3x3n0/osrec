"""Boot generated entry-state hooks and compare discovered state to live captures."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil
from types import SimpleNamespace
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from automated_entry_state import validate_snapshot,effect_plan
from entry_state_lifetimes import validate_lifetimes
from setgroups_capture import validate_setgroups
from klee_liteos import digest
from freestanding_elf import prepare_target
from freestanding_armv7 import run
from run_freestanding_armv7 import observe,require_success
class LiveEntryStateTests(unittest.TestCase):
    def test_allocation_failure_capture_and_replay(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);out=stage/'capture'
            result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),
                '--automated-entry-state','--setgroups-allocation-failures','--out',str(out)],capture_output=True,text=True,timeout=240)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            groups=json.loads((out/'setgroups-capture.json').read_text());events=json.loads((out/'entry-state-lifetimes.json').read_text())
            validate_setgroups(groups,events);self.assertTrue(groups['fault_injected'])
            self.assertEqual([c['raw'] for c in groups['calls']],[0xfffffff4]*3)
            for call in groups['calls']:
                self.assertEqual(call['entry']['objects'],call['exit']['objects'])
                self.assertEqual(call['entry']['fields'],call['exit']['fields'])
            import copy
            for corruption in ('outcome','state','cleanup'):
                bad=copy.deepcopy(groups)
                if corruption=='outcome':bad['calls'][0]['exit']['allocation_attempts'][0]['id']=8
                elif corruption=='state':bad['calls'][0]['exit']['fields'][1]['data']='01000000'
                else:bad['calls'][2]['exit']['lifetime_cursor']-=1
                with self.subTest(allocation_failure_corruption=corruption):
                    with self.assertRaises(ValueError):validate_setgroups(bad,events)
            from setgroups_image_checks import check_failure_images
            check_failure_images(self,out,stage)

    def test_copy_failure_capture_and_replay(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);out=stage/'capture'
            result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),
                '--automated-entry-state','--setgroups-copy-failures','--out',str(out)],capture_output=True,text=True,timeout=240)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            groups=json.loads((out/'setgroups-capture.json').read_text());events=json.loads((out/'entry-state-lifetimes.json').read_text())
            validate_setgroups(groups,events);self.assertTrue(groups['copy_fault_injected'])
            self.assertEqual([c['raw'] for c in groups['calls']],[0,0xfffffff2,0xfffffff2])
            for call in groups['calls'][1:]:
                self.assertEqual(call['entry']['objects'],call['exit']['objects'])
                self.assertEqual(call['entry']['fields'],call['exit']['fields'])
            import copy
            for corruption in ('result','destination','source','partial','missing','allocation','cleanup','state','provenance'):
                bad=copy.deepcopy(groups);call=bad['calls'][1]
                for key in ('entry','exit'):
                    rows=call[key]['user_copy_attempts']
                    if corruption=='result':rows[0]['result']=0
                    elif corruption=='destination':rows[0]['destination_id']+=1
                    elif corruption=='source':rows[0]['source_id']+=1
                    elif corruption=='partial':rows[0]['bytes_copied']=1
                    elif corruption=='missing':rows.clear()
                    elif corruption=='allocation':call[key]['allocation_attempts'][0]['id']=0
                if corruption=='cleanup':call['exit']['lifetime_cursor']-=1
                elif corruption=='state':call['exit']['fields'][1]['data']='01000000'
                elif corruption=='provenance':bad['copy_fault_injected']=False
                with self.subTest(copy_failure_corruption=corruption):
                    with self.assertRaises(ValueError):validate_setgroups(bad,events)
            from setgroups_image_checks import check_copy_failure_images
            check_copy_failure_images(self,out,stage)

    def test_partial_copy_capture_and_replay(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);out=stage/'capture'
            result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),
                '--automated-entry-state','--setgroups-partial-copy-failures','--out',str(out)],capture_output=True,text=True,timeout=240)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            groups=json.loads((out/'setgroups-capture.json').read_text());events=json.loads((out/'entry-state-lifetimes.json').read_text())
            validate_setgroups(groups,events);self.assertTrue(groups['partial_copy_fault_injected'])
            self.assertEqual([c['raw'] for c in groups['calls']],[0,0xfffffff2,0xfffffff2])
            for call in groups['calls'][1:]:
                self.assertEqual(call['entry']['objects'],call['exit']['objects'])
                self.assertEqual(call['entry']['fields'],call['exit']['fields'])
                row=call['exit']['user_copy_attempts'][0]
                self.assertEqual(row['bytes_copied'],2*call['arguments']['size'])
                self.assertEqual(row['result'],row['bytes_copied'])
                self.assertEqual(row['destination_data'],call['arguments']['list']['data'][:2*row['bytes_copied']])
                self.assertIs(row['suffix_unchanged'],True)
            import copy
            for corruption in ('result','bytes','data','suffix','mode'):
                bad=copy.deepcopy(groups)
                for key in ('entry','exit'):
                    row=bad['calls'][2][key]['user_copy_attempts'][0]
                    if corruption=='result':row['result']=0
                    elif corruption=='bytes':row['bytes_copied']+=1
                    elif corruption=='data':row['destination_data']='08000000'
                    elif corruption=='suffix':row['suffix_unchanged']=False
                if corruption=='mode':bad['partial_copy_fault_injected']=False
                with self.subTest(partial_copy_corruption=corruption):
                    with self.assertRaises(ValueError):validate_setgroups(bad,events)
            from setgroups_image_checks import check_copy_failure_images
            check_copy_failure_images(self,out,stage,partial=True)

    def test_generated_snapshots_match_actual_syscalls(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);out=stage/'capture'
            result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),
                '--automated-entry-state','--out',str(out)],capture_output=True,text=True,timeout=240)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            report=json.loads((out/'report.json').read_text());self.assertTrue(report['automated_entry_state'])
            plans={row['root']:row for row in json.loads((out/'entry-state-plan.json').read_text())['plans']}
            frames=json.loads((out/'entry-state-snapshots.json').read_text())['snapshots']
            roots={60:'SysUmask',64:'SysGetPPID',224:'SysGetTid',201:'SysGetEffUserID',202:'SysGetEffGID'}
            self.assertEqual(len(frames),14)
            effects=json.loads((out/'entry-state-effects.json').read_text())['snapshots']
            self.assertEqual(len(effects),6)
            lifetimes=json.loads((out/'entry-state-lifetimes.json').read_text())
            validate_lifetimes(lifetimes,frames+effects)
            self.assertTrue(lifetimes['events'])
            self.assertEqual(sum(e['kind']=='allocate' for e in lifetimes['events']),5)
            self.assertEqual(sum(e['kind']=='release' for e in lifetimes['events']),5)
            self.assertTrue(report['automated_session_identity']['allocation_reuse_tracking'])
            self.assertEqual(report['automated_session_identity']['allocation_reuse_scope'],[206])
            groups=json.loads((out/'setgroups-capture.json').read_text())
            validate_setgroups(groups,lifetimes)
            self.assertEqual([c['arguments']['size'] for c in groups['calls']],[0,1,2])
            last={f['name']:int.from_bytes(bytes.fromhex(f['data']),'little') for f in groups['calls'][-1]['exit']['fields'] if f['kind']=='scalar'}
            self.assertEqual([last[f'groups[{i}]'] for i in range(3)],[7,9,0])
            self.assertFalse(groups['dynamic_object_replay'])
            self.assertEqual(report['setgroups_capture']['sha256'],digest((out/'setgroups-capture.json').read_bytes()))
            for call in groups['calls']:
                self.assertIs(type(call['exit']['allocation_address_reused']),bool)
            # The earlier credential capture remains bound to the retired object.
            old=next(f['objects'][0]['session_id'] for f in frames if f['syscall']==201)
            self.assertIn(old,{e['id'] for e in lifetimes['events'] if e['kind']=='release'})
            import copy
            for change in ('retired','size','copy','edge','missing','order','input_width','input_offset','input_address','input_bytes'):
                bad=copy.deepcopy(groups);events=copy.deepcopy(lifetimes)
                if change=='retired':bad['calls'][0]['exit']['objects'][1]['session_id']=old
                elif change=='size':events['events'][2]['size']=28
                elif change=='copy':bad['calls'][0]['exit']['fields'][1]['data']='01000000'
                elif change=='edge':bad['calls'][0]['exit']['fields'][0]['target_id']=1
                elif change=='missing':bad['calls'][0]['exit']['fields'].pop()
                elif change=='order':events['events'][2],events['events'][3]=events['events'][3],events['events'][2]
                elif change=='input_width':bad['calls'][2]['arguments']['list']['bytes']=4
                elif change=='input_offset':bad['calls'][2]['arguments']['list']['offset']=4
                elif change=='input_address':bad['calls'][2]['arguments']['list']['address']=123
                else:bad['calls'][2]['arguments']['list']['data']='0800000009000000'
                with self.subTest(setgroups_corruption=change):
                    with self.assertRaises(ValueError):validate_setgroups(bad,events)
            from setgroups_image_checks import check_images
            check_images(self,out,stage)
            for frame in effects:
                validate_snapshot(frame,effect_plan(plans['SysUmask']))
                self.assertEqual(int.from_bytes(bytes.fromhex(frame['fields'][0]['data']),'little'),report['umask_replay']['calls'][frame['invocation']]['mask_after'])
            masks=report['umask_replay']['calls']
            task_state=report['task_checkpoint']['checkpoint']['objects']
            for frame in frames:
                validate_snapshot(frame,plans[roots[frame['syscall']]])
                scalars={f['name']:int.from_bytes(bytes.fromhex(f['data']),'little') for f in frame['fields'] if f['kind']=='scalar'}
                if frame['syscall']==60:self.assertEqual(scalars['umask'],masks[frame['invocation']]['mask_before'])
                if frame['syscall']==201:self.assertEqual(scalars['effUserID'],0)
                if frame['syscall']==202:self.assertEqual(scalars['effGid'],0)
                if frame['syscall']==64:
                    self.assertEqual(scalars['processID'],task_state[1]['process_id'])
                    self.assertEqual(frame['fields'][0]['kind'],'edge');self.assertEqual(frame['fields'][0]['target_id'],2)
                if frame['syscall']==224:self.assertEqual(scalars['taskID'],task_state[2]['task_id'])
                self.assertFalse(any('address' in row for row in frame['objects']))
            self.assertFalse(plans['SysGetProcessPriority']['entry_reads'])
            self.assertEqual({r['path'] for r in plans['SysGetPPID']['entry_reads']},
                {'OsCurrProcessGet()->parentProcess','OsCurrProcessGet()->parentProcess->processID'})
            # The existing AArch64 delivery remains functional with generated capture enabled.
            subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_task.py'),
                '--automated-entry-state','--capture',str(out),'--out',str(stage/'image')],check=True,capture_output=True,text=True,timeout=60)
            image=json.loads((stage/'image/manifest.json').read_text())
            self.assertFalse(image['runtime_host_interaction']);self.assertEqual(image['target']['isa'],'AArch64')
            self.assertEqual(image['entry_state_reconstruction'],'generated normalized snapshots')
            self.assertEqual(image['target_observations']['current_pid'],0)
            self.assertEqual(image['target_observations']['parent_pid'],1)
            subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_credentials.py'),
                '--automated-entry-state','--capture',str(out),'--out',str(stage/'credentials')],check=True,capture_output=True,text=True,timeout=60)
            credentials=json.loads((stage/'credentials/manifest.json').read_text())
            self.assertEqual(credentials['entry_state_reconstruction'],'generated normalized snapshots')
            self.assertFalse(credentials['runtime_host_interaction'])
            self.assertEqual(credentials['target_observations']['current_pid'],0)
            self.assertEqual(credentials['target_observations']['locks'],4)
            self.assertEqual(credentials['target_observations']['unlocks'],4)
            self.assertEqual(credentials['target_observations']['lock_depth'],0)
            command=[sys.executable,str(ROOT/'tools/export_freestanding_umask.py'),'--automated-entry-state','--capture',str(out)]
            subprocess.run([*command,'--out',str(stage/'umask')],check=True,capture_output=True,text=True,timeout=60)
            umask=json.loads((stage/'umask/manifest.json').read_text())
            self.assertFalse(umask['runtime_host_interaction']);self.assertTrue(umask['target_observations']['write_effects'])
            self.assertEqual(umask['target_observations']['states_verified'],6)
            subprocess.run([*command,'--continuous','--out',str(stage/'umask-continuous')],check=True,capture_output=True,text=True,timeout=60)
            continuous=json.loads((stage/'umask-continuous/manifest.json').read_text())
            self.assertTrue(continuous['state_continuity_reproduced'])
            self.assertEqual(continuous['target_observations']['states_restored'],1)
            self.assertEqual(continuous['target_observations']['entry_states_checked'],6)
            self.assertEqual(continuous['target_observations']['states_verified'],6)
            # Inject a change after the first exit check. The next entry must
            # fail on target instead of restoring the recorded mask over it.
            sources=stage/'fault-sources';shutil.copytree(stage/'umask-continuous/sources',sources)
            driver=sources/'entry_state_replay.c'
            driver.write_text(driver.read_text().replace('++osrec_result[7];osrec_result[4]=i+1;',
                '++osrec_result[7];osrec_result[4]=i+1; if(i==0) osrec_bound_OsCurrProcessGet->umask^=1;'))
            flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=continuous['target']['entry'],result_address=continuous['target']['result_address']),sources)
            llvm=Path('/opt/homebrew/opt/llvm@16/bin');fault_image=stage/'bad-transition.elf'
            run([llvm/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
                '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',driver,sources/'umask.c','-o',fault_image])
            fault,_=observe(fault_image,'qemu-system-aarch64')
            self.assertEqual(fault['error'],41);self.assertEqual(fault['completed_calls'],1)
            self.assertEqual(fault['states_restored'],1);self.assertEqual(fault['entry_states_checked'],1)
            with self.assertRaises(ValueError):require_success(fault)
            # A separately normalized next entry must not be assigned over an
            # incompatible prior post-state even when both hashes are updated.
            incoming=out/'entry-state-snapshots.json';original=incoming.read_bytes()
            bundle=json.loads(original)
            masks=[f for f in bundle['snapshots'] if f['syscall']==60]
            masks[1]['fields'][0]['data']='01000000'
            incoming.write_text(json.dumps(bundle))
            report['automated_capture_hashes']['snapshots']=digest(incoming.read_bytes())
            (out/'report.json').write_text(json.dumps(report))
            failed=subprocess.run([*command,'--continuous','--out',str(stage/'bad-transition')],capture_output=True,text=True,timeout=60)
            self.assertNotEqual(failed.returncode,0);self.assertIn('previous post-state',failed.stderr)
            self.assertFalse((stage/'bad-transition').exists())
            incoming.write_bytes(original);report['automated_capture_hashes']['snapshots']=digest(original)
            lifetime=report.pop('automated_session_identity')
            (out/'report.json').write_text(json.dumps(report))
            failed=subprocess.run([*command,'--continuous','--out',str(stage/'bad-lifetime')],capture_output=True,text=True,timeout=60)
            self.assertNotEqual(failed.returncode,0);self.assertIn('stable-lifetime capture contract',failed.stderr)
            self.assertFalse((stage/'bad-lifetime').exists())
            report['automated_session_identity']=lifetime
            # Preserve provenance hashes while corrupting an observed effect:
            # execution must catch disagreement and publish no image.
            path=out/'entry-state-effects.json';bundle=json.loads(path.read_text())
            bundle['snapshots'][0]['fields'][0]['data']='01000000'
            path.write_text(json.dumps(bundle))
            report['automated_capture_hashes']['effects']=digest(path.read_bytes())
            (out/'report.json').write_text(json.dumps(report))
            failed=subprocess.run([*command,'--out',str(stage/'bad-effects')],capture_output=True,text=True,timeout=60)
            self.assertNotEqual(failed.returncode,0);self.assertIn('target replay diverged',failed.stderr)
            self.assertFalse((stage/'bad-effects').exists())
if __name__=='__main__':unittest.main()
