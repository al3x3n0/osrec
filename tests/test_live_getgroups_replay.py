"""Live output capture, independent user observations and host-free target faults."""
import copy,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from getgroups_capture import validate_getgroups,output_bytes
from klee_liteos import digest
from freestanding_elf import prepare_target
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success
LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
class LiveGetGroupsTests(unittest.TestCase):
    def test_argument_profiles_across_group_counts(self):
        for count in (1,2):
            for profile,option in (('short','--getgroups-null-output'),('boundaries','--getgroups-null-boundaries'),('negative-sizes','--getgroups-negative-sizes')):
                with self.subTest(count=count,profile=profile),tempfile.TemporaryDirectory() as name:
                    stage=Path(name);capture=stage/'capture';output=stage/'image'
                    result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--getgroups','--getgroups-group-count',str(count),option,'--out',str(capture)],capture_output=True,text=True,timeout=240)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    bundle=json.loads((capture/'getgroups-capture.json').read_text());life=json.loads((capture/'entry-state-lifetimes.json').read_text())
                    validate_getgroups(bundle,life);self.assertEqual(bundle['format'],'osrec-live-getgroups-v12')
                    middle=count if profile=='boundaries' or (profile=='short' and count==1) else 0xffffffea if profile=='negative-sizes' else 0xfffffff2
                    last=count if profile=='short' else 0xfffffff2
                    self.assertEqual([c['raw'] for c in bundle['calls']],[count,middle,last])
                    sizes=[0,count-1,4] if profile=='short' else [0,0,4] if profile=='boundaries' else [0,-1,-2147483648]
                    self.assertEqual([c['arguments']['size'] for c in bundle['calls']],sizes)
                    for i,c in enumerate(bundle['calls']):
                        self.assertEqual(c['entry']['fields'],c['exit']['fields']);self.assertEqual(len(c['entry']['fields']),6+count)
                        copying=profile=='short' and i==2
                        self.assertEqual(len(c['events']),2 if copying else 0)
                        if copying:
                            data=bytes.fromhex('00000000' if count==1 else '0700000000000000')
                            self.assertEqual(output_bytes(c['exit']),data+output_bytes(c['entry'])[4*count:])
                            self.assertEqual(c['entry']['allocation_attempts'][0]['size'],4*count)
                        else:self.assertEqual(output_bytes(c['entry']),output_bytes(c['exit']))
                    for fault in ('legacy','count','raw','signed','output','allocation'):
                        bad=copy.deepcopy(bundle);c=bad['calls'][1]
                        if fault=='legacy':bad['format']='osrec-live-getgroups-v10'
                        elif fault=='count':bad['group_count']=3
                        elif fault=='raw':
                            c['raw']^=1
                            for key in ('entry','exit'):c[key]['raw']=c['raw']
                        elif fault=='signed':
                            c['arguments']['size']=0xffffffff
                            for key in ('entry','exit'):c[key]['arguments']['size']=0xffffffff
                        elif fault=='output':c['exit']['output_data']='00'*16
                        else:
                            for key in ('entry','exit'):c[key]['allocation_attempts'].append({})
                        with self.subTest(capture_fault=fault),self.assertRaises(ValueError):validate_getgroups(bad,life)
                    result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(capture),'--out',str(output)],capture_output=True,text=True,timeout=60)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations']
                    self.assertEqual(manifest['group_count'],count);self.assertEqual(observed['getgroups_argument_group_count'],count)
                    self.assertTrue(observed[{'short':'getgroups_null_output_replay','boundaries':'getgroups_null_boundaries_replay','negative-sizes':'getgroups_negative_sizes_replay'}[profile]])
                    self.assertTrue(manifest['raw_image_execution_match']);self.assertFalse(manifest['runtime_host_interaction'])
                    expected=int(profile=='short')
                    self.assertEqual((observed['allocations'],observed['releases'],observed['copies'],observed['user_copies'],observed['user_copy_bytes']),(expected,expected,expected,expected,4*count*expected))
                    self.assertEqual((observed['states_restored'],observed['states_verified'],observed['entry_states_checked'],observed['locks'],observed['unlocks']),(1,3,3,3,3))
                    if profile in ('boundaries','negative-sizes'):
                        self.assertTrue(all(observed[k]==0 for k in ('allocation_attempts','allocation_failures','user_copy_failures','address_reuses')))
                    sources=stage/'faults';shutil.copytree(output/'sources',sources)
                    flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
                    image=stage/'fault.elf';body=(sources/'getgroups.c').read_text();adapter=(sources/'entry_adapter.h').read_text()
                    build=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-Wno-sign-compare','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'getgroups.c','-o',image]
                    if profile=='boundaries' or (profile=='short' and count==1):
                        mutated=body.replace('if (size == 0)', 'if (size == 0 && list != NULL)');error=11
                    elif profile=='negative-sizes':
                        mutated=body.replace('else if (list == NULL)', 'else if (list == NULL && size >= groupCount)');error=12
                    else:
                        mutated=body.replace('else if (list == NULL)', 'else if (list == NULL && size >= groupCount)');error=11
                    self.assertNotEqual(mutated,body);(sources/'getgroups.c').write_text(mutated)
                    run(build);audit(image,LLVM);failed,_=observe(image);self.assertEqual(failed['error'],error)
                    with self.assertRaises(ValueError):require_success(failed)
                    (sources/'getgroups.c').write_text(body)
                    (sources/'entry_adapter.h').write_text(adapter.replace('++invocation;return raw;','if(invocation==1) output[0]^=1; ++invocation;return raw;'))
                    run(build);audit(image,LLVM);failed,_=observe(image);self.assertEqual(failed['error'],21)
                    with self.assertRaises(ValueError):require_success(failed)

    def test_copy_prefix_cli_rejects_invalid_contracts(self):
        modes=(['--getgroups-copy-bytes','-1'],['--getgroups-copy-bytes','12'],['--getgroups-copy-bytes','1','--getgroups-copy-outcome','half'],['--getgroups-copy-bytes','1','--getgroups-allocation-failure'],['--getgroups-copy-bytes','1','--getgroups-null-output'],['--getgroups-copy-bytes','1','--getgroups-negative-sizes'])
        for mode in modes:
            with self.subTest(mode=mode):
                result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--getgroups',*mode],capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,2,result.stdout+result.stderr)

    def test_arbitrary_copy_prefix(self):
        for count,copied in ((1,1),(2,7),(3,9),(3,0)):
            with self.subTest(count=count,copied=copied),tempfile.TemporaryDirectory() as name:
                stage=Path(name);capture=stage/'capture';output=stage/'image'
                result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--getgroups','--getgroups-group-count',str(count),'--getgroups-output-size',str(count),'--getgroups-output-offset','1','--getgroups-copy-bytes',str(copied),'--out',str(capture)],capture_output=True,text=True,timeout=240)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                bundle=json.loads((capture/'getgroups-capture.json').read_text());lifetimes=json.loads((capture/'entry-state-lifetimes.json').read_text())
                validate_getgroups(bundle,lifetimes);self.assertEqual(bundle['format'],'osrec-live-getgroups-v11');self.assertEqual(bundle['copy_bytes'],copied)
                call=bundle['calls'][2];before=output_bytes(call['entry']);after=output_bytes(call['exit'])
                groups=bytes.fromhex({1:'00000000',2:'0700000000000000',3:'070000000900000000000000'}[count])
                self.assertEqual(after,before[:1]+groups[:copied]+before[1+copied:]);self.assertEqual(call['raw'],0xfffffff2)
                copy_row=call['entry']['user_copy_attempts'][0]
                self.assertEqual((copy_row['size'],copy_row['bytes_copied'],copy_row['result']),(4*count,copied,4*count-copied))
                for fault in ('legacy','negative','full','boolean','missing','remaining','guard'):
                    bad=copy.deepcopy(bundle);c=bad['calls'][2]
                    if fault=='legacy':bad['format']='osrec-live-getgroups-v10'
                    elif fault=='negative':bad['copy_bytes']=-1
                    elif fault=='full':bad['copy_bytes']=4*count
                    elif fault=='boolean':bad['copy_bytes']=True
                    elif fault=='missing':del bad['copy_bytes']
                    elif fault=='remaining':
                        for key in ('entry','exit'):c[key]['user_copy_attempts'][0]['result']+=1
                    else:
                        data=bytearray(after);data[15]^=1;c['exit']['output_data']=data.hex()
                    with self.subTest(capture_fault=fault),self.assertRaises(ValueError):validate_getgroups(bad,lifetimes)
                result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(capture),'--out',str(output)],capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations']
                self.assertEqual(manifest['copy_bytes'],copied);self.assertTrue(observed['getgroups_copy_prefix_replay']);self.assertEqual(observed['getgroups_copy_prefix_group_count'],count)
                self.assertTrue(manifest['raw_image_execution_match']);self.assertFalse(manifest['runtime_host_interaction'])
                self.assertEqual((observed['allocations'],observed['releases'],observed['user_copy_bytes'],observed['user_copy_failures'],observed['locks'],observed['unlocks']),(1,1,copied,1,3,3))
                bad=stage/'bad';shutil.copytree(capture,bad);config=bad/'auto-entry-config.h'
                config.write_text(config.read_text().replace('#define OSREC_GETGROUPS_COPY_BYTES '+str(copied),'#define OSREC_GETGROUPS_COPY_BYTES '+str((copied+1)%(4*count))))
                report=json.loads((bad/'report.json').read_text());report['auto_entry_config_sha256']=digest(config.read_bytes());(bad/'report.json').write_text(json.dumps(report))
                result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(bad),'--out',str(stage/'rejected')],capture_output=True,text=True,timeout=60)
                self.assertNotEqual(result.returncode,0);self.assertIn('copy prefix provenance differs',result.stderr);self.assertFalse((stage/'rejected').exists())
                if count==3 and copied==9:
                    sources=stage/'faults';shutil.copytree(output/'sources',sources)
                    flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
                    image=stage/'fault.elf';adapter=(sources/'entry_adapter.h').read_text()
                    build=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-Wno-sign-compare','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'getgroups.c','-o',image]
                    for fault in ('stub','overcopy'):
                        replacement='(void)destination;(void)source;' if fault=='stub' else 'for(size_t i=0;i<size;++i) destination[i]=source[i];'
                        mutated=adapter.replace('for(size_t i=0;i<copied;++i) destination[i]=source[i];',replacement)
                        self.assertNotEqual(mutated,adapter);(sources/'entry_adapter.h').write_text(mutated)
                        with self.subTest(target_fault=fault):
                            run(build);audit(image,LLVM);failed,_=observe(image);self.assertEqual(failed['error'],22)
                            with self.assertRaises(ValueError):require_success(failed)

    def test_single_group_dependency_widths(self):
        self.check_group_dependency_widths(1)

    def test_two_group_dependency_widths(self):
        self.check_group_dependency_widths(2)

    def check_group_dependency_widths(self,count):
        for outcome,copied,last in (('success',4*count,count),('none',0,0xfffffff2),('half',2*count,0xfffffff2),('allocation',0,0xfffffff4)):
            with self.subTest(outcome=outcome),tempfile.TemporaryDirectory() as name:
                stage=Path(name);capture=stage/'capture';output=stage/'image'
                mode=['--getgroups-allocation-failure'] if outcome=='allocation' else ['--getgroups-copy-outcome',outcome]
                result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--getgroups','--getgroups-group-count',str(count),'--getgroups-output-size',str(count),'--getgroups-output-offset','4',*mode,'--out',str(capture)],capture_output=True,text=True,timeout=240)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                bundle=json.loads((capture/'getgroups-capture.json').read_text());lifetimes=json.loads((capture/'entry-state-lifetimes.json').read_text())
                validate_getgroups(bundle,lifetimes);self.assertEqual(bundle['group_count'],count)
                if count==2:
                    legacy=copy.deepcopy(bundle);legacy['format']='osrec-live-getgroups-v9'
                    with self.assertRaises(ValueError):validate_getgroups(legacy,lifetimes)
                self.assertEqual([c['arguments']['size'] for c in bundle['calls']],[0,count-1,count]);self.assertEqual([c['raw'] for c in bundle['calls']],[count,count if count==1 else 0xffffffea,last])
                call=bundle['calls'][2];before=output_bytes(call['entry']);after=output_bytes(call['exit'])
                self.assertEqual(after,before[:4]+(bytes(4) if count==1 else bytes.fromhex('0700000000000000'))[:copied]+before[4+copied:])
                self.assertEqual(call['entry']['fields'],call['exit']['fields']);self.assertEqual(len(call['entry']['fields']),6+count)
                self.assertEqual(call['entry']['allocation_attempts'][0]['size'],4*count)
                self.assertEqual(len(call['events']),0 if outcome=='allocation' else 2)
                for fault in ('count','allocation','footprint','copy','output'):
                    bad=copy.deepcopy(bundle);c=bad['calls'][2]
                    if fault=='count':bad['group_count']=3
                    elif fault=='allocation':
                        for key in ('entry','exit'):c[key]['allocation_attempts'][0]['size']=12
                    elif fault=='footprint':
                        for key in ('entry','exit'):c[key]['fields'].append(copy.deepcopy(c[key]['fields'][-1]))
                    elif fault=='copy':
                        for key in ('entry','exit'):c[key]['user_copy_attempts'].append({})
                    else:
                        data=bytearray(after);data[15]^=1;c['exit']['output_data']=data.hex()
                    with self.subTest(capture_fault=fault),self.assertRaises(ValueError):validate_getgroups(bad,lifetimes)
                result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(capture),'--out',str(output)],capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations']
                self.assertEqual(manifest['group_count'],count);self.assertTrue(observed['getgroups_single_group_replay' if count==1 else 'getgroups_two_group_replay']);self.assertTrue(manifest['raw_image_execution_match']);self.assertFalse(manifest['runtime_host_interaction'])
                if count==2 and outcome=='success':
                    result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_setgroups.py'),'--arch','aarch64','--capture',str(capture),'--out',str(stage/'setgroups-image')],capture_output=True,text=True,timeout=60)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    self.assertTrue(json.loads((stage/'setgroups-image/manifest.json').read_text())['raw_image_execution_match'])
                expected=int(outcome!='allocation')
                self.assertEqual((observed['allocations'],observed['releases'],observed['copies'],observed['user_copies'],observed['user_copy_bytes']),(expected,expected,expected,expected,copied))
                self.assertEqual((observed['allocation_attempts'],observed['allocation_failures'],observed['user_copy_failures']),(1,int(outcome=='allocation'),int(outcome in ('none','half'))))
                self.assertEqual((observed['states_restored'],observed['states_verified'],observed['entry_states_checked'],observed['locks'],observed['unlocks']),(1,3,3,3,3))
                if outcome=='half':
                    sources=stage/'faults';shutil.copytree(output/'sources',sources)
                    flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
                    image=stage/'fault.elf';body=(sources/'getgroups.c').read_text();adapter=(sources/'entry_adapter.h').read_text()
                    build=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-Wno-sign-compare','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'getgroups.c','-o',image]
                    for fault,error in (('width',101),('count',10),('stub',22)):
                        b=body;a=adapter
                        if fault=='width':b=b.replace('listSize = groupCount * sizeof(int);','listSize = 3 * sizeof(int);')
                        elif fault=='count':b=b.replace('return groupCount;','return groupCount+1;')
                        else:a=a.replace('for(size_t i=0;i<copied;++i) destination[i]=source[i];','(void)destination;(void)source;')
                        self.assertTrue(b!=body or a!=adapter);(sources/'getgroups.c').write_text(b);(sources/'entry_adapter.h').write_text(a)
                        with self.subTest(target_fault=fault):
                            run(build);audit(image,LLVM);failed,_=observe(image);self.assertEqual(failed['error'],error)
                            with self.assertRaises(ValueError):require_success(failed)
                bad=stage/'bad';shutil.copytree(capture,bad);config=bad/'auto-entry-config.h'
                config.write_text(config.read_text().replace('#define OSREC_GETGROUPS_GROUP_COUNT '+str(count),'#define OSREC_GETGROUPS_GROUP_COUNT 3'))
                report=json.loads((bad/'report.json').read_text());report['auto_entry_config_sha256']=digest(config.read_bytes());(bad/'report.json').write_text(json.dumps(report))
                result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(bad),'--out',str(stage/'rejected')],capture_output=True,text=True,timeout=60)
                self.assertNotEqual(result.returncode,0);self.assertIn('group count provenance differs',result.stderr);self.assertFalse((stage/'rejected').exists())

    def test_interior_output_pointer(self):
        for offset in (1,4):
            with self.subTest(offset=offset),tempfile.TemporaryDirectory() as name:
                stage=Path(name);capture=stage/'capture';output=stage/'image'
                result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--getgroups','--getgroups-output-offset',str(offset),'--out',str(capture)],capture_output=True,text=True,timeout=240)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                bundle=json.loads((capture/'getgroups-capture.json').read_text());lifetimes=json.loads((capture/'entry-state-lifetimes.json').read_text())
                validate_getgroups(bundle,lifetimes);self.assertEqual(bundle['output_offset'],offset)
                call=bundle['calls'][2];before=output_bytes(call['entry']);after=output_bytes(call['exit'])
                self.assertEqual(call['arguments']['list'],{'id':201,'offset':offset,'bytes':16-offset})
                self.assertEqual(after,before[:offset]+bytes.fromhex('070000000900000000000000')+before[offset+12:])
                self.assertEqual(call['entry']['fields'],call['exit']['fields']);self.assertEqual(call['exit']['user_copy_attempts'][0]['destination_offset'],offset)
                for fault in ('offset','range','span','copy_offset','prefix','suffix','identity','alias'):
                    bad=copy.deepcopy(bundle);c=bad['calls'][2]
                    if fault=='offset':bad['output_offset']=0
                    elif fault=='range':bad['output_offset']=5
                    elif fault in ('span','identity'):
                        c['arguments']['list']['bytes' if fault=='span' else 'id']+=1
                        for key in ('entry','exit'):c[key]['arguments']=copy.deepcopy(c['arguments'])
                    elif fault=='copy_offset':
                        for key in ('entry','exit'):c[key]['user_copy_attempts'][0]['destination_offset']=0
                    elif fault=='alias':
                        identity=bad['calls'][0]['entry']['objects'][0]['id'];bad['output_region']['id']=identity
                        for row in bad['calls']:
                            row['arguments']['list']['id']=identity
                            for key in ('entry','exit'):
                                row[key]['arguments']=copy.deepcopy(row['arguments'])
                                for attempt in row[key]['user_copy_attempts']:attempt['destination_id']=identity
                    else:
                        data=bytearray(after);data[0 if fault=='prefix' else 15]^=1;c['exit']['output_data']=data.hex()
                    with self.subTest(capture_fault=fault),self.assertRaises(ValueError):validate_getgroups(bad,lifetimes)
                result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(capture),'--out',str(output)],capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations']
                self.assertEqual(manifest['output_offset'],offset);self.assertFalse(manifest['runtime_host_interaction']);self.assertTrue(manifest['raw_image_execution_match'])
                self.assertEqual((observed['allocations'],observed['releases'],observed['user_copy_bytes'],observed['states_restored']),(1,1,12,1))
                sources=stage/'faults';shutil.copytree(output/'sources',sources)
                flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
                image=stage/'fault.elf';adapter=(sources/'entry_adapter.h').read_text()
                build=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-Wno-sign-compare','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'getgroups.c','-o',image]
                for fault,error in (('pointer',107),('prefix',22),('misplaced_copy',22)):
                    broken=adapter
                    if fault=='pointer':broken=broken.replace('(int *)((unsigned char *)output+call->output_offset)','(int *)output')
                    elif fault=='prefix':broken=broken.replace(' ++usercopies;', ' ((volatile unsigned char *)output)[0]^=1;\n ++usercopies;')
                    else:broken=broken.replace('size_t copied=size-call->copy_result;', 'destination=(volatile unsigned char *)output;size_t copied=size-call->copy_result;')
                    self.assertNotEqual(broken,adapter);(sources/'entry_adapter.h').write_text(broken)
                    with self.subTest(target_fault=fault):
                        run(build);audit(image,LLVM);failed,_=observe(image);self.assertEqual(failed['error'],error)
                        with self.assertRaises(ValueError):require_success(failed)
                bad=stage/'bad';shutil.copytree(capture,bad);config=bad/'auto-entry-config.h'
                config.write_text(config.read_text().replace('#define OSREC_GETGROUPS_OUTPUT_OFFSET '+str(offset),'#define OSREC_GETGROUPS_OUTPUT_OFFSET 0'))
                report=json.loads((bad/'report.json').read_text());report['auto_entry_config_sha256']=digest(config.read_bytes());(bad/'report.json').write_text(json.dumps(report))
                result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(bad),'--out',str(stage/'rejected')],capture_output=True,text=True,timeout=60)
                self.assertNotEqual(result.returncode,0);self.assertIn('output offset provenance differs',result.stderr);self.assertFalse((stage/'rejected').exists())

    def test_declared_output_capacity_boundaries(self):
        for capacity in (3,2147483647):
            with self.subTest(capacity=capacity),tempfile.TemporaryDirectory() as name:
                stage=Path(name);capture=stage/'capture';output=stage/'image'
                result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--getgroups','--getgroups-output-size',str(capacity),'--out',str(capture)],capture_output=True,text=True,timeout=240)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                bundle=json.loads((capture/'getgroups-capture.json').read_text());lifetimes=json.loads((capture/'entry-state-lifetimes.json').read_text())
                validate_getgroups(bundle,lifetimes);self.assertEqual(bundle['output_size'],capacity)
                self.assertEqual([c['arguments']['size'] for c in bundle['calls']],[0,2,capacity])
                self.assertEqual([c['raw'] for c in bundle['calls']],[3,0xffffffea,3])
                call=bundle['calls'][2]
                self.assertEqual(output_bytes(call['exit'])[:12],bytes.fromhex('070000000900000000000000'))
                self.assertEqual(output_bytes(call['entry'])[12:],output_bytes(call['exit'])[12:])
                self.assertEqual(call['entry']['fields'],call['exit']['fields'])
                self.assertEqual(call['entry']['allocation_attempts'][0]['size'],12)
                self.assertEqual(call['exit']['user_copy_attempts'][0]['size'],12)
                for fault in ('size','range','bool','allocation','copy','guard'):
                    bad=copy.deepcopy(bundle);c=bad['calls'][2]
                    if fault=='size':
                        c['arguments']['size']=4 if capacity==3 else 3
                        for key in ('entry','exit'):c[key]['arguments']=copy.deepcopy(c['arguments'])
                    elif fault in ('range','bool'):bad['output_size']=2147483648 if fault=='range' else True
                    elif fault in ('allocation','copy'):
                        for key in ('entry','exit'):c[key]['allocation_attempts' if fault=='allocation' else 'user_copy_attempts'][0]['size']=16
                    else:
                        data=bytearray(output_bytes(c['exit']));data[15]^=1;c['exit']['output_data']=data.hex()
                    with self.subTest(capture_fault=fault),self.assertRaises(ValueError):validate_getgroups(bad,lifetimes)
                result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(capture),'--out',str(output)],capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations']
                self.assertEqual(manifest['declared_output_size'],capacity);self.assertFalse(manifest['runtime_host_interaction']);self.assertTrue(manifest['raw_image_execution_match'])
                self.assertEqual((observed['allocations'],observed['releases'],observed['copies'],observed['user_copies'],observed['user_copy_bytes']),(1,1,1,1,12))
                self.assertEqual((observed['states_restored'],observed['states_verified'],observed['entry_states_checked']),(1,3,3))
                sources=stage/'faults';shutil.copytree(output/'sources',sources)
                flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
                image=stage/'fault.elf';body=(sources/'getgroups.c').read_text()
                broken=body.replace('size < groupCount','size <= groupCount') if capacity==3 else body.replace('listSize = groupCount * sizeof(int);','listSize = size * sizeof(int);')
                self.assertNotEqual(body,broken);(sources/'getgroups.c').write_text(broken)
                run([LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-Wno-sign-compare','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'getgroups.c','-o',image])
                audit(image,LLVM);failed,_=observe(image);self.assertEqual(failed['error'],12 if capacity==3 else 101)
                with self.assertRaises(ValueError):require_success(failed)
                bad=stage/'bad';shutil.copytree(capture,bad);config=bad/'auto-entry-config.h'
                config.write_text(config.read_text().replace('#define OSREC_GETGROUPS_OUTPUT_SIZE '+str(capacity),'#define OSREC_GETGROUPS_OUTPUT_SIZE 4'))
                report=json.loads((bad/'report.json').read_text());report['auto_entry_config_sha256']=digest(config.read_bytes());(bad/'report.json').write_text(json.dumps(report))
                result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(bad),'--out',str(stage/'rejected')],capture_output=True,text=True,timeout=60)
                self.assertNotEqual(result.returncode,0);self.assertIn('output size provenance differs',result.stderr);self.assertFalse((stage/'rejected').exists())

    def test_negative_sizes_and_null_precedence(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture';output=stage/'image'
            result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--getgroups','--getgroups-negative-sizes','--out',str(capture)],capture_output=True,text=True,timeout=240)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            bundle=json.loads((capture/'getgroups-capture.json').read_text());lifetimes=json.loads((capture/'entry-state-lifetimes.json').read_text())
            validate_getgroups(bundle,lifetimes);self.assertEqual(bundle['null_output_profile'],'negative-sizes')
            self.assertEqual([c['arguments']['size'] for c in bundle['calls']],[0,-1,-2147483648])
            self.assertEqual([c['raw'] for c in bundle['calls']],[3,0xffffffea,0xfffffff2])
            self.assertIsNotNone(bundle['calls'][1]['arguments']['list']);self.assertIsNone(bundle['calls'][2]['arguments']['list'])
            for c in bundle['calls']:
                self.assertEqual(c['entry']['fields'],c['exit']['fields']);self.assertEqual(output_bytes(c['entry']),output_bytes(c['exit']))
                self.assertEqual(c['events'],[]);self.assertEqual(c['entry']['lifetime_cursor'],c['exit']['lifetime_cursor'])
                self.assertEqual(c['entry']['allocation_attempts'],[]);self.assertEqual(c['exit']['user_copy_attempts'],[])
            for fault in ('unsigned_size','range','pointer','return','profile','output','state','allocation','copy','cursor'):
                bad=copy.deepcopy(bundle);c=bad['calls'][1 if fault=='unsigned_size' else 2]
                if fault in ('unsigned_size','range','pointer'):
                    c['arguments']['list' if fault=='pointer' else 'size']=copy.deepcopy(bad['output_region']) if fault=='pointer' else 0xffffffff if fault=='unsigned_size' else -2147483649
                    for key in ('entry','exit'):c[key]['arguments']=copy.deepcopy(c['arguments'])
                elif fault=='return':
                    c['raw']=0xffffffea
                    for key in ('entry','exit'):c[key]['raw']=c['raw']
                elif fault=='profile':bad['null_output_profile']='boundaries'
                elif fault=='output':c['exit']['output_data']='00'*16
                elif fault=='state':c['exit']['fields'][1]['data']='01000000'
                elif fault in ('allocation','copy'):
                    for key in ('entry','exit'):c[key]['allocation_attempts' if fault=='allocation' else 'user_copy_attempts'].append({})
                else:c['exit']['lifetime_cursor']-=1
                with self.subTest(capture_fault=fault),self.assertRaises(ValueError):validate_getgroups(bad,lifetimes)
            result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(capture),'--out',str(output)],capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations']
            self.assertEqual(manifest['null_output_profile'],'negative-sizes');self.assertTrue(observed['getgroups_negative_sizes_replay'])
            self.assertTrue(manifest['null_output_case'])
            self.assertFalse(manifest['runtime_host_interaction']);self.assertTrue(manifest['raw_image_execution_match'])
            self.assertEqual((observed['states_restored'],observed['states_verified'],observed['entry_states_checked'],observed['locks'],observed['unlocks']),(1,3,3,3,3))
            self.assertTrue(all(observed[k]==0 for k in ('allocation_attempts','allocation_failures','allocations','releases','copies','user_copies','user_copy_bytes','user_copy_failures','address_reuses')))
            sources=stage/'faults';shutil.copytree(output/'sources',sources)
            flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
            image=stage/'fault.elf';adapter=(sources/'entry_adapter.h').read_text();body=(sources/'getgroups.c').read_text()
            build=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-Wno-sign-compare','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'getgroups.c','-o',image]
            for fault,error in (('signed_compare',101),('size_bits',101),('pointer',12),('short_unlock',21),('null_unlock',22),('state',21),('output',22)):
                a=adapter;b=body
                if fault=='signed_compare':b=b.replace('size < groupCount','(unsigned int)size < (unsigned int)groupCount')
                elif fault=='size_bits':a=a.replace('(int)call->size','(int)(call->size & UINT32_C(0x7fffffff))')
                elif fault=='pointer':a=a.replace('call->list_is_null ? 0 : (int *)((unsigned char *)output+call->output_offset)','(int *)((unsigned char *)output+call->output_offset)')
                elif fault=='short_unlock':b=b.replace('else if (size < groupCount) {\n        SCHEDULER_UNLOCK(intSave);','else if (size < groupCount) {\n        (void)intSave;')
                elif fault=='null_unlock':b=b.replace('else if (list == NULL) {\n        SCHEDULER_UNLOCK(intSave);','else if (list == NULL) {\n        (void)intSave;')
                elif fault=='state':a=a.replace('return process.user;', 'if(invocation==1) credential.user.effGid^=1;return process.user;')
                else:a=a.replace('return process.user;', 'if(invocation==2) output[3]^=1;return process.user;')
                self.assertTrue(a!=adapter or b!=body)
                (sources/'entry_adapter.h').write_text(a);(sources/'getgroups.c').write_text(b)
                with self.subTest(target_fault=fault):
                    run(build);audit(image,LLVM);failed,_=observe(image);self.assertEqual(failed['error'],error)
                    with self.assertRaises(ValueError):require_success(failed)
            bad=stage/'bad';shutil.copytree(capture,bad);config=bad/'auto-entry-config.h'
            config.write_text(config.read_text().replace('#define OSREC_GETGROUPS_NEGATIVE_SIZES 1\n',''))
            report=json.loads((bad/'report.json').read_text());report['auto_entry_config_sha256']=digest(config.read_bytes());(bad/'report.json').write_text(json.dumps(report))
            result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(bad),'--out',str(stage/'rejected')],capture_output=True,text=True,timeout=60)
            self.assertNotEqual(result.returncode,0);self.assertIn('null-output provenance differs',result.stderr);self.assertFalse((stage/'rejected').exists())

    def test_null_count_and_sufficient_size(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture';output=stage/'image'
            result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--getgroups','--getgroups-null-boundaries','--out',str(capture)],capture_output=True,text=True,timeout=240)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            bundle=json.loads((capture/'getgroups-capture.json').read_text());lifetimes=json.loads((capture/'entry-state-lifetimes.json').read_text())
            validate_getgroups(bundle,lifetimes);self.assertEqual(bundle['null_output_profile'],'boundaries')
            self.assertEqual([c['arguments']['size'] for c in bundle['calls']],[0,0,4])
            self.assertEqual([c['raw'] for c in bundle['calls']],[3,3,0xfffffff2])
            for c in bundle['calls']:
                self.assertEqual(c['entry']['fields'],c['exit']['fields']);self.assertEqual(output_bytes(c['entry']),output_bytes(c['exit']))
                self.assertEqual(c['events'],[]);self.assertEqual(c['entry']['lifetime_cursor'],c['exit']['lifetime_cursor'])
                self.assertEqual(c['entry']['allocation_attempts'],[]);self.assertEqual(c['exit']['user_copy_attempts'],[])
            for fault in ('count_return','size','pointer','profile','witness','output','state','allocation','copy','cursor'):
                bad=copy.deepcopy(bundle);c=bad['calls'][1 if fault=='count_return' else 2]
                if fault=='count_return':
                    c['raw']=0xfffffff2
                    for key in ('entry','exit'):c[key]['raw']=c['raw']
                elif fault in ('size','pointer'):
                    c['arguments']['size' if fault=='size' else 'list']=2 if fault=='size' else copy.deepcopy(bad['output_region'])
                    for key in ('entry','exit'):c[key]['arguments']=copy.deepcopy(c['arguments'])
                elif fault=='profile':bad['null_output_profile']='short'
                elif fault=='witness':bad['output_region']['id']+=1
                elif fault=='output':c['exit']['output_data']='00'*16
                elif fault=='state':c['exit']['fields'][1]['data']='01000000'
                elif fault in ('allocation','copy'):
                    for key in ('entry','exit'):c[key]['allocation_attempts' if fault=='allocation' else 'user_copy_attempts'].append({})
                else:c['exit']['lifetime_cursor']-=1
                with self.subTest(capture_fault=fault),self.assertRaises(ValueError):validate_getgroups(bad,lifetimes)
            result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(capture),'--out',str(output)],capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations']
            self.assertEqual(manifest['null_output_profile'],'boundaries');self.assertTrue(observed['getgroups_null_boundaries_replay'])
            self.assertFalse(manifest['runtime_host_interaction']);self.assertTrue(manifest['raw_image_execution_match'])
            self.assertEqual((observed['states_restored'],observed['states_verified'],observed['entry_states_checked'],observed['locks'],observed['unlocks']),(1,3,3,3,3))
            self.assertTrue(all(observed[k]==0 for k in ('allocation_attempts','allocation_failures','allocations','releases','copies','user_copies','user_copy_bytes','user_copy_failures','address_reuses')))
            sources=stage/'faults';shutil.copytree(output/'sources',sources)
            flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
            image=stage/'fault.elf';adapter=(sources/'entry_adapter.h').read_text();body=(sources/'getgroups.c').read_text()
            build=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-Wno-sign-compare','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'getgroups.c','-o',image]
            for fault,error in (('count_return',11),('count_unlock',21),('null_unlock',22),('pointer',101),('allocation',101),('state',21),('output',22)):
                a=adapter;b=body
                if fault=='count_return':b=b.replace('if (size == 0) {','if (size == 0) {\n        if(list == NULL) {SCHEDULER_UNLOCK(intSave);return -EFAULT;}')
                elif fault=='count_unlock':b=b.replace('if (size == 0) {\n        SCHEDULER_UNLOCK(intSave);','if (size == 0) {\n        if(list != NULL) SCHEDULER_UNLOCK(intSave);')
                elif fault=='null_unlock':b=b.replace('else if (list == NULL) {\n        SCHEDULER_UNLOCK(intSave);','else if (list == NULL) {\n        (void)intSave;')
                elif fault=='pointer':a=a.replace('call->list_is_null ? 0 : (int *)((unsigned char *)output+call->output_offset)','(int *)((unsigned char *)output+call->output_offset)')
                elif fault=='allocation':b=b.replace('else if (list == NULL) {','else if (list == NULL) {\n        (void)LOS_MemAlloc(m_aucSysMem1, listSize);')
                elif fault=='state':a=a.replace('return process.user;', 'if(invocation==1) credential.user.effGid^=1;return process.user;')
                else:a=a.replace('return process.user;', 'if(invocation==2) output[3]^=1;return process.user;')
                self.assertTrue(a!=adapter or b!=body)
                (sources/'entry_adapter.h').write_text(a);(sources/'getgroups.c').write_text(b)
                with self.subTest(target_fault=fault):
                    run(build);audit(image,LLVM);failed,_=observe(image);self.assertEqual(failed['error'],error)
                    with self.assertRaises(ValueError):require_success(failed)
            bad=stage/'bad';shutil.copytree(capture,bad);config=bad/'auto-entry-config.h'
            config.write_text(config.read_text().replace('#define OSREC_GETGROUPS_NULL_BOUNDARIES 1\n',''))
            report=json.loads((bad/'report.json').read_text());report['auto_entry_config_sha256']=digest(config.read_bytes());(bad/'report.json').write_text(json.dumps(report))
            result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(bad),'--out',str(stage/'rejected')],capture_output=True,text=True,timeout=60)
            self.assertNotEqual(result.returncode,0);self.assertIn('null-output provenance differs',result.stderr);self.assertFalse((stage/'rejected').exists())

    def test_null_output_precedes_short_buffer(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture';output=stage/'image'
            result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--getgroups','--getgroups-null-output','--out',str(capture)],capture_output=True,text=True,timeout=240)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            bundle=json.loads((capture/'getgroups-capture.json').read_text());lifetimes=json.loads((capture/'entry-state-lifetimes.json').read_text())
            validate_getgroups(bundle,lifetimes);self.assertTrue(bundle['null_output_case'])
            self.assertFalse(bundle['allocation_fault_injected']);self.assertEqual(bundle['copy_outcome'],'success')
            self.assertEqual([c['raw'] for c in bundle['calls']],[3,0xfffffff2,3])
            call=bundle['calls'][1];self.assertIsNone(call['arguments']['list'])
            self.assertEqual(call['entry']['fields'],call['exit']['fields']);self.assertEqual(output_bytes(call['entry']),output_bytes(call['exit']))
            self.assertEqual(call['entry']['allocation_attempts'],[]);self.assertEqual(call['exit']['user_copy_attempts'],[])
            self.assertEqual(call['events'],[]);self.assertEqual(call['entry']['lifetime_cursor'],call['exit']['lifetime_cursor'])
            for fault in ('pointer','witness','return','output','state','allocation','copy','mode','injection'):
                bad=copy.deepcopy(bundle);c=bad['calls'][1]
                if fault=='pointer':
                    c['arguments']['list']=copy.deepcopy(bad['output_region'])
                    for key in ('entry','exit'):c[key]['arguments']=copy.deepcopy(c['arguments'])
                elif fault=='witness':bad['output_region']['id']+=1
                elif fault=='return':
                    c['raw']=0xffffffea
                    for key in ('entry','exit'):c[key]['raw']=c['raw']
                elif fault=='output':c['exit']['output_data']='00'*16
                elif fault=='state':c['exit']['fields'][1]['data']='01000000'
                elif fault in ('allocation','copy'):
                    for key in ('entry','exit'):c[key]['allocation_attempts' if fault=='allocation' else 'user_copy_attempts'].append({})
                elif fault=='mode':bad['null_output_case']=False
                else:bad['allocation_fault_injected']=True
                with self.subTest(capture_fault=fault),self.assertRaises(ValueError):validate_getgroups(bad,lifetimes)
            result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(capture),'--out',str(output)],capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations']
            self.assertTrue(manifest['null_output_case']);self.assertTrue(observed['getgroups_null_output_replay'])
            self.assertFalse(manifest['runtime_host_interaction']);self.assertTrue(manifest['raw_image_execution_match'])
            self.assertEqual((observed['states_restored'],observed['states_verified'],observed['entry_states_checked']),(1,3,3))
            self.assertEqual((observed['locks'],observed['unlocks'],observed['allocation_attempts'],observed['allocation_failures']),(3,3,1,0))
            self.assertEqual((observed['allocations'],observed['releases'],observed['copies'],observed['user_copies'],observed['user_copy_bytes'],observed['user_copy_failures']),(1,1,1,1,12,0))
            sources=stage/'faults';shutil.copytree(output/'sources',sources)
            flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
            image=stage/'fault.elf';adapter=(sources/'entry_adapter.h').read_text();body=(sources/'getgroups.c').read_text()
            build=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-Wno-sign-compare','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'getgroups.c','-o',image]
            for fault,error in (('pointer',11),('precedence',11),('unlock',21),('state',21),('output',21),('allocation',101)):
                a=adapter;b=body
                if fault=='pointer':a=a.replace('call->list_is_null ? 0 : (int *)((unsigned char *)output+call->output_offset)','(int *)((unsigned char *)output+call->output_offset)')
                elif fault=='precedence':b=b.replace('else if (list == NULL)', 'else if (list == NULL && size >= groupCount)')
                elif fault=='unlock':b=b.replace('else if (list == NULL) {\n        SCHEDULER_UNLOCK(intSave);','else if (list == NULL) {\n        (void)intSave;')
                elif fault=='state':a=a.replace('return process.user;', 'if(invocation==1) credential.user.effGid^=1;return process.user;')
                elif fault=='output':a=a.replace('return process.user;', 'if(invocation==1) output[3]^=1;return process.user;')
                else:b=b.replace('else if (list == NULL) {','else if (list == NULL) {\n        (void)LOS_MemAlloc(m_aucSysMem1, listSize);')
                self.assertTrue(a!=adapter or b!=body)
                (sources/'entry_adapter.h').write_text(a);(sources/'getgroups.c').write_text(b)
                with self.subTest(target_fault=fault):
                    run(build);audit(image,LLVM);failed,_=observe(image);self.assertEqual(failed['error'],error)
                    if fault in ('unlock','state','output'):self.assertEqual(failed['actual_calls'][1]['raw_bits'],0xfffffff2)
                    with self.assertRaises(ValueError):require_success(failed)
            bad=stage/'bad';shutil.copytree(capture,bad);config=bad/'auto-entry-config.h'
            config.write_text(config.read_text().replace('#define OSREC_GETGROUPS_NULL_OUTPUT 1\n',''))
            report=json.loads((bad/'report.json').read_text());report['auto_entry_config_sha256']=digest(config.read_bytes());(bad/'report.json').write_text(json.dumps(report))
            result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(bad),'--out',str(stage/'rejected')],capture_output=True,text=True,timeout=60)
            self.assertNotEqual(result.returncode,0);self.assertIn('null-output provenance differs',result.stderr);self.assertFalse((stage/'rejected').exists())

    def test_capture_export_and_output_faults(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture';output=stage/'image'
            result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--getgroups','--out',str(capture)],capture_output=True,text=True,timeout=240)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            bundle=json.loads((capture/'getgroups-capture.json').read_text());lifetimes=json.loads((capture/'entry-state-lifetimes.json').read_text())
            validate_getgroups(bundle,lifetimes)
            self.assertEqual([c['raw'] for c in bundle['calls']],[3,0xffffffea,3])
            self.assertEqual(output_bytes(bundle['calls'][2]['exit'])[:12],bytes.fromhex('070000000900000000000000'))
            self.assertEqual(output_bytes(bundle['calls'][2]['exit'])[12:],output_bytes(bundle['calls'][0]['entry'])[12:])
            for fault in ('return','prefix','suffix','continuity','credentials','allocation','copy','identity','lifetime'):
                bad=copy.deepcopy(bundle);c=bad['calls'][2]
                if fault=='return':c['raw']=0
                elif fault in ('prefix','suffix'):
                    data=bytearray(output_bytes(c['exit']));data[0 if fault=='prefix' else 15]^=1;c['exit']['output_data']=data.hex()
                elif fault=='continuity':c['entry']['output_data']='00'*16
                elif fault=='credentials':c['exit']['fields'][1]['data']='01000000'
                elif fault=='allocation':
                    for k in ('entry','exit'):c[k]['allocation_attempts'].clear()
                elif fault=='copy':
                    for k in ('entry','exit'):c[k]['user_copy_attempts'][0]['size']=16
                elif fault=='identity':
                    c['arguments']['list']['id']=202
                    for k in ('entry','exit'):c[k]['arguments']['list']['id']=202
                else:c['exit']['lifetime_cursor']-=1
                with self.subTest(capture_fault=fault):
                    with self.assertRaises(ValueError):validate_getgroups(bad,lifetimes)
            command=[sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(capture),'--out',str(output)]
            result=subprocess.run(command,capture_output=True,text=True,timeout=60);self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations']
            self.assertFalse(manifest['runtime_host_interaction']);self.assertTrue(manifest['raw_image_execution_match'])
            self.assertEqual((observed['allocations'],observed['releases'],observed['copies'],observed['user_copies'],observed['user_copy_bytes']),(1,1,1,1,12))
            self.assertEqual((observed['states_restored'],observed['entry_states_checked'],observed['states_verified']),(1,3,3))
            self.assertEqual((observed['locks'],observed['unlocks'],observed['live_objects']),(3,3,1))
            sources=stage/'faults';shutil.copytree(output/'sources',sources)
            flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
            image=stage/'fault.elf';adapter=(sources/'entry_adapter.h').read_text();body=(sources/'getgroups.c').read_text()
            build=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-Wno-sign-compare','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'getgroups.c','-o',image]
            for fault,error in (('stub',22),('prefix',22),('suffix',22),('cleanup',22),('credentials',20),('return',10)):
                a=adapter;b=body
                if fault=='stub':a=a.replace('for(size_t i=0;i<copied;++i) destination[i]=source[i];\n ++usercopies;','(void)destination;(void)source;\n ++usercopies;')
                elif fault in ('prefix','suffix'):a=a.replace(' ++usercopies;',f' output[{1 if fault=="prefix" else 3}]^=1;\n ++usercopies;')
                elif fault=='cleanup':b=b.replace('(void)LOS_MemFree(m_aucSysMem1, safeList);','(void)safeList;')
                elif fault=='credentials':a=a.replace('return process.user;', 'credential.user.effGid^=1;return process.user;')
                else:b=b.replace('return groupCount;','return groupCount+1;')
                self.assertTrue(a!=adapter or b!=body)
                (sources/'entry_adapter.h').write_text(a);(sources/'getgroups.c').write_text(b)
                with self.subTest(target_fault=fault):
                    run(build);audit(image,LLVM);failed,_=observe(image);self.assertEqual(failed['error'],error)
                    if fault in ('stub','prefix','suffix','cleanup'):self.assertEqual(failed['actual_calls'][2]['raw_bits'],3)
                    with self.assertRaises(ValueError):require_success(failed)
            # Rehash a corrupted guard byte: semantic validation still blocks publication.
            bad=stage/'bad';shutil.copytree(capture,bad);corrupt=copy.deepcopy(bundle)
            data=bytearray(output_bytes(corrupt['calls'][2]['exit']));data[15]^=1;corrupt['calls'][2]['exit']['output_data']=data.hex()
            (bad/'getgroups-capture.json').write_text(json.dumps(corrupt));report=json.loads((bad/'report.json').read_text())
            report['getgroups_capture']['sha256']=digest((bad/'getgroups-capture.json').read_bytes());(bad/'report.json').write_text(json.dumps(report))
            result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(bad),'--out',str(stage/'rejected')],capture_output=True,text=True,timeout=60)
            self.assertNotEqual(result.returncode,0);self.assertIn('output effect differs',result.stderr);self.assertFalse((stage/'rejected').exists())
    def test_output_copy_failure_modes(self):
        for outcome,copied,capacity,offset in (('none',0,4,0),('half',6,4,0),('none',0,3,4),('half',6,3,1)):
            with self.subTest(outcome=outcome,capacity=capacity,offset=offset),tempfile.TemporaryDirectory() as name:
                stage=Path(name);capture=stage/'capture';output=stage/'image'
                result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--getgroups','--getgroups-copy-outcome',outcome,'--getgroups-output-size',str(capacity),'--getgroups-output-offset',str(offset),'--out',str(capture)],capture_output=True,text=True,timeout=240)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                bundle=json.loads((capture/'getgroups-capture.json').read_text());lifetimes=json.loads((capture/'entry-state-lifetimes.json').read_text())
                validate_getgroups(bundle,lifetimes);self.assertEqual(bundle['copy_outcome'],outcome)
                call=bundle['calls'][2];self.assertEqual(call['raw'],0xfffffff2)
                self.assertEqual(call['entry']['fields'],call['exit']['fields']);self.assertEqual(call['entry']['objects'],call['exit']['objects'])
                self.assertEqual(output_bytes(call['exit'])[offset+copied:],output_bytes(call['entry'])[offset+copied:])
                self.assertEqual(output_bytes(call['exit'])[:offset],output_bytes(call['entry'])[:offset])
                self.assertEqual([e['kind'] for e in call['events']],['allocate','release'])
                for fault in ('prefix','suffix','remaining','copied','mode','cleanup','state'):
                    bad=copy.deepcopy(bundle);c=bad['calls'][2]
                    if fault in ('prefix','suffix'):
                        data=bytearray(output_bytes(c['exit']));data[offset if fault=='prefix' else offset+copied]^=1;c['exit']['output_data']=data.hex()
                    elif fault in ('remaining','copied'):
                        for k in ('entry','exit'):c[k]['user_copy_attempts'][0]['result' if fault=='remaining' else 'bytes_copied']+=1
                    elif fault=='mode':bad['copy_outcome']='success'
                    elif fault=='cleanup':c['exit']['lifetime_cursor']-=1
                    else:c['exit']['fields'][1]['data']='01000000'
                    with self.subTest(capture_fault=fault):
                        with self.assertRaises(ValueError):validate_getgroups(bad,lifetimes)
                result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(capture),'--out',str(output)],capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations']
                self.assertEqual(manifest['copy_outcome'],outcome);self.assertFalse(manifest['runtime_host_interaction']);self.assertTrue(manifest['raw_image_execution_match'])
                self.assertEqual((observed['user_copy_bytes'],observed['user_copy_failures'],observed['allocations'],observed['releases']),(copied,1,1,1))
                self.assertEqual((observed['states_restored'],observed['states_verified'],observed['entry_states_checked']),(1,3,3))
                sources=stage/'faults';shutil.copytree(output/'sources',sources)
                flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
                image=stage/'fault.elf';adapter=(sources/'entry_adapter.h').read_text();body=(sources/'getgroups.c').read_text()
                build=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-Wno-sign-compare','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'getgroups.c','-o',image]
                faults=[('cleanup',22),('return',12),('state',22),('overcopy',22)]
                if copied:faults.append(('stub',22))
                for fault,error in faults:
                    a=adapter;b=body
                    if fault=='cleanup':b=b.replace('(void)LOS_MemFree(m_aucSysMem1, safeList);','(void)safeList;')
                    elif fault=='return':a=a.replace('return call->copy_result;','return 0;')
                    elif fault=='state':a=a.replace(' ++usercopies;', ' credential.user.effGid^=1;\n ++usercopies;')
                    elif fault=='overcopy':a=a.replace('for(size_t i=0;i<copied;++i) destination[i]=source[i];','for(size_t i=0;i<size;++i) destination[i]=source[i];')
                    else:a=a.replace('for(size_t i=0;i<copied;++i) destination[i]=source[i];','(void)destination;(void)source;')
                    self.assertTrue(a!=adapter or b!=body)
                    (sources/'entry_adapter.h').write_text(a);(sources/'getgroups.c').write_text(b)
                    with self.subTest(target_fault=fault):
                        run(build);audit(image,LLVM);failed,_=observe(image);self.assertEqual(failed['error'],error)
                        if fault!='return':self.assertEqual(failed['actual_calls'][2]['raw_bits'],0xfffffff2)
                        with self.assertRaises(ValueError):require_success(failed)
                # Even a rehashed construction header must retain the selected injection mode.
                bad=stage/'bad';shutil.copytree(capture,bad);config=bad/'auto-entry-config.h'
                config.write_text('#define OSREC_AUTOMATED_ENTRY_STATE 1\n#define OSREC_GETGROUPS_CAPTURE 1\n')
                report=json.loads((bad/'report.json').read_text());report['auto_entry_config_sha256']=digest(config.read_bytes());(bad/'report.json').write_text(json.dumps(report))
                result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(bad),'--out',str(stage/'rejected')],capture_output=True,text=True,timeout=60)
                self.assertNotEqual(result.returncode,0);self.assertIn('copy injection provenance differs',result.stderr);self.assertFalse((stage/'rejected').exists())
    def test_allocation_failure_capture_and_replay(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture';output=stage/'image'
            result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--automated-entry-state','--getgroups','--getgroups-allocation-failure','--getgroups-output-size','3','--getgroups-output-offset','4','--out',str(capture)],capture_output=True,text=True,timeout=240)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            bundle=json.loads((capture/'getgroups-capture.json').read_text());lifetimes=json.loads((capture/'entry-state-lifetimes.json').read_text())
            validate_getgroups(bundle,lifetimes);self.assertTrue(bundle['allocation_fault_injected'])
            self.assertEqual([c['raw'] for c in bundle['calls']],[3,0xffffffea,0xfffffff4])
            call=bundle['calls'][2]
            self.assertEqual(call['entry']['objects'],call['exit']['objects']);self.assertEqual(call['entry']['fields'],call['exit']['fields'])
            self.assertEqual(output_bytes(call['entry']),output_bytes(call['exit']))
            self.assertEqual(call['entry']['allocation_attempts'],[{'size':12,'id':0,'reuse':False}])
            self.assertEqual(call['events'],[]);self.assertEqual(call['exit']['user_copy_attempts'],[])
            self.assertEqual(call['entry']['lifetime_cursor'],call['exit']['lifetime_cursor'])
            for fault in ('identity','reuse','copy','output','state','cursor','mode'):
                bad=copy.deepcopy(bundle);c=bad['calls'][2]
                if fault in ('identity','reuse'):
                    for key in ('entry','exit'):c[key]['allocation_attempts'][0]['id' if fault=='identity' else 'reuse']=8 if fault=='identity' else True
                elif fault=='copy':
                    for key in ('entry','exit'):c[key]['user_copy_attempts'].append({'source_id':8,'destination_id':201,'size':12,'result':0,'bytes_copied':12})
                elif fault=='output':c['exit']['output_data']='00'*16
                elif fault=='state':c['exit']['fields'][1]['data']='01000000'
                elif fault=='cursor':c['exit']['lifetime_cursor']-=1
                else:bad['allocation_fault_injected']=False
                with self.subTest(capture_fault=fault):
                    with self.assertRaises(ValueError):validate_getgroups(bad,lifetimes)
            result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(capture),'--out',str(output)],capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations']
            self.assertTrue(manifest['allocation_fault_injected_capture']);self.assertFalse(manifest['runtime_host_interaction']);self.assertTrue(manifest['raw_image_execution_match'])
            self.assertEqual((observed['allocation_attempts'],observed['allocation_failures'],observed['allocations'],observed['releases']),(1,1,0,0))
            self.assertEqual((observed['copies'],observed['user_copies'],observed['user_copy_bytes'],observed['user_copy_failures']),(0,0,0,0))
            self.assertEqual((observed['locks'],observed['unlocks'],observed['live_objects']),(3,3,1))
            self.assertEqual((observed['states_restored'],observed['states_verified'],observed['entry_states_checked']),(1,3,3))
            sources=stage/'faults';shutil.copytree(output/'sources',sources)
            flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
            image=stage/'fault.elf';adapter=(sources/'entry_adapter.h').read_text();body=(sources/'getgroups.c').read_text()
            build=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-Wno-sign-compare','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'getgroups.c','-o',image]
            for fault,error in (('unlock',22),('return',12),('state',22),('output',22),('free',103)):
                a=adapter;b=body
                if fault=='unlock':b=b.replace('if (safeList == NULL) {\n        SCHEDULER_UNLOCK(intSave);','if (safeList == NULL) {\n        (void)intSave;')
                elif fault=='return':b=b.replace('return -ENOMEM;', 'return 3;')
                elif fault=='state':a=a.replace('if(!call->allocation_id) {', 'if(!call->allocation_id) {credential.user.effGid^=1;')
                elif fault=='output':a=a.replace('if(!call->allocation_id) {', 'if(!call->allocation_id) {output[3]^=1;')
                else:b=b.replace('return -ENOMEM;', '(void)LOS_MemFree(m_aucSysMem1, safeList);return -ENOMEM;')
                self.assertTrue(a!=adapter or b!=body)
                (sources/'entry_adapter.h').write_text(a);(sources/'getgroups.c').write_text(b)
                with self.subTest(target_fault=fault):
                    run(build);audit(image,LLVM);failed,_=observe(image);self.assertEqual(failed['error'],error)
                    if fault in ('unlock','state','output'):self.assertEqual(failed['actual_calls'][2]['raw_bits'],0xfffffff4)
                    with self.assertRaises(ValueError):require_success(failed)
            bad=stage/'bad';shutil.copytree(capture,bad);config=bad/'auto-entry-config.h'
            config.write_text('#define OSREC_AUTOMATED_ENTRY_STATE 1\n#define OSREC_GETGROUPS_CAPTURE 1\n')
            report=json.loads((bad/'report.json').read_text());report['auto_entry_config_sha256']=digest(config.read_bytes());(bad/'report.json').write_text(json.dumps(report))
            result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getgroups.py'),'--arch','aarch64','--capture',str(bad),'--out',str(stage/'rejected')],capture_output=True,text=True,timeout=60)
            self.assertNotEqual(result.returncode,0);self.assertIn('allocation injection provenance differs',result.stderr);self.assertFalse((stage/'rejected').exists())
if __name__=='__main__':unittest.main()
