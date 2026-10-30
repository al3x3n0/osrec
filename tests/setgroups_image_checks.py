"""Live capture export and target faults for the reviewed dynamic adapter."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success
from freestanding_elf import prepare_target
from klee_liteos import digest
from types import SimpleNamespace
from export_freestanding_setgroups import checkpoint_header
LLVM=Path('/opt/homebrew/opt/llvm@16/bin')

def check_images(test,capture,stage):
    output=stage/'setgroups-image'
    command=[sys.executable,str(ROOT/'tools/export_freestanding_setgroups.py'),'--arch','aarch64','--capture',str(capture),'--out',str(output)]
    result=subprocess.run(command,capture_output=True,text=True,timeout=60)
    test.assertEqual(result.returncode,0,result.stdout+result.stderr)
    manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations']
    test.assertFalse(manifest['runtime_host_interaction']);test.assertTrue(manifest['raw_image_execution_match'])
    test.assertTrue(observed['dynamic_object_replay']);test.assertEqual(observed['states_restored'],1)
    test.assertEqual(observed['entry_states_checked'],3);test.assertEqual(observed['states_verified'],3)
    groups=json.loads((capture/'setgroups-capture.json').read_text())
    count=3+sum(c['arguments']['size']!=0 for c in groups['calls'])
    test.assertEqual((observed['allocations'],observed['copies'],observed['releases'],observed['live_objects']),(count,count,count,1))
    test.assertEqual(observed['user_copies'],count-3)
    test.assertEqual(observed['address_reuses'],sum(sum(c['exit'].get('allocation_reuses',[c['exit']['allocation_address_reused']])) for c in groups['calls']))
    # Rebuild only target sources; the native kernel/capture is never available to the guest.
    sources=stage/'setgroups-fault-sources';shutil.copytree(output/'sources',sources)
    flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
    image=stage/'setgroups-fault.elf';original_adapter=(sources/'entry_adapter.h').read_text();original_body=(sources/'setgroups.c').read_text()
    build=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
        '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-Wno-sign-compare','-nostdlib','-static',
        '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'setgroups.c','-o',image]
    for fault,error in (('copy',20),('missing_free',20),('wrong_free',104),('identity',106)):
        with test.subTest(setgroups_target_fault=fault):
            adapter=original_adapter;body=original_body
            if fault=='copy':adapter=adapter.replace('++copies;','((User *)destination)->effGid^=1;++copies;')
            elif fault=='missing_free':body=body.replace('(void)LOS_MemFree(m_aucSysMem1, oldUser);','(void)oldUser;')
            elif fault=='wrong_free':body=body.replace('LOS_MemFree(m_aucSysMem1, oldUser)','LOS_MemFree(m_aucSysMem1, newUser)')
            else:adapter=adapter.replace('ids[i]=event->id;','ids[i]=checkpoint_groups[invocation].before.user;')
            (sources/'entry_adapter.h').write_text(adapter);(sources/'setgroups.c').write_text(body)
            run(build);audit(image,LLVM);failed,_=observe(image)
            test.assertEqual(failed['status'],3);test.assertEqual(failed['error'],error)
            if fault in ('copy','missing_free'):test.assertEqual(failed['actual_calls'][0]['raw_bits'],0)
            with test.assertRaises(ValueError):require_success(failed)
    # Controlled target fixture: nonzero copied fields ensure a copy stub cannot
    # pass merely because the live root credentials happened to contain zeros.
    varied=copy.deepcopy(groups['calls'])
    values={'userID':17,'effUserID':19,'effGid':29}
    for call in varied:
        for key in ('entry','exit'):
            for field in call[key]['fields']:
                if field['kind']=='scalar':
                    value=values.get(field['name'],int.from_bytes(bytes.fromhex(field['data']),'little'))
                    if call['invocation']==0 and key=='entry':
                        if field['name']=='groups[0]':value=31
                    field['data']=value.to_bytes(4,'little').hex()
    (sources/'entry_checkpoint.h').write_text(checkpoint_header(varied))
    (sources/'entry_adapter.h').write_text(original_adapter);(sources/'setgroups.c').write_text(original_body)
    run(build);audit(image,LLVM);result,_=observe(image);require_success(result)
    test.assertEqual(result['completed_calls'],3)
    stub=original_adapter.replace('for(size_t i=0;i<size;++i) out[i]=in[i];','(void)out;(void)in;')
    (sources/'entry_adapter.h').write_text(stub);run(build)
    failed,_=observe(image);test.assertEqual(failed['error'],20)
    test.assertEqual(failed['copies'],1);test.assertEqual(failed['actual_calls'][0]['raw_bits'],0)
    with test.assertRaises(ValueError):require_success(failed)
    if count>3:
        (sources/'entry_checkpoint.h').write_text(checkpoint_header(groups['calls']))
        # A wrong second group still returns zero and must fail the final exit check.
        adapter=original_adapter.replace('uint32_t raw=(uint32_t)SysSetGroups',
            'if(invocation==2) input_objects[2][1]^=1;uint32_t raw=(uint32_t)SysSetGroups')
        (sources/'entry_adapter.h').write_text(adapter);run(build);failed,_=observe(image)
        test.assertEqual(failed['error'],22);test.assertEqual(failed['completed_calls'],2)
        test.assertEqual(failed['actual_calls'][2]['raw_bits'],0)
        with test.assertRaises(ValueError):require_success(failed)
        # Omitting the temporary buffer release leaves an extra live object/event.
        (sources/'entry_adapter.h').write_text(original_adapter)
        (sources/'setgroups.c').write_text(original_body.replace('(void)LOS_MemFree(m_aucSysMem1, safeList);','(void)safeList;'))
        run(build);failed,_=observe(image);test.assertEqual(failed['error'],21)
        test.assertEqual(failed['completed_calls'],1)
        with test.assertRaises(ValueError):require_success(failed)
    # Alter a rehashed allocation transcript: semantic validation must still reject it.
    bad_capture=stage/'setgroups-bad-capture';shutil.copytree(capture,bad_capture)
    events=json.loads((bad_capture/'entry-state-lifetimes.json').read_text())
    next(e for e in events['events'] if e['kind']=='allocate')['size']=28
    (bad_capture/'entry-state-lifetimes.json').write_text(json.dumps(events))
    report=json.loads((bad_capture/'report.json').read_text())
    report['automated_capture_hashes']['lifetimes']=digest((bad_capture/'entry-state-lifetimes.json').read_bytes())
    (bad_capture/'report.json').write_text(json.dumps(report))
    rejected=stage/'setgroups-rejected'
    result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_setgroups.py'),'--arch','aarch64',
        '--capture',str(bad_capture),'--out',str(rejected)],capture_output=True,text=True,timeout=60)
    test.assertNotEqual(result.returncode,0);test.assertFalse(rejected.exists())
    test.assertIn('allocation/release effects differ',result.stderr)

def check_failure_images(test,capture,stage):
    output=stage/'setgroups-failure-image'
    command=[sys.executable,str(ROOT/'tools/export_freestanding_setgroups.py'),'--arch','aarch64','--capture',str(capture),'--out',str(output)]
    result=subprocess.run(command,capture_output=True,text=True,timeout=60)
    test.assertEqual(result.returncode,0,result.stdout+result.stderr)
    manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations']
    test.assertTrue(manifest['fault_injected_capture']);test.assertFalse(manifest['runtime_host_interaction'])
    test.assertEqual([c['raw_bits'] for c in observed['actual_calls']],[0xfffffff4]*3)
    test.assertEqual((observed['allocation_attempts'],observed['allocation_failures'],observed['allocations'],observed['releases']),(4,3,1,1))
    test.assertEqual((observed['copies'],observed['user_copies'],observed['live_objects']),(0,1,1))
    test.assertEqual(observed['states_restored'],1);test.assertEqual(observed['states_verified'],3)
    sources=stage/'setgroups-failure-faults';shutil.copytree(output/'sources',sources)
    flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
    image=stage/'failure-fault.elf';body=(sources/'setgroups.c').read_text();adapter=(sources/'entry_adapter.h').read_text()
    build=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
        '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-Wno-sign-compare','-nostdlib','-static',
        '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'setgroups.c','-o',image]
    for fault,error in (('cleanup',22),('return',10),('state',20)):
        with test.subTest(allocation_failure_fault=fault):
            altered_body=body;altered_adapter=adapter
            if fault=='cleanup':altered_body=body.replace('(void)LOS_MemFree(m_aucSysMem1, safeList);','(void)safeList;')
            elif fault=='return':altered_body=body.replace('return -ENOMEM;','return 0;')
            else:altered_adapter=adapter.replace('if(!attempt->id) {','if(!attempt->id) {process.user->effGid^=1;')
            (sources/'setgroups.c').write_text(altered_body);(sources/'entry_adapter.h').write_text(altered_adapter)
            run(build);audit(image,LLVM);failed,_=observe(image);test.assertEqual(failed['error'],error)
            if fault=='cleanup':test.assertEqual(failed['actual_calls'][2]['raw_bits'],0xfffffff4);test.assertEqual(failed['live_objects'],2)
            with test.assertRaises(ValueError):require_success(failed)
    bad=stage/'failure-bad-capture';shutil.copytree(capture,bad)
    config=bad/'auto-entry-config.h';config.write_text('#define OSREC_AUTOMATED_ENTRY_STATE 1\n')
    result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_setgroups.py'),'--arch','aarch64',
        '--capture',str(bad),'--out',str(stage/'bad-failure-image')],capture_output=True,text=True,timeout=60)
    test.assertNotEqual(result.returncode,0);test.assertIn('configuration differs',result.stderr)
    test.assertFalse((stage/'bad-failure-image').exists())


def check_copy_failure_images(test,capture,stage,partial=False):
    output=stage/'setgroups-copy-failure-image'
    result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_setgroups.py'),'--arch','aarch64',
        '--capture',str(capture),'--out',str(output)],capture_output=True,text=True,timeout=60)
    test.assertEqual(result.returncode,0,result.stdout+result.stderr)
    manifest=json.loads((output/'manifest.json').read_text());observed=manifest['target_observations']
    test.assertEqual(manifest['partial_copy_fault_injected_capture'],partial)
    test.assertEqual(observed['user_copy_bytes'],6 if partial else 0)
    test.assertTrue(manifest['copy_fault_injected_capture']);test.assertFalse(manifest['runtime_host_interaction'])
    test.assertTrue(manifest['raw_image_execution_match'])
    test.assertEqual([c['raw_bits'] for c in observed['actual_calls']],[0,0xfffffff2,0xfffffff2])
    test.assertEqual((observed['allocation_attempts'],observed['allocation_failures'],observed['allocations'],observed['releases']),(3,0,3,3))
    test.assertEqual((observed['copies'],observed['user_copies'],observed['user_copy_failures'],observed['live_objects']),(1,2,2,1))
    test.assertEqual((observed['states_restored'],observed['entry_states_checked'],observed['states_verified']),(1,3,3))
    sources=stage/'copy-failure-faults';shutil.copytree(output/'sources',sources)
    flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
    image=stage/'copy-fault.elf';body=(sources/'setgroups.c').read_text();adapter=(sources/'entry_adapter.h').read_text()
    build=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
        '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-Wno-sign-compare','-nostdlib','-static',
        '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'setgroups.c','-o',image]
    faults=[('cleanup',21),('return',11),('state',21),('copy_success',101)]
    if partial:faults.extend((('omit_prefix',107),('corrupt_prefix',107),('overwrite_suffix',107)))
    for fault,error in faults:
        with test.subTest(copy_failure_fault=fault):
            altered_body=body;altered_adapter=adapter
            if fault=='cleanup':altered_body=body.replace('(void)LOS_MemFree(m_aucSysMem1, safeList);','(void)safeList;')
            elif fault=='return':altered_body=body.replace('ret = -EFAULT;','ret = 0;')
            elif fault=='state':altered_adapter=adapter.replace('if(call->copy_result) {','if(call->copy_result) {process.user->effGid^=1;')
            elif fault=='copy_success':altered_adapter=adapter.replace('return (int)call->copy_result;','return 0;')
            elif fault=='omit_prefix':altered_adapter=adapter.replace('for(size_t i=0;i<copied;++i) destination[i]=source[i];','(void)source;')
            elif fault=='corrupt_prefix':altered_adapter=adapter.replace('if(call->copy_result) {','if(call->copy_result) {destination[0]^=1;')
            else:altered_adapter=adapter.replace('if(call->copy_result) {','if(call->copy_result) {destination[copied]^=1;')
            test.assertTrue(altered_body!=body or altered_adapter!=adapter)
            (sources/'setgroups.c').write_text(altered_body);(sources/'entry_adapter.h').write_text(altered_adapter)
            run(build);audit(image,LLVM);failed,_=observe(image);test.assertEqual(failed['error'],error)
            if fault=='cleanup':test.assertEqual(failed['actual_calls'][1]['raw_bits'],0xfffffff2);test.assertEqual(failed['live_objects'],2)
            with test.assertRaises(ValueError):require_success(failed)
    bad=stage/'copy-bad-capture';shutil.copytree(capture,bad)
    config=bad/'auto-entry-config.h';config.write_text('#define OSREC_AUTOMATED_ENTRY_STATE 1\n')
    result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_setgroups.py'),'--arch','aarch64',
        '--capture',str(bad),'--out',str(stage/'bad-copy-image')],capture_output=True,text=True,timeout=60)
    test.assertNotEqual(result.returncode,0);test.assertIn('configuration differs',result.stderr)
    test.assertFalse((stage/'bad-copy-image').exists())
