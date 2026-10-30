"""Task policy callback, invalid bounds, unused task and foreign-task permissions."""
import json,shutil,struct,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from live_getscheduler_replay import decode_task_getscheduler,verify_task_config
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success
LLVM=Path('/opt/homebrew/opt/llvm@16/bin')

class LiveGetSchedulerTaskTests(unittest.TestCase):
    def test_canonical_capture_config(self):
        config='#define OSREC_GETSCHEDULER_CAPTURE 1\n#define OSREC_GETSCHEDULER_TASK_CAPTURE 1\n'
        verify_task_config(config)
        for fault in ('missing','duplicate','malformed','undef','alias'):
            if fault=='missing':bad=config.replace('#define OSREC_GETSCHEDULER_TASK_CAPTURE 1\n','')
            elif fault=='duplicate':bad=config+'#define OSREC_GETSCHEDULER_TASK_CAPTURE 1\n'
            elif fault=='malformed':bad=config.replace('TASK_CAPTURE 1','TASK_CAPTURE 1junk')
            elif fault=='undef':bad=config+'#undef OSREC_GETSCHEDULER_TASK_CAPTURE\n'
            else:bad=config.replace('TASK_CAPTURE 1','TASK_CAPTURE true')
            with self.subTest(config_fault=fault),self.assertRaises(ValueError):verify_task_config(bad)

    def test_capture_export_and_typed_callback_faults(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture';output=stage/'image'
            result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--getscheduler-task','--out',str(capture)],capture_output=True,text=True,timeout=240)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            user=(capture/'getscheduler-user-observations.bin').read_bytes();deps=(capture/'getscheduler-dependencies.bin').read_bytes()
            checkpoint=decode_task_getscheduler(user,deps)
            self.assertEqual([c['raw_bits'] for c in checkpoint['calls']],[2,0xffffffea,0xffffffea,0xffffffff])
            self.assertEqual(sum(e['kind']==5 for e in checkpoint['dependency_transcript']),1)
            self.assertEqual(json.loads((capture/'report.json').read_text())['getscheduler_capture']['flag'],-1)
            for fault in ('missing','extra','identity','order','limit','permission','callback','written','policy','flag','mode','return','task_id'):
                a=bytearray(user);b=bytearray(deps)
                if fault=='missing':b=b[:-24]
                elif fault=='extra':b+=b[-24:]
                elif fault=='identity':struct.pack_into('<I',b,24+8,6 if checkpoint['calls'][0]['id_bits']!=6 else 7)
                elif fault=='order':b[24:48],b[48:72]=b[48:72],b[24:48]
                elif fault=='limit':struct.pack_into('<I',b,12,129)
                elif fault=='permission':struct.pack_into('<I',b,120+12,0)
                elif fault=='callback':struct.pack_into('<I',b,48+12,1)
                elif fault=='written':struct.pack_into('<I',b,48+20,0)
                elif fault=='policy':struct.pack_into('<I',b,48+16,65536)
                elif fault=='flag':struct.pack_into('<I',a,4,0)
                elif fault=='mode':struct.pack_into('<I',a,12,19)
                elif fault=='return':struct.pack_into('<I',a,8,0)
                else:struct.pack_into('<I',a,0,128)
                with self.subTest(capture_fault=fault),self.assertRaises(ValueError):decode_task_getscheduler(a,b)
            metadata_path=capture/'getscheduler-checkpoint.manifest.json';original=metadata_path.read_text();metadata=json.loads(original)
            # Boolean aliases in JSON must not pass numeric equality checks.
            metadata['checkpoint']['dependency_transcript'][0]['policy_written']=False
            metadata_path.write_text(json.dumps(metadata))
            command=[sys.executable,str(ROOT/'tools/export_freestanding_getscheduler.py'),'--capture',str(capture),'--out',str(output)]
            result=subprocess.run(command,capture_output=True,text=True,timeout=60)
            self.assertNotEqual(result.returncode,0);self.assertFalse(output.exists())
            metadata_path.write_text(original)
            result=subprocess.run(command,capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            manifest=json.loads((output/'manifest.json').read_text());obs=manifest['target_observations']
            self.assertTrue(manifest['raw_image_execution_match']);self.assertFalse(manifest['runtime_host_interaction']);self.assertTrue(manifest['task_mode_supported']);self.assertFalse(manifest['process_mode_supported'])
            self.assertEqual((obs['abi_version'],obs['bounds_checks'],obs['task_lookups'],obs['permission_checks'],obs['policy_callbacks'],obs['locks'],obs['unlocks'],obs['lock_depth']),(10,4,3,3,1,3,3,0))
            self.assertEqual([c['dependencies_consumed'] for c in obs['actual_calls']],[3,4,6,8]);require_success(obs)
            sources=stage/'fault-sources';shutil.copytree(output/'sources',sources)
            body=(sources/'getscheduler_syscalls.c').read_text();adapter=(sources/'getscheduler_replay.c').read_text()
            image=stage/'fault.elf'
            build=[LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'getscheduler_replay.c',sources/'getscheduler_syscalls.c','-o',image]
            for fault,error in (('permission_sign',12),('bypass_permission',106),('skip_callback',10),('wrong_policy',10),('skip_unlock',108),('wrong_task',105),('process_mode',107),('lost_lock',103),('stub',4)):
                b=body;a=adapter
                if fault=='permission_sign':b=b.replace('return -ret;', 'return ret;')
                elif fault=='bypass_permission':b=b.replace('ret = OsUserTaskOperatePermissionsCheck(taskCB);', 'ret = 0;')
                elif fault=='skip_callback':b=b.replace('taskCB->ops->schedParamGet(taskCB, &param);', 'param.policy=0;')
                elif fault=='wrong_policy':a=a.replace('param->policy=(uint16_t)event->policy;', 'param->policy=(uint16_t)event->policy+1;')
                elif fault=='skip_unlock':b=b.replace('SCHEDULER_UNLOCK(intSave);', '(void)intSave;')
                elif fault=='wrong_task':b=b.replace('OsUserTaskOperatePermissionsCheck(taskCB)', 'OsUserTaskOperatePermissionsCheck(NULL)')
                elif fault=='process_mode':a=a.replace('(int32_t)call->flag);','0);')
                elif fault=='lost_lock':b=b.replace('SCHEDULER_LOCK(intSave);','SCHEDULER_LOCK(intSave);SCHEDULER_LOCK(intSave);')
                else:a=a.replace('SysSchedGetScheduler((int32_t)call->id,(int32_t)call->flag)', '(int32_t)call->raw').replace('require(depth==0 && phase==(invocation==1 ? 1U : 6U),108);','(void)phase;')
                self.assertTrue(a!=adapter or b!=body)
                (sources/'getscheduler_syscalls.c').write_text(b);(sources/'getscheduler_replay.c').write_text(a)
                with self.subTest(target_fault=fault):
                    run(build);audit(image,LLVM);failed,_=observe(image,'qemu-system-aarch64')
                    self.assertEqual(failed['error'],error)
                    with self.assertRaises(ValueError):require_success(failed)

if __name__=='__main__':unittest.main()
