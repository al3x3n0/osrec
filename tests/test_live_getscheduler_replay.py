"""Real process scheduler queries, ordered output boundaries, and target faults."""
import json,shutil,struct,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from live_getscheduler_replay import decode_getscheduler
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success
LLVM=Path('/opt/homebrew/opt/llvm@16/bin')

class LiveGetSchedulerTests(unittest.TestCase):
    def test_live_capture_export_and_faults(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture';output=stage/'image'
            result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--getscheduler','--out',str(capture)],capture_output=True,text=True,timeout=240)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            user=(capture/'getscheduler-user-observations.bin').read_bytes();deps=(capture/'getscheduler-dependencies.bin').read_bytes()
            checkpoint=decode_getscheduler(user,deps)
            self.assertEqual([c['raw_bits'] for c in checkpoint['calls']],[2,2,0xffffffea,0xfffffffd])
            self.assertEqual([e['policy_written'] for e in checkpoint['dependency_transcript']],[0,1,1,0,0])
            self.assertEqual(json.loads((capture/'report.json').read_text())['getscheduler_capture']['flag'],0)
            for fault in ('missing','extra','pid','order','flag','mode','return','success_write','failure_write','failure_policy'):
                a=bytearray(user);b=bytearray(deps)
                if fault=='missing':b=b[:-24]
                elif fault=='extra':b+=b[-24:]
                elif fault=='pid':struct.pack_into('<I',b,24+8,2)
                elif fault=='order':b[24:48],b[48:72]=b[48:72],b[24:48]
                elif fault=='flag':struct.pack_into('<I',a,4,0xffffffff)
                elif fault=='mode':struct.pack_into('<I',a,12,19)
                elif fault=='return':struct.pack_into('<I',a,8,0)
                elif fault=='success_write':struct.pack_into('<I',b,24+20,0)
                elif fault=='failure_write':struct.pack_into('<I',b,72+20,1)
                else:struct.pack_into('<I',b,72+16,2)
                with self.subTest(capture_fault=fault),self.assertRaises(ValueError):decode_getscheduler(a,b)
            result=subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getscheduler.py'),'--capture',str(capture),'--out',str(output)],capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            manifest=json.loads((output/'manifest.json').read_text());obs=manifest['target_observations']
            self.assertTrue(manifest['raw_image_execution_match']);self.assertFalse(manifest['runtime_host_interaction']);self.assertFalse(manifest['task_mode_supported'])
            self.assertEqual((obs['abi_version'],obs['pid_queries'],obs['scheduler_queries'],obs['policy_writes']),(9,1,4,2))
            self.assertEqual([c['dependencies_consumed'] for c in obs['actual_calls']],[2,3,4,5])
            require_success(obs)
            sources=stage/'fault-sources';shutil.copytree(output/'sources',sources)
            body=(sources/'getscheduler_syscalls.c').read_text();adapter=(sources/'getscheduler_replay.c').read_text()
            image=stage/'fault.elf'
            build=[LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'getscheduler_replay.c',sources/'getscheduler_syscalls.c','-o',image]
            for fault,error in (('pid_resolution',3),('return_policy',10),('wrong_id',3),('policy_write',10),('task_mode',7),('skip_lookup',4)):
                b=body;a=adapter
                if fault=='pid_resolution':b=b.replace('if (id == 0)', 'if (id == 99)')
                elif fault=='return_policy':b=b.replace('return policy;', 'return ret;')
                elif fault=='wrong_id':b=b.replace('LOS_GetProcessScheduler(id,', 'LOS_GetProcessScheduler(id+1,')
                elif fault=='policy_write':a=a.replace('*policy=(int32_t)event->policy;', '*policy=(int32_t)event->policy+1;')
                elif fault=='task_mode':a=a.replace('(int32_t)call->flag);','-1);')
                else:a=a.replace('SysSchedGetScheduler((int32_t)call->id,(int32_t)call->flag)', '(int32_t)call->raw')
                self.assertTrue(a!=adapter or b!=body)
                (sources/'getscheduler_syscalls.c').write_text(b);(sources/'getscheduler_replay.c').write_text(a)
                with self.subTest(target_fault=fault):
                    run(build);audit(image,LLVM);failed,_=observe(image,'qemu-system-aarch64')
                    self.assertEqual(failed['error'],error)
                    with self.assertRaises(ValueError):require_success(failed)

if __name__=='__main__':unittest.main()
