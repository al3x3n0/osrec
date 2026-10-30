"""Reboot actual LiteOS-A with different RAMFS data and compare native replay."""
import json
from pathlib import Path
import subprocess
import sys
import struct
from types import SimpleNamespace
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]

sys.path.insert(0,str(ROOT/'tools'))
from live_pid_replay import export_live_pid
from live_priority_replay import export_live_priority

class LiveKernelTests(unittest.TestCase):
    def test_invalid_scalar_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            args=SimpleNamespace(out=Path(directory),kernel_root=ROOT/'build/kernel_liteos_a',
                                 llvm_bin=Path('/opt/homebrew/opt/llvm@16/bin'),compiler='cc')
            for observation in (b'', struct.pack('<2I',2,16),struct.pack('<2I',1,19)):
                with self.assertRaises(ValueError):
                    export_live_pid(args,observation,'0'*64,1)
            self.assertFalse((args.out/'pid-replay').exists())
            invalid=struct.pack('<9I',2,9,16,1,0xffffffea,16,0xffffffff,0xffffffea,16)
            with self.assertRaises(subprocess.CalledProcessError):
                export_live_priority(args,invalid,'0'*64,'SysSchedGetPriorityMin')
            self.assertFalse((args.out/'priority-min-replay').exists())

    def test_changed_payload_and_empty_file(self):
        with tempfile.TemporaryDirectory() as directory:
            stage=Path(directory)
            for label,data,returns,memory in [
                ('changed',b'XYZpqrs',[4,2,1,0],'0011585971727377'),
                ('empty',b'',[0,0,0,0],'0011223344556677')]:
                with self.subTest(label=label):
                    fixture=stage/(label+'.bin'); fixture.write_bytes(data)
                    output=stage/label
                    result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),
                        '--input',str(fixture),'--out',str(output)],capture_output=True,text=True,timeout=180)
                    self.assertEqual(result.returncode,0,result.stderr)
                    report=json.loads((output/'report.json').read_bytes())
                    self.assertTrue(report['actual_kernel_boot'])
                    self.assertTrue(report['guest_mmu_enabled'])
                    self.assertTrue(report['live_native_observations_match'])
                    self.assertEqual(report['raw_returns'],returns)
                    self.assertFalse(report['scheduler_irq_reproduction'])
                    priority=report['priority_replay']
                    self.assertTrue(priority['live_native_observations_match'])
                    self.assertEqual(priority['modeled_dependencies'],[])
                    self.assertEqual([call['raw'] for call in priority['calls']],[31,-22,-22])
                    self.assertEqual(subprocess.check_output([str(output/'priority-replay')],text=True).strip(),
                                     'priority session verified: 3 calls')
                    minimum=report['priority_min_replay']
                    self.assertTrue(minimum['live_native_observations_match'])
                    self.assertEqual(minimum['modeled_dependencies'],[])
                    self.assertEqual([call['raw'] for call in minimum['calls']],[10,-22,-22])
                    self.assertEqual(subprocess.check_output([str(output/'priority-min-replay')],text=True).strip(),
                                     'priority session verified: 3 calls')
                    pid=report['pid_replay']
                    self.assertTrue(pid['live_native_observations_match'])
                    self.assertEqual(pid['modeled_dependencies'],['LOS_GetCurrProcessID'])
                    self.assertEqual(pid['calls'],[{'raw':1,'user_mode':16}])
                    self.assertEqual(subprocess.check_output([str(output/'pid-replay')],text=True).strip(),
                                     'PID session verified: 1 call')
                    identities=report['identity_replay']
                    self.assertTrue(identities['live_native_observations_match'])
                    self.assertEqual([call['raw'] for call in identities['calls']],[0,0,1,1,1,-22,1])
                    self.assertEqual(len(identities['metadata']['dependency_transcript']),10)
                    self.assertFalse(identities['metadata']['symbolic_equivalence_verified'])
                    copied=stage/(label+'-identity-replay')
                    copied.write_bytes((output/'identity-replay').read_bytes()); copied.chmod(0o755)
                    self.assertEqual(subprocess.check_output([str(copied)],cwd=stage,text=True).strip(),
                                     'identity session verified: 7 calls')
                    masks=report['umask_replay']
                    self.assertTrue(masks['live_native_observations_match'])
                    calls=masks['calls']
                    self.assertEqual([call['mask_after'] for call in calls],[0,18,511,0,63,0])
                    self.assertEqual([call['raw'] for call in calls],[calls[0]['mask_before'],0,18,511,0,63])
                    self.assertEqual(subprocess.check_output([str(output/'umask-replay')],text=True).strip(),
                                     'umask session verified: 6 calls')
                    tasks=report['task_checkpoint']['checkpoint']
                    current,parent,task=tasks['objects']
                    self.assertGreater(current['process_id'],1)
                    self.assertEqual(current['parent'],parent['id']);self.assertEqual(parent['process_id'],1)
                    self.assertEqual([call['raw'] for call in tasks['calls']],
                                     [1,task['task_id'],1,task['task_id']])
                    task_image=stage/(label+'-task-image')
                    subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_task.py'),
                                    '--capture',str(output),'--out',str(task_image)],
                                   check=True,capture_output=True,text=True,timeout=60)
                    task_report=json.loads((task_image/'manifest.json').read_text())
                    self.assertEqual(task_report['target']['isa'],'AArch64')
                    self.assertEqual(task_report['target_observations']['task_id'],task['task_id'])
                    self.assertFalse(task_report['runtime_host_interaction'])
                    credentials=report['credentials_checkpoint']['checkpoint']
                    user=credentials['objects'][0]
                    self.assertEqual(credentials['current_process_id'],1)
                    self.assertEqual([call['raw_bits'] for call in credentials['calls']],[0,0,0,0])
                    self.assertEqual((user['effective_uid'],user['effective_gid']),(0,0))
                    credentials_image=stage/(label+'-credentials-image')
                    subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_credentials.py'),
                                    '--capture',str(output),'--out',str(credentials_image)],
                                   check=True,capture_output=True,text=True,timeout=60)
                    credentials_report=json.loads((credentials_image/'manifest.json').read_text())
                    observations=credentials_report['target_observations']
                    self.assertEqual(observations['locks'],4);self.assertEqual(observations['unlocks'],4)
                    self.assertEqual(observations['credential_accesses'],4);self.assertEqual(observations['lock_depth'],0)
                    self.assertFalse(credentials_report['runtime_host_interaction'])
                    priority_checkpoint=report['getpriority_checkpoint']['checkpoint']
                    self.assertEqual([call['raw_bits'] for call in priority_checkpoint['calls']],
                                     [28,28,0xffffffea,0xffffffea,0xffffffea,28])
                    self.assertEqual(len(priority_checkpoint['dependency_transcript']),10)
                    priority_image=stage/(label+'-getpriority-image')
                    subprocess.run([sys.executable,str(ROOT/'tools/export_freestanding_getpriority.py'),
                                    '--capture',str(output),'--out',str(priority_image)],
                                   check=True,capture_output=True,text=True,timeout=60)
                    priority_report=json.loads((priority_image/'manifest.json').read_text())
                    observations=priority_report['target_observations']
                    self.assertEqual([call['raw'] for call in observations['actual_calls']],
                                     [28,28,-22,-22,-22,28])
                    self.assertEqual(observations['dependencies_consumed'],10)
                    self.assertEqual(observations['pid_queries'],4);self.assertEqual(observations['priority_queries'],6)
                    self.assertFalse(priority_report['runtime_host_interaction'])
                    capture=json.loads((output/'capture.json').read_bytes())
                    self.assertEqual(capture['expected'][-1]['memory'],memory)
                    fixture.unlink()
                    self.assertEqual(subprocess.check_output([str(output/'replay')],text=True).strip(),
                                     'syscall session verified: 4 calls')
                    log=(output/'boot.log').read_text()
                    self.assertIn('cpu 0 entering scheduler',log)
                    self.assertIn('OSREC_LIVE_ENTRY pid=1',log)
                    self.assertIn('OSREC_LIVE_DONE',log)

if __name__=='__main__': unittest.main()
