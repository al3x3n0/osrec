"""Original Linux descriptor operations preserve typed aliases across resumes."""
import gzip
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from capture_linux_aarch64 import reviewed_adapter,digest
from generate_linux_aarch64_application import generate
from prepare_linux_aarch64_port import build_bundle
from run_linux_aarch64_checkpoint_pipeline import run,verify_pipeline
from export_syscall_slices import export

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-fd-dup-native'

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxFdDupTests(unittest.TestCase):
    def test_generated_witness_and_original_definitions_are_bound(self):
        source=generate('fd-dup');integration=ROOT/'integrations/linux_aarch64/fd-dup'
        self.assertEqual(source,(integration/'application.c').read_text())
        self.assertEqual(source,(FIXTURE/'sources/application.c').read_text())
        original=json.loads((integration/'port-template.json').read_text())
        for number,kinds in ((23,['unsigned']),(24,['unsigned','unsigned','signed']),(57,['unsigned'])):
            port=json.loads(json.dumps(original));route=next(r for r in port['roots'] if r['number']==number)
            self.assertEqual(route['arguments'],kinds);port['roots'].remove(route)
            with self.assertRaisesRegex(ValueError,'no reviewed route'):reviewed_adapter().application_source('fd-dup',port)
        identity,defs=reviewed_adapter().source_identity(integration)
        self.assertEqual(len(defs),28);self.assertEqual(set(identity['additional_sources']),{'fs/file.c','fs/open.c'})
        self.assertIn(b'__releases(&files->file_lock)',defs['do_dup2']['original'])
        self.assertIn(b'atomic_long_inc_not_zero(&file->f_count)',defs['__fget_files_rcu']['body'])
        self.assertIn(b'__fput_sync(file)',defs['close']['body'])

    def test_descriptor_aliases_bitmaps_and_lifetimes_resume(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-fd-dup-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');review=reviewed_adapter()
            captured,manifest=review.validate_capture(native);calls=captured['calls'];_,states=review.projection(captured)
            names={n:i for i,(n,_) in enumerate(review.fd_dup_plan())}
            row=lambda n:calls[names[n]]
            after=lambda n:states[names[n]+1]
            self.assertTrue(manifest['native_linux_boot']);self.assertEqual(len(calls),73)
            self.assertEqual(captured['initial']['nofile_limit'],[8,8])
            for n,errno in [('dup_closed',9),('same_fd',22),('same_closed_fd',22),('flags_before_bad_source',22),('target_at_limit',9),('table_full',24),('bad_source_full',9),('full_after_fixed_install',24)]:
                self.assertEqual(row(n)['raw_bits'],(1<<64)-errno)
                self.assertEqual(after(n),states[names[n]])
            self.assertEqual(after('table_full')['counts'],[3,5])
            self.assertEqual(after('close_cloexec')['slots'][5],0)
            self.assertTrue(after('close_cloexec')['cloexec']&(1<<5))
            self.assertEqual(row('close_cloexec')['fds_after'][5],[0,0])
            self.assertFalse(after('reuse_closed_clears_cloexec')['cloexec']&(1<<5))
            self.assertEqual(after('console_replace_regular')['counts'],[4,3])
            self.assertEqual(after('regular_replace_console_cloexec')['counts'],[3,5])
            self.assertEqual(row('alias_recreates_seed')['raw_bits'],3)
            self.assertEqual(row('truncated_close')['raw_bits'],0)
            self.assertEqual(after('last_regular_reference')['counts'],[3,0])
            self.assertEqual(states[-1]['counts'],[3,0]);self.assertEqual(states[-1]['slots'],[1,1,1,0,0,0,0,0])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(73,32,768,708))
            self.assertEqual(len(result['syscalls']),13);self.assertFalse(result['runtime_host_interaction'])
            self.assertFalse(result['native_source_build_attested'])
            self.assertEqual(result['saved_state'][-1]['file_counts'],[3,0])
            self.assertEqual(result['saved_state'][1]['fd_slots'][5],0)
            self.assertTrue(result['saved_state'][1]['cloexec']&(1<<5))
            kernel=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            self.assertEqual(kernel['target_observations']['verified_calls'],219)
            self.assertEqual(kernel['target_observations']['isolation_checks'],146)
            self.assertIn('__fget_files_rcu',kernel['context_plan']['context_functions'])
            self.assertIn('files',{f['name'] for f in kernel['context_plan']['owned_state']})
            self.assertIn('file_pool',{f['name'] for f in kernel['context_plan']['owned_state']})
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_reference_and_cloexec_mutants_fail_target_proof(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('++*count;return 1;','return 1;'),('if(p)--p->f_count;','(void)p;'),('t->close_on_exec[fd/64]&=~(1ul<<(fd%64));','(void)fd;(void)t;')]
            for i,(original,mutation) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle)
                model=bundle/'models.c';text=model.read_text();self.assertEqual(text.count(original),1);model.write_text(text.replace(original,mutation))
                descriptor=json.loads(port.read_text());descriptor['bundle']['inputs']['models.c']=digest(model.read_bytes());port.write_text(json.dumps(descriptor))
                output=stage/('bad-kernel-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=output,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(output.exists())

    def test_source_abi_and_false_native_state_reject_before_publication(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,old,new in [('upstream/fs/file.c',b'if (newfd >= rlimit(RLIMIT_NOFILE))',b'if (newfd > rlimit(RLIMIT_NOFILE))'),('upstream/fs/open.c',b'__fput_sync(file);',b'fput(file);'),('upstream/include/uapi/asm-generic/unistd.h',b'__NR_dup3 24',b'__NR_dup3 25')]:
                path=native/filename;raw=path.read_bytes();self.assertEqual(raw.count(old),1);path.write_bytes(raw.replace(old,new))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());path.write_bytes(raw)
            capture=native/'capture.json';data=json.loads(capture.read_text())
            index=next(i for i,(n,_) in enumerate(reviewed_adapter().fd_dup_plan()) if n=='dup_cloexec')
            data['calls'][index]['fds_after'][6][1]=0;capture.write_text(json.dumps(data,indent=2)+'\n')
            log=native/'qemu.log';uart={k:v for k,v in data.items() if k!='format'}
            log.write_text(re.sub(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}$','OSREC_LINUX_CAPTURE '+json.dumps(uart),log.read_text(),flags=re.M))
            mp=native/'capture.manifest.json';m=json.loads(mp.read_text());m['capture_sha256']=digest(capture.read_bytes());m['qemu_log_sha256']=digest(log.read_bytes());mp.write_text(json.dumps(m,indent=2)+'\n')
            with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ'):build_bundle(native,stage/'bad-capture')
            self.assertFalse((stage/'bad-capture').exists())

if __name__=='__main__':unittest.main()
