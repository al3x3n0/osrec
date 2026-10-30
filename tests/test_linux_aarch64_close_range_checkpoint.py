"""Original close_range paths preserve complete bitmap and alias state in QEMU."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-close-range-native'

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxCloseRangeTests(unittest.TestCase):
    def test_generated_witness_and_original_range_bodies_are_bound(self):
        r=reviewed_adapter();p=ROOT/'integrations/linux_aarch64/close-range';s=generate('close-range')
        self.assertEqual(s,(p/'application.c').read_text());self.assertEqual(s,(FIXTURE/'sources/application.c').read_text())
        port=json.loads((p/'port-template.json').read_text());port['roots']=[x for x in port['roots'] if x['number']!=436]
        with self.assertRaisesRegex(ValueError,'no reviewed route'):r.application_source('close-range',port)
        old,_=r.source_identity(ROOT/'integrations/linux_aarch64/fd-control');new,defs=r.source_identity(p)
        self.assertEqual(len(defs),54)
        # fd-control alone has the original fcntl entry, descriptor lookups and read/write/truncate path;
        # close-range keeps their reviewed models and shares every other body unchanged.
        only=set(old['definitions'])-set(new['definitions'])
        self.assertLessEqual({'fcntl','do_fcntl','__fget_light','fdget','vfs_read','shmem_file_read_iter','notify_change','shmem_undo_range'},only)
        for n,h in old['definitions'].items():
            if n not in only:self.assertEqual(new['definitions'][n],h)
        self.assertTrue(defs['close_range']['syscall']);self.assertIn(b'return __close_range(fd, max_fd, flags);',defs['close_range']['body'])
        self.assertIn(b'for (; fd <= max_fd; fd++)',defs['__range_close']['body'])
        self.assertIn(b'bitmap_set(fdt->close_on_exec, fd, max_fd - fd + 1)',defs['__range_cloexec']['body'])
        self.assertIn(b'return fdt->max_fds - 1;',defs['last_fd']['body'])
        names={n for n,_,_ in r.fd_control_plan()}
        self.assertEqual([row for row in r.close_range_plan() if row[0] in names],r.fd_control_plan())
        # Only invalid requests may contain UNSHARE: table cloning is excluded.
        for _,call,_ in r.close_range_plan():
            if call['number']==436:
                flags=call['args'][2]&0xffffffff
                self.assertFalse((flags&2) and not (flags&~6))

    def test_range_aliases_holes_and_full_bitmap_restore(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-close-range-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,m=r.validate_capture(native);_,states=r.projection(c)
            names={n:i for i,(n,_,_) in enumerate(r.close_range_plan())}
            row=lambda n:c['calls'][names[n]]
            after=lambda n:states[names[n]+1]
            self.assertTrue(m['native_linux_boot']);self.assertEqual(len(c['calls']),267)
            for n in ('range_invalid_flags','range_reversed_bounds','range_invalid_before_unshare','range_signed_flags','range_truncated_reversed'):
                self.assertEqual(row(n)['raw_bits'],(1<<64)-22);self.assertEqual(states[names[n]],after(n))
            for n in ('range_truncated_closed_slots','mark_full_tail','close_middle_aliases','close_middle_holes_again','close_high_empty_range','mark_above_table_noop','close_above_table_noop','close_last_table_slot','mark_console_slot','bulk_close_aliases','range_last_reference','empty_range_close_again','mark_after_last_release'):
                self.assertEqual(row(n)['raw_bits'],0,n)
            self.assertEqual(after('range_truncated_closed_slots')['cloexec'],0xffc8)
            self.assertEqual(after('mark_full_tail')['cloexec'],(1<<64)-8)
            self.assertEqual(after('close_middle_aliases')['slots'],[1,1,1,2,0,0,0,2])
            self.assertEqual(after('close_middle_aliases')['counts'],[3,2]);self.assertEqual(after('close_middle_aliases')['next_fd'],4)
            self.assertEqual(row('range_closed_alias_fcntl')['raw_bits'],(1<<64)-9)
            self.assertEqual(row('range_survivor_read')['raw_bits'],4);self.assertEqual(row('range_survivor_offset_seen')['raw_bits'],4)
            self.assertEqual(after('restore_range_aliases')['slots'],[1,1,1,2,2,2,2,2]);self.assertEqual(after('restore_range_aliases')['next_fd'],6)
            self.assertEqual(after('restore_range_aliases')['cloexec'],(1<<64)-56)
            self.assertEqual(row('query_marked_console_slot')['raw_bits'],1)
            self.assertEqual(after('bulk_close_aliases')['counts'],[3,1]);self.assertEqual(row('last_range_alias_reads_position')['raw_bits'],20)
            self.assertEqual(after('range_last_reference')['counts'],[3,0]);self.assertIsNone(row('range_last_reference')['file_after'])
            self.assertEqual(row('read_after_range_last_release')['raw_bits'],(1<<64)-9)
            changed={'close_alias_3','close_alias_4','close_alias_5','close_alias_6','last_regular_reference'}
            old=json.loads((ROOT/'tests/fixtures/linux-aarch64-fd-control-native/capture.json').read_text())
            retained=[(n,v) for (n,_,_),v in zip(r.close_range_plan(),c['calls']) if n in {n for n,_,_ in r.fd_control_plan()}]
            self.assertEqual({n for (n,v),prior in zip(retained,old['calls']) if v!=prior},changed)
            for n in changed:self.assertEqual(row(n)['raw_bits'],(1<<64)-9)
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(267,32,960,860))
            self.assertEqual(len(result['syscalls']),21);self.assertFalse(result['runtime_host_interaction']);self.assertFalse(result['native_source_build_attested'])
            self.assertEqual(result['pause_ordinals'],[49,52,66,241,243,251])
            self.assertEqual([s['cloexec'] for s in result['saved_state']],[(1<<64)-v for v in (8,8,56,128,128,8)])
            self.assertEqual([s['file_counts'] for s in result['saved_state']],[[3,5],[3,2],[3,5],[3,1],[3,0],[3,0]])
            self.assertEqual([s['file']['pos'] for s in result['saved_state']],[0,0,0,20,20,20])
            for s in result['saved_state']:
                self.assertEqual(s['file_dentries'],[1,2]);self.assertEqual(s['dentry_inodes'],[1,2])
                self.assertTrue(s['cloexec']&(1<<63))
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            self.assertEqual(k['target_observations']['verified_calls'],801);self.assertEqual(k['target_observations']['isolation_checks'],534)
            self.assertTrue(any('CLOSE_RANGE_UNSHARE excluded' in d for d in k['source_identity']['modeled_dependencies']))
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_bitmap_model_mutants_fail_before_publication(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            old='for(unsigned int i=first;i<first+count;++i)bits[i/64]|=UINT64_C(1)<<(i%64);'
            changes=['(void)bits;',
                     'for(unsigned int i=first;i<first+count;++i)if(current->files->fdt->fd[i])bits[i/64]|=UINT64_C(1)<<(i%64);',
                     'for(unsigned int i=first;i<first+count-1;++i)bits[i/64]|=UINT64_C(1)<<(i%64);']
            for i,new in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(old),1);p.write_text(s.replace(old,new))
                v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())

    def test_source_abi_and_forged_native_range_flag_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,old,new in [('upstream/fs/file.c',b'for (; fd <= max_fd; fd++)',b'for (; fd < max_fd; fd++)'),('upstream/fs/open.c',b'return __close_range(fd, max_fd, flags);',b'return __close_range(fd, max_fd, 0);'),('upstream/include/uapi/asm-generic/unistd.h',b'__NR_close_range 436',b'__NR_close_range 437')]:
                p=native/filename;s=p.read_bytes();self.assertIn(old,s);p.write_bytes(s.replace(old,new,1))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(s)
            p=native/'capture.json';v=json.loads(p.read_text());i=next(i for i,(n,_,_) in enumerate(reviewed_adapter().close_range_plan()) if n=='mark_full_tail')
            v['calls'][i]['fds_after'][4][1]=0;p.write_text(json.dumps(v,indent=2)+'\n')
            log=native/'qemu.log';uart={k:x for k,x in v.items() if k!='format'};log.write_text(re.sub(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}$','OSREC_LINUX_CAPTURE '+json.dumps(uart),log.read_text(),flags=re.M))
            p=native/'capture.manifest.json';v=json.loads(p.read_text());v['capture_sha256']=digest((native/'capture.json').read_bytes());v['qemu_log_sha256']=digest(log.read_bytes());p.write_text(json.dumps(v,indent=2)+'\n')
            with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ'):build_bundle(native,stage/'bad-native')
            self.assertFalse((stage/'bad-native').exists())
if __name__=='__main__':unittest.main()
