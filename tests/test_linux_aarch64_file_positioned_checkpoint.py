"""Positioned I/O and inode truncation preserve alias state across QEMU resumes."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-file-positioned-native'

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxFilePositionedTests(unittest.TestCase):
    def test_generated_witness_and_original_positioned_bodies_are_bound(self):
        r=reviewed_adapter();p=ROOT/'integrations/linux_aarch64/file-positioned';s=generate('file-positioned')
        self.assertEqual(s,(p/'application.c').read_text());self.assertEqual(s,(FIXTURE/'sources/application.c').read_text())
        descriptor=json.loads((p/'port-template.json').read_text())
        for n in (46,67,68):
            v=json.loads(json.dumps(descriptor));v['roots']=[x for x in v['roots'] if x['number']!=n]
            with self.assertRaisesRegex(ValueError,'no reviewed route'):r.application_source('file-positioned',v)
        old,_=r.source_identity(ROOT/'integrations/linux_aarch64/file-io');new,defs=r.source_identity(p)
        self.assertEqual(len(defs),46)
        for n,h in old['definitions'].items():self.assertEqual(new['definitions'][n],h)
        self.assertIn(b'if (pos < 0)',defs['ksys_pread64']['body']);self.assertIn(b'if (pos < 0)',defs['ksys_pwrite64']['body'])
        self.assertNotIn(b'f_pos =',defs['ksys_pread64']['body']);self.assertNotIn(b'f_pos =',defs['ksys_pwrite64']['body'])
        self.assertLess(defs['do_sys_ftruncate']['body'].index(b'length < 0'),defs['do_sys_ftruncate']['body'].index(b'fdget(fd)'))
        self.assertIn(b'dentry = file->f_path.dentry;',defs['do_ftruncate']['body'])

    def test_positioned_transfers_and_truncation_restore_inode_graph(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-positioned-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,m=r.validate_capture(native);_,states=r.projection(c)
            names={n:i for i,(n,_,_) in enumerate(r.file_positioned_plan())}
            row=lambda n:c['calls'][names[n]]
            before=lambda n:states[names[n]]
            after=lambda n:states[names[n]+1]
            self.assertTrue(m['native_linux_boot']);self.assertEqual(len(c['calls']),171)
            for n in ('pread_initial_preserves_position','pwrite_overwrite_preserves_position','pread_partial_fault','pwrite_partial_fault','pread_alias_keeps_shared_position','pwrite_alias_keeps_shared_position','pwrite_surviving_alias','pread_surviving_alias'):
                self.assertEqual(before(n)['file']['pos'],after(n)['file']['pos'])
            for n in ('pread_negative_before_bad_fd','pwrite_negative_before_bad_fd','ftruncate_negative_before_bad_fd','ftruncate_console','ftruncate_signed_high_length','negative_position_after_last_close'):
                self.assertEqual(row(n)['raw_bits'],(1<<64)-22);self.assertEqual(after(n),before(n))
            for n in ('pread_closed_fd','pwrite_closed_fd','ftruncate_closed_fd','pread_closed_original','pread_after_last_close','pwrite_after_last_close','ftruncate_after_last_close'):
                self.assertEqual(row(n)['raw_bits'],(1<<64)-9);self.assertEqual(after(n),before(n))
            for n in ('pread_console_espipe','pwrite_console_espipe'):self.assertEqual(row(n)['raw_bits'],(1<<64)-29)
            for n in ('pread_eof_null','pread_zero_null','pwrite_zero_null','pread_large_offset','read_after_shrink_eof','pread_empty_bad_pointer'):
                self.assertEqual(row(n)['raw_bits'],0);self.assertEqual(after(n),before(n))
            self.assertEqual((row('pread_partial_fault')['raw_bits'],row('pwrite_partial_fault')['raw_bits']),(4,4))
            self.assertEqual((after('shrink_below_position')['file']['size'],after('shrink_below_position')['file']['pos']),(6,32))
            self.assertEqual(after('shrink_below_position')['file']['bytes'][6:],[0]*58)
            self.assertEqual(after('expand_after_shrink')['file']['bytes'][6:],[0]*58)
            self.assertEqual((after('truncate_empty_keeps_position')['file']['size'],after('truncate_empty_keeps_position')['file']['pos']),(0,32))
            self.assertEqual(after('extend_empty')['file']['bytes'],[0]*64)
            self.assertEqual(after('truncate_max_capacity')['file']['size'],64)
            self.assertEqual(row('pread_at_capacity_tail')['raw_bits'],4)
            self.assertEqual(after('shrink_via_alias')['file']['size'],10)
            self.assertEqual(row('original_read_after_alias_shrink')['raw_bits'],2)
            self.assertEqual(after('extend_via_original')['file']['bytes'][10:],[0]*54)
            self.assertEqual(after('truncate_surviving_alias')['file']['size'],8)
            self.assertEqual(after('extend_surviving_alias')['file']['bytes'][8:],[0]*56)
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(171,32,960,860))
            self.assertEqual(len(result['syscalls']),19);self.assertFalse(result['runtime_host_interaction']);self.assertFalse(result['native_source_build_attested'])
            self.assertEqual([s['file']['pos'] for s in result['saved_state']],[0,32,32,8,8,20])
            self.assertEqual([s['file']['size'] for s in result['saved_state']],[16,6,0,32,10,8])
            for s in result['saved_state']:
                self.assertEqual(s['file_dentries'],[1,2]);self.assertEqual(s['dentry_inodes'],[1,2])
                self.assertEqual(s['inodes'],[dict(mode=0o20000,append=0),dict(mode=0o100000,append=0)])
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            self.assertEqual(k['target_observations']['verified_calls'],513);self.assertEqual(k['target_observations']['isolation_checks'],342)
            self.assertTrue({'inode_pool','dentry_pool','superblock'}<={s['name'] for s in k['context_plan']['owned_state']})
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_truncate_and_positioned_models_fail_before_publication(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('for(unsigned i=(unsigned)length;i<64;++i)file_data.bytes[i]=0;','(void)length;'),('file_data.size=length;','file_data.size=length;p->f_pos=length;'),('return regular_transfer(p,(uintptr_t)buf,count,pos,0);','ssize_t ret=regular_transfer(p,(uintptr_t)buf,count,pos,0);p->f_pos=*pos;return ret;'),('void fdput(struct fd f){fdput_pos(f);}','void fdput(struct fd f){(void)f;}')]
            for i,(old,new) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(old),1);p.write_text(s.replace(old,new))
                v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())

    def test_source_abi_and_forged_native_position_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,old,new in [('upstream/fs/read_write.c',b'if (pos < 0)',b'if (pos <= 0)'),('upstream/fs/open.c',b'if (length < 0)',b'if (length <= 0)'),('upstream/include/uapi/asm-generic/unistd.h',b'__NR3264_ftruncate 46',b'__NR3264_ftruncate 45')]:
                p=native/filename;s=p.read_bytes();self.assertIn(old,s);p.write_bytes(s.replace(old,new,1))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(s)
            p=native/'capture.json';v=json.loads(p.read_text());i=next(i for i,(n,_,_) in enumerate(reviewed_adapter().file_positioned_plan()) if n=='pwrite_overwrite_preserves_position')
            v['calls'][i]['file_after']['pos']=6;p.write_text(json.dumps(v,indent=2)+'\n')
            log=native/'qemu.log';uart={k:x for k,x in v.items() if k!='format'};log.write_text(re.sub(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}$','OSREC_LINUX_CAPTURE '+json.dumps(uart),log.read_text(),flags=re.M))
            p=native/'capture.manifest.json';v=json.loads(p.read_text());v['capture_sha256']=digest((native/'capture.json').read_bytes());v['qemu_log_sha256']=digest(log.read_bytes());p.write_text(json.dumps(v,indent=2)+'\n')
            with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ'):build_bundle(native,stage/'bad-native')
            self.assertFalse((stage/'bad-native').exists())

if __name__=='__main__':unittest.main()
