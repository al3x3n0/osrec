"""Native memfd bytes and shared offsets replay without host filesystem calls."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-file-io-native'

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxFileIoTests(unittest.TestCase):
    def test_generated_witness_and_original_io_bodies_are_bound(self):
        integration=ROOT/'integrations/linux_aarch64/file-io';source=generate('file-io')
        self.assertEqual(source,(integration/'application.c').read_text());self.assertEqual(source,(FIXTURE/'sources/application.c').read_text())
        descriptor=json.loads((integration/'port-template.json').read_text())
        for n in (62,63,64):
            p=json.loads(json.dumps(descriptor));p['roots']=[r for r in p['roots'] if r['number']!=n]
            with self.assertRaisesRegex(ValueError,'no reviewed route'):reviewed_adapter().application_source('file-io',p)
        old,_=reviewed_adapter().source_identity(ROOT/'integrations/linux_aarch64/fd-dup');identity,defs=reviewed_adapter().source_identity(integration)
        self.assertEqual(len(defs),39)
        for n,h in old['definitions'].items():self.assertEqual(identity['definitions'][n],h)
        self.assertTrue(defs['generic_file_llseek_size']['original'].startswith(b'loff_t\ngeneric_file_llseek_size'))
        self.assertIn(b'f.file->f_pos = pos;',defs['ksys_read']['body']);self.assertIn(b'f.file->f_pos = pos;',defs['ksys_write']['body'])
        self.assertIn(b'fdput_pos(f);',defs['ksys_lseek']['body'])

    def test_persistent_bytes_and_shared_offsets_resume(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-io-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,m=r.validate_capture(native);_,states=r.projection(c)
            names={n:i for i,(n,_,_) in enumerate(r.file_io_plan())}
            row=lambda n:c['calls'][names[n]]
            after=lambda n:states[names[n]+1]
            self.assertTrue(m['native_linux_boot']);self.assertEqual(len(c['calls']),118)
            self.assertEqual(row('read_initial')['words'][1:3],[0x64636261,0xa5a56665])
            self.assertEqual(row('query_after_read')['raw_bits'],6)
            self.assertEqual(after('write_sparse')['file']['bytes'][20:28],[0]*8)
            self.assertEqual((after('write_sparse')['file']['size'],after('write_sparse')['file']['pos']),(32,32))
            for n in ('read_eof_bad_pointer','zero_read_null','zero_write_bad_pointer','large_offset_eof'):
                self.assertEqual(row(n)['raw_bits'],0);self.assertEqual(after(n),states[names[n]])
            for n in ('negative_seek','negative_relative_seek','invalid_whence','signed_whence'):
                self.assertEqual(row(n)['raw_bits'],(1<<64)-22);self.assertEqual(after(n),states[names[n]])
            self.assertEqual(after('large_seek')['file']['pos'],0x100000007)
            self.assertEqual(row('read_partial_fault')['raw_bits'],4);self.assertEqual(after('read_partial_fault')['file']['pos'],4)
            self.assertEqual(row('read_partial_fault')['words'][7],0xa5a50001)
            self.assertEqual(row('write_partial_fault')['raw_bits'],4);self.assertEqual(after('write_partial_fault')['file']['pos'],8)
            for n in ('read_first_fault','read_guard_first_fault','write_first_fault','read_huge_count','write_huge_count'):
                self.assertEqual(row(n)['raw_bits'],(1<<64)-14);self.assertEqual(after(n),states[names[n]])
            self.assertEqual(after('alias_seek_updates_original')['file']['pos'],2)
            self.assertEqual(after('original_writes_alias_offset')['file']['pos'],8)
            self.assertEqual(after('alias_reads_after_original_write')['file']['pos'],12)
            self.assertEqual(row('surviving_alias_read')['raw_bits'],16)
            for n in ('closed_original_read','last_alias_read_bad_fd','last_alias_write_bad_fd','last_alias_seek_bad_fd'):
                self.assertEqual(row(n)['raw_bits'],(1<<64)-9)
            self.assertIsNone(row('last_regular_reference')['file_after']);self.assertEqual(after('last_regular_reference')['counts'],[3,0])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(118,32,888,812))
            self.assertEqual(len(result['syscalls']),16);self.assertFalse(result['runtime_host_interaction']);self.assertFalse(result['native_source_build_attested'])
            self.assertEqual([s['file']['pos'] for s in result['saved_state']],[32,4,8,8,12,20])
            self.assertEqual(result['saved_state'][-1]['file_counts'],[3,0]);self.assertEqual(result['saved_state'][-1]['file'],states[-1]['file'])
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            self.assertEqual(k['target_observations']['verified_calls'],354);self.assertEqual(k['target_observations']['isolation_checks'],236)
            self.assertIn('file_data',{v['name'] for v in k['context_plan']['owned_state']});self.assertIn('ksys_read',k['context_plan']['context_functions'])
            self.assertIn('ksys_write',k['context_plan']['context_functions']);self.assertIn('generic_file_llseek_size',k['context_plan']['context_functions'])
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_bytes_position_and_reference_mutants_fail_target_proof(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('*pos+=(loff_t)copied;','(void)pos;'),('if(writing)file_data.bytes[start+copied]=*at;','if(writing)(void)*at;'),('if(f.flags)fput(f.file);','(void)f;'),('if(address+copied<region->user_address || address+copied-region->user_address>=32)break;','(void)region;')]
            for i,(original,mutation) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(original),1);p.write_text(s.replace(original,mutation))
                v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes())
                if i==3:
                    # Imported ELF RAM can map bytes beyond the caller object.
                    # This second region makes the same mistake visible in the
                    # small returning-slice proof, without relying on an MMU.
                    proof=bundle/'proof.c';body=proof.read_text()
                    for old,new in [('memory[2][32]','memory[2][64]'),('regions[2];','regions[2][2];'),('{&regions[s],1}','{regions[s],2}'),('regions[s].user_address','regions[s][0].user_address'),('regions[s]=(struct osrec_user_region)','regions[s][0]=(struct osrec_user_region)')]:
                        self.assertIn(old,body);body=body.replace(old,new)
                    old='if(osrec_slice_session_init(&sessions[s],'
                    self.assertIn(old,body)
                    body=body.replace(old,'regions[s][1]=(struct osrec_user_region){regions[s][0].user_address+32,memory[s]+32,32,3,2};'+old,1)
                    proof.write_text(body);v['bundle']['inputs']['proof.c']=digest(proof.read_bytes())
                port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())

    def test_source_abi_and_false_native_bytes_reject_before_publication(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,old,new in [('upstream/fs/read_write.c',b'f.file->f_pos = pos;',b'f.file->f_pos = 0;'),('upstream/fs/read_write.c',b'offset += eof;',b'offset = eof;'),('upstream/include/uapi/asm-generic/unistd.h',b'__NR_read 63',b'__NR_read 65')]:
                p=native/filename;s=p.read_bytes();self.assertIn(old,s);p.write_bytes(s.replace(old,new,1))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(s)
            p=native/'capture.json';v=json.loads(p.read_text());index=next(i for i,(n,_,_) in enumerate(reviewed_adapter().file_io_plan()) if n=='original_writes_alias_offset')
            v['calls'][index]['file_after']['bytes'][2]^=1;p.write_text(json.dumps(v,indent=2)+'\n')
            log=native/'qemu.log';uart={k:x for k,x in v.items() if k!='format'};log.write_text(re.sub(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}$','OSREC_LINUX_CAPTURE '+json.dumps(uart),log.read_text(),flags=re.M))
            mp=native/'capture.manifest.json';m=json.loads(mp.read_text());m['capture_sha256']=digest(p.read_bytes());m['qemu_log_sha256']=digest(log.read_bytes());mp.write_text(json.dumps(m,indent=2)+'\n')
            with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ'):build_bundle(native,stage/'bad-native')
            self.assertFalse((stage/'bad-native').exists())

if __name__=='__main__':unittest.main()
