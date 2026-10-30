"""Stat ABI output, inode/page metadata and a second caller object survive resumes."""
import gzip,json,re,shutil,struct,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from capture_linux_aarch64 import reviewed_adapter,digest
from generate_linux_aarch64_application import generate
from prepare_linux_aarch64_port import build_bundle
from run_linux_aarch64_checkpoint_pipeline import run,verify_pipeline
from export_syscall_slices import export
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-fstat-native'
def prepare_capture(dst):
    shutil.copytree(FIXTURE,dst,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (dst/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(dst);return dst
class LinuxFstatTests(unittest.TestCase):
    def test_generated_witness_and_original_stat_source_are_bound(self):
        r=reviewed_adapter();p=ROOT/'integrations/linux_aarch64/fstat';s=generate('fstat')
        self.assertEqual(s,(p/'application.c').read_text());self.assertEqual(s,(FIXTURE/'sources/application.c').read_text())
        v=json.loads((p/'port-template.json').read_text());v['roots']=[x for x in v['roots'] if x['number']!=80]
        with self.assertRaisesRegex(ValueError,'no reviewed route'):r.application_source('fstat',v)
        old,_=r.source_identity(ROOT/'integrations/linux_aarch64/close-range');new,defs=r.source_identity(p)
        self.assertEqual(len(defs),58);self.assertEqual(new['stat_abi_reference_release'],'v6.11')
        for n,h in old['definitions'].items():self.assertEqual(new['definitions'][n],h)
        self.assertIn(b'copy_to_user(statbuf,&tmp,sizeof(tmp))',defs['cp_new_stat']['body'])
        self.assertIn(b'error = vfs_fstat(fd, &stat);',defs['newfstat']['body'])
        self.assertIn(b'fdput(f);',defs['vfs_fstat']['body'])
        self.assertIn('stat_digest=stat_digest*',s);self.assertIn('j=18;j<30',s)
    def test_metadata_output_blocks_and_second_buffer_resume(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-fstat-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,_=r.validate_capture(native);_,states=r.projection(c)
            names={n:i for i,(n,_,_) in enumerate(r.fstat_plan())};row=lambda n:c['calls'][names[n]]
            output=lambda n:struct.pack('<32I',*row(n)['stat_words'])
            self.assertEqual(len(c['calls']),286)
            for n in ('stat_bad_fd_before_null','stat_after_last_release','stat_final_closed_fd'):self.assertEqual(row(n)['raw_bits'],(1<<64)-9)
            for n in ('stat_null_output','stat_invalid_output','stat_partial_output','stat_guard_output'):self.assertEqual(row(n)['raw_bits'],(1<<64)-14)
            self.assertEqual(output('stat_partial_output')[:96],struct.pack('<32I',*r.stat_input_words())[:96])
            self.assertEqual(output('stat_partial_output')[96:],output('stat_initial_regular')[:32])
            self.assertEqual(row('stat_guard_output')['stat_words'],r.stat_input_words())
            for n,size,blocks in [('stat_initial_regular',16,8),('stat_after_sparse_write',32,8),('stat_after_shrink',6,8),('stat_empty_unallocated',0,0),('stat_extended_unallocated',48,0),('stat_alias_same_inode',32,8)]:
                b=output(n);self.assertEqual(struct.unpack_from('<q',b,48)[0],size,n);self.assertEqual(struct.unpack_from('<q',b,64)[0],blocks,n)
                self.assertEqual(b[72:120],bytes(48));self.assertEqual(b[120:],bytes(8))
            for n in ('stat_truncated_fd','stat_alias_same_inode','stat_recreated_alias','stat_last_surviving_alias'):
                self.assertEqual(output(n)[8:16],output('stat_initial_regular')[8:16])
            old=json.loads((ROOT/'tests/fixtures/linux-aarch64-close-range-native/capture.json').read_text());oldnames={n for n,_,_ in r.close_range_plan()};kept=[]
            for (n,_,_),v in zip(r.fstat_plan(),c['calls']):
                if n in oldnames:
                    v=json.loads(json.dumps(v));del v['stat_words'];del v['stat_digest']
                    if v['file_after'] is not None:del v['file_after']['blocks']
                    kept.append(v)
            self.assertEqual(kept,old['calls'])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(286,32,1040,940))
            self.assertEqual(len(result['syscalls']),22);self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual(result['pause_ordinals'],[137,146,149,203,258,261])
            self.assertEqual([s['file']['blocks'] for s in result['saved_state']],[8,0,0,8,8,8])
            self.assertEqual([s['file']['size'] for s in result['saved_state']],[32,0,48,32,32,32])
            for s in result['saved_state']:
                self.assertEqual(s['inode_metadata'][1]['blocks'],s['file']['blocks'])
                self.assertEqual(s['inode_metadata'][1]['ino'],r.stat_metadata(c['initial'])[1]['ino'])
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text());self.assertEqual(k['target_observations']['verified_calls'],858);self.assertEqual(k['target_observations']['isolation_checks'],572)
            spec=json.loads((stage/'pipeline/port/spec.json').read_text());self.assertEqual([(o['id'],o['bytes']) for o in spec['objects']],[(1,32),(2,128)])
            self.assertTrue(any(a['symbol']=='stat_digest' for a in spec['assertions']))
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
    def test_metadata_copy_allocation_and_reference_mutants_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('out->size=p==&inode_pool[1] ? file_data.size : 0;','out->size=p==&inode_pool[1] ? 16 : 0;'),
                     ('if(!length)d->d_inode->blocks=0;','(void)d;'),
                     ('struct fd fdget_raw(unsigned int fd){return fdget_pos(fd);}','struct fd fdget_raw(unsigned int fd){struct fd f=fdget_pos(fd);f.flags=0;return f;}'),
                     ('*p=((const unsigned char *)in)[copied];++copied;','(void)in;++copied;')]
            for i,(a,b) in enumerate(changes):
                bundle=stage/str(i);port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(a),1);p.write_text(s.replace(a,b));v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
    def test_source_abi_and_forged_native_metadata_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,a,b in [('upstream/fs/stat.c',b'tmp.st_size = stat->size;',b'tmp.st_size = 16;'),('upstream/include/uapi/asm-generic/stat.h',b'long st_size;',b'int st_size;'),('upstream/include/uapi/asm-generic/unistd.h',b'__NR3264_fstat 80',b'__NR3264_fstat 81')]:
                p=native/filename;s=p.read_bytes();self.assertIn(a,s);p.write_bytes(s.replace(a,b,1))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(s)
            p=native/'capture.json';v=json.loads(p.read_text());i=next(i for i,(n,_,_) in enumerate(reviewed_adapter().fstat_plan()) if n=='stat_extended_unallocated');v['calls'][i]['stat_words'][16]=8;p.write_text(json.dumps(v,indent=2)+'\n')
            log=native/'qemu.log';uart={k:x for k,x in v.items() if k!='format'};log.write_text(re.sub(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}$','OSREC_LINUX_CAPTURE '+json.dumps(uart),log.read_text(),flags=re.M))
            p=native/'capture.manifest.json';v=json.loads(p.read_text());v['capture_sha256']=digest((native/'capture.json').read_bytes());v['qemu_log_sha256']=digest(log.read_bytes());p.write_text(json.dumps(v,indent=2)+'\n')
            with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ'):build_bundle(native,stage/'bad-native')
            self.assertFalse((stage/'bad-native').exists())
if __name__=='__main__':unittest.main()
