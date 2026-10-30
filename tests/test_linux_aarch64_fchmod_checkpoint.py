"""Owner permission changes remain shared through aliases and checkpoint resumes."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-fchmod-native'
def prepare_capture(dst):
    shutil.copytree(FIXTURE,dst,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (dst/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(dst);return dst
class LinuxFchmodTests(unittest.TestCase):
    def test_generated_witness_and_original_chmod_source_are_bound(self):
        r=reviewed_adapter();p=ROOT/'integrations/linux_aarch64/fchmod';s=generate('fchmod')
        self.assertEqual(s,(p/'application.c').read_text());self.assertEqual(s,(FIXTURE/'sources/application.c').read_text())
        old,_=r.source_identity(ROOT/'integrations/linux_aarch64/fstat');new,defs=r.source_identity(p)
        self.assertEqual(len(defs),61)
        for n,h in old['definitions'].items():self.assertEqual(new['definitions'][n],h)
        self.assertIn(b'(mode & S_IALLUGO) | (inode->i_mode & ~S_IALLUGO)',defs['chmod_common']['body'])
        self.assertIn(b'fdput(f);',defs['fchmod']['body'])
        self.assertIn(b'return chmod_common(&file->f_path, mode);',defs['vfs_fchmod']['body'])
        v=json.loads((p/'port-template.json').read_text());v['roots']=[x for x in v['roots'] if x['number']!=52]
        with self.assertRaisesRegex(ValueError,'no reviewed route'):r.application_source('fchmod',v)
    def test_owner_modes_open_access_aliases_and_mount_links_resume(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-fchmod-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,_=r.validate_capture(native);_,states=r.projection(c)
            names={n:i for i,(n,_,_) in enumerate(r.fchmod_plan())};row=lambda n:c['calls'][names[n]]
            output=lambda n:struct.pack('<32I',*row(n)['stat_words'])
            self.assertEqual(len(c['calls']),303)
            self.assertEqual(r.stat_metadata(c['initial'])[1]['uid'],1002)
            for n in ('chmod_bad_fd','chmod_after_last_release','chmod_final_closed_fd'):self.assertEqual(row(n)['raw_bits'],(1<<64)-9)
            self.assertEqual(row('chmod_console_denied')['raw_bits'],(1<<64)-1)
            self.assertEqual(row('chmod_console_denied')['file_after']['mode'],0o100777)
            for n,mode in [('stat_mode_600',0o600),('stat_mode_640',0o640),('stat_mode_none',0),('stat_mode_readonly',0o400),('stat_mode_shared_alias',0o604),('stat_mode_restored_alias',0o640)]:
                b=output(n);self.assertEqual(struct.unpack_from('<I',b,16)[0],0o100000|mode,n)
                self.assertEqual(row(n)['file_after']['mode'],0o100000|mode,n)
                self.assertEqual(b[72:120],bytes(48));self.assertEqual(b[120:],bytes(8))
            self.assertEqual(row('read_initial')['raw_bits'],6);self.assertEqual(row('read_initial')['file_after']['mode'],0o100000)
            self.assertGreater(row('pwrite_alias_keeps_shared_position')['raw_bits'],0)
            self.assertEqual(row('stat_mode_shared_alias')['file_after']['pos'],row('pwrite_alias_keeps_shared_position')['file_after']['pos'])
            self.assertEqual(output('stat_mode_shared_alias')[8:16],output('stat_initial_regular')[8:16])
            # All old calls remain in order with the same return values, I/O bytes,
            # descriptor observations and content/position/allocation transitions.
            old=json.loads((ROOT/'tests/fixtures/linux-aarch64-fstat-native/capture.json').read_text());oldnames={n for n,_,_ in r.fstat_plan()};kept=[]
            def stable(v):
                v=json.loads(json.dumps(v));del v['stat_words'];del v['stat_digest']
                if v['file_after'] is not None:v['file_after'].pop('mode',None)
                return v
            kept=[stable(v) for (n,_,_),v in zip(r.fchmod_plan(),c['calls']) if n in oldnames]
            self.assertEqual(kept,[stable(v) for v in old['calls']])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(303,32,1088,964))
            self.assertEqual(len(result['syscalls']),23);self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual(result['pause_ordinals'],[99,103,146,214,218,276])
            self.assertEqual([s['inode_metadata'][1]['mode'] for s in result['saved_state']],[0o100600,0o100000,0o100400,0o100604,0o100640,0o100640])
            for s in result['saved_state']:
                self.assertEqual(s['file_mounts'],[1,2]);self.assertEqual(s['mount_ids'],[1,2])
                self.assertEqual(s['inode_metadata'][1]['uid'],1002)
                self.assertEqual(s['inode_metadata'][1]['mode'],s['file']['mode'])
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text());self.assertEqual(k['target_observations']['verified_calls'],909);self.assertEqual(k['target_observations']['isolation_checks'],606)
            spec=json.loads((stage/'pipeline/port/spec.json').read_text());self.assertEqual([(o['id'],o['bytes']) for o in spec['objects']],[(1,32),(2,128)])
            self.assertTrue(any(a['symbol']=='stat_digest' for a in spec['assertions']))
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
    def test_mode_owner_mount_and_inode_lock_mutants_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('p->i_mode=a->ia_mode;','(void)a;'),
                     ('if(p->uid!=current_euid())return -EPERM;','(void)p;'),
                     ('void mnt_drop_write(struct vfsmount *p){linux_assert(p->write_depth!=1);--p->write_depth;}','void mnt_drop_write(struct vfsmount *p){linux_assert(p->write_depth!=1);}'),
                     ('void inode_unlock(struct inode *p){linux_assert(p->lock_depth!=1);--p->lock_depth;}','void inode_unlock(struct inode *p){linux_assert(p->lock_depth!=1);}')]
            for i,(a,b) in enumerate(changes):
                bundle=stage/str(i);port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(a),1);p.write_text(s.replace(a,b));v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
    def test_source_abi_and_forged_native_mode_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,a,b in [('upstream/fs/open.c',b'newattrs.ia_valid = ATTR_MODE | ATTR_CTIME;',b'newattrs.ia_valid = ATTR_CTIME;'),('upstream/fs/open.c',b'err = vfs_fchmod(f.file, mode);',b'err = 0;'),('upstream/include/uapi/asm-generic/unistd.h',b'__NR_fchmod 52',b'__NR_fchmod 53')]:
                p=native/filename;s=p.read_bytes();self.assertIn(a,s);p.write_bytes(s.replace(a,b,1))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(s)
            p=native/'capture.json';v=json.loads(p.read_text());i=next(i for i,(n,_,_) in enumerate(reviewed_adapter().fchmod_plan()) if n=='chmod_owner_600');v['calls'][i]['file_after']['mode']=0o100777;p.write_text(json.dumps(v,indent=2)+'\n')
            log=native/'qemu.log';uart={k:x for k,x in v.items() if k!='format'};log.write_text(re.sub(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}$','OSREC_LINUX_CAPTURE '+json.dumps(uart),log.read_text(),flags=re.M))
            p=native/'capture.manifest.json';v=json.loads(p.read_text());v['capture_sha256']=digest((native/'capture.json').read_bytes());v['qemu_log_sha256']=digest(log.read_bytes());p.write_text(json.dumps(v,indent=2)+'\n')
            with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ'):build_bundle(native,stage/'bad-native')
            self.assertFalse((stage/'bad-native').exists())
if __name__=='__main__':unittest.main()
