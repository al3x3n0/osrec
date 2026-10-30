"""Shared memfd status flags, append callbacks and credential-sensitive NOATIME."""
import gzip,json,re,shutil,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from capture_linux_aarch64 import reviewed_adapter,digest
from generate_linux_aarch64_application import generate
from prepare_linux_aarch64_port import build_bundle
from run_linux_aarch64_checkpoint_pipeline import run,verify_pipeline
from export_syscall_slices import export
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-file-status-native'
def prepare_capture(dst):
    shutil.copytree(FIXTURE,dst,ignore=shutil.ignore_patterns('root.ext2.gz'));(dst/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()));reviewed_adapter().validate_capture(dst);return dst
class LinuxFileStatusTests(unittest.TestCase):
    def test_generated_witness_original_dependencies_and_flag_abi(self):
        r=reviewed_adapter();p=ROOT/'integrations/linux_aarch64/file-status';new,defs=r.source_identity(p);old,_=r.source_identity(ROOT/'integrations/linux_aarch64/file-group-setters')
        self.assertEqual(new['definitions'],old['definitions']);self.assertEqual(len(defs),94);self.assertEqual(len(new['additional_sources']),10)
        self.assertNotIn('setfl',defs);self.assertIn('setfl body not retained',new['scope'])
        self.assertEqual(generate('file-status'),(p/'application.c').read_text());self.assertEqual((p/'application.c').read_bytes(),(FIXTURE/'sources/application.c').read_bytes())
        self.assertIn('#define F_SETFL 4',(p/'upstream/include/uapi/asm-generic/fcntl.h').read_text())
        policy=json.loads((p/'checkpoint-policy.json').read_text());self.assertEqual(policy['fields']['file_pool']['element']['members']['f_flags'],dict(type='uint32_t',policy='persist'))
        for i,(_,_,data) in enumerate(r.file_status_plan()):
            expected=list(data) if data is not None else [0xa5a50000+j for j in range(8)];words=r.input_words('file-status',i);self.assertEqual(words,expected);words[0]^=0xffffffff;self.assertEqual(r.input_words('file-status',i),expected)
    def test_live_flags_append_noatime_aliases_and_joint_resumes(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-status-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,_=r.validate_capture(native);_,states=r.projection(c);names={n:i for i,(n,_,_) in enumerate(r.file_status_plan())};row=lambda n:c['calls'][names['file_status_'+n]]
            self.assertEqual(len(c['calls']),630)
            for n,value in [('get_shared',134146),('get_new_alias',134146),('get_cleared',133122),('get_narrow',132098),('get_retained',395266),('get_after_drop',394242)]:self.assertEqual(row(n)['raw_bits'],value,n)
            for n,size,pos,raw in [('write_append',20,20,4),('pwrite_append',24,2,4),('pwrite_high_append',28,2,4),('append_partial',32,32,4),('append_fault',32,5,(1<<64)-14),('append_zero',32,5,0),('pwrite_zero',32,5,0),('negative_pwrite',32,5,(1<<64)-22),('write_overwrite',32,5,4),('pwrite_normal',32,5,4),('write_survivor',36,36,4),('stat_restored',16,0,0)]:
                v=row(n);self.assertEqual((v['file_after']['size'],v['file_after']['pos'],v['raw_bits']),(size,pos,raw),n)
            self.assertEqual(row('stat_append')['file_after']['bytes'][16:20],list(b'APND'));self.assertEqual(row('stat_pwrite')['file_after']['bytes'][20:24],list(b'PWRT'));self.assertEqual(row('append_partial')['file_after']['bytes'][28:32],list(b'PART'))
            self.assertEqual(row('get_alias_cloexec')['raw_bits'],0)
            alias=row('stat_alias');self.assertEqual(alias['fds_after'][3:6],[[2,1],[2,1],[2,1]]);self.assertEqual(alias['fd_status_after'][3:6],[134146]*3)
            self.assertEqual(row('reinstall_original')['raw_bits'],3);self.assertEqual(row('close_original')['fd_status_after'][3],None)
            for n in ('owner_noatime','retain_noatime','clear_noatime','capable_noatime','retain_after_drop','clear_after_drop'):self.assertEqual(row(n)['raw_bits'],0,n)
            for n in ('noatime_denied','denied_after_drop'):
                i=names['file_status_'+n];self.assertEqual(row(n)['raw_bits'],(1<<64)-1);self.assertEqual(states[i],states[i+1])
            self.assertEqual(row('bad_fd_flags')['raw_bits'],(1<<64)-9)
            old=json.loads((ROOT/'tests/fixtures/linux-aarch64-file-group-setters-native/capture.json').read_text());oldnames={n for n,_,_ in r.file_group_setters_plan()}
            def stable(v):
                v=dict(v);v.pop('fd_status_after',None);v.pop('stat_digest',None);return v
            self.assertEqual([stable(v) for (n,_,_),v in zip(r.file_status_plan(),c['calls']) if n in oldnames],[stable(v) for v in old['calls']])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU));self.assertEqual((result['logical_calls'],len(result['syscalls']),result['qemu_matrix_executions']),(630,32,32));self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual([s['file_flags'][1] for s in result['saved_state']],[134146,134146,134146,132098,133122,131074]);self.assertEqual([s['file']['pos'] for s in result['saved_state']],[20,2,5,36,36,0]);self.assertEqual([s['file']['size'] for s in result['saved_state']],[20,24,32,36,36,16]);self.assertEqual([s['fsuid'] for s in result['saved_state']],[1002,1002,1002,1002,1001,1002])
            self.assertEqual(result['saved_state'][-1]['cloexec'],40);self.assertEqual(result['saved_state'][-1]['fd_slots'][5],0)
            for s in result['saved_state']:
                expected=states[s['ordinal']];self.assertEqual(s['file_flags'],expected['file_status']);self.assertEqual(s['file_capability_pool'],expected['file_credentials']['caps']);self.assertEqual(s['file_gid_pool'],expected['file_credentials']['gids'])
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text());self.assertEqual((k['target_observations']['verified_calls'],k['target_observations']['isolation_checks']),(1890,1260));shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
    def test_append_position_protected_flags_and_noatime_mutants_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-status-mutants-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('if(writing && count && (p->f_flags&O_APPEND))','if(0)'),
                     ('ssize_t vfs_write(struct file *p,const char *buf,size_t count,loff_t *pos){return regular_transfer(p,(uintptr_t)buf,count,pos,1);}','ssize_t vfs_write(struct file *p,const char *buf,size_t count,loff_t *pos){ssize_t n=regular_transfer(p,(uintptr_t)buf,count,pos,1);if(n>0)p->f_pos=*pos;return n;}'),
                     ('p->f_flags=(p->f_flags&~mask)|(flags&mask);','p->f_flags=(flags&mask);'),
                     ('if((flags&O_NOATIME) && !(p->f_flags&O_NOATIME) &&','if((flags&O_NOATIME) && 0 &&'),
                     ('if((flags&O_NOATIME) && !(p->f_flags&O_NOATIME) &&','if((flags&O_NOATIME) &&'),
                     ('case 3:result=p->f_flags;break;','case 3:result=p->object_id==2 ? LINUX_INITIAL_FILE_FLAGS_1 : LINUX_INITIAL_FILE_FLAGS_0;break;')]
            for i,(a,b) in enumerate(changes):
                bundle=stage/str(i);port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(a),1);p.write_text(s.replace(a,b));v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
    def test_original_source_flag_abi_and_jointly_forged_evidence_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-status-forged-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,a,b in [('upstream/kernel/sys.c',b'new->sgid = new->egid;',b'new->sgid = old->sgid;'),('upstream/include/uapi/asm-generic/fcntl.h',b'#define F_SETFL 4',b'#define F_SETFL 5')]:
                p=native/filename;s=p.read_bytes();self.assertIn(a,s);p.write_bytes(s.replace(a,b,1))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(s)
            original={n:(native/n).read_bytes() for n in ('capture.json','qemu.log','capture.manifest.json')};names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_status_plan())}
            for field in ('alias','position','partial','permission','ignored'):
                v=json.loads(original['capture.json'])
                if field=='alias':v['calls'][names['file_status_get_shared']]['fd_status_after'][4]=131074
                elif field=='position':v['calls'][names['file_status_pwrite_append']]['file_after']['pos']=24
                elif field=='partial':v['calls'][names['file_status_append_partial']]['raw_bits']=8
                elif field=='permission':v['calls'][names['file_status_noatime_denied']]['raw_bits']=0
                else:v['calls'][names['file_status_append_nonblock_ignored']]['fds_after'][4][1]=1
                (native/'capture.json').write_text(json.dumps(v,indent=2)+'\n');uart={k:x for k,x in v.items() if k!='format'};altered,count=re.subn(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}\r?$','OSREC_LINUX_CAPTURE '+json.dumps(uart),original['qemu.log'].decode(),flags=re.M);self.assertEqual(count,1);(native/'qemu.log').write_text(altered)
                m=json.loads(original['capture.manifest.json']);m['capture_sha256']=digest((native/'capture.json').read_bytes());m['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(m,indent=2)+'\n')
                with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ'):build_bundle(native,stage/'bad-native')
                self.assertFalse((stage/'bad-native').exists())
                for n,data in original.items():(native/n).write_bytes(data)
if __name__=='__main__':unittest.main(verbosity=2)
