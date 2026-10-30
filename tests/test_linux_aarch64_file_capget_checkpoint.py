"""Original capget queries in a persistent, combined Linux file session."""
import gzip,json,re,shutil,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from capture_linux_aarch64 import reviewed_adapter,profile_integration,digest
from generate_linux_aarch64_application import generate
from prepare_linux_aarch64_port import build_bundle
from run_linux_aarch64_checkpoint_pipeline import run,verify_pipeline
from export_syscall_slices import export
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-file-capget-native'
def prepare_capture(dst):
    shutil.copytree(FIXTURE,dst,ignore=shutil.ignore_patterns('root.ext2.gz'));(dst/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()));reviewed_adapter().validate_capture(dst);return dst
class LinuxFileCapgetTests(unittest.TestCase):
    def test_generated_witness_original_query_bodies_and_immutable_inputs(self):
        r=reviewed_adapter();p=profile_integration('file-capget');new,defs=r.source_identity(p);old,_=r.source_identity(profile_integration('file-status'));standalone,_=r.source_identity(profile_integration('capget'))
        self.assertEqual(len(defs),97);self.assertEqual(len(new['additional_sources']),10)
        self.assertEqual({n:new['definitions'][n] for n in old['definitions']},old['definitions'])
        for n in ('capget','cap_get_target_pid','cap_capget'):self.assertEqual(new['definitions'][n],standalone['definitions'][n])
        self.assertEqual(generate('file-capget'),(p/'application.c').read_text());self.assertEqual((p/'application.c').read_bytes(),(FIXTURE/'sources/application.c').read_bytes())
        self.assertIn(dict(number=90,function='linux_capget',arguments=['buffer','buffer']),json.loads((p/'port-template.json').read_text())['roots'])
        for i,(_,_,data) in enumerate(r.file_capget_plan()):
            expected=list(data) if data is not None else [0xa5a50000+j for j in range(8)];words=r.input_words('file-capget',i);self.assertEqual(words,expected);words[0]^=0xffffffff;self.assertEqual(r.input_words('file-capget',i),expected)
        for profile in ('fsuid','setresuid','uid-setters','credential-setters','fd-dup','file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status'):self.assertEqual(generate(profile),(profile_integration(profile)/'application.c').read_text())
    def test_live_queries_fault_prefixes_no_publication_and_fresh_resumes(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-capget-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,_=r.validate_capture(native);_,states=r.projection(c);plan=r.file_capget_plan();names={n:i for i,(n,_,_) in enumerate(plan)};row=lambda n:c['calls'][names['file_capget_'+n]]
            self.assertEqual(len(c['calls']),696);self.assertEqual(sum(entry['number']==90 for _,entry,_ in plan),66)
            for i,(_,entry,_) in enumerate(plan):
                if entry['number']==90:self.assertEqual(states[i],states[i+1])
            for n,e in [('initial',1),('fowner_gain',72),('fowner_drop',64),('root_gain',9),('root_drop',0),('final',0)]:self.assertEqual(row(n)['words'][2],e,n)
            for n in ('initial','initial_v2','initial_legacy','fowner_gain','fowner_drop','root_gain','root_drop','final','aliased_output','aliased_v2','legacy','unknown_null','null_negative_pid','tail_null'):self.assertEqual(row(n)['raw_bits'],0,n)
            self.assertEqual(row('unknown_null')['words'][0],0x20080522);self.assertEqual(row('unknown_output')['words'][0],0x20080522)
            for n in ('unknown_output','negative_pid'):self.assertEqual(row(n)['raw_bits'],(1<<64)-22,n)
            self.assertEqual(row('missing_pid')['raw_bits'],(1<<64)-3)
            for n in ('tail_pid_fault','guard_output','partial_output','partial_output_v2','partial_legacy','null_header','bad_header','bad_output'):self.assertEqual(row(n)['raw_bits'],(1<<64)-14,n)
            for n in ('partial_output','partial_output_v2','partial_legacy'):self.assertEqual(row(n)['words'][6:],[64,r.FILE_CAP_INITIAL|64])
            self.assertEqual(row('aliased_output')['words'][:6],[64,r.FILE_CAP_INITIAL|64,0,0,0,0]);self.assertEqual(row('legacy')['words'][5:],[0xa5a50005,0xa5a50006,0xa5a50007])
            old=json.loads((ROOT/'tests/fixtures/linux-aarch64-file-status-native/capture.json').read_text());oldnames={n for n,_,_ in r.file_status_plan()};self.assertEqual([v for (n,_,_),v in zip(plan,c['calls']) if n in oldnames],old['calls'])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU));self.assertEqual((result['logical_calls'],len(result['syscalls']),result['qemu_matrix_executions']),(696,33,32));self.assertFalse(result['runtime_host_interaction']);self.assertEqual(result['pause_ordinals'],[193,198,208,359,365,695])
            self.assertEqual((result['context_bytes'],result['record_bytes']),(1336,1188))
            for st in result['saved_state']:
                expected=states[st['ordinal']];cred=expected['file_credentials'];self.assertEqual(st['file_capability_pool'],cred['caps']);self.assertEqual(st['generation'],cred['generation']);self.assertEqual(st['file_flags'],expected['file_status']);self.assertEqual(st['file_gid_pool'],cred['gids']);self.assertEqual(st['file_fsuids'],cred['fsuids'])
            final=states[-1]['file_credentials'];self.assertEqual((final['generation'],final['epochs'],final['active']),(83,[82,83],1))
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text());self.assertEqual((k['target_observations']['verified_calls'],k['target_observations']['isolation_checks']),(2088,1392));shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
    def test_live_capability_copy_and_target_lookup_mutants_reject_at_runtime(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-capget-mutants-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('return cap_capget(target,e,i,p);','int result=cap_capget(target,e,i,p);e->val=1;return result;'),
                     ('return cap_capget(target,e,i,p);','return cap_capget(target,e,p,i);'),
                     ('    if(!r)return count;','    if(!r)return count;\n    if(capacity==32 && (uintptr_t)out-r->user_address==24)return count;'),
                     ('return pid==current->pid ? current : 0;','(void)pid;return current;')]
            for i,(a,b) in enumerate(changes):
                bundle=stage/str(i);port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(a),1);p.write_text(s.replace(a,b));v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
    def test_original_query_and_jointly_forged_native_evidence_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-capget-forged-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            p=native/'upstream/kernel/capability.c';original=p.read_bytes();self.assertIn(b'if (pid < 0)',original);p.write_bytes(original.replace(b'if (pid < 0)',b'if (pid <= 0)',1))
            with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
            self.assertFalse((stage/'bad-source').exists());p.write_bytes(original)
            original={n:(native/n).read_bytes() for n in ('capture.json','qemu.log','capture.manifest.json')};names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_capget_plan())}
            for field in ('live','partial','pid','alias','version'):
                v=json.loads(original['capture.json'])
                if field=='live':v['calls'][names['file_capget_fowner_gain']]['words'][2]=64
                elif field=='partial':v['calls'][names['file_capget_partial_output']]['words'][6]=72
                elif field=='pid':v['calls'][names['file_capget_missing_pid']]['raw_bits']=0
                elif field=='alias':v['calls'][names['file_capget_aliased_output']]['words'][0]=0x20080522
                else:v['calls'][names['file_capget_unknown_null']]['words'][0]=0
                (native/'capture.json').write_text(json.dumps(v,indent=2)+'\n');uart={k:x for k,x in v.items() if k!='format'};altered,count=re.subn(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}\r?$','OSREC_LINUX_CAPTURE '+json.dumps(uart),original['qemu.log'].decode(),flags=re.M);self.assertEqual(count,1);(native/'qemu.log').write_text(altered)
                m=json.loads(original['capture.manifest.json']);m['capture_sha256']=digest((native/'capture.json').read_bytes());m['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(m,indent=2)+'\n')
                with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ'):build_bundle(native,stage/'bad-native')
                self.assertFalse((stage/'bad-native').exists())
                for n,data in original.items():(native/n).write_bytes(data)
if __name__=='__main__':unittest.main(verbosity=2)
