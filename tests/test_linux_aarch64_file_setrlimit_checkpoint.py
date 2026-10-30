"""Original limit updates affect retained descriptor admission and survive resumes."""
import gzip,json,re,shutil,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from capture_linux_aarch64 import PROFILES,reviewed_adapter,profile_integration,digest
from generate_linux_aarch64_application import generate
from prepare_linux_aarch64_port import build_bundle
from run_linux_aarch64_checkpoint_pipeline import run,verify_pipeline
from export_syscall_slices import export
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-file-setrlimit-native'
INF=(1<<64)-1
def prepare_capture(dst):
    shutil.copytree(FIXTURE,dst,ignore=shutil.ignore_patterns('root.ext2.gz'));(dst/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()));reviewed_adapter().validate_capture(dst);return dst
class LinuxFileSetrlimitTests(unittest.TestCase):
    def test_original_helper_witness_complete_routes_and_input_snapshots(self):
        r=reviewed_adapter();p=profile_integration('file-setrlimit');identity,defs=r.source_identity(p);old,_=r.source_identity(profile_integration('file-limits'))
        self.assertEqual(len(defs),111);self.assertEqual({n:identity['definitions'][n] for n in old['definitions']},old['definitions']);self.assertEqual(identity['additional_sources'],old['additional_sources'])
        self.assertEqual(defs['do_prlimit']['declaration'].split('(')[0],'static int do_prlimit');self.assertIn(b'*rlim = *new_rlim;',defs['do_prlimit']['body']);self.assertIn(b'copy_from_user(&new_rlim, rlim, sizeof(*rlim))',defs['setrlimit']['body'])
        self.assertEqual(generate('file-setrlimit'),(p/'application.c').read_text());self.assertEqual((p/'application.c').read_bytes(),(FIXTURE/'sources/application.c').read_bytes())
        routes={v['number'] for v in json.loads((p/'port-template.json').read_text())['roots']};union={v['number'] for profile in PROFILES for v in json.loads((profile_integration(profile)/'port-template.json').read_text())['roots']};self.assertEqual(routes,union);self.assertEqual(len(routes),39)
        for i,(_,_,data) in enumerate(r.file_setrlimit_plan()):
            expected=list(data) if data is not None else [0xa5a50000+j for j in range(8)];words=r.input_words('file-setrlimit',i);self.assertEqual(words,expected);words[0]^=1;self.assertEqual(r.input_words('file-setrlimit',i),expected)
        self.assertNotIn('int do_prlimit(', (p/'models.c').read_text());self.assertNotIn('int do_prlimit(', (p/'model.h').read_text())
    def test_live_limit_changes_descriptor_admission_and_joint_resumes(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-setrlimit-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,_=r.validate_capture(native);rows,states=r.projection(c);plan=r.file_setrlimit_plan();names={n:i for i,(n,_,_) in enumerate(plan)};at=lambda n:rows[names['file_setrlimit_'+n]]
            self.assertEqual(len(rows),973);self.assertEqual(at('lower_nofile')['file_all_rlimits_after'][7],[4,8])
            for n,errno in [('dup_denied',24),('dup3_denied',9),('fcntl_min_denied',22),('hard_raise_denied',1),('soft_exceeds_hard',22),('invalid_resource',22),('invalid_null',14),('null_nofile',14),('bad_pointer',14),('guard_pointer',14),('partial_input',14),('raise_memlock_hard_denied',1),('raise_nofile_hard_denied',1)]:self.assertEqual(at(n)['raw_bits'],(1<<64)-errno,n)
            self.assertEqual(at('existing_fd_usable')['raw_bits'],1);self.assertEqual(at('dup_restored')['raw_bits'],4);self.assertEqual(at('read_restored_nofile')['words'][4:],[8,0,8,0])
            self.assertEqual(at('unchanged_after_fault')['file_all_rlimits_after'][7],[8,8]);self.assertEqual(at('read_wide_core')['words'][1:5],[3,1,0xffffffff,0xffffffff])
            self.assertEqual(at('raise_memlock_hard_denied')['file_all_rlimits_after'][8],[2097152,4194304]);self.assertEqual(at('raise_memlock_soft')['file_all_rlimits_after'][8],[4194304]*2)
            final=at('final_15')['file_all_rlimits_after'];self.assertEqual(final[3],[4194304,INF]);self.assertEqual(final[4],[0x100000003,INF]);self.assertEqual(final[7],[4,5]);self.assertEqual(final[8],[4194304]*2)
            oldnames={n for n,_,_ in r.file_limits_plan()};self.assertEqual([row for (n,_,_),row in zip(plan,rows) if n in oldnames],json.loads((ROOT/'tests/fixtures/linux-aarch64-file-limits-native/capture.json').read_text())['calls'])
            for i,((n,entry,_),row) in enumerate(zip(plan,rows)):
                self.assertEqual(row['file_all_rlimits_after'],states[i+1]['resource_limits'])
                if entry['number']==164:
                    self.assertEqual(row['words'],row['input_words'])
                    if row['raw_bits']:self.assertEqual(states[i],states[i+1],n)
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU));self.assertEqual((result['logical_calls'],len(result['syscalls']),result['qemu_matrix_executions']),(973,39,32));self.assertFalse(result['runtime_host_interaction']);self.assertEqual((result['context_bytes'],result['record_bytes']),(1784,1552))
            self.assertEqual(result['pause_ordinals'],[names['file_setrlimit_'+n]+1 for n in ('dup_denied','dup_restored','wide_core','lower_memlock_hard','raise_memlock_hard_denied','raise_nofile_hard_denied')])
            for st in result['saved_state']:
                self.assertEqual(st['resource_limits'],rows[st['ordinal']-1]['file_all_rlimits_after']);self.assertEqual(st['nofile_limit'],st['resource_limits'][7][0])
            self.assertEqual(result['saved_state'][0]['resource_limits'][7],[4,8]);self.assertEqual(result['saved_state'][-1]['resource_limits'][7],[4,5])
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text());self.assertEqual((k['target_observations']['verified_calls'],k['target_observations']['isolation_checks']),(2919,1946))
            fields={v['path']:v for v in k['checkpoint_codec']['fields']}
            for j in range(16):
                for field in ('rlim_cur','rlim_max'):self.assertEqual(fields[f'process_signal.rlim[{j}].{field}']['policy'],'persist')
            for field in ('task.signal','task.group_leader'):self.assertEqual(fields[field]['policy'],'self_reference');self.assertNotIn('wire_offset',fields[field])
            self.assertEqual(fields['resource_lock_depth']['policy'],'persist');shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
    def test_faulty_admission_capability_width_and_input_fault_models_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-setrlimit-mutants-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('return resource_limit(resource)->rlim_cur;','return resource==RLIMIT_NOFILE ? 8 : resource_limit(resource)->rlim_cur;'),
                     ('return ns_capable(current_user_ns(),cap);','return cap==CAP_SYS_RESOURCE || ns_capable(current_user_ns(),cap);'),
                     ('return linux_assert(p!=current || resource_lock_depth!=1 || !value || (resource!=3 && resource!=4 && resource!=7 && resource!=8)) ? -EINVAL : 0;','if(linux_assert(p!=current || resource_lock_depth!=1 || !value || (resource!=3 && resource!=4 && resource!=7 && resource!=8)))return -EINVAL;value->rlim_cur&=UINT32_MAX;return 0;'),
                     ('if(!source){for(unsigned long k=j;k<n;++k)destination[k]=0;return n-j;}','if(!source){for(unsigned long k=j;k<n;++k)destination[k]=0;if(n==16 && (uintptr_t)in-r->user_address==24)return 0;return n-j;}')]
            for i,(a,b) in enumerate(changes):
                port=build_bundle(native,stage/str(i));p=port.parent/'models.c';s=p.read_text();self.assertEqual(s.count(a),1);p.write_text(s.replace(a,b));v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
    def test_original_source_abi_and_jointly_forged_updates_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-setrlimit-forged-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,a,b in [('upstream/kernel/sys.c',b'*rlim = *new_rlim;',b'*rlim = *old_rlim;'),('upstream/include/uapi/asm-generic/unistd.h',b'#define __NR_setrlimit 164',b'#define __NR_setrlimit 165')]:
                p=native/filename;original=p.read_bytes();self.assertEqual(original.count(a),1);p.write_bytes(original.replace(a,b))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(original)
            original={n:(native/n).read_bytes() for n in ('capture.json','qemu.log','capture.manifest.json')};names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_setrlimit_plan())}
            for field in ('update','admission','fault_order','wide','hard_denial','input'):
                v=json.loads(original['capture.json']);at=lambda n:v['calls'][names['file_setrlimit_'+n]]
                if field=='update':at('lower_nofile')['file_all_rlimits_after'][7][0]=8
                elif field=='admission':at('dup_denied')['raw_bits']=4
                elif field=='fault_order':at('invalid_null')['raw_bits']=(1<<64)-22
                elif field=='wide':at('wide_core')['file_all_rlimits_after'][4][0]=3
                elif field=='hard_denial':at('raise_memlock_hard_denied')['file_all_rlimits_after'][8][1]=8388608
                else:at('lower_nofile')['input_words'][0]=5
                (native/'capture.json').write_text(json.dumps(v,indent=2)+'\n');altered,count=re.subn(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}\r?$','OSREC_LINUX_CAPTURE '+json.dumps({k:x for k,x in v.items() if k!='format'}),original['qemu.log'].decode(),flags=re.M);self.assertEqual(count,1);(native/'qemu.log').write_text(altered);m=json.loads(original['capture.manifest.json']);m['capture_sha256']=digest((native/'capture.json').read_bytes());m['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(m,indent=2)+'\n')
                with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ'):build_bundle(native,stage/'bad-native')
                self.assertFalse((stage/'bad-native').exists())
                for n,data in original.items():(native/n).write_bytes(data)
if __name__=='__main__':unittest.main(verbosity=2)
