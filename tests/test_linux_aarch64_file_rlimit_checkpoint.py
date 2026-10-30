"""Original getrlimit queries share retained file-session resource state."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-file-rlimit-native'
LIMITS=[[(1<<64)-1]*2,[8,8]]
def prepare_capture(dst):
    shutil.copytree(FIXTURE,dst,ignore=shutil.ignore_patterns('root.ext2.gz'));(dst/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()));reviewed_adapter().validate_capture(dst);return dst
class LinuxFileRlimitTests(unittest.TestCase):
    def test_generated_witness_original_wrapper_and_complete_route_union(self):
        r=reviewed_adapter();p=profile_integration('file-rlimit');identity,defs=r.source_identity(p);old,_=r.source_identity(profile_integration('file-credentials'))
        self.assertEqual(len(defs),109);self.assertEqual(len(identity['additional_sources']),11)
        self.assertEqual({n:identity['definitions'][n] for n in old['definitions']},old['definitions'])
        self.assertIn(b'do_prlimit(current, resource, NULL, &value)',defs['getrlimit']['body']);self.assertNotIn('do_prlimit',defs)
        self.assertEqual(generate('file-rlimit'),(p/'application.c').read_text());self.assertEqual((p/'application.c').read_bytes(),(FIXTURE/'sources/application.c').read_bytes())
        port=json.loads((p/'port-template.json').read_text());routes={v['number'] for v in port['roots']};all_routes=set();buffer_kinds={v['number']:[k=='buffer' for k in v['arguments']] for v in port['roots']}
        for profile in PROFILES:
            roots=json.loads((profile_integration(profile)/'port-template.json').read_text())['roots'];all_routes.update(v['number'] for v in roots)
            for v in roots:
                if v['number'] in buffer_kinds:self.assertEqual([k=='buffer' for k in v['arguments']],buffer_kinds[v['number']],(profile,v['number']))
            if profile in ('minimal','credentials','fsgid','group-setters','getgroups','setgroups','setgroups-denied','capabilities','capget','prctl'):continue
            self.assertEqual(generate(profile),(profile_integration(profile)/'application.c').read_text())
        self.assertTrue(routes<=all_routes);self.assertEqual(len(routes),38)
        manifest=json.loads((FIXTURE/'capture.manifest.json').read_text());self.assertEqual(manifest['source_sha256']['linux-native-arguments.h'],digest((FIXTURE/'sources/linux-native-arguments.h').read_bytes()))
        for i,(_,entry,data) in enumerate(r.file_rlimit_plan()):
            expected=list(data) if data is not None else [0xa5a50000+j for j in range(8)];words=r.input_words('file-rlimit',i);self.assertEqual(words,expected);words[0]^=1;self.assertEqual(r.input_words('file-rlimit',i),expected);self.assertEqual(len(entry['args']),5)
    def test_live_queries_fault_precedence_retained_limits_and_joint_resumes(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-rlimit-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,_=r.validate_capture(native);rows,states=r.projection(c);plan=r.file_rlimit_plan();names={n:i for i,(n,_,_) in enumerate(plan)};row=lambda n:rows[names['file_rlimit_'+n]]
            self.assertEqual(len(rows),851);self.assertEqual(c['initial']['nofile_limit'],[8,8]);self.assertEqual(c['initial']['nproc_limit'],LIMITS[0])
            self.assertEqual(row('initial_nofile')['words'][:4],[8,0,8,0]);self.assertEqual(row('initial_nproc')['words'][2:6],[0xffffffff]*4)
            self.assertEqual(row('end_aligned')['words'][4:8],[8,0,8,0]);self.assertEqual(row('unaligned')['words'][1:5],[0xffffffff]*4);self.assertEqual(row('narrow_resource')['words'][2:6],[8,0,8,0])
            for n in ('invalid_resource','invalid_null','invalid_bad_address','narrow_invalid'):
                self.assertEqual(row(n)['raw_bits'],(1<<64)-22);self.assertEqual(row(n)['words'],row(n)['input_words'])
            for n in ('null_nofile','bad_nproc','guard_nofile','partial_nofile','partial_nproc'):self.assertEqual(row(n)['raw_bits'],(1<<64)-14)
            self.assertEqual(row('guard_nofile')['words'],row('guard_nofile')['input_words'])
            self.assertEqual(row('partial_nofile')['words'][6:],[8,0]);self.assertEqual(row('partial_nofile')['words'][:6],row('partial_nofile')['input_words'][:6]);self.assertEqual(row('partial_nproc')['words'][6:],[0xffffffff]*2)
            self.assertEqual(row('table_full_nofile')['words'][:4],[8,0,8,0]);self.assertIsNone(row('last_release_nproc')['file_after'])
            for i,(n,_,_) in enumerate(plan):
                self.assertEqual(rows[i]['file_rlimits_after'],LIMITS)
                if n.startswith('file_rlimit_'):self.assertEqual(states[i],states[i+1],n)
            inherited=[];oldnames={n for n,_,_ in r.file_credentials_plan()}
            for (n,_,_),v in zip(plan,rows):
                if n in oldnames:v=dict(v);v.pop('file_rlimits_after');inherited.append(v)
            self.assertEqual(inherited,json.loads((ROOT/'tests/fixtures/linux-aarch64-file-credentials-native/capture.json').read_text())['calls'])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU));self.assertEqual((result['logical_calls'],len(result['syscalls']),result['qemu_matrix_executions']),(851,38,32));self.assertFalse(result['runtime_host_interaction']);self.assertEqual(result['pause_ordinals'],[33,34,39,51,758,820]);self.assertEqual((result['context_bytes'],result['record_bytes']),(1520,1324))
            for st in result['saved_state']:self.assertEqual(st['resource_limits'],LIMITS)
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text());self.assertEqual((k['target_observations']['verified_calls'],k['target_observations']['isolation_checks']),(2553,1702))
            for j in range(2):
                for field in ('rlim_cur','rlim_max'):
                    f=next(v for v in k['checkpoint_codec']['fields'] if v['path']==f'resource_limits[{j}].{field}');self.assertEqual(f['policy'],'persist');self.assertIn('wire_offset',f)
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
    def test_model_wrong_resource_truncation_ordering_and_partial_copy_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-rlimit-mutants-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('return &resource_limits[resource==RLIMIT_NOFILE];','return &resource_limits[resource!=RLIMIT_NOFILE];'),
                     ('*old_rlim=*resource_limit(resource);return 0;','*old_rlim=*resource_limit(resource);old_rlim->rlim_cur&=UINT32_MAX;return 0;'),
                     ('if(resource>=RLIM_NLIMITS)return -EINVAL;','if(resource>=RLIM_NLIMITS){old_rlim->rlim_cur=0;old_rlim->rlim_max=0;return 0;}'),
                     ('if(!r)return count;\n    size_t copied=0;','if(!r)return count;\n    if(count==16 && (uintptr_t)out-r->user_address==24)return count;\n    size_t copied=0;')]
            for i,(a,b) in enumerate(changes):
                bundle=stage/str(i);port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(a),1);p.write_text(s.replace(a,b));v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
    def test_original_wrapper_abi_and_jointly_forged_observations_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-rlimit-forged-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,a,b in [('upstream/kernel/sys.c',b'copy_to_user(rlim, &value, sizeof(*rlim))',b'copy_to_user(rlim, &value, sizeof(value.rlim_cur))'),('upstream/include/uapi/asm-generic/unistd.h',b'#define __NR_getrlimit 163',b'#define __NR_getrlimit 164')]:
                p=native/filename;original=p.read_bytes();self.assertEqual(original.count(a),1);p.write_bytes(original.replace(a,b))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(original)
            original={n:(native/n).read_bytes() for n in ('capture.json','qemu.log','capture.manifest.json')};names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_rlimit_plan())}
            for field in ('nproc','nofile','query','partial','ordering'):
                v=json.loads(original['capture.json']);at=lambda n:v['calls'][names['file_rlimit_'+n]]
                if field=='nproc':at('initial_nproc')['file_rlimits_after'][0][0]=0xffffffff
                elif field=='nofile':at('initial_nofile')['file_rlimits_after'][1][1]=7
                elif field=='query':at('initial_nofile')['words'][0]=7
                elif field=='partial':at('partial_nofile')['words'][6]=0xa5a50006
                else:at('invalid_null')['raw_bits']=(1<<64)-14
                (native/'capture.json').write_text(json.dumps(v,indent=2)+'\n');uart={k:x for k,x in v.items() if k!='format'};altered,count=re.subn(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}\r?$','OSREC_LINUX_CAPTURE '+json.dumps(uart),original['qemu.log'].decode(),flags=re.M);self.assertEqual(count,1);(native/'qemu.log').write_text(altered)
                m=json.loads(original['capture.manifest.json']);m['capture_sha256']=digest((native/'capture.json').read_bytes());m['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(m,indent=2)+'\n')
                with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ'):build_bundle(native,stage/'bad-native')
                self.assertFalse((stage/'bad-native').exists())
                for n,data in original.items():(native/n).write_bytes(data)
if __name__=='__main__':unittest.main(verbosity=2)
