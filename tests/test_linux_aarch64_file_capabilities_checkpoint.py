"""Original capset publication controls file ownership/mode across joint resumes."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-file-capabilities-native'
def prepare_capture(dst):
    shutil.copytree(FIXTURE,dst,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (dst/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(dst);return dst
class LinuxFileCapabilitiesTests(unittest.TestCase):
    def test_generated_witness_original_capset_and_typed_credential_policy(self):
        r=reviewed_adapter();p=ROOT/'integrations/linux_aarch64/file-capabilities'
        self.assertEqual(generate('file-capabilities'),(p/'application.c').read_text())
        self.assertEqual((p/'application.c').read_bytes(),(FIXTURE/'sources/application.c').read_bytes())
        old,_=r.source_identity(ROOT/'integrations/linux_aarch64/fchown-capable');new,defs=r.source_identity(p)
        cap,_=r.source_identity(ROOT/'integrations/linux_aarch64/capabilities')
        self.assertEqual(len(defs),72)
        for n,h in old['definitions'].items():self.assertEqual(new['definitions'][n],h)
        for n in ('capset','cap_validate_magic','mk_kernel_cap','cap_inh_is_capped','cap_capset'):self.assertEqual(new['definitions'][n],cap['definitions'][n])
        self.assertIn(b'abort_creds(new);',defs['capset']['body'])
        policy=json.loads((p/'checkpoint-policy.json').read_text())['fields']
        self.assertEqual(policy['task']['members']['cred']['targets'],['credential_pool[0]','credential_pool[1]'])
        self.assertEqual(policy['pending_credential']['policy'],'transient')
        self.assertEqual(policy['credential_pool']['element']['members']['cap_permitted']['members']['val']['policy'],'persist')
        v=json.loads((p/'port-template.json').read_text());v['roots']=[x for x in v['roots'] if x['number']!=91]
        with self.assertRaisesRegex(ValueError,'no reviewed route'):r.application_source('file-capabilities',v)
    def test_live_authority_permitted_removal_candidate_abort_and_resumes(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-capabilities-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,_=r.validate_capture(native);_,states=r.projection(c)
            names={n:i for i,(n,_,_) in enumerate(r.file_capabilities_plan())};row=lambda n:c['calls'][names[n]]
            self.assertEqual(len(c['calls']),369);self.assertEqual(c['initial']['file_capabilities'],[1,r.FILE_CAP_INITIAL,0,(1<<41)-1,0])
            for n in ('file_caps_transfer_denied','file_caps_bad_pid','file_caps_subset_denied','file_caps_inheritable_denied','file_caps_reclaim_denied','file_caps_chmod_denied','file_caps_alias_denied','file_caps_permanent_transfer_denied','file_caps_regain_removed_denied','file_caps_regain_fowner_denied'):self.assertEqual(row(n)['raw_bits'],(1<<64)-1,n)
            self.assertEqual(row('file_caps_bad_version')['raw_bits'],(1<<64)-22);self.assertEqual(row('file_caps_bad_version')['words'][0],0x20080522)
            for n in ('file_caps_guard_copy','file_caps_null_header'):self.assertEqual(row(n)['raw_bits'],(1<<64)-14)
            for n in ('file_caps_drop_chown','file_caps_regain_chown','file_caps_transfer_again','file_caps_fowner_only','file_caps_chmod_foreign','file_caps_both','file_caps_reclaim','file_caps_remove_chown_permitted','file_caps_remove_fowner_permitted'):self.assertEqual(row(n)['raw_bits'],0,n)
            self.assertEqual(row('file_caps_chmod_foreign')['file_after']['uid'],9001);self.assertEqual(row('file_caps_chmod_foreign')['file_after']['mode'],0o100400)
            self.assertEqual(row('file_caps_chmod_foreign')['file_caps_after'],[8,r.FILE_CAP_INITIAL,0])
            self.assertEqual(row('file_caps_stat_dropped_mode')['file_after']['mode'],0o100400)
            self.assertEqual(row('file_caps_stat_alias')['file_after']['uid'],9002)
            self.assertEqual(row('file_caps_stat_all_removed')['file_caps_after'],[0,r.FILE_CAP_BOOT,0])
            i=names['file_caps_subset_denied'];before=states[i]['file_credentials'];after=states[i+1]['file_credentials']
            self.assertEqual((after['active'],after['generation'],after['epochs']),(before['active'],before['generation'],before['epochs']))
            self.assertEqual(after['caps'][1-after['active']],before['caps'][before['active']])
            old=json.loads((ROOT/'tests/fixtures/linux-aarch64-fchown-capable-native/capture.json').read_text());oldnames={n for n,_,_ in r.fchown_capable_plan()}
            def stable(v):
                v=json.loads(json.dumps(v));v.pop('file_caps_after',None);del v['stat_digest'];return v
            self.assertEqual([stable(v) for (n,_,_),v in zip(r.file_capabilities_plan(),c['calls']) if n in oldnames],[stable(v) for v in old['calls']])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions']),(369,32));self.assertEqual(len(result['syscalls']),25);self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual([s['ownership_effective_caps'] for s in result['saved_state']],[0,0,8,0,9,8])
            for s in result['saved_state']:
                expected=states[s['ordinal']]['file_credentials'];self.assertEqual(s['file_capability_pool'],expected['caps']);self.assertEqual(s['credential_id'],expected['active']+1);self.assertEqual(s['generation'],expected['generation']);self.assertEqual(s['slot_generations'],expected['epochs'])
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text());self.assertEqual(k['target_observations']['verified_calls'],1107);self.assertEqual(k['target_observations']['isolation_checks'],738)
            fields={f['path'] for f in k['checkpoint_codec']['fields']}
            for i in range(2):
                for n in ('effective','permitted','inheritable','bset','ambient'):self.assertIn('credential_pool['+str(i)+'].cap_'+n+'.val',fields)
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
    def test_chown_fowner_publication_and_subset_mutants_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-caps-mutants-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('bool chown=current_cred()->cap_effective.val&UINT64_C(1);','bool chown=true;'),
                     ('if(p->uid!=current_euid() && !(current_cred()->cap_effective.val&UINT64_C(8)))return -EPERM;','if(p->uid!=current_euid())return -EPERM;'),
                     ('current->cred=candidate;++credential_generation;','++credential_generation;'),
                     ('return (a.val&~b.val)==0;','(void)a;(void)b;return true;')]
            for i,(a,b) in enumerate(changes):
                bundle=stage/str(i);port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(a),1);p.write_text(s.replace(a,b));v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
    def test_source_abi_and_jointly_forged_capability_observations_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,a,b in [('upstream/kernel/capability.c',b'return commit_creds(new);',b'return 0;'),('upstream/security/commoncap.c',b'new->cap_effective   = *effective;',b'new->cap_effective = old->cap_effective;'),('upstream/include/uapi/asm-generic/unistd.h',b'__NR_capset 91',b'__NR_capset 92')]:
                p=native/filename;s=p.read_bytes();self.assertIn(a,s);p.write_bytes(s.replace(a,b,1))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(s)
            original={n:(native/n).read_bytes() for n in ('capture.json','qemu.log','capture.manifest.json')}
            for field in ('initial','effective','permitted'):
                v=json.loads(original['capture.json'])
                if field=='initial':v['initial']['file_capabilities'][1]|=64
                else:
                    i=next(i for i,(n,_,_) in enumerate(reviewed_adapter().file_capabilities_plan()) if n=='file_caps_remove_chown_permitted');v['calls'][i]['file_caps_after'][0 if field=='effective' else 1]|=1
                (native/'capture.json').write_text(json.dumps(v,indent=2)+'\n');uart={k:x for k,x in v.items() if k!='format'}
                altered,count=re.subn(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}\r?$','OSREC_LINUX_CAPTURE '+json.dumps(uart),original['qemu.log'].decode(),flags=re.M)
                self.assertEqual(count,1);(native/'qemu.log').write_text(altered)
                m=json.loads(original['capture.manifest.json']);m['capture_sha256']=digest((native/'capture.json').read_bytes());m['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(m,indent=2)+'\n')
                with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ|file capability entry state differs'):build_bundle(native,stage/'bad-native')
                self.assertFalse((stage/'bad-native').exists())
                for n,data in original.items():(native/n).write_bytes(data)
if __name__=='__main__':unittest.main(verbosity=2)
