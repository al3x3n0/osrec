"""Filesystem GID, effective GID and inode groups across capability/file resumes."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-file-fsgid-native'
def prepare_capture(dst):
    shutil.copytree(FIXTURE,dst,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (dst/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(dst);return dst
class LinuxFileFsgidTests(unittest.TestCase):
    def test_generated_witness_original_setfsgid_and_both_persisted_slots(self):
        r=reviewed_adapter();p=ROOT/'integrations/linux_aarch64/file-fsgid'
        self.assertEqual(generate('file-fsgid'),(p/'application.c').read_text());self.assertEqual((p/'application.c').read_bytes(),(FIXTURE/'sources/application.c').read_bytes())
        old,_=r.source_identity(ROOT/'integrations/linux_aarch64/file-capabilities');new,defs=r.source_identity(p);fsgid,_=r.source_identity(ROOT/'integrations/linux_aarch64/fsgid')
        self.assertEqual(len(defs),74)
        for n,h in old['definitions'].items():self.assertEqual(new['definitions'][n],h)
        for n in ('setfsgid','__sys_setfsgid'):self.assertEqual(new['definitions'][n],fsgid['definitions'][n])
        self.assertIn(b'old_fsgid = from_kgid_munged(old->user_ns, old->fsgid);',defs['__sys_setfsgid']['body'])
        self.assertIn(b'abort_creds(new);',defs['__sys_setfsgid']['body'])
        f=json.loads((p/'checkpoint-policy.json').read_text())['fields'];self.assertEqual(f['credential_pool']['element']['members']['fsgid'],{'type':'uint32_t','policy':'persist'})
        v=json.loads((p/'port-template.json').read_text());v['roots']=[x for x in v['roots'] if x['number']!=152]
        with self.assertRaisesRegex(ValueError,'no reviewed route'):r.application_source('file-fsgid',v)
    def test_live_filesystem_group_permissions_silent_denial_aliases_and_resumes(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-fsgid-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,_=r.validate_capture(native);_,states=r.projection(c)
            names={n:i for i,(n,_,_) in enumerate(r.file_fsgid_plan())};row=lambda n:c['calls'][names[n]]
            self.assertEqual(len(c['calls']),401);self.assertEqual(c['initial']['file_fsgid'],2002)
            self.assertEqual(row('file_fsgid_real')['raw_bits'],2002);self.assertEqual(row('file_fsgid_real')['file_fsgid_after'],2001)
            self.assertEqual(row('file_fsgid_effective_query')['raw_bits'],2002);self.assertEqual(row('file_fsgid_effective_query')['file_fsgid_after'],2001)
            for n in ('file_fsgid_foreign_denied','file_fsgid_invalid_query','file_fsgid_same_no_publish'):self.assertEqual((row(n)['raw_bits'],row(n)['file_fsgid_after']),(2001,2001))
            for n in ('file_fsgid_effective_group_denied','file_fsgid_real_group_denied'):self.assertEqual(row(n)['raw_bits'],(1<<64)-1)
            for n,g in [('file_fsgid_stat_real',2001),('file_fsgid_stat_denied',2001),('file_fsgid_stat_saved',2003),('file_fsgid_stat_supplementary',0),('file_fsgid_stat_effective',2002),('file_fsgid_stat_restored',0),('file_fsgid_stat_alias_saved',2003),('file_fsgid_stat_alias_real',2001)]:
                self.assertEqual(row(n)['file_after']['gid'],g,n);self.assertEqual(row(n)['file_after']['uid'],1002)
            self.assertEqual((row('file_fsgid_saved_narrow')['raw_bits'],row('file_fsgid_saved_narrow')['file_fsgid_after']),(2001,2003))
            for n in ('file_fsgid_foreign_denied','file_fsgid_invalid_query','file_fsgid_same_no_publish','file_fsgid_alias_query'):
                i=names[n];before=states[i]['file_credentials'];after=states[i+1]['file_credentials']
                self.assertEqual((before['active'],before['generation'],before['epochs']),(after['active'],after['generation'],after['epochs']))
            i=names['file_fsgid_alias_query'];self.assertNotEqual(*states[i]['file_credentials']['fsgids']);self.assertEqual(states[i]['file_credentials'],states[i+1]['file_credentials'])
            i=names['file_fsgid_alias_refresh_dropped'];self.assertEqual(states[i+1]['file_credentials']['fsgids'],[2001,2001]);self.assertEqual(states[i+1]['file_credentials']['generation'],states[i]['file_credentials']['generation']+1)
            old=json.loads((ROOT/'tests/fixtures/linux-aarch64-file-capabilities-native/capture.json').read_text());oldnames={n for n,_,_ in r.file_capabilities_plan()}
            def stable(v):
                v=json.loads(json.dumps(v));v.pop('file_fsgid_after',None);del v['stat_digest'];return v
            self.assertEqual([stable(v) for (n,_,_),v in zip(r.file_fsgid_plan(),c['calls']) if n in oldnames],[stable(v) for v in old['calls']])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions']),(401,32));self.assertEqual(len(result['syscalls']),26);self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual([s['fsgid'] for s in result['saved_state']],[2001,2001,2003,2002,2003,2001])
            for s in result['saved_state']:
                state=states[s['ordinal']]['file_credentials'];self.assertEqual(s['file_fsgids'],state['fsgids']);self.assertEqual(s['file_capability_pool'],state['caps']);self.assertEqual(s['gids'],[2001,2002,2003]);self.assertEqual(s['generation'],state['generation'])
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text());self.assertEqual(k['target_observations']['verified_calls'],1203);self.assertEqual(k['target_observations']['isolation_checks'],802)
            fields={f['path'] for f in k['checkpoint_codec']['fields']}
            for i in range(2):self.assertIn('credential_pool['+str(i)+'].fsgid',fields)
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
    def test_effective_group_stale_fsgid_invalid_preparation_and_privilege_mutants_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-fsgid-mutants-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('a->ia_vfsgid!=current_fsgid()','a->ia_vfsgid!=current_egid()'),
                     ('current->cred=candidate;++credential_generation;','candidate->fsgid=current->cred->fsgid;current->cred=candidate;++credential_generation;'),
                     ('bool gid_valid(kgid_t v){return v!=UINT32_MAX;}','bool gid_valid(kgid_t v){(void)v;return true;}'),
                     ('return ns==current_cred()->user_ns && ns->initial && cap==CAP_SETGID && (current_cred()->cap_effective.val&(UINT64_C(1)<<CAP_SETGID));','return ns==current_cred()->user_ns && ns->initial && cap==CAP_SETGID;')]
            for i,(a,b) in enumerate(changes):
                bundle=stage/str(i);port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(a),1);p.write_text(s.replace(a,b));v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
    def test_source_abi_and_jointly_forged_filesystem_group_observations_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,a,b in [('upstream/kernel/sys.c',b'new->fsgid = kgid;',b'new->fsgid = old->fsgid;'),('upstream/include/uapi/asm-generic/unistd.h',b'__NR_setfsgid 152',b'__NR_setfsgid 153')]:
                p=native/filename;s=p.read_bytes();self.assertIn(a,s);p.write_bytes(s.replace(a,b,1))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(s)
            original={n:(native/n).read_bytes() for n in ('capture.json','qemu.log','capture.manifest.json')}
            for field in ('initial','query','group'):
                v=json.loads(original['capture.json'])
                if field=='initial':v['initial']['file_fsgid']=2003
                else:
                    n='file_fsgid_effective_query' if field=='query' else 'file_fsgid_real_group';i=next(i for i,(name,_,_) in enumerate(reviewed_adapter().file_fsgid_plan()) if name==n)
                    if field=='query':v['calls'][i]['file_fsgid_after']=2002
                    else:v['calls'][i]['file_after']['gid']=2002
                (native/'capture.json').write_text(json.dumps(v,indent=2)+'\n');uart={k:x for k,x in v.items() if k!='format'}
                altered,count=re.subn(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}\r?$','OSREC_LINUX_CAPTURE '+json.dumps(uart),original['qemu.log'].decode(),flags=re.M)
                self.assertEqual(count,1);(native/'qemu.log').write_text(altered)
                m=json.loads(original['capture.manifest.json']);m['capture_sha256']=digest((native/'capture.json').read_bytes());m['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(m,indent=2)+'\n')
                with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ|filesystem-group entry state differs'):build_bundle(native,stage/'bad-native')
                self.assertFalse((stage/'bad-native').exists())
                for n,data in original.items():(native/n).write_bytes(data)
if __name__=='__main__':unittest.main(verbosity=2)
