"""Scalar GID setters share live file, capability and supplementary state."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-file-group-setters-native'
def prepare_capture(dst):
    shutil.copytree(FIXTURE,dst,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (dst/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(dst);return dst
class LinuxFileGroupSettersTests(unittest.TestCase):
    def test_generated_witness_original_setters_and_persisted_gid_slots(self):
        r=reviewed_adapter();p=ROOT/'integrations/linux_aarch64/file-group-setters'
        self.assertEqual(generate('file-group-setters'),(p/'application.c').read_text());self.assertEqual((p/'application.c').read_bytes(),(FIXTURE/'sources/application.c').read_bytes())
        old,_=r.source_identity(ROOT/'integrations/linux_aarch64/file-groups');new,defs=r.source_identity(p);groups,_=r.source_identity(ROOT/'integrations/linux_aarch64/group-setters')
        self.assertEqual(len(defs),94)
        for n,h in old['definitions'].items():self.assertEqual(new['definitions'][n],h)
        for n in ('setgid','__sys_setgid','setregid','__sys_setregid','setresgid','__sys_setresgid'):self.assertEqual(new['definitions'][n],groups['definitions'][n])
        self.assertIn(b'new->fsgid = new->egid;',defs['__sys_setresgid']['body']);self.assertIn(b'new->sgid = new->egid;',defs['__sys_setregid']['body'])
        fields=json.loads((p/'checkpoint-policy.json').read_text())['fields']['credential_pool']['element']['members']
        for n in ('gid','egid','sgid','fsgid'):self.assertEqual(fields[n],dict(type='uint32_t',policy='persist'))
        v=json.loads((p/'port-template.json').read_text());v['roots']=[x for x in v['roots'] if x['number']!=143]
        with self.assertRaisesRegex(ValueError,'no reviewed route'):r.application_source('file-group-setters',v)
        plans={'file-io':r.file_io_plan,'file-positioned':r.file_positioned_plan,'fd-control':r.fd_control_plan,'close-range':r.close_range_plan,'fstat':r.fstat_plan,'fchmod':r.fchmod_plan,'fchown':r.fchown_plan,'fchown-capable':r.fchown_capable_plan,'file-capabilities':r.file_capabilities_plan,'file-fsgid':r.file_fsgid_plan,'file-fsuid':r.file_fsuid_plan,'file-groups':r.file_groups_plan,'file-group-setters':r.file_group_setters_plan}
        for profile,factory in plans.items():
            with self.subTest(profile=profile):
                integration=ROOT/'integrations/linux_aarch64'/profile
                self.assertEqual(r.application_source(profile,json.loads((integration/'port-template.json').read_text())),(integration/'application.c').read_text())
                for i,(_,_,data) in enumerate(factory()):
                    expected=list(data) if data is not None else [0xa5a50000+j for j in range(8)]
                    words=r.input_words(profile,i);self.assertEqual(words,expected)
                    words[0]^=0xffffffff
                    self.assertEqual(r.input_words(profile,i),expected)
                    if data is not None:
                        data[0]^=0xffffffff
                        self.assertEqual(r.input_words(profile,i),expected)
    def test_live_ids_partial_aborts_fsgid_repair_file_checks_and_joint_resumes(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-group-setters-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,_=r.validate_capture(native);_,states=r.projection(c);names={n:i for i,(n,_,_) in enumerate(r.file_group_setters_plan())};row=lambda n:c['calls'][names['file_group_setters_'+n]]
            self.assertEqual(len(c['calls']),568)
            for n,ids in [('res_foreign',[7001,7002,7003]),('gid_narrow',[8001]*3),('regid_foreign',[8101,8102,8102]),('gid_real',[8101,8101,8102]),('gid_saved',[8101,8102,8102]),('regid_real_effective',[8101,8101,8102]),('regid_collapse_saved',[8101]*3),('res_nondefault',[8201,8202,8203]),('res_restore_ids',[2001,2002,2003])]:
                self.assertEqual(row(n)['raw_bits'],0,n);self.assertEqual(row(n)['file_gids_after'],ids,n)
            self.assertEqual(row('getgid_foreign')['raw_bits'],7001);self.assertEqual(row('getegid_foreign')['raw_bits'],7002);self.assertEqual(row('query_foreign')['words'][:3],[7001,7002,7003])
            for n in ('old_effective_denied','gid_foreign_denied','regid_partial_denied','res_foreign_denied','egid_not_fsgid_denied','gid_lost_saved_denied','nondefault_egid_denied'):self.assertEqual(row(n)['raw_bits'],(1<<64)-1,n)
            self.assertEqual(row('gid_invalid')['raw_bits'],(1<<64)-22)
            i=names['file_group_setters_regid_partial_denied'];before=states[i]['file_credentials'];after=states[i+1]['file_credentials'];self.assertEqual((before['active'],before['generation']),(after['active'],after['generation']));self.assertEqual(after['gids'][after['active']],[8101,8102,8102]);self.assertEqual(after['gids'][1-after['active']],[8102,8102,8102]);self.assertEqual(row('query_partial_abort')['words'][:3],[8101,8102,8102])
            for n in ('res_foreign_denied','res_all_sentinel','res_same_no_publish','gid_invalid'):
                i=names['file_group_setters_'+n];self.assertEqual(states[i]['file_credentials'],states[i+1]['file_credentials'],n)
            self.assertEqual((row('res_all_sentinel')['file_gids_after'],row('res_all_sentinel')['file_fsgid_after']),([8101,8102,8102],8101));self.assertEqual(row('res_repair_fsgid')['file_fsgid_after'],8102)
            i=names['file_group_setters_res_repair_fsgid'];self.assertEqual(states[i+1]['file_credentials']['generation'],states[i]['file_credentials']['generation']+1)
            self.assertEqual(row('query_guard')['raw_bits'],(1<<64)-14);self.assertEqual((row('query_guard')['words'][0],row('query_guard')['words'][7]),(8101,8101))
            for n,gid in [('stat_privileged',7002),('stat_real',8101),('stat_distinct_fsgid',8101),('stat_repair',8102),('stat_nondefault_copy',8201),('stat_supplementary',8301),('stat_restored',0)]:self.assertEqual(row(n)['file_after']['gid'],gid,n)
            for n in ('copy_nondefault','copy_fsgid','copy_fsuid_real','copy_fsuid_restore','copy_groups'):
                self.assertEqual(row(n)['file_gids_after'],[8201,8202,8203],n)
            for st in states:self.assertEqual(sum(p['usage'] for p in st['file_credentials']['group_pool']),1)
            old=json.loads((ROOT/'tests/fixtures/linux-aarch64-file-groups-native/capture.json').read_text());oldnames={n for n,_,_ in r.file_groups_plan()}
            def stable(v):
                v=dict(v);v.pop('file_gids_after',None);v.pop('stat_digest',None);return v
            self.assertEqual([stable(v) for (n,_,_),v in zip(r.file_group_setters_plan(),c['calls']) if n in oldnames],[stable(v) for v in old['calls']])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU));self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],len(result['syscalls'])),(568,32,32));self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual([s['gids'] for s in result['saved_state']],[[7001,7002,7003],[8101,8101,8102],[8101,8102,8102],[8101,8102,8102],[8201,8202,8203],[2001,2002,2003]])
            self.assertEqual([s['fsgid'] for s in result['saved_state']],[7002,8101,8102,8102,8201,2002])
            for s in result['saved_state']:
                cred=states[s['ordinal']]['file_credentials'];self.assertEqual(s['file_gid_pool'],cred['gids']);self.assertEqual(s['file_fsgids'],cred['fsgids']);self.assertEqual(s['file_fsuids'],cred['fsuids']);self.assertEqual(s['file_capability_pool'],cred['caps']);self.assertEqual(s['file_group_pool'],cred['group_pool']);self.assertEqual(s['generation'],cred['generation'])
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text());self.assertEqual((k['target_observations']['verified_calls'],k['target_observations']['isolation_checks']),(1704,1136));fields={f['path'] for f in k['checkpoint_codec']['fields']}
            for i in range(2):
                for n in ('gid','egid','sgid'):self.assertIn('credential_pool['+str(i)+'].'+n,fields)
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
    def test_fixed_getter_stale_copy_abort_repair_and_security_mutants_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-group-setters-mutants-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('gid_t current_gid(void){return current_cred()->gid;}','gid_t current_gid(void){return LINUX_INITIAL_GID;}'),
                     ('*candidate=*current->cred;get_group_info(candidate->group_info);','*candidate=*current->cred;candidate->gid=LINUX_INITIAL_GID;candidate->egid=LINUX_INITIAL_EGID;candidate->sgid=LINUX_INITIAL_SGID;get_group_info(candidate->group_info);'),
                     ('linux_assert(candidate!=pending_credential);put_group_info(candidate->group_info);','linux_assert(candidate!=pending_credential);candidate->gid=current->cred->gid;put_group_info(candidate->group_info);'),
                     ('current->cred=candidate;++credential_generation;','candidate->fsgid=current->cred->fsgid;current->cred=candidate;++credential_generation;'),
                     ('(flags==LSM_SETID_FS || flags==LSM_SETID_ID || flags==LSM_SETID_RE || flags==LSM_SETID_RES) ? 0 : -EINVAL;','flags==LSM_SETID_FS ? 0 : -EINVAL;')]
            for i,(a,b) in enumerate(changes):
                bundle=stage/str(i);port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(a),1);p.write_text(s.replace(a,b));v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
    def test_source_abi_and_jointly_forged_scalar_group_evidence_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-group-setters-forged-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,a,b in [('upstream/kernel/sys.c',b'new->sgid = new->egid;',b'new->sgid = old->sgid;'),('upstream/include/uapi/asm-generic/unistd.h',b'__NR_setregid 143',b'__NR_setregid 142')]:
                p=native/filename;s=p.read_bytes();self.assertIn(a,s);p.write_bytes(s.replace(a,b,1))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(s)
            original={n:(native/n).read_bytes() for n in ('capture.json','qemu.log','capture.manifest.json')};names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_group_setters_plan())}
            for field in ('live','saved','repair','owner','denied'):
                v=json.loads(original['capture.json'])
                if field=='live':v['calls'][names['file_group_setters_res_foreign']]['file_gids_after']=[2001,2002,2003]
                elif field=='saved':v['calls'][names['file_group_setters_regid_collapse_saved']]['file_gids_after'][2]=8102
                elif field=='repair':v['calls'][names['file_group_setters_res_repair_fsgid']]['file_fsgid_after']=8101
                elif field=='owner':v['calls'][names['file_group_setters_effective_group']]['file_after']['gid']=2002
                else:v['calls'][names['file_group_setters_regid_partial_denied']]['raw_bits']=0
                (native/'capture.json').write_text(json.dumps(v,indent=2)+'\n');uart={k:x for k,x in v.items() if k!='format'}
                altered,count=re.subn(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}\r?$','OSREC_LINUX_CAPTURE '+json.dumps(uart),original['qemu.log'].decode(),flags=re.M);self.assertEqual(count,1);(native/'qemu.log').write_text(altered)
                m=json.loads(original['capture.manifest.json']);m['capture_sha256']=digest((native/'capture.json').read_bytes());m['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(m,indent=2)+'\n')
                with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ'):build_bundle(native,stage/'bad-native')
                self.assertFalse((stage/'bad-native').exists())
                for n,data in original.items():(native/n).write_bytes(data)
if __name__=='__main__':unittest.main(verbosity=2)
