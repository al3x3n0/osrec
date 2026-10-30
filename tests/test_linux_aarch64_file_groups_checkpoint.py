"""Live supplementary membership, credential/list lifetimes and file resumes."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-file-groups-native'
def prepare_capture(dst):
    shutil.copytree(FIXTURE,dst,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (dst/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(dst);return dst
class LinuxFileGroupsTests(unittest.TestCase):
    def test_generated_witness_original_group_helpers_and_typed_list_policy(self):
        r=reviewed_adapter();p=ROOT/'integrations/linux_aarch64/file-groups'
        self.assertEqual(generate('file-groups'),(p/'application.c').read_text());self.assertEqual((p/'application.c').read_bytes(),(FIXTURE/'sources/application.c').read_bytes())
        old,_=r.source_identity(ROOT/'integrations/linux_aarch64/file-fsuid');new,defs=r.source_identity(p);groups,_=r.source_identity(ROOT/'integrations/linux_aarch64/setgroups')
        self.assertEqual(len(defs),88)
        for n,h in old['definitions'].items():self.assertEqual(new['definitions'][n],h)
        for n in ('getgroups','setgroups','groups_to_user','groups_from_user','set_groups','set_current_groups','may_setgroups'):self.assertEqual(new['definitions'][n],groups['definitions'][n])
        self.assertIn(b'if (!may_setgroups())',defs['setgroups']['body']);self.assertIn(b'groups_sort(group_info);',defs['setgroups']['body'])
        f=json.loads((p/'checkpoint-policy.json').read_text())['fields'];ref=f['credential_pool']['element']['members']['group_info'];self.assertEqual((ref['policy'],ref['targets'],ref['nullable']),('context_reference',['group_pool[0]','group_pool[1]'],False));self.assertEqual(f['allocated_group']['policy'],'transient')
        v=json.loads((p/'port-template.json').read_text());v['roots']=[x for x in v['roots'] if x['number']!=159]
        with self.assertRaisesRegex(ValueError,'no reviewed route'):r.application_source('file-groups',v)
    def test_live_group_authorization_fault_lifetimes_aliases_and_joint_resumes(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-groups-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,_=r.validate_capture(native);_,states=r.projection(c);names={n:i for i,(n,_,_) in enumerate(r.file_groups_plan())};row=lambda n:c['calls'][names['file_groups_'+n]]
            self.assertEqual(len(c['calls']),509);self.assertEqual(c['initial']['file_capabilities'],[1,4194377,0,(1<<41)-1,0])
            self.assertEqual(row('duplicates')['file_groups_after'],[4001,4003,4003,4007]);self.assertEqual(row('query_count')['raw_bits'],4);self.assertEqual(row('query_full')['words'][:4],[4001,4003,4003,4007]);self.assertEqual(row('query_small')['raw_bits'],(1<<64)-22)
            self.assertEqual(row('query_partial')['raw_bits'],(1<<64)-14);self.assertEqual(row('query_partial')['words'][7],4001)
            for n in ('denied_negative_size','denied_guard','denied_replacement','denied_invalid_size','alias_denied_replacement','root_no_setgid_denied','permanent_denied'):self.assertEqual(row(n)['raw_bits'],(1<<64)-1,n)
            for n in ('foreign_group_denied','egid_not_member_denied','nonowner_member_denied','removed_member_denied','removed_zero_denied'):self.assertEqual(row(n)['raw_bits'],(1<<64)-1,n)
            for n in ('member_group','second_member_group','fsgid_group','alias_member','alias_second_member','alias_member_restored','restore_inode_group'):self.assertEqual(row(n)['raw_bits'],0,n)
            for n in ('query_empty','query_empty_null','query_after_fault'):self.assertEqual(row(n)['raw_bits'],0,n)
            for n in ('oversize','invalid_gid','query_negative'):self.assertEqual(row(n)['raw_bits'],(1<<64)-22,n)
            self.assertEqual(row('partial_copy')['raw_bits'],(1<<64)-14);self.assertEqual(row('replace_narrow_count')['file_groups_after'],[5001,5003]);self.assertEqual(row('root_fsuid')['file_caps_after'][0],9);self.assertEqual(row('root_fsuid')['file_fsuid_after'],0)
            for n in ('invalid_gid','partial_copy'):
                i=names['file_groups_'+n];before=states[i]['file_credentials'];after=states[i+1]['file_credentials'];self.assertEqual((before['active'],before['generation'],before['group_links']),(after['active'],after['generation'],after['group_links']));released=next(p for p in after['group_pool'] if not p['usage']);self.assertEqual(released,dict(usage=0,ngroups=2,gid=[4009 if n=='invalid_gid' else 4005,0,0,0]))
            for st in states:
                cred=st['file_credentials'];self.assertEqual(sum(p['usage'] for p in cred['group_pool']),1)
                self.assertEqual(cred['group_pool'][cred['group_links'][cred['active']]]['usage'],1)
            old=json.loads((ROOT/'tests/fixtures/linux-aarch64-file-fsuid-native/capture.json').read_text());oldnames={n for n,_,_ in r.file_fsuid_plan()}
            def stable(v,ordinal):
                v=json.loads(json.dumps(v));v.pop('file_groups_after',None);v.pop('stat_digest',None)
                if ordinal<20:v['file_caps_after'][1]&=~64
                return v
            self.assertEqual([stable(v,i) for i,((n,_,_),v) in enumerate(zip(r.file_groups_plan(),c['calls'])) if n in oldnames],[stable(v,10000) for v in old['calls']])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU));self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],len(result['syscalls'])),(509,32,29));self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual([s['supplementary_groups'] for s in result['saved_state']],[[4001,4003,4003,4007],[4001,4003,4003,4007],[],[],[5001,5003],[0]])
            self.assertEqual([s['ownership_effective_caps'] for s in result['saved_state']],[64,0,64,64,0,1])
            for s in result['saved_state']:
                cred=states[s['ordinal']]['file_credentials'];self.assertEqual(s['file_group_pool'],cred['group_pool']);self.assertEqual(s['file_group_links'],[j+1 for j in cred['group_links']]);self.assertEqual(s['file_fsuids'],cred['fsuids']);self.assertEqual(s['file_fsgids'],cred['fsgids']);self.assertEqual(s['file_capability_pool'],cred['caps']);self.assertEqual(s['generation'],cred['generation'])
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text());self.assertEqual((k['target_observations']['verified_calls'],k['target_observations']['isolation_checks']),(1527,1018));fields={f['path'] for f in k['checkpoint_codec']['fields']}
            for i in range(2):self.assertIn('credential_pool['+str(i)+'].group_info',fields);self.assertIn('group_pool['+str(i)+'].usage',fields)
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
    def test_frozen_membership_stale_copy_reference_sort_and_privilege_mutants_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-groups-mutants-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('bool linux_in_supplementary_group(kgid_t gid){const struct group_info *p=current_cred()->group_info;for(int j=0;j<p->ngroups;++j)if(p->gid[j]==gid)return true;return false;}','bool linux_in_supplementary_group(kgid_t gid){return gid==0;}'),
                     ('*candidate=*current->cred;get_group_info(candidate->group_info);','*candidate=*current->cred;candidate->group_info=&group_pool[0];get_group_info(candidate->group_info);'),
                     ('put_group_info(current->cred->group_info);current->cred=candidate;','current->cred=candidate;'),
                     ('for(int i=1;i<p->ngroups;++i){uint32_t v=p->gid[i];int j=i;','for(int i=p->ngroups;i<p->ngroups;++i){uint32_t v=p->gid[i];int j=i;'),
                     ('(current_cred()->cap_effective.val&(UINT64_C(1)<<cap))','(cap==CAP_SETGID || (current_cred()->cap_effective.val&(UINT64_C(1)<<cap)))')]
            for i,(a,b) in enumerate(changes):
                bundle=stage/str(i);port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(a),1);p.write_text(s.replace(a,b));v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
    def test_original_source_abi_and_jointly_forged_group_evidence_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-groups-forged-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,a,b in [('upstream/kernel/groups.c',b'group_info->gid[i] = kgid;',b'group_info->gid[i] = 0;'),('upstream/include/uapi/asm-generic/unistd.h',b'__NR_setgroups 159',b'__NR_setgroups 157')]:
                p=native/filename;s=p.read_bytes();self.assertIn(a,s);p.write_bytes(s.replace(a,b,1))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(s)
            original={n:(native/n).read_bytes() for n in ('capture.json','qemu.log','capture.manifest.json')};names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_groups_plan())}
            for field in ('initial','duplicates','denied','owner','fault'):
                v=json.loads(original['capture.json'])
                if field=='initial':v['initial']['file_capabilities'][1]&=~64
                elif field=='duplicates':v['calls'][names['file_groups_duplicates']]['file_groups_after']=[4007,4001,4003,4003]
                elif field=='denied':v['calls'][names['file_groups_denied_negative_size']]['raw_bits']=(1<<64)-22
                elif field=='owner':v['calls'][names['file_groups_member_group']]['file_after']['gid']=4009
                else:v['calls'][names['file_groups_partial_copy']]['file_groups_after']=[4005]
                (native/'capture.json').write_text(json.dumps(v,indent=2)+'\n');uart={k:x for k,x in v.items() if k!='format'}
                altered,count=re.subn(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}\r?$','OSREC_LINUX_CAPTURE '+json.dumps(uart),original['qemu.log'].decode(),flags=re.M);self.assertEqual(count,1);(native/'qemu.log').write_text(altered)
                m=json.loads(original['capture.manifest.json']);m['capture_sha256']=digest((native/'capture.json').read_bytes());m['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(m,indent=2)+'\n')
                with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ|file capability entry state differs'):build_bundle(native,stage/'bad-native')
                self.assertFalse((stage/'bad-native').exists())
                for n,data in original.items():(native/n).write_bytes(data)
if __name__=='__main__':unittest.main(verbosity=2)
