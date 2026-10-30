"""UID/GID setters, supplementary lists and capabilities share persistent state."""
import gzip
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from capture_linux_aarch64 import reviewed_adapter,digest
from generate_linux_aarch64_application import generate
from prepare_linux_aarch64_port import build_bundle
from run_linux_aarch64_checkpoint_pipeline import run,verify_pipeline
from export_syscall_slices import export

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-credential-setters-native'
BOOT=1<<22;GID=1<<6;PCAP=1<<8;UID=1<<7
FS=sum(1<<n for n in (0,1,2,3,4,9,27,32));INITIAL=BOOT|GID|PCAP|UID|FS
INHERIT=(1<<0)|(1<<32)|GID

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxCredentialSettersTests(unittest.TestCase):
    def test_generated_witness_and_original_group_definitions_are_bound(self):
        source=generate('credential-setters')
        self.assertEqual(source,(ROOT/'integrations/linux_aarch64/credential-setters/application.c').read_text())
        self.assertEqual(source,(FIXTURE/'sources/application.c').read_text())
        original=json.loads((ROOT/'integrations/linux_aarch64/credential-setters/port-template.json').read_text())
        for number,arity in ((144,1),(143,2),(149,3),(152,1)):
            port=json.loads(json.dumps(original));route=next(r for r in port['roots'] if r['number']==number)
            self.assertEqual(route['arguments'],['unsigned']*arity);port['roots'].remove(route)
            with self.assertRaisesRegex(ValueError,'no reviewed route'):reviewed_adapter().application_source('credential-setters',port)
        old,_=reviewed_adapter().source_identity(ROOT/'integrations/linux_aarch64/group-setters')
        new,_=reviewed_adapter().source_identity(ROOT/'integrations/linux_aarch64/credential-setters')
        for name in ('setgid','setregid','setresgid','setfsgid','__sys_setgid','__sys_setregid','__sys_setresgid','__sys_setfsgid'):
            self.assertEqual(new['definitions'][name],old['definitions'][name])

    def test_combined_credentials_capabilities_and_lists_resume(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-credential-setters-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');review=reviewed_adapter()
            captured,manifest=review.validate_capture(native);calls=captured['calls'];_,states=review.projection(captured)
            names={n:i for i,(n,_,_) in enumerate(review.credential_setters_plan())}
            row=lambda n:calls[names[n]]
            after=lambda n:states[names[n]+1]
            self.assertTrue(manifest['native_linux_boot']);self.assertEqual(len(calls),98)
            self.assertEqual(row('invalid_setgid')['raw_bits'],(1<<64)-22)
            self.assertEqual(after('invalid_setgid'),states[names['invalid_setgid']])
            self.assertEqual(row('privileged_all_groups')['gids_after'],[4001]*3)
            self.assertEqual(row('privileged_all_groups')['fsgid_after'],4001)
            self.assertEqual(row('query_privileged_groups')['words'][1:4],[4001]*3)
            self.assertEqual(after('same_gid_publishes')['generation'],states[names['same_gid_publishes']]['generation']+1)
            self.assertEqual(row('privileged_foreign_fsgid')['fsgid_after'],9001)
            for n in ('fsgid_probe','sentinels_preserve_fsgid','sentinels_keep_divergent_fsgid','same_resgid_no_publication'):
                self.assertEqual(after(n),states[names[n]])
            self.assertEqual(row('explicit_egid_repairs_fsgid')['fsgid_after'],2002)
            self.assertEqual(row('privileged_foreign_regid')['gids_after'],[9001,9002,9002])
            self.assertEqual(row('effective_group_query')['raw_bits'],9002)
            self.assertEqual(row('uid_copy_preserves_group_ids')['gids_after'],[9001,9002,9002])
            self.assertEqual(row('uid_copy_preserves_group_ids')['uids_after'],[0]*3)
            self.assertEqual(row('replace_groups_privileged')['groups_after'],[5001,5005,5009])
            for n in ('saved_only_real_gid_denied','foreign_resgid_denied','dropped_old_real_denied','setgid_denied_after_uid_drop','setresgid_denied_after_uid_drop','setgroups_denied_after_uid_drop','foreign_regid_after_permitted_drop','list_denied_after_permitted_drop','cannot_restore_permitted_setgid','list_still_denied_after_root_regain'):
                self.assertEqual(row(n)['raw_bits'],(1<<64)-1)
                self.assertEqual(after(n)['generation'],states[names[n]]['generation'])
            self.assertEqual(row('foreign_fsgid_denied')['raw_bits'],2002)
            self.assertEqual(row('foreign_fsgid_denied')['fsgid_after'],2002)
            for n in ('partial_real_gid_then_effective_denied','final_partial_gid_abort'):
                state=after(n);old=states[names[n]];candidate=1-state['active']
                self.assertEqual(state['active'],old['active']);self.assertEqual(state['generation'],old['generation'])
                self.assertEqual(state['pool'][candidate],[2002,2002,2003,2002])
                self.assertEqual(state['pool'][state['active']],[2001,2002,2003,2002])
                self.assertEqual(state['uids'][candidate],old['uids'][old['active']])
                self.assertEqual(state['user_links'][candidate],old['user_links'][old['active']])
            self.assertEqual(row('query_active_after_abort')['words'][1:4],[2001,2002,2003])
            self.assertEqual(row('real_group_after_abort')['raw_bits'],2001)
            self.assertEqual(row('unprivileged_saved_gid')['gids_after'],[2001,2003,2003])
            self.assertEqual(row('real_to_effective_gid')['gids_after'],[2003]*3)
            self.assertEqual(row('foreign_groups_after_regain')['gids_after'],[9001,9002,9002])
            self.assertEqual(row('gid_changes_preserve_caps_and_ambient')['capabilities_after'],[INITIAL,INITIAL,INHERIT,(1<<41)-1,GID])
            self.assertEqual(row('scalar_changes_preserve_list')['groups_after'],[5001,5005,5009])
            self.assertEqual(row('drop_effective_uid')['capabilities_after'][0],0)
            self.assertEqual(row('same_root_gid_without_capability')['raw_bits'],0)
            self.assertEqual(row('same_root_gid_without_capability')['capabilities_after'][0],0)
            self.assertEqual(row('uid_value_does_not_authorize_gid')['fsgid_after'],0)
            self.assertEqual(row('restore_saved_root_uid')['capabilities_after'][0],INITIAL)
            self.assertEqual(row('foreign_groups_after_uid_restore')['gids_after'],[0,1001,2003])
            self.assertEqual(row('replace_list_after_uid_restore')['groups_after'],[6001,6003])
            self.assertEqual(row('truncated_fsgid')['fsgid_after'],2003)
            self.assertEqual(row('sentinels_publish_repair_fsgid')['fsgid_after'],1001)
            self.assertEqual(after('sentinels_publish_repair_fsgid')['generation'],states[names['sentinels_publish_repair_fsgid']]['generation']+1)
            self.assertEqual(row('partial_group_output')['raw_bits'],(1<<64)-14)
            self.assertEqual(row('partial_group_output')['words'][1:4],[0,0xa5a50002,0xa5a50003])
            self.assertEqual(row('truncated_root_gid')['gids_after'],[0]*3)
            self.assertEqual(row('truncated_invalid_gid')['raw_bits'],(1<<64)-22)
            self.assertEqual(row('truncated_regid')['gids_after'],[2001,2003,2003])
            self.assertEqual(row('list_allowed_after_fsuid_drop')['groups_after'],[7001])
            self.assertTrue(row('drop_filesystem_uid_caps')['capabilities_after'][0]&GID)
            self.assertEqual(row('foreign_gid_after_fsuid_drop')['gids_after'],[9002]*3)
            self.assertEqual(row('uid_repair_preserves_groups')['gids_after'],[9002]*3)
            self.assertEqual(row('remove_permitted_setgid')['capabilities_after'][4],0)
            self.assertEqual(row('restore_uid_only_remaining_permitted')['capabilities_after'][0],INITIAL&~GID)
            self.assertEqual(row('fsgid_still_denied_after_root_regain')['fsgid_after'],2002)
            self.assertEqual(row('group_copy_preserves_user_accounting')['uids_after'],[9001]*3)
            self.assertEqual(row('move_final_accounting_user')['uids_after'],[9002]*3)
            self.assertEqual(row('aliased_final_group_ids')['words'][1],2003)
            self.assertEqual(row('final_user_ids')['words'][1:4],[9002]*3)
            self.assertEqual(row('final_securebits')['raw_bits'],12);self.assertEqual(states[-1]['generation'],43)
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU,pause_ordinals=None))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(98,32,536,444))
            self.assertEqual(len(result['syscalls']),23);self.assertFalse(result['runtime_host_interaction'])
            pauses=('partial_real_gid_then_effective_denied','drop_effective_uid','sentinels_keep_divergent_fsgid','remove_permitted_setgid','move_final_accounting_user','final_partial_gid_abort')
            self.assertEqual([r['ordinal'] for r in result['saved_state']],[names[n]+1 for n in pauses])
            for saved in result['saved_state']:
                state=states[saved['ordinal']]
                self.assertEqual(saved['credential_pool'],state['pool']);self.assertEqual(saved['credential_uids'],state['uids'])
                self.assertEqual(saved['credential_capabilities'],state['capabilities']);self.assertEqual(saved['credential_securebits'],state['securebits'])
                self.assertEqual(saved['user_links'],[v[0]+1 for v in state['user_links']]);self.assertEqual(saved['accounting_links'],[v[1]+1 for v in state['user_links']])
                self.assertEqual(saved['group_pool'],state['group_pool']);self.assertEqual(sum(p['usage'] for p in saved['user_accounting']),1)
            kernel=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            for field in ('verified_calls','return_value_checks','application_memory_checks'):self.assertEqual(kernel['target_observations'][field],294)
            self.assertEqual(kernel['target_observations']['isolation_checks'],196)
            self.assertEqual(len(kernel['source_identity']['reviewed_source']['definitions']),51)
            functions=kernel['context_plan']['context_functions']+kernel['context_plan']['pure_functions']
            for helper in ('__sys_setgid','__sys_setregid','__sys_setresgid','__sys_setfsgid','__sys_setuid','set_cred_ucounts'):self.assertTrue(any(n.endswith(helper) for n in functions))
            self.assertFalse(kernel['source_identity']['native_source_build_attested'])
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_permission_lost_scalar_copy_and_erased_abort_fail_target_proof(self):
        changes=[('(current_cred()->cap_effective.val&(UINT64_C(1)<<cap))!=0;',
                  '(current_cred()->cap_permitted.val&(UINT64_C(1)<<cap))!=0;'),
                 ('*candidate=*current->cred;',
                  '*candidate=*current->cred;candidate->gid=LINUX_INITIAL_GID;candidate->egid=LINUX_INITIAL_EGID;candidate->sgid=LINUX_INITIAL_SGID;candidate->fsgid=LINUX_INITIAL_EGID;'),
                 ('pending_credential=0;}}','pending_credential=0;candidate->gid=current->cred->gid;}}')]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for i,(original,mutation) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle);model=bundle/'models.c';source=model.read_text();self.assertEqual(source.count(original),1);model.write_text(source.replace(original,mutation))
                descriptor=json.loads(port.read_text());descriptor['bundle']['inputs']['models.c']=digest(model.read_bytes());port.write_text(json.dumps(descriptor))
                output=stage/('bad-kernel-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):
                    export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/credential-setters/upstream',out=output,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(output.exists())

    def test_original_group_helpers_and_native_active_state_are_bound(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for i,(path,needle,mutation,error) in enumerate([
                ('upstream/kernel/sys.c',b'new->gid = new->egid = new->sgid = new->fsgid = kgid;',b'new->egid = new->fsgid = kgid;','reviewed source identity'),
                ('upstream/kernel/sys.c',b'if (rgid != (gid_t) -1 ||',b'if (rgid != (gid_t) -1 &&','reviewed source identity'),
                ('upstream/include/uapi/asm-generic/unistd.h',b'__NR_setgid 144',b'__NR_setgid 143','syscall ABI source identity')]):
                source=native/path;raw=source.read_bytes();self.assertEqual(raw.count(needle),1);source.write_bytes(raw.replace(needle,mutation))
                output=stage/('bad-source-'+str(i))
                with self.assertRaisesRegex(ValueError,error):build_bundle(native,output)
                self.assertFalse(output.exists());source.write_bytes(raw)
            captured=json.loads((native/'capture.json').read_text());names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().credential_setters_plan())}
            captured['calls'][names['setgid_denied_after_uid_drop']]['gids_after'][0]=9001
            (native/'capture.json').write_text(json.dumps(captured))
            log=(native/'qemu.log').read_text();start=log.index('OSREC_LINUX_CAPTURE ');end=log.index('\n',start)
            log=log[:start]+'OSREC_LINUX_CAPTURE '+json.dumps({k:v for k,v in captured.items() if k!='format'})+log[end:];(native/'qemu.log').write_text(log)
            manifest=json.loads((native/'capture.manifest.json').read_text());manifest['capture_sha256']=digest((native/'capture.json').read_bytes());manifest['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'state transitions differ'):build_bundle(native,stage/'bad-observation')
            self.assertFalse((stage/'bad-observation').exists())

if __name__=='__main__':unittest.main()
