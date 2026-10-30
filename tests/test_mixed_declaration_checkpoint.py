"""Mixed readonly/owned declarations survive returning calls and fresh images."""
import json
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from export_syscall_slices import export
from verify_syscall_slices import verify_matrix
from run_c_application_checkpoint_chain import run_pipeline,verify_chain
from slice_port_bundle import digest,verify_published
from application_pause import verify_joint

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/portable-slice-port'


def prepare_fixture(destination,local=False):
    shutil.copytree(FIXTURE,destination)
    provider=destination/'provider.c';text=provider.read_text()
    original='static const uint64_t private_seed=PRIVATE_HIGH+PRIVATE_LOW;'
    if text.count(original)!=1:raise ValueError('mixed fixture seed declaration changed')
    if local:
        check='uint32_t SeedReferenceCheck(void){static const uint64_t private_seed=PRIVATE_HIGH+PRIVATE_LOW,*seed_ref=&private_seed;return seed_ref==&private_seed;}\n'
    else:
        text=text.replace(original,'static const uint64_t private_seed=PRIVATE_HIGH+PRIVATE_LOW,*seed_ref=&private_seed;')
        check='uint32_t SeedReferenceCheck(void){return seed_ref==&private_seed;}\n'
    text=text.replace('uint64_t Provider(', check+'uint64_t Provider(')
    text=text.replace('    alias->value+=delta;', '    if(!SeedReferenceCheck())return UINT64_MAX;\n    alias->value+=delta;')
    provider.write_text(text)
    header=destination/'port_types.h';header.write_text(header.read_text().replace('#endif','uint32_t SeedReferenceCheck(void);\n#endif'))
    adapter=destination/'adapter.c';adapter.write_text(adapter.read_text().replace('ctx->alias==&ctx->ledger ?', 'ctx->alias==&ctx->ledger && osrec_kernel_SeedReferenceCheck((struct osrec_kernel_context *)ctx) ?'))
    policy_file=destination/'checkpoint-policy.json';policy=json.loads(policy_file.read_text());policy['fields']['osrec_local_SeedReferenceCheck_seed_ref_0' if local else 'seed_ref']={'type':'const uint64_t *','policy':'transient'};policy_file.write_text(json.dumps(policy,indent=2)+'\n')
    port_file=destination/'port.json';port=json.loads(port_file.read_text());port['bundle']['inputs']={n:digest((destination/n).read_bytes()) for n in port['bundle']['inputs']};port_file.write_text(json.dumps(port,indent=2)+'\n')
    return port_file


class MixedDeclarationTests(unittest.TestCase):
    def test_readonly_references_reconstructed_between_images(self):
        self.check_reconstructed_references(local=False)

    def test_function_local_readonly_references_reconstructed_between_images(self):
        self.check_reconstructed_references(local=True)

    def check_reconstructed_references(self,local):
        with tempfile.TemporaryDirectory(prefix='osrec-mixed-declarations-') as name:
            stage=Path(name);port_root=stage/'port';port_file=prepare_fixture(port_root,local=local)
            args=SimpleNamespace(arch='aarch64',capture=port_root,kernel_root=stage/'unused',out=stage/'kernel',port=port_file,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000)
            kernel=export(args);plan=kernel['context_plan'];codec=kernel['checkpoint_codec']
            seed_name='osrec_local_SeedReferenceCheck_seed_ref_0' if local else 'seed_ref'
            self.assertEqual([f['name'] for f in plan['owned_state']],['ledger','alias',seed_name] if local else ['seed_ref','ledger','alias'])
            readonly=plan['lifted_constants'] if local else plan['retained_declarations'];self.assertEqual([f['declaration'] for f in readonly],['private_seed'])
            self.assertEqual(readonly[0]['source'],'provider.c')
            if local:self.assertEqual(readonly[0]['function'],'SeedReferenceCheck')
            self.assertEqual(kernel['state_layout']['OSREC_SLICE_STATE_BYTES'],32);self.assertEqual(codec['record_bytes'],80)
            seed_field=next(f for f in codec['fields'] if f['path']==seed_name);self.assertEqual(seed_field['policy'],'transient');self.assertNotIn('wire_offset',seed_field)
            self.assertIn('SeedReferenceCheck',plan['context_functions']);self.assertIn('SeedReferenceCheck',plan['function_dependencies']['Provider'])
            matrix=verify_matrix(args.out,stage/'kernel-qemu',qemu=QEMU,llvm_bin=LLVM);self.assertEqual(len(matrix['executions']),4)
            chain_args=SimpleNamespace(slices=args.out,source=[port_root/'application.c'],spec=port_root/'spec.json',pause_ordinals=[2,4,5],out=stage/'chain',llvm_bin=LLVM,qemu=QEMU)
            result=run_pipeline(chain_args);self.assertEqual(result['logical_calls'],6)
            values=[8589934601,4294967313,12884901908]
            for i,ordinal in enumerate((2,4,5)):
                joint=verify_joint(chain_args.out/('stage-'+str(i))/'checkpoint',kernel)
                self.assertEqual(len(joint['record']),80);self.assertEqual(struct.unpack_from('<QQ',joint['record'],64),(values[i],ordinal))
            for row in result['stages']:
                self.assertEqual(row['qemu_executions'],4);self.assertFalse(row['observations']['guest_host_services'])
            # A reviewed but wrong readonly-reference seed must fail the target
            # proof before any image is published.
            provider=port_root/'provider.c';provider.write_text(provider.read_text().replace('*seed_ref=&private_seed','*seed_ref=0'))
            port=json.loads(port_file.read_text());port['bundle']['inputs']['provider.c']=digest(provider.read_bytes());port_file.write_text(json.dumps(port))
            bad=SimpleNamespace(**dict(vars(args),out=stage/'bad-kernel'))
            with self.assertRaises(ValueError):export(bad)
            self.assertFalse(bad.out.exists())
            shutil.rmtree(port_root);verify_published(args.out/'port-inputs',kernel)
            self.assertEqual(verify_chain(chain_args.out)['status'],'verified')


if __name__=='__main__':unittest.main()
