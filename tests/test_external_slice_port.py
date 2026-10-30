"""A copied external 64-bit port uses the shared build, replay and checkpoint path."""
import json
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from export_syscall_slices import export,validate_port
from verify_syscall_slices import verify_matrix
from run_c_application_checkpoint_chain import run_pipeline,verify_chain
from slice_port_bundle import digest,verify_published
from application_pause import verify_joint
from export_application_replay import export as compose
from run_freestanding_armv7 import require_success
from freestanding_armv7 import run
from contextify_slice import transform

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/portable-slice-port'


def nested_fixture(destination):
    """Relocate the reviewed fixture without flattening its source/header layout."""
    shutil.copytree(FIXTURE,destination)
    mapping={'provider.c':'models/kernel.c','kernel.c':'syscalls/kernel.c','port_types.h':'include/port_types.h','adapter.c':'session/slice_driver.c','proof.c':'verification/proof.c'}
    for old,new in mapping.items():
        target=destination/new;target.parent.mkdir(parents=True,exist_ok=True);(destination/old).rename(target)
    for source,macro in (('models/kernel.c','MODEL_DELTA'),('syscalls/kernel.c','SYSCALL_DELTA')):
        path=destination/source;text=path.read_text().replace('#include "port_types.h"','#include "../include/port_types.h"\n#include "private.h"')
        text=text.replace('alias->value+=delta','alias->value+=MODEL_DELTA(delta)') if source.startswith('models/') else text.replace('APPLY_DELTA(delta,output)','APPLY_DELTA(SYSCALL_DELTA(delta),output)')
        path.write_text(text);path.with_name('private.h').write_text('#define '+macro+'(n) (n)\n')
    adapter=destination/'prepare.py';text=adapter.read_text()
    for old,new in (*mapping.items(),('capture.c','data/capture.c')):text=text.replace("'"+old+"'","'"+new+"'")
    text=text.replace("        shutil.copyfile(root/name, sources/name)","        (sources/name).parent.mkdir(parents=True,exist_ok=True)\n        shutil.copyfile(root/name, sources/name)")
    text=text.replace("'checkpoint-policy.json'):","'checkpoint-policy.json', 'models/private.h', 'syscalls/private.h'):")
    text=text.replace("    (sources/'data/capture.c').write_text", "    (sources/'data').mkdir()\n    (sources/'data/capture.c').write_text")
    text=text.replace("headers=['include/port_types.h']","headers=['include/port_types.h','models/private.h','syscalls/private.h']")
    adapter.write_text(text)
    port_file=destination/'port.json';port=json.loads(port_file.read_text());bundle=port['bundle']
    bundle['proofs']['session']['source']=mapping['proof.c']
    names=[mapping.get(n,n) for n in bundle['inputs']]+['models/private.h','syscalls/private.h']
    bundle['inputs']={n:digest((destination/n).read_bytes()) for n in names}
    port_file.write_text(json.dumps(port,indent=2)+'\n')
    return port_file


class ExternalPortTests(unittest.TestCase):
    def test_nested_sources_same_basenames_and_checkpoint_chain(self):
        with tempfile.TemporaryDirectory(prefix='osrec-nested-port-') as name:
            stage=Path(name);port_root=stage/'external port';port_file=nested_fixture(port_root)
            args=SimpleNamespace(arch='aarch64',capture=port_root,kernel_root=stage/'unused',out=stage/'kernel',port=port_file,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000)
            kernel=export(args);plan=kernel['context_plan']
            self.assertEqual([(f['name'],f['source']) for f in plan['value_initializers']],[('ledger','models/kernel.c'),('alias','models/kernel.c')])
            names=['models/kernel.c','syscalls/kernel.c','include/port_types.h','models/private.h','syscalls/private.h']
            self.assertEqual(plan['input_sha256'],{n:digest((port_root/n).read_bytes()) for n in names})
            self.assertEqual(plan['function_dependencies']['Add'],['Provider'])
            for n in names[:2]:self.assertTrue((args.out/'sources'/n).read_text().startswith('#include "slice_context.h"'))
            members=run([LLVM/'llvm-ar','t',args.out/'slices.a']).stdout.splitlines()
            self.assertEqual(len(members),len(set(members)))
            self.assertEqual(sum(n.endswith('-kernel.c.o') for n in members),2)
            # An adapter named slice_driver.c belongs in the library; only the
            # root proof driver is excluded. This is a full-path decision.
            self.assertEqual(sum(n.endswith('-slice_driver.c.o') for n in members),1)
            symbols=run([LLVM/'llvm-nm','--defined-only',args.out/'slices.a']).stdout
            self.assertIn('osrec_kernel_adapter',symbols);self.assertIn('osrec_kernel_Provider',symbols);self.assertIn('osrec_kernel_Add',symbols)
            self.assertEqual(kernel['state_layout']['OSREC_SLICE_STATE_BYTES'],24);self.assertEqual(kernel['checkpoint_codec']['record_bytes'],80)
            matrix=verify_matrix(args.out,stage/'kernel-qemu',qemu=QEMU,llvm_bin=LLVM);self.assertEqual(len(matrix['executions']),4)
            chain_args=SimpleNamespace(slices=args.out,source=[port_root/'application.c'],spec=port_root/'spec.json',pause_ordinals=[2,4,5],out=stage/'chain',llvm_bin=LLVM,qemu=QEMU)
            result=run_pipeline(chain_args);self.assertEqual(result['logical_calls'],6)
            for i,ordinal in enumerate((2,4,5)):
                joint=verify_joint(chain_args.out/('stage-'+str(i))/'checkpoint',kernel)
                self.assertEqual(struct.unpack_from('<Q',joint['record'],72)[0],ordinal)
            for row in result['stages']:
                self.assertEqual(row['qemu_executions'],4);self.assertFalse(row['observations']['guest_host_services'])
            # Distinct basename pins survive publication, original input removal
            # and composition. Tampering with either copy is still detected.
            for n in names[:2]:
                damaged=args.out/'port-inputs'/n;raw=damaged.read_bytes();damaged.write_bytes(raw+b'\n')
                with self.assertRaisesRegex(ValueError,'input identity mismatch'):verify_published(args.out/'port-inputs',kernel)
                damaged.write_bytes(raw)
            shutil.rmtree(port_root);verify_published(args.out/'port-inputs',kernel)
            self.assertEqual(verify_chain(chain_args.out)['status'],'verified')

    def test_prepared_source_path_rejections_before_mutation(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/'toy.h').write_text('#include <stdint.h>\nuint64_t Root(void);\n')
            original='#include "toy.h"\nstatic uint64_t value;\nuint64_t Root(void){return ++value;}\n';(root/'kernel.c').write_text(original)
            (root/'alias.c').symlink_to(root/'kernel.c')
            for names,headers in ((['kernel.c','kernel.c'],['toy.h']),(['kernel.c'],['toy.h','kernel.c']),(['./kernel.c'],['toy.h']),(['../kernel.c'],['toy.h']),([str(root/'kernel.c')],['toy.h']),(['alias.c'],['toy.h'])):
                with self.subTest(names=names,headers=headers):
                    with self.assertRaisesRegex(ValueError,'prepared source'):transform(root,names,headers,LLVM/'clang')
                    self.assertEqual((root/'kernel.c').read_text(),original);self.assertFalse((root/'slice_context.h').exists())

    def test_external_64bit_port_fresh_chain_and_rejections(self):
        with tempfile.TemporaryDirectory(prefix='osrec-external-svc-') as name:
            stage=Path(name);port_root=stage/'external port';shutil.copytree(FIXTURE,port_root)
            port_file=port_root/'port.json';port=json.loads(port_file.read_text())
            args=SimpleNamespace(arch='aarch64',capture=port_root,kernel_root=stage/'no-native-kernel-required',out=stage/'kernel',port=port_file,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000)
            # Invalid construction identities reject before executing adapter Python.
            adapter=port_root/'prepare.py';saved=adapter.read_bytes();adapter.write_bytes(b'raise RuntimeError("must not execute")\n'+saved)
            with self.assertRaisesRegex(ValueError,'input identity mismatch'):export(args)
            self.assertFalse(args.out.exists());adapter.write_bytes(saved)
            overlap=dict(vars(args));overlap['out']=port_root/'image'
            with self.assertRaisesRegex(ValueError,'overlaps'):export(SimpleNamespace(**overlap))
            for changes in ({'adapter':'../prepare.py'},{'adapter':'/tmp/prepare.py'},{'adapter':'missing.py'},{'inputs':{'prepare.py':'wrong'}},{'proofs':{}},{'proofs':{'session':{'source':'proof.c','result_abi':True}}}):
                bad=dict(port);bad['bundle']=dict(port['bundle'],**changes)
                with self.assertRaises(ValueError):validate_port(bad)
            missing=dict(vars(args),application_frame=True);missing['out']=stage/'missing-proof'
            with self.assertRaisesRegex(ValueError,'lacks selected frame proof'):export(SimpleNamespace(**missing))
            kernel=export(args);observed=kernel['target_observations'];self.assertEqual(observed['abi_version'],26);self.assertEqual(observed['completed_calls'],18)
            self.assertEqual([(f['name'],f['source']) for f in kernel['context_plan']['value_initializers']],[('ledger','provider.c'),('alias','provider.c')])
            self.assertNotIn('private_seed',(args.out/'sources/slice_context.h').read_text())
            self.assertEqual(kernel['state_layout']['OSREC_SLICE_STATE_BYTES'],24);self.assertEqual(kernel['checkpoint_codec']['record_bytes'],80)
            self.assertIsNone(kernel['kernel_image_sha256']);self.assertEqual(kernel['source_identity']['kind'],'synthetic-aarch64-portability-fixture')
            verify_published(args.out/'port-inputs',kernel)
            matrix=verify_matrix(args.out,stage/'kernel-qemu',qemu=QEMU,llvm_bin=LLVM);self.assertEqual(len(matrix['executions']),4)
            chain_args=SimpleNamespace(slices=args.out,source=[port_root/'application.c'],spec=port_root/'spec.json',pause_ordinals=[2,4,5],out=stage/'chain',llvm_bin=LLVM,qemu=QEMU)
            result=run_pipeline(chain_args);self.assertEqual(result['logical_calls'],6)
            self.assertEqual([r['observations']['completed_calls'] for r in result['stages']],[2,4,2,2])
            values=[json.loads((port_root/'capture.json').read_text())['initial_value']]+[c['raw_bits'] for c in json.loads((port_root/'capture.json').read_text())['calls']]
            for i,ordinal in enumerate((2,4,5)):
                checkpoint=chain_args.out/('stage-'+str(i))/'checkpoint';joint=verify_joint(checkpoint,kernel)
                self.assertEqual(struct.unpack_from('<QQ',joint['record'],64),(values[ordinal],ordinal))
                cp=json.loads((checkpoint/'application/checkpoint.json').read_text());self.assertEqual(len(cp['completed_calls']),ordinal)
                self.assertEqual(cp['frame']['v'],json.loads(chain_args.spec.read_text())['frame']['v'])
            for row in result['stages']:
                self.assertEqual(row['qemu_executions'],4);self.assertFalse(row['observations']['guest_host_services'])
            self.assertEqual(verify_chain(chain_args.out)['status'],'verified')
            # The original port directory is unnecessary for replay/verification.
            shutil.rmtree(port_root)
            verify_chain(chain_args.out);verify_published(args.out/'port-inputs',kernel)
            damaged=args.out/'port-inputs/kernel.c';raw=damaged.read_bytes();damaged.write_bytes(raw+b'\n')
            with self.assertRaisesRegex(ValueError,'input identity mismatch'):verify_published(args.out/'port-inputs',kernel)
            composition=SimpleNamespace(slices=args.out,application=chain_args.out/'routes',out=stage/'bad-compose',arch='aarch64',entry_address=0x40800000,result_address=0x40380000,llvm_bin=LLVM,qemu=QEMU)
            with self.assertRaisesRegex(ValueError,'input identity mismatch'):compose(composition)
            damaged.write_bytes(raw)
            retained=chain_args.out/'stage-1/image/kernel-port-inputs/prepare.py';raw=retained.read_bytes();retained.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'input identity mismatch'):verify_chain(chain_args.out)
            retained.write_bytes(raw);verify_chain(chain_args.out)
            for field in ('return_value_checks','recipe_checks','restart_checks','scalar_width'):
                bad=dict(observed);bad[field]=0
                with self.assertRaises(ValueError):require_success(bad)

    def test_reviewed_but_incorrect_port_rejected_on_target(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);port_root=stage/'port';shutil.copytree(FIXTURE,port_root)
            port_file=port_root/'port.json';original=json.loads(port_file.read_text())
            args=SimpleNamespace(arch='aarch64',capture=port_root,kernel_root=stage/'unused',out=stage/'bad',port=port_file,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000)
            provider=port_root/'provider.c';saved=provider.read_bytes();provider.write_bytes(saved.replace(b'alias->value+=delta',b'alias->value+=(uint32_t)delta'))
            port=json.loads(json.dumps(original));port['bundle']['inputs']['provider.c']=digest(provider.read_bytes());port_file.write_text(json.dumps(port))
            with self.assertRaises(ValueError):export(args)
            self.assertFalse(args.out.exists());provider.write_bytes(saved)
            port=dict(original,argument_width=32);port_file.write_text(json.dumps(port))
            with self.assertRaises(ValueError):export(args)
            self.assertFalse(args.out.exists())
            port=json.loads(json.dumps(original));port['bundle']['proofs']['session']['result_abi']=18;port_file.write_text(json.dumps(port))
            with self.assertRaisesRegex(ValueError,'proof result ABI differs'):export(args)
            self.assertFalse(args.out.exists())


if __name__=='__main__':unittest.main()
