"""Supplied sectionless user ELFs and retained joint checkpoints share one chain engine."""
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
from compile_c_application import compile_application
from import_application_checkpoint import digest
from run_application_checkpoint_chain import run_pipeline
from application_checkpoint_chain import verify_chain
from application_pause import verify_joint

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/portable-slice-port'


class ElfChainTests(unittest.TestCase):
    def test_supplied_elf_resume_and_finish_only(self):
        with tempfile.TemporaryDirectory(prefix='osrec-user-elf-') as name:
            stage=Path(name);source=stage/'source';shutil.copytree(FIXTURE,source)
            options=SimpleNamespace(arch='aarch64',capture=source,kernel_root=stage/'unused',out=stage/'kernel',port=source/'port.json',llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000)
            kernel=export(options)
            compile_application([source/'application.c'],source/'port.json',stage/'compiled',LLVM,json.loads((source/'spec.json').read_text()),6)
            # The supplied input has no sections, symbols, source or build manifest.
            raw=bytearray((stage/'compiled/application.elf').read_bytes());struct.pack_into('<Q',raw,40,0);struct.pack_into('<HHH',raw,58,0,0,0)
            elf=stage/'application.elf';elf.write_bytes(raw)
            checkpoint=stage/'checkpoint.json';metadata=json.loads((stage/'compiled/checkpoint.json').read_text());metadata['elf_sha256']=digest(raw);checkpoint.write_text(json.dumps(metadata))
            shutil.rmtree(source);shutil.rmtree(stage/'compiled')
            base=dict(slices=options.out,llvm_bin=LLVM,qemu=QEMU)
            args=SimpleNamespace(**base,elf=elf,checkpoint=checkpoint,pause_ordinals=[2,4,5],out=stage/'elf-chain')
            root=run_pipeline(args);self.assertEqual(root['input_mode'],'elf');self.assertEqual(root['logical_calls'],6)
            self.assertEqual([r['generation'] for r in root['stages']],[1,2,3,None]);self.assertFalse((args.out/'compiled').exists())
            self.assertEqual((args.out/'inputs/application.elf').read_bytes(),raw)
            first=args.out/'stage-0/checkpoint'
            continuation=SimpleNamespace(**base,resume_checkpoint=first,pause_ordinals=[4,5],out=stage/'resumed-chain')
            resumed=run_pipeline(continuation);self.assertEqual(resumed['first_ordinal'],2);self.assertEqual(resumed['logical_calls'],4)
            self.assertEqual([(r['input_ordinal'],r['output_ordinal']) for r in resumed['stages']],[(2,4),(4,5),(5,6)])
            self.assertEqual([r['generation'] for r in resumed['stages']],[2,3,None]);self.assertEqual([r['observations']['completed_calls'] for r in resumed['stages']],[4,2,2])
            self.assertEqual(resumed['stages'][0]['observations']['checkpoint_start_ordinal'],2)
            self.assertEqual(root['stages'][0]['observations']['current_state_address'],resumed['stages'][0]['observations']['producer_state_address'])
            self.assertNotEqual(resumed['stages'][0]['observations']['producer_state_address'],resumed['stages'][0]['observations']['current_state_address'])
            # A final consumer needs no additional intermediate checkpoint.
            final=SimpleNamespace(**base,resume_checkpoint=continuation.out/'stage-0/checkpoint',pause_ordinals=[],out=stage/'finish-only')
            completed=run_pipeline(final);self.assertEqual(completed['first_ordinal'],4);self.assertEqual(completed['logical_calls'],2);self.assertEqual(len(completed['stages']),1)
            self.assertEqual(completed['stages'][0]['stage'],'finish');self.assertEqual(completed['stages'][0]['observations']['completed_calls'],4)
            for result in (root,resumed,completed):
                for row in result['stages']:
                    self.assertEqual(row['qemu_executions'],4);self.assertFalse(row['observations']['guest_host_services'])
            for points in ([1],[2],[6],[4,4],[5,4],[True]):
                invalid=SimpleNamespace(**base,resume_checkpoint=first,pause_ordinals=points,out=stage/'invalid')
                with self.assertRaisesRegex(ValueError,'increase'):run_pipeline(invalid)
                self.assertFalse(invalid.out.exists())
            bad=dict(metadata);bad['calls']=bad['calls'][:-1];checkpoint.write_text(json.dumps(bad))
            invalid=SimpleNamespace(**base,elf=elf,checkpoint=checkpoint,pause_ordinals=[2],out=stage/'bad-elf-count')
            with self.assertRaisesRegex(ValueError,'route count/ordinal'):run_pipeline(invalid)
            self.assertFalse(invalid.out.exists())
            # A user ELF alone cannot restore an arbitrary later kernel ordinal.
            joint=verify_joint(first,kernel)
            invalid=SimpleNamespace(**base,elf=first/'application/original.elf',checkpoint=first/'application/checkpoint.json',pause_ordinals=[4],out=stage/'missing-kernel-state')
            with self.assertRaisesRegex(ValueError,'joint kernel state'):run_pipeline(invalid)
            self.assertFalse(invalid.out.exists());self.assertEqual(joint['pause_ordinal'],2)
            # Retained artifacts are independent of source checkpoints and ELF inputs.
            elf.unlink();checkpoint.unlink();shutil.rmtree(args.out)
            verify_chain(continuation.out)
            shutil.rmtree(continuation.out);verify_chain(final.out)
            workflow=final.out/'workflow.json';saved=workflow.read_bytes();bad=json.loads(saved);bad['first_ordinal']=3;bad['logical_calls']=3;workflow.write_text(json.dumps(bad))
            with self.assertRaises(ValueError):verify_chain(final.out)
            workflow.write_bytes(saved)
            saved_record=final.out/'initial-checkpoint/kernel.bin';saved=saved_record.read_bytes();saved_record.write_bytes(b'bad')
            with self.assertRaises(ValueError):verify_chain(final.out)
            saved_record.write_bytes(saved);verify_chain(final.out)


if __name__=='__main__':unittest.main()
