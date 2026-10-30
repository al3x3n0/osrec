"""Validate credential reconstruction, raw return bits and capture consistency."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from klee_liteos import digest
from live_credentials_replay import CALLS,decode_credentials,prepare_source,export_live_credentials
from export_freestanding_credentials import export
from run_freestanding_armv7 import observe,require_success
from freestanding_elf import describe,prepare_target
from freestanding_armv7 import run
KERNEL=ROOT/'build/kernel_liteos_a';LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'

class CredentialsTests(unittest.TestCase):
    def args(self,stage):
        return SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000,
            capture=stage/'capture',out=stage/'image',kernel_root=KERNEL,llvm_bin=LLVM,qemu=QEMU)

    def capture(self,args,euid=123,egid=456,pid=1,bad=None):
        args.capture.mkdir();_,identity=prepare_source(KERNEL)
        returns=[euid,egid,euid,egid]
        if bad is not None:returns[bad]^=1
        user=b''.join(struct.pack('<3I',number,raw,16) for number,raw in zip(CALLS,returns))
        kernel=b''.join(struct.pack('<6I',number,pid,euid,egid,raw,0x113) for number,raw in zip(CALLS,returns))
        metadata={'format':'osrec-live-credentials-checkpoint-v1','source_identity':identity,
            'checkpoint':decode_credentials(user,kernel),'kernel_image_sha256':'0'*64,
            'user_observations_sha256':digest(user),'kernel_observations_sha256':digest(kernel)}
        (args.capture/'credentials-user-observations.bin').write_bytes(user)
        (args.capture/'credentials-kernel-observations.bin').write_bytes(kernel)
        (args.capture/'credentials-checkpoint.manifest.json').write_text(json.dumps(metadata))
        return user,kernel

    def test_nondefault_and_high_bit_credentials(self):
        for euid,egid in ((123,456),(0xffffffff,0x80000000),(0,0)):
            with self.subTest(euid=euid),tempfile.TemporaryDirectory() as directory:
                args=self.args(Path(directory));self.capture(args,euid,egid)
                with contextlib.redirect_stdout(io.StringIO()):export(args)
                elf=args.out/'credentials.elf';layout=describe(elf)
                self.assertEqual(layout['entry'],args.entry_address);self.assertEqual(layout['result_address'],args.result_address)
                manifest=json.loads((args.out/'manifest.json').read_text())
                self.assertFalse(manifest['runtime_host_interaction']);self.assertEqual(manifest['system_libraries'],[])
                shutil.rmtree(args.capture);shutil.rmtree(args.out/'sources')
                (args.out/'checkpoint.json').unlink();(args.out/'manifest.json').unlink()
                report,raw=observe(elf,QEMU);require_success(report)
                raw_report,raw_result=observe(args.out/'credentials.bin',QEMU,descriptor=elf);require_success(raw_report)
                self.assertEqual(raw,raw_result)
                self.assertEqual([call['raw_bits'] for call in report['actual_calls']],[euid,egid,euid,egid])
                self.assertEqual(report['locks'],4);self.assertEqual(report['unlocks'],4)
                self.assertEqual(report['credential_accesses'],4);self.assertEqual(report['lock_depth'],0)

    def test_corrupt_returns_fail_in_target(self):
        for index in range(4):
            with self.subTest(index=index),tempfile.TemporaryDirectory() as directory:
                args=self.args(Path(directory));self.capture(args,bad=index)
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(args)
                self.assertFalse(args.out.exists())

    def test_corrupt_capture_never_publishes(self):
        for label in ('hash','source','field','configuration','reference','state','mode','kernel_return'):
            with self.subTest(label=label),tempfile.TemporaryDirectory() as directory:
                args=self.args(Path(directory));user,kernel=self.capture(args)
                path=args.capture/'credentials-checkpoint.manifest.json';metadata=json.loads(path.read_text())
                if label=='hash':(args.capture/'credentials-user-observations.bin').write_bytes(b'bad')
                elif label=='source':metadata['source_identity']['source']['revision']='changed'
                elif label=='field':metadata['checkpoint']['objects'][0]['effective_uid']=999
                elif label=='configuration':metadata['checkpoint']['configuration']['LOSCFG_SECURITY_CAPABILITY']=False
                elif label=='reference':metadata['checkpoint']['current_credentials']=0
                else:
                    data=bytearray(kernel);offset={'state':32,'mode':44,'kernel_return':40}[label]
                    struct.pack_into('<I',data,offset,8)
                    (args.capture/'credentials-kernel-observations.bin').write_bytes(data)
                    metadata['kernel_observations_sha256']=digest(data)
                path.write_text(json.dumps(metadata))
                with self.assertRaises(ValueError):export(args)
                self.assertFalse(args.out.exists())

    def test_lock_contract_rejects_broken_sequences(self):
        with tempfile.TemporaryDirectory() as directory:
            args=self.args(Path(directory));self.capture(args)
            with contextlib.redirect_stdout(io.StringIO()):export(args)
            sources=args.out/'sources';original=(sources/'credentials_syscalls.c').read_text()
            changes=(('SCHEDULER_LOCK(intSave);','intSave=UINT32_C(0x51a7);',3),
                     ('SCHEDULER_UNLOCK(intSave);','(void)intSave;',20),
                     ('SCHEDULER_UNLOCK(intSave);','(void)intSave; SCHEDULER_UNLOCK(0);',2))
            for before,after,error in changes:
                with self.subTest(error=error):
                    (sources/'credentials_syscalls.c').write_text(original.replace(before,after))
                    image=Path(directory)/'broken.elf'
                    flags=prepare_target(args,sources)
                    run([LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin',
                        '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
                        '-Wall','-Wextra','-Werror','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined',
                        '-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'credentials_replay.c',
                        sources/'credentials_syscalls.c','-o',image])
                    report,_=observe(image,QEMU)
                    self.assertEqual(report['status'],3);self.assertEqual(report['error'],error)
                    with self.assertRaisesRegex(ValueError,'target replay diverged'):require_success(report)

    def test_generated_snapshots_and_lock_failures(self):
        from reconstruct_entry_state import reconstruction_header
        values=(0xffffffff,0x80000000,123,456)
        plans=[];frames=[]
        for i,(number,value) in enumerate(zip(CALLS,values)):
            field='effUserID' if number==201 else 'effGid'
            plans.append({'blockers':[],'arguments':[],'state_writes':[],
                'object_providers':[{'function':'OsCurrUserGet','return_type':'User *'}],
                'entry_reads':[{'path':'OsCurrUserGet()->'+field,'pointer_edge':False,'volatile':False,'bitfield':False}]})
            frames.append({'format':'osrec-entry-snapshot-v1','objects':[{'id':1,'type':'User'}],
                'roots':[{'name':'OsCurrUserGet()','object_id':1}],
                'fields':[{'object_id':1,'name':field,'kind':'scalar','bytes':4,'data':struct.pack('<I',value).hex()}]})
        with tempfile.TemporaryDirectory() as directory:
            args=self.args(Path(directory));sources=Path(directory)/'sources';sources.mkdir()
            flags=prepare_target(args,sources)
            (sources/'entry_reconstruction.h').write_text(reconstruction_header(frames,plans))
            (sources/'credentials_checkpoint.h').write_text('struct checkpoint_call { uint32_t number,raw; };\nstatic const struct checkpoint_call checkpoint_calls[4]={'+
                ','.join('{'+str(n)+',UINT32_C('+str(v)+')}' for n,v in zip(CALLS,values))+'};\n')
            shutil.copy2(ROOT/'integrations/liteos_a/credentials_model.h',sources/'credentials_model.h')
            shutil.copy2(ROOT/'integrations/rtl_aarch64/credentials_snapshot_replay.c',sources/'credentials_replay.c')
            original,_=prepare_source(KERNEL)
            changes=((None,None,0),('SCHEDULER_LOCK(intSave);','intSave=UINT32_C(0x51a7);',3),
                     ('SCHEDULER_UNLOCK(intSave);','(void)intSave;',20),
                     ('SCHEDULER_UNLOCK(intSave);','(void)intSave; SCHEDULER_UNLOCK(0);',2))
            for before,after,error in changes:
                with self.subTest(error=error):
                    (sources/'credentials_syscalls.c').write_text(original if before is None else original.replace(before,after))
                    image=Path(directory)/'generated.elf'
                    run([LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin',
                        '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
                        '-Wall','-Wextra','-Werror','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined',
                        '-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'credentials_replay.c',
                        sources/'credentials_syscalls.c','-o',image])
                    report,_=observe(image,QEMU)
                    self.assertEqual(report['error'],error)
                    if error:self.assertEqual(report['status'],3)
                    else:
                        require_success(report)
                        self.assertEqual([call['raw_bits'] for call in report['actual_calls']],list(values))
                        self.assertEqual(report['current_pid'],0)

    def test_live_owner_rejected_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            args=self.args(Path(directory));user,kernel=self.capture(args,pid=3);args.out.mkdir()
            with self.assertRaisesRegex(ValueError,'owner'):export_live_credentials(args,user,kernel,'0'*64)
            self.assertEqual(list(args.out.iterdir()),[])

if __name__=='__main__':
    if len(sys.argv)==4:
        KERNEL=Path(sys.argv[1]);LLVM=Path(sys.argv[2]);QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
