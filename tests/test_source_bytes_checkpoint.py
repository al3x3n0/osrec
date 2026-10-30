"""Exact UTF-8/CRLF kernel inputs survive transformation and fresh images."""
import json
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from test_mixed_declaration_checkpoint import prepare_fixture as prepare_local_fixture
from export_syscall_slices import export
from verify_syscall_slices import verify_matrix
from run_c_application_checkpoint_chain import run_pipeline,verify_chain
from slice_port_bundle import digest,verify_published
from application_pause import verify_joint

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
LABEL='核;,/*)*/é🙂'


def prepare_fixture(destination):
    """Pin a real byte-oriented variant of the reviewed portable C fixture."""
    port_file=prepare_local_fixture(destination,local=True)
    provider=destination/'provider.c';text=provider.read_text(encoding='utf-8')
    original='return seed_ref==&private_seed;'
    if text.count(original)!=1:raise ValueError('source-byte fixture boundary check changed')
    expected=','.join(str(n) for n in LABEL.encode('utf-8')+b'\0')
    check='static const unsigned char label[]="'+LABEL+'";static const unsigned char *text=label;const unsigned char expected[]={'+expected+'};if(seed_ref!=&private_seed || text!=label || sizeof(label)!=sizeof(expected))return 0;for(unsigned i=0;i<sizeof(expected);++i)if(text[i]!=expected[i])return 0;return 1;'
    provider.write_text(text.replace(original,check),encoding='utf-8')
    # Both original kernel bodies, owned declarations/macros and the C app
    # carry multibyte text. The adapter copies prepared inputs byte-for-byte.
    for name in ('provider.c','kernel.c','port_types.h','application.c'):
        path=destination/name;body=path.read_text(encoding='utf-8')
        path.write_bytes(b'\xef\xbb\xbf'+('/* 原始文件 '+name+' é🙂 */\n'+body).replace('\n','\r\n').encode('utf-8'))
    policy_file=destination/'checkpoint-policy.json';policy=json.loads(policy_file.read_text())
    policy['fields']['osrec_local_SeedReferenceCheck_text_1']={'type':'const unsigned char *','policy':'transient'}
    policy_file.write_text(json.dumps(policy,indent=2)+'\n')
    port=json.loads(port_file.read_text());port['bundle']['inputs']={n:digest((destination/n).read_bytes()) for n in port['bundle']['inputs']}
    port_file.write_text(json.dumps(port,indent=2)+'\n')
    return port_file


class SourceByteTests(unittest.TestCase):
    def test_utf8_crlf_bom_provenance_and_checkpoint_chain(self):
        with tempfile.TemporaryDirectory(prefix='osrec-source-bytes-') as name:
            stage=Path(name);port_root=stage/'port';port_file=prepare_fixture(port_root)
            args=SimpleNamespace(arch='aarch64',capture=port_root,kernel_root=stage/'unused',out=stage/'kernel',port=port_file,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000)
            kernel=export(args);plan=kernel['context_plan'];codec=kernel['checkpoint_codec']
            self.assertEqual((plan['source_encoding'],plan['source_offsets']),('utf-8','bytes'))
            self.assertEqual(plan['input_sha256'],{n:digest((port_root/n).read_bytes()) for n in ('provider.c','kernel.c','port_types.h')})
            self.assertEqual([f['name'] for f in plan['owned_state']],['ledger','alias','osrec_local_SeedReferenceCheck_seed_ref_0','osrec_local_SeedReferenceCheck_text_1'])
            self.assertEqual([f['declaration'] for f in plan['lifted_constants']],['private_seed','label'])
            original=(port_root/'provider.c').read_bytes()
            for item in plan['lifted_constants']:
                self.assertEqual(original[item['offset']:item['offset']+len(item['declaration'])],item['declaration'].encode('utf-8'))
            self.assertEqual(kernel['state_layout']['OSREC_SLICE_STATE_BYTES'],40);self.assertEqual(codec['record_bytes'],80)
            text_field=next(f for f in codec['fields'] if f['path']=='osrec_local_SeedReferenceCheck_text_1');self.assertEqual(text_field['policy'],'transient');self.assertNotIn('wire_offset',text_field)
            for n in ('provider.c','kernel.c','port_types.h'):
                raw=(args.out/'sources'/n).read_bytes();self.assertTrue(raw.startswith(b'\xef\xbb\xbf'));self.assertEqual(raw.count(b'\xef\xbb\xbf'),1)
                self.assertIn(('/* 原始文件 '+n+' é🙂 */\r\n').encode('utf-8'),raw);raw.decode('utf-8')
            self.assertIn(LABEL.encode('utf-8'),(args.out/'sources/provider.c').read_bytes())
            matrix=verify_matrix(args.out,stage/'kernel-qemu',qemu=QEMU,llvm_bin=LLVM);self.assertEqual(len(matrix['executions']),4)
            chain_args=SimpleNamespace(slices=args.out,source=[port_root/'application.c'],spec=port_root/'spec.json',pause_ordinals=[2,4,5],out=stage/'chain',llvm_bin=LLVM,qemu=QEMU)
            result=run_pipeline(chain_args);self.assertEqual(result['logical_calls'],6)
            for i,pair in enumerate(((8589934601,2),(4294967313,4),(12884901908,5))):
                joint=verify_joint(chain_args.out/('stage-'+str(i))/'checkpoint',kernel)
                self.assertEqual(len(joint['record']),80);self.assertEqual(struct.unpack_from('<QQ',joint['record'],64),pair)
            for row in result['stages']:
                self.assertEqual(row['qemu_executions'],4);self.assertFalse(row['observations']['guest_host_services'])
            # Byte provenance includes comments, CRLF and the BOM. A harmless
            # comment change is still a different reviewed construction input.
            published=args.out/'port-inputs/provider.c';raw=published.read_bytes();published.write_bytes(raw.replace('原始文件'.encode('utf-8'),'修改文件'.encode('utf-8'),1))
            with self.assertRaisesRegex(ValueError,'input identity mismatch'):verify_published(args.out/'port-inputs',kernel)
            published.write_bytes(raw)
            # Re-pin a wrong reconstructed string and require a target-proof
            # failure, so intact pointers alone cannot conceal byte corruption.
            provider=port_root/'provider.c';raw=provider.read_bytes();provider.write_bytes(raw.replace(LABEL.encode('utf-8'),('錯'+LABEL[1:]).encode('utf-8'),1))
            port=json.loads(port_file.read_text());port['bundle']['inputs']['provider.c']=digest(provider.read_bytes());port_file.write_text(json.dumps(port))
            bad=SimpleNamespace(**dict(vars(args),out=stage/'bad-kernel'))
            with self.assertRaises(ValueError):export(bad)
            self.assertFalse(bad.out.exists())
            shutil.rmtree(port_root);verify_published(args.out/'port-inputs',kernel)
            self.assertEqual(verify_chain(chain_args.out)['status'],'verified')


if __name__=='__main__':unittest.main()
