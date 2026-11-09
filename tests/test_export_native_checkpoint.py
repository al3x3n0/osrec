"""Packing checks use independent byte reconstruction, not generated C execution."""
import errno
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from export_native_checkpoint import export,sparse_runs


class EmbeddedExport(unittest.TestCase):
    def fixture(self,root):
        package,oracle=root/'package',root/'oracle';package.mkdir();oracle.mkdir()
        size=8*4096
        header=struct.pack('<10Q',0x3145564954414e4c,1,0x40000000,size,16,1,1,0,0,1)
        (package/'native.bin').write_bytes(header)
        (package/'application.bin').write_bytes(b'application')
        (package/'vma.bin').write_bytes(b'vma')
        with (package/'memory.bin').open('wb') as file:
            file.truncate(size);file.seek(4096+17);file.write(b'captured page')
            file.seek(6*4096);file.write(bytes([0xa5])*4096)
        (package/'manifest.json').write_text(json.dumps(dict(source_image_sha256='a'*64,memory_size=size,application={'user_elf_sha256':'b'*64})))
        calls=[dict(number=25,arguments=[3,1,0,0,0,0],result=1),
               dict(event='exception',number=-1,arguments=[0x92000045,0x1000,0x201000],result=None),
               dict(event='exception',number=-1,arguments=[0x92000045,0x1000,0x201000],result=None),
               dict(number=142,arguments=[1,2,3,0,0,0],result=None)]
        record=dict(source_image_sha256='a'*64,calls=calls,counter_reads=1,mmio_accesses=1,
                    end=dict(stop_code=1,function='kernel_power_off+0x0',pc='0x80008008eb30'))
        (oracle/'calls.json').write_text(json.dumps(record))
        (oracle/'counters.bin').write_bytes(struct.pack('<3Q',0x800080000000,0xdf02,123))
        (oracle/'mmio.bin').write_bytes(struct.pack('<5Q',0x800080000004,0x80008000e000,4,1,65))
        return package,oracle

    def test_sparse_roundtrip_and_reproducible_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);package,oracle=self.fixture(root)
            first=export(package,oracle,root/'first');second=export(package,oracle,root/'second')
            self.assertEqual(first,second)
            self.assertEqual((root/'first'/'image.c').read_bytes(),(root/'second'/'image.c').read_bytes())
            payload=(root/'first'/'payload.bin').read_bytes();restored=bytearray(first['memory_size'])
            # Generated extent offsets point into the payload after aligned metadata.
            import re
            rows=re.findall(r'\{(\d+),\{osrec_checkpoint_payload\+(\d+),(\d+)\}\}',(root/'first'/'image.c').read_text())
            for offset,start,size in rows:
                offset,start,size=map(int,(offset,start,size));restored[offset:offset+size]=payload[start:start+size]
            self.assertEqual(restored,(package/'memory.bin').read_bytes())
            self.assertEqual(first['stored_memory_bytes'],8192)
            self.assertEqual(first['events'],3)
            start,size=first['asset_offsets']['expected']
            events=list(struct.iter_unpack('<10Q',payload[start:start+size]))
            self.assertEqual(events[0],(0,25,3,1,0,0,0,0,1,1))
            self.assertEqual(events[1],(1,(1<<64)-1,0x92000045,0x1000,0x201000,0,0,0,0,0))
            self.assertEqual(events[-1][-1],0)
            with (package/'memory.bin').open('rb') as file:
                with patch('os.lseek',side_effect=OSError(errno.EINVAL,'no sparse seeking')):
                    self.assertEqual(list(sparse_runs(file,first['memory_size'])),[(4096,8192),(24576,28672)])

    def test_reject_mismatched_or_truncated_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);package,oracle=self.fixture(root)
            original=json.loads((oracle/'calls.json').read_text())
            bad=dict(original,source_image_sha256='c'*64)
            (oracle/'calls.json').write_text(json.dumps(bad))
            with self.assertRaisesRegex(ValueError,'identities differ'):export(package,oracle,root/'wrong')
            (oracle/'calls.json').write_text(json.dumps(original))
            (oracle/'mmio.bin').write_bytes(b'x')
            with self.assertRaisesRegex(ValueError,'truncated hardware'):export(package,oracle,root/'short')


if __name__=='__main__':unittest.main()
