"""Opt-in native execution of a statically linked, self-checking checkpoint."""
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from export_native_checkpoint import export,verify_standalone
from check_embedded_checkpoint import payload_file_offset
from source_image import compare
PACKAGE=os.environ.get('OSREC_NATIVE_APPLICATION')
ORACLE=os.environ.get('OSREC_NATIVE_APPLICATION_ORACLE')


class EmbeddedNative(unittest.TestCase):
    @unittest.skipUnless(sys.platform=='linux' and platform.machine() in ('aarch64','arm64') and PACKAGE and ORACLE,
                         'arm64 Linux and OSREC_NATIVE_APPLICATION/ORACLE required')
    def test_linked_state_and_acceptance_checks(self):
        package,oracle=Path(PACKAGE).resolve(),Path(ORACLE).resolve()
        cc='clang-19' if shutil.which('clang-19') else 'cc'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/'image';library=root/'library';empty=root/'empty';empty.mkdir()
            manifest=export(package,oracle,image)
            subprocess.run(['make','-C',str(ROOT/'runtime/linuxkernel_el0'),'CC='+cc,'OUT='+str(library),
                            'IMAGE='+str(image),'check-standalone-host','standalone-checkpoint'],check=True,capture_output=True,text=True,timeout=180)
            binary=image/'user-checkpoint';audit=verify_standalone(binary)
            self.assertTrue(audit['static']);self.assertFalse(audit['libc']);self.assertFalse(audit['tls'])
            run=subprocess.run([str(binary)],cwd=empty,check=True,capture_output=True,text=True,timeout=180)
            result=json.loads(run.stdout);self.assertTrue(result['verified']);self.assertEqual(result['events'],manifest['events'])
            trace=root/'calls.json'
            subprocess.run([str(binary),'--trace',str(trace)],cwd=empty,check=True,capture_output=True,text=True,timeout=180)
            self.assertTrue(compare(oracle/'calls.json',trace)['matches'])
            mutant=root/'wrong-expectation';shutil.copyfile(binary,mutant);mutant.chmod(0o755)
            with mutant.open('r+b') as file:
                file.seek(payload_file_offset(binary)+manifest['asset_offsets']['expected'][0]+64)
                value=file.read(1);file.seek(-1,1);file.write(bytes([value[0]^1]))
            rejected=subprocess.run([str(mutant)],cwd=empty,capture_output=True,text=True,timeout=180)
            self.assertNotEqual(rejected.returncode,0);self.assertFalse(json.loads(rejected.stdout)['verified'])
            guard=image/'image-check'
            subprocess.run([cc,'-std=c11','-O2','-Wall','-Wextra','-Werror','-mgeneral-regs-only','-mbranch-protection=none',
                            '-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pie','-mno-outline-atomics','-DOSREC_FREESTANDING',
                            '-I'+str(ROOT/'include'),'-I'+str(ROOT/'runtime/el0'),'-I'+str(ROOT/'tools'),
                            '-I'+str(ROOT/'runtime/linuxkernel_el0'),'-nostdlib','-static','-Wl,-e,_start,-Ttext-segment=0x600000000000',
                            str(ROOT/'tests/linuxkernel_image_host.c'),'image.c','image.S',
                            *map(str,sorted((library/'standalone').glob('*.o'))),'-o',str(guard)],
                           cwd=image,check=True,capture_output=True,text=True,timeout=180)
            checked=subprocess.run([str(guard)],cwd=empty,check=True,capture_output=True,text=True,timeout=120)
            self.assertIn('failure cleanup passed',checked.stdout)
            # Auditing a static ELF alone cannot establish that libc is absent.
            link_map=binary.with_name(binary.name+'.map');text=link_map.read_text()
            link_map.write_text(text+'\nLOAD /lib/libc.a\n')
            with self.assertRaisesRegex(ValueError,'unexpected standalone linker input'):verify_standalone(binary)
            link_map.write_text(text)


if __name__=='__main__':unittest.main()
