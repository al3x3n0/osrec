"""Native application continuation, checked against an independent QEMU run."""
import json
import mmap
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from source_image import compare
PACKAGE=os.environ.get('OSREC_NATIVE_APPLICATION')
ORACLE=os.environ.get('OSREC_NATIVE_APPLICATION_ORACLE')


def probe(package):
    data=(package/'native.bin').read_bytes();h=struct.unpack_from('<10Q',data)
    root=struct.unpack_from('<Q',data,80+272+520+72)[0]&0x0000fffffffff000
    table_sites=80+272+520+532584+16*h[5]
    target=struct.unpack_from('<Q',data,table_sites)[0]
    a=struct.unpack_from('<10Q',(package/'application.bin').read_bytes())
    with (package/'memory.bin').open('rb') as file,mmap.mmap(file.fileno(),0,access=mmap.ACCESS_READ) as memory:
        for pc in range(a[8],a[9],4):
            table=root
            for shift in (39,30,21,12):
                d,=struct.unpack_from('<Q',memory,table-h[2]+8*(pc>>shift&511))
                if not d&1:break
                if shift>12 and d&2:table=d&0x0000fffffffff000;continue
                pa=(d&0x0000fffffffff000)&~((1<<shift)-1)
                word,=struct.unpack_from('<I',memory,pa-h[2]+(pc&((1<<shift)-1)))
                if word&0x3b000000==0x39000000 and not word&(1<<26) and word>>22&3==1:
                    size=1<<(word>>30)
                    return pc,(word>>5)&31,((word>>10)&4095)*size,target
                break
    raise AssertionError('no scalar application load for guard test')


class NativeApplication(unittest.TestCase):
    @unittest.skipUnless(sys.platform=='linux' and platform.machine() in ('aarch64','arm64') and PACKAGE and ORACLE,
                         'arm64 Linux and OSREC_NATIVE_APPLICATION/ORACLE required')
    def test_complete_application(self):
        package,oracle=Path(PACKAGE).resolve(),Path(ORACLE).resolve()
        cc='clang-19' if shutil.which('clang-19') else 'cc'
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)
            subprocess.run(['make','-C',str(ROOT/'runtime/linuxkernel_el0'),'OUT='+str(out),'CC='+cc,'checkpoint'],
                           check=True,capture_output=True,text=True,timeout=180)
            expected=json.loads((oracle/'calls.json').read_text())
            for executable in ('user-checkpoint','user-checkpoint-shared'):
                record=out/(executable+'.json')
                subprocess.run([str(out/executable),str(package),str(oracle/'counters.bin'),str(record),str(oracle/'mmio.bin')],
                               check=True,capture_output=True,text=True,timeout=180)
                self.assertTrue(compare(oracle/'calls.json',record)['matches'])
                actual=json.loads(record.read_text())
                self.assertEqual(actual['end']['pc'],expected['end']['pc'])
                self.assertEqual(actual['end']['stop_code'],1)
                self.assertEqual(actual['counters_consumed'],(oracle/'counters.bin').stat().st_size//24)
                self.assertEqual(actual['mmio_consumed'],(oracle/'mmio.bin').stat().st_size//40)
            guard=out/'guard'
            subprocess.run([cc,'-D_XOPEN_SOURCE=700','-std=c11','-O2','-Wall','-Wextra','-Werror',
                            '-I'+str(ROOT/'include'),'-I'+str(ROOT/'runtime/el0'),
                            str(ROOT/'tests/linuxkernel_application_guard.c'),str(out/'liblinuxkernel-el0.a'),'-o',str(guard)],
                           check=True,capture_output=True,text=True)
            result=subprocess.run([str(guard),str(package),*[str(v) for v in probe(package)]],
                                  check=True,capture_output=True,text=True,timeout=60)
            self.assertIn('guard and recovery passed',result.stdout)
            target=next(c['result'] for c in expected['calls'] if c['number']==222 and c['result'] is not None and c['result']<1<<48)
            collision=subprocess.run([str(guard),'collision',str(package),str(oracle/'counters.bin'),str(target)],
                                     check=True,capture_output=True,text=True,timeout=60)
            self.assertIn('collision rejected before user access',collision.stdout)


if __name__=='__main__':unittest.main()
