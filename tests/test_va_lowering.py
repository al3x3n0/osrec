import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from va_lowering import branch,logical_value,logical_word,guard_exclusive_regions,BRK,SITE_STOP,lower_profile,isolated_constant

class Lowering(unittest.TestCase):
    @unittest.skipUnless(shutil.which('cc'),'host compiler required')
    def test_host_lowering_contracts(self):
        with tempfile.TemporaryDirectory() as tmp:
            for harness,source,defines in [('el0_lower_host.c','lower.c',[]),('el0_lower_mmu_host.c','lower_mmu.c',['-DOSREC_MMU_TEST'])]:
                exe=str(Path(tmp)/source)
                subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-DOSREC_LOWERED',*defines,'-I'+str(ROOT/'runtime/el0'),str(ROOT/'tests'/harness),str(ROOT/'runtime/el0'/source),'-o',exe],check=True,capture_output=True,text=True)
                result=subprocess.run([exe],check=True,capture_output=True,text=True)
                self.assertIn('contracts passed',result.stdout)
    def test_no_traps_inside_exclusive_regions(self):
        words={0x1000:0x885f7c20,0x1004:0xb7f80040,0x1008:0x88027c20}
        code={0x1004:BRK};extended={}
        self.assertEqual(guard_exclusive_regions(words,code,extended),1)
        self.assertEqual(code[0x1000],BRK)
        self.assertEqual(extended[0x1000],(words[0x1000],SITE_STOP))
        self.assertNotIn(0x1008,code)

    def test_task_size_subtraction_is_not_page_offset(self):
        from va_constants import sites,classify
        profile=lower_profile(dict(derived=[dict(name='-PAGE_OFFSET',expr='-PAGE_OFFSET',offsets=[0,0],uses=['add','sub'])]))
        params=dict(PAGE_OFFSET=0xffff000000000000,VMEMMAP_START=0xfffffdffc0000000)
        task_size={0x1000:0xd2e0002b,0x1004:0xcb08016b,0x1008:0xeb0a017f}
        kinds=classify(sites(task_size),params,profile['derived'],words=task_size)
        self.assertFalse(any(k and k[0]=='derived' for k in kinds))
        normalize={0x1000:0xd2e0002b,0x1004:0x8b0b0108}
        kinds=classify(sites(normalize),params,profile['derived'],words=normalize)
        self.assertTrue(any(k and k[:2]==('derived','-PAGE_OFFSET') for k in kinds))

    def test_partial_constant_consumption_requires_a_stop(self):
        site=dict(kind='mov',rd=8,insns=[(0x1000,0xd2d00208),(0x1008,0xf2ffffe8)])
        self.assertFalse(isolated_constant(site,{0x1004:0x8b080109}))
        self.assertFalse(isolated_constant(site,{0x1004:0x54000040}))
        self.assertTrue(isolated_constant(site,{0x1004:0xd51b4237}))

    def test_branch_range(self):
        self.assertEqual(branch(0x1000,0x1008),0x14000002)
        self.assertEqual(branch(0x1008,0x1000),0x17fffffe)
        with self.assertRaises(ValueError):branch(0,1<<27)
    def test_logical_roundtrip(self):
        for n in range(2):
            for r in range(64):
                for s in range(64):
                    word=0x92000000|n<<22|r<<16|s<<10
                    value=logical_value(word)
                    if value is not None:self.assertEqual(logical_value(logical_word(word,value)),value)
        self.assertEqual(logical_word(0xb24003e0,0),0xaa1f03e0)

if __name__=='__main__':unittest.main()
