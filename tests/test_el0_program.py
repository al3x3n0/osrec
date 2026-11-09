"""Full-checkpoint continuation and two independent negative checks."""
import os,struct,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from check_el0_program import run
from kernel_source_verify import Elf

@unittest.skipUnless(os.environ.get('OSREC_EL0_PROGRAM_IMAGE') and os.environ.get('OSREC_EL0_PROGRAM_OBSERVER'),
                     'set OSREC_EL0_PROGRAM_IMAGE and OSREC_EL0_PROGRAM_OBSERVER for native full-checkpoint tests')
class Program(unittest.TestCase):
    def test_complete_computation_and_validation_inputs(self):
        image=Path(os.environ['OSREC_EL0_PROGRAM_IMAGE']).resolve()
        observer=Path(os.environ['OSREC_EL0_PROGRAM_OBSERVER']).resolve()
        elf=Elf(image/'checkpoint');symbols={s['name']:s for s in elf.symbols if s['shndx']}
        def mutated(destination,name,offset):
            destination.mkdir();data=bytearray(elf.data);va=symbols[name]['value']+offset
            section=next(s for s in elf.sections if s['addr']<=va<s['addr']+s['size'])
            at=section['offset']+va-section['addr'];data[at]^=1
            binary=destination/'checkpoint';binary.write_bytes(data);binary.chmod(0o755)
        with tempfile.TemporaryDirectory() as name:
            root=Path(name)
            valid=run(image,root/'valid',observer)
            self.assertTrue(valid['verified']);self.assertEqual(valid['result']['events'],2272)
            self.assertEqual((valid['result']['counters'],valid['result']['uart_bytes']),(9,92))
            mutated(root/'bad-oracle','flat_expected',64)
            invalid=run(root/'bad-oracle',root/'oracle-check',observer)
            self.assertFalse(invalid['verified']);self.assertEqual(invalid['result']['first_mismatch'],0)
            # Corrupting expected results changes validation, never execution.
            self.assertEqual(invalid['result']['events'],2272)
            self.assertEqual((invalid['result']['counters'],invalid['result']['uart_bytes']),(9,92))
            self.assertEqual(invalid['result']['debug'],valid['result']['debug'])
            mutated(root/'bad-code-map','flat_user_text',8)
            invalid=run(root/'bad-code-map',root/'code-map-check',observer)
            self.assertFalse(invalid['verified'])
            self.assertEqual((invalid['result']['reason'],invalid['result']['detail']),(3,0x102))
            self.assertEqual(invalid['result']['transitions'],0)

if __name__=='__main__':unittest.main()
