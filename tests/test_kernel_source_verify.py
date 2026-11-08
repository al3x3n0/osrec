"""Source verification reads objects as ELF: st_size extents, RELA fields, zero runs and lld's ADRP+ADD relaxation."""
import shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import kernel_source_verify as ksv

LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
MC=str(LLVM/'llvm-mc');LLD=str(LLVM/'ld.lld')
SOURCE='''
    .text
    .globl entry
    .type entry,%function
entry:                       // adrp+add against data: lld relaxes to nop+adr
    adrp x9, table
    add  x9, x9, :lo12:table
    bl   callee
    ret
    .size entry, .-entry
    b    entry               // out-of-line code past st_size, not part of entry
    .globl padded
padded:                      // a zero run in the middle (objdump prints it as ...)
    sub  sp, sp, #0x150
    .zero 120
    b    callee
    .size padded, .-padded
    .globl callee
    .type callee,%function
callee:
    ret
    .size callee, .-callee
    .data
table: .quad 1
'''

def tools():return Path(MC).exists() and Path(LLD).exists()


@unittest.skipUnless(tools(),'llvm-mc and ld.lld are required')
class LinkedObject(unittest.TestCase):
    def setUp(self):
        self.tmp=Path(tempfile.mkdtemp());(self.tmp/'a.s').write_text(SOURCE)
        subprocess.run([MC,'-triple=aarch64-linux-gnu','-filetype=obj','-o',str(self.tmp/'a.o'),str(self.tmp/'a.s')],check=True)
        subprocess.run([LLD,'-o',str(self.tmp/'a.elf'),'-e','entry','-Ttext=0x400000','-Tdata=0x400800',str(self.tmp/'a.o')],check=True)
        self.obj=ksv.Elf(self.tmp/'a.o');self.image=ksv.Elf(self.tmp/'a.elf')
        self.address={s['name']:s['value'] for s in self.image.symbols}
    def tearDown(self):shutil.rmtree(self.tmp)
    def check(self,name):
        code,relocated=self.obj.function(name)
        return code,relocated,ksv.compare(code,relocated,self.image.read(self.address[name],len(code)))

    def test_relaxed_adrp_add_is_accepted_by_shape(self):
        code,relocated,(mismatched,unknown,relaxed)=self.check('entry')
        self.assertEqual(len(code),16)  # st_size: the trailing branch is excluded
        self.assertEqual(self.image.read(self.address['entry'],4),ksv.NOP.to_bytes(4,'little'))
        self.assertEqual((mismatched,unknown,relaxed),([],0,1))

    def test_zero_run_keeps_word_alignment(self):
        code,_,(mismatched,_,_)=self.check('padded')
        self.assertEqual(len(code),128);self.assertEqual(mismatched,[])

    def test_changed_word_is_reported(self):
        code,relocated=self.obj.function('padded');live=bytearray(self.image.read(self.address['padded'],len(code)))
        live[4]^=1
        self.assertEqual(ksv.compare(code,relocated,bytes(live))[0],[1])

    def test_relaxation_requires_its_exact_shape(self):
        code,relocated=self.obj.function('entry');live=bytearray(self.image.read(self.address['entry'],len(code)))
        live[4:8]=(int.from_bytes(live[4:8],'little')^1).to_bytes(4,'little')  # adr into another register
        mismatched,_,relaxed=ksv.compare(code,relocated,bytes(live))
        self.assertEqual(relaxed,0);self.assertTrue(mismatched)

    def test_relocated_field_only_is_ignored(self):
        code,relocated=self.obj.function('entry');live=bytearray(self.image.read(self.address['entry'],len(code)))
        bl=int.from_bytes(live[8:12],'little')
        live[8:12]=((bl&0xfc000000)|((bl+5)&0x03ffffff)).to_bytes(4,'little')
        self.assertEqual(ksv.compare(code,relocated,bytes(live))[0],[])
        live[8:12]=(bl^0x80000000).to_bytes(4,'little')  # bl -> b: opcode bits are outside the field
        self.assertEqual(ksv.compare(code,relocated,bytes(live))[0],[2])


class CompileCommandLookup(unittest.TestCase):
    def test_source_path_matches_exactly_not_by_suffix(self):
        tree='/src/linux'
        with tempfile.TemporaryDirectory() as tmp:
            entries=[dict(directory=tmp,file=tree+'/arch/arm64/mm/mmap.c',command='clang -c -o arch/arm64/mm/mmap.o x'),
                     dict(directory=tmp,file=tree+'/mm/mmap.c',command='clang -c -o mm/mmap.o x')]
            Path(tmp,'compile_commands.json').write_text(__import__('json').dumps(entries))
            units=ksv.Units(Path(tmp),type('Image',(),{'symbols':[]})())
            entry,how=units.entry(dict(source=tree+'/mm/mmap.c',function='find_vma',address=0))
            self.assertEqual((entry['file'],how),(tree+'/mm/mmap.c','source'))
            self.assertEqual(units.entry(dict(source=tree+'/lib/copy_template.S',function='f',address=0)),(None,'no_compile_command'))


if __name__=='__main__':unittest.main()
