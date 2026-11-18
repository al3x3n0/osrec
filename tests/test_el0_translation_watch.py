"""Write tracking must precede every fast return from write admission."""
from pathlib import Path
import hashlib,json,os,shutil,struct,subprocess,sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))

class Admission(unittest.TestCase):
    def test_requires_pretranslated_backend(self):
        from export_el0_program import export
        with self.assertRaisesRegex(ValueError,'requires --pretranslated-memory'):
            export(None,None,None,None,None,track_pretranslated_writes=True)

@unittest.skipUnless(shutil.which('cc'),'host compiler required')
class Writes(unittest.TestCase):
    def test_actual_admission_page_boundaries_partial_writes_bitmap_and_ttbr(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/'test'
            strip=['-Wl,-dead_strip'] if sys.platform=='darwin' else ['-Wl,--gc-sections']
            result=subprocess.run(['cc','-O2','-std=c11','-Wall','-Wextra','-Werror',
                '-ffunction-sections','-fdata-sections','-DOSREC_LOWERED',
                '-DOSREC_TRACK_PRETRANSLATED_WRITES=1',
                '-I'+str(ROOT/'runtime/el0_flat'),'-I'+str(ROOT/'runtime/el0'),
                str(ROOT/'tests/el0_translation_watch_host.c'),str(ROOT/'runtime/el0_flat/memory.c'),
                *strip,'-o',str(binary)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)

@unittest.skipUnless(os.environ.get('OSREC_EL0_TRACKED_IMAGE'),'tracked image not selected')
class FullImage(unittest.TestCase):
    def test_every_original_and_cloned_native_store_retains_a_checked_adapter(self):
        import re
        from el0_flat_lower import decode,MEMORY,LOAD
        from export_el0_program import Package
        from kernel_source_verify import Elf
        image=Path(os.environ['OSREC_EL0_TRACKED_IMAGE']).resolve();elf=Elf(image/'checkpoint')
        manifest=json.loads((image/'manifest.json').read_text());package=Package(Path(manifest['package']))
        symbol=next(s for s in elf.symbols if s['name']=='flat_ops')
        operations={r[0]:r for r in struct.iter_unpack('<8Q',elf.read(symbol['value'],manifest['adaptations']*64))}
        def store(word):
            op=decode(word)
            return op.kind==MEMORY and not op.info&LOAD or word&~31==0xd50b7420
        macros={}
        with (image/'program.S').open() as stream:
            for line in stream:
                if line.startswith(('flat_capture ','flat_native_capture ','flat_resume ','flat_native_resume ')):
                    macro,arguments=line.strip().split(' ',1);macros[arguments.split(',')[0]]=macro
                match=re.fullmatch(r'\.Lp([0-9a-f]+):\n',line)
                if not match:continue
                pc=int(match[1],16)
                if pc in operations:continue
                word=package.word(pc)
                if word==0xd421e000 and pc in package.sites:word=package.sites[pc][0]
                self.assertFalse(store(word),'untracked native store at %#x'%pc)
        for pc,row in operations.items():
            if row[5]==MEMORY and not row[6]&LOAD:
                self.assertEqual(macros['.Lnr%x'%pc],'flat_resume')
                self.assertEqual(macros['.Ld%x'%pc],'flat_capture')
        proof=json.loads((image/'call-specialization.json').read_text())
        for function in proof['functions']:
            for pc,word in function['instructions']:
                self.assertFalse(store(int(word,16)),'untracked cloned store at '+pc)

    def test_model_rejects_missing_dependency_dirty_bypass_range_and_bitmap_holes(self):
        self.reject_mutations(('dependency','dirty','range','bitmap'))

    def test_model_rejects_writable_descriptor_records(self):
        self.reject_mutations(('permissions',))

    def reject_mutations(self,modes):
        from kernel_source_verify import Elf
        from el0_hardware_model import prepare
        image=Path(os.environ['OSREC_EL0_TRACKED_IMAGE']).resolve();elf=Elf(image/'checkpoint')
        symbols={s['name']:s for s in elf.symbols if s['shndx']}
        def offset(address):
            section=next(s for s in elf.sections if s['addr']<=address<s['addr']+s['size'])
            return section['offset']+address-section['addr']
        with tempfile.TemporaryDirectory() as directory:
            for mode in modes:
                with self.subTest(mode=mode):
                    out=Path(directory)/mode;out.mkdir();data=bytearray(elf.data)
                    metadata=json.loads((image/'hardware-memory.json').read_text())
                    manifest=json.loads((image/'manifest.json').read_text())
                    watched=metadata['pretranslated_memory']['watched_pages']
                    if mode=='dependency':watched.pop()
                    elif mode=='dirty':struct.pack_into('<Q',data,offset(symbols['flat_translation_dirty']['value']),0)
                    elif mode=='range':
                        alias=next(a for a in metadata['aliases'] if a['pa']<=watched[0]<a['pa']+a['bytes'])
                        va=alias['va']+watched[0]-alias['pa'];metadata['write_ranges'].append([va,va+4096])
                    elif mode=='permissions':
                        start=struct.unpack_from('<Q',data,40)[0];stride=struct.unpack_from('<H',data,58)[0]
                        at=start+symbols['flat_pretranslated_checks']['shndx']*stride+8
                        struct.pack_into('<Q',data,at,struct.unpack_from('<Q',data,at)[0]|1)
                    else:
                        bit=(watched[0]-metadata['ram_base'])//4096;symbol=symbols['flat_immutable_page_bits']
                        data[offset(symbol['value'])+bit//8]&=~(1<<(bit%8))
                        start=offset(symbol['value']);raw=data[start:start+symbol['size']]
                        metadata['immutable_page_bitmap']['sha256']=hashlib.sha256(raw).hexdigest()
                    (out/'checkpoint').write_bytes(data)
                    raw=(json.dumps(metadata,indent=2)+'\n').encode();(out/'hardware-memory.json').write_bytes(raw)
                    manifest['hardware_memory_sha256']=hashlib.sha256(raw).hexdigest()
                    (out/'manifest.json').write_text(json.dumps(manifest))
                    with self.assertRaisesRegex(ValueError,'descriptor|watched|bitmap|write ranges|mode is writable'):
                        prepare(out,Path(directory)/(mode+'-model'),Path('/opt/homebrew/opt/llvm@16/bin'))
