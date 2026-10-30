"""Reject machine-checkpoint drift and unsupported external state before execution."""
import copy,json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from qemu_vm_checkpoint import FORMAT,capture,sha,verify,write,Machine

class MachineCheckpointTests(unittest.TestCase):
    def bundle(self,stage):
        (stage/'assets').mkdir();(stage/'qemu').write_bytes(b'pinned emulator');(stage/'assets/kernel').write_bytes(b'pinned kernel');(stage/'vmstate.bin').write_bytes(b'machine state')
        recipe=dict(format=FORMAT,qemu=str(stage/'qemu'),qemu_sha256=sha(stage/'qemu'),files=dict(kernel=dict(path='assets/kernel',sha256=sha(stage/'assets/kernel'))))
        write(stage/'recipe.json',recipe);write(stage/'manifest.json',dict(recipe_sha256=sha(stage/'recipe.json'),vmstate_sha256=sha(stage/'vmstate.bin')))
        return recipe
    def test_changed_assets_emulator_recipe_and_machine_state_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);self.bundle(stage);verify(stage)
            for path in ('assets/kernel','qemu','recipe.json','vmstate.bin'):
                target=stage/path;original=target.read_bytes();target.write_bytes(original+b' ')
                with self.subTest(path=path),self.assertRaises(ValueError):verify(stage)
                target.write_bytes(original);verify(stage)
    def test_unsupported_external_state_and_control_overrides_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);base=dict(format=FORMAT,external_state='immutable-boot-assets-only',arguments=['-nodefaults'])
            cases=[dict(external_state='writable-disk'),dict(arguments=['-nodefaults','-drive','file=x,format=raw']),dict(arguments=['-nodefaults','-netdev=user,id=n']),dict(arguments=['-nodefaults','-qmp','stdio']),dict(arguments=[])]
            for i,change in enumerate(cases):
                recipe=copy.deepcopy(base);recipe.update(change);write(stage/'input.json',recipe)
                with self.subTest(change=change),self.assertRaises(ValueError):capture(stage/'input.json',stage/('out'+str(i)))
                self.assertFalse((stage/('out'+str(i))).exists())
    def test_missing_or_ambiguous_console_protocol_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);recipe=dict(format=FORMAT,external_state='immutable-boot-assets-only',arguments=['-nodefaults'],protocol={})
            write(stage/'input.json',recipe)
            with self.assertRaisesRegex(ValueError,'console protocol'):capture(stage/'input.json',stage/'out')
            recipe['protocol']=dict(ready_prefix='ready',success_prefix='pass',failure_prefix='fail',expected_success='other',continue_line='go\n');write(stage/'input.json',recipe)
            with self.assertRaisesRegex(ValueError,'continuation/oracle'):capture(stage/'input.json',stage/'out')
    def test_execution_labels_cannot_escape_evidence_directory(self):
        with self.assertRaisesRegex(ValueError,'execution label'):Machine(Path('/nonexistent'),'../escape')

if __name__=='__main__':unittest.main()
