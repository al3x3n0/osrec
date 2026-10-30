"""All 16 entry-state resource pairs survive original getrlimit queries and resumes."""
import gzip,json,re,shutil,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from capture_linux_aarch64 import reviewed_adapter,profile_integration,digest
from generate_linux_aarch64_application import generate
from prepare_linux_aarch64_port import build_bundle
from run_linux_aarch64_checkpoint_pipeline import run,verify_pipeline
from export_syscall_slices import export
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-file-limits-native'
def prepare_capture(dst):
    shutil.copytree(FIXTURE,dst,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (dst/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(dst);return dst
class LinuxFileLimitsTests(unittest.TestCase):
    def test_original_sources_generated_witness_and_entry_seeded_limits(self):
        r=reviewed_adapter();p=profile_integration('file-limits');identity,defs=r.source_identity(p);old,_=r.source_identity(profile_integration('file-rlimit'))
        self.assertEqual(identity['definitions'],old['definitions']);self.assertEqual(len(defs),109)
        self.assertEqual(identity['additional_sources'],old['additional_sources']);self.assertNotIn('do_prlimit',defs)
        self.assertEqual(generate('file-limits'),(p/'application.c').read_text());self.assertEqual((p/'application.c').read_bytes(),(FIXTURE/'sources/application.c').read_bytes())
        c=json.loads((FIXTURE/'capture.json').read_text());self.assertEqual(len(c['initial']['rlimits']),16)
        self.assertEqual(c['initial']['rlimits'][6:8],[[(1<<64)-1]*2,[8,8]])
        self.assertTrue(any(a!=b for a,b in c['initial']['rlimits']))
        with tempfile.TemporaryDirectory() as name:
            out=Path(name);r.capture_sources(p,out,c);h=(out/'capture.h').read_text()
            for i,pair in enumerate(c['initial']['rlimits']):
                for n,v in zip(('CUR','MAX'),pair):self.assertIn(f'#define LINUX_INITIAL_RLIMIT_{i}_{n} {v}u',h)
        self.assertIn('return &resource_limits[resource];',(p/'models.c').read_text())
        for i,(_,entry,data) in enumerate(r.file_limits_plan()):
            expected=list(data) if data is not None else [0xa5a50000+j for j in range(8)]
            words=r.input_words('file-limits',i);self.assertEqual(words,expected);words[0]^=1;self.assertEqual(r.input_words('file-limits',i),expected)
    def test_live_all_resources_faults_inherited_calls_and_joint_resumes(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-limits-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,_=r.validate_capture(native);rows,states=r.projection(c);plan=r.file_limits_plan();names={n:i for i,(n,_,_) in enumerate(plan)}
            limits=c['initial']['rlimits'];self.assertEqual(len(rows),924)
            for phase in ('entry','aborted','table_full','released'):
                for resource,pair in enumerate(limits):
                    row=rows[names[f'file_limits_{phase}_{resource}']];offset=2*(resource%3)
                    self.assertEqual(row['raw_bits'],0);self.assertEqual(row['words'][offset:offset+4],[part for v in pair for part in (v&0xffffffff,v>>32)])
            for resource in (0,3,4,8,11,15):
                row=rows[names[f'file_limits_partial_{resource}']];self.assertEqual(row['raw_bits'],(1<<64)-14)
                self.assertEqual(row['words'][:6],row['input_words'][:6]);self.assertEqual(row['words'][6:],[limits[resource][0]&0xffffffff,limits[resource][0]>>32])
            row=rows[names['file_limits_narrow_stack']];self.assertEqual(row['words'][1:5],[part for v in limits[3] for part in (v&0xffffffff,v>>32)])
            for n in ('null_stack','guard_core'):
                row=rows[names['file_limits_'+n]];self.assertEqual(row['raw_bits'],(1<<64)-14);self.assertEqual(row['words'],row['input_words'])
            inherited=[];oldnames={n for n,_,_ in r.file_rlimit_plan()}
            for i,((n,_,_),row) in enumerate(zip(plan,rows)):
                self.assertEqual(row['file_all_rlimits_after'],limits)
                if n.startswith('file_limits_'):self.assertEqual(states[i],states[i+1])
                if n in oldnames:row=dict(row);row.pop('file_all_rlimits_after');inherited.append(row)
            self.assertEqual(inherited,json.loads((ROOT/'tests/fixtures/linux-aarch64-file-rlimit-native/capture.json').read_text())['calls'])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU))
            self.assertEqual((result['logical_calls'],len(result['syscalls']),result['qemu_matrix_executions']),(924,38,32));self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual(result['pause_ordinals'],[names['file_limits_'+n]+1 for n in ('entry_3','partial_4','partial_11','aborted_3','table_full_7','released_15')]);self.assertEqual((result['context_bytes'],result['record_bytes']),(1744,1548))
            for st in result['saved_state']:self.assertEqual(st['resource_limits'],limits)
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text());self.assertEqual((k['target_observations']['verified_calls'],k['target_observations']['isolation_checks']),(2772,1848))
            for j in range(16):
                for field in ('rlim_cur','rlim_max'):
                    f=next(v for v in k['checkpoint_codec']['fields'] if v['path']==f'resource_limits[{j}].{field}');self.assertEqual(f['policy'],'persist');self.assertIn('wire_offset',f)
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
    def test_wrong_resource_truncation_invalid_order_and_partial_copy_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-limits-mutants-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('return &resource_limits[resource];','return &resource_limits[resource==RLIMIT_NOFILE];'),
                     ('*old_rlim=*resource_limit(resource);return 0;','*old_rlim=*resource_limit(resource);old_rlim->rlim_max&=UINT32_MAX;return 0;'),
                     ('if(resource>=RLIM_NLIMITS)return -EINVAL;','if(resource>=RLIM_NLIMITS){old_rlim->rlim_cur=0;old_rlim->rlim_max=0;return 0;}'),
                     ('if(!r)return count;\n    size_t copied=0;','if(!r)return count;\n    if(count==16 && (uintptr_t)out-r->user_address==24)return count;\n    size_t copied=0;')]
            for i,(a,b) in enumerate(changes):
                bundle=stage/str(i);port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(a),1);p.write_text(s.replace(a,b));v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
    def test_jointly_forged_limits_entry_shape_and_partial_output_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-limits-forged-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');original={n:(native/n).read_bytes() for n in ('capture.json','qemu.log','capture.manifest.json')};names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_limits_plan())}
            for field in ('shape','boolean','ordering','nofile','core','last_resource','partial','query'):
                v=json.loads(original['capture.json'])
                if field=='shape':v['initial']['rlimits'].pop()
                elif field=='boolean':v['initial']['rlimits'][0][0]=True
                elif field=='ordering':v['initial']['rlimits'][3]=[9,8]
                elif field=='nofile':v['initial']['rlimits'][7][1]=9
                elif field=='core':v['calls'][names['file_limits_entry_4']]['file_all_rlimits_after'][4][0]^=1
                elif field=='last_resource':v['calls'][names['file_limits_released_15']]['file_all_rlimits_after'][15][1]^=1
                elif field=='partial':v['calls'][names['file_limits_partial_4']]['words'][6]^=1
                else:v['calls'][names['file_limits_entry_3']]['words'][0]^=1
                (native/'capture.json').write_text(json.dumps(v,indent=2)+'\n');uart={k:x for k,x in v.items() if k!='format'};altered,count=re.subn(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}\r?$','OSREC_LINUX_CAPTURE '+json.dumps(uart),original['qemu.log'].decode(),flags=re.M);self.assertEqual(count,1);(native/'qemu.log').write_text(altered)
                m=json.loads(original['capture.manifest.json']);m['capture_sha256']=digest((native/'capture.json').read_bytes());m['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(m,indent=2)+'\n')
                with self.assertRaisesRegex(ValueError,'entry state is invalid|return/memory/state transitions differ'):build_bundle(native,stage/'bad-native')
                self.assertFalse((stage/'bad-native').exists())
                for n,data in original.items():(native/n).write_bytes(data)
if __name__=='__main__':unittest.main(verbosity=2)
