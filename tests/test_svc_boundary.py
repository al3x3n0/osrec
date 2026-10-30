"""SVC boundary contracts, BTF paths, live bindings and reduced-boundary comparison."""
import copy,hashlib,json,os,shutil,struct,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from kernel_btf import BTF,locate,resolve
from live_kernel_binding import check_config,validate as validate_binding
from svc_boundary import FORMAT as OBSERVATION,validate_contract,user_objects
from draft_live_binding import draft
from reduced_boundary_replay import bound_fields,expected,mismatches,normalize,replay,state_source

CONTRACT=ROOT/'integrations/linux_aarch64/svc-boundary.json'
BINDING=ROOT/'integrations/linux_aarch64/file-io/live-binding.json'
POLICY=ROOT/'integrations/linux_aarch64/file-io/checkpoint-policy.json'
SLICE=Path(os.environ.get('OSREC_FILE_IO_SLICE',ROOT/'build/linux-transfer-guard-rebuild-20261026/file-io/kernel'))
CONTRACTS=ROOT/'integrations/linux_aarch64/file-io/analysis-contracts.json'
FD_CONTROL=ROOT/'integrations/linux_aarch64/fd-control'
LLVM=Path(os.environ.get('OSREC_LLVM16_BIN','/opt/homebrew/opt/llvm@16/bin'))
KERNEL=ROOT/'build/linux-svc-machine-checkpoint-20261026/checkpoint/assets/kernel'

def btf_blob(types,names):
    """Encode (kind,name,value,extra) records; kinds follow the BTF numbering."""
    strings=b'\0';offsets={}
    for n in names:offsets[n]=len(strings);strings+=n.encode()+b'\0'
    data=b''
    for kind,name,value,extra,flag in types:
        count=len(extra) if kind in (4,5) else 0
        data+=struct.pack('<III',offsets.get(name,0),(kind<<24)|count|(flag<<31),value)
        if kind==1:data+=struct.pack('<I',value*8)
        elif kind==3:data+=struct.pack('<III',*extra)
        elif kind in (4,5):data+=b''.join(struct.pack('<III',offsets.get(m,0),t,o) for m,t,o in extra)
    return struct.pack('<HBBIIIII',0xeb9f,1,0,24,0,len(data),len(data),len(strings))+data+strings

def sample_btf():
    names=['int','long','inner','obj','arr','inner_t','bits','b','a','p','c','x','dup','outer','in']
    types=[(1,'int',4,None,0),(1,'long',8,None,0),
        (4,'inner',24,[('b',2,0),('arr',4,64)],0),(3,'',0,(2,1,2),0),(2,'',3,None,0),
        (4,'obj',24,[('a',1,0),('p',8,64),('',7,128)],0),(5,'',4,[('c',1,0)],0),(8,'inner_t',5,None,0),
        (4,'bits',4,[('x',1,(3<<24)|0)],1),(4,'dup',4,[('a',1,0)],0),(4,'dup',4,[('a',1,0)],0),(4,'outer',32,[('x',1,0),('in',3,64)],0)]
    return btf_blob(types,names)

class Memory:
    def __init__(self,cells):self.cells=cells
    def u(self,address,size=8):return int.from_bytes(bytes(self.cells.get(address+i,0) for i in range(size)),'little')
    def read(self,address,size):return bytes(self.cells.get(address+i,0) for i in range(size))
def place(cells,address,value,size=8):
    for i,b in enumerate(value.to_bytes(size,'little')):cells[address+i]=b

class ContractTests(unittest.TestCase):
    def test_linux_contract_accepted_and_mutations_rejected(self):
        base=json.loads(CONTRACT.read_text());validate_contract(copy.deepcopy(base))
        mutations=[('number_register','x0'),('result_register','x31'),('preserved_registers',['x0']),('isa','armv7'),
            ('entry',dict(base['entry'],synchronous_vector_offset=1025)),('entry',dict(base['entry'],asynchronous_vector_offsets=[1024])),
            ('kernel_anchor',dict(base['kernel_anchor'],max_entry_steps=0)),('return',{'continuation':'elr','user_mode':'EL0t'}),
            ('kernel_memory_visibility','always'),('trap',dict(base['trap'],bytes=2))]
        for key,value in mutations:
            c=copy.deepcopy(base);c[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):validate_contract(c)

class UserObjectTests(unittest.TestCase):
    BINDING={'user_objects':{'buffer':{'bytes':32,'object_id':1,'permissions':3}}}
    CONTRACT={'argument_registers':['x0','x1','x2']}
    def test_pointers_into_one_buffer_admit_one_object(self):
        # getresuid(&ids[0], &ids[1], &ids[2]): three words of one buffer, one replayed copy.
        found=user_objects(self.BINDING,{148:['buffer','buffer','buffer']},{'number':148,'x0':100,'x1':104,'x2':108},self.CONTRACT)
        self.assertEqual(found,[dict(argument=0,arguments=[0,1,2],address=100,size=40,object_id=1,permissions=3)])
    def test_separate_buffers_stay_separate(self):
        found=user_objects(self.BINDING,{148:['buffer','buffer','buffer']},{'number':148,'x0':100,'x1':200,'x2':300},self.CONTRACT)
        self.assertEqual([(o['address'],o['size'],o['arguments']) for o in found],[(100,32,[0]),(200,32,[1]),(300,32,[2])])

class BtfTests(unittest.TestCase):
    def test_typed_paths_follow_members_pointers_arrays_and_anonymous_records(self):
        blob=b'pad'+sample_btf()+b'tail';self.assertEqual(locate(blob),3);btf=BTF(blob)
        cells={};place(cells,0x100,7,4);place(cells,0x108,0x200);place(cells,0x110,9,4)
        place(cells,0x200,11);place(cells,0x208,21);place(cells,0x210,22)
        m=Memory(cells)
        def get(path):a,t=resolve(btf,m.u,0x100,'obj',path);return m.u(a,btf.scalar(t))
        self.assertEqual([get('.a'),get('.p->b'),get('.p->arr[1]'),get('.c')],[7,11,22,9])
        # container_of: p targets the `in` member of an enclosing outer at 0x1f8.
        place(cells,0x1f8,5,4);self.assertEqual(get('.p-><outer.in>.x'),5)
        for path in ('.a-><outer.in>.x','.p-><obj.p>.a','.p-><outer.missing>.x'):
            with self.subTest(path=path),self.assertRaises((ValueError,KeyError)):get(path)
        for path in ('.p->arr[2]','.missing','p->b','.a->b','.p->arr[0]->b'):
            with self.subTest(path=path),self.assertRaises((ValueError,KeyError)):get(path)
        place(cells,0x108,0)
        with self.assertRaisesRegex(ValueError,'null pointer'):get('.p->b')
        with self.assertRaisesRegex(ValueError,'not unique'):btf.struct('dup')
        with self.assertRaisesRegex(ValueError,'bitfield'):btf.member(btf.struct('bits'),'x')
    def test_missing_or_ambiguous_blob_rejected(self):
        with self.assertRaises(ValueError):locate(b'no type data')
        with self.assertRaises(ValueError):locate(sample_btf()+sample_btf())

class BindingTests(unittest.TestCase):
    def test_reviewed_binding_and_configuration_checks(self):
        b=json.loads(BINDING.read_text());validate_binding(copy.deepcopy(b))
        config='CONFIG_ARM64_VA_BITS=48\nCONFIG_PAGE_SHIFT=12\nCONFIG_DEBUG_INFO_BTF=y\n# CONFIG_RANDOMIZE_BASE is not set\n'
        check_config(b,config)
        for bad in (config.replace('=48','=52'),config.replace('# CONFIG_RANDOMIZE_BASE is not set','CONFIG_RANDOMIZE_BASE=y'),config.replace('CONFIG_DEBUG_INFO_BTF=y\n','')):
            with self.subTest(config=bad),self.assertRaises(ValueError):check_config(b,bad)
        for change in (lambda d:d['descriptors']['class']['values'].update({'4096':3,'16384':3}),lambda d:d['scalars'].update({'bad field':{'path':'.pid'}}),
                       lambda d:d['scalars']['task.pid'].update(width=4),lambda d:d.update(type_source='dwarf')):
            d=copy.deepcopy(b);change(d)
            with self.assertRaises(ValueError):validate_binding(d)
        for change in (lambda d:d['external'].update(classes=[3]),lambda d:d['external'].update(descriptor_argument='x0')):
            d=copy.deepcopy(b);change(d)
            with self.assertRaisesRegex(ValueError,'external-call'):validate_binding(d)
    def test_released_objects_are_unobservable_except_reference_count(self):
        b=json.loads(BINDING.read_text());state=observation()['kernel_post'];_,exported,_=state_source(state,b)
        released=copy.deepcopy(state);released['pool'][1]=None;released['file_data']=None;released['slots'][4]=0
        want=expected(released,exported,b);field=dict(zip(exported,want))
        self.assertEqual((field['file_pool[1].f_count'],field['file_pool[1].object_id']),(0,2))
        self.assertIsNone(field['file_pool[1].f_pos']);self.assertIsNone(field['file_data.size'])
        got=[0 if w is None else w for w in want];got[exported.index('file_pool[1].f_pos')]=8
        self.assertEqual(mismatches(exported,got,want),[])
        got[exported.index('file_pool[1].f_count')]=1
        self.assertEqual([m['field'] for m in mismatches(exported,got,want)],['file_pool[1].f_count'])
    def test_related_objects_are_wired_per_class_and_bound(self):
        b=json.loads((FD_CONTROL/'live-binding.json').read_text());validate_binding(copy.deepcopy(b))
        state=copy.deepcopy(observation()['kernel_pre']);state['transient']['superblock.write_depth']=0
        state['scalars'].update({'inode_pool[0].i_mode':0o20000,'inode_pool[0].append':0,'inode_pool[1].i_mode':0o100000,'inode_pool[1].append':0,'files.count.counter':1})
        # The file-io observation predates the fields only fd-control binds.
        for o in state['pool']:
            if o:o['f_owner.signum']=0;o['f_iocb_flags']=0
        lines,exported,_=state_source(state,b)
        self.assertIn('    ctx->file_pool[1].f_owner.signum=(__typeof__(ctx->file_pool[1].f_owner.signum))UINT64_C(0);',lines)
        for line in ('    ctx->file_pool[1].f_path.dentry=&ctx->dentry_pool[1];','    ctx->dentry_pool[0].d_inode=&ctx->inode_pool[0];',
                     '    ctx->inode_pool[1].i_sb=&ctx->superblock;'):self.assertIn(line,lines)
        self.assertIn('inode_pool[1].i_mode',exported)
        self.assertLessEqual({'inode_pool[].i_mode','inode_pool[].append','file_pool[].f_path.dentry','dentry_pool[].d_inode','inode_pool[].i_sb'},bound_fields(state,b))
        policy=json.loads((FD_CONTROL/'checkpoint-policy.json').read_text())
        self.assertEqual(normalize('argument:ctx->file_pool[1].f_path.dentry->d_inode->i_mode',policy),'inode_pool[].i_mode')
        self.assertEqual(normalize('argument:ctx->file_pool[1].f_path.dentry->d_inode->i_sb->write_depth',policy),'superblock.write_depth')
        # A class released by the call leaves its inode unobservable afterwards.
        released=copy.deepcopy(state);released['pool'][1]=None
        for k in ('inode_pool[1].i_mode','inode_pool[1].append'):del released['scalars'][k]
        self.assertIsNone(dict(zip(exported,expected(released,exported,b)))['inode_pool[1].i_mode'])
        self.assertEqual([c['path'] for c in b['preconditions']],['.signal->rlim[7].rlim_cur','.signal->rlim[1].rlim_cur'])
        for change in (lambda d:d['preconditions'][0].pop('reason'),lambda d:d['preconditions'][0].update(equals='8'),lambda d:d['preconditions'].append({'path':1,'equals':8,'reason':'r'})):
            d=copy.deepcopy(b);change(d)
            with self.assertRaisesRegex(ValueError,'precondition'):validate_binding(d)
        related=b['descriptors']['related']
        for change in (lambda r:r['links'].append(dict(field='superblock',target='superblock')),
                       lambda r:r['links'].append(dict(field='inode_pool[].i_sb',target='superblock',same_as='.f_inode')),
                       lambda r:r['members'].update({'inode_pool.i_mode':dict(path='.f_inode->i_mode')}),
                       lambda r:r['members']['inode_pool[].i_mode'].update(require=1),
                       lambda r:r['members'].update({'superblock.s_maxbytes':dict(path='.f_inode->i_sb->s_maxbytes')}),
                       lambda r:r['members']['inode_pool[].osrec_shmem.seals'].update({'class':3}),
                       lambda r:r['preconditions'][0].pop('reason'),
                       lambda r:r['preconditions'][0].update(equals='0')):
            d=copy.deepcopy(b);change(d['descriptors']['related'])
            with self.assertRaises(ValueError):validate_binding(d)
    def test_analyzer_paths_normalize_through_policy_references(self):
        policy=json.loads(POLICY.read_text())
        self.assertEqual(normalize('argument:ctx->current->files->fdt->max_fds',policy),'files.fdtab.max_fds')
        self.assertEqual(normalize('argument:ctx->current->files',policy),'task.files')
        self.assertEqual(normalize('argument:ctx->file_data.size',policy),'file_data.size')
        self.assertTrue(normalize('argument:ctx->current->files->unknown',policy).endswith('?'))
        self.assertEqual(normalize('*(argument:ctx->current->files->file_lock)',policy),'files.file_lock')
        self.assertEqual(normalize('argument:ctx->current->files->fdt->full_fds_bits[0]',policy),'files.fdtab.full_fds_bits[]')
        self.assertEqual(normalize('argument:ctx->file_pool[1].f_pos',policy),'file_pool[].f_pos')
        self.assertEqual(normalize('argument:fd',policy),'argument:fd')
        self.assertTrue(normalize('global:other',policy).endswith('?'))

class DraftTests(unittest.TestCase):
    def test_schema_references_drive_btf_paths_and_width_checks(self):
        names=['int','long','atomic','counter','files','count','next','task','pid']
        types=[(1,'int',4,None,0),(1,'long',8,None,0),(4,'atomic',8,[('counter',2,0)],0),(4,'files',16,[('count',3,0),('next',1,64)],0),
            (2,'',4,None,0),(4,'task',16,[('pid',1,0),('files',5,64)],0)]
        policy=dict(fields=dict(current=dict(type='struct task *',policy='self_reference',target='task'),
            task=dict(type='struct task',policy='members',members=dict(pid=dict(type='int32_t',policy='persist'),files=dict(type='struct files *',policy='self_reference',target='files'),model_only=dict(type='int',policy='persist'))),
            files=dict(type='struct files',policy='members',members=dict(count=dict(type='int64_t',policy='persist'),next=dict(type='uint64_t',policy='persist'))),
            orphan=dict(type='struct orphan',policy='members',members=dict(value=dict(type='int',policy='persist')))))
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);(stage/'policy.json').write_text(json.dumps(policy));(stage/'kernel').write_bytes(b'image'+btf_blob(types,names))
            rows=draft(stage/'policy.json',stage/'kernel','current','task')['fields']
        self.assertEqual([c['path'] for c in rows['task.pid']['candidates']],['.pid'])
        self.assertEqual([c['path'] for c in rows['files.count']['candidates']],['.files->count.counter'])
        self.assertFalse(rows['files.next']['candidates'][0]['width_matches'])
        self.assertEqual((rows['task.model_only']['status'],rows['orphan.value']['status']),('model-only','unreachable'))
    @unittest.skipUnless(KERNEL.exists(),'Linux checkpoint kernel image required')
    def test_draft_recovers_reviewed_file_io_paths(self):
        r=draft(POLICY,KERNEL,'current','task_struct',BINDING)['against_reviewed']
        self.assertEqual((len(r['agree']),len(r['preferred_agree']),r['differs'],r['reviewed_only']),(22,22,[],['user_ns.initial']))
        self.assertIn(r['descriptor_table']['reviewed'],r['descriptor_table']['draft']);self.assertEqual([tuple(x) for x in r['invariants']['reviewed']],[tuple(x) for x in r['invariants']['draft']])

def observation(address=0xffffda25c0b0):
    """A read(alias, buffer, 8) boundary in the shape svc_boundary.py records."""
    def state(pos):
        pool=[dict(address=0xffff000003e1b100,object_id=1,f_count=3,f_mode=3,f_mode_native=0xe0003,f_flags=2,f_pos=0,f_version=0),
              dict(address=0xffff000003e1b000,object_id=2,f_count=1,f_mode=7,f_mode_native=0xe001f,f_flags=131074,f_pos=pos,f_version=0)]
        scalars={'task.pid':1,'task.tgid':1,'parent.pid':0,'parent.tgid':0,'fs.umask':18,'creds.uid':0,'creds.euid':0,'creds.suid':0,'creds.gid':0,'creds.egid':0,'creds.sgid':0,'user_ns.initial':1,
                 'files.next_fd':3,'files.resize_in_progress':0,'files.fdtab.max_fds':64,'files.fdtab.open_fds[0]':0x17,'files.fdtab.close_on_exec[0]':8,'files.fdtab.full_fds_bits[0]':0}
        return dict(scalars=scalars,pool=pool,slots=[1,1,1,0,2]+[0]*59,file_data=dict(size=8,bytes=(b'abcdeX2h'+bytes(56)).hex()),
                    transient={'rcu_depth':0,'model_fault':0,'files.file_lock':0,'file_pool[0].f_lock':0,'file_pool[1].f_lock':0})
    before=bytes(8)+bytes.fromhex('583200000a0000002008fd0900000000636465004c696e75');after=b'abcdeX2h'+before[8:]
    obj=lambda data:[dict(argument=1,address=address,size=32,object_id=1,permissions=3,bytes=data.hex())]
    kernel=json.loads((SLICE/'manifest.json').read_text())['kernel_image_sha256'] if SLICE.is_dir() else ''
    return dict(format=OBSERVATION,binding_sha256=hashlib.sha256(BINDING.read_bytes()).hexdigest(),checkpoint=dict(kernel_sha256=kernel),
        call=dict(number=63,arguments=[4,address,8,0,0,0]),pre=dict(user_objects=obj(before)),kernel_pre=state(0),
        returned=dict(result=8,user_objects=obj(after)),kernel_post=state(8))

@unittest.skipUnless(SLICE.is_dir() and (LLVM/'clang').exists() and shutil.which('qemu-system-aarch64'),'published file-io slice, LLVM 16 and QEMU required')
class ReducedReplayTests(unittest.TestCase):
    def run_case(self,stage,name,obs,binding=BINDING,slice_dir=SLICE,contracts=CONTRACTS):
        path=stage/(name+'.json');path.write_text(json.dumps(obs));return replay(path,slice_dir,binding,stage/name,LLVM,'qemu-system-aarch64',60,contracts)
    def test_equivalence_and_divergence_controls(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);base=observation()
            r=self.run_case(stage,'consistent',base)
            self.assertEqual(r['status'],'equivalent',r['comparison']);self.assertEqual(r['comparison']['changed_fields'],['file_pool[1].f_pos'])
            self.assertEqual(r['footprint']['uncovered'],[]);self.assertFalse(r['claims']['kernel_image_needed'])
            # The footprint is fully discovered; its one field range was checked on both live states.
            self.assertEqual(r['footprint']['blockers'],{});self.assertTrue(r['claims']['footprint_unblocked'])
            self.assertEqual({(c['field'],c['state'],c['value']) for c in r['footprint']['state_range_checks']},{('max_fds','pre',64),('max_fds','post',64)})
            self.assertTrue(r['footprint']['external_memory'])
            o=copy.deepcopy(base);o['kernel_post']['pool'][1]['f_pos']=7
            r=self.run_case(stage,'post_position',o);self.assertEqual(r['status'],'diverged')
            self.assertEqual([m['field'] for m in r['comparison']['post_mismatches']],['file_pool[1].f_pos'])
            o=copy.deepcopy(base);o['returned']['user_objects'][0]['bytes']='00'+o['returned']['user_objects'][0]['bytes'][2:]
            self.assertEqual(self.run_case(stage,'user_bytes',o)['status'],'diverged')
            # Beyond the arm64 1 << 48 access_ok limit the slice must fail with -EFAULT.
            o=observation(address=(1<<48)-4)
            r=self.run_case(stage,'above_task_size',o);self.assertEqual(r['comparison']['result']['reduced'],(1<<64)-14);self.assertEqual(r['status'],'diverged')
    def test_binding_and_slice_identity_enforced(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);o=observation();o['binding_sha256']='0'*64
            with self.assertRaisesRegex(ValueError,'binding differs'):self.run_case(stage,'binding',o)
            copied=stage/'slice';shutil.copytree(SLICE,copied,ignore=shutil.ignore_patterns('*.elf','*.bin','*.a','port-inputs'))
            with (copied/'sources/models.c').open('a') as f:f.write('\n')
            with self.assertRaisesRegex(ValueError,'differs from its manifest'):self.run_case(stage,'tampered',observation(),slice_dir=copied)
            o=observation();o['checkpoint']['kernel_sha256']='1'*64
            with self.assertRaisesRegex(ValueError,'observed kernel image'):self.run_case(stage,'kernel',o)
            # A live state outside a range the proof relied on is refused, and
            # without the contracts the footprint stays blocked.
            o=observation();o['kernel_pre']['scalars']['files.fdtab.max_fds']=65
            with self.assertRaisesRegex(ValueError,'violates the analysis range'):self.run_case(stage,'range',o)
            with self.assertRaisesRegex(ValueError,'footprint analysis is blocked'):self.run_case(stage,'uncontracted',observation(),contracts=None)

if __name__=='__main__':unittest.main()
