"""SVC boundary contracts, BTF paths, live bindings and reduced-boundary comparison."""
import copy,hashlib,json,os,shutil,struct,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from kernel_btf import BTF,locate,resolve
from live_kernel_binding import check_config,validate as validate_binding
from svc_boundary import FORMAT as OBSERVATION,validate_contract,user_objects
from draft_live_binding import draft
from reduced_boundary_replay import bound_fields,check_ranges,covered,expected,generate,held_fields,mismatches,node,normalize,replay,state_source

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

    def test_a_pointer_argument_binds_no_object(self):
        # futex(uaddr, op, val, utime, uaddr2, val3): a null timeout and an unused uaddr2.
        found=user_objects(self.BINDING,{98:['buffer','signed','unsigned','pointer','pointer','unsigned']},{'number':98,'x0':100,'x1':129,'x2':1,'x3':0,'x4':0,'x5':0},
            {'argument_registers':['x0','x1','x2','x3','x4','x5']})
        self.assertEqual([(o['address'],o['size'],o['arguments']) for o in found],[(100,32,[0])])

class GlobalBindingTests(unittest.TestCase):
    """Kernel data the task does not reach, bound from a derived data symbol (the futex hash)."""
    def setUp(self):
        names=['int','long','atomic','counter','list_head','next','prev','plist','node_list','bucket','waiters','lock','chain']
        types=[(1,'int',4,None,0),(1,'long',8,None,0),(4,'atomic',4,[('counter',1,0)],0),(4,'list_head',16,[('next',2,0),('prev',2,64)],0),
            (4,'plist',16,[('node_list',4,0)],0),(4,'bucket',64,[('waiters',3,0),('lock',1,32),('chain',5,64)],0)]
        self.btf=BTF(btf_blob(types,names));self.symbols={'symbols':{'__futex_data':dict(address='0x1000',
            layout=dict(size=16,align=16,fields=dict(queues=dict(offset=0,size=8),hashsize=dict(offset=8,size=8))),
            live_checks=[dict(check='power_of_two',field='hashsize'),dict(check='linear_map',field='queues',align=64),
                dict(check='empty_lists',array='queues',count='hashsize',record='bucket',stride=64,counter='waiters.counter',list='chain.node_list',lock='lock')])}}
        self.binding={'globals':[dict(symbol='__futex_data',page_offset=0x10000,scalars={'__futex_data.hashsize':'hashsize'},
            array=dict(pointer='queues',count='hashsize',field='__futex_data.queues',pool='futex_hash_buckets',capacity=4,record='bucket',
                members={'waiters.counter':{'path':'.waiters.counter'}},transient={'lock':0}))]}
        self.cells={};place(self.cells,0x1000,0x20000);place(self.cells,0x1008,4)
        for i in range(8):place(self.cells,0x20000+64*i+8,0x20000+64*i+8);place(self.cells,0x20000+64*i+16,0x20000+64*i+8)
    def project(self,symbols=True):
        from live_kernel_binding import project_globals
        state=dict(scalars={},transient={},evidence={});project_globals(self.binding,self.btf,Memory(self.cells),self.symbols if symbols else None,state);return state
    def test_buckets_bind_into_the_pool(self):
        place(self.cells,0x20000+64*2,3,4);place(self.cells,0x20000+64*2+8,0x30000)   # a bucket with waiters may have a chain
        state=self.project()
        self.assertEqual(state['scalars'],{'__futex_data.hashsize':4,**{'futex_hash_buckets[%d].waiters.counter'%i:3 if i==2 else 0 for i in range(4)}})
        self.assertEqual(state['transient'],{'futex_hash_buckets[%d].lock'%i:0 for i in range(4)})
        self.assertEqual(state['references'],{'__futex_data.queues':'futex_hash_buckets[0]'})
        self.assertEqual(state['evidence']['global __futex_data']['empty_bucket'],3)
    def test_size_layout_and_symbol_failures_reject(self):
        for change,message in (((0x1008,8),'differs from the slice pool'),((0x20000+64+4,1,4),'lock is held'),((0x1000,0x20008),'linear-map')):
            with self.subTest(message=message):
                saved=dict(self.cells);place(self.cells,*change)
                with self.assertRaisesRegex(ValueError,message):self.project()
                self.cells=saved
        with self.assertRaisesRegex(ValueError,'derived data symbol'):self.project(symbols=False)
        bad=copy.deepcopy(self.binding);bad['globals'][0]['array']['capacity']=300
        with self.assertRaises(ValueError):validate_binding(dict(json.loads((FD_CONTROL/'live-binding.json').read_text()),globals=bad['globals']))
        validate_binding(json.loads((FD_CONTROL/'live-binding.json').read_text()))

class PerCpuBindingTests(unittest.TestCase):
    """Per-CPU state: this CPU's copy is at a per-CPU address plus the CPU's offset (arm64 TPIDR_EL1)."""
    OFFSET=0xffff7fff9e017000
    class CpuMemory(Memory):
        def __init__(self,cells,offset):super().__init__(cells);self.offset=offset;self.reads=0
        def register(self,name):
            if name!='TPIDR_EL1':raise KeyError(name)
            self.reads+=1;return self.offset
    def test_a_per_cpu_symbol_is_bound_at_this_cpus_copy(self):
        from live_kernel_binding import project_globals
        link=0xffff800081ec87c0;copy=(link+self.OFFSET)&(1<<64)-1;cells={}
        place(cells,copy+277,1,1);place(cells,copy+276,0,1)
        symbols={'symbols':{'rcu_data':dict(address='%#x'%link,percpu=True,layout=dict(size=960,align=64,fields=dict(rcu_need_heavy_qs=dict(offset=276,size=1),rcu_urgent_qs=dict(offset=277,size=1))),live_checks=[])}}
        binding={'percpu':{'offset_register':'TPIDR_EL1'},'globals':[dict(symbol='rcu_data',page_offset=0,scalars={'rcu_data.rcu_urgent_qs':'rcu_urgent_qs','rcu_data.rcu_need_heavy_qs':'rcu_need_heavy_qs'})]}
        memory=self.CpuMemory(cells,self.OFFSET);state=dict(scalars={},transient={},evidence={})
        project_globals(binding,None,memory,symbols,state)
        self.assertEqual(state['scalars'],{'rcu_data.rcu_urgent_qs':1,'rcu_data.rcu_need_heavy_qs':0})
        self.assertEqual((state['evidence']['global rcu_data']['address'],state['evidence']['percpu_offset']),('%#x'%copy,self.OFFSET))
        # Without the offset the per-CPU link address is read, which holds no copy.
        project_globals(binding,None,self.CpuMemory(cells,0),symbols,state:=dict(scalars={},transient={},evidence={}))
        self.assertEqual(state['scalars']['rcu_data.rcu_urgent_qs'],0)
    def test_per_cpu_members_need_the_offset_register(self):
        base=json.loads((FD_CONTROL/'live-binding.json').read_text());validate_binding(copy.deepcopy(base))
        self.assertIn('percpu',base['descriptors']['related']['members']['mount_pcp.mnt_writers'])
        for mutate in (lambda b:b.pop('percpu'),lambda b:b['descriptors']['related']['members']['mount_pcp.mnt_writers']['percpu'].update(width=4),
                       lambda b:b['descriptors']['related']['members']['sb_read_count[0]']['percpu'].update(width=3),lambda b:b.update(percpu={'offset_register':'TPIDR EL1'})):
            b=copy.deepcopy(base);mutate(b)
            with self.subTest(),self.assertRaises(ValueError):validate_binding(b)

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
    def test_cast_step_names_the_record_behind_an_untyped_pointer(self):
        # holder{void *p; int *q;} and obj{int a; int b;}: `->(obj)` reads through p, never through q.
        names=['int','holder','obj','p','q','a','b']
        types=[(1,'int',4,None,0),(2,'',0,None,0),(2,'',1,None,0),(4,'holder',16,[('p',2,0),('q',3,64)],0),(4,'obj',8,[('a',1,0),('b',1,32)],0)]
        btf=BTF(btf_blob(types,names));cells={};place(cells,0x100,0x200);place(cells,0x200,5,4);place(cells,0x204,6,4)
        m=Memory(cells)
        def get(path):a,t=resolve(btf,m.u,0x100,'holder',path);return m.u(a,btf.scalar(t))
        self.assertEqual([get('.p->(obj).a'),get('.p->(obj).b')],[5,6])
        for path in ('.q->(obj).a','.p->(missing).a'):
            with self.subTest(path=path),self.assertRaises((ValueError,KeyError)):get(path)
        place(cells,0x100,0)
        with self.assertRaisesRegex(ValueError,'null pointer'):get('.p->(obj).a')
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
        self.assertEqual(normalize('argument:ctx->file_pool[1].f_path.dentry->d_inode->i_sb->s_writers.rw_sem[0].read_count',policy),'superblock.s_writers.rw_sem[].read_count')
        # A class released by the call leaves its inode unobservable afterwards.
        released=copy.deepcopy(state);released['pool'][1]=None
        for k in ('inode_pool[1].i_mode','inode_pool[1].append'):del released['scalars'][k]
        self.assertIsNone(dict(zip(exported,expected(released,exported,b)))['inode_pool[1].i_mode'])
        self.assertEqual([c['path'] for c in b['preconditions']],['.signal->rlim[7].rlim_cur','.signal->rlim[1].rlim_cur','.nsproxy->time_ns'])
        # A precondition may name a derived data symbol instead of a value (the task's time namespace is init_time_ns).
        self.assertEqual(b['preconditions'][2]['equals_symbol'],'init_time_ns')
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
    def test_held_fields_model_state_and_range_forms(self):
        b=json.loads((FD_CONTROL/'live-binding.json').read_text());validate_binding(copy.deepcopy(b))
        policy=json.loads((FD_CONTROL/'checkpoint-policy.json').read_text())
        # Indexed member arrays, references to one pool's embedded member, and reads below transient leaves.
        for path,field in (('argument:ctx->current->cred->user_ns->uid_map->extent[2].count','user_ns.uid_map.extent[].count'),
                           ('argument:ctx->file_pool[1].f_path.dentry->d_inode->i_mapping->a_ops','inode_pool[].i_data.a_ops'),
                           ('argument:ctx->folio_pool[0].mapping->host->i_size','inode_pool[].i_size'),
                           ('argument:ctx->inode_pool[1].i_data.i_pages.xa_head->flags','folio_pool[].flags'),
                           ('*(argument:ctx->inode_wb.list_lock)','inode_wb.list_lock'),
                           ('argument:ctx->superblock.s_fsnotify_info->watched_objects[0]->counter','superblock.s_fsnotify_info.watched_objects[].counter')):
            with self.subTest(path=path):self.assertEqual(normalize(path,policy),field)
        sources=[('live',{'inode_pool[].i_uid.val','superblock.s_fsnotify_info'}),('held',{'superblock.s_flags'}),('model',{'tk_core','fop_pool[]'})]
        cover=lambda f:covered(f,node(policy,f),policy,sources)
        self.assertEqual([cover(f) for f in ('inode_pool[].i_uid','superblock.s_fsnotify_info.watched_objects[].counter','superblock.s_flags',
                                             'tk_core.timekeeper.xtime_sec','fop_pool[].read','superblock.s_user_ns','inode_pool[].i_gid','superblock.s_time_gran')],
                         ['live','live','held','model','model','live',None,None])
        # Held fields are exported per live class and expected at the precondition value under its mask.
        o=json.loads((ROOT/'build/linux-svc-state-20261103a/observe-pread/boundary.json').read_text()) if (ROOT/'build/linux-svc-state-20261103a/observe-pread/boundary.json').exists() else None
        if o is None:self.skipTest('fd-control observation required')
        state=o['kernel_pre'];held={f:(m,v) for f,m,v in held_fields(state,b)}
        self.assertEqual(held['vfs_mount.mnt.mnt_flags'],(632,0));self.assertEqual(held['superblock.s_time_min'],((1<<64)-1,1<<63))
        source,_,exported=generate(state,b,o,o['pre']['user_objects'])
        self.assertIn('(uint64_t)(uintptr_t)ctx->inode_pool[1].i_hash.pprev&UINT64_C(%d);'%((1<<64)-1),source)
        released=copy.deepcopy(state);released['pool'][1]=None
        want=dict(zip(exported,expected(state,exported,b)));gone=dict(zip(exported,expected(released,exported,b)))
        self.assertEqual((want['superblock.s_fsnotify_info'],gone['superblock.s_fsnotify_info']),(0,None))
        self.assertIn('    ctx->folio_pool[0].mapping=&ctx->inode_pool[1].i_data;',source);self.assertNotIn('ctx->folio_pool[1]',source)
        # Range forms: listed fields, every pool entry, and an unmasked held precondition.
        def ranges(validated_by,low=0,high=64):return check_ranges([dict(record='r',field='f',min=low,max=high,validated_by=validated_by)],[('pre',state)],b)
        self.assertEqual(len(ranges('live state fields user_ns.uid_map.nr_extents, user_ns.gid_map.nr_extents')),2)
        self.assertEqual({c['live'] for c in ranges('live state field inode_pool[].i_size, checked against each captured state')},{'inode_pool[0].i_size','inode_pool[1].i_size'})
        self.assertEqual([c['live'] for c in ranges('live precondition noop_bdi.capabilities',0,0)],['noop_bdi.capabilities'])
        for bad in ('live precondition mount.mnt_flags','live state field files.missing','the reviewer'):
            with self.subTest(bad=bad),self.assertRaises(ValueError):ranges(bad)
        for change in (lambda d:d['descriptors']['related']['links'].append(dict(field='folio_pool[0].index',target='inode_pool[1]')),
                       lambda d:d['descriptors']['related']['links'].append(dict(field='inode_pool[].i_op',target='iop_pool[]',object='.f_inode->i_op')),
                       lambda d:d['descriptors']['related']['preconditions'].append(dict(path='.f_inode->i_flctx',equals=0,reason='r',field='superblock.s_flags')),
                       lambda d:d['model_state'].update({'tk_core':''})):
            d=copy.deepcopy(b);change(d)
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
