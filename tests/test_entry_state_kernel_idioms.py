"""Kernel idioms: compile-time builtins, build-eliminated calls, traps, scalar bitmaps, volatile snapshots."""
import copy,json,sys,tempfile,unittest
from pathlib import Path
import test_entry_state as basic
from entry_state import Analyzer

POLICY={'current':{'kind':'object_provider','reason':'test current object','implementation':'stable object binding','snapshot_safe':True}}
MODEL='''struct Info{unsigned long flags;volatile unsigned long shared;};
struct Lock{unsigned count;};
struct Obj{struct Info info;struct Lock locks[3];unsigned value;};
struct Obj *current(void);
'''

class KernelIdiomTests(unittest.TestCase):
    def plan(self,text,root='root',policy=POLICY,**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),MODEL+text)[0];before=copy.deepcopy(tree)
            analyzer=Analyzer(tree,policy,**options);plan=analyzer.analyze(root)
            self.assertEqual(tree,before);self.assertEqual(plan,analyzer.fresh().analyze(root))
            self.assertNotIn('bounded-pointer:',json.dumps(plan))
            return plan
    def kinds(self,plan):return {b['kind'] for b in plan['blockers']}

    def test_compile_time_builtins(self):
        p=self.plan('unsigned root(unsigned x){if(__builtin_constant_p(current()->value))return 1;if(x>9)__builtin_unreachable();return x;}')
        self.assertFalse(p['blockers'],p['blockers'])
        # The constant_p operand is never evaluated, so it contributes no read.
        self.assertNotIn('current()->value',{r['path'] for r in p['entry_reads']})
        self.assertEqual({c['callee'] for c in p['call_sites'] if c.get('resolution')=='compiler_builtin'},{'__builtin_constant_p','__builtin_unreachable'})

    def test_build_eliminated_calls_need_evidence(self):
        text='extern void bad_size(void);void assert_fail(void) __attribute__((error("bad")));void other(void);\nunsigned root(unsigned x){if(x==3)bad_size();if(x==4)assert_fail();if(x==5)other();return x;}'
        p=self.plan(text)
        self.assertEqual({b['detail'].split(': ')[-1] for b in p['blockers']},{'bad_size','other'})
        p=self.plan(text,linked_symbols={'other','root'})
        self.assertEqual({b['detail'].split(': ')[-1] for b in p['blockers']},{'other'})
        self.assertEqual({c['build_evidence']['kind'] for c in p['call_sites'] if c.get('resolution')=='build_eliminated'},{'error_attribute','absent_from_linked_image'})

    def test_operand_free_asm_before_unreachable_is_a_trap(self):
        p=self.plan('unsigned root(unsigned x){if(x>7){__asm__ volatile("brk 0x800");;do{;__builtin_unreachable();}while(0);}return x;}')
        self.assertFalse(p['blockers'],p['blockers']);self.assertEqual(len(p['trap_proofs']),1)
        for body in ('__asm__ volatile("nop");return x;','unsigned y;__asm__ volatile("mov %0, #1":"=r"(y));__builtin_unreachable();'):
            with self.subTest(body=body):
                self.assertIn('architecture_or_ordering',self.kinds(self.plan('unsigned root(unsigned x){if(x>7){'+body+'}return x;}')))

    def test_scalar_field_is_a_one_element_bitmap(self):
        helpers='static int test_bit(unsigned nr,const volatile unsigned long *addr){return 1UL & (addr[nr/64] >> (nr%64));}\n'
        flags=[{'record':'struct Info','field':'flags','reason':'bits set asynchronously; entry snapshot','validated_by':'fixture'}]
        # A volatile view of the word needs a classification before it is entry state.
        self.assertIn('volatile_memory',self.kinds(self.plan(helpers+'int root(void){return test_bit(3,&current()->info.flags);}')))
        p=self.plan(helpers+'int root(void){return test_bit(3,&current()->info.flags);}',volatile_fields=flags)
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertIn('*(current()->info.flags)',{r['path'] for r in p['entry_reads']})
        # Word 1 of a one-word object, or a parameter with no known extent, stays blocked.
        self.assertTrue(self.plan(helpers+'int root(void){return test_bit(70,&current()->info.flags);}')['blockers'])
        self.assertTrue(self.plan(helpers+'int root(const unsigned long *p){return test_bit(3,p);}')['blockers'])

    def test_volatile_field_snapshots_require_a_classification(self):
        text='unsigned long root(void){return *(const volatile unsigned long *)&current()->info.shared;}'
        self.assertIn('volatile_memory',self.kinds(self.plan(text)))
        fields=[{'record':'struct Info','field':'shared','reason':'set asynchronously; entry snapshot','validated_by':'fixture'}]
        p=self.plan(text,volatile_fields=fields)
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual([r['volatile_snapshot'] for r in p['entry_reads'] if r.get('volatile_snapshot')],[{'record':'struct Info','field':'shared'}])
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),MODEL)[0]
            with self.assertRaises(ValueError):Analyzer(tree,POLICY,volatile_fields=[{'record':'struct Info','field':'shared'}])

    def test_struct_element_arrays_name_ordering_model_locks(self):
        policy={**POLICY,'lock':{'kind':'ordering_model','reason':'sequential replay','implementation':'no-op'}}
        text='void lock(struct Lock *);static void take(struct Obj *o,int level){lock(o->locks+level-1);}\nvoid root(void){take(current(),2);}'
        p=self.plan(text,policy=policy)
        self.assertFalse(p['blockers'],p['blockers'])
        p=self.plan(text.replace('take(current(),2)','take(current(),9)'),policy=policy)
        self.assertIn('array_bounds',self.kinds(p))
        # The object may be reached through a READ_ONCE-style dereference.
        p=self.plan(text.replace('take(current(),2)','take(*(struct Obj *const volatile *)&slot,2)').replace('void root','struct Obj *slot;void root'),
            policy=policy,volatile_accesses={'classification':'sequential_snapshot','reason':'r','validated_by':'v'})
        self.assertFalse(p['blockers'],p['blockers'])

    def test_integer_addresses_block_only_when_dereferenced(self):
        self.assertFalse(self.plan('unsigned long root(unsigned long a){const char *p=(const char *)(a & ~15UL);return p!=0;}')['blockers'])
        self.assertIn('unresolved_pointer_origin',self.kinds(self.plan('unsigned root(unsigned long a){return *(unsigned *)a;}')))

class TaggedPointerTests(unittest.TestCase):
    def kinds(self,plan):return {b['kind'] for b in plan['blockers']}
    FD='''struct File{struct File *next;unsigned mode;};struct Table{struct File *slot[4];unsigned count;};struct Task{struct Table *table;};
struct Task *task(void);
struct fd{struct File *file;unsigned flags;};
static unsigned long light(unsigned i){struct File *f=i<4 ? task()->table->slot[i] : 0;if(!f)return 0;if(task()->table->count==1)return (unsigned long)f;return 1 | (unsigned long)f;}
static unsigned long get_pos(unsigned i){unsigned long v=light(i);struct File *f=(struct File *)(v & ~3);if(f && f->mode)v|=2;return v;}
static struct fd to_fd(unsigned long v){return (struct fd){(struct File *)(v & ~3),v & 3};}
'''
    def plan(self,text,root='root',policy=None,**options):
        policy=policy or {'task':{'kind':'object_provider','reason':'fixture task','implementation':'fixture','snapshot_safe':True}}
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),self.FD+text)[0]
            analyzer=Analyzer(tree,policy,**options);plan=analyzer.analyze(root)
            self.assertEqual(plan,analyzer.fresh().analyze(root));return plan

    def test_tagged_descriptor_pointer_is_recovered(self):
        p=self.plan('unsigned root(unsigned i){struct fd f=to_fd(get_pos(i));if(!f.file)return 0;return f.file->mode;}')
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual({r['path'] for r in p['entry_reads'] if r['path'].endswith('->mode')},{'task()->table->slot[%d]->mode'%k for k in range(4)})
        self.assertTrue(all(x['cleared_bits']==3 and x['pointee_alignment_at_least']==8 for x in p['tagged_pointer_proofs']))

    def test_uncleared_tags_or_unaligned_pointees_are_not_recovered(self):
        for body in ('unsigned long v=get_pos(i);struct File *f=(struct File *)(v & ~1);return f ? f->mode : 0;',
                     'unsigned long v=get_pos(i)|8;struct File *f=(struct File *)(v & ~3);return f ? f->mode : 0;',
                     'unsigned long v=get_pos(i)+4;struct File *f=(struct File *)(v & ~3);return f ? f->mode : 0;',
                     'unsigned long v=i;struct File *f=(struct File *)(v & ~3);return f ? f->mode : 0;'):
            with self.subTest(body=body):
                self.assertIn('unresolved_pointer_origin',self.kinds(self.plan('unsigned root(unsigned i){'+body+'}')))
        p=self.plan('struct Byte{char c;};struct Byte *bytes(void);unsigned root(void){unsigned long v=1|(unsigned long)bytes();struct Byte *b=(struct Byte *)(v & ~1);return b->c;}',
            policy={'bytes':{'kind':'object_provider','reason':'fixture','implementation':'fixture','snapshot_safe':True},'task':{'kind':'object_provider','reason':'fixture','implementation':'fixture','snapshot_safe':True}})
        self.assertIn('unresolved_pointer_origin',self.kinds(p))

    def test_flags_split_from_the_same_word_prove_the_file_non_null(self):
        put='static void put(struct File *f){f->mode--;}\nstatic void fdput(struct fd fd){if(fd.flags & 1)put(fd.file);}\n'
        p=self.plan(put+'unsigned root(unsigned i){struct fd f=to_fd(get_pos(i));unsigned m=f.file ? f.file->mode : 0;fdput(f);return m;}')
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertTrue([x for x in p['null_guard_proofs'] if x['kind']=='tag_linked_flag_guard'])
        # A tagged null (flags set without a file) breaks the link; so does a flag outside the cleared bits.
        tagged_null=self.FD.replace('if(!f)return 0;','if(!f)return 1;')
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),tagged_null+put+'unsigned root(unsigned i){struct fd f=to_fd(get_pos(i));fdput(f);return 0;}')[0]
            p=Analyzer(tree,{'task':{'kind':'object_provider','reason':'fixture','implementation':'fixture','snapshot_safe':True}}).analyze('root')
        self.assertIn('unresolved_pointer_origin',self.kinds(p))
        # A flag test that is always false makes the call unreachable: the decided branch is skipped.
        p=self.plan(put.replace('fd.flags & 1','fd.flags & 0')+'unsigned root(unsigned i){struct fd f=to_fd(get_pos(i));fdput(f);return 0;}')
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual([(d['function'],d['outcome']) for d in p['decided_branch_proofs']],[('fdput',0)])

    def test_memory_model_argument_effects_enter_the_footprint(self):
        policy={'task':{'kind':'object_provider','reason':'fixture','implementation':'fixture','snapshot_safe':True},
                'load_acquire':{'kind':'memory_model','reads':[0],'reason':'acquire load','implementation':'reads *p'},
                'store_release':{'kind':'memory_model','writes':[0],'reason':'release store','implementation':'writes *p'}}
        p=self.plan('unsigned load_acquire(const unsigned *);void store_release(unsigned *,unsigned);unsigned root(void){store_release(&task()->table->count,1);return load_acquire(&task()->table->count);}',policy=policy)
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertIn('*(task()->table->count)',{r['path'] for r in p['entry_reads']})
        self.assertIn('*(task()->table->count)',{r['path'] for r in p['state_writes']})
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),self.FD)[0]
            with self.assertRaises(ValueError):Analyzer(tree,{'x':{'kind':'ordering_model','reads':[0],'reason':'r','implementation':'i'}})

class KernelContractTests(unittest.TestCase):
    MODEL='''struct File{struct File *next;unsigned mode;};
struct Table{unsigned max;struct File **fd;};struct Task{struct Table *table;};
struct Task *task(void);
unsigned long mask_nospec(unsigned long index,unsigned long size);
'''
    POLICY={'task':{'kind':'object_provider','reason':'fixture','implementation':'fixture','snapshot_safe':True},
            'mask_nospec':{'kind':'value_model','semantics':'index_mask','reason':'assembly mask','implementation':'index_mask'}}
    RANGE=[{'record':'struct Table','field':'max','min':4,'max':4,'reason':'four slots','validated_by':'fixture'}]
    EXTENT=[{'record':'struct Table','field':'fd','extent_field':'max','reason':'array of max slots','validated_by':'fixture'}]
    def plan(self,text,root='root',policy=None,**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),self.MODEL+text)[0]
            analyzer=Analyzer(tree,policy or self.POLICY,**options);plan=analyzer.analyze(root)
            self.assertEqual(plan,analyzer.fresh().analyze(root));return plan
    def kinds(self,plan):return {b['kind'] for b in plan['blockers']}
    LOOKUP='unsigned root(unsigned fd){struct Table *t=task()->table;unsigned long m=mask_nospec(fd,t->max);struct File *f=t->fd[fd&m];f=(struct File *)(m&(unsigned long)f);if(!f)return 0;return f->mode;}'

    def test_value_model_mask_and_pointer_extent(self):
        p=self.plan(self.LOOKUP,state_ranges=self.RANGE,pointer_extents=self.EXTENT)
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual({r['path'] for r in p['entry_reads'] if r['path'].endswith('->mode')},{'task()->table->fd[%d]->mode'%k for k in range(4)})
        self.assertIn(self.RANGE[0],p['state_range_assumptions'])
        # Without the extent contract the heap array has no bound; an inexact range is not an extent.
        self.assertIn('dynamic_extent',self.kinds(self.plan(self.LOOKUP,state_ranges=self.RANGE)))
        self.assertIn('dynamic_extent',self.kinds(self.plan(self.LOOKUP,state_ranges=[dict(self.RANGE[0],min=0)],pointer_extents=self.EXTENT)))
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),self.MODEL)[0]
            with self.assertRaises(ValueError):Analyzer(tree,{'m':{'kind':'value_model','semantics':'other','reason':'r','implementation':'i'}})
            with self.assertRaises(ValueError):Analyzer(tree,self.POLICY,pointer_extents=[{'record':'struct Table','field':'fd'}])

    def test_pointer_formation_over_a_contracted_extent(self):
        text='unsigned root(unsigned fd){struct Table *t=task()->table;unsigned long m=mask_nospec(fd,t->max);struct File **e=t->fd+(fd&m);struct File *f=*e;f=(struct File *)(m&(unsigned long)f);return f ? f->mode : 0;}'
        p=self.plan(text,state_ranges=self.RANGE,pointer_extents=self.EXTENT)
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual({r['path'] for r in p['entry_reads'] if r['path'].endswith('->mode')},{'task()->table->fd[%d]->mode'%k for k in range(4)})
        # Without the extent contract the element pointer is only derived: its dereference blocks.
        self.assertIn('dereference of a derived pointer (unproven offset) needs a checked span',{b['detail'] for b in self.plan(text,state_ranges=self.RANGE)['blockers']})

    def test_read_once_views_keep_element_provenance(self):
        vol={'classification':'sequential_snapshot','reason':'r','validated_by':'v'}
        text='unsigned root(unsigned fd){struct Table *t=task()->table;unsigned long m=mask_nospec(fd,t->max);struct File *f=*(struct File *const volatile *)&t->fd[fd&m];f=(struct File *)(m&(unsigned long)f);return f ? f->mode : 0;}'
        p=self.plan(text,state_ranges=self.RANGE,pointer_extents=self.EXTENT,volatile_accesses=vol)
        self.assertFalse(p['blockers'],p['blockers'])
        # The kernel spells the volatile view through typeof/_Generic; Clang still marks it NoOp.
        generic='(const volatile __typeof__(_Generic((t->fd[fd&m]), char: (char)0, default: (t->fd[fd&m]))) *)'
        p=self.plan(text.replace('(struct File *const volatile *)',generic),state_ranges=self.RANGE,pointer_extents=self.EXTENT,volatile_accesses=vol)
        self.assertFalse(p['blockers'],p['blockers'])
        # Changing the pointee type still drops element provenance.
        p=self.plan(text.replace('(struct File *const volatile *)','(unsigned long *)').replace('struct File *f=*','struct File *f=(struct File *)*'),
            state_ranges=self.RANGE,pointer_extents=self.EXTENT,volatile_accesses=vol)
        self.assertIn('pointer_arithmetic',self.kinds(p))

    def test_null_only_pointers_behind_guards_are_infeasible_and_anonymous_members_are_transparent(self):
        p=self.plan('struct S{union{unsigned a;unsigned b;};};static struct S *none(void){return 0;}\nunsigned root(void){struct S *s=none();if(!s)return 0;return s->b;}')
        # s is null-only, so the guard is decided and the read after it is unreachable.
        self.assertFalse(p['blockers'],p['blockers']);self.assertFalse(p['entry_reads'])
        self.assertEqual([(d['kind'],d.get('outcome')) for d in p['decided_branch_proofs']],[('decided_condition',1),('unreachable_after_decided_exit',None)])
        # Without the guard the null read still blocks.
        self.assertIn('unresolved_pointer_origin',self.kinds(self.plan('struct S{union{unsigned a;unsigned b;};};static struct S *none(void){return 0;}\nunsigned root(void){struct S *s=none();return s->b;}')))
        p=self.plan('struct S{union{unsigned a;unsigned b;};};struct S *get(void);\nunsigned root(void){return get()->b;}',policy={**self.POLICY,'get':{'kind':'object_provider','reason':'r','implementation':'i','snapshot_safe':True}})
        self.assertEqual({r['path'] for r in p['entry_reads']},{'get()->b'})

    def test_operand_free_asm_and_volatile_accesses_need_contracts(self):
        text='unsigned root(void){__asm__ volatile("dmb ish" ::: "memory");return *(const volatile unsigned *)&task()->table->max;}'
        p=self.plan(text)
        self.assertTrue({'architecture_or_ordering','volatile_memory'}<=self.kinds(p),p['blockers'])
        p=self.plan(text,operand_free_asm={'classification':'no_memory_effects','reason':'r','validated_by':'v'},
                    volatile_accesses={'classification':'sequential_snapshot','reason':'r','validated_by':'v'})
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual([r['volatile_snapshot'] for r in p['entry_reads'] if r.get('volatile_snapshot')],[{'classification':'sequential_snapshot'}])
        # Asm with operands is never covered by the operand-free contract.
        p=self.plan('unsigned root(void){unsigned v;__asm__ volatile("mrs %0, tpidr_el1":"=r"(v));return v;}',operand_free_asm={'classification':'no_memory_effects','reason':'r','validated_by':'v'})
        self.assertIn('architecture_or_ordering',self.kinds(p))

    def test_typeof_spellings_are_not_variable_bounds(self):
        p=self.plan('unsigned root(unsigned i){struct Table *t=task()->table;__typeof__(*(t->fd[i & 3])) *f=t->fd[i & 3];return f ? f->mode : 0;}',
            state_ranges=self.RANGE,pointer_extents=self.EXTENT)
        self.assertNotIn('unsupported_construct',self.kinds(p))

class StackObjectTests(unittest.TestCase):
    MODEL='''struct File{unsigned mode;long pos;};struct Task{struct File *file;struct File *spare;};struct Task *task(void);
struct Kiocb{struct File *filp;long pos;int flags;};
struct Iter{unsigned char type;union{struct{union{const void *iov;void *ubuf;};unsigned long count;};};};
static void init_kiocb(struct Kiocb *k,struct File *f){*k=(struct Kiocb){.filp=f,.flags=1};}
static void init_iter(struct Iter *i,void *buf,unsigned long n){*i=(struct Iter){.type=5,.ubuf=buf,.count=n};}
static long read_iter(struct Kiocb *k,struct Iter *i){k->pos+=i->count;return k->filp->mode+(long)(unsigned long)i->ubuf;}
'''
    POLICY={'task':{'kind':'object_provider','reason':'fixture','implementation':'fixture','snapshot_safe':True}}
    def plan(self,text,root='root'):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),self.MODEL+text)[0]
            analyzer=Analyzer(tree,self.POLICY);plan=analyzer.analyze(root)
            self.assertEqual(plan,Analyzer(tree,self.POLICY).analyze(root));return plan
    def kinds(self,plan):return {b['kind'] for b in plan['blockers']}

    def test_fields_written_through_the_address_are_read_back(self):
        p=self.plan('long root(void *buf){struct Kiocb k;struct Iter it;struct File *f=task()->file;init_kiocb(&k,f);k.pos=f->pos;init_iter(&it,buf,8);long r=read_iter(&k,&it);f->pos=k.pos;return r;}')
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertIn('task()->file->mode',{r['path'] for r in p['entry_reads']})
        self.assertFalse([r for r in p['entry_reads'] if 'auto:' in r['path']])

    def test_late_writes_converge_and_unwritten_fields_block(self):
        # The field is read in a loop before the write that feeds it (visit order).
        p=self.plan('long root(int n){struct Kiocb k={.filp=task()->spare};long r=0;for(int i=0;i<2;i++){r+=k.filp->mode;init_kiocb(&k,task()->file);}return r;}')
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertLessEqual({'task()->file->mode','task()->spare->mode'},{r['path'] for r in p['entry_reads']})
        p=self.plan('struct Box{struct File *f;};static void touch(struct Box *b){(void)b;}long root(void){struct Box b;touch(&b);return b.f->mode;}')
        self.assertIn('unresolved_pointer_origin',self.kinds(p))
        # A conditional initialization leaves the field indeterminate on the other path.
        p=self.plan('long root(int c){struct Kiocb k;if(c)init_kiocb(&k,task()->file);return k.filp->mode;}')
        self.assertIn('unresolved_pointer_origin',self.kinds(p))
        p=self.plan('long root(int c){struct Kiocb k={0};if(c)init_kiocb(&k,task()->file);return k.filp ? k.filp->mode : 0;}')
        self.assertFalse(p['blockers'],p['blockers'])

class CallbackContractTests(unittest.TestCase):
    MODEL='''struct File;struct Ops{long (*read)(struct File *);long (*read_iter)(struct File *);};
struct File{const struct Ops *f_op;long pos;};struct File *file(void);
long generic_read(struct File *f){return f->pos;}
long other_read(struct File *f){return -f->pos;}
long root(void){struct File *f=file();if(f->f_op->read)return f->f_op->read(f);return f->f_op->read_iter(f);}
'''
    POLICY={'file':{'kind':'object_provider','reason':'fixture','implementation':'fixture','snapshot_safe':True}}
    CONTRACT=[{'record':'struct Ops','field':'read_iter','targets':['generic_read'],'reason':'r','validated_by':'v'},
              {'record':'struct Ops','field':'read','targets':[],'reason':'r','validated_by':'v'}]
    def plan(self,**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),self.MODEL)[0]
            return Analyzer(tree,self.POLICY,**options).analyze('root')
    def test_contracted_callbacks_resolve_and_null_fields_are_unreachable(self):
        p=self.plan(callback_targets=self.CONTRACT)
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual({c['callee'] for c in p['call_sites'] if c.get('resolution')=='callback contract'},{'generic_read'})
        self.assertEqual(len([c for c in p['call_sites'] if c.get('resolution')=='contract_null_callback']),1)
        reads={r['path'] for r in p['entry_reads']}
        self.assertTrue({'file()->f_op->read','file()->f_op->read_iter','file()->pos'}<=reads,reads)
        self.assertEqual(len(p['callback_contract_uses']),2)
        self.assertIn('indirect_call',{b['kind'] for b in self.plan()['blockers']})
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),self.MODEL)[0]
            with self.assertRaises(ValueError):Analyzer(tree,self.POLICY,callback_targets=[{'record':'struct Ops','field':'read','targets':['a b'],'reason':'r','validated_by':'v'}])

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
