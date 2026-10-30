"""Path facts, state ranges, pointer-element arrays, null guards and by-value records."""
import copy,json,sys,tempfile,unittest
from pathlib import Path
import test_entry_state as basic
from entry_state import Analyzer,capture_header

POLICY={'current':{'kind':'object_provider','reason':'test current object','implementation':'stable object binding','snapshot_safe':True}}
RANGES=[{'record':'struct Table','field':'max','min':0,'max':4,'reason':'four inline slots','validated_by':'fixture'}]
MODEL='''struct File{unsigned mode;long pos;int count;};
struct Table{unsigned max;struct File *slot[4];unsigned long bits[1];};
struct Task{struct Table *table;};
struct Task *current(void);
'''

class PathFactTests(unittest.TestCase):
    def plan(self,text,root='root',policy=POLICY,**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),MODEL+text)[0];before=copy.deepcopy(tree)
            analyzer=Analyzer(tree,policy,**options);plan=analyzer.analyze(root)
            self.assertEqual(tree,before)
            self.assertEqual(plan,analyzer.fresh().analyze(root))
            self.assertNotIn('bounded-pointer:',json.dumps(plan))
            return plan
    def kinds(self,plan):return {b['kind'] for b in plan['blockers']}
    def reads(self,plan):return {r['path'] for r in plan['entry_reads']}

    def test_early_exit_guard_and_state_range_bound_an_index(self):
        body='unsigned root(unsigned i){struct Table *t=current()->table;if(i>=t->max)return 0;return t->slot[i]->mode;}'
        p=self.plan(body,state_ranges=RANGES)
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual({r for r in self.reads(p) if '->mode' in r},{'current()->table->slot[%d]->mode'%k for k in range(4)})
        self.assertEqual(p['state_range_assumptions'][0]['field'],'max')
        proof=[v['proof'] for v in p['local_index_proofs'] if v['proof']['kind']=='path_fact_interval'][0]
        self.assertEqual(proof['bounds'],[0,3]);self.assertTrue(proof['guards'])
        capture_header([p])
        # Without the declared range the guard bounds i only by the field's type.
        self.assertIn('dynamic_extent',self.kinds(self.plan(body)))

    def test_guards_are_invalidated_by_stores_labels_loops_and_volatile(self):
        bodies={
            'store':'if(i>=t->max)return 0;i=i+1;return t->slot[i]->mode;',
            'label':'if(i>=t->max)return 0;again:return t->slot[i]->mode;goto again;',
            'loop':'if(i>=t->max)return 0;for(;;){unsigned m=t->slot[i]->mode;i++;if(m)return m;}',
            'address':'if(i>=t->max)return 0;touch(&i);return t->slot[i]->mode;',
            'nonexit':'if(i>=t->max)(void)0;return t->slot[i]->mode;',
        }
        for name,body in bodies.items():
            with self.subTest(case=name):
                p=self.plan('void touch(unsigned*);unsigned root(unsigned i){struct Table *t=current()->table;'+body+'}',state_ranges=RANGES)
                self.assertTrue(self.kinds(p)&{'array_bounds','dynamic_extent'},p['blockers'])
        p=self.plan('unsigned root(volatile unsigned i){struct Table *t=current()->table;if(i>=t->max)return 0;return t->slot[i]->mode;}',state_ranges=RANGES)
        self.assertTrue(p['blockers'])

    def test_helper_returns_parameters_and_the_index_mask_idiom(self):
        helpers='''unsigned long mask_of(unsigned long i,unsigned long n){return i<n ? ~0ul : 0;}
unsigned clamp(unsigned i,unsigned n){return i<n ? i : 0;}
void clear(unsigned fd,struct Table *t){t->bits[fd/64]&=~(1ul<<(fd%64));}
'''
        p=self.plan(helpers+'unsigned root(unsigned fd){struct Table *t=current()->table;fd=clamp(fd,t->max);clear(fd,t);return t->slot[fd]->mode;}',state_ranges=RANGES)
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertIn('current()->table->bits[0]',{r['path'] for r in p['state_writes']})
        p=self.plan(helpers+'''unsigned root(unsigned fd){struct Table *t=current()->table;
unsigned long m=mask_of(fd,t->max);struct File **e=t->slot+(fd&m);struct File *f=*e;
f=(void*)(m&(unsigned long)f);if(!f)return 0;return f->mode;}''',state_ranges=RANGES)
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual({r for r in self.reads(p) if r.endswith('->mode')},{'current()->table->slot[%d]->mode'%k for k in range(4)})
        self.assertEqual(p['masked_pointer_proofs'][0]['mask_function'],'mask_of')
        # A mask that is not all-ones/zero leaves an unresolved integer address,
        # which blocks when dereferenced; a reassigned operand cannot borrow the mask's comparison.
        p=self.plan(helpers+'unsigned root(unsigned long m){struct File *f=*current()->table->slot;f=(void*)(m&(unsigned long)f);return f?f->mode:0;}',state_ranges=RANGES)
        self.assertIn('unresolved_pointer_origin',self.kinds(p))
        self.assertFalse(self.plan('unsigned root(unsigned long a){char *p=(char *)a;(void)p;return 0;}')['blockers'])
        p=self.plan(helpers+'unsigned root(unsigned fd){struct Table *t=current()->table;unsigned long m=mask_of(fd,t->max);fd=fd+1;return t->slot[fd&m]->mode;}',state_ranges=RANGES)
        self.assertTrue(self.kinds(p)&{'array_bounds','dynamic_extent'})

    def test_null_guards_prune_only_dominated_reads(self):
        lookup='struct File *find(unsigned i){return i<4 ? current()->table->slot[i] : 0;}\n'
        for body in ('struct File *f=find(i);if(!f)return 0;return f->mode;',
                     'struct File *f=find(i);return f && f->mode;',
                     'struct File *f=find(i);return !f || f->mode;',
                     'struct File *f=find(i);if(f){return f->mode;}return 0;',
                     'struct File *f=find(i);if(__builtin_expect(!!(f==0),0))return 0;return f->mode;'):
            with self.subTest(body=body):
                p=self.plan(lookup+'unsigned root(unsigned i){'+body+'}')
                self.assertFalse(p['blockers'],p['blockers']);self.assertTrue(p['null_guard_proofs'])
        for body in ('struct File *f=find(i);return f->mode;',
                     'struct File *f=find(i);if(!f)return 0;f=find(i+1);return f->mode;',
                     'struct File *f=find(i);if(!f)(void)0;return f->mode;',
                     'struct File *f=find(i);if(f)i++;return f->mode;'):
            with self.subTest(body=body):
                self.assertIn('unresolved_pointer_origin',self.kinds(self.plan(lookup+'unsigned root(unsigned i){'+body+'}')))

    def test_loop_conditions_and_whole_expression_guards(self):
        p=self.plan('unsigned root(unsigned s,unsigned n){unsigned sum=0;for(unsigned k=0;k<n;k+=3){if(s+k>=4)break;sum+=current()->table->slot[s+k]->mode;}return sum;}')
        self.assertFalse(p['blockers'],p['blockers'])
        # Loop conditions are not path facts: induction variables keep the
        # analyzer's loop certificates, which do not cover this while loop.
        p=self.plan('unsigned root(unsigned n){unsigned sum=0,k=0;while(k<4){sum+=current()->table->slot[k]->mode;k++;}return sum;}')
        self.assertTrue(self.kinds(p)&{'array_bounds','dynamic_extent'})
        # A store between the guard and the use voids the fact.
        p=self.plan('unsigned root(unsigned s){for(unsigned k=0;k<2;k++){if(s+k>=4)break;s++;(void)current()->table->slot[s+k]->mode;}return 0;}')
        self.assertTrue(self.kinds(p)&{'array_bounds','dynamic_extent'})

    def test_short_circuit_conditions_guard_their_right_operand(self):
        policy={**POLICY,'wide':POLICY['current']}
        p=self.plan('struct Wide{unsigned v[8];};struct Wide *wide(void);unsigned root(unsigned i){return i<8 && wide()->v[i];}',policy=policy)
        self.assertFalse(p['blockers'],p['blockers']);self.assertEqual(len(self.reads(p)),8)
        p=self.plan('struct Wide{unsigned v[8];};struct Wide *wide(void);unsigned root(unsigned i){return i>=8 || wide()->v[i];}',policy=policy)
        self.assertFalse(p['blockers'],p['blockers'])
        for body in ('return wide()->v[i] && i<8;','return (i<8 && (i=i+1)) && wide()->v[i];','return i<9 && wide()->v[i];'):
            with self.subTest(body=body):
                self.assertTrue(self.plan('struct Wide{unsigned v[8];};struct Wide *wide(void);unsigned root(unsigned i){'+body+'}',policy=policy)['blockers'])

    def test_values_proven_beyond_the_portable_constant_folder(self):
        for index in ('(index++,5)','index ? 5 : 5','index&3U ? 5 : 6'):
            with self.subTest(index=index):
                p=self.plan('struct Wide{unsigned v[8];};struct Wide *wide(void);unsigned index;unsigned root(void){return wide()->v['+index+'];}',
                    policy={**POLICY,'wide':POLICY['current']})
                self.assertFalse(p['blockers'],p['blockers']);self.assertLessEqual(self.reads(p)-{'global:index'},{'wide()->v[5]','wide()->v[6]'})
        # Pure constants stay with the portable folder, which rejects wide types.
        p=self.plan('struct Wide{unsigned v[8];};struct Wide *wide(void);unsigned root(void){return wide()->v[5ULL+0ULL];}',policy={**POLICY,'wide':POLICY['current']})
        self.assertTrue(p['blockers'])
        # Uninitialized, self-initialized and escaped locals remain unproven.
        for body in ('unsigned k;if(k>=8)return 0;return wide()->v[k];','unsigned k=k;if(k>=8)return 0;return wide()->v[k];',
                     'unsigned k=0;touch(&k);if(k>=8)return 0;return wide()->v[k];'):
            with self.subTest(body=body):
                p=self.plan('struct Wide{unsigned v[8];};struct Wide *wide(void);void touch(unsigned*);unsigned root(void){'+body+'}',policy={**POLICY,'wide':POLICY['current']})
                self.assertTrue(p['blockers'])

    def test_by_value_records_carry_pointer_fields(self):
        p=self.plan('''struct Ref{struct File *file;unsigned flags;};
struct Ref get(unsigned i){struct File *f=i<4 ? current()->table->slot[i] : 0;return (struct Ref){f,f ? 1u : 0u};}
void put(struct Ref r){if(r.flags && r.file)r.file->count--;}
long root(unsigned i){struct Ref r=get(i);long pos=-1;if(r.file){pos=r.file->pos;put(r);}return pos;}''')
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual({w['path'] for w in p['state_writes']},{'current()->table->slot[%d]->count'%k for k in range(4)})
        self.assertIn('current()->table->slot[2]->pos',self.reads(p))

    def test_mixed_element_and_object_pointers_dereference(self):
        p=self.plan('''long through(long *p){return p ? *p : 0;}
long root(unsigned i){long local=1;long *p=i ? &local : &current()->table->slot[0]->pos;return through(p);}''')
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertIn('*(current()->table->slot[0]->pos)',self.reads(p))

    def test_external_memory_boundaries_and_contract_validation(self):
        policy={**POLICY,'user_byte':{'kind':'memory_model','result':'external_memory','reason':'admitted user memory','implementation':'runtime'}}
        p=self.plan('unsigned char *user_byte(unsigned long);void root(unsigned long a){current()->table->slot[0]->mode=*user_byte(a);*user_byte(a+1)=2;}',policy=policy)
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual({(x['path'],x['write']) for x in p['external_memory_accesses']},{('*(external:user_byte())',False),('*(external:user_byte())',True)})
        self.assertFalse([r for r in p['entry_reads'] if 'external' in r['path']])
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),MODEL)[0]
            for bad in ([{'record':'struct Table','field':'max','min':5,'max':4,'reason':'r','validated_by':'v'}],
                        [{'record':'struct Table','field':'max','min':0,'max':4,'reason':'r'}],
                        [RANGES[0],RANGES[0]]):
                with self.assertRaises(ValueError):Analyzer(tree,POLICY,state_ranges=bad)
            with self.assertRaises(ValueError):Analyzer(tree,{'x':{'kind':'object_provider','result':'external_memory','reason':'r','implementation':'i'}})

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
