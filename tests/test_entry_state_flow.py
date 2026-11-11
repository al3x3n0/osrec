"""Path-sensitive facts: return partitions, correlated stores, value splits, data models and element stores."""
import tempfile,unittest
from pathlib import Path
import test_entry_state as basic
from entry_state import Analyzer

MODEL='''typedef unsigned long uintptr_t;struct Obj{unsigned a,b;unsigned arr[4];};struct Obj*current(void);
struct St{struct Obj *node;int flag;};
static _Bool is_err(const void *p){return (uintptr_t)p>=(uintptr_t)-4095;}
static void *err_ptr(long e){return (void *)e;}
'''

class Base(unittest.TestCase):
    def plan(self,text,root='root',policy=basic.POLICY,**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),MODEL+text)[0]
            analyzer=Analyzer(tree,policy,**options);plan=analyzer.analyze(root)
            self.assertEqual(plan,analyzer.fresh().analyze(root));return plan
    def reads(self,plan):return {r['path'] for r in plan['entry_reads']}
    def clean(self,text,reads,**options):
        p=self.plan(text,**options);self.assertFalse(p['blockers'],p['blockers']);self.assertEqual(self.reads(p),reads);return p

class FlowTests(Base):

    def test_return_partitions_split_callee_states_by_the_returned_value(self):
        start='static struct Obj *start(struct St *s,int k){if(k){s->node=(struct Obj *)1;return 0;}s->node=current();return current();}\n'
        # A local holding the result, the call itself as the condition, and a wrapper returning the local.
        self.clean(start+'unsigned root(int k){struct St st;struct Obj *o=start(&st,k);if(!o)return 0;return st.node->a;}',{'current()->a'})
        self.clean(start+'unsigned root(int k){struct St st;if(!start(&st,k))return 0;return st.node->a;}',{'current()->a'})
        self.clean(start+'static struct Obj *wrap(struct St *s,int k){struct Obj *o=start(s,k);return o;}\n'
                   'unsigned root(int k){struct St st;if(!wrap(&st,k))return 0;return st.node->a;}',{'current()->a'})
        # A store after the call, or a reassigned local, ends the partition.
        for body in ('struct Obj *o=start(&st,k);st.node=(struct Obj *)1;if(!o)return 0;return st.node->a;',
                     'struct Obj *o=start(&st,k);o=current();if(!o)return 0;return st.node->a;'):
            with self.subTest(body=body):
                p=self.plan(start+'unsigned root(int k){struct St st;'+body+'}')
                self.assertIn('unresolved_pointer_origin',{b['kind'] for b in p['blockers']})

    def test_callee_alias_closure_keeps_fields_the_callee_never_stores(self):
        # get() stores only `flag` (through mark), so its return reads `node` as the caller left it.
        text='static void mark(struct St *s){s->flag=1;}static struct Obj *get(struct St *s){mark(s);return s->node;}\n'
        self.clean(text+'unsigned root(void){struct St st;st.node=(struct Obj *)1;st.node=current();return get(&st)->a;}',{'current()->a'})
        # A callee that stores `node` itself hides it.
        p=self.plan('static struct Obj *swap(struct St *s){struct Obj *o=s->node;s->node=(struct Obj *)1;return o;}\n'
                    'unsigned root(void){struct St st;st.node=current();swap(&st);return st.node->a;}')
        self.assertIn('unresolved_pointer_origin',{b['kind'] for b in p['blockers']})

    def test_a_repeated_guard_proves_its_earlier_store(self):
        body='struct Obj *w=0;const int was=state&1;if(!was){w=current();}if(state&2)goto out;if(!was){return w->a;}out:return 0;'
        p=self.clean('unsigned root(unsigned state){'+body+'}',{'current()->a'})
        self.assertEqual({g['kind'] for g in p['null_guard_proofs']},{'correlated_store_guard'})
        for bad in (body.replace('const int was','int was').replace('goto out;','{was=0;goto out;}'),   # the guard variable changes
                    body.replace('if(!was){w=current();}','if(!was){if(state&4)goto out;w=current();}'),  # the store can be skipped
                    body.replace('w=current();}','w=current();}w=0;')):                                    # a second store
            with self.subTest(body=bad):
                p=self.plan('unsigned root(unsigned state){'+bad+'}')
                self.assertIn('unresolved_pointer_origin',{b['kind'] for b in p['blockers']})

    def test_value_classes_split_on_integer_views_under_both_data_models(self):
        make='static struct Obj *make(int k){if(k)return err_ptr(-12);return current();}\n'
        # o escapes, so its value lives in the flow state: the IS_ERR guard removes the error class.
        p=self.clean(make+'unsigned root(int k){struct Obj *o=make(k);struct Obj **q=&o;if(is_err(o))return 0;return o->a;}',{'current()->a'})
        # An object address is never in the error range, on ILP32 or LP64.
        p=self.clean('unsigned root(void){struct Obj *o=current();if(is_err(o))return o->b;return o->a;}',{'current()->a'})
        self.assertEqual([d.get('outcome') for d in p['decided_branch_proofs'] if d['kind']=='decided_condition'],[0])
        # A comparison whose outcome differs between data models stays undecided.
        p=self.plan('unsigned root(void){struct Obj *o=current();if((uintptr_t)o>0xffffffffUL)return o->b;return o->a;}')
        self.assertEqual(self.reads(p),{'current()->a','current()->b'})

    def test_element_addresses_store_but_one_past_and_automatic_arrays_do_not(self):
        policy={**basic.POLICY,'pool':{'kind':'object_provider','reason':'r','implementation':'i','snapshot_safe':True}}
        text='struct P{struct Obj items[2];struct Obj *head;};struct P *pool(void);\n'
        p=self.plan(text+'void root(unsigned n){struct P *p=pool();p->head=&p->items[n%2];}',policy=policy)
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual(p['pointer_store_proofs'][0]['elements'],['pool()->items[0]','pool()->items[1]'])
        for body in ('p->head=&p->items[2];','struct Obj local[2];p->head=&local[0];'):
            with self.subTest(body=body):
                p=self.plan(text+'void root(void){struct P *p=pool();'+body+'}',policy=policy)
                self.assertTrue(any('bounded pointer store' in b['detail'] for b in p['blockers']),p['blockers'])

    def test_escaped_pointer_steps_and_several_callback_targets(self):
        # The stored value of an escaped pointer follows the step (the element access itself
        # still needs a memory contract for an escaped cursor).
        p=self.plan('unsigned root(void){unsigned *p=current()->arr;unsigned **q=&p;p++;return *p;}')
        self.assertEqual(self.reads(p),{'current()->arr[1]'})
        # Either target may run: their states join (the null target's store keeps the read blocked).
        p=self.plan('static void good(struct St *s){s->node=current();}static void bad(struct St *s){s->node=0;}\n'
                    'unsigned root(int k){struct St st;void (*f)(struct St *)=k?good:bad;f(&st);return st.node->a;}')
        self.assertIn('unresolved_pointer_origin',{b['kind'] for b in p['blockers']})

    def test_a_declared_range_tightens_a_mask_and_is_an_assumption(self):
        # The static `& 1` bound is [0, 1]; the declared range of the masked field makes it 0.
        ranges=[dict(record='struct Obj',field='a',min=0,max=0,reason='r',validated_by='live state field obj.a')]
        text='unsigned root(void){struct Obj *o=current();if(!(o->a&1u))return 0;return o->b;}'
        p=self.clean(text,{'current()->a'},state_ranges=ranges)
        self.assertEqual([(a['record'],a['field']) for a in p['state_range_assumptions']],[('struct Obj','a')])
        self.assertEqual(self.reads(self.plan(text)),{'current()->a','current()->b'})
        # A range the mask already implies still decides nothing more.
        p=self.plan(text,state_ranges=[dict(ranges[0],max=3)]);self.assertEqual(self.reads(p),{'current()->a','current()->b'})

    def test_a_rejecting_assertion_bounds_what_follows_it(self):
        # check(c) flags a fault the replay rejects: after it, c is false, so i < 4 bounds the index.
        text='int fault;int check(int failure){if(failure)fault=1;return failure;}\nunsigned root(unsigned i){check(i>=4);return current()->arr[i];}'
        contract=[dict(function='check',condition_argument=0,reason='r',validated_by='v')]
        p=self.clean(text,{'current()->arr[0]','current()->arr[1]','current()->arr[2]','current()->arr[3]'},fault_assertions=contract)
        self.assertEqual([g['assertion'] for g in p['fault_assertion_guards']],['check']);self.assertEqual(p['fault_assertion_contracts'],contract)
        # Without the contract, before the call, or with the bound changed in between, the index stays unproven.
        for body,options in ((text,{}),(text.replace('check(i>=4);return current()->arr[i];','unsigned v=current()->arr[i];check(i>=4);return v;'),{'fault_assertions':contract}),
                             (text.replace('check(i>=4);','check(i>=4);i+=4;'),{'fault_assertions':contract})):
            with self.subTest(body=body):self.assertTrue(self.plan(body,**options)['blockers'])
        with self.assertRaises(ValueError):Analyzer({'kind':'TranslationUnitDecl','inner':[]},basic.POLICY,fault_assertions=[dict(contract[0],condition_argument='0')])

    def test_a_recursive_walk_widens_and_a_low_bit_mask_keeps_its_values(self):
        # s.node climbs ->parent in a loop: the stored value would gain a step every pass.
        policy={**basic.POLICY,'top':{'kind':'object_provider','reason':'r','implementation':'i','snapshot_safe':True}}
        text='struct N{struct N *parent;unsigned a;};struct N *top(void);struct S{struct N *node;};\n'
        p=self.plan(text+'unsigned root(int k){struct S s;struct S *q=&s;q->node=top();while(k--)q->node=q->node->parent;return q->node->a;}',policy=policy)
        kinds={b['kind'] for b in p['blockers']}
        self.assertNotIn('analysis_limit',kinds);self.assertIn('unresolved_pointer_origin',kinds)
        # v in [1, 3]: v & 3 is v, never 0.
        self.clean('unsigned root(void){unsigned v=current()->a%3+1;if((v&3)==0)return current()->b;return v;}',{'current()->a'})
        self.assertEqual(self.reads(self.plan('unsigned root(void){unsigned v=current()->a%5;if((v&3)==0)return current()->b;return v;}')),{'current()->a','current()->b'})

USER_POLICY={**basic.POLICY,'get_byte':{'kind':'memory_model','writes':[1],'reason':'reads one user byte','implementation':'fixture'}}
USER=[{'function':'root','parameter':'buf','reason':'user buffer','validated_by':'fixture'}]
USER_MODEL='int get_byte(const void *p,char *value);\n'

class UserAddressTests(Base):
    def test_user_addresses_step_round_trip_and_subtract_without_kernel_memory(self):
        # fault_in_readable: align, step by pages, read one byte per page, return the remainder.
        body='''unsigned long root(const char *buf,unsigned long size){
const char *uaddr=buf,*start=buf,*end;volatile char c;
if(!size)return 0;
if((unsigned long)uaddr&4095){if(get_byte(uaddr,(char *)&c))goto out;uaddr=(const char *)(((unsigned long)uaddr+4095)&~4095UL);}
end=(const char *)(((unsigned long)start+size+4095)&~4095UL);
if(end<start)end=0;
while(uaddr!=end){if(get_byte(uaddr,(char *)&c))goto out;uaddr+=4096;}
out:(void)c;
if(size>uaddr-start)return size-(uaddr-start);
return 0;}'''
        p=self.clean(USER_MODEL+body,set(),policy=USER_POLICY,user_addresses=USER)
        self.assertEqual({u['kind'] for u in p['user_address_proofs']},{'user_address_offset','user_address_difference'})
        self.assertEqual({v['kind'] for v in p['local_volatile_storage_proofs']},{'discarded_volatile_scalar'})
        # Without the contract the same code blocks; so does a direct dereference, and a used volatile value.
        self.assertTrue(self.plan(USER_MODEL+body,policy=USER_POLICY)['blockers'])
        for bad in ('unsigned root(const char *buf){return buf[1];}',
                    'unsigned root(const char *buf){volatile char c;get_byte(buf,(char *)&c);return c;}'):
            with self.subTest(body=bad):
                p=self.plan(USER_MODEL+bad,policy=USER_POLICY,user_addresses=USER)
                self.assertTrue(p['blockers'],bad)
        with self.assertRaises(ValueError):Analyzer({'kind':'TranslationUnitDecl','inner':[]},basic.POLICY,user_addresses=[{'function':'root'}])

class SignAndLoopTests(Base):
    def test_sign_tests_select_return_states_and_narrow_returned_locals(self):
        # begin() stores a null page on failure; the caller breaks on a negative status.
        text='''static int lookup(struct Obj **out,int k){if(k<0){*out=0;return -5;}*out=current();return 0;}
static int begin(struct Obj **page,int k){int ret;if(k>9)return -1;ret=lookup(page,k);if(ret)return ret;return 0;}
unsigned root(int k){unsigned sum=0;do{struct Obj *page;long status=begin(&page,k);if(status<0)break;sum+=page->a;k--;}while(k>0);return sum;}'''
        self.clean(text,{'current()->a'})
        p=self.plan(text.replace('if(status<0)break;','if(status>0)break;'))
        self.assertTrue(p['blockers'])

    def test_a_null_replacing_store_proves_later_reads(self):
        self.clean('unsigned root(int k){struct Obj *w=0;if(k)w=current();if(!w)w=current();k++;return w->a;}',{'current()->a'})
        for bad in ('struct Obj *w=0;if(k)w=current();if(!w)w=0;return w->a;',
                    'struct Obj *w=0;if(!w)w=current();if(k)w=0;return w->a;',
                    'struct Obj *w=0;if(!w){if(k)goto skip;w=current();}skip:return w->a;'):
            with self.subTest(body=bad):
                p=self.plan('unsigned root(int k){'+bad+'}')
                self.assertIn('unresolved_pointer_origin',{b['kind'] for b in p['blockers']})

ARRAY='''struct V{struct Obj *base;unsigned long len;};
static int fill(struct V *v,unsigned n){do{v->base=current();v->len=1;v++;}while(--n);return 0;}
static struct V *from(unsigned n,struct V *fast){if(n>8)return (struct V *)-22;if(fill(fast,n))return (struct V *)-14;return fast;}
'''

class ArraySummaryTests(Base):
    def test_a_pointer_carrying_automatic_array_is_one_summarized_object(self):
        for body in ('unsigned root(unsigned n){struct V st[8];struct V *v=st;if(!n||n>8)return 0;fill(v,n);return v[n-1].base->a;}',
                     # through the address of an escaped pointer local, and through a record that holds the cursor
                     'static void imp(struct V **vp,unsigned n){fill(*vp,n);}\nunsigned root(unsigned n){struct V st[8];struct V *v=st;if(!n||n>8)return 0;imp(&v,n);return v->base->a;}',
                     'struct I{const struct V *iov;};static void init(struct I *i,const struct V *v){i->iov=v;}\nunsigned root(unsigned n){struct V st[8];struct I it;if(!n||n>8)return 0;fill(st,n);init(&it,st);const struct V *p=it.iov;return p->base->a;}',
                     # a dominating IS_ERR guard removes the error constants
                     'unsigned root(unsigned n){struct V st[8];struct V *v=from(n,st);if(is_err(v))return 0;return v->base->a;}'):
            with self.subTest(body=body):
                p=self.clean(ARRAY+body,{'current()->a'})
                self.assertEqual({a['array'] for a in p['automatic_array_summaries']},{'st'})
        for bad in ('unsigned root(void){struct V st[8];return st[0].base->a;}',                                    # never stored
                    'unsigned root(unsigned n){struct V st[8];fill(st,1);st[1].base=0;return st[0].base->a;}',     # one element null
                    'void sink(struct V *);unsigned root(void){struct V st[8];fill(st,1);sink(st);return st[0].base->a;}',  # escapes to unknown code
                    'unsigned root(unsigned n){struct V st[8];struct V *v=from(n,st);return v->base->a;}'):       # no error guard
            with self.subTest(body=bad):self.assertTrue(self.plan(ARRAY+bad)['blockers'])

    def test_call_results_carried_from_the_previous_pass_reach_the_alias_closure(self):
        # The import_iovec shape: the allocation path returns null or an error, so after the IS_ERR
        # guard the cursor is the summarized array. The closure re-resolving the call flow-
        # insensitively would see the null; the previous pass's visit-time result does not.
        lib=r"""static struct V *nomem(unsigned long n,unsigned long sz){(void)n;(void)sz;return 0;}
static void release(const void *p){(void)p;}
static struct V *from3(unsigned long n,unsigned long fast_n,struct V *fast){struct V *v=fast;int ret;if(n==0)return v;if(n>1024)return (struct V *)-22;
 if(n>fast_n){v=nomem(n,sizeof(struct V));if(!v)return (struct V *)-12;}ret=fill(v,n);if(ret){if(v!=fast)release(v);return (struct V *)(long)ret;}return v;}
struct I{const struct V *iov;unsigned long n;};
static void init(struct I *i,const struct V *v,unsigned long n){i->iov=v;i->n=n;}
static long imp(unsigned n,struct V **iovp,struct I *i){struct V *v;unsigned long seg;long t=0;v=from3(n,8,*iovp);if(is_err(v)){*iovp=0;return (long)v;}
 for(seg=0;seg<n;seg++){long len=(long)v[seg].len;if(!len){if(v!=*iovp)release(v);*iovp=0;return -14;}if(len>100-t){len=100-t;v[seg].len=len;}t+=len;}
 init(i,v,n);if(v==*iovp)*iovp=0;else *iovp=v;return t;}
"""
        body='unsigned root(unsigned n){struct V st[8];struct V *iov=st;struct I it;if(n<2)return 0;long r=imp(n,&iov,&it);if(r<0)return 0;return it.iov->base->a;}'
        p=self.clean(ARRAY+lib+body,{'current()->a'})
        self.assertEqual({a['array'] for a in p['automatic_array_summaries']},{'st'})
        # Without the error guard the null (and error) results reach the subscript.
        self.assertTrue(self.plan(ARRAY+lib.replace('if(is_err(v)){*iovp=0;return (long)v;}','')+body)['blockers'])

    def test_a_boundary_loaded_pointer_is_a_user_address(self):
        policy={**basic.POLICY,'load':{'kind':'memory_model','writes':[0],'user_values':[0],'reason':'r','implementation':'i'},
                'copy':{'kind':'memory_model','writes':[0],'reason':'r','implementation':'i'}}
        model='int load(unsigned char *out,const void *p);int copy(void *to,const void *from);\n'
        body='unsigned root(const void *vec){void *buf;if(load((unsigned char *)&buf,vec))return 0;char c;copy(&c,(const char *)buf+1);return 0;}'
        user=[dict(function='root',parameter='vec',reason='r',validated_by='v')]
        self.clean(model+body,set(),policy=policy,user_addresses=user)
        bad=body.replace('char c;copy(&c,(const char *)buf+1);return 0;','return *(const char *)buf;')
        self.assertTrue(self.plan(model+bad,policy=policy,user_addresses=user)['blockers'])
        with self.assertRaises(ValueError):self.plan(model+body,policy={**policy,'load':{**policy['load'],'user_values':[1]}},user_addresses=user)

HASH='''typedef struct {int counter;} cnt_t;struct H{cnt_t w;cnt_t other;unsigned long n;unsigned arr[4];};struct H *hcur(void);
'''
HASH_POLICY={**basic.POLICY,'hcur':dict(basic.POLICY['current'])}

class FutexShapeTests(Base):
    """Shapes of futex_hash, futex_hb_waiters_pending, jhash2 and futex_q_init."""
    def test_a_nested_member_range_applies_through_its_outer_record_only(self):
        ranges=[dict(record='struct H',field='w.counter',min=0,max=3,reason='r',validated_by='v')]
        for body in ('unsigned root(void){struct H *h=hcur();return h->arr[(&h->w)->counter];}',
                     'unsigned root(void){struct H *h=hcur();return h->arr[h->w.counter];}'):
            with self.subTest(body=body):
                p=self.plan(HASH+body,policy=HASH_POLICY,state_ranges=ranges);self.assertFalse(p['blockers'],p['blockers'])
                self.assertEqual([(a['record'],a['field']) for a in p['state_range_assumptions']],[('struct H','w.counter')])
        # The same counter type under another member, or with no range, stays unbounded.
        for body,options in (('unsigned root(void){struct H *h=hcur();return h->arr[h->other.counter];}',dict(state_ranges=ranges)),
                             ('unsigned root(void){struct H *h=hcur();return h->arr[h->w.counter];}',{})):
            with self.subTest(body=body):self.assertTrue(self.plan(HASH+body,policy=HASH_POLICY,**options)['blockers'])

    def test_a_mask_bounds_an_unbounded_operand(self):
        ranges=[dict(record='struct H',field='n',min=4,max=4,reason='r',validated_by='v')]
        self.assertFalse(self.plan(HASH+'unsigned root(unsigned x){struct H *h=hcur();return h->arr[x & (h->n - 1)];}',policy=HASH_POLICY,state_ranges=ranges)['blockers'])
        for body in ('unsigned root(unsigned x){struct H *h=hcur();return h->arr[x | (h->n - 1)];}',
                     'unsigned root(unsigned x){struct H *h=hcur();return h->arr[x & h->n];}'):
            with self.subTest(body=body):self.assertTrue(self.plan(HASH+body,policy=HASH_POLICY,state_ranges=ranges)['blockers'])

    def test_a_const_view_reads_scalars_of_a_stack_object(self):
        view=HASH+"""union K{struct {void *p;unsigned long a;unsigned o;} x;struct {unsigned long w0,w1;unsigned o;} y;};
static unsigned sum(const unsigned *k,unsigned n){unsigned s=0;while(n>3){s+=k[0]+k[1]+k[2];n-=3;k+=3;}
 switch(n){case 3:s+=k[2];case 2:s+=k[1];case 1:s+=k[0];break;default:break;}return s;}
"""
        p=self.plan(view+'unsigned root(void){union K key={0};key.x.p=hcur();key.x.o=3;return sum((const unsigned *)&key,4);}',policy=HASH_POLICY)
        self.assertFalse(p['blockers'],p['blockers']);self.assertTrue(p['automatic_views'])
        self.assertFalse([r for r in p['entry_reads'] if not r['path'].startswith('argument:')])
        for body in ('unsigned root(void){return sum((const unsigned *)&hcur()->n,4);}',                                        # not a stack object
                     'unsigned root(void){union K key={0};unsigned *k=(unsigned *)&key;k[1]=2;key.x.p=hcur();return ((struct H *)key.x.p)->arr[0];}'):  # a writable view
            with self.subTest(body=body):self.assertTrue(self.plan(view+body,policy=HASH_POLICY)['blockers'])

    def test_a_const_record_copy_is_program_data(self):
        record="""static void cb(void){}
union U{unsigned long u;void *p;};
struct Q{void (*f)(void);unsigned b;union U k;};
"""
        from entry_state import fixed_global_read
        p=self.plan(record+'static const struct Q init={.f=cb,.b=7,.k=(union U){.u=0}};\nunsigned root(void){struct Q q=init;return q.b+current()->a;}')
        self.assertFalse(p['blockers'],p['blockers'])
        copied=[r for r in p['entry_reads'] if r['path']=='global:init']
        self.assertEqual([r['immutable_global']['kind'] for r in copied],['defined_const_record']);self.assertTrue(fixed_global_read(copied[0],p))
        # The copy proves only that the read is no entry state: a callback copied out is still unresolved.
        self.assertIn('indirect_call',{b['kind'] for b in self.plan(record+'static const struct Q init={.f=cb,.b=7};\nunsigned root(void){struct Q q=init;q.f();return q.b;}')['blockers']})
        # A mutable record is entry state.
        p=self.plan(record+'static struct Q init={.f=cb,.b=7};\nunsigned root(void){struct Q q=init;return q.b;}')
        self.assertFalse([r for r in p['entry_reads'] if r['path']=='global:init' and 'immutable_global' in r])

if __name__=='__main__':unittest.main()
