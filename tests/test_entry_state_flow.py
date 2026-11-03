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

if __name__=='__main__':unittest.main()
