"""Derived pointers, checked-span boundary models, and branches decided from automatic-record fields."""
import tempfile,unittest
from pathlib import Path
import test_entry_state as basic
from entry_state import Analyzer

SPAN={'copy_out':{'kind':'memory_model','spans':[{'pointer':1,'length':2,'access':'read','objects':['global:buffer','global:zeros']}],
                  'reason':'fixture copy to user memory','implementation':'fails unless the span lies inside buffer or zeros'},
      'copy_in':{'kind':'memory_model','spans':[{'pointer':0,'length':2,'access':'write','objects':['global:buffer']}],
                 'reason':'fixture copy from user memory','implementation':'fails unless the span lies inside buffer'}}
DECLS='''unsigned char buffer[16];static const unsigned char zeros[16];unsigned char other[16];
unsigned long copy_out(void *to,const void *from,unsigned long n);unsigned long copy_in(void *to,const void *from,unsigned long n);
'''

class CheckedSpanTests(unittest.TestCase):
    def plan(self,text,root='root',policy=SPAN):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0]
            analyzer=Analyzer(tree,policy);plan=analyzer.analyze(root)
            self.assertEqual(plan,analyzer.fresh().analyze(root));return plan
    def kinds(self,plan):return {b['kind'] for b in plan['blockers']}

    def test_span_from_a_checked_array_reads_the_whole_array(self):
        p=self.plan(DECLS+'unsigned long root(void *user,unsigned long off,unsigned long n,int z){void *k=z?(void *)zeros:(void *)buffer;k+=off;return copy_out(user,k+1,n);}')
        self.assertFalse(p['blockers'],p['blockers'])
        reads={r['path'] for r in p['entry_reads']}
        self.assertEqual({r for r in reads if 'buffer' in r},{'global:buffer[%d]'%i for i in range(16)})
        self.assertTrue(all(r['immutable_global'] for r in p['entry_reads'] if 'zeros' in r['path']))
        self.assertEqual({o for s in p['checked_span_proofs'] for o in s['objects']},{'global:buffer','global:zeros'})

    def test_writes_and_origins_the_model_rejects(self):
        p=self.plan(DECLS+'unsigned long root(const void *user,unsigned long off,unsigned long n,int z){unsigned char *k=z?other:buffer;return copy_in(k+off,user,n);}')
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual({w['path'] for w in p['state_writes']},{'global:buffer[%d]'%i for i in range(16)})
        self.assertEqual(p['checked_span_proofs'][0]['rejected_at_run_time'],['global:other'])
        # The zero page is not a listed destination: a copy into it never completes.
        p=self.plan(DECLS+'unsigned long root(const void *user,unsigned long n){return copy_in((void *)zeros,user,n);}')
        self.assertFalse(p['blockers']);self.assertFalse(p['state_writes'])

    def test_unknown_origins_and_unchecked_uses_stay_blocked(self):
        p=self.plan(DECLS+'unsigned long root(void *user,unsigned char *k,unsigned long n){return copy_out(user,k+1,n);}')
        self.assertIn('boundary_memory_effect',self.kinds(p))
        p=self.plan(DECLS+'unsigned root(unsigned long off){unsigned char *k=buffer+off;return *k;}')
        self.assertIn('dereference of a derived pointer (unproven offset) needs a checked span',{b['detail'] for b in p['blockers']})
        p=self.plan(DECLS+'unsigned char *saved;void root(unsigned long off){saved=buffer+off;}')
        self.assertIn('derived pointer store needs an escape and reconstruction model',{b['detail'] for b in p['blockers']})
        p=self.plan(DECLS+'unsigned char *root(unsigned long off){return buffer+off;}')
        self.assertIn('derived pointer return needs a result-binding model',{b['detail'] for b in p['blockers']})
        # A derived pointer passed to a boundary argument that is not a checked span.
        p=self.plan(DECLS+'unsigned long root(void *user,unsigned long off,unsigned long n){return copy_out(buffer+off,user,n);}')
        self.assertIn('derived pointer boundary arguments need a checked span',{b['detail'] for b in p['blockers']})

    def test_span_contracts_are_validated(self):
        for span in ({'pointer':1,'length':2,'access':'read'},{'pointer':1,'length':2,'access':'copy','objects':['global:buffer']},
                     {'pointer':1,'length':2,'access':'read','objects':['buffer']}):
            with self.subTest(span=span),self.assertRaises(ValueError):
                Analyzer({'kind':'TranslationUnitDecl','inner':[]},{'copy_out':{'kind':'memory_model','spans':[span],'reason':'r','implementation':'i'}})

class DecidedBranchTests(unittest.TestCase):
    RECORD='''struct it{unsigned char type;unsigned count;void *base;};struct obj{unsigned a,b;};struct obj *current(void);void escape(struct it *);
static void init(struct it *i,void *base){*i=(struct it){.type=2,.count=1,.base=base};}
static unsigned read(struct it *i){if(i->type==2)return current()->a;return current()->b;}
'''
    def plan(self,text):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0]
            return Analyzer(tree,basic.POLICY).analyze('root')
    def reads(self,plan):return {r['path'] for r in plan['entry_reads']}

    def test_a_field_set_by_a_whole_object_store_decides_the_branch(self):
        p=self.plan(self.RECORD+'unsigned root(void *b){struct it i;init(&i,b);return read(&i);}')
        self.assertFalse(p['blockers'],p['blockers']);self.assertEqual(self.reads(p),{'current()->a'})
        self.assertEqual([(d['function'],d.get('outcome')) for d in p['decided_branch_proofs']],[('read',1),('read',None)])
        self.assertEqual(p['decided_branch_proofs'][1]['kind'],'unreachable_after_decided_exit')

    def test_unknown_or_undominated_fields_keep_both_branches(self):
        for body in ('struct it i;init(&i,b);i.type++;return read(&i);','struct it i;init(&i,b);escape(&i);return read(&i);',
                     'struct it i;unsigned r=read(&i);init(&i,b);return r;'):
            with self.subTest(body=body):
                p=self.plan(self.RECORD+'unsigned root(void *b){'+body+'}')
                self.assertEqual(self.reads(p),{'current()->a','current()->b'})

if __name__=='__main__':unittest.main()
