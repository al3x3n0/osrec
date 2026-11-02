"""Constant hook lists, compiler offsetof designators, and goto/loop-aware integer intervals."""
import tempfile,unittest
from pathlib import Path
import test_entry_state as basic
from entry_state import Analyzer,entry_accesses,fixed_global_read

HOOKS='''
#include <stddef.h>
struct node{struct node*next;};
struct head{struct node*first;};
struct entry{int pad;struct node list;int id;};
struct heads{struct head a,b;};
extern const struct heads heads;
static const struct entry table[2]={{0,{0},7},{0,{0},9}};
const struct heads heads={{(struct node*)&table[0].list},{(struct node*)&table[1].list}};
#define container_of(p,t,m) ((t*)(void*)((char*)(p)-offsetof(t,m)))
#define entry_safe(p,t,m) ({ struct node *q_=(p); q_ ? container_of(q_,t,m) : NULL; })
#define for_each(pos,h) for(pos=entry_safe((h)->first,struct entry,list);pos;pos=entry_safe((pos)->list.next,struct entry,list))
struct entry *current(void);
int consult(const struct entry*e,int value){(void)e;return value;}
int root(int value){int rc=0;struct entry*p;for_each(p,&heads.b){rc=consult(p,value);if(rc)break;}return rc;}
'''

class HookListTests(unittest.TestCase):
    def analyze(self,text,root='root',**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree,identity=basic.EntryStateTests().parse(Path(tmp),text)
            return Analyzer(tree,basic.POLICY,**options).analyze(root),identity

    def test_constant_hook_walk_reads_only_program_constants(self):
        plan,identity=self.analyze(HOOKS)
        self.assertFalse(plan['blockers'],plan['blockers'])
        self.assertEqual(identity['offsetof_designators'],2)
        self.assertEqual({r['path'] for r in plan['entry_reads']},{'global:heads.b.first','global:table[1].list.next'})
        self.assertTrue(all(fixed_global_read(r,plan) for r in plan['entry_reads']))
        self.assertEqual(entry_accesses(plan),[])
        proofs=[p for p in plan['container_proofs'] if p['kind']=='container_of_member_address']
        self.assertEqual({o['object'] for p in proofs for o in p['origins']},{'global:table[1]'})
        self.assertEqual(proofs[0]['designator'],{'record':'struct entry','fields':['list'],'source':'libclang'})

    def test_mutable_or_mismatched_tables_stay_blocked(self):
        variants=(
            # A writable head may point anywhere at run time.
            HOOKS.replace('const struct heads heads=','struct heads heads=').replace('extern const struct heads heads;','extern struct heads heads;'),
            # The designator names a different member than the one the pointer addresses.
            HOOKS.replace('struct entry{int pad;struct node list;int id;};','struct entry{int pad;struct node list;struct node other;};')
                 .replace('{{0,{0},7},{0,{0},9}}','{{0,{0},{0}},{0,{0},{0}}}').replace('offsetof(t,m)','offsetof(t,other)'),
            # The head points at a member of an object of another record type.
            HOOKS.replace('(struct node*)&table[1].list','(struct node*)&lone.list').replace('static const struct entry table','struct other{int a,b;struct node list;};static const struct other lone={0,0,{0}};static const struct entry table'),
        )
        for text in variants:
            with self.subTest(text=text[-200:]):
                plan,_=self.analyze(text)
                # container_of is not proven: its result is only a derived address, and walking
                # the list through it blocks.
                self.assertFalse([p for p in plan.get('container_proofs',[]) if p['kind']=='container_of_member_address'])
                self.assertIn('dereference of a derived pointer (unproven offset) needs a checked span',{b['detail'] for b in plan['blockers']},plan['blockers'])

    def test_goto_retry_and_definition_union_bound_an_index(self):
        plan,_=self.analyze('''struct T{unsigned max;void*slot[64];unsigned next;};struct T*current(void);
static unsigned limit(int which){return which==1?100000:8;}
static int alloc(unsigned end){struct T*t;unsigned fd;int error;
repeat:
 t=current();fd=t->next;
 error=-24;if(fd>=end)goto out;
 if(t->max==0)goto repeat;
 error=fd;
out:
 return error;}
void *root(void){int r=alloc(limit(7));if(r>=0)return current()->slot[r];return 0;}''')
        self.assertFalse(plan['blockers'],plan['blockers'])
        self.assertEqual({r['path'] for r in plan['entry_reads'] if 'slot' in r['path']},{'current()->slot[%d]'%i for i in range(8)})

    def test_counter_bounded_by_its_exit_guard(self):
        plan,_=self.analyze('''struct T{unsigned long bits[1];unsigned max;};struct T*current(void);
static unsigned long scan(const unsigned long*addr,unsigned long size,unsigned long start){
 unsigned long idx,tmp,sz=size;
 if(start>=sz)goto out;
 idx=start/64;
 for(tmp=addr[idx];!tmp;tmp=addr[idx]){if((idx+1)*64>=sz)goto out;idx++;}
 sz=idx*64;
out:
 return sz;}
unsigned long root(unsigned long start){struct T*t=current();unsigned long n=t->max;if(n>64)return 0;return scan(t->bits,n,start);}''')
        self.assertFalse(plan['blockers'],plan['blockers'])
        self.assertIn('current()->bits[0]',{r['path'] for r in plan['entry_reads']})

    def test_unguarded_counter_and_skipped_definition_stay_unproven(self):
        for body in ('for(tmp=addr[idx];!tmp;tmp=addr[idx]){idx++;}',
                     'for(tmp=addr[idx];!tmp;tmp=addr[idx]){if((idx+1)*64>=sz+64)goto out;idx++;}'):
            with self.subTest(body=body):
                plan,_=self.analyze('''struct T{unsigned long bits[1];};struct T*current(void);
static unsigned long scan(const unsigned long*addr,unsigned long sz,unsigned long start){unsigned long idx,tmp;
 if(start>=sz)return sz;idx=start/64;'''+body+'''out:return idx;}
unsigned long root(unsigned long s){return scan(current()->bits,64,s);}''')
                self.assertIn('dynamic_extent',{b['kind'] for b in plan['blockers']},plan['blockers'])
        # A jump past the only assignment leaves the variable possibly uninitialized.
        plan,_=self.analyze('''struct T{int a[4];};struct T*current(void);
int root(int k){unsigned i;if(k)goto use;i=k&3;use:return current()->a[i];}''')
        self.assertIn('dynamic_extent',{b['kind'] for b in plan['blockers']},plan['blockers'])

    def test_switch_cases_inherit_definitions_before_the_switch(self):
        plan,_=self.analyze('''struct T{int a[8];};struct T*current(void);
int root(unsigned long arg,int cmd){int v=(int)(arg&7);switch(cmd){case 1:return current()->a[v];case 2:v=0;return current()->a[v];}return 0;}''')
        self.assertFalse(plan['blockers'],plan['blockers'])

if __name__=='__main__':unittest.main()
