"""KQuery parsing and dependency extraction for KLEE state discovery."""
import shutil,struct,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from klee_state_discovery import KQuery,Printer,Stp,dependencies,candidates,analyze_paths,ktest_values,default_kleaver,input_ranges,top_level,hit_entries,separate_members,graph_invariants

HEADER='''array s1[8] : w32 -> w8 = symbolic
array s2[8] : w32 -> w8 = symbolic
array s3[4] : w32 -> w8 = symbolic
array o4[8] : w32 -> w8 = symbolic
array const_arr1[16] : w32 -> w8 = [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
'''

def query(*constraints):
    return HEADER+'(query ['+'\n'.join(constraints)+'] false)\n'

class KQueryTests(unittest.TestCase):
    def deps(self,text):
        imprecise=[];return [dependencies(c,imprecise) for c in KQuery(text).constraints()],imprecise

    def test_labels_and_plain_reads(self):
        found,_=self.deps(query('(Eq false (Eq 0 N0:(ReadLSB w64 0 s1)))','(Eq false (Slt N0 (ReadLSB w64 0 s2)))'))
        self.assertEqual(found,[{'s1'},{'s1','s2'}])

    def test_update_list_reads_only_reachable_entries(self):
        # The object holds s1 at bytes 0..7 and s2 at 8..15; the read index is 0 or 8.
        updates='U0:['+', '.join('%d=(Read w8 %d s2)'%(8+i,i) for i in range(8))+', '+', '.join('%d=(Read w8 %d s1)'%(i,i) for i in range(8))+'] @ const_arr1'
        found,imprecise=self.deps(query('(Eq 0 (Read w8 (Select w32 (Eq 0 (Read w8 0 s3)) 8 0) %s))'%updates))
        self.assertEqual(found,[{'s1','s2','s3'}]);self.assertFalse(imprecise)
        found,_=self.deps(query('(Eq 0 (ReadLSB w32 0 %s))'%updates))
        self.assertEqual(found,[{'s1'}])
        # Unlabeled update lists are read the same way.
        found,_=self.deps(query('(Eq 0 (Read w8 1 [1=(Read w8 0 s2), 0=(Read w8 0 s1)] @ const_arr1))'))
        self.assertEqual(found,[{'s2'}])
        # A read of never-updated bytes depends on nothing symbolic.
        found,_=self.deps(query('(Eq 0 (Read w8 9 U1:[0=(Read w8 0 s1)] @ const_arr1))'))
        self.assertEqual(found,[set()])

    def test_chained_versions_keep_older_entries(self):
        # U1 extends U0: a read of byte 0 through U1 reaches the entry stored in U0.
        found,_=self.deps(query('(Eq 0 (Read w8 0 U1:[1=(Read w8 0 s2)] @ U0:[0=(Read w8 0 s1)] @ const_arr1))','(Eq 0 (Read w8 1 U1))'))
        self.assertEqual(found,[{'s1'},{'s2'}])

    def test_printer_round_trips_labels_widths_and_versions(self):
        text=query('(Ult N0:(ReadLSB w32 (w32 4) U0:[1=(Read w8 0 s2)] @ s1) 9)','(Eq false (Eq (w64 0) (ZExt w64 N0)))')
        q=KQuery(text);constraints=q.constraints();show=Printer(q)
        self.assertEqual(show(constraints[0]),'(Ult N0 9)')
        self.assertEqual(show(constraints[1]),'(Eq false (Eq (w64 0) (ZExt w64 N0)))')
        self.assertEqual(show(constraints[0][2][0]),'N0')
        # Standalone printing defines each label at its first use.
        alone=Printer(q,standalone=True)(constraints[1])
        self.assertEqual(alone,'(Eq false (Eq (w64 0) (ZExt w64 N0:(ReadLSB w32 (w32 4) U0:[(w32 1)=(Read w8 (w32 0) s2)] @ s1))))')
        q2=KQuery('(query [(Eq 0 (Read w8 (w32 2) [1=(Read w8 0 s2)] @ s1))] false)');c=q2.constraints()[0]
        self.assertEqual(Printer(q2)(c),'(Eq 0 (Read w8 (w32 2) [(w32 1)=(Read w8 (w32 0) s2)] @ s1))')

    def test_top_level_splits_labelled_bare_and_constant_constraints(self):
        self.assertEqual(top_level(' (Eq 0 (Read w8 0 s1))\n N0:(Ult (ReadLSB w32 0 s2) 9) N0 false\n(Eq false N0)'),
            ['(Eq 0 (Read w8 0 s1))','N0:(Ult (ReadLSB w32 0 s2) 9)','N0','false','(Eq false N0)'])

    def test_pruned_reads_keep_only_entries_they_can_return(self):
        # Byte 0 was stored twice (newest first): only the newest store answers it.
        q=KQuery(query('(Eq 0 (Read w8 0 U0:[1=(Read w8 0 s2), 0=(Read w8 0 s3), 0=(Read w8 0 s1)] @ const_arr1))'));c=q.constraints()[0]
        self.assertEqual(hit_entries(c[2][1]),{1})
        self.assertEqual(Printer(q,standalone=True,prune=hit_entries)(c),'(Eq 0 (Read w8 (w32 0) [(w32 0)=(Read w8 (w32 0) s3)] @ const_arr1))')
        # A symbolic index keeps every entry unless the path says otherwise.
        q=KQuery(query('(Eq 0 (Read w8 (Read w8 0 s3) U0:[1=(Read w8 0 s2), 0=(Read w8 0 s1)] @ const_arr1))'));c=q.constraints()[0]
        self.assertIsNone(hit_entries(c[2][1]));self.assertEqual(hit_entries(c[2][1],lambda read:{0}),{0})

    def test_pruned_reads_define_index_labels_before_entries_use_them(self):
        # The index's label N0 is also stored in an entry: its definition must come first.
        text=query('(Eq 0 (Read w8 N0:(ZExt w32 (Read w8 0 s3)) [N0=(Read w8 0 s1), 1=(Read w8 0 s2)] @ const_arr1))')
        q=KQuery(text);c=q.constraints()[0]
        printed=Printer(q,standalone=True,prune=lambda r:{0})(c)
        self.assertLess(printed.index('N0:'),printed.index('N0='))

    def test_chained_versions_print_each_version_once(self):
        text=query('(Eq 0 (Read w8 0 U1:[1=(Read w8 0 s2)] @ U0:[0=(Read w8 0 s1)] @ const_arr1))','(Eq 0 (Read w8 1 U1))','(Eq 0 (Read w8 2 U0))')
        q=KQuery(text);cs=q.constraints();show=Printer(q,standalone=True)
        printed=' '.join(show(c) for c in cs)
        self.assertEqual(printed.count('(Read w8 (w32 0) s1)'),1)
        self.assertIn('U1:[(w32 1)=(Read w8 (w32 0) s2)] @ U0:[(w32 0)=(Read w8 (w32 0) s1)] @ const_arr1',printed)

    def test_canonical_labels_print_equal_expressions_equally(self):
        one=KQuery(query('(Eq false (Eq 0 N3:(Add w64 N7:(ReadLSB w64 0 s1) N7)))'));two=KQuery(query('(Eq false (Eq 0 N0:(Add w64 N1:(ReadLSB w64 0 s1) N1)))'))
        def show(q):c=q.constraints()[0];return Printer(q,standalone=True,canonical=True)(c)
        first,second=show(one),show(two)
        self.assertEqual(first,second);self.assertIn('N0:',first)

    def test_questions_carry_only_connected_constraints(self):
        text=query('(Ult (ReadLSB w64 0 s1) 9)','(Ult (ReadLSB w64 0 s2) 5)','(Eq (ReadLSB w64 0 o4) (ReadLSB w64 0 s2))')
        q=KQuery(text);cs=q.constraints();stp=Stp(text,'kleaver')
        stp.focus(q,cs,[dependencies(c,[]) for c in cs])
        context,_,_=stp.context('(Ult (ReadLSB w64 0 s1) 10)',[],True)
        self.assertIn('s1',context);self.assertNotIn('s2',context)
        # An output's observation joins only questions that name the output.
        context,_,_=stp.context('(Ult (ReadLSB w64 0 s2) 6)',[],True)
        self.assertNotIn('o4',context);self.assertIn('s2',context)
        context,_,_=stp.context('(Ult (ReadLSB w64 0 o4) 5)',[],True)
        self.assertIn('o4',context);self.assertIn('(Ult (ReadLSB w64 (w32 0) s2) 5)',context);self.assertNotIn('s1',context)
        # Feasibility names no array: it is asked under every constraint.
        context,_,_=stp.context('false',[],True)
        self.assertIn('s1',context);self.assertIn('o4',context)

    def test_unbounded_indices_are_conservative_and_reported(self):
        updates='U0:[0=(Read w8 0 s1), 1=(Read w8 0 s2)] @ const_arr1'
        found,imprecise=self.deps(query('(Eq 0 (Read w8 (Read w8 0 s3) %s))'%updates))
        self.assertEqual(found,[{'s1','s2','s3'}]);self.assertEqual(imprecise,['const_arr1'])
        self.assertEqual(candidates(KQuery(query('(Add w32 4 (Select w32 (Eq 0 (Read w8 0 s3)) 1 2))')).constraints()[0]),{5,6})

    def test_paths_split_control_and_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)
            (d/'test000001.kquery').write_text(query('(Eq false (Eq 0 (ReadLSB w64 0 s1)))','(Eq (ReadLSB w64 0 o4) (Add w64 (ReadLSB w64 0 s2) 1))'))
            (d/'test000002.kquery').write_text(query('(Ult (ReadLSB w32 0 s3) 9)'))
            (d/'test000002.domain.err').write_text('')
            paths=analyze_paths(d,{'s1':'a','s2':'b','s3':'c','o4':'out'})
        self.assertEqual(paths[0]['control'],['a']);self.assertEqual(paths[0]['data'],{'out':['b']})
        self.assertEqual(paths[1]['errors'],['domain.err'])

    def test_stopped_states_are_prefixes_not_paths(self):
        from klee_state_discovery import summarize
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)
            (d/'test000001.kquery').write_text(query('(Eq (ReadLSB w64 0 o4) (ReadLSB w64 0 s2))'))
            (d/'test000002.kquery').write_text(query('(Eq false (Eq 0 (ReadLSB w64 0 s1)))'))
            (d/'test000002.early').write_text('Execution halting.\n')
            names={'s1':'a','s2':'b','s3':'c','o4':'out'};paths=analyze_paths(d,names)
            for p in paths:p['model_fault']=0
        self.assertEqual((paths[1]['fault'],paths[1]['analyzed'],paths[1]['prefix_control']),('partial',False,['a']))
        report=summarize(paths,names,[])
        self.assertEqual(report['required'],['b']);self.assertTrue(report['required_is_lower_bound'])
        self.assertEqual((report['paths']['partial'],report['paths']['in_domain']),(1,1));self.assertEqual(report['prefix_control_not_required'],['a'])

    def test_stopped_states_prove_no_output_unchanged(self):
        from klee_state_discovery import summarize
        names={'s1':'a','s2':'out','o4':'out'}
        def paths_of(stopped):
            with tempfile.TemporaryDirectory() as tmp:
                d=Path(tmp)
                (d/'test000001.kquery').write_text(query('(Eq (ReadLSB w64 0 o4) (ReadLSB w64 0 s2))'))
                if stopped:
                    (d/'test000002.kquery').write_text(query('(Eq false (Eq 0 (ReadLSB w64 0 s1)))'))
                    (d/'test000002.early').write_text('Execution halting.\n')
                paths=analyze_paths(d,names,None,KLEAVER)
            for p in paths:p['model_fault']=0
            return paths
        # The finished path leaves out unchanged; a stopped path may still write it.
        self.assertEqual(summarize(paths_of(False),names,[])['unchanged_outputs'],['out'])
        self.assertEqual(summarize(paths_of(True),names,[])['unchanged_outputs'],[])

    def test_split_inputs_are_listed_apart_from_required(self):
        from klee_state_discovery import summarize
        names={'s1':'argument:0','s2':'b','o4':'out'}
        paths=[dict(test='t1',errors=[],fault='never',model_fault=0,control=['argument:0','b'],data={'out':['b']},unchanged=[],imprecise_reads=0)]
        report=summarize(paths,names,[],['argument:0'])
        self.assertEqual(report['required'],['b']);self.assertEqual(report['split_inputs'],['argument:0']);self.assertEqual(report['control_dependencies'],['b'])

    def test_ktest_with_many_objects(self):
        def blob(b):return struct.pack('>I',len(b))+b
        data=b'KTEST'+struct.pack('>I',3)+struct.pack('>I',0)+struct.pack('>II',0,0)+struct.pack('>I',300)
        data+=b''.join(blob(('s%d'%i).encode())+blob(bytes([i%256])) for i in range(300))
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'t.ktest';path.write_bytes(data);values=ktest_values(path)
        self.assertEqual(len(values),300);self.assertEqual(values['s299'],bytes([299%256]))

HEADER_C="""struct item {int size;unsigned char bytes[4];};
struct osrec_kernel_context {
    int before;
    struct item item;
    int after;
};
static inline void osrec_context_restore(struct osrec_kernel_context *ctx)
{
    for(unsigned osrec_i=0;osrec_i<sizeof(*ctx);++osrec_i)((unsigned char *)ctx)[osrec_i]=0;
    ctx->item.size=3;
}
"""

class SeparateMemberTests(unittest.TestCase):
    def test_member_moves_to_its_own_object(self):
        header=separate_members(HEADER_C,['item'])
        self.assertIn('struct item *osrec_separate_item;',header);self.assertIn('#define item osrec_separate_item[0]',header)
        self.assertLess(header.index('ctx->osrec_separate_item=&osrec_separate_item_object;'),header.index('ctx->item.size=3;'))
        with self.assertRaises(ValueError):separate_members(HEADER_C,['missing'])

    @unittest.skipUnless(shutil.which('cc'),'no C compiler')
    def test_accesses_reach_the_separate_object(self):
        import subprocess
        program="""#include <stddef.h>
#include "context.h"
__typeof__(*((struct osrec_kernel_context *)0)->osrec_separate_item) osrec_separate_item_object;
int main(void){
    static struct osrec_kernel_context ctx;osrec_context_restore(&ctx);
    ctx.item.bytes[ctx.item.size]=7;ctx.before=1;ctx.after=2;
    return !(osrec_separate_item_object.size==3 && osrec_separate_item_object.bytes[3]==7 && sizeof(ctx.item)==8 && &ctx.item==&osrec_separate_item_object);
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);(d/'context.h').write_text(separate_members(HEADER_C,['item']));(d/'main.c').write_text(program)
            subprocess.run(['cc','-std=c11','-o',str(d/'main'),str(d/'main.c')],check=True,capture_output=True)
            self.assertEqual(subprocess.run([str(d/'main')]).returncode,0)

class InputDomainTests(unittest.TestCase):
    BINDING={'descriptors':{'pool':'file_pool','class':{'values':{'8192':1,'32768':2}}}}
    STATE={'scalars':{'files.fdtab.max_fds':64},'pool':[{'object_id':1,'f_pos':0,'f_count':3},None]}
    CONTRACTS={'state_ranges':[{'validated_by':'live state field files.fdtab.max_fds','min':0,'max':64,'reason':'r'}],
               'input_domains':[{'field':'file_pool[].f_pos','min':0,'max':(1<<63)-1,'reason':'r'},{'field':'file_pool[].f_count','min':0,'max':1<<32,'reason':'r'}]}

    def test_sources_expand_over_the_pool_and_intersect(self):
        ranges,provenance=input_ranges(self.CONTRACTS,self.BINDING,[('pre',self.STATE)])
        self.assertEqual(ranges['files.fdtab.max_fds'],(0,64))
        self.assertEqual(ranges['file_pool[0].object_id'],(1,2));self.assertEqual(ranges['file_pool[1].object_id'],(1,2))
        self.assertEqual(ranges['file_pool[1].f_pos'],(0,(1<<63)-1))
        self.assertIn('binding class values',{p['source'] for p in provenance})

    def test_graph_invariants_fix_and_bound_descriptor_fields(self):
        binding={'descriptors':{'capacity':64}}
        contracts={'graph_invariants':[dict(field='files.fdtab.open_fds[0]',kind='slot_mask',reason='r'),
            dict(field='files.fdtab.full_fds_bits[0]',kind='full_slot_words',reason='r'),dict(field='files.next_fd',kind='at_most_first_free_slot',reason='r')]}
        state=dict(slots=[1,1,1,0,2]+[0]*59,scalars={'files.fdtab.open_fds[0]':23,'files.fdtab.full_fds_bits[0]':0,'files.next_fd':3})
        found=graph_invariants(contracts,binding,[('pre',state)])
        self.assertEqual(set(found['fixed']),{'files.fdtab.open_fds[0]','files.fdtab.full_fds_bits[0]'});self.assertEqual(found['bounds'],{'files.next_fd':(0,3)})
        stale=dict(state,scalars=dict(state['scalars'],**{'files.fdtab.open_fds[0]':31}))
        with self.assertRaises(ValueError):graph_invariants(contracts,binding,[('pre',state),('post',stale)])
        with self.assertRaises(ValueError):graph_invariants({'graph_invariants':[dict(field='files.next_fd',kind='other',reason='r')]},binding,[('pre',state)])

    def test_observed_states_must_satisfy_every_domain(self):
        import copy
        state=copy.deepcopy(self.STATE);state['pool'][0]['f_pos']=1<<63
        with self.assertRaisesRegex(ValueError,'violates the input domain file_pool\\[0\\].f_pos'):
            input_ranges(self.CONTRACTS,self.BINDING,[('pre',state)])

KLEAVER=default_kleaver(shutil.which('klee'))

@unittest.skipUnless(KLEAVER,'kleaver (KLEE) is not installed')
class SolverTests(unittest.TestCase):
    """Questions answered by STP through kleaver."""
    def analyze(self,*constraints,names,domains=None):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);(d/'test000001.kquery').write_text(query(*constraints))
            return analyze_paths(d,names,domains,KLEAVER)[0]

    def test_outputs_are_unchanged_only_when_proven(self):
        o='(ReadLSB w64 0 o4)';s='(ReadLSB w64 0 s1)'
        names={'s1':'bits','o4':'bits','s2':'count'}
        # Clearing a bit transforms the field: its own input is a data dependency.
        p=self.analyze('(Eq %s (And w64 %s 18446744073709551607))'%(o,s),names=names)
        self.assertEqual(p['unchanged'],[]);self.assertEqual(p['data'],{'bits':['bits']})
        # Clearing a bit the path condition proves clear leaves it unchanged.
        p=self.analyze('(Eq 0 (And w64 %s 8))'%s,'(Eq %s (And w64 %s 18446744073709551607))'%(o,s),names=names)
        self.assertEqual(p['unchanged'],['bits']);self.assertEqual(p['data'],{})
        # max(x, 1) is the identity on the declared domain x >= 1.
        shaped='(Add w64 N0:%s (Mul w64 (SExt w64 (ZExt w32 (Slt N0 1))) (Sub w64 1 N0)))'%s
        p=self.analyze('(Eq %s %s)'%(o,shaped),names=names,domains={'bits':(1,None,True)})
        self.assertEqual(p['unchanged'],['bits'])
        p=self.analyze('(Eq %s %s)'%(o,shaped),names=names)
        self.assertEqual(p['unchanged'],[])

    def test_conditions_implied_by_the_domain_are_not_dependencies(self):
        s='(ReadLSB w64 0 s1)';shaped='N0:(Add w64 N1:%s (Mul w64 (SExt w64 (ZExt w32 (Slt N1 1))) (Sub w64 1 N1)))'%s
        names={'s1':'count','s2':'other'}
        # max(x, 1) != 0 holds for every x >= 1: no information about x.
        p=self.analyze('(Eq false (Eq 0 %s))'%shaped,names=names,domains={'count':(1,None,True)})
        self.assertEqual(p['control'],[]);self.assertEqual(p['domain_implied_conditions'],1)
        # max(x, 1) + 1 > 0 fails at the type maximum: x stays a dependency.
        p=self.analyze('(Slt 0 (Add w64 1 %s))'%shaped,names=names,domains={'count':(1,None,True)})
        self.assertEqual(p['control'],['count'])
        # A path condition is never implied by the path itself.
        p=self.analyze('(Ult (ReadLSB w64 0 s2) 9)',names=names,domains={'count':(1,None,True)})
        self.assertEqual(p['control'],['other'])

    def test_index_confinement_depends_on_access_width(self):
        # Field a is bytes 0..7 (s1), field b bytes 8..11 (s2). N0 is 0 on the path. A one-byte write
        # at N0 is confined to a's bytes [0, 7]; an eight-byte read from N0 must still not reach b.
        def ktest(objects):
            blob=lambda b:struct.pack('>I',len(b))+b
            return b'KTEST'+struct.pack('>I',3)+struct.pack('>I',0)+struct.pack('>II',0,0)+struct.pack('>I',len(objects))+b''.join(blob(n.encode())+blob(v) for n,v in objects)
        u0='U0:['+', '.join('%d=(Read w8 %d s2)'%(8+i,i) for i in range(4))+', '+', '.join('%d=(Read w8 %d s1)'%(i,i) for i in range(8))+'] @ const_arr1'
        constraints=('(Eq 0 N0:(ZExt w32 (Read w8 0 s3)))','(Eq 5 (Read w8 12 U1:[N0=(Read w8 1 s3)] @ %s))'%u0,'(Eq 7 (ReadLSB w64 N0 U1))')
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);(d/'test000001.kquery').write_text(query(*constraints))
            (d/'test000001.ktest').write_bytes(ktest([('s1',bytes([7,0,0,0,0,0,0,0])),('s2',bytes(8)),('s3',bytes([0,7,0,0]))]))
            p=analyze_paths(d,{'s1':'a','s2':'b','s3':'c'},None,KLEAVER)[0]
        self.assertEqual(p['control'],['a','c']);self.assertEqual(p['imprecise_reads'],0)

    def test_pruned_read_equals_the_original_on_the_path(self):
        # A symbolic index confined by the path to the s1 field: the pruned read drops s2's
        # stores and still equals the original read under the path constraints.
        updates='['+', '.join('%d=(Read w8 %d s2)'%(8+i,i) for i in range(8))+', '+', '.join('%d=(Read w8 %d s1)'%(i,i) for i in range(8))+'] @ const_arr1'
        index='(ZExt w32 (Read w8 0 s3))'
        text=query('(Ult %s 8)'%index,'(Eq 0 (Read w8 %s %s))'%(index,updates))
        q=KQuery(text);cs=q.constraints();read=cs[1][2][1]
        self.assertEqual(read[0],'read')
        pruned=Printer(q,standalone=True,prune=lambda r:hit_entries(r,lambda _:set(range(8,16))))(read)
        self.assertNotIn('s2',pruned)
        stp=Stp(text,KLEAVER)
        self.assertEqual(stp.valid(['(Eq %s %s)'%(Printer(q,standalone=True)(read),pruned)]),[True])
        # Without the path the two differ.
        self.assertEqual(stp.valid(['(Eq %s %s)'%(Printer(q,standalone=True)(read),pruned)],path=False),[False])

    def test_model_fault_is_decided_per_path(self):
        fault='(ReadLSB w32 0 o5)';names={'s3':'x','o5':'model_fault'}
        header=HEADER+'array o5[4] : w32 -> w8 = symbolic\n'
        def decide(*constraints):
            with tempfile.TemporaryDirectory() as tmp:
                d=Path(tmp);(d/'test000001.kquery').write_text(header+'(query ['+'\n'.join(constraints)+'] false)\n')
                return analyze_paths(d,names,None,KLEAVER)[0]['fault']
        x='(ReadLSB w32 0 s3)'
        self.assertEqual(decide('(Ult %s 4)'%x,'(Eq %s (ZExt w32 (Ult 9 %s)))'%(fault,x)),'never')
        self.assertEqual(decide('(Ult 9 %s)'%x,'(Eq %s (ZExt w32 (Ult 9 %s)))'%(fault,x)),'always')
        self.assertEqual(decide('(Eq %s (ZExt w32 (Ult 9 %s)))'%(fault,x)),'undecided')

    def test_sibling_paths_with_equal_outputs_merge(self):
        from klee_state_discovery import summarize
        names={'s1':'y','s3':'x','o4':'out','o5':'model_fault'};header=HEADER+'array o5[4] : w32 -> w8 = symbolic\n'
        def ktest(values):
            blob=lambda b:struct.pack('>I',len(b))+b
            return b'KTEST'+struct.pack('>IIIII',3,0,0,0,len(values))+b''.join(blob(k.encode())+blob(v) for k,v in values.items())
        x,y='(ReadLSB w32 0 s3)','(ReadLSB w64 0 s1)'
        def run(second):
            # x < 9 is the model domain; inside it y < 5 picks between two paths returning 0 and SECOND.
            cases=[(['(Ult %s 9)'%x,'(Ult %s 5)'%y,'(Eq 0 (ReadLSB w64 0 o4))','(Eq 0 (ReadLSB w32 0 o5))'],dict(s3=1,s1=1,o4=0,o5=0)),
                   (['(Ult %s 9)'%x,'(Eq false (Ult %s 5))'%y,'(Eq %d (ReadLSB w64 0 o4))'%second,'(Eq 0 (ReadLSB w32 0 o5))'],dict(s3=1,s1=7,o4=second,o5=0)),
                   (['(Eq false (Ult %s 9))'%x,'(Eq 1 (ReadLSB w32 0 o5))'],dict(s3=12,s1=0,o4=0,o5=1))]
            with tempfile.TemporaryDirectory() as tmp:
                d=Path(tmp)
                for i,(constraints,values) in enumerate(cases,1):
                    (d/('test%06d.kquery'%i)).write_text(header+'(query ['+'\n'.join(constraints)+'] false)\n')
                    sizes={'s1':8,'s3':4,'o4':8,'o5':4}
                    (d/('test%06d.ktest'%i)).write_bytes(ktest({k:v.to_bytes(sizes[k],'little') for k,v in values.items()}))
                paths=analyze_paths(d,names,None,KLEAVER)
            for p in paths:p['model_fault']=int(p['fault']=='always')
            return paths
        paths=run(0);self.assertEqual(paths[0]['outputs'],{'out':'0000000000000000'})
        report=summarize(paths,names,[])
        self.assertEqual(report['required'],['x']);self.assertEqual(report['control_without_effect'],['y'])
        # Different results keep the condition; so does incomplete exploration.
        self.assertEqual(summarize(run(1),names,[])['required'],['x','y'])
        self.assertEqual(summarize(paths,names,[],complete=False)['required'],['x','y'])

    def test_symbolic_indices_reach_only_feasible_runs(self):
        # Bytes 0..7 come from s1 and 8..15 from s2; the index is bounded to 8..15 by the path.
        updates='U0:['+', '.join('%d=(Read w8 %d s2)'%(8+i,i) for i in range(8))+', '+', '.join('%d=(Read w8 %d s1)'%(i,i) for i in range(8))+'] @ const_arr1'
        index='N0:(ZExt w32 (Read w8 0 s3))'
        p=self.analyze('(Ule 8 %s)'%index,'(Ult N0 16)','(Eq 0 (Read w8 N0 %s))'%updates,names={'s1':'a','s2':'b','s3':'c'})
        self.assertEqual(p['control'],['b','c']);self.assertEqual(p['imprecise_reads'],0)

if __name__=='__main__':unittest.main()
