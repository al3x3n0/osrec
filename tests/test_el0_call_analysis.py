"""Proof boundaries for caller-specific native returns."""
from pathlib import Path
import sys
import unittest
import io
import shutil
import subprocess
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from el0_call_analysis import analyze_calls,leaf_body,writes_lr,frame_body,analyze_call_trees,write_call_trees,partial_leaf_body,branch_target,PARTIAL_COPY_LIMIT
from el0_flat_lower import decode,Op,OBSERVE,SYSTEM,INDIRECT
from el0_hardware import immediate

RET=0xd65f03c0


class LeafCalls(unittest.TestCase):
    def test_closed_conditional_cfg_multiple_returns_and_loop(self):
        words={0x100:0xb4000040,0x104:RET,0x108:0x91000400,0x10c:0x35ffffe0,0x110:RET}
        self.assertEqual(leaf_body(0x100,0x114,words,{}),tuple(words))
        self.assertIsNone(leaf_body(0x100,0x110,words,{}))
        self.assertIsNone(leaf_body(0x100,0x114,words,{},limit=4))

    def test_calls_escaping_edges_unknown_returns_and_falloff_are_rejected(self):
        for word in (0x94000001,0x14000020,0x54000100,0xd61f0000,0xd63f0100,0xd65f0000,
                     0xd4000001,0xd421e000,0xd503233f):
            with self.subTest(word=hex(word)):
                self.assertIsNone(leaf_body(0x100,0x108,{0x100:word,0x104:RET},{}))
        self.assertIsNone(leaf_body(0x100,0x104,{0x100:0xd503201f},{}))

    def test_lr_writes_rejected_but_storing_lr_is_allowed(self):
        for word in (0xaa0003fe,0x5280001e,0xf940001e,0xa9407800,0xf84087c0,0x910003fe):
            with self.subTest(word=hex(word)):
                self.assertTrue(writes_lr(word))
                self.assertIsNone(leaf_body(0x100,0x108,{0x100:word,0x104:RET},{}))
        self.assertFalse(writes_lr(0xf900001e)) # STR x30,[x0]
        self.assertEqual(leaf_body(0x100,0x108,{0x100:0xf900001e,0x104:RET},{}),(0x100,0x104))

    def test_full_inline_shadow_operations_allowed_gateways_groups_rejected(self):
        word=0xd5034fdf # DAIFSet, fully inline shadow update
        words={0x100:word,0x104:RET}
        self.assertEqual(leaf_body(0x100,0x108,words,{0x100:(decode(word),0)}),(0x100,0x104))
        self.assertIsNone(leaf_body(0x100,0x108,words,{0x100:(decode(word),0x40000000)}))
        self.assertIsNone(leaf_body(0x100,0x108,words,{0x100:(decode(0xf9400000),0)}))
        self.assertIsNone(leaf_body(0x100,0x108,words,{},groups={0x100}))
        self.assertIsNone(leaf_body(0x100,0x104,{0x100:RET},{0x100:(decode(RET),0x20000000)}))

    def test_only_direct_entry_calls_specialized_and_size_is_bounded(self):
        words={0:0x94000040,4:0xd503201f,8:0x9400003e,12:0xd503201f,
               16:0x9400003b,20:0xd503201f,24:0xd63f0100,
               0x100:0x91000400,0x104:RET}
        calls=analyze_calls(words,{},(),[(0x100,0x108)])
        self.assertEqual(calls,{0:(0x100,0x104),8:(0x100,0x104)})
        self.assertEqual(analyze_calls(words,{},(),[(0x100,0x108)],limit=2),{0:(0x100,0x104)})
        self.assertEqual(words[0x104],RET) # Original indirect entry stays intact.


class FrameCalls(unittest.TestCase):
    def fixture(self,child=(0x91000400,RET)):
        words={0:0x94000040,4:0xd503201f,
               0x100:0xa9bf7bfd,0x104:0x9400003f,0x108:0xa8c17bfd,0x10c:RET}
        words.update({0x200+4*i:w for i,w in enumerate(child)})
        return words,[(0x100,0x110),(0x200,0x200+4*len(child))]

    def test_nested_pair_save_restore_and_private_callee_frame(self):
        for child in ((0x91000400,RET),(0xa9bf7bfd,0xd503201f,0xa8c17bfd,RET)):
            words,extents=self.fixture(child)
            plan=analyze_call_trees(words,{},(),extents)
            self.assertIn(0,plan.roots);self.assertEqual(plan.summaries[0x100].depth,1)
            nested=plan.children[0,0x104]
            self.assertEqual(plan.returns[nested],(0,0x108))
            self.assertEqual(plan.returns[0],(None,4))
            self.assertEqual(plan.nodes[nested],plan.summaries[0x200].body)

    def test_unknown_and_overlapping_callee_stores_invalidate_saved_lr(self):
        for store in (0xf9000001,0xf90007ff,0x390023e0):
            with self.subTest(store=hex(store)):
                words,extents=self.fixture((store,RET))
                plan=analyze_call_trees(words,{},(),extents)
                self.assertNotIn(0x100,plan.summaries);self.assertNotIn(0,plan.roots)
                self.assertIn(0x104,plan.roots) # Leaf call remains independently valid.

    def test_no_abi_register_preservation_assumption(self):
        for clobber,expected in ((0xd503201f,True),(0x91000413,False)):
            words={0:0x94000040,4:0xd503201f,0x100:0xaa1e03f3,0x104:0x9400003f,
                   0x108:0xaa1303fe,0x10c:RET,0x200:clobber,0x204:RET}
            plan=analyze_call_trees(words,{},(),[(0x100,0x110),(0x200,0x208)])
            self.assertEqual(0 in plan.roots,expected)
        words,extents=self.fixture((0xa9bf53f3,0x91000413,0xa8c153f3,RET))
        plan=analyze_call_trees(words,{},(),extents)
        self.assertEqual(plan.summaries[0x200].registers[19],('in',19))

    def test_cfg_join_cannot_keep_a_stack_value_invalidated_on_one_path(self):
        words={0x100:0xd10043ff,0x104:0xf90007fe,0x108:0xb4000060,
               0x10c:0x390023e0,0x110:0x14000002,0x114:0xd503201f,
               0x118:0xf94007fe,0x11c:0x910043ff,0x120:RET}
        self.assertIsNone(frame_body(0x100,0x124,words,{},(),{}))

    def test_partial_local_stores_and_unknown_sp_adjustment_reject(self):
        for middle in (0x390023e0,0x92401fff): # STRB [sp,#8], AND sp,xzr,#0xff
            words={0x100:0xd10043ff,0x104:0xf90007fe,0x108:middle,
                   0x10c:0xf94007fe,0x110:0x910043ff,0x114:RET}
            self.assertIsNone(frame_body(0x100,0x118,words,{},(),{}))

    def test_generated_shadow_scratch_stores_are_included_in_alias_effects(self):
        system=0xd5034fdf
        child=frame_body(0x200,0x208,{0x200:system,0x204:RET},
                         {0x200:(decode(system),0)},(),{})
        self.assertIn((-16,16),child.stores)
        words={0x100:0xf81f83fe,0x104:0x9400003f,0x108:0xf85f83fe,0x10c:RET}
        self.assertIsNone(frame_body(0x100,0x110,words,{},(),{0x200:child}))
        words={0x100:0xf81f83fe,0x104:system,0x108:0xf85f83fe,0x10c:RET}
        self.assertIsNone(frame_body(0x100,0x110,words,{0x104:(decode(system),0)},(),{}))

    def test_recursive_calls_unbalanced_frames_depth_and_copy_budget(self):
        words,extents=self.fixture()
        self.assertNotIn(0,analyze_call_trees(words,{},(),extents,max_depth=0).roots)
        self.assertNotIn(0,analyze_call_trees(words,{},(),extents,limit=2).roots)
        self.assertIsNone(frame_body(0x100,0x108,{0x100:0xd10043ff,0x104:RET},{},(),{}))
        recursive={0x100:0xa9bf7bfd,0x104:0x97ffffff,0x108:0xa8c17bfd,0x10c:RET}
        self.assertFalse(analyze_call_trees(recursive,{},(),[(0x100,0x110)]).summaries)


class PartialCalls(unittest.TestCase):
    def fixture(self):
        # CBZ selects a slow path whose first instruction is a nested BL.
        return {0:0x94000040,4:0xd503201f,0x100:0xb4000060,
                0x104:0x91000400,0x108:RET,0x10c:0x9400003d,0x110:RET}

    def test_fast_return_stays_private_slow_call_is_not_copied(self):
        words=self.fixture();proof=partial_leaf_body(0x100,0x114,words,{})
        self.assertEqual(proof.body,(0x100,0x104,0x108))
        self.assertEqual(proof.exits,(0x10c,))
        plan=analyze_call_trees(words,{},(),[(0x100,0x114)])
        self.assertEqual(plan.roots[0],proof.body)
        self.assertNotIn(0x100,plan.summaries) # Cannot summarize an unknown callee.

    def test_lr_changes_gateways_groups_and_metadata_rejoin_original_code(self):
        for word in (0xaa0003fe,0xf94007fe,0xa8c17bfd,0x9400003d,
                     0xd4000001,0xd61f0100,0xd63f0100,0xd65f0000):
            words=self.fixture();words[0x10c]=word
            with self.subTest(word=hex(word)):
                proof=partial_leaf_body(0x100,0x114,words,{})
                self.assertEqual(proof.exits,(0x10c,))
                self.assertNotIn(0x10c,proof.body)
        words=self.fixture();words[0x10c]=0xd50343df
        for desc,groups in (({0x10c:(decode(words[0x10c]),1)},()),({},(0x10c,)),
                            ({0x10c:(Op(OBSERVE,words[0x10c]),0)},())):
            proof=partial_leaf_body(0x100,0x114,words,desc,groups)
            self.assertEqual(proof.exits,(0x10c,))
        for metadata in (1,0x20000000):
            self.assertIsNone(partial_leaf_body(0x100,0x104,{0x100:RET},{0x100:(decode(RET),metadata)}))

    def test_loops_external_edges_budget_and_fallthrough_exits(self):
        words={0x100:0xb4000060,0x104:0x91000400,0x108:RET,
               0x10c:0x91000421,0x110:0x17fffffc}
        proof=partial_leaf_body(0x100,0x114,words,{},limit=4)
        self.assertEqual(proof.body,(0x100,0x104,0x108));self.assertEqual(proof.exits,(0x10c,))
        self.assertLessEqual(len(proof.body),4)
        words[0x10c]=0x1400003d # Tail edge to an original function.
        self.assertEqual(partial_leaf_body(0x100,0x114,words,{}).exits,(0x10c,))
        self.assertIsNone(partial_leaf_body(0x100,0x114,words,{},limit=1))
        self.assertIsNone(partial_leaf_body(0x10c,0x110,words,{}))

    def test_slow_only_components_are_pruned_but_loops_with_a_return_edge_stay(self):
        words={0x100:0xb4000060,0x104:0x91000400,0x108:RET,
               0x10c:0x91000421,0x110:0x17ffffff}
        proof=partial_leaf_body(0x100,0x114,words,{})
        self.assertEqual(proof.body,(0x100,0x104,0x108));self.assertEqual(proof.exits,(0x10c,))
        words[0x110]=0x17fffffc # Returning to the entry can still reach RET.
        self.assertEqual(partial_leaf_body(0x100,0x114,words,{}).body,tuple(words))

    def test_larger_search_finds_small_return_paths_without_relaxing_copy_or_lr_limits(self):
        words={0:0x94000040,4:0xd503201f,0x100:0xb4000800,0x184:RET,0x280:0x94000000}
        words.update({pc:0x91000400 for pc in range(0x104,0x184,4)})
        words.update({pc:0x91000421 for pc in range(0x200,0x280,4)})
        self.assertIsNone(partial_leaf_body(0x100,0x284,words,{}))
        proof=partial_leaf_body(0x100,0x284,words,{},scan_limit=256)
        self.assertEqual(len(proof.body),34);self.assertIn(0x184,proof.body)
        self.assertEqual(proof.exits,(0x200,))
        self.assertIn(0,analyze_call_trees(words,{},(),[(0x100,0x284)]).roots)
        words[0x140]=0xaa0003fe # An LR write still ends the proof.
        self.assertIsNone(partial_leaf_body(0x100,0x284,words,{},scan_limit=256))

    def test_expanded_return_paths_over_the_copy_cap_keep_the_original_prefix(self):
        words=self.fixture();words[0x10c]=0x91000421
        words.update({pc:0x91000421 for pc in range(0x110,0x300,4)})
        words[0x300]=RET
        bounded=partial_leaf_body(0x100,0x304,words,{})
        expanded=partial_leaf_body(0x100,0x304,words,{},scan_limit=256)
        self.assertEqual(expanded,bounded)
        self.assertLessEqual(len(expanded.body),64)

    def test_production_copy_cap_and_total_budget_are_independently_enforced(self):
        words=self.fixture();words[0x10c]=0x91000421
        words.update({pc:0x91000421 for pc in range(0x110,0x2fc,4)})
        words[0x2fc]=RET
        plan=analyze_call_trees(words,{},(),[(0x100,0x300)])
        self.assertEqual(len(plan.nodes[0]),PARTIAL_COPY_LIMIT)
        self.assertIn(0x2fc,plan.nodes[0])
        self.assertNotIn(0,analyze_call_trees(words,{},(),[(0x100,0x300)],limit=PARTIAL_COPY_LIMIT-1).roots)

    def test_partial_callee_cannot_prove_a_parent_and_old_copies_keep_budget_priority(self):
        words=self.fixture();words.update({8:0x9400007e,12:0xd503201f,0x200:RET})
        plan=analyze_call_trees(words,{},(),[(0x100,0x114),(0x200,0x204)],limit=1)
        self.assertEqual(plan.roots,{8:(0x200,)})
        self.assertNotIn(0x100,plan.summaries)

    def test_smaller_partial_copies_cover_more_sites_without_changing_proofs_or_budget(self):
        words={0:0x94000040,4:0xd503201f,8:0x9400007e,12:0xd503201f,
               16:0x940000bc,20:0xd503201f,
               0x100:0xb40000a0,0x104:0x91000400,0x108:0x91000400,0x10c:0x91000400,0x110:RET,
               0x114:0x94000000,0x118:RET,
               0x200:0xb4000060,0x204:0x91000400,0x208:RET,0x20c:0x94000000,0x210:RET,
               0x300:0xb4000060,0x304:0x91000400,0x308:RET,0x30c:0x94000000,0x310:RET}
        extents=[(0x100,0x11c),(0x200,0x214),(0x300,0x314)]
        plan=analyze_call_trees(words,{},(),extents,limit=6)
        self.assertEqual(set(plan.roots),{8,16})
        self.assertEqual(sum(map(len,plan.nodes.values())),6)
        self.assertEqual(plan.roots[8],partial_leaf_body(0x200,0x214,words,{}).body)
        self.assertEqual(plan.partial[0x200].exits,(0x20c,))
        self.assertFalse(plan.summaries)
        again=analyze_call_trees(dict(reversed(list(words.items()))),{},(),list(reversed(extents)),limit=6)
        self.assertEqual(plan.roots,again.roots)

    def test_observation_hook_keeps_its_original_call_eligible_only_without_metadata(self):
        words={0:0x94000040,4:0xd503201f,0x100:RET}
        for metadata,expected in ((0,True),(1,False)):
            desc={0:(Op(OBSERVE,words[0]),metadata)}
            self.assertEqual(0 in analyze_call_trees(words,desc,(),[(0x100,0x104)]).roots,expected)
        for kind in (SYSTEM,INDIRECT):
            self.assertFalse(analyze_call_trees(words,{0:(Op(kind,words[0]),0)},(),[(0x100,0x104)]).roots)


LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
QEMU=shutil.which('qemu-system-aarch64')


@unittest.skipUnless(QEMU and (LLVM/'clang').exists(),'cross clang and QEMU required')
class ExecutedCallTree(unittest.TestCase):
    def test_partial_fast_return_call_fallback_tail_exit_and_budget_fallthrough(self):
        for mode in ('call','tail','fallthrough','common_frame','wide'):
            words={0:0x94000040,4:0xd503201f,0x100:0xb4000080,
                   0x104:0x91000400,0x108:RET}
            if mode=='call':
                words.update({0x110:0xa9bf7bfd,0x114:0x9400003b,0x118:0xa8c17bfd,0x11c:RET})
                original='''
.Lp110:
    stp x29,x30,[sp,#-16]!
.Lp114:
    mov x30,#0x118
    b .Lp200
.Lp200:
    add x0,x0,#9
    b .Lp118
.Lp118:
    ldp x29,x30,[sp],#16
    b .Lp4
'''
            elif mode=='tail':
                words[0x110]=0x1400003c
                original='.Lp110:\n    b .Lp200\n.Lp200:\n    add x0,x0,#9\n    b .Lp4\n'
            elif mode=='common_frame':
                words={0:0x94000040,4:0xd503201f,0x100:0xa9bf7bfd,0x104:0xb4000080,
                       0x108:0x91000400,0x10c:0x910043ff,0x110:RET,
                       0x114:0x9400003b,0x118:0xa8c17bfd,0x11c:RET}
                original='''
.Lp114:
    mov x30,#0x118
    b .Lp200
.Lp200:
    add x0,x0,#9
    ldp x29,x30,[sp],#16
    b .Lp4
'''
            elif mode=='wide':
                words.update({pc:0x91000400 for pc in range(0x110,0x250,4)})
                words[0x250]=RET;original=''
            else:
                words.update({0x110:0x91002400,0x114:0x17fffffb})
                original='''
.Lp114:
    b .Lp100
.Lp100:
    cbz x0,.Lp110
    add x0,x0,#1
    b .Lp4
.Lp110:
    add x0,x0,#9
    b .Lp114
'''
            plan=analyze_call_trees(words,{},(),[(0x100,max(words)+4)])
            if mode=='wide':self.assertGreater(len(plan.nodes[0]),64)
            if mode=='fallthrough':
                # Exercise a prefix that stops because of the copy budget,
                # rather than because the next instruction is unsupported.
                proof=partial_leaf_body(0x100,0x120,words,{},limit=4)
                plan.roots[0]=plan.nodes[0]=proof.body
                plan.partial[0x100]=proof
            self.assertIn(0x100,plan.partial)
            def control(pc,w,to,specialize):
                if w&0xfc000000==0x14000000:return '    b '+to(branch_target(pc,w))+'\n'
                if w&0x7e000000==0x34000000:
                    inv=(w^(1<<24))&~(0x7ffff<<5)
                    return '    .inst 0x%x\n    b %s\n'%(inv|(2<<5),to(branch_target(pc,w)))
                return '    .inst 0x%x\n'%w
            generated=io.StringIO()
            write_call_trees(generated,plan,words,{},lambda pc:'.Lp%x'%pc,
                             lambda r,v:''.join('    '+line+'\n' for line in immediate(r,v)),control)
            cases=[]
            for flags in range(16):
                for value in (0,1,0xffffffffffffffff):
                    number=len(cases)//7
                    expected=(value+1)&((1<<64)-1) if value else 10 if mode=='fallthrough' else 80 if mode=='wide' else 9
                    cases+=['mov x30,#4','mov x19,#0x%x'%(flags<<28),
                            'msr nzcv,x19',
                            '\n'.join(immediate(0,value)),
                            '\n'.join(immediate(21,expected)),
                            'adrp x20,.Lafter%d\nadd x20,x20,:lo12:.Lafter%d'%(number,number),
                            'b .Lclone0_p100\n.Lafter%d:'%number]
            source=''' .text
.global _start
_start:
    adrp x1,stack_end
    add x1,x1,:lo12:stack_end
    mov sp,x1
    mov x29,#0x9abc
'''+ '\n'.join(cases)+'''
    mov x2,#0
    b finish
.Lp4:
    mrs x1,nzcv
    cmp x1,x19
    b.ne failed
    cmp x0,x21
    b.ne failed
    cmp x30,#4
    b.ne failed
    mov x1,#0x9abc
    cmp x29,x1
    b.ne failed
    adrp x1,stack_end
    add x1,x1,:lo12:stack_end
    mov x2,sp
    cmp x1,x2
    b.ne failed
    br x20
failed:
    mov x2,#1
finish:
    adrp x1,exit_status
    add x1,x1,:lo12:exit_status
    str x2,[x1,#8]
    mov x0,#0x20
    hlt #0xf000
'''+generated.getvalue()+original+'''
.data
.balign 16
exit_status: .quad 0x20026,1
.bss
.balign 16
.space 4096
stack_end:
'''
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                out=Path(directory);(out/'fixture.S').write_text(source)
                built=subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-nostdlib','-fuse-ld=lld',
                    '-Wl,-Ttext=0x40200000,-e,_start',str(out/'fixture.S'),'-o',str(out/'fixture')],capture_output=True,text=True)
                self.assertEqual(built.returncode,0,built.stderr)
                run=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                    '-nodefaults','-display','none','-monitor','none','-serial','none',
                    '-semihosting-config','enable=on,target=native','-device','loader,file='+str(out/'fixture')+',cpu-num=0'],
                    capture_output=True,text=True,timeout=30)
                self.assertEqual(run.returncode,0,run.stderr)

    def test_nested_copy_returns_to_parent_and_restores_lr_sp_flags_and_saved_registers(self):
        words,extents=FrameCalls().fixture((0xa9bf53f3,0x91000400,0xa8c153f3,RET))
        plan=analyze_call_trees(words,{},(),extents)
        generated=io.StringIO()
        write_call_trees(generated,plan,words,{},lambda pc:'.Lp%x'%pc,
                         lambda r,v:''.join('    '+line+'\n' for line in immediate(r,v)),
                         lambda pc,w,to,specialize:'    .inst 0x%x\n'%w)
        source=''' .text
.global _start
_start:
    adrp x1,stack_end
    add x1,x1,:lo12:stack_end
    mov sp,x1
    mov x0,#7
    mov x19,#0x1234
    mov x20,#0x5678
    mov x29,#0x9abc
    mov x1,#0xa0000000
    msr nzcv,x1
    mov x30,#4
    b .Lclone0_p100
.Lp4:
    mrs x1,nzcv
    mov x2,#0xa0000000
    cmp x1,x2
    b.ne failed
    cmp x0,#8
    b.ne failed
    cmp x30,#4
    b.ne failed
    mov x1,#0x1234
    cmp x19,x1
    b.ne failed
    mov x1,#0x5678
    cmp x20,x1
    b.ne failed
    mov x1,#0x9abc
    cmp x29,x1
    b.ne failed
    adrp x1,stack_end
    add x1,x1,:lo12:stack_end
    mov x2,sp
    cmp x1,x2
    b.ne failed
    mov x2,#0
    b finish
.Lp108:
failed:
    mov x2,#1
finish:
    adrp x1,exit_status
    add x1,x1,:lo12:exit_status
    str x2,[x1,#8]
    mov x0,#0x20
    hlt #0xf000
'''+generated.getvalue()+'''.data
.balign 16
exit_status: .quad 0x20026,1
.bss
.balign 16
.space 4096
stack_end:
'''
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);(out/'fixture.S').write_text(source)
            built=subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-nostdlib','-fuse-ld=lld',
                '-Wl,-Ttext=0x40200000,-e,_start',str(out/'fixture.S'),'-o',str(out/'fixture')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            run=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                '-nodefaults','-display','none','-monitor','none','-serial','none',
                '-semihosting-config','enable=on,target=native','-device','loader,file='+str(out/'fixture')+',cpu-num=0'],
                capture_output=True,text=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)


if __name__=='__main__':unittest.main()
