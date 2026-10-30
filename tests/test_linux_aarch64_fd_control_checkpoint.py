"""Descriptor flags and minimum-fd aliases survive self-contained QEMU resumes."""
import gzip
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from capture_linux_aarch64 import reviewed_adapter,digest
from generate_linux_aarch64_application import generate
from prepare_linux_aarch64_port import build_bundle
from run_linux_aarch64_checkpoint_pipeline import run,verify_pipeline
from export_syscall_slices import export
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-fd-control-native'

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxFdControlTests(unittest.TestCase):
    def test_generated_witness_and_original_helpers_are_bound(self):
        r=reviewed_adapter();p=ROOT/'integrations/linux_aarch64/fd-control';s=generate('fd-control')
        self.assertEqual(s,(p/'application.c').read_text());self.assertEqual(s,(FIXTURE/'sources/application.c').read_text())
        port=json.loads((p/'port-template.json').read_text());port['roots']=[x for x in port['roots'] if x['number']!=25]
        with self.assertRaisesRegex(ValueError,'no reviewed route'):r.application_source('fd-control',port)
        old,_=r.source_identity(ROOT/'integrations/linux_aarch64/file-positioned');new,defs=r.source_identity(p)
        self.assertEqual(len(defs),309)
        for n,h in old['definitions'].items():self.assertEqual(new['definitions'][n],h)
        # The syscall entry and do_fcntl are the original fs/fcntl.c bodies.
        self.assertTrue(defs['fcntl']['syscall']);self.assertIn(b'err = do_fcntl(fd, cmd, arg, f.file);',defs['fcntl']['body'])
        self.assertIn(b'err = f_dupfd(argi, filp, O_CLOEXEC);',defs['do_fcntl']['body']);self.assertIn(b'case F_GETFL:',defs['check_fcntl_cmd']['body'])
        # So are the descriptor lookups and their single-owner fast path.
        self.assertIn(b'atomic_read_acquire(&files->count) == 1',defs['__fget_light']['body']);self.assertIn(b'return __to_fd(__fdget_raw(fd));',defs['fdget_raw']['body'])
        self.assertIn(b'mask & (unsigned long)needs_masking',defs['files_lookup_fd_raw']['body'])
        # The read/write/truncate path is original down to the page cache; operation-table calls are
        # rewritten to reviewed dispatch models and nothing else in the bodies changes.
        self.assertIn(b'ret = osrec_f_op_read_iter(filp->f_op, &kiocb, &iter);',defs['new_sync_read']['body'])
        self.assertEqual(defs['new_sync_read']['rewritten_calls'],['filp->f_op->read_iter(&kiocb, &iter)'])
        self.assertIn(b'error = shmem_get_folio(inode, index, &folio, SGP_READ);',defs['shmem_file_read_iter']['body'])
        self.assertIn(b'folio = filemap_get_entry(inode->i_mapping, index);',defs['shmem_get_folio_gfp']['body'])
        self.assertIn(b'status = osrec_a_ops_write_begin(a_ops, file, mapping, pos, bytes,',defs['generic_perform_write']['body'])
        self.assertIn(b'shmem_undo_range(inode, lstart, lend, false);',defs['shmem_truncate_range']['body'])
        self.assertIn(b'if (!(ia_valid & ATTR_DELEG)) {',defs['notify_change']['body'])
        self.assertIn(b'if (!relatime_need_update(mnt, inode, now))',defs['atime_needs_update']['body'])
        self.assertIn(b'alloc_fd(from, nofile, flags)',defs['f_dupfd']['body'])
        # The arm64 system call entry: the EL0 synchronous handler, el0_svc and the table call.
        self.assertIn(b'case ESR_ELx_EC_SVC64:',defs['el0t_64_sync_handler']['body'])
        self.assertIn(b'el0_svc_common(regs, regs->regs[8], __NR_syscalls, sys_call_table);',defs['do_el0_svc']['body'])
        self.assertEqual(defs['__invoke_syscall']['rewritten_calls'],['syscall_fn(regs)'])
        self.assertIn(b'set_close_on_exec(fd, fdt)',defs['set_close_on_exec']['body'])
        self.assertIn(b'close_on_exec(fd, current->files)',defs['get_close_on_exec']['body'])
        # Identifier mapping, the close flush, descriptor-table bit search and the LSM hook bodies.
        self.assertIn(b'return map_id_up(&targ->uid_map, __kuid_val(kuid));',defs['from_kuid']['body'])
        self.assertIn(b'locks_remove_posix(filp, id);',defs['filp_flush']['body'])
        self.assertEqual(defs['filp_flush']['rewritten_calls'],['filp->f_op->flush(filp, id)'])
        self.assertIn(b'FIND_NEXT_BIT(~addr[idx], /* nop */, nbits, start)',defs['_find_next_zero_bit']['body'])
        self.assertIn(b'return call_int_hook(file_permission, file, mask);',defs['security_file_permission']['body'])
        # User copies run the original iterator chain down to raw_copy_to_user; the
        # always-inline step is a named constant called directly.
        self.assertIn(b'len = raw_copy_to_user(iter_to, from, len);',defs['copy_to_user_iter']['body'])
        self.assertEqual(defs['_copy_to_iter']['rewritten_calls'],['copy_to_user_iter, memcpy_to_iter'])
        self.assertIn(b'copy_to_user_iter(base + iter->iov_offset, 0, len, priv, priv2)',defs['iterate_ubuf']['body'])
        prior=[(n,c,d) for n,c,d in r.fd_control_plan() if n in {n for n,_,_ in r.file_positioned_plan()}]
        self.assertEqual(prior,r.file_positioned_plan())

    def test_descriptor_local_flags_and_minimum_aliases_restore(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-fd-control-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,m=r.validate_capture(native);_,states=r.projection(c)
            names={n:i for i,(n,_,_) in enumerate(r.fd_control_plan())}
            row=lambda n:c['calls'][names[n]]
            after=lambda n:states[names[n]+1]
            self.assertTrue(m['native_linux_boot']);self.assertEqual(len(c['calls']),233)
            old_names={n for n,_,_ in r.file_positioned_plan()}
            retained=[row for (n,_,_),row in zip(r.fd_control_plan(),c['calls']) if n in old_names]
            self.assertEqual(retained,json.loads((ROOT/'tests/fixtures/linux-aarch64-file-positioned-native/capture.json').read_text())['calls'])
            expected={'get_seed_cloexec':1,'get_regular_status':0x20002,'get_console_status':2,'query_cleared_seed':0,
                      'query_ignored_flag_bits':0,'query_set_seed':1,'duplicate_min_six':6,'duplicate_cloexec_min_four':4,
                      'query_plain_alias_flag':0,'query_cloexec_alias_flag':1,'query_original_independent_flag':1,
                      'query_cleared_other_alias':0,'query_shared_regular_status':0x20002,'fcntl_alias_reads_shared_file':4,
                      'fcntl_alias_offset_seen_original':4,'duplicate_min_five':5,'full_minimum_allocation':7,
                      'duplicate_table_full':-24,'duplicate_minimum_at_limit':-22,'duplicate_negative_minimum':-22,
                      'bad_fd_before_minimum':-9,'bad_fd_before_unknown_command':-9,'unknown_command_valid_fd':-22,
                      'reuse_minimum_with_cloexec':5,'reuse_minimum_clears_stale_flag':5,'query_reused_minimum_flag':0,
                      'truncated_descriptor_and_command':1,'truncated_minimum':6,'query_truncated_alias_flag':0,
                      'closed_descriptor_flag':-9,'closed_descriptor_setflag':-9,'query_dup_alias_flag':0,
                      'query_alias_after_original_clear':1,'query_original_after_clear':0,'closed_original_fcntl':-9,
                      'duplicate_surviving_cloexec':3,'query_recreated_cloexec':1,'query_surviving_status':0x20002,
                      'fcntl_after_last_reference':-9,'fcntl_bad_fd_before_negative_minimum':-9}
            for n,value in expected.items():self.assertEqual(row(n)['raw_bits'],value&((1<<64)-1),n)
            self.assertEqual(after('duplicate_min_six')['next_fd'],4)
            self.assertEqual(after('set_alias_cloexec')['cloexec'],88)
            self.assertEqual(after('full_minimum_allocation')['counts'],[3,5])
            self.assertEqual(after('full_minimum_allocation')['next_fd'],6)
            self.assertEqual(after('release_truncated_alias')['slots'],[1,1,1,2,0,0,0,0])
            self.assertEqual(after('release_truncated_alias')['cloexec'],8)
            self.assertEqual(after('clear_original_with_alias_set')['cloexec'],16)
            self.assertEqual(after('duplicate_surviving_cloexec')['counts'],[3,5])
            self.assertEqual(after('last_regular_reference')['counts'],[3,0])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(233,32,2544,1520))
            self.assertEqual(len(result['syscalls']),20);self.assertFalse(result['runtime_host_interaction']);self.assertFalse(result['native_source_build_attested'])
            self.assertEqual(result['pause_ordinals'],[24,34,43,153,184,218])
            self.assertEqual([s['cloexec'] for s in result['saved_state']],[0,88,200,16,40,128])
            self.assertEqual([s['file_counts'] for s in result['saved_state']],[[3,1],[3,3],[3,5],[3,2],[3,5],[3,0]])
            for s in result['saved_state']:
                self.assertEqual(s['file_dentries'],[1,2]);self.assertEqual(s['dentry_inodes'],[1,2])
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            self.assertEqual(k['target_observations']['verified_calls'],699);self.assertEqual(k['target_observations']['isolation_checks'],466)
            # Linux's arm64 memset.S runs, on RAM that start_mmu.S maps as Normal memory.
            self.assertTrue(k['target']['mmu_enabled']);self.assertEqual(k['target']['mmu']['mode'],'identity')
            # Every call enters through Linux's arm64 entry.S, assembled from the pinned kernel tree.
            tree=ROOT/'integrations/linux_aarch64/fd-control/upstream/kernel-tree'
            self.assertEqual(k['source_hashes']['linux-entry.S'],digest((tree/'arch/arm64/kernel/entry.S').read_bytes()))
            dispatch=(stage/'pipeline/kernel/sources/slice_dispatch.h').read_text()
            self.assertIn('return (int64_t)osrec_linux_el0_svc(ctx, number, arguments);',dispatch);self.assertIn('osrec_kernel_dispatch_root',dispatch)
            symbols=subprocess.run([LLVM/'llvm-nm','--defined-only',stage/'pipeline/kernel/slices.elf'],capture_output=True,text=True,check=True).stdout
            address=lambda name:{l.split()[2]:l.split()[0] for l in symbols.splitlines() if len(l.split())==3 and l.split()[1] in 'TtWw'}.get(name)
            self.assertEqual(address('memset'),address('__pi_memset'))
            for name in ('vectors','el0t_64_sync','ret_to_user','el0t_64_sync_handler'):self.assertIsNotNone(address(name),name)
            self.assertEqual(k['source_hashes']['linux-memset.S'],digest((ROOT/'integrations/linux_aarch64/fd-control/upstream/kernel-tree/arch/arm64/lib/memset.S').read_bytes()))
            dependencies=k['source_identity']['modeled_dependencies']
            self.assertTrue(any(d.startswith('original fcntl syscall entry, check_fcntl_cmd and do_fcntl') for d in dependencies))
            self.assertTrue(any(d.startswith('original read/write/truncate path: fdget_pos, vfs_read/vfs_write') for d in dependencies))
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_control_model_mutants_fail_before_publication(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('models.c','    if(end1>start1 && start1<64)memset(','    if(0)memset('),
                     # BPF's file_fcntl hook rejecting F_SETFD: security_file_fcntl's list walk returns it.
                     ('model.h','static inline int bpf_lsm_file_fcntl(struct file *file,unsigned int cmd,unsigned long arg){(void)file;(void)cmd;(void)arg;return 0;}','static inline int bpf_lsm_file_fcntl(struct file *file,unsigned int cmd,unsigned long arg){(void)file;(void)arg;return cmd==2 ? -1 : 0;}'),
                     ('models.c','    return !!(p->fdt->close_on_exec[fd/64]&(UINT64_C(1)<<(fd%64)));','    return !(p->fdt->close_on_exec[fd/64]&(UINT64_C(1)<<(fd%64)));')]
            for i,(filename,old,new) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle);p=bundle/filename;s=p.read_text();self.assertEqual(s.count(old),1);p.write_text(s.replace(old,new))
                v=json.loads(port.read_text());v['bundle']['inputs'][filename]=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
            # A breakpoint syndrome instead of SVC64 takes Linux's el0_dbg path, a fault boundary.
            bundle=stage/'port-esr';port=build_bundle(native,bundle);p=bundle/'entry-glue.S';s=p.read_text();old='mov\tx9, #0x56000000';self.assertEqual(s.count(old),1)
            p.write_text(s.replace(old,'mov\tx9, #0xf2000000'));v=json.loads(port.read_text());v['bundle']['inputs']['entry-glue.S']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/'bad-esr'
            with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
            self.assertFalse(out.exists())
            # Without the identity map, memset.S's unaligned stores fault on Device memory.
            bundle=stage/'port-mmu-off';port=build_bundle(native,bundle);v=json.loads(port.read_text());del v['target_mmu'];port.write_text(json.dumps(v));out=stage/'bad-mmu-off'
            with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
            self.assertFalse(out.exists())

    def test_source_abi_and_forged_native_descriptor_flag_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,old,new in [('upstream/fs/file.c',b'if (from >= nofile)',b'if (from > nofile)'),('upstream/mm/shmem.c',b'nr = i_size & ~PAGE_MASK;',b'nr = i_size & PAGE_MASK;'),('upstream/fs/fcntl.c',b'err = f_dupfd(argi, filp, O_CLOEXEC);',b'err = f_dupfd(argi, filp, 0);'),('upstream/include/uapi/asm-generic/unistd.h',b'__NR3264_fcntl 25',b'__NR3264_fcntl 26')]:
                p=native/filename;s=p.read_bytes();self.assertIn(old,s);p.write_bytes(s.replace(old,new,1))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(s)
            p=native/'capture.json';v=json.loads(p.read_text());i=next(i for i,(n,_,_) in enumerate(reviewed_adapter().fd_control_plan()) if n=='set_alias_cloexec')
            v['calls'][i]['fds_after'][3][1]=0;p.write_text(json.dumps(v,indent=2)+'\n')
            log=native/'qemu.log';uart={k:x for k,x in v.items() if k!='format'};log.write_text(re.sub(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}$','OSREC_LINUX_CAPTURE '+json.dumps(uart),log.read_text(),flags=re.M))
            p=native/'capture.manifest.json';v=json.loads(p.read_text());v['capture_sha256']=digest((native/'capture.json').read_bytes());v['qemu_log_sha256']=digest(log.read_bytes());p.write_text(json.dumps(v,indent=2)+'\n')
            with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ'):build_bundle(native,stage/'bad-native')
            self.assertFalse((stage/'bad-native').exists())

if __name__=='__main__':unittest.main()
