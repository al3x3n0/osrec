# Minimal AArch64 Linux syscall slices

This port captures a libc-free application's syscalls under a real ARM64 Linux kernel, then runs the same application through the existing local gateway and returning kernel slices. Each session retains its state between calls. Joint checkpoints carry application CPU/RAM state and a portable kernel state record into fresh images. Replay images contain their code and data and require no host services, root disk, semihosting or running Linux kernel.

The [Linux IRQ workflow](linux-irq-replay.md) extends asynchronous execution with native nanosleep/timer/IRQ trace correlation and hardware-delivered callback replay. The route/profile coverage below describes the returning-slice matrix.

## Supported profiles

There are currently **39 distinct syscall routes across 35 reviewed profiles**. The `file-setrlimit` profile combines all 39 reviewed routes in a 973-call workload; the separate credential profile has 23. Each route retains the bounded argument/state contract described below.

| Area | Routes |
| --- | --- |
| Process/identity queries | `getpid`, `gettid`, `getppid`, `getuid`, `geteuid`, `getgid`, `getegid`, `getresuid`, `getresgid` |
| Creation mask | `umask` |
| Scalar user IDs | `setuid`, `setreuid`, `setresuid`, `setfsuid` |
| Scalar group IDs | `setgid`, `setregid`, `setresgid`, `setfsgid` |
| Supplementary groups | `getgroups`, `setgroups` |
| Capabilities/control | `capget`, `capset`, selected `prctl` capability/securebit options |
| Descriptors | `dup`, `dup3`, `close`, `close_range`, six reviewed `fcntl` commands across the file profiles |
| File data/position | `read`, `write`, `pread64`, `pwrite64`, `lseek`, `ftruncate` |
| File metadata | `fstat`, ordinary-bit `fchmod`, bounded unprivileged and `CAP_CHOWN` ownership changes |
| Resource limits | `getrlimit` for all sixteen resource types; `setrlimit` for STACK, CORE, NOFILE and MEMLOCK |

The `fd-dup` profile starts Linux descriptor operations with original `dup` (23), `dup3` (24) and `close` (57), alongside the baseline ten routes. Its generated 73-call witness checks lowest-free allocation, table-full `EMFILE`, bad descriptors, flag/error precedence, same-descriptor `EINVAL`, fixed-slot replacement, close-on-exec updates, 32-bit argument truncation and alias lifetimes. It retains 28 original definitions, including allocation, lookup, installation, replacement and removal helpers from [Linux v6.10 `fs/file.c`](https://github.com/torvalds/linux/blob/v6.10/fs/file.c) and close bodies from [`fs/open.c`](https://github.com/torvalds/linux/blob/v6.10/fs/open.c). Each definition and source excerpt is hash-pinned.

Native preparation opens readonly `/init` as descriptor 3 with close-on-exec and sets/observes `RLIMIT_NOFILE=(8,8)`. Descriptors 0–2 share the console file; the workload leaves those slots open. Private `fcntl(F_GETFD/F_GETFL)` probes observe descriptors 0–7 after every call. Object identities are inferred from the admitted construction and duplicate/replacement rules; those probes do not attest native open-file-description addresses or reference counts. The kernel's initial console status flags are 2; the ARM64 readonly seed has `O_LARGEFILE=131072`. These construction and observation calls are excluded from replay roots.

Replay persists nullable typed descriptor links to two file objects, balanced file reference counts, `next_fd`, open bits, close-on-exec bits and the full-word bitmap. A fixed 64-slot table preserves Linux's bitmap algorithm, while the checked resource limit admits only descriptors 0–7. Closing a descriptor preserves its stale close-on-exec bit; later allocation clears it. Replacing a slot closes its former file reference, and closing the original seed leaves aliases usable until the last reference is released. The regular object's reference count reaches zero before a later console-only sequence.

The reviewed sequential boundary models lock/RCU and atomic reference operations, fixed-capacity expansion and successful `filp_flush`. The projected `f_mode` contains only the consumed `FMODE_BACKING` bit, zero for both admitted classes; it is not the native file-mode word. Driver flush callbacks, notification/lock consumers, delayed reclamation, concurrent table changes, fork/exec and resize are excluded. File contents, offsets, pathname operations and read/write are the next file-operation work; they are not part of this descriptor profile. The generic analyzer discovers the direct source dependencies and mutable objects, and the explicit policy restores pointer aliases into each fresh context. Replay uses no root disk or host services.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile fd-dup --kernel-image /path/to/arm64/Image \
  --timeout 300 --out build/linux-fd-dup
```


The `file-io` profile adds Linux `read` (63), `write` (64) and `lseek` (62) to the descriptor profile: 118 native calls across sixteen routes. It preserves all twenty-eight descriptor definitions and adds eleven original definitions from [Linux v6.10 `fs/read_write.c`](https://github.com/torvalds/linux/blob/v6.10/fs/read_write.c): the syscall wrappers, `ksys_read`, `ksys_write`, `ksys_lseek`, `file_ppos`, `rw_verify_area`, `unsigned_offsets`, `vfs_setpos` and `generic_file_llseek_size`. The reviewed extractor accepts signed offset/size return types, pointer returns and a return type on its own line. The generated translation unit suppresses Linux's conventional signed-comparison warning only around original bodies; reviewed models retain strict warnings.

Native preparation creates a close-on-exec RW memfd, writes the 16-byte seed `abcdefghijklmnop` and rewinds it before the workload. It requires builtin `MEMFD_CREATE`, `SHMEM` and 4 KiB pages. Private `F_GET_SEALS` probes identify the single memfd class, `F_GETFD/F_GETFL` observe flags, `pread` observes up to 64 file bytes without moving its position, and `lseek(0,SEEK_CUR)` observes its shared offset. The seed's native status flags are `O_RDWR | O_LARGEFILE = 131074`. A protected page immediately after the 32-byte caller buffer produces real partial `EFAULT` behavior. These preparation and observation calls are outside replay roots.

The returning slices use original Linux syscall/helper control flow and a reviewed direct model of the filesystem callbacks. The regular file has 64 bytes of persistent storage and a mutable logical size. Reads and writes update the shared file object's `f_pos`; duplicated descriptors therefore share position and contents. Seek supports `SEEK_SET`, `SEEK_CUR` and `SEEK_END`, including signed negative errors, end-relative positioning, and a position above 32 bits. Writes in this recipe stay within the 64-byte capacity; seek may move beyond it and later reads return EOF. The observed cases include overwrites, extension, zero-filled sparse gaps, partial reads/writes at the guard page, invalid pointers, zero counts, EOF-before-copy behavior, invalid descriptors and truncation of fd/whence arguments. Last-reference closure makes native file observations unavailable; the model retains an inactive snapshot for checkpoint checking.

The callback model excludes filesystem allocation/reclamation, append, independent opens, `SEEK_DATA/SEEK_HOLE`, notifications, rejecting LSM hooks, task I/O-accounting consumers, pathname lookup and console I/O. Modeled `fdget_pos` takes and releases a strong file reference under the sequential contract; it does not reproduce Linux's borrowed-reference optimization or concurrent position locks. Copies are limited to the admitted 32-byte caller object even when other imported ELF segments map the surrounding guard-page bytes. The transfer model applies arm64 `access_ok()` with `TASK_SIZE_MAX = 1 << 48` (`CONFIG_ARM64_VA_BITS=48`); the earlier 47-bit limit was exposed by a [live SVC boundary](svc-boundary-replay.md) whose stack buffer lies above `1 << 47`. File contents and descriptor state are internal to each replay context; the replay image requires no memfd syscall, host filesystem, root disk or running kernel.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile file-io --kernel-image /path/to/arm64/Image \
  --timeout 300 --out build/linux-file-io
```

The `file-positioned` profile adds `pread64` (67), `pwrite64` (68) and `ftruncate` (46) to `file-io`: 171 native calls across nineteen routes. It retains all thirty-nine earlier original definitions and adds seven definitions from [Linux v6.10 `fs/read_write.c`](https://github.com/torvalds/linux/blob/v6.10/fs/read_write.c#L620) and [`fs/open.c`](https://github.com/torvalds/linux/blob/v6.10/fs/open.c#L147): the three syscall wrappers, both positioned-I/O helpers, `do_sys_ftruncate` and `do_ftruncate`. Four application arguments are bound, including full signed 64-bit explicit positions and lengths. The earlier generated witnesses remain byte-for-byte unchanged.

Positioned transfers update file contents through a local offset and leave the shared `f_pos` unchanged. Negative positions are rejected before descriptor lookup; a console descriptor without positioned-I/O mode returns `ESPIPE` even for zero count and an invalid buffer. Native evidence covers bad descriptors/pointers, zero counts, EOF, positions above 32 bits, partial guard-page transfers, aliased reads/writes and subsequent ordinary I/O against the unchanged offset.

Truncation uses the original negative-length/lookup ordering and the original regular-file, write-mode, large-file and append checks. The reviewed model adds typed file-path → dentry → inode links and a superblock write boundary. Projected inode modes contain the type bits consumed by the retained code; inode addresses, complete permission modes and superblock identities are not native memory observations. The admitted regular object has clear append state and ARM64 `O_LARGEFILE`. Successful security and direct `do_truncate` callbacks update the existing 64-byte file store, preserve `f_pos`, clear discarded tail bytes on shrink and expose zeros on re-extension. Superblock write depth is balanced at every call boundary. Negative lengths, closed descriptors and console truncation are verified against native Linux.

The workload truncates through both the original descriptor and duplicated aliases, including after closing the original. It preserves offsets beyond a newly shortened EOF, clears to empty, extends again, fills the maximum 64-byte capacity and verifies that old discarded bytes do not return. The limits remain one RW regular file, eight usable descriptors, a 32-byte caller object and sequential execution. General filesystem allocation, inode notification/privilege-clearing consumers, idmapped mounts, append, `SEEK_DATA/SEEK_HOLE`, independent opens and pathname lookup are excluded. Native capture still uses a real memfd; replay contains its selected state and uses no host services.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile file-positioned --kernel-image /path/to/arm64/Image \
  --timeout 300 --out build/linux-file-positioned
```

The positioned profile and its affected regressions can also run against archived native captures, without another Linux boot:

```sh
ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_(linux_aarch64_file_positioned_checkpoint|linux_aarch64_file_io_checkpoint|context_graph_checkpoint)$' \
  --output-junit qemu-linux-file-positioned-regressions.xml
```

The `fd-control` profile adds syscall 25 (`fcntl`) to `file-positioned`: 233 native calls across twenty routes. It admits `F_DUPFD`, `F_DUPFD_CLOEXEC`, `F_GETFD`, `F_SETFD` and `F_GETFL`, plus an observed unknown-command error. It pins 309 original definitions:

- **Descriptors and `fcntl`.** The [`f_dupfd`, `set_close_on_exec` and `get_close_on_exec` helpers](https://github.com/torvalds/linux/blob/v6.10/fs/file.c#L1132); the syscall entry, `check_fcntl_cmd` and `do_fcntl` ([`fs/fcntl.c`](https://github.com/torvalds/linux/blob/v6.10/fs/fcntl.c#L346)); `fdget`, `fdget_raw`, `fdget_pos`, `fdput`, `fdput_pos` and the `__fget_light` single-owner fast path.
- **Read and write.** `vfs_read`, `vfs_write`, `new_sync_read`, `new_sync_write` and the write checks; `shmem_file_read_iter`, `shmem_file_write_iter`, `shmem_write_begin`, `shmem_write_end` and `shmem_get_folio_gfp`; `generic_perform_write`, `copy_page_to_iter`, `copy_page_from_iter_atomic`, `fault_in_readable`; `folio_mark_accessed`, `folio_mark_dirty` and the arm64 `flush_dcache_folio`.
- **Page cache.** `filemap_get_entry`, `find_lock_entries`, `find_get_entries` and the `lib/xarray.c` walk (`xas_load`, `xas_start`, `xas_find`) with its `include/linux/xarray.h` helpers.
- **Truncation.** `do_truncate`, `notify_change`, `setattr_prepare`, `setattr_copy`, `shmem_setattr`, `shmem_undo_range`, `truncate_inode_folio` and `truncate_inode_partial_folio`. `fs/attr.c` and `mm/truncate.c` are taken from 6.10.14, the running kernel, where they differ from v6.10.
- **System call entry.** `el0t_64_sync_handler`, `el0_svc`, `do_el0_svc`, `el0_svc_common`, `invoke_syscall` and the inline helpers they use (`enter_from_user_mode`, `exit_to_user_mode`, `fp_user_discard`, `syscall_set_return_value`); with the assembly below, every call enters and leaves as Linux's own does.
- **Identifiers, close and descriptor allocation.** `from_kuid_munged`, `from_kgid_munged`, `from_kuid`, `from_kgid` and `map_id_up` over the bound namespace maps; `filp_flush`, `dnotify_flush` and `locks_remove_posix` on close; `expand_files`, `find_next_zero_bit` and `_find_next_zero_bit` (whose body is `lib/find_bit.c`'s `FIND_NEXT_BIT`, copied verbatim into `model.h`).
- **User copies.** `_copy_to_iter`, `__copy_from_iter`, `copy_to_user_iter`, `copy_from_user_iter`, the `include/linux/iov_iter.h` iterators (`iterate_and_advance`, `iterate_ubuf`, `iterate_iovec`) and the arm64 `access_ok` with its helpers. Only `__arch_copy_to_user` and `__arch_copy_from_user`, the `copy_*_user.S` primitives, are models.
- **LSM hooks.** `security_file_permission`, `security_file_fcntl`, `security_file_truncate`, `security_inode_setattr` and `security_inode_post_setattr` walk their hook lists as the kernel does.
- **Timestamps.** `touch_atime`, `atime_needs_update`, `file_update_time`, `current_time`, `timestamp_truncate`, `inode_update_timestamps`, `generic_update_time`, `inode_maybe_inc_iversion`, `__mark_inode_dirty` and `ktime_get_coarse_real_ts64`.

Calls through an operation table (`f_op->read_iter`, `f_op->flush`, `a_ops->write_begin`, `i_op->setattr`, `s_op->dirty_inode` and four more) are the only change to the bodies. `prepare.py` rewrites each listed call text, which must occur exactly once, into a reviewed dispatch model that selects the callee by the table's object class. A static callee of such a model (`shmem_file_read_iter`, `shmem_setattr`) is extracted without `static`.

The iterators take their step function as an argument and are always inlined, so each call site's step is a constant. The context transform rejects function pointers, so the two user-address steps are an enumeration in `model.h`. `_copy_to_iter` and `__copy_from_iter` pass the named step, and `iterate_ubuf` and `iterate_iovec` call it directly; these are four more rewritten call texts.

The LSM hook bodies are original. `call_int_hook` and `call_void_hook` are `security.c`'s macros, copied into `model.h` with one change: the kernel calls each list entry's function through the entry (`P->hook.FUNC`), the copy calls it directly. The lists are a constant table, as `__ro_after_init` makes them after boot. The kernel builds three LSMs (capability, integrity with IMA and EVM off, and BPF), and only BPF registers these hooks. So each list holds one entry, BPF's no-op attachment point; every live trace runs it as its four-instruction default, with no program attached.

Their reviewed boundaries are:

- The LSM hook table above is constant: an attached BPF program or another LSM is outside the profile.
- The callees of other `fcntl` commands (`setfl`, locks, owners, leases, notify, pipe sizes, seals, write hints, `F_DUPFD_QUERY`) are fault boundaries: a path that reaches one is outside the profile.
- Per-CPU mount writer counts, rwsems, folio flag operations and atomics, the user-copy primitives (`__arch_copy_to_user`, `__arch_copy_from_user`), folio allocation and page-cache deletion are models. The copy primitives reach only the observed 32-byte user object; past it the live workload has a guard page, so an access there faults. Swap, huge pages, userfaultfd, quota and privilege removal are fault boundaries.
- The file has one order-0 folio. Its 64-byte store holds the first 64 bytes of the page; the rest of the page is zero by the binding's invariant.
- The kernel's `memset` is the original arm64 assembly, `arch/arm64/lib/memset.S`, assembled verbatim as `linux-memset.S` against reduced `linkage.h`, `assembler.h` and `cache.h`. Its strong `memset` replaces the slice runtime's weak C one. It stores unaligned and zeroes with `DC ZVA`, which fault on the Device memory an MMU-off harness sees. So the port sets `"target_mmu": "identity"`: the image starts with `start_mmu.S`, which identity-maps RAM as Normal memory before the replay (see [MMU-on harness](#mmu-on-harness)).

The profiles derived from `fd-control` (`close-range` through `file-setrlimit`) still use the earlier reviewed five-command dispatch model.

#### System call entry and exit

Every `fd-control` call enters the slice as an SVC from EL0 enters Linux. It
runs the original arm64 entry and exit:

- `arch/arm64/kernel/entry.S` assembled verbatim as `linux-entry.S`: the
  `vectors` table, `kernel_entry` in `el0t_64_sync`, `ret_to_user` and
  `kernel_exit` with its ERET;
- the C handlers from `entry-common.c` and `syscall.c`.

The assembly builds as Kbuild builds it, against the kernel's own headers. The
77 headers `entry.S` and `memset.S` include are pinned whole, with
`entry.S`, under `upstream/kernel-tree` (6.10.14; three headers differ from
v6.10, and their URLs name the stable tree). Preparation generates the
headers a kernel build would:

- `asm/cpucaps.h` and `asm/sysreg-defs.h`, by the kernel's awk generators from
  the pinned `arch/arm64/tools` inputs;
- `generated/autoconf.h`, from the live kernel's configuration;
- the generic `asm/types.h` and `asm/errno.h` wrappers;
- `asm/asm-offsets.h`, from a marked block of `model.h`. That block gives the
  `pt_regs` offsets and the task offsets `entry.S` reads (`thread_info` first,
  as on arm64, and `thread.sctlr_user`), and `_Static_assert`s check them
  against the model's structures.

The port declares the include setup per assembly source (`assembly_options`).
Alternatives stay unpatched, so their default instructions run. On the live
Cortex-A53 most are the same nops and branches; the SSBD check is one that
differs, skipped here and patched in live.

`entry-glue.S` is the reviewed model of what surrounds that code: the hardware
and the per-CPU setup. `osrec_linux_el0_svc`:

1. saves the caller's VBAR, SP_EL0, TPIDR_EL1, ELR, SPSR and ESR;
2. makes `__entry_task` the slice's current task, with a per-CPU offset of
   zero;
3. writes what an SVC writes: ESR as an SVC64 syndrome, ELR as the EL0 return
   address and SPSR as EL0t;
4. loads x0–x5 and x8, zeroing every other register;
5. branches to the vector for synchronous exceptions from 64-bit EL0.

Linux then runs unchanged. `el0t_64_sync_handler` reads ESR with the kernel's
own `read_sysreg`. The return is real: `kernel_exit`'s ERET drops to EL0, and
an undefined instruction there traps back through the glue's vector table,
which accepts only that trap. Any other exception is a replay fault.

The C side keeps two reviewed models:

- **The system call table.** It holds the slice's system call numbers instead
  of function pointers: indirect calls cannot be made context-explicit.
  `__invoke_syscall`'s `syscall_fn(regs)` is rewritten to the table call
  `osrec_sys_call`, which unpacks the argument registers as the
  `SYSCALL_DEFINE` wrappers do.
- **The thread flags.** Thread flags are transient model state, zero between
  calls, as in the 38 live traces (`el0_svc` and `do_el0_svc` take no work or
  trace branch). Work on return (signals, rescheduling), tracing and the other
  exception classes are fault boundaries. The live-boundary tools enter at the
  root, so the live binding does not bind the flags yet.

Analyses that start at the root (KLEE discovery, its validation, the reduced
replay) call `osrec_kernel_dispatch_root`. That is the direct root dispatch
`slice_dispatch.h` now also provides; their images hold no assembly.
`fd-control`'s test also changes the glue's syndrome to a breakpoint and
expects the replay to diverge.

#### MMU-on harness

The slice images normally start with the MMU and caches off, so every access is
Device-nGnRnE. A port that sets `"target_mmu": "identity"` starts with
`integrations/rtl_aarch64/start_mmu.S` instead. After clearing `.bss`, it builds
a stage-1 translation with VA = PA and turns the MMU on, caches still off:

| Range | Mapping |
|---|---|
| `0x00000000`–`0x3fffffff` | Device-nGnRnE, execute-never: what the MMU-off image sees |
| RAM, `0x40000000`–`0x7fffffff` | Normal Non-cacheable, EL1/EL0 read-write, EL0-executable |
| The image's `.text` | 4 KiB pages, read-only, executable at EL1 and EL0 |

Above 2 GiB nothing is mapped. Text needs its own pages because memory EL0 can
write is never executable at EL1, and the gateway's applications run at EL0.
Memory stays non-cacheable, so the physical memory a host or RTL observer reads
after a run is current.

- **Linker script.** `prepare_target` page-aligns `.text` and checks that it
  fits the four level-3 tables.
- **Manifest.** The image manifest records `mmu_enabled` and the mapping.
- **Composed images.** Application images built from such a library start the
  same way.
- **Gateway.** The application gateway requires the MMU off or this identity
  map: TTBR0 must point at `start_mmu.S`'s level-1 table, with its `TCR_EL1`.

`tests/test_identity_mmu_start.py` checks the behaviour on a small image:

- under `start.S`, an unaligned store faults;
- under `start_mmu.S`, the same unaligned store and `DC ZVA` work;
- a store into `.text` faults.

The `fd-control` test also exports the port without `target_mmu` and expects
the replay to diverge.

Close-on-exec flags belong to individual descriptor slots and persist independently of their aliases. Both duplication commands allocate the lowest available descriptor at or above the requested minimum and retain the same shared file object. Native observations check minimum-slot allocation, table-full and invalid-minimum errors, bad-descriptor precedence, ignored flag bits, integer narrowing, clearing stale close-on-exec bits on reuse and duplication through a surviving alias after the original closes. Reads and seeks through the new aliases observe the same file contents and offset. All earlier 171 native call observations remain identical and retain their relative order.

Each file adds `f_owner.signum`, the signal number that the original `F_GETSIG` reads and `F_SETSIG` writes. Inodes carry their size, flags, owners, timestamps, `i_version`, state, mapping and `shmem_inode_info` fields; the superblock, mount, coarse clock, folio and operation tables are model objects. The context is 2,184 bytes and the record 1,388. File status flags remain fixed and are queried through `F_GETFL`. `F_SETFL`, file locks, leases, owners, seals, rejecting security hooks and the other general `fcntl` commands are excluded. The other file-model bounds remain one 64-byte memory file, eight usable descriptors, a 32-byte caller object and one sequential task.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile fd-control --kernel-image /path/to/arm64/Image \
  --timeout 300 --out build/linux-fd-control
```

The descriptor-control suite and its positioned-I/O compatibility suite run from the archived native fixtures:

```sh
ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_(fd_control|file_positioned)_checkpoint$' \
  --output-junit qemu-linux-fd-control-regressions.xml
```

The `close-range` profile adds `close_range` (436) to `fd-control`: 267 native calls across twenty-one routes. It retains the original [Linux v6.10 syscall wrapper](https://github.com/torvalds/linux/blob/v6.10/fs/open.c#L1494) and [`__close_range`, `__range_close`, `__range_cloexec` and `last_fd` helpers](https://github.com/torvalds/linux/blob/v6.10/fs/file.c#L645), bringing the original-definition count to fifty-four. Flags zero close live descriptors inclusively and skip holes; `CLOSE_RANGE_CLOEXEC` marks descriptor slots without releasing references. Reversed bounds and invalid flags return the native errors, and all three arguments narrow to unsigned 32-bit values before validation.

The workload marks a full tail, closes middle aliases, reads through a survivor and reallocates the holes while preserving shared file contents and position. Later range calls close all but one regular alias and then release the last reference. All 233 inherited calls remain in order with their original arguments and inputs. Five later individual `close` calls now return `EBADF` because the earlier range calls have already removed their descriptors; the other 228 inherited observations remain identical to the descriptor-control capture.

The fixed fd table has 64 bitmap slots even though only eight descriptors can be allocated. Close-on-exec ranges therefore mark closed slots above the resource limit, including bit 63; those bits persist across checkpoint saves and restores. Native probes observe flags only for live descriptors. Closed-slot bitmap remnants are checked against the original source's transition rules and the reviewed fixed-table construction, rather than native kernel memory. The existing 960-byte context and 860-byte record already encode the complete bitmap. No analyzer, gateway or codec changes are needed; the reviewed extractor additionally accepts the original `static inline unsigned` helper declaration.

`CLOSE_RANGE_UNSHARE` is excluded. Its full original branch is retained, but unshare/table-replacement boundaries fail if reached, and valid unshare requests are absent from the admitted recipe. Scheduler hints are modeled under the sequential contract; flush and reschedule boundaries check that the file-table lock is released. Fork/exec, shared tables, allocation/reclamation, additional scheduler behavior and external close consumers remain excluded. The other file-model bounds remain one 64-byte memory file and a 32-byte caller object, with no host services during replay.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile close-range --kernel-image /path/to/arm64/Image \
  --timeout 300 --out build/linux-close-range
```

Archived-fixture regressions cover the new profile and descriptor-control compatibility:

```sh
ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_(close_range|fd_control)_checkpoint$' \
  --output-junit qemu-linux-close-range-regressions.xml
```

The `fstat` profile adds syscall 80 through original Linux `newfstat`, `vfs_fstat`, `vfs_getattr` and `cp_new_stat` bodies: 286 native calls across twenty-two routes, with fifty-eight pinned original definitions. The [original Linux v6.10 stat control flow](https://github.com/torvalds/linux/blob/v6.10/fs/stat.c#L372) uses reviewed direct filesystem-getattr, successful security, device-encoding and bounded user-copy boundaries. The application explicitly discards successful stat timestamps (bytes 72–119); timestamp-consuming applications need a clock input model and are outside this contract. All other structure bytes, including zero padding, are checked. The checked LP64 layout reference is a selected [Linux v6.11 generic stat header](https://github.com/torvalds/linux/blob/v6.11/include/uapi/asm-generic/stat.h#L19), with static size/offset assertions and native Linux 6.10.14 validation.

A separate 128-byte caller object has its own native guard page; the earlier 32-byte I/O object remains unchanged. Successful queries contribute all normalized stat words to a persistent application digest. The C/ELF chain restores that digest through fresh-image resumes and checks its final value against native execution. The returning proof checks both caller objects for output correctness and inter-session isolation. NULL, invalid, first-guard and partially accessible outputs reproduce native errors and exact accessible prefixes. Descriptor lookup errors precede output-copy faults.

Entry device/inode identities, full mode, link count, ownership and preferred block size come from native `fstat` observations and persist on the typed inode objects. The bounded memfd uses at most one 4 KiB page: successful writes allocate eight 512-byte blocks, truncation to zero releases them, and extension without writes leaves zero blocks. Private native stat probes independently check block count after every call. Repeated stat queries through aliases return the same identity and current size without advancing the shared position. After last-reference closure, the retained file and inode allocation fields are inactive model bookkeeping. All 267 inherited calls retain their earlier observed results and I/O-buffer bytes; the new capture additionally records metadata outputs and block observations.

The inode fields add 80 bytes: context size is 1040 bytes and portable record size 940 bytes. The analyzer, gateway and codec require no changes; capture generation, the application frontend and the proof now admit two caller objects for this profile. Limits remain one 64-byte memory file, eight usable descriptors, an initial namespace and sequential execution. Timestamp consumers, general allocation, pathname lookup, independent opens, rejecting security hooks and the earlier excluded filesystem/process features remain unsupported. Replay uses no host services.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile fstat --kernel-image /path/to/arm64/Image \
  --timeout 300 --out build/linux-fstat
```

Archived fixtures also support the metadata and range-close compatibility suites:

```sh
ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_(fstat|close_range)_checkpoint$' \
  --output-junit qemu-linux-fstat-regressions.xml
```

The `fchmod` profile adds syscall 52 through original Linux `fchmod`, `vfs_fchmod` and `chmod_common` bodies: 303 native calls across twenty-three routes, with sixty-one pinned original definitions. The [Linux v6.10 chmod helpers](https://github.com/torvalds/linux/blob/v6.10/fs/open.c#L595) retain descriptor lookup/release, 16-bit mode narrowing, preservation of inode type bits, attribute construction and cleanup. Reviewed models implement ordinary owner-authorized permission updates, successful security hooks, mount write access and inode locking. A private native `fchown` assigns the memfd to effective UID 1002 before credentials are dropped; ownership changes are capture construction, not a replay route. Native stat probes observe its mode after every call. The console belongs to another UID and native chmod returns `EPERM` without changing either inode.

The recipe exercises modes 0600, 0640, 0000, 0400 and 0604, high argument bits, invalid/closed descriptors, alias mutation and later stat queries. Changes update the shared inode; already-open descriptors retain their read/write access and shared position. Six joint checkpoints preserve those modes, both caller objects and the application metadata digest. Typed links restore each file's mount object alongside its dentry/inode graph. Mount write and inode-lock depths must return to zero after both success and denial. The context is 1088 bytes and the portable record 964 bytes. The generic analyzer, gateway and codec require no changes.

This profile admits the low nine permission bits in the initial namespace and sequential execution. Special set-ID/sticky bits, ACLs, delegation/retry, idmapped mounts, additional rejecting security hooks, pathname lookup and clock consumers remain outside its contract. Existing file-capacity, descriptor, timestamp and other profile limits remain. The final mode retained after last-reference closure is an inactive model snapshot. All 286 inherited calls retain their scalar results, I/O bytes, descriptor state and content/position/allocation observations; stat ownership and mode outputs reflect the new construction and mutations.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile fchmod --kernel-image /path/to/arm64/Image \
  --timeout 300 --out build/linux-fchmod

ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_(fchmod|fstat)_checkpoint$' \
  --output-junit qemu-linux-fchmod-regressions.xml
```

The `fchown` profile adds syscall 55 through six original Linux definitions: `fchown`, `ksys_fchown`, `vfs_fchown`, `chown_common`, `setattr_vfsuid` and `setattr_vfsgid`. Its recipe contains 328 calls across twenty-four routes and reuses all sixty-one earlier definition hashes, for sixty-seven originals. The [Linux v6.10 ownership helpers](https://github.com/torvalds/linux/blob/v6.10/fs/open.c#L688) retain descriptor lookup/release, UID/GID sentinel handling, initial attribute construction, security-hook sequencing and mount/inode cleanup. Namespace conversions, filesystem attribute updates, group membership and successful security hooks are explicit reviewed models.

Capture setup transfers the memfd to effective UID 1002 and explicitly seeds supplementary group zero before dropping credentials. Private `getgroups` and `capget` then observe the admitted group list and zero effective capabilities. Those setup/query calls are outside replay roots. The task retains effective UID/FSUID 1002 and effective group/FSGID 2002 throughout the workload. Original `fchown` calls can retain the UID and change the file's group between 0 and 2002. Foreign UID/group changes and non-owner console changes are denied; a denied combined UID/GID request leaves both fields unchanged. The all-ones ID sentinel preserves that field, and unsigned 32-bit argument narrowing is checked natively.

Native private stat probes record live UID/GID after every call. Queries through duplicated aliases observe shared ownership, and changes remain permitted with mode 0000 because ownership admission and existing-open access are separate checks. Six joint checkpoints retain ownership alongside file bytes, offsets, modes, descriptor flags, mount links and the application metadata digest. The UID/GID fields were already persisted for stat, so the checkpoint field policy is unchanged; context and portable record sizes remain 1088 and 964 bytes. All 303 inherited calls preserve scalar results, I/O bytes, descriptor observations and content/position/allocation/mode transitions; stat group output and its digest reflect the new changes.

This is a bounded unprivileged ownership profile: privileged UID transfer, effective `CAP_CHOWN`, changing task groups/capabilities, idmapped namespaces, delegation, ACLs, set-ID/sticky modes, file-capability consumers, additional rejecting security hooks and timestamp consumers remain excluded. Group membership is a captured fixed input; `setgroups` and `capset` are not replay routes in this file profile. Existing file-capacity, descriptor, pathname and sequential-execution limits remain. Ownership retained after last-reference closure is an inactive model snapshot. Replay needs no host services.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile fchown --kernel-image /path/to/arm64/Image \
  --timeout 600 --out build/linux-fchown

ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_(fchown|fchmod)_checkpoint$' \
  --output-junit qemu-linux-fchown-regressions.xml
```

The `fchown-capable` profile exercises privileged ownership transfer without granting chmod authority. Its generated 330-call workload retains the same sixty-seven original definitions and twenty-four replay routes. The task stays at effective UID/FSUID 1002 with effective **CAP_CHOWN only**. Private capture construction uses `capset` after the credential drop; `capget` checks the exact effective mask of 1. A permitted `CAP_SYS_BOOT` bit is reserved for native capture teardown, and is never effective during the workload. Neither capability syscall is a replay root in this file profile.

The reviewed `notify_change` model reads the effective capability from the credential object to admit UID/GID transfer, including reclamation when the caller no longer owns the inode. The original ownership helpers remain unchanged; the full Linux `setattr_prepare` capability/namespace/LSM machinery is not retained. The workload transfers to UID 9001/group 3001, changes a foreign owner's group to 3003, preserves both fields through all-ones sentinels, and restores UID 1002/group 0 through arguments with high bits set. It also transfers mode-0000 ownership to UID 0/group 4001 and still reads through the existing open descriptor without moving its shared offset. `CAP_FOWNER` is absent: attempts to chmod another owner's inode return `EPERM` and preserve its mode. Duplicated descriptors share transfers to UID 9002 and groups 4003/4007, and an alias can reclaim the same inode.

A persisted 64-bit credential capability field adds eight bytes: the context is 1096 bytes and the portable record is 972 bytes. Six joint checkpoints retain foreign and root ownership, later group changes through aliases, restored ownership, and inactive state after final closure. The decoder independently checks the saved capability, both inode ownership records, descriptor aliases, file bytes/offsets/modes and typed mount links. The 303 inherited permission-profile calls retain their scalar, memory, descriptor and file observations; the application metadata digest includes the new stat queries.

This profile fixes task credentials, supplementary groups and effective capabilities for the whole run. It does not combine file operations with runtime credential/capability setters. The ordinary-mode, initial-namespace, one-file/64-byte storage, eight usable descriptors, sequential-execution and timestamp exclusions remain. Pathname lookup, ACLs, idmaps, delegation and file-capability consumers remain outside this contract. Replay is self-contained and has no host-service dependency.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile fchown-capable --kernel-image /path/to/arm64/Image \
  --timeout 1200 --out build/linux-fchown-capable

ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_(fchown_capable|fchown)_checkpoint$' \
  --output-junit qemu-linux-fchown-capable-regressions.xml
```

The `file-capabilities` profile combines runtime `capset` with the file operations in one persistent context: 369 calls across twenty-five routes. It reuses all sixty-seven original ownership/file definitions and adds five original definitions from the existing capability port: `capset`, `cap_validate_magic`, `mk_kernel_cap`, `cap_inh_is_capped` and `cap_capset`. Both source excerpts and the selected capability ABI header are pinned. The full task UID/GID setter family remains separate; this combination specifically makes capability changes visible to later ownership and mode operations.

Capture starts with effective `CAP_CHOWN`, permitted `CAP_CHOWN | CAP_FOWNER | CAP_SYS_BOOT`, zero inheritable/ambient capabilities and the observed bounding set. The native task keeps UID/FSUID 1002, group/FSGID 2002 and supplementary group zero. Private `capget` observes effective/permitted/inheritable sets after every application call; private `prctl` observes the entry bounding/ambient sets. The workload never makes `CAP_SYS_BOOT` effective; its permitted bit remains available for capture teardown. Neither private query is a replay route in this profile.

Original `capset` validates the header version, PID and bounded data copy before preparing a credential candidate. Original commoncap code checks permitted/inheritable/effective subset rules. Reviewed two-slot prepare/commit/abort boundaries preserve both credential copies, the typed active-slot reference and publication generations. A permission rejection after preparation leaves a copied inactive slot without publishing it; a bad header, foreign PID or guarded copy fault never prepares a candidate. Unknown versions write the supported version back before returning `EINVAL`.

The inode attribute model reads the active credential's effective bits: `CAP_CHOWN` admits ownership transfer/reclamation, while `CAP_FOWNER` admits nonowner chmod. The workload drops and regains effective bits, verifies denied ownership transfer with mask zero, transfers an inode to UID 9001, changes its mode using `CAP_FOWNER` alone, and confirms that this bit still cannot reclaim ownership. Dropping `CAP_FOWNER` makes the next chmod fail after a fresh-image resume. With both bits restored, an alias changes ownership and mode on the same inode. Later permitted-set removal makes regain fail permanently, and file ownership stays unchanged. All 330 inherited file-profile calls preserve their scalar, memory, descriptor and file observations; the running stat digest includes the added queries.

The checkpoint policy persists all five capability sets in both credential slots, active pointer identity, generation counters and the existing inode/file/descriptor/mount graph. Six pauses cover an effective drop, a rejected prepared candidate, foreign-owner chmod, a later effective drop, alias changes with both bits and permanent permitted removal. The independent raw-record decoder compares both credential copies and their generations with the value/lifetime projection, and compares the active effective/permitted/inheritable values with native observations. Post-call capability observations are checks, not inputs that overwrite the model's live state.

Bounds remain one sequential task in the initial namespace, ordinary modes, one 64-byte memfd and eight usable descriptors. Task identity/group setters, runtime namespace changes, general `prctl`, `capget` replay, allocator exhaustion, ACLs, delegation, file-capability consumers, pathname lookup and timestamp consumers remain excluded. The full Linux `setattr_prepare` permission machinery is represented by the reviewed inode attribute model; the original ownership and chmod helpers and capability subset code are retained. Replay requires no host services.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile file-capabilities --kernel-image /path/to/arm64/Image \
  --timeout 1200 --out build/linux-file-capabilities

ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_(file_capabilities|fchown_capable)_checkpoint$' \
  --output-junit qemu-linux-file-capabilities-regressions.xml
```

The `file-fsgid` profile adds original `setfsgid` (152) to the combined file/capability session: 401 calls across twenty-six routes. It reuses all seventy-two earlier definitions and adds the original wrapper and `__sys_setfsgid` helper from the existing Linux v6.10 credential port. The selected kernel/sys.c excerpt and generic syscall ABI are pinned independently. Both credential slots now persist a filesystem GID alongside the five capability sets; task real/effective/saved GIDs remain 2001/2002/2003 and UID/FSUID remains 1002.

Without effective `CAP_SETGID`, original `setfsgid` admits the task's real/effective/saved/current filesystem GID. The workload switches between 2001, 2002 and 2003, checks unsigned 32-bit argument narrowing, and verifies that a foreign group request silently returns the old filesystem GID without publication. Same-ID requests prepare and abort a copied candidate; the all-ones invalid-ID query returns before preparation. A successful change publishes through the same typed two-slot credential pool used by runtime `capset`. Group changes preserve capability sets. The current permitted mask excludes `CAP_SETGID`, so the workload cannot grant arbitrary filesystem groups.

The inode group-membership model now reads the active credential's **filesystem GID**, rather than effective GID. With effective capabilities zero, FSGID 2001 and EGID 2002, assigning inode group 2001 succeeds while assigning group 2002 is denied. A `getegid` call still returns 2002. After switching FSGID to 2003, that group becomes available and the old real group is denied; supplementary group zero and the inode's current group remain admitted. Aliased descriptors observe the same inode group changes. A successful `capset` while FSGID is 2001 copies it into the newly published credential, proving that the two syscall families share live credential state.

Native capture privately calls `setfsgid(-1)` after every application syscall. The invalid-ID request observes the live filesystem group without preparing or mutating credentials. Each replay call is checked against those observations, while an independent value/lifetime projection and raw-record decoder check both FSGID slots, active references, publication generations, capability sets and file/inode state. Six joint pauses cover real/saved/effective filesystem groups, nonpublishing preparation, alias changes and capability publication with a nondefault filesystem group. The 369 inherited calls retain scalar, memory, descriptor, file and capability observations; the running stat digest includes the added stat queries.

This profile changes filesystem group identity only. Task UID/FSUID setters, real/effective/saved GID setters, supplementary-list setters and namespace changes remain separate. Its successful group security hook is a reviewed boundary; no rejecting LSM, allocator exhaustion or concurrent credential consumer is admitted. The initial namespace, ordinary-mode, single-file/64-byte storage, eight-descriptor, pathname/ACL/delegation/file-capability and timestamp-consumer limits remain. Replay has no host-service dependency.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile file-fsgid --kernel-image /path/to/arm64/Image \
  --timeout 1200 --out build/linux-file-fsgid

ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_(file_fsgid|file_capabilities)_checkpoint$' \
  --output-junit qemu-linux-file-fsgid-regressions.xml
```

The `file-fsuid` profile adds original `setfsuid` (151) and filesystem capability fixups to the combined file/FSGID/capability session: 452 calls across twenty-seven routes. It retains all seventy-four earlier definitions and reuses seven definitions from the existing FSUID port: `setfsuid`, `__sys_setfsuid`, `cap_emulate_setxuid`, `cap_task_fix_setuid`, `cap_drop`, `cap_drop_fs_set` and `cap_raise_fs_set`. The syscall, commoncap and filesystem-capability excerpts, syscall numbers, selected capability declarations and securebits header are hash-pinned. Securebits are observed as zero at native entry and remain fixed in this profile.

Task real/effective/saved UIDs stay 1001/1002/0, while filesystem UID can select one of those IDs or its current value. The permitted set excludes `CAP_SETUID`, so a foreign request silently returns the old FSUID. Invalid all-ones IDs return before preparation; same-ID and denied requests prepare and abort without publication. An application `geteuid` still returns 1002 while FSUID is 1001. The inode attribute model uses the active **filesystem UID** for owner checks. With effective capabilities zero, the old EUID-owned inode denies chmod and ownership operations after the filesystem user changes. After the inode is transferred to UID 1001, FSUID 1001 permits ordinary owner operations even though EUID remains 1002.

Original commoncap code applies the filesystem capability mask: entering FSUID zero raises only filesystem bits present in the permitted set, here `CAP_CHOWN | CAP_FOWNER`; leaving zero drops effective filesystem bits. The workload verifies foreign ownership transfer and nonowner chmod while those bits are effective, then denied operations after dropping back to FSUID 1001. Alias operations use the same inode. Interleaved `capset` and `setfsgid` publications while FSUID is nondefault preserve it in the newly active credential. Inserted sequences restore ownership, mode, FSUID, FSGID and capabilities before continuing; all 401 inherited calls retain scalar, memory, descriptor, file and capability observations, with the running metadata digest incorporating the added queries.

Private native `setfsuid(-1)` observes FSUID after each application call without preparing credentials. Both credential slots persist FSUID, FSGID, all five capability sets and securebits, alongside typed active references and publication epochs. Six joint checkpoints cover the EUID/FSUID mismatch, root filesystem capability gain, subsequent effective-bit loss, unprivileged ownership, alias/group changes and restored state. Independent projection and raw-record decoding check both slots through fresh-image resumes. Captured post-call observations verify execution; they do not replace live runtime state.

Bounds remain one sequential task in the initial namespace, one 64-byte memfd, eight usable descriptors, ordinary modes and successful reviewed security boundaries. Real/effective/saved UID/GID setters, supplementary-list replacement, securebit mutation, general capability/prctl queries, allocator exhaustion, concurrent consumers, pathname lookup, ACLs, delegation, file-capability consumers and timestamp consumers remain separate or excluded. `notify_change` permission/attribute handling and credential allocation/publication are reviewed models; the selected original syscall and capability-fixup bodies execute in replay. The reference native kernel is 6.10.14-linuxkit; selected implementation sources are Linux v6.10 and the stat-layout reference is v6.11. Exact native source/build attestation remains unavailable. Replay images require no host services or running Linux kernel.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile file-fsuid --kernel-image /path/to/arm64/Image \
  --timeout 1200 --out build/linux-file-fsuid

ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_(file_fsuid|file_fsgid)_checkpoint$' \
  --output-junit qemu-linux-file-fsuid-regressions.xml
```

The retained `file-fsuid` validation run passed 452 calls, 27 replay routes and 32 QEMU matrix executions. TCG and HVF native captures matched after the workload’s explicit timestamp normalization. All eight new/affected regression cases passed, including four FSUID runtime-divergence mutations and five jointly forged native observations. Twenty-five earlier workflows passed offline verification. The generated report is `build/live-syscall-checks/linux-file-fsuid-validation.json`; the complete pipeline is `build/linux-file-fsuid-pipeline-final-v1`.

The `file-groups` profile combines original `getgroups` (158) and `setgroups` (159) with the file, capability and filesystem-ID session: 509 calls across twenty-nine routes. It retains all eighty-one earlier definitions and adds seven original Linux v6.10 group definitions: the two syscall wrappers, `groups_to_user`, `groups_from_user`, `set_groups`, `set_current_groups` and `may_setgroups`. Source excerpts and syscall numbers are pinned. List allocation, reference operations, sorting, security boundaries and supplementary membership checks are explicit reviewed models.

The native constructor seeds supplementary group zero and observes it before replay. Effective capabilities initially contain `CAP_CHOWN`; permitted capabilities additionally include `CAP_FOWNER`, `CAP_SYS_BOOT` and `CAP_SETGID`. After the baseline twenty-call prefix, a new sequence makes SETGID effective, installs a sorted list with duplicates, queries its count and contents, and changes inode groups using supplementary membership while CHOWN is absent. Dropping effective SETGID makes list replacement return `EPERM` before size validation or user-copy faults, while existing supplementary membership still authorizes later owner/group operations. FSGID and FSUID changes and capset publications preserve the live list.

An empty replacement removes supplementary membership. The workload distinguishes membership from FSGID, effective GID and the inode's existing group, and retains the FSUID owner check. Invalid IDs and guarded partial input copies release the new list without publishing credentials; their partly filled inactive storage remains visible to the independent model. Successful high-word count narrowing installs a two-ID list. Descriptor aliases use that shared membership to change the same inode. Entering FSUID zero raises permitted filesystem capabilities but does not make SETGID effective, so setgroups still fails. The sequence restores list zero, filesystem IDs, inode ownership and descriptor state, then permanently removes permitted SETGID before running the inherited filesystem-ID/file recipes.

Both credential slots contain typed references to two capacity-four list objects. Active credentials, prepared candidates and caller allocations own modeled references; inactive credential copies retain non-owning last-copy pointers. Every credential prepare takes a reference, commit releases the old active reference, and abort releases the candidate. Reusing a released list slot preserves its object identity. The checkpoint policy retains list counts, four ID slots, reference counts and both credential links, together with capabilities, FSUID/FSGID, publication generations and the existing file graph. Six joint checkpoints cover duplicate membership, capability drop, an empty list, a failed partial copy, alias changes and restored state. Native private getgroups checks live membership after every application call; reference counts and inactive snapshots are model bookkeeping rather than native kernel-memory observations.

The 452 inherited calls retain raw returns, caller memory, descriptor and file observations. The first twenty calls privately observe the additional permitted SETGID bit; after the inserted sequence, their capability observations match the previous profile. The metadata digest includes added stat queries. Post-call observations check computed live state; replay does not load them as state updates.

The initial namespace permits supplementary changes, as established by the successful constructor seed. Capacity is four IDs, including duplicates and the empty list. Namespace-disabled setgroups, larger allocations, allocation exhaustion, concurrent credential/list users, rejecting LSM hooks, real/effective/saved UID/GID setters and the earlier filesystem/pathname/ACL/delegation/timestamp exclusions remain outside this profile. It still models one 64-byte memfd and eight usable descriptors, uses ordinary inode modes, and retains the original selected syscall/capability bodies. Native Linux/source build attestation remains unavailable. Replay uses no host services or running Linux kernel.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile file-groups --kernel-image /path/to/arm64/Image \
  --timeout 1200 --out build/linux-file-groups

ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_(file_groups|file_fsuid)_checkpoint$' \
  --output-junit qemu-linux-file-groups-regressions.xml
```

The retained `file-groups` run passed 509 calls, 29 replay routes and 32 QEMU matrix executions, with matching TCG/HVF native observations after explicit timestamp normalization. All eight new/affected regression cases passed, including five new runtime-divergence mutations and five jointly forged native observations. Twenty-six earlier workflows passed offline verification. The complete pipeline is `build/linux-file-groups-pipeline-final-v1`; the generated report is `build/live-syscall-checks/linux-file-groups-validation.json`.

The `file-group-setters` profile combines original `setgid` (144), `setregid` (143) and `setresgid` (149) with the file, capability, supplementary-list and filesystem-ID session: 568 calls across thirty-two routes. All eighty-eight previous definitions are retained; six original scalar group definitions are reused from the existing Linux v6.10 group-setter port. Both syscall bodies/helpers and selected syscall-number declarations are hash-pinned. The group security boundary admits the four reviewed setter flags; other security-policy consumers remain excluded.

While effective SETGID is present, the workload installs foreign real/effective/saved groups, uses unsigned 32-bit narrowing in setgid, and verifies that the resulting FSGID admits later owner/group changes through a descriptor alias without CHOWN. After effective SETGID is dropped, setgid selects the real or saved GID while preserving the other IDs. setregid exercises saved-ID preservation and replacement. A denied setregid first accepts a real-GID change into the prepared candidate, then rejects its requested effective GID; the active credential stays unchanged while the inactive snapshot retains that partial real-GID edit. A subsequent setresgid permission denial returns before preparation and preserves the snapshot.

An all-sentinel setresgid call is a no-op even when FSGID differs from EGID. An explicit request for the unchanged EGID repairs that distinct FSGID and publishes a credential. The workload verifies file-group admission before and after repair, loss of a saved ID, genuine no-op publication behavior and a guarded getresgid output with a valid written prefix. getgid, getegid and getresgid read the live scalar IDs. Capset, setfsgid, setfsuid and supplementary-list replacement preserve nondefault real/effective/saved GIDs in their copied credentials. Supplementary membership still authorizes inode-group changes independently of the scalar IDs.

Both credential slots already contain persisted scalar GID fields; their values now evolve alongside FSGID, FSUID, capability sets, list links and reference counts. Private native getresgid observes all three task GIDs after every application call. The independent value/lifetime projection, per-call state checks and raw-record decoder check active and inactive tuples, partial edits, publication generations and the typed file/list graph across six joint checkpoints. Captured post-call fields verify execution and are not loaded as runtime state updates.

Construction caches immutable input-row recipes for the thirteen file profiles, avoiding repeated reconstruction of the complete nested plan for each call. Each caller receives a fresh mutable buffer. Regression checks verify that generated applications stay byte-identical and that editing a returned buffer or a separately built plan cannot change later inputs. This cache exists only during construction; the guest contains compiled code and data.

Inserted sequences restore task GIDs 2001/2002/2003, FSGID 2002, supplementary group zero, FSUID, capabilities and inode ownership before the inherited session continues. All 509 inherited native scalar, memory, descriptor, file, capability and group observations are preserved; the metadata digest includes the added stat calls. The SETGID bit is still permanently removed at the inherited boundary, so later unprivileged filesystem-ID tests retain their earlier behavior.

Bounds remain one sequential task in the initial namespace, one 64-byte memfd, eight usable descriptors, two credential slots and two supplementary-list objects of capacity four. Real/effective/saved UIDs remain fixed; their setters and user-accounting changes are separate. Namespace changes, rejecting LSM hooks, allocation exhaustion, concurrent consumers, pathname lookup, ACLs, delegation, special inode modes, file-capability consumers and timestamp consumers remain excluded. The selected original setter bodies execute; credential allocation/publication and file permission callbacks remain explicit reviewed models. Native Linux/source build attestation remains unavailable. Replay requires no host services or running Linux kernel.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile file-group-setters --kernel-image /path/to/arm64/Image \
  --timeout 1200 --out build/linux-file-group-setters

ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_(file_group_setters|file_groups)_checkpoint$' \
  --output-junit qemu-linux-file-group-setters-regressions.xml
```

The retained `file-group-setters` run passed 568 calls, 32 replay routes and 32 QEMU matrix executions, with matching TCG/HVF native observations after explicit timestamp normalization. All eight new/affected regression cases passed, including five runtime-divergence mutations, five jointly forged observations and immutable-input checks across all thirteen file profiles. Twenty-seven earlier workflows passed offline verification. The context remains 1,336 bytes and the record 1,188 bytes. The complete pipeline is `build/linux-file-group-setters-pipeline-final-v2`; the generated report is `build/live-syscall-checks/linux-file-group-setters-validation.json`.

The `file-status` profile adds `F_SETFL` behavior to the existing `fcntl` route in the combined file/group session: 630 calls across the same thirty-two routes. It retains all ninety-four original definitions and pins a selected Linux v6.10 `asm-generic/fcntl.h` declaration excerpt. The `fcntl` entry, flag-setting helper and append filesystem callback are explicit reviewed models; this profile does not retain the original `setfl` or `generic_file_write_iter` bodies. Native TCG/HVF captures verify the admitted behavior against Linux 6.10.14.

`O_APPEND`, `O_NONBLOCK` and `O_NOATIME` belong to the shared open description. Changing them through an alias affects the other aliases and subsequent duplicates. `F_GETFL` reads live flags. Access mode and `O_LARGEFILE` remain fixed; supplied creation, truncation, close-on-exec and upper bits do not change file contents or descriptor-local close-on-exec state. Descriptor replacement and closure preserve the surviving open description and its flags.

Nonempty ordinary writes with APPEND select EOF and advance the shared position. Linux's admitted append behavior also places `pwrite64` data at EOF, including with an explicit high offset, while preserving the shared position. Guard-page partial copies append only the copied prefix. Zero-count, negative-position and wholly faulting writes preserve size/position as observed natively. Clearing APPEND restores positioned overwrite behavior. The workload distinguishes all these effects through file bytes, size, shared offset and stat results.

Adding NOATIME requires ownership through the live FSUID or effective `CAP_FOWNER`. Retaining an already-set flag and clearing it do not require a new ownership check. FSUID changes and capability drop/regain exercise that ordering; denied additions leave the entire state unchanged. The workload restores initial file bytes, size, position, status flags, live descriptor flags and active credentials before the inherited session continues. The closed temporary alias retains its stale close-on-exec bitmap bit under the original close rules; that bit is preserved in the checkpoint. All 568 inherited native observations remain unchanged apart from the cumulative digest's extra stat queries and the new private status observations.

Private native `F_GETFL` probes record all live descriptor flags after every application call. Both file objects' status fields were already persisted, so context and record sizes stay unchanged. Six joint checkpoints cover append, positioned append, three aliases, a closed/reinstalled original descriptor, a nonowner denial and restored state. The independent projection and raw-record decoder check live aliases, shared flags, credential/list state and released-object snapshots. Nonblocking is retained and queryable; blocking devices and scheduling effects are excluded. Direct/asynchronous I/O flags, append-only inodes, pipe/driver checks, additional fcntl commands and the earlier filesystem/namespace/concurrency exclusions remain outside the contract. Timestamp consumers remain excluded. Replay requires no host services or running Linux kernel.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile file-status --kernel-image /path/to/arm64/Image \
  --timeout 1200 --out build/linux-file-status

ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_(file_status|file_group_setters)_checkpoint$' \
  --output-junit qemu-linux-file-status-regressions.xml
```

The retained `file-status` run passed 630 calls, 32 replay routes and 32 QEMU matrix executions. TCG/HVF native observations matched after explicit timestamp normalization. All eight new/affected regression cases passed, including six runtime-divergence mutations and five jointly forged observations; twenty-eight earlier workflows passed offline verification. The context remains 1,336 bytes and the record 1,188 bytes. The complete pipeline is `build/linux-file-status-pipeline-final-v3`; the generated report is `build/live-syscall-checks/linux-file-status-validation.json`.

The `file-capget` profile adds original `capget` (90), `cap_get_target_pid` and `cap_capget` bodies to the persistent file session: 696 calls across thirty-three routes and ninety-seven pinned original definitions. All 630 inherited native observations are preserved exactly, including the stat digest and live descriptor flags. Sixty-six application queries read the currently published credentials after capability updates and FSUID fixups; they leave both credential copies, publication generations, supplementary lists and file state unchanged.

Version 1 returns one capability record and preserves the remaining caller bytes; versions 2 and 3 return two records. Unknown-version negotiation updates the header, including with a null output pointer. Null output bypasses PID inspection after version validation. Negative and guaranteed-absent PIDs, invalid headers/output, a header ending at the guard page, aliased header/output and writable-prefix faults are compared against native Linux. The single-task lookup model admits the current PID and guaranteed-absent INT32_MAX; other tasks, task traversal, ptrace and namespaces remain excluded. The shared copy boundary distinguishes the guarded 32-byte capability/scalar object from the separate 128-byte stat object.

Six joint checkpoints retain FOWNER gain/drop, partial output, root-FSUID gain/drop and final reduced capabilities. Fresh consumers continue querying and using the same evolving credentials. The application-visible query route uses the retained kernel bodies and current state, while private native probes provide construction-time observations. Replay needs no host interaction. The file-status profile's explicit F_SETFL/append models and all earlier file, scheduler, namespace and timestamp bounds still apply.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile file-capget --kernel-image /path/to/arm64/Image \
  --timeout 1200 --out build/linux-file-capget

ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_(file_capget|file_status)_checkpoint$' \
  --output-junit qemu-linux-file-capget-regressions.xml
```

The retained `file-capget` run passed 696 calls, 33 replay routes and 32 QEMU matrix executions, with matching TCG/HVF native observations. All eight new/affected regression cases passed, including four new runtime-divergence mutations and five new jointly forged observations; twenty-nine earlier workflows passed offline verification. All 630 inherited observations remain identical. The context remains 1,336 bytes and the portable record 1,188 bytes. The complete pipeline is `build/linux-file-capget-pipeline-final-v1`; the generated report is `build/live-syscall-checks/linux-file-capget-validation.json`.

The `file-prctl` profile adds the seven reviewed commoncap `prctl` operations to the persistent file session: 767 calls across thirty-four routes and ninety-nine original definitions. It retains the original `cap_task_prctl` and `cap_prctl_drop` bodies; the general `sys_prctl` wrapper is retained only as a pinned dispatch-prefix excerpt, not compiled as a replay path. The CLI, generated application, five-argument recipe, bundle preparation and QEMU verification use the existing automation.

The native constructor initially retains permitted SETPCAP in addition to the previous capability set. A new application block gains effective SETPCAP, drops bounding bit 40, exercises ambient capabilities, changes securebits, and permanently removes SETPCAP before the inherited workload continues. Every earlier application return and caller-memory observation is preserved. Native observations differ only in the first twenty private permitted-set probes, the explicit zero fifth argument and the added private control-state field. The dropped bounding bit and locked KEEP_CAPS persist through all later credential copies, aborts, file operations and fresh resumes.

Ambient CHOWN alone does not authorize ownership transfer. The workload removes effective CHOWN/FOWNER and verifies an ownership-transfer denial and a separate nonowner NOATIME denial. It checks ambient raise/lower/clear and reserved arguments, including a nonzero fifth argument, and verifies that capset removes ambient bits absent from permitted/inheritable sets. There is no exec consumer in this contract.

NO_SETUID_FIXUP suppresses the original FSUID capability fixup while entering root; clearing it restores the usual permitted filesystem-bit gain on the next transition. Later FSUID transitions continue normally while KEEP_CAPS is locked. Permission checks precede invalid bounding-capability validation; keepcaps can change without effective SETPCAP until locked. Locked or unsupported securebit updates are denied without publishing or changing either credential slot.

Private native prctl probes observe bounding and ambient masks and securebits after every call. The independent projection, per-call adapter and raw-record decoder check both credential slots and the active state. Six joint checkpoints cover ambient raise, suppressed root entry, restored root fixup, the KEEP_CAPS lock, an inherited root-FSUID query and final reduced capabilities. Existing persisted fields are sufficient; no host services or running Linux kernel are needed during replay. Other prctl options, extra LSM consumers, exec/fork, other tasks, namespaces and the earlier bounded-file, scheduling and timestamp exclusions remain outside the contract.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile file-prctl --kernel-image /path/to/arm64/Image \
  --timeout 1200 --out build/linux-file-prctl

ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_(file_prctl|file_capget)_checkpoint$' \
  --output-junit qemu-linux-file-prctl-regressions.xml
```

The retained `file-prctl` run passed 767 calls, 34 replay routes and 32 QEMU matrix executions, with matching TCG/HVF native observations. All eight new/affected regression cases passed, including four new runtime-divergence mutations and five new jointly forged observations; thirty earlier workflows passed offline verification. All 696 inherited application observations are preserved with the explicit entry-permission and argument-width adjustments above. The context remains 1,336 bytes and the portable record 1,188 bytes. The complete pipeline is `build/linux-file-prctl-pipeline-final-v1`; the generated report is `build/live-syscall-checks/linux-file-prctl-validation.json`.

The `file-credentials` profile adds original `setuid`, `setreuid` and `setresuid` to the combined file session: 821 calls across all thirty-seven reviewed routes. It retains all ninety-nine prior definitions and adds nine original UID/accounting definitions, including `set_user`, `flag_nproc_exceeded` and `set_cred_ucounts`. Real/effective/saved IDs, FSUID, capability/securebit state, groups, user/accounting links and file state now evolve together. This is bounded coverage of these routes, not unrestricted Linux syscall support.

The native constructor retains permitted SETUID temporarily and sets an unlimited NPROC limit, observed in the entry manifest. A new application block exercises privileged UID changes, unprivileged real/saved-ID admission, effective-root capability drop/regain, KEEP_CAPS, ambient clearing, and NO_SETUID_FIXUP suppression. Ownership, chmod and NOATIME checks respond to the changed effective capabilities and FSUID. An already-open positioned read remains usable after dropping privilege. The block restores initial user IDs, file ownership, capabilities and securebits, then removes SETUID before the inherited session continues. All 767 earlier observations remain identical except for the first twenty private entry-permitted-set probes and the added private UID observations.

Credential preparation, publication and abort balance modeled user/accounting references in addition to the existing supplementary-list references. Four admitted real-UID identities use typed pools: 1001, 0, 9001 and 9002. An aborted `setreuid` may leave an inactive UID edit whose nonowning user/accounting pointers still describe the old active user. The checkpoint preserves that distinction; a later preparation overwrites it from the active credential. NPROC flags remain clear under the observed unlimited limit; fork, exec, physical slab/RCU lifetimes and external accounting consumers remain excluded.

The same source analysis and typed checkpoint codec discover the added state. User/accounting pointers serialize as context-relative IDs; accounting namespace pointers are self-references rebound from the schema. Private getresuid observes active IDs after every call. Six checkpoints cover real-UID accounting transfer, a partial inactive abort, dropping all root IDs with KEEP_CAPS, suppressed UID fixups, restored entry credentials and the final inherited session. Timestamp, pathname-open, namespace, scheduler, extra LSM and earlier bounded-file exclusions remain in force. Replay requires no host services or running Linux kernel.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile file-credentials --kernel-image /path/to/arm64/Image \
  --timeout 1200 --out build/linux-file-credentials

ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_(file_credentials|file_prctl)_checkpoint$' \
  --output-junit qemu-linux-file-credentials-regressions.xml
```

The retained `file-credentials` run passed 821 calls across all 37 reviewed routes and 32 QEMU matrix executions, including six joint checkpoint/resume boundaries. Native TCG/HVF observations match. All eight new/affected regression cases passed, including five new runtime-divergence mutations and five new jointly forged observations; 31 earlier workflows passed offline verification. All 767 inherited observations are preserved with the documented private-probe adjustments. The context is 1,488 bytes and the portable record 1,292 bytes. The complete pipeline is `build/linux-file-credentials-pipeline-final-v2`; the generated report is `build/live-syscall-checks/linux-file-credentials-validation.json`.

The `file-rlimit` profile adds original `getrlimit` (163) to the combined credential/file session: 851 calls across 38 reviewed routes and 109 original definitions. All 108 earlier definitions and all 821 earlier observations are preserved. The [Linux v6.10 wrapper](https://github.com/torvalds/linux/blob/v6.10/kernel/sys.c#L1447) is retained unchanged. Its `do_prlimit` dependency is an explicit query-only model; the general original helper and resource-limit setters are outside this profile.

Two typed soft/hard pairs retain NPROC=`(UINT64_MAX,UINT64_MAX)` and NOFILE=`(8,8)`. Both application queries and the existing descriptor-allocation/UID-accounting consumers read these objects. The generic analyzer discovers the added array and its four scalar fields; the checkpoint codec persists them without raw pointers. Native private `getrlimit` probes observe both pairs after every call. Native buffer normalization is now generated from the reviewed port argument kinds, including selection of the separate stat buffer, and the generated header is bound in capture provenance. This step makes the admitted limits explicit retained state; their values remain fixed throughout the recipe.

Thirty added application queries cover 64-bit infinity, low-32-bit resource narrowing, aligned and unaligned output, NULL/bad/guarded pointers, eight-byte partial output, and invalid-resource rejection before checking the output pointer. Queries are interleaved with real-UID/accounting transfer, an inactive credential abort, capability fixups, descriptor-table exhaustion and last file-reference release. They publish no credentials and change no file state. Six joint checkpoints retain partial output, accounting and abort state, a full table and released-file state. Other valid resource numbers, limit setters, CPU timers, other tasks, namespaces, concurrency and the earlier bounded-file exclusions remain outside the contract.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile file-rlimit --kernel-image /path/to/arm64/Image \
  --timeout 1200 --out build/linux-file-rlimit

ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_file_rlimit_checkpoint$'
```

The retained `file-rlimit` run passed 851 calls, 38 routes, 32 QEMU executions and six joint resume boundaries, with matching native TCG/HVF observations. The four new regression cases, seven preflight cases and one affected credential-generation case passed. Four rebuilt faulty models and five jointly forged native observations were rejected; all 32 earlier workflows passed offline verification. The analyzer discovers 191 context functions, 48 pure functions and 24 state objects. The context/portable record sizes are 1,520/1,324 bytes. The accepted native captures are `build/linux-file-rlimit-native-tcg-v2` and `build/linux-file-rlimit-native-hvf-v1`; the complete pipeline is `build/linux-file-rlimit-pipeline-final-v1`. The generated report is `build/live-syscall-checks/linux-file-rlimit-validation.json`.

The `file-limits` profile extends those queries to all 16 resource types, with 924 calls across the same 38 routes and 109 original definitions. It captures every soft/hard pair at entry and seeds typed retained state from those observations. The original `getrlimit` wrapper reads that state through the explicit query-only `do_prlimit` model. Descriptor allocation and UID accounting read slots NOFILE and NPROC in the same array. All 851 earlier application observations are preserved; an additional private probe records all 16 pairs after every call.

The 73 added calls include four complete resource sweeps around entry, an aborted credential change, descriptor exhaustion and last-reference release. They also cover 32-bit argument narrowing, unaligned output, NULL/guard faults and eight-byte partial output for six resources. Six joint resumes preserve the complete array and application output alongside credentials and files. The generic analyzer and codec discover and persist all 32 scalar limit fields. Values remain unchanged during this query-only recipe; setters, CPU-timer enforcement, other tasks and concurrent updates remain excluded.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile file-limits --kernel-image /path/to/arm64/Image \
  --timeout 1200 --out build/linux-file-limits

ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_file_limits_checkpoint$'
```

The retained `file-limits` pipeline passed 924 calls, 38 routes, 32 QEMU executions and six joint resumes at ordinals 26, 41, 43, 80, 807 and 893. Native TCG/HVF observations match, and all 851 inherited observations are preserved. All 33 earlier workflows passed offline verification. The analyzer discovers 191 context functions, 48 pure functions and 24 state objects; the context and portable record occupy 1,744 and 1,548 bytes. The complete pipeline is `build/linux-file-limits-pipeline-final-v1`; accepted native captures are `build/linux-file-limits-native-tcg-v1` and `build/linux-file-limits-native-hvf-v1`. The four new regression cases, seven preflight cases and affected generation case passed. Four rebuilt faulty models failed during target execution, and all eight jointly forged native captures were rejected. The generated evidence report is `build/live-syscall-checks/linux-file-limits-validation.json`.

The `file-setrlimit` profile adds original `setrlimit` (164) and replaces the query-only `do_prlimit` model with its [original Linux v6.10 helper](https://github.com/torvalds/linux/blob/v6.10/kernel/sys.c#L1388). The workload contains 973 calls across 39 routes and 111 original definitions; all 109 earlier definitions are reused unchanged. All 924 inherited application observations remain identical. The additional 49 calls update STACK, CORE, NOFILE and MEMLOCK pairs and read their live values. Other resource queries remain supported.

Limits now belong to a typed signal object linked from the task; the original helper follows the task's group-leader link and updates that object under a modeled sequential task lock. Both links are rebound by the generic codec. Lowering soft NOFILE to four makes `dup` fail with `EMFILE`, rejects an out-of-range `dup3`/`F_DUPFD`, and leaves existing descriptors usable. Restoring the soft limit to eight permits allocation again. Later calls retain a 64-bit CORE soft value, reduce hard limits, reject unprivileged hard-limit raises and allow soft-limit increases within the reduced hard bound. Failed validation and input copies leave the retained limits unchanged.

The original setter copies its input before validating the resource: invalid-resource plus NULL returns `EFAULT`, unlike the original query's `EINVAL`. Aligned/unaligned input, low-32-bit argument narrowing, guard faults and eight-byte partial input are covered. Six joint checkpoints carry changed limits and descriptor state into fresh consumers. CPU-limit updates/timers, enforcement of STACK/CORE/MEMLOCK beyond their stored pairs, other tasks, concurrent changes and extra rejecting LSMs remain outside the recipe. The security hook and lock are explicit dependency models. NOFILE's model admission ceiling is eight: this is equivalent for the admitted workload, whose initial hard limit is eight and whose permitted set lacks `CAP_SYS_RESOURCE`; it does not claim to capture the native global `sysctl_nr_open`.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile file-setrlimit --kernel-image /path/to/arm64/Image \
  --timeout 1200 --out build/linux-file-setrlimit

ctest --test-dir build/live-syscall-checks -j1 \
  -R '^freestanding_linux_aarch64_file_setrlimit_checkpoint$'
```

The retained `file-setrlimit` pipeline passed 973 calls, 39 routes, 32 QEMU executions and six joint resumes at ordinals 41, 46, 944, 948, 950 and 956. Native TCG/HVF observations match; all 924 earlier observations are preserved, and all 34 earlier workflows passed offline verification. The analyzer discovers 195 context functions, 48 pure functions and 25 state objects. Context and portable record sizes are 1,784 and 1,552 bytes. The accepted pipeline is `build/linux-file-setrlimit-pipeline-final-v3`, with captures `build/linux-file-setrlimit-native-tcg-v1` and `build/linux-file-setrlimit-native-hvf-v1`. Earlier export attempts are diagnostics; the accepted run includes both explicit initializer macro arguments and a summary derived from the live saved NOFILE value. The four new regression cases, seven preflight cases and two affected generation cases passed. Four faulty models were rejected during target execution, and six jointly forged captures plus original-source/ABI tampering were rejected before publication. The generated report is `build/live-syscall-checks/linux-file-setrlimit-validation.json`.

Milestone revalidation on October 19, 2026 passed all thirteen focused cases: four `file-setrlimit` checkpoint cases, seven preflight cases and the two affected `file-limits`/`file-rlimit` generation cases. The two CTest suites completed in 56.56 seconds. Offline verification passed for all 35 retained workflows, including the accepted `file-setrlimit` pipeline. All-profile preflight confirms 35 profiles and 39 distinct routes, with `file-setrlimit` covering the union. An evidence audit matched 26 recorded source/artifact hashes and confirmed equality of the retained TCG/HVF entry state and all 973 call observations. The checkpoint suite rebuilt and executed replay images in QEMU; native captures were reused from October 17. RTL/timing validation and native-kernel source-build attestation remain unverified. The fresh summary is `build/linux-milestone-validation-20261019.json`; its artifact hashes bind the suite log/XML, affected-case logs, preflight, workflow verification and evidence audit.

To repeat the focused milestone checks:

```sh
ctest --test-dir build/live-syscall-checks -j1 --output-on-failure \
  -R '^(freestanding_linux_aarch64_file_setrlimit_checkpoint|linux_aarch64_preflight)$'
python3 tests/test_linux_aarch64_file_limits_checkpoint.py \
  LinuxFileLimitsTests.test_original_sources_generated_witness_and_entry_seeded_limits
python3 tests/test_linux_aarch64_file_rlimit_checkpoint.py \
  LinuxFileRlimitTests.test_generated_witness_original_wrapper_and_complete_route_union
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --verify build/linux-file-setrlimit-pipeline-final-v3
```

The `minimal` profile covers 20 calls across ten Linux AArch64 syscalls:

| Syscall | Number | Verified effect |
| --- | ---: | --- |
| `umask` | 166 | Return old mask, retain new mask, mask to `0777`, truncate the native `int` argument |
| `getpid` | 172 | Return current task's thread-group ID |
| `getppid` | 173 | Read parent thread-group ID with balanced RCU boundaries |
| `getuid`, `geteuid` | 174, 175 | Return real/effective user IDs |
| `getgid`, `getegid` | 176, 177 | Return real/effective group IDs |
| `gettid` | 178 | Return current thread ID |
| `getresuid` | 148 | Write real/effective/saved user IDs, including aliased destinations and partial `EFAULT` output |
| `getresgid` | 150 | Write real/effective/saved group IDs, including first/third destination faults |

The application uses x8 for the syscall number, x0–x5 for arguments and x0 for the raw result. The capture process starts as PID 1, prepares user IDs `(1001, 1002, 0)` and group IDs `(2001, 2002, 2003)`, and sets the initial mask to `022`. Credential preparation, output and poweroff are capture infrastructure; they are outside the ten replay roots. The guest observes the mask after each call through `umask` probes that restore the observed value. This is a syscall-observed state projection, not a physical kernel-memory checkpoint.

The original definitions come from [Linux v6.10 `kernel/sys.c`](https://raw.githubusercontent.com/torvalds/linux/v6.10/kernel/sys.c), with numbers pinned from [its generic syscall ABI](https://raw.githubusercontent.com/torvalds/linux/v6.10/include/uapi/asm-generic/unistd.h). Reviewed excerpts retain their SPDX identifiers and source attribution under `integrations/linux_aarch64/upstream/`. `source-identity.json` pins every selected definition and both excerpt files. Preparation expands the `SYSCALL_DEFINE` wrappers into ordinary C signatures; it preserves the original bodies and their control flow.

The `credentials` profile adds `setresgid` (149), retaining its original ordinary helper `__sys_setresgid` and syscall wrapper under `integrations/linux_aarch64/credentials/`. Its 42-call recipe covers unprivileged changes among the current real/effective/saved group IDs, `-1` arguments, unchanged requests, denied changes (`-EPERM`), 32-bit argument truncation, filesystem-group updates, later group queries and partial user-copy faults after changes. Five successful calls change the credential object; denied and unchanged calls leave it intact. User IDs stay fixed in this profile.

Native credential evidence includes private `getresgid` probes and `setfsgid(-1)` probes after every application call. The latter returns the filesystem group ID without changing it. These probes use separate memory from the application witness. Native results, group IDs, filesystem group IDs and masks are checked independently before exporting slices. Credential-pool slots and generation counters are model bookkeeping, not measurements of Linux's allocator or physical credential objects.

The `fsgid` profile extends that recipe to 62 calls across twelve roots by adding original Linux `setfsgid` (152) and its `__sys_setfsgid` helper. It tests changes to the filesystem group ID while real/effective/saved group IDs stay unchanged, old-value returns, silent permission denial, invalid `-1` probes, unchanged requests, 32-bit truncation and later `setresgid` calls that restore the filesystem group ID to the effective group ID. Native return values alone cannot distinguish successful, denied and unchanged requests; the post-call filesystem-group probe provides that distinction.

The `group-setters` profile extends the recipe to 94 calls across fourteen roots with original Linux `setgid` (144), `setregid` (143) and their ordinary helpers. It checks unprivileged permission rules, saved-ID replacement and preservation, invalid `setgid(-1)` requests, argument truncation, partial user-copy faults and later loss of access to a dropped saved ID. A denied `setregid` can modify the candidate's real ID before its effective-ID check fails; active native credentials remain unchanged. Successful `setgid` and `setregid` calls can publish copied credentials even when scalar ID values do not change, unlike the early no-op shortcut in `setresgid`.

The `getgroups` profile adds original `getgroups` (158) and its static `groups_to_user` helper from [Linux v6.10 `kernel/groups.c`](https://raw.githubusercontent.com/torvalds/linux/v6.10/kernel/groups.c): 112 calls across fifteen syscall roots. Capture installs an unsorted supplementary list before dropping privileges; Linux returns its sorted values `(4001,4003,4007)`. The recipe checks count-only queries with ignored invalid pointers, undersized buffers, negative sizes, low-32-bit argument truncation, oversized buffers, first-copy faults and faults after one or two successful writes. Scalar group-ID setters leave this supplementary list unchanged, including after their credential copies and publication.

This profile pins both original source excerpts separately. `additional_sources` binds `kernel/groups.c`, and definition hashes cover the static copy helper as well as the syscall. Extraction preserves the helper's return type and static scope, and emits it before its caller; the shared Clang analyzer discovers and contextualizes its direct dependencies. Neither original body is changed.

Native evidence currently uses the locally available LinuxKit `6.10.14-linuxkit` ARM64 Image and its embedded configuration. The manifest records the Image/config hashes and actual release. The selected upstream v6.10 bodies are behaviorally checked against this kernel. An exact source rebuild of the native binary is not attested; `native_source_build_attested` is false.

The `setresuid` profile adds original `setresuid` (147), `__sys_setresuid`, `set_user` and `flag_nproc_exceeded` from [Linux v6.10 `kernel/sys.c`](https://github.com/torvalds/linux/blob/v6.10/kernel/sys.c#L646), plus original `set_cred_ucounts` from [its credential implementation](https://github.com/torvalds/linux/blob/v6.10/kernel/cred.c#L544). Its 82 calls exercise real/effective/saved UID changes, effective-root capability drop/regain, keepcaps, ambient clearing on removal of the last root identity, denied foreign IDs, argument truncation and securebit suppression/locks. Private `getresuid` and `setfsuid(-1)` probes observe the active UID tuple and FSUID after every call. Explicit effective-UID requests repair a divergent FSUID; the all-sentinel early no-op preserves it.

The accounting model owns four fixed identities `(1001,0,9001,9002)`. Both credential slots carry typed links to per-user and per-namespace accounting objects. Preparation acquires their references, original helpers switch them when real UID changes, and commit/abort release ownership. Inactive slots retain non-owning snapshots. The native witness explicitly sets and observes an unlimited NPROC limit; replay preserves the original deferred-limit flag helper under this bounded contract. The model's task flags represent the selected NPROC flag, not a physical snapshot of every Linux task flag. These links and counts model selected credential ownership, rather than Linux slab or RCU lifetimes. Allocation exhaustion, other accounting identities, exec/fork and external accounting consumers are outside this profile.

The `uid-setters` profile adds original `setuid` (146), `setreuid` (145) and their ordinary helpers from [Linux v6.10 `kernel/sys.c`](https://github.com/torvalds/linux/blob/v6.10/kernel/sys.c#L515), for 93 calls across nineteen routes. Privileged `setuid` replaces real/effective/saved IDs; without effective `CAP_SETUID`, it admits the current real or saved ID and changes only effective UID and FSUID. `setuid(-1)` is invalid. `setreuid` admits real-ID changes to the old real/effective IDs and effective-ID changes to any old real/effective/saved ID. It replaces the saved ID when a real argument is supplied or an explicit effective argument differs from the old real ID. Same-ID and all-sentinel `setreuid` requests publish a copy and repair FSUID, while `setresuid` retains its early no-op shortcut.

A failed `setreuid` can change the inactive copy's real and effective fields before rejecting permission. Its user/accounting links remain from the copied active credential because the original `set_user` and `set_cred_ucounts` calls occur later. Replay preserves these scalar/link differences and releases candidate ownership on abort. The checker and raw checkpoint decoder use explicit expected links rather than infer inactive links from a partially changed UID. Three pauses retain such aborted copies, and later calls overwrite them through normal credential preparation.

The `credential-setters` profile combines all four UID setters and all four GID setters with supplementary lists, capabilities and securebits: 98 calls across twenty-three routes. It reuses the eight previously pinned original `setgid`, `setregid`, `setresgid`, `setfsgid` wrapper/helper definitions. Unlike the older `group-setters` profile, admission observes live effective `CAP_SETGID`. Privileged `setgid` replaces real/effective/saved/filesystem GIDs; privileged RE/RES/FS operations can select unrelated group IDs. Unprivileged requests retain the original old-ID permission rules and denial ordering.

UID/GID fields, list links, capability sets and UID-keyed accounting share one evolving credential pool. Every preparation copies scalar GIDs along with UID state, including preparations for capset, prctl, list replacement and filesystem UID changes. Group setters preserve supplementary IDs, user/accounting identity and capabilities under the reviewed successful group-ID LSM contract. Dropping effective UID zero clears effective `CAP_SETGID` and denies later foreign group/list changes. Regaining it restores only permitted capabilities; after permanent permitted `CAP_SETGID` removal, GID and supplementary-list admission stays restricted. FSUID capability changes leave the nonfilesystem `CAP_SETGID` bit intact. The recipe observes these differences in the same session.

## Automated workflow

Before supplying another kernel, run the preflight without booting it:

```sh
python3 tools/preflight_linux_aarch64.py \
  --profile all --kernel-image /path/to/arm64/Image --check-tools \
  --llvm-bin /path/to/llvm/bin --qemu qemu-system-aarch64 \
  --out build/linux-kernel-preflight.json
```

Use `--profile file-setrlimit` to check just the complete combined profile. Without `--kernel-image`, the command audits local profile inputs only; `--config` supplies a configuration when the Image has none embedded. `--accel tcg` is the default, and `--accel hvf` checks that the QEMU binary offers HVF. Tool checks are optional and run only with `--check-tools`.

The JSON report includes source-definition hashes, syscall numbers and arities checked against the pinned ABI, recipe call counts, generated-witness checks, model-input hashes, required builtin configuration, kernel identity and requested tool versions. It discovers the route union from the validated profiles and identifies profiles covering it. An all-profile audit also rejects differences between the command registry and profile directories. The current inventory is 35 profiles and 39 distinct routes, all combined by `file-setrlimit`. Capture uses the same profile configuration check, including the 4 KiB guard-page and SHMEM/MEMFD requirements. Missing, modular, contradictory and comment-only builtin settings reject before capture creates an output directory.

Exit status zero means the requested construction checks passed. Failed checks return one and can be saved as a JSON report; an existing report is never overwritten. `inputs_validated` means no kernel was checked; `prerequisites_validated` means the supplied Image/configuration also passed the prerequisites. Neither status verifies native syscall behavior or attests a source rebuild. In particular, these checks do not extend the reviewed argument domains or extend resource updates beyond their reviewed contracts. The native capture and full QEMU replay/resume pipeline below remain required for a new kernel.

The preflight passed for all 32 profiles against the available LinuxKit 6.10.14 Image and local LLVM/QEMU tools. Seven regression cases passed, including tampered inputs, registry drift and rejection of missing or forged builtin configuration before capture publication. A fresh `file-credentials` capture reproduced all 821 earlier observations; its complete QEMU pipeline passed 32 executions and six resume boundaries. All 32 earlier workflows also passed offline verification. Evidence is `build/linux-aarch64-preflight-native-final-v2.json`, `build/linux-preflight-file-credentials-pipeline-final-v1/` and `build/live-syscall-checks/linux-aarch64-preflight-validation.json`. Syscall coverage and replay bounds are unchanged.

Run native capture, portable bundle preparation, kernel export, four-mode verification and the C checkpoint chain with one command:

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --kernel-image /path/to/arm64/Image \
  --out build/my-linux-aarch64-pipeline
```

Select user credential transitions with `--profile setresuid`:

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile setresuid --kernel-image /path/to/arm64/Image \
  --timeout 600 --out build/linux-setresuid
```

The witness generator supports this profile too. The same reviewed recipe binds all three unsigned UID arguments, input bytes, syscall routes and expected post-call state. NPROC setup/query and final poweroff belong to native capture infrastructure and are excluded from the replay roots.

Select all four scalar user-ID setters with `--profile uid-setters`:

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile uid-setters --kernel-image /path/to/arm64/Image \
  --timeout 600 --out build/linux-uid-setters
```

This generated witness mixes ID/RE/RES/FS setters with capability, securebit and group-list calls. It checks privileged and unprivileged paths, saved-root restoration, partially changed inactive credentials, high-word argument truncation, keepcaps, locked fixup suppression and live UID output after changes. Successful accounting changes visit all four fixed identities. Group IDs remain fixed; supplementary lists can change when the evolving effective capability set permits it.

Select the combined user/group credential workload with `--profile credential-setters`:

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile credential-setters --kernel-image /path/to/arm64/Image \
  --timeout 600 --out build/linux-credential-setters
```

Capture binds active real/effective/saved GIDs and FSGID after every call through the existing private probes. The generated witness includes privileged group changes, missing/permanently removed SETGID admission, UID-driven capability changes, supplementary-list replacement, filesystem-ID repair, low-32-bit truncation and partial/aliased group output. The two credential slots, group-list pools and user/accounting graph use the existing portable policy and layout.

Select mutable credentials with the same pipeline:

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile credentials --kernel-image /path/to/arm64/Image \
  --out build/my-linux-credentials-pipeline
```

Use `--profile fsgid` to include filesystem-group changes, or `--profile group-setters` for all four scalar group-ID setters. The native-capture command accepts the same profile choices. Bundle preparation and capture reuse infer the profile from the pinned native observations. An explicitly requested mismatching profile is rejected. Omitting the profile for a new native capture retains the original `minimal` profile.

Select supplementary-list queries with `--profile getgroups`. Its native guard-page fixture requires `CONFIG_ARM64_4K_PAGES=y`, checked before constructing output. The same supplied-Image capture, bundle, slice and checkpoint pipeline handles this profile.

Select supplementary-list replacement with `--profile setgroups`. This separate profile supplies twelve roots: the ten baseline getters/mask operations plus original Linux `getgroups` (158) and `setgroups` (159). It retains the original `groups_to_user`, `groups_from_user`, `set_groups`, `set_current_groups` and `may_setgroups` helpers. Its 56-call C workload replaces unsorted lists, preserves duplicates, clears lists, accepts valid IDs including zero and `UINT32_MAX-1`, checks signed/unsigned size truncation, and verifies read/write faults after partial copies. Native capture retains effective UID zero and `CAP_SETGID`, with UID tuple `(1001,0,0)` and GID tuple `(2001,2002,2003)`. The scalar group setters from the unprivileged profiles are excluded from this separate recipe.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile setgroups --kernel-image /path/to/arm64/Image \
  --timeout 600 --out build/linux-setgroups
```

The same guard-page setup checks native input reads as well as output writes. Each call records its input words separately from output, and private post-call probes observe the full current supplementary list. Replay reads live user memory through the bounded `get_user` model; it does not assign the recorded output as a substitute for syscall execution.

Select missing-capability rejection with `--profile setgroups-denied`. Its 60-call workload uses the same twelve roots and adds requests with counts five, `NGROUPS_MAX` (65536) and `INT32_MIN`. Native setup drops effective UID to 1002 and observes the effective `CAP_SETGID` bit with version-three `capget` before the workload and after every call. All 21 `setgroups` requests return `EPERM`, including zero counts, invalid IDs, inaccessible pointers and invalid sizes. Original Linux `may_setgroups` rejects these requests before size validation, allocation or user copying. Later getters and mask updates still execute in the same session. The [Linux capability UAPI](https://raw.githubusercontent.com/torvalds/linux/v6.10/include/uapi/linux/capability.h) and `capget` number are pinned with the capture ABI; these private probes belong to capture infrastructure and are excluded from replay roots.

Select capability transitions with `--profile capabilities`. This 64-call profile supplies thirteen roots: the baseline ten, `getgroups`, `setgroups`, and original `capset` (91). It retains `cap_validate_magic` and `mk_kernel_cap` from [Linux v6.10 `kernel/capability.c`](https://raw.githubusercontent.com/torvalds/linux/v6.10/kernel/capability.c), plus `cap_inh_is_capped` and `cap_capset` from [Linux v6.10 `security/commoncap.c`](https://raw.githubusercontent.com/torvalds/linux/v6.10/security/commoncap.c). The workload drops effective `CAP_SETGID`, observes `setgroups` denial, regains the effective bit from the permitted set, and successfully replaces the list again. Later it permanently drops the permitted bit, rejects attempts to regain it, and verifies inheritable-set restrictions. All calls share one evolving credential/list context.

Select application capability queries with `--profile capget`. It interleaves 21 original `capget` (90) calls with the 64-call capability/list workload, supplying 85 calls across fourteen roots. It retains original `cap_get_target_pid` and commoncap `cap_capget` helpers from the same reviewed source files. Application output contains the live effective, permitted and inheritable sets after drops, regains and permanent removal. Version-one queries copy only the low three words; version-two/three queries copy six words. Bounding and ambient sets remain part of the persisted context and native state observations, but the capget ABI does not return them.

The query recipe checks self PIDs zero/one, negative-PID `EINVAL`, missing-PID `ESRCH`, NULL/bad headers, protected-page output faults and aliased header/output buffers. NULL output stops after version validation: an unsupported version is rewritten to version three and returns success, while a non-NULL output returns `EINVAL`. Valid-version NULL queries ignore negative or inaccessible PID fields. A real native fault after the first eight output bytes is reproduced by the bounded copy model and then checked on both native QEMU accelerators. The missing PID is `INT32_MAX`, which cannot identify a live task; this profile does not model arbitrary foreign task lookup or visibility rules.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile capget --kernel-image /path/to/arm64/Image \
  --timeout 600 --out build/linux-capget
```

Select capability process control with `--profile prctl`. Its 92-call workload adds syscall 167 to the fourteen getter/list/capability routes, for fifteen routes in total. It executes original `cap_task_prctl` and `cap_prctl_drop` from [Linux v6.10 commoncap](https://github.com/torvalds/linux/blob/v6.10/security/commoncap.c#L1160). The adapter admits only `PR_CAPBSET_READ`, `PR_CAPBSET_DROP`, `PR_CAP_AMBIENT`, `PR_GET_SECUREBITS`, `PR_SET_SECUREBITS`, `PR_GET_KEEPCAPS` and `PR_SET_KEEPCAPS`, with all five arguments checked. The original general `sys_prctl` wrapper is not exported. Its initial dispatch and short-circuit return are pinned as routing evidence in `upstream/kernel/prctl-dispatch-prefix.txt`; the reviewed dependency model assumes other LSM hooks allow the admitted operations.

Native preparation adds effective/permitted `CAP_SETPCAP` to `CAP_SETGID | CAP_SYS_BOOT`. Original code drops bounding bits, raises/lowers/clears ambient bits, changes securebits and enforces irreversible locks. Dropping the bounding `CAP_SETGID` bit leaves its existing effective, permitted, inheritable and ambient bits usable: a later `setgroups` still succeeds. Removing its inheritable bit through `capset` clears ambient and prevents subsequent restoration outside the reduced bounding set. A separate sequence denies bounding drops without effective `CAP_SETPCAP`, restores that effective capability from permitted, locks ambient raising and keepcaps, and then permanently removes permitted `CAP_SETPCAP`. Reserved ambient arguments three/four/five, unknown operations, invalid capability indices, privilege-before-index ordering and repeated successful no-op publication are checked against native Linux. Private `PR_GET_SECUREBITS` probes bind the securebit state after every call; they run only during capture.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile prctl --kernel-image /path/to/arm64/Image \
  --timeout 600 --out build/linux-prctl
```

Select filesystem user-ID changes with `--profile fsuid`. This 84-call profile adds original `setfsuid` (151) and `__sys_setfsuid` to the capability/list/process-control port, supplying sixteen syscall routes. It retains original `cap_task_fix_setuid` and `cap_emulate_setxuid` from [Linux commoncap](https://github.com/torvalds/linux/blob/v6.10/security/commoncap.c#L1057), and `cap_drop`, `cap_drop_fs_set` and `cap_raise_fs_set` from [the kernel capability header](https://github.com/torvalds/linux/blob/v6.10/include/linux/capability.h#L109). The filesystem set includes eight bits, including `CAP_LINUX_IMMUTABLE` and high-word `CAP_MAC_OVERRIDE`. Selected original inline definitions, filesystem masks and added UAPI capability numbers are pinned separately from the syscall and security source excerpts.

Native setup retains real/effective/saved UIDs `(1001,0,0)`, starts FSUID at zero and supplies effective/permitted filesystem capabilities plus `CAP_SETUID`, `CAP_SETGID`, `CAP_SETPCAP` and `CAP_SYS_BOOT`. The workload changes FSUID to real UID 1001, uses `CAP_SETUID` to select unrelated UID 9001, drops that effective permission and verifies silent denial. Every setter returns its previous FSUID, including denied and unchanged requests, so private `setfsuid(-1)` probes observe the resulting FSUID after every call. Invalid `-1` probes return before credential preparation; valid unchanged and denied requests prepare and abort a copy without publication. Low-32-bit truncation is checked for nonroot, zero and invalid arguments.

Changing FSUID from zero to nonzero normally clears the filesystem set from effective capabilities; changing it back to zero restores only filesystem bits present in permitted. This leaves real/effective/saved UIDs, supplementary groups, inheritable and ambient sets unchanged. The recipe verifies high-word `capget` output, ambient preservation, later ambient removal through `capset`, permanent permitted-bit removal, and continued denial of `setgroups` after its nonfilesystem effective permission was removed. `SECURE_NO_SETUID_FIXUP` suppresses filesystem capability drop/regain; a locked version of that flag survives restoration and rejects later unlocking. Only the filesystem branch of the original setuid security helper is admitted; real/effective/saved UID changes and exec are excluded.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile fsuid --kernel-image /path/to/arm64/Image \
  --timeout 600 --out build/linux-fsuid
```

The C witness is generated from the same named recipes, input seeds and reviewed port argument kinds. Pointer conversion is derived from each route's `buffer` arguments. This removes the separate handwritten argument/seed tables for new profile construction. Capture rejects a stale generated filesystem-user witness before producing output; the resulting C source is pinned in native evidence and the portable bundle. The generator can also emit witnesses for the existing Linux profiles without changing their retained sources:

```sh
python3 tools/generate_linux_aarch64_application.py \
  --profile fsuid --out build/generated-fsuid-application.c
```

For `capabilities` and `capget`, native preparation narrows effective and permitted sets to `CAP_SETGID | CAP_SYS_BOOT`, leaves inheritable and ambient sets empty, and observes the full 41-bit bounding set. `CAP_SYS_BOOT` remains in the admitted sets to terminate native capture. Private `capget` and `prctl` probes record effective, permitted, inheritable, bounding and ambient sets after every call. Those probes are capture infrastructure; the replay roots contain `capset`, with no native probing or host service. The recipe also covers version-one/two/three formats, invalid-version writeback, self-PID selection, foreign-PID rejection before data access, header/data copy faults, identical successful publication and masking of invalid high capability bits.

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile capabilities --kernel-image /path/to/arm64/Image \
  --timeout 600 --out build/linux-capabilities
```

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --profile setgroups-denied --kernel-image /path/to/arm64/Image \
  --timeout 600 --out build/linux-setgroups-denied
```

The capture requires an uncompressed ARM64 Image and a matching configuration. It reads embedded `IKCFG_ST`/`IKCFG_ED` configuration data when available; otherwise supply `--config /path/to/.config`. Builtin ARM64, multiuser, ELF loading, ext4, virtio block and PL011 console support are checked before boot. QEMU `virt`, one Cortex-A53 CPU, TCG and 512 MiB RAM are the defaults. `--timeout` bounds capture; `--accel hvf` can accelerate capture on compatible macOS hosts. Slice and application verification use the existing Cortex-A53/TCG machinery independently of capture acceleration.

Capture generates a readonly 2 MiB root filesystem containing `/init` and `/dev/console`. The filesystem builder needs no host mounting, device-node privileges, Docker daemon or external `mkfs`. The init executable uses native Linux `svc` instructions. Output uses the emulated UART, and native reboot/PSCI powers the VM off. Unexpected reboots stop the runner and incomplete captures fail. This disk belongs to native capture only; the exported slice images do not load it.

For `getgroups`, the 32-byte caller witness occupies the last 32 bytes of a page, followed by a dedicated page inside its ELF allocation. Native capture protects that second page with `mprotect(PROT_NONE)` before executing the application. This makes writes beyond the witness produce real Linux partial `EFAULT` observations. These setup calls belong to capture infrastructure. Replay uses the existing bounded `put_user` memory contract and needs no MMU fault handler or host service. Private post-call `getgroups` probes use a separate stack buffer and bind the full supplementary list to the observations.

Individual stages can also be run and verified separately:

```sh
python3 tools/capture_linux_aarch64.py \
  --kernel-image /path/to/arm64/Image --out build/my-linux-native
python3 tools/prepare_linux_aarch64_port.py \
  --capture build/my-linux-native --out build/my-linux-port
python3 tools/export_syscall_slices.py \
  --capture build/my-linux-native --port build/my-linux-port/port.json \
  --out build/my-linux-slices
python3 tools/verify_syscall_slices.py \
  --image build/my-linux-slices --out build/my-linux-slices-qemu
python3 tools/run_c_application_checkpoint_chain.py \
  --slices build/my-linux-slices --source build/my-linux-port/application.c \
  --spec build/my-linux-port/spec.json --pause-ordinals 8,15,19 \
  --out build/my-linux-chain
python3 tools/run_c_application_checkpoint_chain.py --verify build/my-linux-chain
```

Reuse a verified native capture without booting again:

```sh
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --capture build/my-linux-native --out build/my-linux-aarch64-pipeline
python3 tools/run_linux_aarch64_checkpoint_pipeline.py \
  --verify build/my-linux-aarch64-pipeline
```

Choose new output directories. The portable bundle pins the adapter, original definitions, models, policy, application, proof and complete native capture evidence. Construction verifies raw returns, copied bytes, mask transitions, source identities and native artifact hashes before publishing. The package's retained inputs support later composition and offline verification after deleting the original capture directory. The workflow report hashes every retained artifact and checks saved state against native observations.

## State and gateway

The shared Clang analyzer automatically owns the projection's mutable objects and threads the context through direct calls. Original syscall bodies reach their modeled `current`, credential helpers, `xchg` and `put_user` dependencies through that context. Each session reconstructs the initial seeds once; calls keep preceding updates.

| State | Checkpoint policy |
| --- | --- |
| Mask, task/parent IDs, credential values, initial-namespace marker | Persisted scalar fields |
| Current-task, filesystem, parent and namespace links | Fixed context references reconstructed at destination addresses |
| Active credential link | Fixed in `minimal`; typed slot IDs 1/2 in mutable-credential profiles |
| Supplementary count/list and both credential links, in `getgroups` | Persisted count and four-ID capacity; links rebound to the shared local group object |
| Invocation memory view, RCU depth, unused parent links | Transient; reconstructed and required quiescent at boundaries |

The `minimal` context is 136 bytes; its portable record is 112 bytes, comprising a 64-byte header and 48 scalar payload bytes. Native kernel addresses and structure padding are not serialized. This port supplies projected model types, not Linux's physical `task_struct` or `cred` layout.

Mutable credentials use two reusable slots. `prepare_creds` copies the active slot into the inactive one; the original Linux helper validates and updates the candidate; `commit_creds` publishes it through `current->cred`. No allocation is pending at a checkpoint boundary. The active link uses the shared typed `context_reference` policy with non-null wire IDs 1 and 2. Both slots' scalar fields and generation counters are persisted; namespace links are rebound locally, and the pending candidate is transient. Restore therefore reconstructs whichever slot was active at the pause, at its new destination address. This profile has a 216-byte context and a 184-byte record (64-byte header plus 120-byte payload).

`setfsgid` prepares a candidate before checking permissions or unchanged valid IDs. On these aborted requests, the model's inactive slot contains the copied active credentials, but the active pointer and publication generations do not change. `abort_creds` must release the pending candidate before the boundary. Invalid `-1` probes return before preparation. The `fsgid` profile persists both slots, including these inactive copies, using the same 216-byte context and 184-byte record. These are reviewed pool semantics, not a reconstruction of native allocator addresses or freed objects.

The `group-setters` profile uses that same layout. A candidate partially modified before `setregid` denial remains in the inactive model slot; abort releases its pending status without publishing it. Its generation still records the last successful publication, not preparation or partial modification. Both slot contents therefore need independent restoration checks, even when native active IDs and the syscall errno show no state change. The inactive contents are modeled pool bookkeeping; Linux's physical aborted allocation is not captured.

The `getgroups` profile adds one `group_info` object with a persisted signed count and four 32-bit slots. Both credential slots link to that same object through fixed self references. Its three populated IDs and zero unused slot survive copies, aborts, publication and fresh-image restoration. The context is 256 bytes and the record is 204 bytes (64-byte header plus 140-byte payload). The model omits Linux's flexible allocation and reference counter: queries borrow the fixed current list, and the supported scalar setters only copy its link.

The `setgroups` profile supplies two reusable list objects of capacity four. Both credential slots hold typed context references with wire IDs 1 or 2, rebound to the destination context's local objects on restoration. List counts, all ID cells and model reference counts are persisted. Preparing credentials acquires the old-list reference; original `set_groups` releases that reference and acquires the new list; publication releases the retired active reference; the original syscall releases its caller allocation reference. A failed input copy releases the allocation without publication. At a call boundary exactly one list has usage one, and the other has usage zero. Freed list cells retain their last partial contents until the next allocation zeroes them, so failure checkpoints verify both objects, not only the active list.

Inactive credential slots are non-owning last-copy snapshots and may point to a freed or reused list slot. Their pointers and generations are model bookkeeping, not Linux's physical retired credentials. These modeled references represent admitted sequential ownership; they do not reproduce Linux's objective/subjective credential counts or RCU reclamation. Sorting is a reviewed bounded insertion-sort primitive replacing Linux's generic sort/comparator dependency. The context is 296 bytes; the wire record is 252 bytes (64-byte header plus 188-byte payload). Namespace `setgroups_allowed` is persisted as enabled; pending credential/allocation pointers and user-memory bindings are transient and must be cleared at each boundary.

The `setgroups-denied` profile adds one persisted effective `CAP_SETGID` bit to each credential slot. Its permission model consults the active credential's observed bit. The context is 312 bytes and its record is 260 bytes (64-byte header plus 196-byte payload). Both bits remain zero, both credential links select the initial group object, and all pool references, generations and list cells remain unchanged on rejection. The capability bit is a selected dependency, not a full Linux capability-set or namespace-security model. In this profile the list allocator, credential preparation and security-fix hook are never reached.

The `capabilities` profile stores five 64-bit capability sets in each credential slot. Original commoncap code validates permitted/effective/inheritable subsets and masks the ambient set. Reviewed bitwise primitives implement combine, intersection and subset checks; namespace capability checks use the active effective set. Capability setters copy the same supplementary-list reference and balance it on commit or abort, while list setters copy the current capability sets. A denied capset after credential preparation refreshes the inactive snapshot without advancing its epoch or publishing it. The context is 376 bytes and the wire record is 332 bytes (64-byte header plus 268-byte payload). All ten capability fields, both lists, both list links and all credential generations survive fresh-image restoration. The copied capability ABI header is included in the owned header closure and schema identity.

The `capget` profile uses that same 376-byte context and 332-byte record. Queries borrow the active credential and balance RCU without allocating, publishing, changing list references or advancing credential generations. Its reviewed self-task security wrapper calls original commoncap `cap_capget`; the finite task lookup model returns no task for the admitted missing PID. A bounded `copy_to_user` primitive writes caller memory and returns the remaining byte count on a fault. This contracts the observed aligned 32-byte witness cases; it is not a general implementation of Linux's architecture-dependent copy/fault handling. Every query checks return bits, copied bytes and unchanged context state before the next call can proceed.

The `prctl` profile adds a persisted 32-bit securebits field to both credential slots, alongside the five capability sets. Its context is 392 bytes and its portable record is 340 bytes (64-byte header plus 276-byte payload). `prepare_creds` copies securebits as well as capability/list state, and original process-control code publishes successful changes through the same credential lifecycle. Denials leave active state and generations unchanged; capset denials can still refresh the inactive snapshot. Reviewed prctl and securebits UAPI macro excerpts join the owned header closure. Capability checks consult the active effective set; audit effects and the `PF_SUPERPRIV` hint have no consumer in the admitted sequential domain.

The `fsuid` profile uses the same 392-byte context and 340-byte wire record. Both credential slots already contain a persisted FSUID; it now changes and is independently checked alongside capability sets and securebits. The security wrapper validates the prepared candidate and admits `LSM_SETID_FS` before calling original commoncap code. UID mapping uses the initial namespace, and permission checks use the current effective `CAP_SETUID`. Successful filesystem changes use the existing credential/list reference lifecycle. No VFS access checks, real/effective/saved user changes, allocation failures or additional rejecting LSM hooks are modeled.

Imported application `svc` sites become `brk #0x5353`. The embedded EL1 gateway saves the live EL0 frame, validates the site/ordinal, reads live registers and dispatches against the same session. A successful syscall, including a negative errno return, updates the result register and advances PC by four before `eret`. At a requested boundary, it saves the pre-next-syscall frame and returns to the container. Fresh-image restoration reconstructs seeds, overlays saved scalars, rebinds links and validates the destination context before continuing.

The default chain is 0 → 8 → 15 → 19 → 20. Saved masks are `077`, `002` and `022`; real/effective/saved credentials remain intact. Resumed intervals load twice into different contexts. Kernel proof plus four chain images run ELF/raw × EL1/EL3, yielding 20 matrix executions.

The credential chain is 0 → 8 → 23 → 26 → 35 → 41 → 42, yielding 28 matrix executions. At ordinals 23, 26 and 35, active wire IDs are 2, 1 and 2, and generations are 1, 2 and 5. Group tuples are `(2001,2001,2003)`, `(2003,2003,2001)` and `(2001,2001,2003)`. The following calls query the restored credentials, and later calls change them again. The workflow decodes both slots and the active link directly from each saved record, comparing the active scalar state with native observations and all pool bookkeeping with the independent transition projection.

The filesystem-group chain is 0 → 43 → 46 → 48 → 54 → 58 → 61 → 62, yielding 32 matrix executions. Saved filesystem group IDs are `2003,2003,2001,2001,2003,2003`; active wire IDs are `1,1,2,2,1,1`, with generations `6,6,7,11,12,12`. The pause at 46 preserves an aborted candidate copy without advancing its generation. At 54 the filesystem group ID differs from the effective group ID; a later `setresgid` repairs it even when the requested effective ID equals the current one. At 58 an unchanged valid request has refreshed the inactive copy without publication.

The group-setter chain is 0 → 63 → 67 → 70 → 80 → 87 → 93 → 94, also yielding 32 matrix executions. Active wire IDs are `2,2,2,1,2,2`, with generations `13,13,15,22,27,27`. At 67, inactive slot 0 has real GID 2001 while active slot 1 still has real GID 2003 after a denied request. At 80, the effective GID 2003 matches neither real nor saved GID, so `setgid(2003)` has been denied. At 87 all three IDs have become 2001; the next calls verify that former saved GID 2003 can no longer be regained. The final record contains copied slots with identical values but different last-publication generations.

The supplementary-query chain is 0 → 67 → 95 → 100 → 106 → 109 → 111 → 112, yielding 32 matrix executions. Active wire IDs are `2,2,2,1,2,2`, with generations `13,27,27,28,29,29`; every saved supplementary list is `(4001,4003,4007)`. Later queries read the restored list after both credential slots have become active in turn. The workflow decodes its count and all four list slots from each raw record and compares them with native post-call observations.

The supplementary-replacement chain is 0 → 27 → 31 → 33 → 37 → 43 → 50 → 56, yielding 32 matrix executions. Saved active lists are `(7001,7001,7003,7007)` at the first three pauses, then empty, `(0,4294967294)` and `(4001,4003)`. Generations are `3,3,3,4,7,9`. Pauses 31 and 33 retain partial input-copy and invalid-ID allocation contents in the free list without changing active credentials. The empty-list pause is followed by a positive-size NULL query that succeeds without accessing memory. Subsequent setters replace the restored list again, including successful publication of identical list values. The workflow independently decodes both list objects, both credential links, active credentials and generations from every raw record.

The permission-denied chain is 0 → 22 → 31 → 35 → 40 → 53 → 59 → 60, yielding 32 matrix executions. Every record preserves the initial list `(4001,4003,4007)`, active credential ID 1, both group-object IDs 1, zero capability bits and zero generations. The record at 53 preserves mask `077` after a mask update followed by a denied setter; the final pause restores `022`. A denied clear leaves the list nonempty, so its later positive-size NULL query returns `EFAULT`. A denied one-ID replacement leaves length three, so its later one-slot query returns `EINVAL`. The independent raw decoder compares both persisted capability bits with native post-call observations and checks every credential/list pool cell.

The capability-transition chain is 0 → 23 → 27 → 35 → 43 → 52 → 58 → 64, yielding 32 matrix executions. Generations are `2,4,6,9,14,16`. Saved lists are `(5001,5005,5009)`, `(6001,6003)`, `(7001,7001,7003,7007)`, empty, `(9001)` and `(9001)`. The first pause has dropped the effective group capability but retains it in permitted; the next interval denies a setter, regains permission and replaces the list. The pause at 52 has removed the permitted group capability, so subsequent attempts to restore it are denied. The pause at 58 has also removed the inheritable bit; a later attempt to add it fails. Each record independently decodes both slots' five capability sets and compares active sets with native observations, including copied inactive state after aborts.

The application-query chain is 0 → 24 → 28 → 54 → 61 → 71 → 78 → 85, yielding 32 matrix executions. Generations are `2,3,7,9,14,16`; queries themselves leave all credential/list state unchanged. Pauses 24 and 28 resume immediately before queries of dropped and regained effective state. Pause 54 follows a partial output fault. Pause 61 precedes a query that overwrites its own already-read header. Pauses 71 and 78 resume before queries of permanently reduced permitted and inheritable sets. The original 64 mutation/getter calls retain their relative order and capture inputs; only explicit query calls are interleaved, so historical recipes remain unchanged.

The capability-prctl chain is 0 → 28 → 43 → 50 → 75 → 83 → 88 → 92, yielding 32 matrix executions. Generations are `2,7,9,24,25,26`. The first pause retains ambient `CAP_SETGID`; the second additionally retains its dropped bounding bit. At 50, an attempted inheritable restore has failed after ambient removal. At 75, securebits value 240 locks keepcaps and the prohibition on ambient raising; later attempts to unlock or alter those bits fail. At 83, permitted `CAP_SETPCAP` has been dropped, so later privilege regain and bounding mutation fail. At 88, the empty group list retains the same capabilities and locks. Every raw record independently decodes both credential slots' capabilities and securebits, list objects, links and publication generations.

The filesystem-user chain is 0 → 35 → 37 → 44 → 52 → 66 → 71 → 84, yielding 32 matrix executions. Generations are `8,8,12,17,24,28`, and saved FSUIDs are `1001,1001,1001,0,0,1001`. At 35 filesystem effective bits have been dropped while low/high ambient bits remain set; the next interval queries that restored state. At 37 an unrelated-UID request has been denied and its inactive copy remains part of the checkpoint. At 44 the no-fixup securebit has preserved effective filesystem bits after a nonroot change. At 52 a root restoration cannot regain two filesystem bits removed from permitted. At 66 fixup suppression is locked; at 71 a later capset has left only effective `CAP_SYS_BOOT`, and a root change after resume must preserve that restricted set. The raw-record decoder checks both FSUID slots and compares active values with native probes.

The user-transition chain pauses after ordinals `26,40,44,49,58,75`, then finishes at 82, for 32 replay executions. Its publication generations are `4,10,12,16,22,35`. Saved UID tuples are `(1001,1001,0)`, `(0,0,0)`, `(9001,0,0)`, `(1001,1001,1001)`, `(9001,9001,9002)` and `(1001,1001,1001)`. The raw decoder checks both slots' UID/FSUID/capability/securebit values, user/accounting links, ownership counts and task flags. Each resumed interval executes later queries or setters against this restored state.

The complete user-setter chain pauses after ordinals `30,47,53,66,77,87` and finishes at 93, for 32 replay executions. Generations are `8,18,22,33,41,49`, with fifty publications at completion. At 47 an inactive real UID 9002 still links to user/accounting identity 1001. At 53 an inactive tuple `(9001,9002,0)` also retains identity 1001. At 87 an inactive tuple `(1001,9001,1001)` retains identity 9002. Active credentials, ownership counts and publication generations stay unchanged on all three denials. The remaining pauses retain effective capability drop, all-ID replacement with keepcaps, and suppressed real/effective/saved updates.

The combined credential chain pauses after ordinals `40,53,63,75,88,92` and finishes at 98, for 32 replay executions. Generations are `11,19,24,33,40,42`, with forty-three publications at completion. At 40 and 92 the active GID tuple remains `(2001,2002,2003)` while a denied `setregid` leaves inactive real GID 2002; UID/accounting state is copied and balanced. At 53 an effective-UID drop has cleared effective capabilities while GIDs remain zero. At 63 FSGID 2003 differs from effective GID 1001 and survives the RES all-sentinel no-op. At 75 permitted SETGID is permanently absent; at 88 the accounting identity has changed to UID 9002 while group IDs and the single supplementary group 7001 remain intact. A later UID preparation overwrites the aborted inactive GID field through normal copying.

The descriptor chain is 0 → 35 → 39 → 45 → 46 → 52 → 67 → 73, for 32 replay executions. The first pause has all eight slots open and file reference counts `(3,5)`. At 39 slot 5 is closed but its close-on-exec bit remains set; the next allocation clears that stale bit. At 45 both console aliases have been replaced by regular aliases with balanced release. At 46 descriptor 3 is closed while four aliases retain the regular object; resume recreates descriptor 3 from an alias. At 52 a truncated close preserves the stale slot-5 flag for later allocation. At 67 the regular reference count is zero; only the console file remains. The raw decoder checks all 64 pointer IDs, both file objects, the table link, flags, bitmaps, `next_fd` and the fixed resource limit. The context is 768 bytes and the portable record 708 bytes.

`tests/test_linux_aarch64_fd_dup_checkpoint.py` checks generated arguments, original pointer-returning helpers and their lock annotation, all 32 resume modes and 219 returning-proof calls with 146 isolation checks. Dropping lookup reference acquisition, omitting release and failing to clear close-on-exec bits must cause target replay divergence before image publication. Changed original helpers and ABI numbers are rejected. False native close-on-exec observations are rejected even after capture and UART hashes are re-pinned together.

The file-I/O chain pauses after ordinals `30,43,46,68,84,109` and finishes at 118, for 32 replay executions. Saved positions are `32,4,8,8,12,20`; file size is 32 at every pause. The first pause preserves a sparse gap of eight zero bytes. The next two preserve successful four-byte prefixes from partially faulting reads and writes. At 68 descriptor 4 shares the offset just changed by a write through descriptor 3. At 84 descriptor 3 has been closed while four regular aliases survive; resume reads and writes through descriptor 6. At 109 the last regular reference is gone; its data and offset remain an inactive model snapshot. The raw decoder checks all 64 descriptor IDs, both file objects, flags/bitmaps, size, 64 data bytes and shared position against the independent projection, comparing native file observations whenever an alias is live. The context is 888 bytes and the portable record is 812 bytes.

The positioned/truncation chain pauses after ordinals `41,54,60,108,109,135` and finishes at 171, for 32 replay executions. Saved `(size,position)` pairs are `(16,0)`, `(6,32)`, `(0,32)`, `(32,8)`, `(10,8)` and `(8,20)`. The first pause follows a partially faulting positioned write without moving the shared offset. The next two preserve a shortened or empty file with its old position still beyond EOF. At 108 a positioned write through descriptor 4 leaves shared position 8 intact; at 109 a truncate through that alias shortens the file seen by later reads through descriptor 3. At 135 the original descriptor has been closed and a surviving alias truncates below shared position 20. Every raw record independently decodes file/dentry/inode IDs, type/append state, all 64 descriptor slots, contents, size and position. The context is 960 bytes and the portable record 860 bytes.


The descriptor-control chain is 0 → 24 → 34 → 43 → 153 → 184 → 218 → 233, for 32 replay executions. Saved close-on-exec bitmaps are `0x00,0x58,0xc8,0x10,0x28,0x80`, with regular-file reference counts `1,3,5,2,5,0`. At 24 the seed flag has been cleared; at 34 two aliases have their own set flags. At 43 all eight descriptors are occupied even though the allocation hint remains 6. At 153 the original descriptor has a clear flag while its alias remains set. At 184 a surviving alias has recreated descriptor 3 with close-on-exec after the original closed. At 218 the last regular reference is gone and its stale slot-7 bit is retained. Each resume checks the raw descriptor IDs, bitmaps, counts, typed inode links and bounded file contents/size/offset against native observations and the independent transition projection.

The range-close chain is 0 → 49 → 52 → 66 → 241 → 243 → 251 → 267, for 32 replay executions. Saved close-on-exec bitmaps are `0xfffffffffffffff8`, `0xfffffffffffffff8`, `0xffffffffffffffc8`, `0xffffffffffffff80`, `0xffffffffffffff80` and `0xfffffffffffffff8`. Regular reference counts are `5,2,5,1,0,0`; positions are `0,0,0,20,20,20`. At 52 only the original and descriptor 7 survive the middle close. At 66 the holes and allocation hint have been restored while high closed-slot flags remain set. At 241 only descriptor 7 owns the regular file; at 243 the range close releases it. At 251 a close-on-exec range marks those closed slots again without recreating any file reference. Every saved record checks all descriptor IDs, all 64 bitmap bits, counts, inode links and file state through the existing raw decoder.

The metadata chain is 0 → 137 → 146 → 149 → 203 → 258 → 261 → 286, for 32 replay executions. Saved file sizes are `32,0,48,32,32,32`; block counts are `8,0,0,8,8,8`, and positions are `32,32,32,8,20,20`. Pauses 146 and 149 distinguish empty/extended logical size from physical allocation. At 203 an alias observes the same inode after a positioned write. At 258 only descriptor 7 owns the file; at 261 a query after range release has returned `EBADF`. Raw records decode both complete inode metadata objects and their allocation fields, alongside the existing file/dentry links, descriptor graph and bounded contents.


## Verification and bounds

`tests/test_linux_aarch64_checkpoint.py` uses archived real native observations and executes the full returning-slice/gateway/checkpoint pipeline on QEMU. Its native root disk is compressed in the fixture and restored byte-for-byte. Tests reject changed capture/source identities before bundle publication, detect corrupted retained checkpoint data, verify independent sessions and reset, and reject reviewed models that omit mask updates or user-memory copies before kernel image publication. A filesystem format check protects inode and indirect-block offsets used by native boot.

`tests/test_linux_aarch64_credentials_checkpoint.py` archives the credential capture and executes all 28 replay modes. It checks denied/no-op transitions, argument truncation, changed IDs, partial faults, raw checkpoint slot IDs and both pool generations. The kernel proof verifies 126 calls across two interleaved sessions and a reset session, including 84 isolation checks. Mutations that omit credential cloning, publication or correct generation updates fail target proof before image publication. A tampered original helper is rejected; incorrect native filesystem-group observations are rejected even when their JSON and UART artifact hashes are updated together.

`tests/test_linux_aarch64_fsgid_checkpoint.py` covers the 32-mode filesystem-group chain. Its proof verifies 186 calls and 124 isolation checks, including candidate aborts, filesystem/effective-ID divergence and later repair. Models that fail to release aborted candidates or incorrectly reject the admitted filesystem-group security hook fail target proof before publication. A tampered original helper and a falsely reported state change on a silently denied request are rejected, including when capture/UART hashes are re-pinned together.

`tests/test_linux_aarch64_group_setters_checkpoint.py` checks all 32 group-setter replay modes. Its proof verifies 282 calls and 188 isolation checks, including successful publication with unchanged IDs and abort after partial modification. Models that publish a failed candidate or reject either admitted group-setter security hook fail target proof before publication. Changed saved-ID source logic and falsely reported active-state changes on denied requests are rejected, including when JSON/UART hashes are re-pinned together.

`tests/test_linux_aarch64_getgroups_checkpoint.py` checks all 32 supplementary-query replay modes. Its proof verifies 336 calls and 224 isolation checks, including native guard-page partial faults and restoration of the shared list links. Models that drop the group-list link during credential copying or omit supplementary-ID output fail target proof before publication. Changed additional source and falsely reported supplementary-list updates are rejected, including when native JSON/UART hashes are re-pinned together.

`tests/test_linux_aarch64_setgroups_checkpoint.py` checks the 32-mode replacement chain, sorted duplicates, empty lists, maximum capacity, invalid IDs, guarded input faults and model references on both success and failure. Its kernel proof verifies 168 calls and 112 isolation checks. Mutations that lose credential publication, omit list reference acquisition or reverse sorting fail target proof before image publication. Changed original input-copy source and falsely reported active-list changes on failed requests are rejected, including when native JSON/UART hashes are re-pinned together.

`tests/test_linux_aarch64_setgroups_denied_checkpoint.py` checks the 32-mode rejection chain, native capability observations, error precedence, unchanged pool state and continued execution after `EPERM`. Its kernel proof verifies 180 calls and 120 isolation checks. Models that falsely grant the capability or change the credential generation during rejection fail target proof before publication. A changed capability ABI and falsely reported post-call capability changes are rejected, including when native JSON/UART hashes are re-pinned together.

`tests/test_linux_aarch64_capabilities_checkpoint.py` checks the 32-mode transition chain, effective/permitted distinction, irreversible permitted removal, inheritable restrictions, version/error ordering, high-bit masking, list lifetime balance and inactive copies after aborted capsets. Its kernel proof verifies 192 calls and 128 isolation checks. Models that use permitted capabilities to authorize group setters or leak a prepared candidate's list reference on abort fail target proof before publication. Changed original commoncap restrictions and falsely reported regained capabilities are rejected, including when native JSON/UART hashes are re-pinned together.

`tests/test_linux_aarch64_capget_checkpoint.py` checks live application query bytes, all version/NULL/PID cases, an eight-byte partial copy and aliased output through the 32-mode resume chain. Its kernel proof verifies 255 calls and 170 isolation checks. Models that return the permitted set as effective or omit capability output fail target proof before publication. Changed original commoncap getter code and falsely reported query bytes are rejected, including when native JSON/UART hashes are re-pinned together.

`tests/test_linux_aarch64_prctl_checkpoint.py` checks all seven admitted process-control options and their effects on later capability/list calls through the 32-mode chain. The returning-kernel proof checks 276 calls and 184 isolation checks. Models that authorize bounding drops through permitted rather than effective capabilities, or discard securebits during credential copying, must fail target proof before publication. Changes to the original hook, dispatch-prefix evidence or securebits ABI are rejected. Falsely reported native securebit state is rejected even when the JSON/UART hashes are re-pinned together.

`tests/test_linux_aarch64_fsuid_checkpoint.py` checks witness generation, old-FSUID returns, silent denial, inactive copies, low/high capability words, selective drop/regain, ambient preservation and securebit suppression/locking through the 32-mode chain. Its returning proof verifies 252 calls and 168 isolation checks. Skipped commoncap fixup and authorization through permitted rather than effective capabilities must fail with target replay divergence before publication. Changes to original FSUID code, kernel-header masks or commoncap fixup are rejected, along with false native FSUID observations whose JSON/UART hashes were re-pinned.

`tests/test_linux_aarch64_setresuid_checkpoint.py` checks the generated witness, early no-op behavior, FSUID repair, live UID queries, saved-root restoration, keepcaps, selective permitted regain and securebit-controlled transitions. Its returning proof checks 246 calls and 164 isolation checks. Skipped UID fixup, permitted-set authorization and leaked accounting ownership must fail with target replay divergence before publication. Original UID/accounting/commoncap source changes and falsely reported native UID changes are rejected even after capture/UART hashes are re-pinned together.

`tests/test_linux_aarch64_uid_setters_checkpoint.py` checks generated ID/RE arguments, both setters' admission and saved-ID rules, no-op publication, inactive partial edits, explicit accounting links, all four successful accounting identities, aliased/partial UID output, keepcaps and suppressed/locked capability fixup. Its returning proof checks 279 calls and 186 isolation checks. Skipped UID fixup, permitted-set admission and erasing aborted inactive fields must fail with target replay divergence before publication. Changed original ID/RE helpers, syscall ABI numbers and false native active-UID changes are rejected, including after JSON/UART hashes are re-pinned together.

`tests/test_linux_aarch64_credential_setters_checkpoint.py` checks privileged/unprivileged scalar GIDs, saved-ID rules, silent FSGID denial, list/capability preservation, UID-driven SETGID admission, permanent permitted removal and accounting continuity. Its returning proof checks 294 calls and 196 isolation checks. Authorizing through permitted capabilities, losing scalar GIDs during credential preparation and erasing an aborted real-GID change must fail with target replay divergence before publication. Tests verify exact reuse of the eight original GID definitions and reject changed helpers, ABI numbers and false native post-denial group state even when JSON/UART hashes are re-pinned together.

The retained end-to-end run is `build/linux-aarch64-pipeline-final-v1`. It was produced with the single `--kernel-image` command using the available LinuxKit Image. Its `native/` evidence records a completed TCG Linux boot and 20 observed calls; `kernel/`, `kernel-qemu/` and `chain/` retain the device-free returning slices and all 20 matrix executions. Offline verification passed and construction hashes identify the finished tools. An additional HVF capture produced identical syscall observations. The standalone TCG capture is also retained at `build/linux-aarch64-native-final-v1`.

The mutable-credential run is `build/linux-credentials-pipeline-final-v1`, produced by the single `--profile credentials --kernel-image` command. It retains a completed TCG Linux boot with 42 calls, the original-helper returning slices and all 28 matrix executions. Offline verification passed; both capture and pipeline construction hashes match the current tools. The native capture is archived at `tests/fixtures/linux-aarch64-credentials-native/`, with its root disk compressed losslessly. The earlier minimal-profile workflow still passes offline verification.

The filesystem-group run is `build/linux-fsgid-pipeline-final-v1`, produced with `--profile fsgid --kernel-image`. It retains a completed TCG Linux boot with 62 calls, original Linux helpers, returning-slice proof and all 32 ELF/raw × EL1/EL3 executions. The native fixture is `tests/fixtures/linux-aarch64-fsgid-native/`; its root disk is compressed losslessly. Earlier captures and their profile recipes remain supported.

All three Linux CTest suites passed serially for this extension: ten tests in 419.00 seconds. Evidence is `build/live-syscall-checks/qemu-linux-fsgid-results.xml` and `linux-fsgid-validation.json`. The validation record includes native Image/config identities, all original-definition hashes, saved active/inactive credential state, current construction hashes, abort and repair ordinals, and successful offline verification of the new and both earlier profiles. Additional HVF capture observations equal the retained TCG observations.

The group-setter run is `build/linux-group-setters-pipeline-final-v1`, produced with `--profile group-setters --kernel-image`. It retains a completed TCG Linux boot with 94 calls, fourteen original syscall roots and four ordinary helpers, returning-slice proof and all 32 replay modes. The fixture is `tests/fixtures/linux-aarch64-group-setters-native/`, including a losslessly compressed root disk. Native HVF and TCG syscall observations are identical; capture and pipeline hashes identify the current tools. The shared analyzer, gateway and checkpoint codec did not need changes for the additional roots.

All four Linux CTest suites passed serially for the group-setter extension: thirteen tests in 395.62 seconds. Evidence is `build/live-syscall-checks/qemu-linux-group-setters-results.xml` and `linux-group-setters-validation.json`. The validation record includes native identities, eighteen original-definition hashes, saved active/inactive credential state, partial-abort and unchanged-publication ordinals, current construction hashes and offline verification of all four retained profiles. The new suite rejects publication of failed candidates and incorrect rejection of either admitted setter security hook before producing an image.

The supplementary-query run is `build/linux-getgroups-pipeline-final-v1`, produced with `--profile getgroups --kernel-image`. It retains a completed TCG Linux boot with 112 calls, fifteen original syscall roots and five ordinary/static helpers, returning-slice proof and all 32 replay modes. The fixture is `tests/fixtures/linux-aarch64-getgroups-native/`, including a losslessly compressed root disk and the guarded witness ELF. Native HVF and TCG observations are identical; source identities cover both reviewed Linux files and construction hashes identify the current tools. The shared analyzer, gateway and checkpoint codec did not need changes for the new group object or static helper.

All five Linux CTest suites passed serially for supplementary queries: sixteen tests in 839.84 seconds. Evidence is `build/live-syscall-checks/qemu-linux-getgroups-results.xml` and `linux-getgroups-validation.json`. The validation record includes native identities, both source-file hashes and twenty definition hashes, decoded list state, partial-copy bytes, current construction hashes and offline verification of all five retained profiles. Both broken list-reference and group-copy models fail target proof before publication.

The supplementary-replacement run is `build/linux-setgroups-pipeline-final-v1`, produced with `--profile setgroups --kernel-image`. It retains a completed TCG Linux boot with 56 calls, twelve original syscall roots and five original helpers from two reviewed source files, returning-slice proof and all 32 replay modes. The fixture is `tests/fixtures/linux-aarch64-setgroups-native/`, including a losslessly compressed native root disk. Native HVF and TCG observations agree byte-for-byte. The shared analyzer, gateway and checkpoint codec handle the additional typed list references without changes. All five earlier retained Linux workflows pass offline verification with the extended tooling.

All six Linux CTest suites passed serially for supplementary replacement: nineteen tests in 1118.58 seconds. Evidence is `build/live-syscall-checks/qemu-linux-setgroups-results.xml` and `linux-setgroups-validation.json`. The validation record binds native Image/config identities, seventeen original definitions from both source files, all decoded checkpoint pools and links, partial-allocation states, current construction hashes and successful offline verification of every retained Linux profile. Broken publication, reference-acquisition and sorting models fail target proof before image publication.

The permission-denied run is `build/linux-setgroups-denied-pipeline-final-v1`, produced with `--profile setgroups-denied --kernel-image`. It retains a completed native TCG boot with 60 calls, twelve original roots, five original helpers, native capability observations and all 32 replay modes. The fixture is `tests/fixtures/linux-aarch64-setgroups-denied-native/`, including the losslessly compressed root disk and pinned capability ABI. Native HVF and TCG observations agree byte-for-byte. The returning-slice proof checks 180 calls, 120 isolation checks, three completed sessions and reset. The shared analyzer, gateway and checkpoint codec handle the added scalar dependency without changes; all six earlier retained Linux workflows pass offline verification.

All seven Linux CTest suites passed serially for missing-capability rejection: twenty-two tests in 598.03 seconds. Evidence is `build/live-syscall-checks/qemu-linux-setgroups-denied-results.xml` and `linux-setgroups-denied-validation.json`. The validation record binds the native Image/config, seventeen original definitions, both capture ABI headers, decoded capability/list/credential state, all denial ordinals and current construction hashes. It includes successful offline verification of all six earlier retained profiles. Both false-capability and denial-side-effect models fail target proof before image publication.

The capability-transition run is `build/linux-capabilities-pipeline-final-v1`, produced with `--profile capabilities --kernel-image`. It retains a completed native TCG boot with 64 calls, thirteen original roots and nine original helpers from four reviewed Linux source files, all five capability observations and all 32 replay modes. The fixture is `tests/fixtures/linux-aarch64-capabilities-native/`, including the losslessly compressed root disk. Native HVF capture `build/linux-capabilities-native-probe-v2` produces identical observations. The returning-slice proof checks 192 calls and 128 isolation checks. The shared analyzer, gateway and checkpoint codec handle the full capability-set dependency and static inline helper without changes.

All eight Linux CTest suites passed serially for capability transitions: twenty-five tests in 191.80 seconds. Evidence is `build/live-syscall-checks/qemu-linux-capabilities-results.xml` and `linux-capabilities-validation.json`. The validation record binds native Image/config identities, twenty-two original definitions from four source files, both ABI headers, all decoded credential/list/capability pools and current construction hashes. It records the version/fault/abort ordinals, sixteen successful credential publications and successful offline verification of all seven earlier profiles. Incorrect permission selection and leaked abort references fail target proof before image publication.

The application-query run is `build/linux-capget-pipeline-final-v1`, produced with `--profile capget --kernel-image`. It retains a completed native TCG boot with 85 calls, fourteen original roots and eleven original helpers from four reviewed Linux source files, live application query bytes and all 32 replay modes. The fixture is `tests/fixtures/linux-aarch64-capget-native/`, including the losslessly compressed root disk. Native HVF and TCG observations agree byte-for-byte, including the eight-byte partial output. The returning-slice proof checks 255 calls and 170 isolation checks. All eight earlier retained Linux workflows pass offline verification with the extended tools.

All nine Linux CTest suites passed serially for application capability queries: twenty-eight tests in 238.53 seconds. Evidence is `build/live-syscall-checks/qemu-linux-capget-results.xml` and `linux-capget-validation.json`. The validation record binds native Image/config identities, twenty-five original definitions, both ABI headers, all query/version/PID/fault ordinals, partial-copy bytes, decoded context state and current construction hashes. Incorrect effective snapshots and omitted output fail target proof before image publication. The shared analyzer, gateway and checkpoint codec did not require changes.

The capability-prctl run is `build/linux-prctl-pipeline-final-v1`, produced with `--profile prctl --kernel-image`. It retains a completed native TCG boot with 92 calls, fifteen syscall routes and twenty-seven original definitions from four reviewed Linux source excerpts. Syscall 167 routes directly to original `cap_task_prctl` for the seven admitted options; the full general wrapper is excluded, with its dispatch prefix pinned separately. The fixture is `tests/fixtures/linux-aarch64-prctl-native/`, including the losslessly compressed root disk, all three UAPI excerpts and dispatch evidence. Native HVF capture `build/linux-prctl-native-probe-v3` agrees byte-for-byte with TCG. The returning proof checks 276 calls and 184 isolation checks, and the retained chain passes all 32 replay modes. All nine earlier retained workflows pass offline verification.

All ten Linux CTest suites passed serially for capability process control: thirty-one tests in 2186.06 seconds. Evidence is `build/live-syscall-checks/qemu-linux-prctl-results.xml` and `linux-prctl-validation.json`. The validation record binds native Image/config identities, all original-definition and source/header/dispatch hashes, five argument values, named call ordinals, both slots' decoded capabilities and securebits, twenty-six credential publications and current construction hashes. Both wrong-permission and lost-securebit models fail with target replay divergence before publication. The shared analyzer, gateway and checkpoint codec required no changes.

The filesystem-user run is `build/linux-fsuid-pipeline-final-v1`, produced with `--profile fsuid --kernel-image`. It retains a completed native TCG boot with 84 calls across sixteen routes, thirty-four original definitions from five reviewed source/header excerpts, all 32 replay modes and a generated C witness. The fixture is `tests/fixtures/linux-aarch64-fsuid-native/`, including the losslessly compressed root disk. Native HVF capture `build/linux-fsuid-native-probe-v1` agrees byte-for-byte with TCG. The returning proof verifies 252 calls and 168 isolation checks. Twenty-nine credential publications and all copied FSUID/capability/securebit state are checked independently. The shared analyzer, gateway and checkpoint codec required no changes; the reviewed extractor now accepts original static inline void and kernel-capability return declarations.

All four new FSUID tests passed in 235.20 seconds. The four directly affected earlier Linux suites—minimal, mutable credentials, capget and prctl—also passed serially: thirteen tests in 1269.71 seconds. Evidence is `build/live-syscall-checks/qemu-linux-fsuid-results.xml`, `qemu-linux-fsuid-affected-results.xml` and `linux-fsuid-validation.json`. The validation record binds Image/config identities, all original-definition and source/header hashes, both FSUID slots, all five capability sets, securebits, named calls, generated witness identity and current construction hashes. Both skipped-fixup and permitted-authorization models fail with target replay divergence before publication. All ten earlier retained workflows pass offline verification with the extended tools.

The user-transition run is `build/linux-setresuid-pipeline-final-v4`, produced with the single `--profile setresuid --kernel-image` command. It retains a completed native TCG boot, 82 calls across seventeen routes, thirty-nine original definitions from six reviewed source/header excerpts and all 32 replay modes. The native fixture is `tests/fixtures/linux-aarch64-setresuid-native/`. Its observations agree with `build/linux-setresuid-native-probe-v2`, captured with HVF. The returning proof checks 246 calls and 164 isolation checks, including three complete sessions and reset. Thirty-five credential publications are checked independently. The context occupies 536 bytes and the portable record 444 bytes; both user/accounting pools and typed credential links survive fresh-image restoration. The shared Clang analyzer, gateway and checkpoint codec required no changes. All eleven earlier retained workflows pass offline verification with the extended tools.

All four new user-transition tests passed in 206.61 seconds. The three affected earlier suites—minimal, mutable credentials and FSUID—also passed serially: eleven tests in 287.23 seconds. Evidence is `build/live-syscall-checks/qemu-linux-setresuid-results.xml`, `qemu-linux-setresuid-affected-results.xml` and `linux-setresuid-validation.json`. The validation record binds the current construction/extractor/generator hashes, native identities, all thirty-nine original definitions, six source/header excerpts, generated witness, named transitions, copied UID/FSUID/capability/securebit state and typed accounting ownership. All three model mutants fail with target replay divergence before image publication.

The complete user-setter run is `build/linux-uid-setters-pipeline-final-v1`, produced with the single `--profile uid-setters --kernel-image` command. It retains a completed native TCG boot, 93 calls across nineteen routes, forty-three original definitions from six reviewed source/header excerpts and all 32 replay modes. The fixture is `tests/fixtures/linux-aarch64-uid-setters-native/`. Native observations agree with HVF capture `build/linux-uid-setters-native-probe-v1`. The returning proof checks 279 calls and 186 isolation checks across three sessions and reset. Fifty publications and all inactive scalar/link differences are checked independently. The context remains 536 bytes and its portable record 444 bytes. The shared analyzer, gateway and checkpoint codec required no changes, and all twelve earlier workflows pass offline verification.

All four new user-setter tests passed in 112.99 seconds. The three affected earlier suites—minimal, group setters and `setresuid`—also passed serially: eleven tests in 247.83 seconds. Evidence is `build/live-syscall-checks/qemu-linux-uid-setters-results.xml`, `qemu-linux-uid-setters-affected-results.xml` and `linux-uid-setters-validation.json`. The validation record binds current construction/extractor/generator and test-source hashes, all forty-three original definitions, native identities, generated witness, named calls, fifty publications, both credential slots and the three paused inactive UID/accounting differences. All three model mutants fail with target replay divergence before publication.

The combined credential run is `build/linux-credential-setters-pipeline-final-v1`, produced with the single `--profile credential-setters --kernel-image` command. It retains a completed native TCG boot, 98 calls across twenty-three routes, fifty-one original definitions from six reviewed source/header excerpts and all 32 replay modes. The fixture is `tests/fixtures/linux-aarch64-credential-setters-native/`; its observations agree with HVF capture `build/linux-credential-setters-native-probe-v1`. The returning proof checks 294 calls and 196 isolation checks across three sessions and reset. Forty-three credential publications, both scalar-ID pools, live capability/list state and typed user/accounting links are checked independently. The context remains 536 bytes and the portable record 444 bytes. The shared analyzer, gateway and checkpoint codec required no changes, and all thirteen earlier workflows pass offline verification.

All four new combined-credential tests passed in 136.28 seconds. The three affected earlier suites—group setters, capabilities and UID setters—also passed serially: ten tests in 454.98 seconds. Evidence is `build/live-syscall-checks/qemu-linux-credential-setters-results.xml`, `qemu-linux-credential-setters-affected-results.xml` and `linux-credential-setters-validation.json`. The validation record binds current construction/extractor/generator and test-source hashes, native identities, all fifty-one definitions, exact reuse of the eight GID definitions, named calls, forty-three publications, scalar/list/capability/accounting state and both paused partial real-GID aborts. All three model mutants fail with target replay divergence before image publication.

The descriptor run is `build/linux-fd-dup-pipeline-final-v2`. It uses the completed native TCG capture from `build/linux-fd-dup-pipeline-final-v1/native`, then rebuilds the final reviewed model and verifies all 32 replay modes through the automated `--capture` path. Capture and workflow construction hashes match the current tools; the final bundle matches the current model, policy and generated witness. Its 73 observations equal HVF capture `build/linux-fd-dup-native-probe-v2`; the fixture is `tests/fixtures/linux-aarch64-fd-dup-native/`. The returning proof checks 219 calls and 146 isolation checks. The generic analyzer contextualizes fifty functions and eleven state objects; fifteen functions are pure. The shared analyzer, gateway and codec required no changes. All fourteen earlier workflows pass offline verification.

All four descriptor tests passed in 287.08 seconds under CTest. The three reference/flag mutants each fail with target replay divergence before publication. Original-source, syscall-ABI and jointly re-pinned false native-state evidence are also rejected. The three affected earlier suites—typed context references, minimal Linux and combined credential setters—also passed serially: nine tests in 533.21 seconds, for thirteen fresh tests across four suites. The retained evidence is `build/live-syscall-checks/qemu-linux-fd-dup-results.xml`, `qemu-linux-fd-dup-affected-results.xml` and `linux-fd-dup-validation.json`. The validation record binds native identities, constructor/extractor/generator/model/test hashes, all twenty-eight original definitions, every named call, all six decoded descriptor records and the final reference-zero state.

The file-I/O run is `build/linux-file-io-pipeline-final-v2`, using the completed TCG Linux capture from `build/linux-file-io-pipeline-final-v1/native`. The `--capture` workflow rebuilds the final model, checks 118 observations and verifies all 32 ELF/raw × EL1/EL3 replay modes. Its native observations equal HVF capture `build/linux-file-io-native-probe-v1`; the fixture is `tests/fixtures/linux-aarch64-file-io-native/`. The returning proof checks 354 calls and 236 isolation checks, with sixty-five contextualized functions, nineteen pure functions and twelve state objects. All thirty-nine original definitions are pinned, including exact reuse of the twenty-eight descriptor definitions. The shared analyzer, gateway and codec required no changes, and all fifteen earlier Linux workflows pass offline verification.

All four file-I/O tests passed in 154.42 seconds under CTest. Four mutants omit position advancement, byte writes, reference release or caller-object bounds; each fails with target replay divergence before image publication. The bounds mutant uses an extra adjacent mapped region to expose access beyond the caller object. Original-source/ABI changes and jointly re-pinned false native file bytes are also rejected. The two affected suites—FSUID and descriptor operations—also passed serially: eight tests in 311.91 seconds, for twelve fresh tests across three suites. The correct model additionally passes the same adjacent-region harness with 354 call checks; evidence is `build/linux-file-io-adjacent-region-control-v1`. The retained test reports are `build/live-syscall-checks/qemu-linux-file-io-results.xml` and `qemu-linux-file-io-affected-results.xml`; `linux-file-io-validation.json` in that directory binds native identities, all thirty-nine original definitions, current model/extractor/generator/test hashes, six saved file states, the final inactive snapshot and the adjacent-memory control.



The positioned/truncation run is `build/linux-file-positioned-pipeline-final-v2`, using the completed native TCG capture from `build/linux-file-positioned-pipeline-final-v1/native`. The automated `--capture` workflow checks 171 observations across nineteen routes and verifies all 32 ELF/raw × EL1/EL3 replay modes. Its native observations equal HVF capture `build/linux-file-positioned-native-probe-v1`; the fixture is `tests/fixtures/linux-aarch64-file-positioned-native/`. The returning proof checks 513 calls and 342 isolation checks across three complete sessions and reset. The generic analyzer contextualizes seventy-nine functions and fifteen state objects; twenty functions are pure. All forty-six original definitions are pinned, with exact reuse of the thirty-nine file-I/O definitions. The adapter and proof derive buffer argument normalization from the generated route schema, including the four-argument positioned calls. The shared analyzer, gateway and codec required no changes, and all sixteen earlier Linux workflows pass offline verification.

All four positioned/truncation tests passed in 779.20 seconds under CTest. The four model mutants omit discarded-tail clearing, move the shared offset on truncate, commit a positioned read's local offset, or omit descriptor-reference release; each fails with target replay divergence before image publication. Original-source/ABI changes and a jointly re-pinned false native positioned offset are also rejected. The two affected suites—typed context references and file I/O—passed serially: five tests in 704.30 seconds, for nine fresh tests across three suites. Reports are `build/live-syscall-checks/qemu-linux-file-positioned-results.xml` and `qemu-linux-file-positioned-affected-results.xml`. The accompanying `linux-file-positioned-validation.json` binds native identities, all forty-six original definitions, current construction/model/extractor/generator/test hashes, both report and log hashes, six decoded file/inode records, the final inactive snapshot and verification of all sixteen earlier workflows.

The descriptor-control run is `build/linux-fd-control-pipeline-final-v1`, using the fresh native TCG capture `build/linux-fd-control-native-tcg-v1`. Its 233 observations equal HVF capture `build/linux-fd-control-native-hvf-v1`, including all 171 earlier positioned/truncation observations unchanged. The fixture is `tests/fixtures/linux-aarch64-fd-control-native/`, with a losslessly compressed root disk. The returning proof checks 699 calls and 466 isolation checks across three sessions and reset, and all 32 replay/resume modes pass. The analyzer contextualizes eighty-four functions and fifteen state objects; twenty functions are pure. Forty-six earlier original definition hashes are reused exactly and the three original descriptor helpers bring the total to forty-nine. The general `fcntl` entry/dispatch remains an explicit reviewed boundary. The shared analyzer, gateway and codec required no changes, and all seventeen earlier Linux workflows pass offline verification.

All four descriptor-control tests passed in 157.42 seconds under CTest. Four model mutants omit flag mutation, ignore the duplication minimum, omit the close-on-exec duplication flag or leak the lookup reference; each fails with target replay divergence before image publication. Changed original helper/ABI inputs and a jointly re-pinned false native descriptor flag are also rejected. The affected positioned/truncation suite passed all four tests in 307.90 seconds, for eight fresh tests across two suites. Reports are `build/live-syscall-checks/qemu-linux-fd-control-results.xml` and `qemu-linux-fd-control-affected-results.xml`. The accompanying `linux-fd-control-validation.json` binds native identities, all forty-nine original definitions, the explicit modeled entry boundary, current constructor/model/extractor/generator/test hashes, both report and log hashes, all six decoded descriptor/file/inode records, the final inactive file snapshot and verification of all seventeen earlier workflows.

The range-close run is `build/linux-close-range-pipeline-final-v1`, using the fresh native TCG capture `build/linux-close-range-native-tcg-v1`. Its 267 observations equal HVF capture `build/linux-close-range-native-hvf-v1`; the fixture is `tests/fixtures/linux-aarch64-close-range-native/`, including the losslessly compressed root disk. The returning proof checks 801 calls and 534 isolation checks across three sessions and reset, and all 32 ELF/raw × EL1/EL3 replay modes pass. The analyzer contextualizes ninety-five functions and fifteen state objects; twenty-one functions are pure. All fifty-four original definitions are pinned, reusing the forty-nine descriptor-control definitions exactly. Five inherited close results change to native `EBADF` after earlier range closure; the other 228 inherited observations are identical. All eighteen earlier Linux workflows pass offline verification.

All four range-close tests passed in 221.80 seconds under CTest. Three bitmap mutants omit range updates, mark only open descriptors or skip the inclusive last slot; each fails with target replay divergence before image publication. Changed original range-loop/wrapper/ABI inputs and a jointly re-pinned false native alias flag are also rejected. The affected descriptor-control suite passed all four tests in 227.20 seconds, for eight fresh tests across two suites. Reports are `build/live-syscall-checks/qemu-linux-close-range-results.xml` and `qemu-linux-close-range-affected-results.xml`. The accompanying `linux-close-range-validation.json` binds native identities, all fifty-four original definitions, current constructor/model/extractor/generator/test hashes, both report and log hashes, all six complete bitmap/descriptor/file/inode records, the five intentional inherited error changes, explicit unshare exclusion and verification of all eighteen earlier workflows.

The metadata run is `build/linux-fstat-pipeline-final-v1`, using fresh native TCG capture `build/linux-fstat-native-tcg-v2`. Its 286 normalized observations equal HVF capture `build/linux-fstat-native-hvf-v1`; the fixture is `tests/fixtures/linux-aarch64-fstat-native/`. The returning proof checks 858 calls and 572 isolation checks across three sessions and reset, covering both caller objects. All 32 ELF/raw × EL1/EL3 replay/resume modes pass with the persistent application metadata digest. The analyzer contextualizes 103 functions and fifteen state objects; twenty-four functions are pure. Fifty-four earlier original definitions are reused exactly; four stat definitions bring the total to fifty-eight. All nineteen earlier Linux workflows pass offline verification.

All four metadata tests passed in 310.83 seconds under CTest. Four model mutants return stale size, retain blocks after truncation to zero, leak the stat lookup reference or omit output writes; each fails with target replay divergence before image publication. Changed original stat source, stat-layout and syscall-ABI inputs and jointly re-pinned false native metadata are also rejected. The affected range-close suite passed all four tests in 102.42 seconds, for eight fresh tests across two suites. Reports are `build/live-syscall-checks/qemu-linux-fstat-results.xml` and `qemu-linux-fstat-affected-results.xml`. The accompanying `linux-fstat-validation.json` binds native identities, all fifty-eight original definitions, current constructor/model/extractor/generator/test hashes, both report and log hashes, both caller objects, the application digest, six decoded inode/allocation records and verification of all nineteen earlier workflows. It explicitly records the timestamp exclusion and the separately selected v6.11 stat-layout reference.

The permission-change run is `build/linux-fchmod-pipeline-final-v1`, using fresh native TCG capture `build/linux-fchmod-native-tcg-v2`. Its 303 normalized observations equal HVF capture `build/linux-fchmod-native-hvf-v1`; the fixture is `tests/fixtures/linux-aarch64-fchmod-native/`. The returning proof checks 909 calls and 606 isolation checks across three sessions and reset, and all 32 replay/resume modes pass with the application metadata digest. Six raw saved-state records independently decode modes 0100600, 0100000, 0100400, 0100604, 0100640 and 0100640 together with mount IDs and typed links. The final record follows last-reference release and retains inactive mode bookkeeping. The analyzer contextualizes 115 functions and sixteen state objects; twenty-four functions are pure. Fifty-eight earlier original definitions are reused exactly; three chmod definitions bring the total to sixty-one. All twenty earlier Linux workflows pass offline verification.

All four permission-change tests passed in 415.22 seconds under CTest. Four model mutants omit the mode update, allow a non-owner change, omit mount write release or omit inode unlock; each fails with target replay divergence before image publication. Changed original chmod helper/wrapper and syscall-ABI inputs and jointly re-pinned false native mode observations are also rejected. The affected metadata suite passed all four tests in 285.03 seconds, for eight fresh tests across two suites. Reports are `build/live-syscall-checks/qemu-linux-fchmod-results.xml` and `qemu-linux-fchmod-affected-results.xml`. The accompanying `linux-fchmod-validation.json` binds native identities, all sixty-one original definitions, current constructor/model/extractor/generator/test hashes, both report and log hashes, six decoded inode/mount records, both caller objects, the application digest, preserved inherited observations and verification of all twenty earlier workflows. It records the construction-only ownership transfer, ordinary-mode boundary, timestamp exclusion and corrected initial test-only read-count expectation.

The ownership run is `build/linux-fchown-pipeline-final-v1`, using fresh native TCG capture `build/linux-fchown-native-tcg-v2`. Its 328 normalized observations equal HVF capture `build/linux-fchown-native-hvf-v1`; the fixture is `tests/fixtures/linux-aarch64-fchown-native/`. The returning proof checks 984 calls and 656 isolation checks across three sessions and reset, and all 32 replay/resume modes pass with the application metadata digest. Six independently decoded records preserve GID 2002 through same-owner/sentinel, mode-zero, alias and denied combined-change boundaries, then retain GID 0 after restoration and last-reference release. UID remains 1002. The analyzer contextualizes 128 functions and sixteen state objects; twenty-six functions need no context. Sixty-one earlier original definitions and the complete checkpoint field policy are reused unchanged. All twenty-one earlier Linux workflows pass offline verification.

All four ownership tests passed in 1714.11 seconds under CTest. Four model mutants omit the group write, bypass UID authorization, bypass group membership or apply the unchanged-ID sentinel as a group value; each fails with target replay divergence before image publication. Changed original ownership helper/wrapper and syscall-ABI inputs and jointly re-pinned false native GID, supplementary-group and effective-capability observations are also rejected. The affected permission-change suite passed all four tests in 291.39 seconds, for eight fresh tests across two suites. Reports are `build/live-syscall-checks/qemu-linux-fchown-results.xml` and `qemu-linux-fchown-affected-results.xml`. The accompanying `linux-fchown-validation.json` binds native identities, all sixty-seven original definitions, current constructor/model/extractor/generator/test hashes, both report and log hashes, six decoded ownership/mount records, both caller objects, the application digest, preserved inherited observations and verification of all twenty-one earlier workflows. It records the explicit supplementary-group seed and readback, zero effective capabilities, the corrected CRLF handling in the evidence test, the unprivileged ownership boundary and the timestamp exclusion. Both ownership suites allow 2400 seconds for four faulty-model exports plus the full QEMU matrix on loaded hosts.

Four affected CTest suites passed serially in 70.47 seconds: CPU gateway, application checkpoint chains, external ports and the four-test Linux AArch64 suite. Evidence is `build/live-syscall-checks/qemu-linux-aarch64-results.xml` and `linux-aarch64-validation.json`; the latter records report hashes, native kernel/config identities, saved masks and credentials, and construction hashes. The regression fixture archives the verified native TCG capture.

For the credential extension, all six affected suites passed: gateway, application chains, external ports, typed context references, minimal Linux and mutable Linux credentials. The new three-test suite passed a focused rerun in 385.21 seconds after the initial 300-second limit interrupted its mutation checks; its CTest timeout is now 900 seconds. Both runs are retained in `build/live-syscall-checks/qemu-linux-credentials-results.xml` and `qemu-linux-credentials-rerun-results.xml`. `linux-credentials-validation.json` records the successful suite results, initial timeout, native identities, original-definition hashes, raw saved credential state and current construction hashes. Additional HVF capture observations equal the retained TCG observations.

All profiles use one sequential task in the initial user namespace, fixed task identities and, except in `setresuid`, `uid-setters` and `credential-setters`, fixed real/effective/saved user identities, a reviewed call recipe and a 32-byte caller witness. The older `credentials`, `fsgid`, `group-setters` and `getgroups` recipes admit scalar group changes without effective `CAP_SETGID`. The `credential-setters` recipe exercises effective/permitted SETGID transitions in the combined state; `setgroups` retains this capability for supplementary replacements. Mutable credential profiles use successful credential security hooks and two reusable copy-on-write slots. They do not reproduce Linux's general allocator, reference-count/RCU reclamation, allocation failures or additional rejecting security hooks. Linux RCU, task/namespace access, integer exchange and user copies use explicit bounded contracts. Invalid user addresses reproduce native `EFAULT` behavior through region validation; replay does not execute Linux MMU fault handling. There is no scheduler, SMP synchronization, arbitrary namespace mapping, unrestricted syscall argument domain, process creation, general VFS or device model. The `fsuid` profile supplies filesystem user-ID changes only; `setresuid` supplies the reviewed three-ID setter and bounded user-accounting state, while `uid-setters` covers all four scalar user-ID setters. The `credential-setters` profile combines all scalar user/group setters with live capability/list/accounting state. New roots or broader argument domains need reviewed models, policies, native observations and target proofs. Other ARM64 Images can be supplied to the same capture infrastructure; the supported syscall closure and state contracts remain explicit.

The `getgroups` profile retains its fixed three-ID list. Runtime list replacement and changing lengths are supported for zero through four IDs, with two reusable list slots and modeled lifetimes. Missing-effective-capability rejection is supported by `setgroups-denied`, including larger counts rejected before allocation. Effective/permitted/inheritable transitions are supported in `capabilities` for the reviewed same-process recipe, a fixed initial namespace, fixed bounding set and zero ambient state. General variable-sized allocation, namespace-disabled `setgroups`, additional rejecting LSM hooks, audit/warning side effects, allocation failures, exec transitions and arbitrary capability domains remain outside the admitted recipes. The `prctl` profile supports reviewed bounding-set drops, ambient changes and securebit/keepcaps controls; unrelated general prctl options, real/effective/saved UID changes and exec remain outside its domain. The `fsuid` profile admits securebit-controlled filesystem UID/capability interactions. The `setresuid` profile extends these to real/effective/saved UID transitions. The `uid-setters` profile adds ID/RE semantics and partially edited inactive copies. The `credential-setters` profile adds effective-capability-controlled GID changes in the same credential pool. Resource-limit exhaustion, arbitrary user allocation and irreversible removal of all permitted capabilities through UID changes are not covered by these native recipes. Audit and legacy-format warning callbacks are no-op replay models. Native initial list/capability setup is capture preparation; subsequent workload setters are replay roots. Construction hashes in historical workflows identify the tools used at the time; offline verification does not require those hashes to match later revisions.

All replay verification uses QEMU. The baseline gateway remains sequential, with MMU disabled and interrupts masked, and provides no process memory isolation or SVE/SME state contract.

The privileged ownership run is `build/linux-fchown-capable-pipeline-final-v1`, using accepted TCG capture `build/linux-fchown-capable-native-tcg-v2`. All 330 normalized observations and entry authorization fields equal `build/linux-fchown-capable-native-hvf-v1`; the archived fixture is `tests/fixtures/linux-aarch64-fchown-capable-native/`. The returning proof verifies 990 calls, 660 isolation checks, three completed sessions, reset and four input rejections. The analyzer retains the same 128 context functions, twenty-six pure functions and sixteen state objects as the unprivileged ownership profile. All sixty-seven original definition hashes are reused, with one additional persisted credential field. All twenty-two earlier Linux workflows pass offline verification.

The joint chain is 0 → 103 → 108 → 116 → 236 → 238 → 300 → 330. Its six decoded records retain effective mask 1 throughout. File UID/GID values are `(9001,3001)`, `(9001,3003)`, `(0,4001)`, `(9002,4007)`, `(1002,0)`, `(1002,0)`. The final record has regular-file reference count zero; its inode fields are inactive bookkeeping. All 32 ELF/raw × EL1/EL3 replay/resume executions pass, including application memory, metadata digest and subsequent permission/error checks. The context/record sizes are 1096/972 bytes.

The four privileged-ownership regression tests passed in 1019.50 seconds under CTest (1013.316 seconds in unittest). The four rebuilt mutants ignore effective `CAP_CHOWN`, omit a UID write, omit a GID write or incorrectly allow nonowner chmod using `CAP_CHOWN`; all reject with target replay divergence before image publication. Source-wrapper and constructor-ABI tampering, as well as jointly re-pinned false UID/GID output or an effective mask that also grants `CAP_FOWNER`, are rejected. The suite also checks scalar, memory, descriptor and file observations for all 303 inherited calls, the persisted capability field, both caller objects, the full 32-mode chain and verification after removing the original capture. Its report is `build/live-syscall-checks/qemu-linux-fchown-capable-results.xml`.

The affected unprivileged ownership suite passed all four tests in 1033.31 seconds under CTest (1027.007 seconds in unittest), for eight fresh tests across the two suites. Its report is `build/live-syscall-checks/qemu-linux-fchown-capable-affected-results.xml`. The combined `linux-fchown-capable-validation.json` binds current model, extractor, constructor, generator and test hashes; native TCG/HVF equality; all sixty-seven original definitions; both suite reports and logs; six decoded ownership/capability/mount records; both caller objects; the application metadata digest; and verification of all twenty-two earlier workflows. It also records the diagnostic 300-second capture timeout and the accepted 1200-second retry, with no intervening production change. Fixed task credentials/effective capability inputs and the earlier file/namespace/timestamp limits remain explicit.

The combined file/capability run is `build/linux-file-capabilities-pipeline-final-v1`, using accepted native TCG capture `build/linux-file-capabilities-native-tcg-v1`. Its 369 normalized observations equal `build/linux-file-capabilities-native-hvf-v1`; the archived fixture is `tests/fixtures/linux-aarch64-file-capabilities-native/`. All 32 replay modes pass. The returning proof verifies 1107 calls and 738 isolation checks across three sessions and reset, with four input rejections. The analyzer identifies 138 context functions, thirty-five pure functions and nineteen state objects. The context is 1232 bytes and the portable record is 1100 bytes. All twenty-three earlier Linux workflows pass offline verification.

The combined chain is 0 → 111 → 118 → 125 → 127 → 266 → 278 → 369. Saved effective masks are `0,0,8,0,9,8`; generations are `1,1,3,4,7,9`, and active credential IDs are `2,2,2,1,2,2`. The first two records distinguish an effective-bit drop from a later rejected prepared candidate: generation and active slot remain unchanged, while the inactive effective set changes from 1 to 0 because preparation copied the active credential before rejection. Later records retain a foreign owner's mode changed with `CAP_FOWNER`, a subsequent effective drop, shared alias changes with both bits, and failed regain after permitted CHOWN removal. Final generation is 10 with effective/inheritable/ambient sets zero and permitted `CAP_SYS_BOOT` only; both slots retain those final capability values, with slot epochs 10 and 9. Original file metadata, descriptor/mount links and both caller buffers are verified alongside these credential records.

All four combined-profile tests passed in 178.51 seconds under CTest (176.565 seconds in unittest). The four rebuilt faulty models ignore live CHOWN admission, ignore live FOWNER admission, omit credential publication or bypass capability subset constraints; each fails with target replay divergence before publication. Tampered original capset/commoncap bodies and syscall ABI inputs reject, and jointly re-pinned false initial permitted capabilities or post-removal effective/permitted outputs also reject. The full regression chain validates both credential slots and all five capability fields, checks all 330 inherited calls' stable observations and verifies the retained bundle after deleting the original capture directory. The report is `build/live-syscall-checks/qemu-linux-file-capabilities-results.xml`.

The affected fixed-capability ownership suite also passed all four tests in 78.46 seconds under CTest (78.210 seconds in unittest), for eight fresh tests across the two suites. Its report is `build/live-syscall-checks/qemu-linux-file-capabilities-affected-results.xml`. The combined `linux-file-capabilities-validation.json` binds current constructor, extractor, model, policy, generator and test hashes; native TCG/HVF equality; all seventy-two retained definitions; both reports and logs; both credential slots at all six decoded checkpoints; the inode/file/descriptor/mount graph; both caller objects; the application digest; and verification of all twenty-three earlier workflows. Effective/permitted capability inputs are mutable in this profile, while task IDs/groups, namespace, storage capacity and timestamp-consumer exclusions remain explicit.

The filesystem-group run is `build/linux-file-fsgid-pipeline-final-v2`, using native TCG capture `build/linux-file-fsgid-native-tcg-v2`. Its 401 normalized observations and entry fields equal `build/linux-file-fsgid-native-hvf-v1`; the fixture is `tests/fixtures/linux-aarch64-file-fsgid-native/`. All 32 replay modes pass. The returning proof verifies 1203 calls and 802 isolation checks, three sessions and reset, and four input rejections. Seventy-two earlier definition hashes and the two original filesystem-group definitions are reused unchanged. The analyzer identifies 143 context functions, thirty-seven pure functions and nineteen state objects. Context/record sizes are 1248/1108 bytes. All twenty-four earlier Linux workflows pass offline verification.

The filesystem-group chain is 0 → 117 → 122 → 125 → 131 → 293 → 298 → 401. Saved active FSGIDs are `2001,2001,2003,2002,2003,2001`; real/effective/saved GIDs stay `2001,2002,2003`. Generations are `2,2,3,4,13,15`. The first record has FSGID slots `[2001,2002]`; the second retains `[2001,2001]` after preparation and abort without changing generation. The final pause is a successful `capset` publication while FSGID is 2001, and both slots retain that value. Final generation is 19, slot epochs are 18/19, both FSGIDs have been restored to 2002, and capability values match the inherited final permitted-only reboot state. File ownership, metadata, aliases, contents/offsets, mount links, both caller objects and the running application digest are verified with the credential state.

All four filesystem-group tests passed in 1111.94 seconds under CTest (1106.699 seconds in unittest). The four rebuilt faulty models use EGID for inode group admission, suppress the filesystem-GID update during publication, prepare for an invalid-ID query or grant absent `CAP_SETGID`; each rejects with target replay divergence before publication. Source-helper and syscall-ABI tampering reject, as do jointly re-pinned false entry FSGID, live FSGID and inode-group observations. The suite checks silent old-ID returns, no publication on denial/same-ID requests, invalid queries that preserve unequal inactive slots, capset publication with a nondefault FSGID, all 369 inherited calls' stable observations, both saved FSGID fields and the full replay chain after deleting the original capture. Its report is `build/live-syscall-checks/qemu-linux-file-fsgid-results.xml`.

The affected combined file/capability suite also passed all four tests in 1542.62 seconds under CTest (1531.573 seconds in unittest), for eight fresh tests across the two suites. Its report is `build/live-syscall-checks/qemu-linux-file-fsgid-affected-results.xml`. The combined `linux-file-fsgid-validation.json` binds current model, policy, extractor, constructor, generator and test hashes; TCG/HVF equality; all seventy-four original definitions; both suite reports and logs; six decoded FSGID/capability/credential records; inode/file/descriptor/mount state; both caller objects; the application digest; and verification of all twenty-four earlier workflows. It records the earlier 400-call witness extension that added capset with a nondefault FSGID, and the export correction that removed an inherited `gid_valid` macro collision with the new reviewed function declaration. The correction changed neither native observations nor retained original definitions. Filesystem GID and capabilities are mutable in this profile; task UID/FSUID and real/effective/saved/supplementary group setters remain outside it.
