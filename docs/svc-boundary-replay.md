# Live SVC boundaries and reduced replay

This workflow observes one real system call inside a resumed full-machine
checkpoint, then maps its registers, user memory and kernel objects onto a
Clang-derived slice footprint. The original kernel slice runs on that state in a
freestanding image, and the result is compared with the full-VM baseline.

It covers three of the gaps listed for the proprietary-kernel path:

1. **SVC boundary contract.** The trap encoding, number/argument/result
   registers, preserved registers, exception vectors, syndrome class, return
   rule and kernel-state anchor are configuration, not code.
2. **Live state → Clang state mapping.** A reviewed binding names the kernel
   field that supplies each schema field. Offsets and widths come from the running
   kernel's own BTF; nothing is hand-laid-out. A drafting tool proposes the syntactic
   part of the binding from the schema and BTF.
3. **Reduced vs full-VM comparison.** Result, user-object bytes and every bound
   kernel field are compared after the call.

## Components

| File | Role |
| --- | --- |
| `integrations/linux_aarch64/svc-boundary.json` | Linux arm64 `svc #0` contract: `x8` number, `x0`–`x5` arguments, `x0` result, all other GPRs and the user SP preserved, synchronous lower-EL vector at `VBAR+0x400` with ESR class `0x15`, asynchronous lower-EL vectors, `SP_EL0` as the `current` anchor. Kernel memory is read only in EL1, which holds whether or not KPTI is active. |
| `integrations/linux_aarch64/file-io/live-binding.json` | Reviewed correspondence between `file-io` checkpoint-policy fields and kernel paths such as `.files->fdt->open_fds[0]` and `.f_count.counter`. It includes the descriptor-pool classification by inode type, the `f_mode` projection mask and shmem page-cache bytes. |
| `integrations/linux_aarch64/fd-control/live-binding.json` | The `file-io` binding extended to the `fd-control` slice (`fcntl`, `writev`, `pread64`, `pwrite64`, `ftruncate`). It binds each live file's dentry and inode as related objects (see [related objects](#related-objects)). The `f_mode` mask also keeps `FMODE_PREAD` and `FMODE_PWRITE`. A precondition requires `RLIMIT_NOFILE` to be the model's 8 (see [preconditions](#preconditions)). |
| `tools/gdb_remote.py` | Minimal GDB remote client for QEMU's TCG gdbstub. |
| `tools/kernel_btf.py` | Embedded BTF reader and typed path resolver (`.member`, `->member`, `[n]`, anonymous records, `-><record.member>` container steps and `->(record)` casts of untyped pointers; bitfields rejected). |
| `tools/live_kernel_binding.py` | Applies a binding to live memory. It rejects unbound object classes, more than one live object per pool class, a mismatched embedded `fdt`, a descriptor capacity differing from the model, and file bytes beyond `i_size`. |
| `tools/svc_boundary.py` | Captures the boundary from a machine checkpoint. |
| `tools/reduced_boundary_replay.py` | Runs the footprint check, generates the image, executes it in QEMU and compares the result. |
| `tools/kernel_data_symbols.py` | Derives reviewed data-symbol addresses (ADRP pairs) from the pinned Image and its kallsyms text dump, and checks their layout against live memory (see [kernel data symbols](#kernel-data-symbols-2026-11-04)). |

`qemu_vm_checkpoint.Machine` accepts only a loopback `-gdb tcp:127.0.0.1:PORT`
observer. Recipe arguments and the immutable-asset rule are unchanged.

## Observation

```sh
B=build/linux-svc-machine-checkpoint-20261026
python3 tools/svc_boundary.py --checkpoint $B/checkpoint \
  --contract integrations/linux_aarch64/svc-boundary.json \
  --binding integrations/linux_aarch64/file-io/live-binding.json \
  --port integrations/linux_aarch64/file-io/port-template.json \
  --kernel-config $B/kernel.config --select number=63 --select x2=8 \
  --out build/svc-boundary-read
```

The observer breaks at the lower-EL vectors, not at user instructions, so it
needs no user-binary layout and no kernel symbols. At the selected synchronous
entry it checks the following:

- entry is in EL1h from EL0t;
- the ESR class is SVC;
- the word at `ELR-4` is the contract trap.

It then records the untouched user registers and the admitted user objects,
which typed `buffer` arguments in the port recipe declare as 32 bytes. It also
records each page containing them. Next it steps through kernel entry code
until `SP_EL0` holds a kernel address (55 instructions on this kernel). It
projects the kernel pre-state through the binding.

The only accepted next stop is the continuation (`trap + 4`) in EL0. Signal
redirection or re-entry before it fails the capture. The tool then makes these
checks:

- every preserved register is unchanged;
- no user byte outside the admitted objects changed on the surrounding pages.

Kernel post-state is read at the **first later lower-EL entry** of any kind,
whether SVC, IRQ or fault. Before that point only user instructions ran, so
the observation sees the call's kernel effects without any later kernel
execution. Finally the guest must still print the checkpoint's exact
`OSREC_VM_PASS` oracle, so observation cannot silently perturb execution.

## Sequence capture

`--all` (in place of `--select`) observes every SVC from resume until the guest
stops and writes `sequence.json`. For each call it records:
- the entry registers and user objects;
- the kernel pre-state, projected at the call's own entry;
- the return;
- the kernel post-state, projected at the first later lower-EL entry;
- the count of non-SVC entries (IRQs, faults) before the call.

A call during which the machine exits, such as the final `reboot`, is marked
terminal.

Two live-kernel situations needed explicit rules:

- **Interrupted return.** An IRQ can be taken after `eret`, before the first
  continuation instruction runs. The stop then lands on an asynchronous vector
  with `ELR` equal to the continuation and a user-mode `SPSR`. The return has
  happened and the user GPRs are untouched, so the call's post-state is taken
  at that entry. Any other early entry still fails.
- **Released objects.** After the last descriptor to a file closes, the object
  has no live address. Its members and file bytes are recorded as
  unobservable, not as zero. A comparison may only require a reference count
  of 0.

The binding's `external` rule marks calls the slice does not model: numbers
without a slice root, and `read`/`write`/`lseek` on console-class descriptors.
Such a call is admissible in a chain only if every observable bound field is
the same before and after it.

On the 2026-10-26 checkpoint the sequence holds 24 calls
(`build/linux-svc-chain-20261026/observe/sequence.json`):

| Calls | Bound kernel state |
| --- | --- |
| 2 console reads (fd 0), 10 console writes (fd 1) | unchanged |
| 11 `lseek`/`write`/`close`/`read` on the memfd and its alias | changed by `write`, the two `close`s, `lseek(SEEK_SET)` and `read` |
| `reboot` | terminal |

Timer IRQs occurred between calls, and one call's return was interrupted
before its first user instruction. The oracle line was reproduced.

## Drafting a binding

`tools/draft_live_binding.py` proposes binding paths so that review starts from
a draft instead of a blank file:

```sh
python3 tools/draft_live_binding.py \
  --policy integrations/linux_aarch64/file-io/checkpoint-policy.json \
  --kernel-image build/linux-svc-machine-checkpoint-20261026/checkpoint/assets/kernel \
  --reviewed integrations/linux_aarch64/file-io/live-binding.json --out draft.json
```

The tool starts at the anchor record and follows the schema's own edges through
same-named kernel members:
- self references, such as `task.files → files`;
- context references, such as `files.fdt → files.fdtab`;
- embedded records;
- pointer-element pools, such as `files.fdtab.fd[] → file_pool`.

Persistent leaves are matched by member name. Single-member records are
unwrapped (`kuid_t.val`, `atomic_long_t.counter`), and a model array of length
one maps to `[0]` on a kernel pointer. Each row is classified as follows:
- **proposed:** exactly one candidate.
- **ambiguous:** several routes. Where one schema object is reachable both
  through a reference and as an embedded member, the tool proposes the
  pointer-equality invariant that a reviewed binding uses to decide. It prefers
  the reference route, because that is what the retained code follows.
- **model-only:** no same-named kernel member.
- **unreachable:** no schema edge from the anchor.

Width mismatches are flagged.

Against the reviewed `file-io` binding:

- **Agreement:** 22 of 23 reviewed paths are proposed, the preferred path
  agrees on all 22, and none disagree. The draft's routes include the
  reviewed descriptor table, and it proposes the same `fdt == &fdtab`
  invariant.
- **Model-only:** `user_ns.initial` (reviewed as `level == 0`) and
  `object_id` (reviewed as an inode-type class). Both are semantic
  projections the draft does not attempt.
- **Unreachable:** `file_data`, a model store that the reviewed binding fills
  from the page cache.
- **Width mismatch:** `resize_in_progress` is flagged (`_Bool` vs `int`).

The draft is syntactic. The `f_mode` projection mask, object classification and
page-cache bytes still need review, and name agreement is not evidence of
semantic correspondence.

## Footprint and reduced replay

```sh
python3 tools/reduced_boundary_replay.py --boundary build/svc-boundary-read/boundary.json \
  --slice build/linux-transfer-guard-rebuild-20261026/file-io/kernel \
  --binding integrations/linux_aarch64/file-io/live-binding.json \
  --contracts integrations/linux_aarch64/file-io/analysis-contracts.json --out build/svc-boundary-read-replay
```

The replay refuses inputs in these cases:

- the slice manifest names a different kernel image than the checkpoint;
- any slice source hash differs from its manifest;
- the binding differs from the one used for observation.

It reruns `tools/entry_state.py` on the slice's contextified sources for the
observed root (`osrec_kernel_linux_read`, for example), under the profile's
analysis contracts (`analysis-contracts.json`). The contracts declare two things:

- the OSREC user-memory runtime functions as external-memory boundaries;
- one field range, `struct fdtable.max_fds` in `[0, 64]`, tied to the live field
  `files.fdtab.max_fds`.

The footprint must have no blockers. Every range the proof used is checked
against the captured pre- and post-state. Each discovered entry
read is normalized through the checkpoint policy's self/context references.
Examples: `argument:ctx->current->files->fdt->max_fds` becomes
`files.fdtab.max_fds`, and `*(…->file_lock)` becomes `files.file_lock`. Plain
syscall arguments map to the contract registers. Any read that does not land on
a bound field fails the replay.

The analyzer used to stop at `fdt->fd[fd]` and the `struct file` members behind
it: 42 blockers on `read`/`write` and 12 on `close`. Reviewed policy supplied
that region. It is now discovered (see
[path facts](entry-state-analysis.md#path-facts-field-ranges-and-descriptor-tables)):

- all 64 descriptor slots and their `f_count`/`f_mode`/`f_pos`/`object_id`;
- `file_data`;
- the open-descriptor bitmaps.

User bytes are reported as external memory. Minimality and completeness are not
claimed.

The analysis depends only on the root, the contracts, the analyzer modules and
the sources it parses (`syscalls.c`, `models.c` and every header). Its result is
cached under `build/footprint-cache/`, keyed by their SHA-256, so the
boundaries of one root from one checkpoint share one run, and KLEE discovery
reuses it too. A large closure can outlast the default 300-second bound;
`OSREC_FOOTPRINT_TIMEOUT` raises it.

The generated driver restores the context and overwrites it with the 95 bound
live fields and the user-object bytes. It calls the slice dispatcher with the
captured `x8`/`x0`–`x5`, then exports every bound field twice, before and after
the call. QEMU runs the ELF with no kernel, disk, serial device or semihosting.
Pre-export values must equal the live pre-state, which shows the restore is
exact. Post-export values, the result and the user bytes must equal the full-VM
observation.

## Results (2026-10-26)

All three boundaries come from the existing `linux-svc-machine-checkpoint-20261026` Linux 6.10.14 checkpoint.
The original oracle line was reproduced after every observation.

| Boundary | Kernel fields changed by the call | Original `file-io` slice | Corrected slice |
| --- | --- | --- | --- |
| `read(4, sp_buf, 8)` → 8 | `file_pool[1].f_pos` 0→8 | diverged: `-EFAULT` | equivalent (result, 32 user bytes, 95 fields) |
| `write(4, sp_buf, 2)` → 2 | `f_pos`, file bytes | diverged: `-EFAULT` | equivalent |
| `close(3)` → 0 | `next_fd`, `open_fds`, `fd[3]`, `f_count` | equivalent | equivalent |

The divergence was a real model defect. The reviewed `file-io` transfer model
admitted user ranges only below `0x7fffffffffff` (47 bits). On this kernel
(`CONFIG_ARM64_VA_BITS=48`), arm64 `access_ok()` uses `TASK_SIZE_MAX = 1 << 48`,
and the live PID 1 stack buffer is at `0xffffda25c0b0`. Earlier native captures
placed caller objects at low addresses, and their only huge-count witness is
`2^63`, so neither bound was ever discriminated.

The model and the shared witness predictor (`integrations/linux_aarch64/prepare.py`)
now use `1 << 48`. This does not change any existing witness. The `file-io`
pipeline was rebuilt into `build/linux-file-io-task-size-20261026` and
re-verified: 118 native calls and 32 QEMU matrix executions.

The 19 other Linux profiles that copied the same transfer bound now use it as
well. Each was rebuilt from a fresh native capture and passed its regression
suite (`build/linux-task-size-rebuild-20261026/summary.txt`): `close-range`,
`fchmod`, `fchown`, `fchown-capable`, `fd-control`, `file-capabilities`,
`file-capget`, `file-credentials`, `file-fsgid`, `file-fsuid`,
`file-group-setters`, `file-groups`, `file-limits`, `file-positioned`,
`file-prctl`, `file-rlimit`, `file-setrlimit`, `file-status`, `fstat`.

### Blocker-free footprints

The analysis gaps on these roots are now closed (see
[path facts](entry-state-analysis.md#path-facts-field-ranges-and-descriptor-tables)).

- **Re-observation.** All three calls were re-observed with the current binding,
  because the `external` rule had changed its hash. They were replayed through the
  guarded `file-io` slice with `analysis-contracts.json`.
- **Evidence.** `build/linux-svc-unblocked-20261026/report.json`.

| Boundary | Footprint blockers (before → after) | Footprint fields | `max_fds` range check | Result |
| --- | --- | --- | --- | --- |
| `read(4, sp_buf, 8)` → 8 | 42 → 0 | 12, none uncovered | pre 64, post 64 | equivalent |
| `write(4, sp_buf, 2)` → 2 | 42 → 0 | 12, none uncovered | pre 64, post 64 | equivalent |
| `close(3)` → 0 | 12 → 0 | 10, none uncovered | pre 64, post 64 | equivalent |

The descriptor slots and `file_pool[].f_count/f_mode/f_pos/object_id` are now
discovered by the analyzer, not supplied by review. User bytes appear only as
external memory.

**Normalization.** A slot's context reference with several targets is accepted
when all targets are elements of one pool, so `fd[3]->f_pos` becomes
`file_pool[].f_pos`.

**Model guard.** The 20 transfer models gained a capacity guard,
`if(start+copied>=64)break;`. It cannot change behavior inside the admitted
domain. All 20 profiles were rebuilt from fresh native captures and passed their
regression suites (`build/linux-transfer-guard-rebuild-20261026/summary.txt`).

**Replay refusals.** The replay now refuses:

- a blocked footprint;
- a live state outside a range that the proof used.

### Related objects

A slice can hold objects that a live file reaches, beside the file pool.
`fd-control` has a superblock, `inode_pool[2]` and `dentry_pool[2]`, and each
file has an `f_path.dentry` reference. The model's initial state lays them out
by object class: `file_pool[i]` points at `dentry_pool[i]`, which points at
`inode_pool[i]`, and every inode points at the one superblock.

`descriptors.related` in the binding follows that layout:

- `members` gives per-class values read through the class's live file:
  `inode_pool[].i_mode` (`.f_inode->i_mode`, file-type bits only) and
  `inode_pool[].append` (`.f_inode->i_flags & S_APPEND`). They become fields
  such as `inode_pool[1].i_mode`. A class with no live file has none; its
  fields are unobservable, as released pool members are.
- A member with a `class` is read only through that class's live file. Its
  field need not be per class: a singleton such as a superblock field would be
  read through the one class that reaches it.
- `preconditions` hold per-class model constants, with an optional `class`
  and `mask`, as the [anchor preconditions](#preconditions) do.
- `links` wires `file_pool[i].f_path.dentry`, `dentry_pool[i].d_inode` and
  `inode_pool[i].i_sb` for every class. A link with a `path` is checked on the
  live file: the pointer must be non-null. With `same_as`, it must also equal
  another path; `.f_path.dentry->d_inode` must be the file's `f_inode`.

The superblock's only field, `write_depth`, is a transient, zero at every
boundary: `sb_start_write` and `sb_end_write` balance within a call.

### Preconditions

A reviewed model can hold live state constant. The `file-io`-derived models
return `rlimit(RLIMIT_NOFILE)` as 8, while PID 1's limit is 1024. A binding's
`preconditions` list such values, each with a path from the anchor, the value
and the model's reason. Capture refuses a state where one differs.

The `file-io` and `fd-control` bindings require
`.signal->rlim[7].rlim_cur == 8`. A capture from a checkpoint at the default
limit stops with
`live .signal->rlim[7].rlim_cur=1024 differs from the model constant 8`.

All four guest programs (`init.c`, `init-more.c`, `init-ids.c`,
`init-state.c`) lower the limit to 8 before their checkpoint. The 35 `file-io`
manifest entries were recaptured from the rebuilt checkpoints
`build/linux-svc-machine-checkpoint{,-more,-ids}-20261029n` into
`build/linux-svc-file-io-20261029n`, with the same selections. Every call
returns the same result and binds the same kernel state as before; only stack
addresses and stale stack bytes moved.

### State-changing calls (2026-10-29)

`examples/linux-vm-checkpoint/init-state.c` first lowers `RLIMIT_NOFILE` to the
model's 8. After the checkpoint it changes descriptor and file state, then
restores the file, so the original transfer sequence and PASS line follow
(suffix ` state=ok`). Linux 6.10 runs it to completion
(`build/linux-svc-machine-checkpoint-state-20261029b`). 21 boundaries were
captured with the `fd-control` binding into `build/linux-svc-state-20261029b`
and replayed through a rebuilt `fd-control` slice
(`build/linux-fd-control-port-20261029/kernel`).

| Calls | Static replay |
| --- | --- |
| `pread64`: 4 bytes at 2; all 10 bytes; negative offset (`-EINVAL`) | equivalent |
| `pwrite64`: 2 bytes at 6; 1 byte at 9, extending the file; restoring 4 bytes | equivalent |
| `ftruncate`: shrink to 4, grow to 6, restore 8; negative length and the console (`-EINVAL`) | equivalent |
| `fcntl`: `F_GETFD`/`F_SETFD` (4), `F_GETFL`, `F_DUPFD` from 6 and from 10 (`-EINVAL`), `F_DUPFD_CLOEXEC`, `-EBADF` | blocked: fd allocator, as for `dup` |

Getting there needed three fixes.

- **`f_mode` mask.** `pread64` first returned `-ESPIPE`: the file-io mask
  dropped `FMODE_PREAD`, which `fd-control` reads.
- **Unit merge.** The analyzer compared function signatures as printed. Clang
  prints C's `_Bool` as `bool` in one unit and `_Bool` in another, so
  `close_on_exec`'s two declarations looked incompatible. Signatures now
  compare with typedef names expanded.
- **Truncate loop.** The model zeroes the truncated tail with
  `for(unsigned i=(unsigned)length;i<64;++i)`. A counter of this kind is now
  bounded without a known start (see
  [entry-state analysis](entry-state-analysis.md)).

[KLEE state discovery](klee-state-discovery.md#state-changing-calls) covers all
21, including `fcntl`.

The `fd-control` slice now runs the original `fcntl` entry and `do_fcntl`, and
the original `fdget`/`fdget_raw`/`fdput` lookups with their `__fget_light`
fast path (`build/linux-fd-control-port-20261029p/kernel`). The binding adds
three fields for them:

- `FMODE_PATH` in the `f_mode` mask, which the `fcntl` entry tests;
- `f_owner.signum`, which `F_GETSIG` and `F_SETSIG` use;
- `files.count.counter`, which selects the fast path.

The 21 boundaries were recaptured with it into `build/linux-svc-state-20261029p`.
The static replays give the same results as above.

### Original read, write and truncate path (2026-10-30)

The `fd-control` slice now runs the original read, write and truncate paths
down through shmem, the page cache and the inode timestamps
(`build/linux-fd-control-port-20261030c/kernel`; see
[Linux slices](linux-aarch64-slices.md)). The binding adds what they consume:

- `task.ioac.{rchar,wchar,syscr,syscw}`, the read/write accounting the
  original `vfs_read` and `vfs_write` update;
- `f_iocb_flags`, and `FMODE_ATOMIC_POS`, `FMODE_WRITER`, `FMODE_CAN_READ`,
  `FMODE_CAN_WRITE` and `FMODE_NONOTIFY` in the `f_mode` mask;
- per class, `inode_pool[].i_size` (now the file size, named by
  `file_data.size_field`) and `inode_pool[].i_flags` (`S_NOATIME`,
  `S_IMMUTABLE`, `S_NOCMTIME`, `S_SWAPFILE`, `S_NOSEC`);
- for the regular file, the `shmem_inode_info` seals, `alloced`, `swapped` and
  `fallocend`.

`shmem_inode_info` encloses the inode, so its fields are reached with a
`container_of` step in the typed path:
`.f_inode-><shmem_inode_info.vfs_inode>.seals`. The step dereferences the
pointer, checks that the named member has the pointee's BTF type and moves
back by the member's offset.

New preconditions hold what the model fixes: `RLIMIT_FSIZE` unlimited, and for
the regular file no fsnotify mark on its superblock, exactly one cached page, no
writable mapping, no lock context, an unhashed inode and `VM_NORESERVE`.

The mount configuration is a precondition as well, not bound state:

- superblock flags `SB_NOSEC | SB_I_VERSION`, with `SB_RDONLY`, `SB_NOATIME`,
  `SB_NODIRATIME` and `SB_LAZYTIME` clear;
- `s_maxbytes = MAX_LFS_FILESIZE`;
- no `MNT_NOATIME`, `MNT_NODIRATIME`, `MNT_RELATIME` or `MNT_READONLY` on the
  mount;
- no `BDI_CAP_WRITEBACK`.

The original code still reads all of these. They were first bound as members.
[KLEE state discovery](klee-state-discovery.md) then made every tested mount
bit a symbolic unknown, and `pread` and `pwrite` never finished exploring. They
are mount options, fixed for the lifetime of the mount, so the binding checks
them on each captured call and the model's superblock and mount carry them.
Timestamps, `i_version`, `i_state`, the folio's flags and the coarse clock
stay unobserved model state: the clock is not reachable from the task without
kernel symbols.

The 21 boundaries were recaptured into `build/linux-svc-state-20261030a`, and
again into `build/linux-svc-state-20261030b` after the mount configuration
became a precondition. The
live values match the model: seals `F_SEAL_SEAL`, one allocated page, `S_NOSEC`
on the inode and `SB_NOSEC | SB_I_VERSION` on the superblock.

The static replay is blocked on these boundaries. The footprint analysis
cannot follow the page cache. The xarray head, the folio and the page are
pointers built from model state, reached through pointer arithmetic and
`container_of`, and their extents are dynamic. `pread64`, `pwrite64` and
`ftruncate` report 186–292 blocked accesses, mostly unresolved pointer
origins and local pointers, and `ftruncate` also hits 75 analysis limits.
`fcntl` stays blocked as before (31 accesses).
[KLEE state discovery](klee-state-discovery.md#original-read-write-and-truncate-path-2026-10-30)
and concrete validation still check these boundaries. The analysis is
cached per input under `build/footprint-cache/`, and `OSREC_FOOTPRINT_TIMEOUT`
(default 300 s) bounds it.

### Binding the page-cache footprint (2026-11-03)

The `pread64` and `pwrite64` footprints became blocker-free on 2026-11-03 (see
[entry-state analysis](entry-state-analysis.md#flow-sensitive-values-and-path-correlations-2026-11-03)).
The replay then stopped at the binding check, with 46 and 48 schema fields
that the binding did not supply. All six `pread64`/`pwrite64` boundaries now
replay as equivalent.

The gap had four causes.

**Field mapping in `normalize`.** Three mapping bugs made reads that the
binding already supplied look unbound:
- An indexed member array (`uid_map.extent[2].count`) gained a second `[]`.
- A reference whose targets are one member of a pool (`i_mapping` →
  `inode_pool[0].i_data` / `inode_pool[1].i_data`) was rejected as ambiguous.
- A read below a transient leaf (`inode_wb.list_lock`,
  `s_fsnotify_info->watched_objects[0]`) ended in `?`. It now keeps its
  sub-path and is covered by that leaf.

A record read (`i_uid`) is covered when each of its leaves is.

**State the task reaches, now live-bound.**
- Per class: the inode's `i_uid`, `i_gid`, `i_state`, `i_version` and mapping
  `gfp_mask`, and the dentry's `DCACHE_FSNOTIFY_PARENT_WATCHED` bit.
- `task.thread_info.flags`, masked to `TIF_TAGGED_ADDR`.
- The regular file's folio: `flags`, `index` and `_refcount`. The xarray head is
  an untyped `void *`. The new `->(folio)` path step reads it as a
  `struct folio`, as `file_data` already does for the page bytes.

New links wire and check the class's pointers:
- `f_op`, `i_op` and `a_ops`;
- `f_mapping` and `i_mapping`, which must be the inode's own `i_data` (`object`);
- `i_data.host`, which must be the inode (`same_as`);
- the class-2 xarray head and the folio's `mapping` (links with a `class`).

The bound values differ from the old model seeds where it matters:
- The folio has no `PG_lru` and holds two references.
- The inode is clean before the first read; `pread` sets `I_DIRTY_SYNC`.
- `PG_workingset` and the MGLRU reference count (`LRU_REFS_MASK`, bit 57)
  advance on each access. The live bits move exactly as the model's
  `lru_gen_inc_refs` predicts. Bound without them, three boundaries diverged
  on the folio flags.

**Configuration held by preconditions.** A related precondition can name the
schema `field` whose model value it holds. The replay counts that field as
covered. The image exports the model value under the precondition's mask, and
the replay compares it with the precondition's value before and after the
call. This covers:
- the superblock flags, `s_maxbytes` and the mount flags (existing
  preconditions);
- `s_time_gran` = 1 and the full time64 range (new; all hold live);
- the null `s_fsnotify_info`;
- the bdi capabilities (0, now unmasked);
- one cached page, no writable mapping, no lock context, the unhashed inode
  and `VM_NORESERVE`.

A new precondition ties the shm superblock's user namespace to the initial
one. Inode locks and the mount writer count are transient zeroes.

**Declared model state.** The binding's `model_state` section lists fields it
cannot observe, each with its reason:
- the coarse clock `tk_core`: it is not reachable from the task, and
  `CONFIG_KALLSYMS_ALL` is off, so it has no data symbol;
- the inode timestamps, which are compared with and set from that clock;
- the per-class operation tables;
- the writeback association of a clean inode.

The replay report lists these reads under `footprint.model_state` and the
precondition-held ones under `footprint.held`.

**Two state ranges now decide branches.**
- `struct backing_dev_info.capabilities` ∈ [0, 0], validated by
  `live precondition noop_bdi.capabilities`. `balance_dirty_pages_ratelimited`
  then returns before the dirty-throttling counters.
- `struct uid_gid_map.nr_extents` ∈ [0, 5], validated by both maps' live
  `nr_extents`. The forward/reverse arrays of larger maps are then never read.

Two analyzer changes were needed for these ranges:
- **Mask intersection.** A constant mask's static bound (`x & 1` ∈ [0, 1]) used
  to hide the operand's declared range. It is now intersected with the
  operand-based interval.
- **Ranges as assumptions.** Every range the value analysis uses is now a
  `state_range_assumption`, so the replay checks it on both live states.
  Before, only index proofs recorded their ranges.

The 21 boundaries were recaptured into `build/linux-svc-state-20261103a`.

| Boundary | Result | Changed fields |
|---|---|---|
| `pread` | 4 | `rchar`, `syscr`, `i_state` |
| `pread-negative` | `-EINVAL` | — |
| `pread-all` | 10 | `rchar`, `syscr`, folio flags |
| `pwrite` | 2 | `wchar`, `syscw`, `i_version`, folio flags |
| `pwrite-extend` | 1 | `wchar`, `syscw`, `i_size`, `i_version`, folio flags |
| `pwrite-restore` | 4 | `wchar`, `syscw`, `i_version`, folio flags |

Each row is `equivalent`: result, user bytes and every bound field (177) match
the full VM before and after the call.

### fcntl (2026-11-03)

`fcntl` was blocked on six reads and writes of `close_on_exec[fd / 64]`. Linux
indexes the bitmap with the raw descriptor in `close_on_exec`,
`__set_close_on_exec` and `__clear_close_on_exec`. That is safe only because
`fdget` has already found the descriptor below `max_fds`, and that fact passes
through `__fget_light`'s tagged return and `__to_fd`'s `struct fd`.

The model's `close_on_exec` already flags a descriptor at or above `max_fds`
with `linux_assert`. The two bitmap stores now carry the same check (port
`build/linux-fd-control-port-20261103a`). Two changes make the check usable:
- **Analysis contract.** The new `fault_assertions` contract names
  `linux_assert` and its condition argument. After such a call statement the
  analysis takes the condition as false, so `fd < max_fds <= 64` bounds the
  index.
- **Replay check.** The replay image now exports `model_fault` after the call,
  and a faulted run is never `equivalent`. Before, `model_fault` was reset but
  never checked.

All 10 `fcntl` boundaries replay as `equivalent` with `model_fault = 0`. They
needed no binding additions. With `pread64` and `pwrite64`, 16 of the 21
captured boundaries replay.

`ftruncate` is still blocked. Its analysis now converges (see
[entry-state analysis](entry-state-analysis.md#fcntl-and-ftruncate-2026-11-03)),
but 200 accesses in the truncation path remain unproven.

### writev (2026-11-04)

The fd-control slice now has the `writev` root (`linux_writev`, number 66). It
runs the original `do_writev`, `vfs_writev`, `import_iovec`, `__import_iovec`,
`iovec_from_user` and `copy_iovec_from_user`. `do_iter_readv_writev` and
`do_loop_readv_writev` go through the reviewed `f_op` dispatch models.

Three bindings and models changed:
- **The user iovec.** The binding's `iovec` user object (id 65536) binds up to 8
  segments of 64 bytes each. The segments are objects from id 65537 up.
  `svc_boundary.py` reads the live array and merges segments that overlap.
- **User copies.** `unsafe_get_user` is a width-checked call to
  `linux_get_user`. User copies admit only objects the call names: the
  32-byte buffer and the iovec objects. They can't reach code or stack.
- **Fault models.** The compat copy, `kmalloc_array` (more than `UIO_FASTIOV`
  segments) and `iov_iter_bvec_advance` are fault models. A run that reaches
  one is never `equivalent`.

The replay image is now built with `-ftrivial-auto-var-init=pattern`. A
summarized stack array read before its element is defined then sees `0xAA`
bytes instead of a stale value that might match.

Since 2026-11-05, a port that declares `stack_init` is built that way instead,
for both its slices and the replay image. fd-control declares `zero`, matching
the live kernel's `CONFIG_INIT_STACK_ALL_ZERO`, which its binding requires.
The report claims `automatic_initialization`.

On port `build/linux-fd-control-port-20261103b` and captures
`build/linux-svc-state-20261103b`, every row below is `equivalent` with
`model_fault = 0`:

| Calls | Boundaries |
| --- | --- |
| `writev`: 2 segments; 1 segment (the `ubuf` path); 0 segments | 3 |
| `write` | 1 |
| `pread64`, `pwrite64` | 6 |
| `fcntl` | 10 |

The 10 `fcntl` boundaries and 7 file-I/O boundaries (17 in total) were replayed
again with the new analysis and build flags. 20 of the 27 captured boundaries
now replay. The 5 `ftruncate` boundaries remain blocked, and the two futex
calls have no slice root yet.

### Kernel data symbols (2026-11-04)

A futex hash bucket is not reachable from `current`. It hangs off the static
`__futex_data` (`queues`, `hashsize`). This kernel lists only text symbols
(`CONFIG_KALLSYMS_ALL` is off), and a static anonymous struct has no BTF
variable.

`tools/kernel_data_symbols.py` derives the address from the pinned Image
instead, using the review `integrations/linux_aarch64/data-symbols.json`:
- **References.** For each symbol, the review lists ADRP + ADD/LDR/STR pairs in
  named functions. The tool decodes each pair and rejects it if a branch, or a
  write that could hit the base register, comes in between. All references must
  agree on one address.
- **Image base.** The base is checked, not trusted: 98% of global text symbols
  (29349 of 29918) start with a function-entry encoding at that base.
- **Placement.** The address must lie in image data after init text.
- **Discovery.** `--list FUNCTION` prints the candidate pairs a reviewer reads
  against the source.

`__futex_data` comes out at `0xffff80008237a930` from three references:
`futex_hash` (ADD and LDR) and `futex_init` (ADD, which then stores
`futex_hashsize` at +8). The result is
`build/linux-data-symbols-d196f8248abdddab.json`.

`check_live` validates the reviewed layout against kernel memory in kernel
mode:
- `hashsize` is a power of two.
- `queues` is a 64-byte-aligned linear-map address.
- In every bucket with no waiters, the BTF `futex_hash_bucket` list head points
  to itself and the lock is free.

At the state checkpoint's first futex call, the check gives `queues =
0xffff000002f68000` and `hashsize = 256`, with all 256 buckets empty and
unlocked. The guest oracle still matches after the observation.

`tests/test_kernel_data_symbols.py` covers the derivation and its rejections on
a synthetic Image, and the live checks on synthetic memory.

**Per-CPU symbols (2026-11-05).**
- A reviewed symbol may be `percpu`. Its derived address is then the per-CPU
  link address, and the binding reads this CPU's copy at that address plus
  `TPIDR_EL1`.
- With `btf_record`, the reviewed layout must match the image's BTF.
- `rcu_data` is derived this way at `0xffff800081ec87c0`. `rcu_all_qs`, `rcu_qs`
  and `rcu_momentary_dyntick_idle` all form that address.
- Related members can also be per-CPU, such as the mount's `mnt_pcp->mnt_writers`
  and the freeze-protection `read_count`.

See [kernel binary replay](kernel-binary-replay.md#closing-the-gaps-2026-11-05).

### futex (2026-11-05)

The fd-control slice now has the `futex` root (`linux_futex`, number 98). It
covers two non-blocking private calls:
- `FUTEX_WAKE_PRIVATE` finding no waiter, which returns 0;
- `FUTEX_WAIT_PRIVATE` on a changed value, which returns `-EAGAIN`.

**Original code.** The slice runs v6.10's syscall entry and `do_futex`, plus:
- `futex_wake`, `futex_wait`, `__futex_wait` and `futex_wait_setup`;
- `get_futex_key`, `futex_hash`, `futex_q_lock`, `futex_q_unlock`,
  `futex_get_value_locked` and `futex_setup_timer`;
- the `futex.h` helpers, `jhash2` and `rol32`.

**Model state.** `futex_q_init` is copied verbatim from `requeue.c` into
`models.c`. `__futex_data` and a 256-bucket pool are model globals: `futex_init`
leaves buckets with no waiters and empty, self-linked chains, and the pool starts
the same way.

**Fault models.** The calls outside these two paths fault:
- shared keys (`get_user_pages_fast`);
- timeouts (`get_timespec64` and the hrtimer helpers);
- queueing and sleeping (`futex_wait_queue`, `futex_unqueue`);
- waking a waiter: `futex_wake`'s `this->wake(...)` is rewritten to the dispatch
  model `osrec_futex_q_wake`;
- the requeue, wake-op and PI commands.

`futex_wake_mark` and `futex_wait_restart` appear only as addresses (in
`futex_q_init.wake` and `set_restart_fn`'s argument). They need no context,
and the context transform now renames a function named in a const global's
initializer.

**Binding.**
- **`task.mm`** is bound as the live pointer value, because a private key hashes
  `{mm, page address, offset}`. The slice never dereferences it.
- **`task.timer_slack_ns`** is bound because `futex_wait` reads it.
- **The `globals` entry** binds `__futex_data` from the derived symbols. The
  capture takes `--data-symbols`, the derived file, and requires it to come from
  the checkpoint's kernel image; the observation then claims
  `kernel_symbols_used`. The projection:
  - runs `check_live`;
  - requires `hashsize` to equal the pool's 256;
  - binds each bucket's `waiters.counter` as a scalar and its lock word as free;
  - makes `__futex_data.queues` refer to `futex_hash_buckets[0]`.

**Contracts.**
- The hash size is in [256, 256], with `queues` given a pointer extent of
  `hashsize`. So `hash & (hashsize - 1)` selects one of the 256 bound buckets.
- Every bucket's `waiters.counter` is 0, checked on each pre- and post-state.
  This is why `futex_wake` returns before walking a chain.

Two states fall outside the slice:
- a waiter anywhere in the hash, which the range check rejects;
- a wait whose value matches, which faults in `futex_wait_queue`.

**Captures.** The binding changed, so all 27 boundaries were captured again
from the state checkpoint into `build/linux-svc-state-20261105a`. The port is
`build/linux-fd-control-port-20261105a`, built from a fresh native capture with
233 calls; its pipeline verified the slices.

**Results.** All 22 non-`ftruncate` boundaries replay as `equivalent`, with
`model_fault = 0`:
- 2 `futex`: wake → 0, wait → -11, each with 436 bound fields;
- 3 `writev`, 1 `write`, 3 `pread64`, 3 `pwrite64`;
- 10 `fcntl`.

**Negative check.** Setting the captured futex word to the expected value (6)
makes the wait take the sleep path. The replay then diverges with
`model_fault = 1`.

The binary replays of the two futex calls and the three `writev` calls are
equivalent too (`build/kernel-boundary-20261105`). See
[kernel binary replay](kernel-binary-replay.md#measuring-authenticity) for their
authentic-code shares.

### futex scenarios (2026-11-06)

The state checkpoint (`build/linux-svc-machine-checkpoint-state-20261105g`)
now makes 22 futex calls (`examples/linux-vm-checkpoint/init-state.c`). They
cover every non-blocking single-thread path: none needs a second thread,
blocking or waking.

| Group | Calls | Result |
|---|---|---|
| Wake and wait | private wake (no waiter), wait on a changed value | 0, -EAGAIN |
| Bitset | wait-bitset, wait-bitset with mask 0, wake-bitset | -EAGAIN, -EINVAL, 0 |
| Timeouts | absolute (`WAIT_BITSET`) and relative (`WAIT`), not firing; an invalid `tv_nsec` | -EAGAIN, -EAGAIN, -EINVAL |
| Errors | unknown command, unaligned word, unmapped word | -ENOSYS, -EINVAL, -EFAULT |
| Requeue | `REQUEUE`, `CMP_REQUEUE` with a mismatch and a match, no waiters | 0, -EAGAIN, 0 |
| Wake-op | `WAKE_OP` adding 1 to the second word | 0, word 3 → 4 |
| PI, uncontended | `LOCK_PI` (the task's first), `TRYLOCK_PI` of an own word, `UNLOCK_PI`, `TRYLOCK_PI`, `UNLOCK_PI` | 0, -EDEADLK, 0, 0, 0 |
| Shared | wake and wait without the private flag | 0, -EAGAIN |

**All 22 replay as `equivalent` from source**, with `model_fault = 0`
(`build/linux-svc-state-20261105g`, port `build/linux-fd-control-port-20261105g`).
The 23 earlier boundaries stay equivalent: 45 of 45.

**Original code added** to the fd-control slice:
- `futex_requeue` (requeue.c), `futex_wake_op` and `futex_atomic_op_inuser`
  (waitwake.c), `double_lock_hb`/`double_unlock_hb`, `wake_up_q`;
- `futex_lock_pi`, `futex_lock_pi_atomic`, `lock_pi_update_atomic`,
  `futex_unlock_pi`, `refill_pi_state_cache` (pi.c), `futex_top_waiter`,
  `futex_cmpxchg_value_locked` (core.c);
- the hrtimer setup and cancel of an on-stack sleeper (`hrtimer.c`:
  `__hrtimer_init`, `hrtimer_init_sleeper_on_stack`, `hrtimer_try_to_cancel`,
  `hrtimer_cancel`, `hrtimer_active`, `ktime_add_safe`), `get_timespec64`,
  `futex_init_timeout`, `copy_from_user`;
- `get_futex_key`'s shared branch with `folio_test_anon`;
- the kmalloc-96 allocation of the first `pi_state`: `kzalloc_noprof`,
  `__kmalloc_index`, `kmalloc_trace_noprof` and SLUB's fast path;
- the original list walks (`plist_for_each_entry{,_safe}`): the analysis
  proves each ends at its empty head (see
  [entry-state analysis](entry-state-analysis.md#futex-scenarios-2026-11-06)).

**Reviewed models** where the kernel is assembly or outside the slice:
- arm64's `__futex_atomic_op` and `futex_atomic_cmpxchg_inatomic` (LDXR/STLXR
  loops): one load and store of the admitted user word;
- GUP-fast for one page: the bound page, a folio reference and
  `folio_set_referenced`, as `gup_fast_pte_range` does;
- `ktime_get` returns 0: the counter is not reproducible, and the value only
  arms a timer that is cancelled unarmed;
- faulting models for everything contended: queueing and waking a waiter,
  the rt_mutex proxy lock, attaching a `pi_state` to another owner.

**Binding additions** (`tools/live_kernel_binding.py`, `live-binding.json`):
- **`command_pointers`**: futex's `utime` (16 bytes) and `uaddr2` (4 bytes)
  become user objects only for the commands that read them.
- **Unmapped objects**: a named object the user address space does not map
  stays an object with no access, so the replay faults the same way (EFAULT).
- **`hrtimer_bases`** (a per-CPU data symbol, calibrated through `rcu_data`'s
  BTF per-CPU offset): each clock base's `seq` and `running`.
- **Preconditions on derived symbols**: `current->nsproxy->time_ns` must be
  `init_time_ns`.
- **`empty_lists`**: every live hash bucket's chain must be self-linked.
- **`opaque_pointers`**: `task.pi_state_cache` is carried as a value. After the
  first `LOCK_PI` it names the kmalloc-96 object, and is exported as that
  object's live address.
- **`user_page`**: for a shared futex, the binding walks the task's page tables
  (TTBR0_EL1, four levels, linear map through the derived `memstart_addr`). It
  requires a user page that `pte_write()` admits, and binds that folio's
  `flags`, `_refcount` and `mapping`.
- **`extra_caches`**: kmalloc-96 is bound like kmalloc-192 (cache, per-CPU
  state, freelist head object, slab).
- **Pinned post-state objects**: the post-state binds the slab object at the
  pre-state's head address, so an allocation is compared on the object it
  returned, not on the next free one. Words holding an address inside the
  object (the new `pi_state`'s self-linked list) are exported as live
  addresses.

The binary replays are 21 of 22 equivalent: the relative-timeout wait reads
the arch counter, which a replay cannot reproduce (see
[kernel binary replay](kernel-binary-replay.md#futex-scenarios-2026-11-06)).

## Limits

- The binding is reviewed per profile. BTF supplies layout, not meaning. The
  `f_mode` projection keeps only consumed bits, and the console's live mode
  (`0xe0003` → `0x3`) differs from the `FMODE_STREAM` seed the earlier native
  preparation assumed. Console I/O is outside the admitted routes, so no
  observed call exercises the difference.
- Page-cache bytes rely on the arm64 VA_BITS=48/4K vmemmap→linear-map relation
  (`page_offset + ((page - vmemmap_start) / sizeof(struct page) << 12)`). The
  binding pins that configuration and requires one direct xarray entry.
- The footprint relies on one declared field range (`max_fds ≤ 64`), checked on
  each replayed state, and on the transfer model's explicit capacity guard; the
  interval analysis cannot express that relational loop bound by itself.
- [KLEE state discovery](klee-state-discovery.md) runs each root symbolically on
  the observed object graph. It checks which footprint fields the call actually
  needs. On `read`, `write` and `close`, every required field lies in the
  static footprint.
- A proprietary kernel needs its own contract, anchor register, type source and
  binding. A DWARF type source with the same interface is available; see
  [kernel type sources](kernel-type-sources.md).
- This replays one call with the kernel side reduced. It does not yet:
  - resume the user continuation in the reduced image;
  - chain several boundaries;
  - run the full-VM user state in a standalone ELF.

  Joint continuity across boundaries (gap 3) and standalone execution (gap 6)
  remain open.
