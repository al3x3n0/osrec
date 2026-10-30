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
| `integrations/linux_aarch64/fd-control/live-binding.json` | The `file-io` binding extended to the `fd-control` slice (`fcntl`, `pread64`, `pwrite64`, `ftruncate`). It binds each live file's dentry and inode as related objects (see [related objects](#related-objects)). The `f_mode` mask also keeps `FMODE_PREAD` and `FMODE_PWRITE`. A precondition requires `RLIMIT_NOFILE` to be the model's 8 (see [preconditions](#preconditions)). |
| `tools/gdb_remote.py` | Minimal GDB remote client for QEMU's TCG gdbstub. |
| `tools/kernel_btf.py` | Embedded BTF reader and typed path resolver (`.member`, `->member`, `[n]`, anonymous records; bitfields rejected). |
| `tools/live_kernel_binding.py` | Applies a binding to live memory. It rejects unbound object classes, more than one live object per pool class, a mismatched embedded `fdt`, a descriptor capacity differing from the model, and file bytes beyond `i_size`. |
| `tools/svc_boundary.py` | Captures the boundary from a machine checkpoint. |
| `tools/reduced_boundary_replay.py` | Runs the footprint check, generates the image, executes it in QEMU and compares the result. |

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
