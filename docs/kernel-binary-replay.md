# Kernel binary replay

A replay of a system call should run authentic kernel code, not models of it.
The source slices compile the original syscall bodies and replace everything
below and around them with reviewed models. Measured against the live kernel,
they cover 55% of the instructions a call executes (see
[Measuring authenticity](#measuring-authenticity)).

The binary replay runs the kernel's own machine code instead. It covers every
instruction from the SVC vector to the return to user mode, entry and exit
included.

## Capture

`tools/kernel_boundary_capture.py` takes a full-machine checkpoint and a
selection, like `svc_boundary.py`, and runs the checkpoint three times. It
needs no kernel symbols and no binding.

1. **Entry.** A gdbstub stops at the selected synchronous lower-EL vector entry.
   The tool records the general-purpose and FP/SIMD registers and 29 EL1 system
   registers, then saves the machine there as an entry snapshot. The source
   QEMU runs with `migration.store-global-state=off`: a snapshot taken at a
   debugger stop would otherwise carry the `debug` run state, which an incoming
   machine cannot enter.
2. **Trace.** The entry snapshot single-steps to the user continuation under
   the TCG plugin `tools/qemu_plugins/footprint.c`. The plugin records every
   executed instruction and every memory access: virtual and physical address,
   size, load or store.
   - Stepping masks interrupts and timers. Without it, a timer tick that came
     due while the snapshot was saved and restored runs first, and the call
     never returns.
   - At the continuation, the tool reads the post-state of every touched
     physical page and the user registers.
3. **Pre-state.** The paused entry snapshot supplies the pre-state of the same
   pages, and of the page-table pages the kernel's own tables use to translate
   every touched virtual page. Each traced access's physical page must agree
   with the table walk.

A call that touches device memory is refused.

## Replay

`tools/kernel_boundary_replay.py` builds an ELF image from the capture. Every
captured page sits at its live physical address: the kernel instructions,
data, stacks and the kernel's translation tables. RAM matches the live
machine: 512 MiB at `0x40000000`.

A stub at EL2 starts the call. EL2 has its own translation regime, so it can
switch the EL1&0 MMU on without being mapped there itself. The stub:

- sets `HCR_EL2.RW` (no traps) and gives EL1 counter and timer access;
- copies `MIDR`/`MPIDR` to `VPIDR_EL2`/`VMPIDR_EL2`, so EL1 reads them
  unchanged;
- restores the captured EL1 system registers, ending with `SCTLR_EL1`;
- restores the FP/SIMD and user registers;
- `eret`s to EL0 at the trap instruction.

The CPU then takes the SVC itself, and the kernel runs from its vector exactly
as it did live. No interrupt controller is configured, so no interrupt
arrives, as in the stepped trace. The same plugin traces the replay. Breakpoints
on the EL1-from-EL1 vectors catch any fault or interrupt the live call did not
take.

The replay is `equivalent` only when all of these hold:

- it returns to the continuation in EL0;
- its kernel instruction sequence equals the live trace;
- its memory accesses (virtual and physical address, size, kind) equal the live
  trace;
- its user registers equal the live ones;
- every touched page equals its live post-state.

```sh
cmake -S . -B build/cmake -DOSREC_BUILD_KERNEL_BINARY_REPLAY=ON
cmake --build build/cmake --target osrec_footprint
export OSREC_FOOTPRINT_PLUGIN=$PWD/build/cmake/libfootprint.so
python3 tools/kernel_boundary_capture.py \
  --checkpoint build/linux-svc-machine-checkpoint-state-20261029b/checkpoint \
  --select number=25 --select x0=4 --select x1=2 --select x2=1 --out build/fcntl-capture
python3 tools/kernel_boundary_replay.py --capture build/fcntl-capture --out build/fcntl-replay
```

## Results (2026-10-29)

38 boundaries on Linux 6.10 were captured into
`build/kernel-boundary-20261029/capture-*` and replayed into `replay-*`. Of
these, 24 come from the state checkpoint (`init-state.c`) and 14 from the
identity checkpoint (`init-ids.c`). Every one is equivalent, and every replayed
kernel instruction is the live kernel's own.

| Calls | Kernel instructions | Pages in the image |
|---|---|---|
| `getppid`, `geteuid`, `getgid`, `getegid`, `gettid`, `umask` | 253–310 | 27–33 |
| `-EBADF`/`-EINVAL` paths of `dup`, `dup3`, `close`, `lseek`, `fcntl`, `pread64`, `ftruncate` | 257–399 | 26–37 |
| `fcntl` `F_GETFD`, `F_SETFD`, `F_GETFL` | 376–423 | 36 |
| `close`, `lseek`, `getresgid` | 368–494 | 34–38 |
| `fcntl` `F_DUPFD`, `F_DUPFD_CLOEXEC` | 598–599 | 38–39 |
| zero-length `write`, `read` | 632, 1,289 | 45, 64 |
| `read`, `pread64` | 1,365–1,524 | 73–76 |
| `write`, `pwrite64` | 1,544–1,816 | 79–90 |
| `ftruncate` (grow, shrink) | 1,164–2,563 | 60–78 |

The image needs no kernel image file: it holds only the pages the call used,
26–90 per call, plus the stub. These include code through shmem, the page cache,
iov copying, atime and inode timestamp updates, writeback list handling and
LSM hooks.

`tests/test_kernel_boundary.py` checks the table walker (4- and 3-level, with
block mappings), the trace parser, the ELF image and the stub. It also captures
and replays `fcntl` live, and checks that a changed pre-state diverges.

## Measuring authenticity

`tools/linux_kallsyms.py` boots the kernel image with a PID 1
(`examples/linux-vm-checkpoint/init-kallsyms.c`) that prints `/proc/kallsyms`.
It opens it through a detached proc mount, so the root disk needs no `/proc`.
The output for this image is `build/linux-kallsyms-d196f8248abdddab.txt`.

`tools/kernel_authenticity.py` attributes each traced live instruction to a
kernel function. It then reports which share of the live call a replay runs as
authentic kernel code:

- **A source slice** covers a function when the slice holds that function's
  original body and the call's own slice root (`linux_NAME` for
  `__arm64_sys_NAME`) reaches it in the slice's static call graph. Reviewed
  models, code the slice leaves out, and originals only other calls reach don't
  count.
- **A binary replay** covers the instructions it executes from the kernel
  image, if it is equivalent.

Across the 38 calls (28,711 live instructions), set against the `fd-control`
source slice:

| | Before (2026-10-29) | Original `fcntl` entry | Original descriptor lookups | Original read/write/truncate path | arm64 `memset.S` | C system call entry | arm64 `entry.S` | ID mapping, close, bit search | User copies | LSM hooks |
|---|---|---|---|---|---|---|---|---|---|---|
| Original slice code | 7.0% | 9.0% | 11.4% | 54.9% | 58.4% | 71.6% | 90.0% | 92.0% | 92.9% | **95.3%** |
| Reviewed models | 8.5% | 7.2% | 7.2% | 5.9% | 5.9% | 5.9% | 5.9% | 5.2% | 4.4% | 1.9% |
| Code the slices leave out | 84.6% | 83.8% | 81.3% | 39.2% | 35.7% | 22.5% | 4.1% | 2.8% | 2.8% | 2.8% |
| **Binary replay** | **100%** | **100%** | **100%** | **100%** | **100%** | **100%** | **100%** | **100%** | **100%** | **100%** |

Syscall entry and exit (`vectors`, `el0t_64_sync`, `el0_svc`,
`invoke_syscall`, `ret_to_user`) are 31.6% of all instructions. The slices now
run all of it.

- **The `fcntl` entry** (`build/linux-fd-control-port-20261029n`):
  `SYSCALL_DEFINE3(fcntl)`, `check_fcntl_cmd` and `do_fcntl` are now the original
  `fs/fcntl.c` bodies, replacing the reviewed five-command model.
- **The descriptor lookups** (`build/linux-fd-control-port-20261029p`):
  `fdget`, `fdget_raw`, `fdput`, `__fdget`, `__fdget_raw`, `__fget_light` and
  `files_lookup_fd_raw` are original. They need one more bound field,
  `files->count`, which selects the single-owner fast path.
- **The read/write/truncate path** (`build/linux-fd-control-port-20261030c`):
  `fdget_pos`, `vfs_read`, `vfs_write` and everything below them down to
  shmem, the page cache and the inode timestamps are original, as are
  `do_truncate`, `notify_change`, `shmem_setattr` and the page-cache undo
  ([Linux slices](linux-aarch64-slices.md) lists them).
- **`memset`** (`build/linux-fd-control-port-20261030f`): the original arm64
  assembly, which needs Normal memory. The slice image now starts with an
  identity-mapped MMU
  ([MMU-on harness](linux-aarch64-slices.md#mmu-on-harness)). The measurement
  counts the functions an original `linux-*.S` file defines
  (`SYM_FUNC_START`, `SYM_FUNC_ALIAS`) when a reachable slice function calls
  them. Only `ftruncate` calls `memset`: shrink and restore go from 64.3% to
  83.1%, grow from 62.1% to 65.3%. The slice zeroes the model's 64-byte page
  store; the live call zeroes the rest of a 4 KiB page. The share counts the
  function, not its instruction count.
- **System call entry and exit** (`build/linux-fd-control-port-20261030h`):
  every call enters through Linux's own code.
  - The C chain is original: `el0t_64_sync_handler`, `el0_svc`, `do_el0_svc`,
    `el0_svc_common`, `invoke_syscall`. It took the share to 71.6%
    (`build/linux-fd-control-port-20261030g`).
  - `entry.S` is assembled verbatim: `vectors`, `kernel_entry` in
    `el0t_64_sync`, `ret_to_user` and `kernel_exit`.
  - A reviewed glue file models the hardware's part of an SVC. The return
    through `kernel_exit`'s ERET is real
    ([Linux slices](linux-aarch64-slices.md#system-call-entry-and-exit)).
  - The system call table holds numbers, not pointers, so the table call is a
    model.
  - The measurement adds `el0t_64_sync_handler` as a root and credits the
    entry assembly with it. Its traversal stops at other calls' roots.

Per call, the read/write/truncate path moves:

| Calls | Before | After |
|---|---|---|
| `read`, `pread64` (incl. zero-length and to end of file) | 6.0–7.6% | 65.9–73.2% |
| `write`, `pwrite64` | 4.5–6.9% | 76.9–78.8% |
| zero-length `write` | 13.0% | 50.6% |
| `ftruncate` grow, shrink, restore | 5.9–12.9% | 62.1–64.3% |
| `lseek` | 8.9–15.2% | 24.1–28.3% |

`fcntl`, `dup`, `close` and the identity calls are unchanged.

- **ID mapping, close and bit search** (`build/linux-fd-control-port-20261030j`,
  like the next two): `from_kuid_munged` through `map_id_up` over the
  namespace's live `uid_map`/`gid_map`; `filp_flush`, `dnotify_flush` and
  `locks_remove_posix` on close; `expand_files` and `find_next_zero_bit`.
- **User copies:** `_copy_to_iter`, `__copy_from_iter`, the `iov_iter.h`
  iterators, `copy_to_user_iter`, `copy_from_user_iter` and `access_ok`. Only
  the `copy_*_user.S` primitives remain models.
- **LSM hooks:** the five `security_*` hooks walk their hook lists as the
  kernel does. Each list holds BPF's no-op attachment point, which the
  measurement counts as left out: it is defined in `model.h`, not as slice
  code.

What remains is 1.9% reviewed models and 2.8% left-out code:

- **Models:** the per-CPU mount writer count, the rwsems, the writeback list
  lock (`locked_inode_to_wb_and_lock_list`), `dquot_initialize` and
  `__fput_sync`.
- **Left out:** `__cond_resched` with `rcu_all_qs`, `__dquot_initialize`,
  `percpu_up_read`, the cgroup writeback attach, `__task_pid_nr_ns`,
  `shmem_file_llseek`, the `copy_*_user.S` primitives and BPF's hook
  defaults. `close`'s `memset` is
  the compiler's stack zeroing (`CONFIG_INIT_STACK_ALL_ZERO`), which the
  slice build does not reproduce.

Calls with no models on their path (`umask`, the error returns) run 100%
original code. Every call is now 84.4–100%:

| Calls | Before entry | After entry | Now |
|---|---|---|---|
| `read`, `pread64` | 65.9–73.2% | 81.6–91.7% | 89.8–96.5% |
| `write`, `pwrite64` | 50.6–78.8% | 88.4–92.4% | 92.6–94.0% |
| `ftruncate` grow, shrink, restore | 65.3–83.1% | 85.8–92.4% | 92.7–95.6% |
| `fcntl` | 23.2–43.4% | 83.3–100% | 98.9–100% |
| `close`, `dup` errors, `lseek` | 10.2–28.3% | 67.8–100% | 84.4–100% |
| identity queries (`getuid`, `getresgid`, ...) | 4.5–15.3% | 64.7–91.0% | 89.7–100% |
| `umask`, `pread64`/`ftruncate` error returns | 5.5–30.5% | 100% | 100% |

## Scope

- A capture covers one call from one machine state. The replay reproduces that
  path; it does not explore other inputs.
  [KLEE state discovery](klee-state-discovery.md) does that on the source
  slices.
- Hardware the call reads must be reproducible. QEMU models the same CPU. The
  generic counter can differ; none of the 38 calls' results depended on it.
- The binary replay needs no source and no symbols, which suits a proprietary
  kernel. Symbols are used only to attribute instructions to functions.
