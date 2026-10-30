# Minimal ramfs Linux target

The primary Linux analysis target is now a kernel we build ourselves from the
analyzed source. The linuxkit kernel stays as a regression target for the
existing profiles.

## Build

`integrations/linux_aarch64/ramfs-kernel/` contains the container recipe
(`Dockerfile`, Debian trixie with clang 19), `build.sh` and the resulting
`config`. The source is `linux-6.10.14.tar.xz`; its SHA-256 matches the
kernel.org list, though the list's signature was not checked. It is unpacked
on a case-sensitive volume (`build/linux-6.10.14-src.sparseimage`, mounted at
`/Volumes/osrec-linux-6.10.14`) because the tree has names that differ only by
case.

The configuration starts from `tinyconfig` and adds:

- `MULTIUSER`, `BLK_DEV_INITRD`, `BINFMT_ELF` and a PL011 console;
- `EXPERT` and `MEMFD_CREATE`;
- `VA_BITS=48` with 4K pages;
- DWARF 5.

`SHMEM`, `TMPFS`, `BLOCK` and modules are disabled. Rootfs is therefore ramfs,
and memfd files are tiny-shmem files that use ramfs file operations. `build.sh`
fails a requested option that does not survive `olddefconfig` into
`config-check.txt`.

The result is a 3.1 MB `Image`, a `vmlinux` with DWARF, and
`compile_commands.json`. The build commands use host-compatible absolute paths,
so `tools/entry_state.py` can read them with Homebrew clang 19.

## Capture

`tools/capture_linux_aarch64.py --root initramfs` builds an initramfs with
`tools/minimal_initramfs.py`. It holds `/init` and `/dev/console`. The tool
boots with `-initrd … rdinit=/init` and attaches no block device. The
prerequisites become `BLK_DEV_INITRD` instead of ext4/virtio, and `MEMFD_CREATE`
without `SHMEM`.

The file profiles' private descriptor-class probe reads the `fstat` file type
on ramfs roots, because ramfs memfds have no seals. Disk captures keep the seal
probe.

The `file-io` capture (`build/linux-ramfs-file-io-capture-20261026`) records
118 calls. Its entry state and every call observation are identical to the
linuxkit capture.

## Source correspondence

- **Own build.** The booted Image is built from the analyzed tree, configuration
  and compiler, so correspondence holds by construction.
- **Pinned excerpts.** The v6.10 excerpts used by the reviewed slices match
  6.10.14, with one exception: `fs/file.c` `__close_range`. A stable backport
  rewrote its `CLOSE_RANGE_UNSHARE` path to unshare only when the table is
  shared, using `dup_fd` with a punched hole.
- **Uapi values.** The uapi macro values are identical.

## Whole-source analysis (first measurement)

A single real unit, `fs/read_write.c`, takes about 40 s, peaks at 1.7 GiB RSS
and has an 835 MiB JSON AST. With roots `ksys_read`/`ksys_write` it reports 52
and 95 blockers. They fall into five groups:

- **Arch primitives:** `get_current`, per-CPU operations, atomics and rwsem.
- **Callees in other units:** `__fdget_pos`, `fput` and similar.
- **Compile-time-only calls:** `__builtin_constant_p`, `__compiletime_assert_*`
  and `__bad_size_call_parameter`.
- **The `f_op` indirect call.**
- **Pointer origins** that depend on the groups above.

### Architecture tier and compile-time calls

`integrations/linux_aarch64/ramfs-kernel/analysis-contracts.json` declares:

- `get_current` as an object provider, the SVC anchor read through `mrs sp_el0`;
- the `sb->s_writers` per-CPU rwsem operations as ordering models;
- `struct thread_info.flags` as a volatile snapshot field.

`--linked-symbols` passes `llvm-nm` output for `vmlinux`, which has no undefined
symbols. The analyzer also recognizes:

| Rule | Covers |
| --- | --- |
| Compile-time builtins | `__builtin_constant_p` (its operand is not evaluated) and `__builtin_unreachable` |
| Build-eliminated calls | `error`-attributed functions, and externals with no definition in the linked image |
| Traps | An operand-free asm followed by `__builtin_unreachable()` (arm64 `BUG()`) ends the path |
| One-element bitmaps | A scalar field taken by address is a one-element array for bitmap helpers |
| Struct-element arrays | Inline arrays of structs form bounded pointers; ordering models may name such locks |
| Integer addresses | Integer-to-pointer conversions block only when dereferenced |

| Step | `ksys_read` | `ksys_write` |
| --- | --- | --- |
| Baseline | 52 | 95 |
| Compile-time calls, `get_current` | 42 | 80 |
| Integer addresses at use, lock models | 37 | 45 |
| Traps, volatile snapshot, struct arrays | 35 | 43 |

No assembly, atomic, integer-address or volatile blockers remain. What remains
on both roots:

- the fd tagged pointer: `__fdget_pos` in `fs/file.c` returns
  `(unsigned long)file | flags`, and `__to_fd` recovers it with `& ~3`;
- local `kiocb` and `iov_iter` records initialized through their address;
- the `f_op->read_iter`/`write_iter` callback;
- the pointer origins that depend on these.

Tests are in `tests/test_entry_state_kernel_idioms.py`. Evidence is in
`build/linux-ramfs-analysis-20261026/report.json`.

### Closure with `fs/file.c`

Analyzing `fs/read_write.c` together with `fs/file.c` resolves the real
descriptor lookup. With both units loaded the run peaks at 3.1 GiB and takes
about 12 minutes on a loaded host.

| Step | `ksys_read` | `ksys_write` |
| --- | --- | --- |
| Single unit after the architecture tier | 35 | 43 |
| Closure with `fs/file.c` | **4** | **4** |

**Analyzer mechanisms:**

| Mechanism | What it covers |
| --- | --- |
| Tagged integer provenance | `(unsigned long)file`, `1 \| ptr` and `v \|= FDPUT_POS_UNLOCK` carry pointer origins with low tag bits; `(T *)(v & ~L)` recovers them only when every tag is cleared and the pointee's alignment exceeds the cleared bits. Integers without provenance are tagged nulls (constants up to 7) or unresolved. |
| Guarded tag OR | A tag OR under a non-null guard on the pointer recovered from the same word applies only to non-null alternatives. |
| Tag-linked fields | `{(T *)(v & ~3), v & 3}` records that a non-zero flags field implies a non-null file, so `fdput`'s `if (fd.flags & FDPUT_FPUT) fput(fd.file)` resolves. A tagged null breaks the link. |
| `READ_ONCE` views | Clang's `NoOp` qualification casts that add `volatile` keep array-element provenance. Dereferenced object paths may decay arrays. |
| Infeasible paths | A pointer whose only value is null, read behind a non-null guard (fsnotify with `CONFIG_FSNOTIFY` off), is recorded as infeasible. |
| Anonymous members | Members of anonymous structs and unions are transparent in paths. |

**Contracts** (`analysis-contracts.json`):

- `array_index_mask_nospec` is an `index_mask` value model, because arm64
  implements it in assembly;
- `raw_atomic64_cmpxchg` and `raw_atomic_read_acquire` are memory models with
  declared argument reads and writes;
- mutexes and RCU read sections are ordering models;
- `fput` reads and writes its file until `fs/file_table.c` joins the closure;
- `fdtable.max_fds` is exactly 64, and `fdtable.fd` points to `max_fds`
  elements (a pointer extent);
- operand-free asm has no memory effects;
- volatile accesses are sequential snapshots.

**Discovered footprint.** It includes:

- `current->files->count`, `files->fdt`, `max_fds` and `fd[0..63]`;
- each file's `f_mode`, `f_pos`, `f_count`, `f_op->read`, `f_op->read_iter` and
  `f_iocb_flags`;
- the `f_path.dentry`/`d_inode`/`i_sb` chain;
- on the write path, `sb->s_writers`.

**Remaining blockers on each root:**

- the `f_op->read_iter`/`write_iter` callback (two sites);
- the stack-allocated `kiocb` and `iov_iter`, which `init_sync_kiocb` and
  `iov_iter_ubuf` initialize through their address.
