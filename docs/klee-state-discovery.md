# KLEE state discovery

`tools/klee_state_discovery.py` asks which bound kernel state a slice root
actually depends on for one captured Linux boundary. It runs the root under
KLEE with the bound state symbolic. It then compares the inputs that symbolic
execution needs with the static Clang entry-state footprint
([entry-state analysis](entry-state-analysis.md)).

```
python3 tools/klee_state_discovery.py \
  --boundary build/linux-svc-unblocked-20261026/observe-read/boundary.json \
  --slice build/linux-transfer-guard-rebuild-20261026/file-io/kernel \
  --binding integrations/linux_aarch64/file-io/live-binding.json \
  --contracts integrations/linux_aarch64/file-io/analysis-contracts.json \
  --max-time 1200 --out build/klee-state-read
```

The inputs are:

- an `svc_boundary.py` observation;
- the published callable-slice port that the observation was compared with;
- the reviewed live binding;
- optionally, the analysis contracts.

The tool checks that the binding, slice sources and kernel image hash match the
observation.

## Driver

The generated driver (`klee_driver.c`) does the following:

- Restores the observed pre-state.
- Keeps the observed object graph concrete: descriptor slots and embedded
  links.
- Makes concrete the scalars that the binding fixes with `require`/`equals`.
  These are model preconditions, not state to discover.
- Makes symbolic every other bound scalar, the file bytes and each admitted
  user object. Each one is a separate, exactly sized KLEE object.
- Keeps syscall arguments as observed. `--symbolic-arg INDEX:LOW:HIGH` widens
  one argument. `INDEX:LOW:HIGH:split` also forks one path per value (see
  [Symbolic arguments](#symbolic-arguments)).
- Keeps the context members listed in the contracts' `klee_separate_members`
  (`file_data`) in their own KLEE objects (see below).
- Calls the root directly (`osrec_kernel_dispatch_root`) when the slice
  provides it. `fd-control` enters every call through Linux's assembly entry,
  which KLEE's bitcode cannot hold; discovery starts below it, at the root. The
  validation and reduced-replay images do the same.

### Separate objects

KLEE models each C object as one array. The slice keeps all kernel state in
one 888-byte context struct, and a file write stores to
`file_data.bytes[f_pos + i]` at a symbolic index. From then on, every read of
any context field is an array query over all 888 bytes, with the stored bytes
as an update list.

For the KLEE build only, the tool compiles a copy of the sources in which
`slice_context.h` holds each listed member as a pointer to a separate global
(`osrec_separate_file_data`). `#define file_data osrec_separate_file_data[0]`
keeps every `ctx->file_data` access unchanged. The restore re-points the
member after zeroing the context. The static footprint, the validator and the
published slice keep the original layout. The validator replays every
in-domain KTest on that layout, which checks that KLEE's results carry over.
They do for every run below, and the results match the flat layout exactly.

Measured as CPU time (KLEE with its solver processes):

| Run | Flat context | Separate `file_data` |
|-----|--------------|----------------------|
| write, captured call | 25 s, 114 solver queries | 15 s, 85 queries |
| read, captured call | 90–100 s, 331 queries | 80–84 s, 331 queries |
| write, count 0–16 split | 4395 queries | 1679 queries |
| write, count 0–16 split, dependency analysis | 454 s solver, 43 s Python | 65 s solver, 15 s Python |

`--separate-member` adds members for one run.

`--split-field FIELD:LOW:HIGH` forks a symbolic state field per value, as
`split` does for arguments. Splitting `file_pool[1].f_pos` over 0–64 makes
every file index concrete and cuts the cost per query about 20×. It also
multiplies the paths: the captured write needed 45× more queries. Splitting
`file_pool[].f_pos` forks both pool files before the call, 65 × 65 ways.
Neither variant is used.

Input domains are shaped with branch-free expressions, not with `klee_assume`.
This keeps a domain constraint from appearing as a use of the input. Each
shaping is the identity inside its domain:

- **Declared ranges** keep a value in `[low, high]` and fold any other value
  into that range.
- **Referenced pool files** take `max(f_count, 1)`. A descriptor-table slot
  holds a file reference (Linux `fd_install`/`get_file`).

**Graph invariants** (`graph_invariants` in the contracts) tie descriptor
fields to the observed slots. They are evaluated on each observed state's own
slots, and every pre- and post-state must satisfy them:

- `slot_mask`: `open_fds` equals the installed slots. Between calls of a
  single-threaded task, no descriptor is reserved without being installed.
- `full_slot_words`: `full_fds_bits` marks the full `open_fds` words.
- `at_most_first_free_slot`: `next_fd` is at most the lowest free
  descriptor. It becomes a range.

Fields the graph determines stay concrete and are reported as
`fixed_by_graph`, like the slots themselves. `close_on_exec` has no such
invariant. After `close(3)` of a memfd created with `MFD_CLOEXEC`, bit 3 stays
set. Linux clears it only when the number is allocated again. The live check
rejected that candidate invariant.

After the call, each output is observed through a fresh symbolic array that is
constrained to equal it: the result, `model_fault`, and the fields in the
static write set (with user and file bytes). The rest of the state cannot
change, because the static writes over-approximate it. If the static footprint
is blocked, its write set can miss writes through the accesses it could not
resolve. In that case every bound field is observed, `static_write_set` is
null, `static_blockers` lists the blockers, and the static reads are only a
lower bound for the comparison.

## Dependencies

KLEE writes one KQuery per path (`--write-kqueries`). The parser handles:

- labels;
- labelled and unlabelled update lists;
- versions that extend another version (`U3:[…] @ U2`).

A read through an update list depends only on the entries its index can hit.
When an index or entry index has no finite candidate set, the question goes to
STP through KLEE's `kleaver`.

- KQuery labels are scoped to one query, so each question is printed
  standalone, with every label defined at its first use.
- Each question runs in its own process. On the same path, a 20-question batch
  in one process took 386 s; separate processes took under 1 s per question.
- Update entries are grouped into runs, one per stored field.
- Each path's KTest is a model of its constraints. An evaluator checks this:
  on the 150 paths below it satisfies all 4540 constraints. Each distinct
  symbolic index is evaluated under that model. One query then proves that the
  index never leaves the field it hits. Reads are then decided by interval
  overlap, with no further queries.
- An index that cannot be confined is bisected over runs: a group the index
  cannot reach is pruned, a reachable group is split, and an undecided group
  counts as reachable.

On the write boundary this cut solver calls from 581 to 88, with identical
results. The domain-implied check described below adds a few queries, for 110
in total. KLEE exploration itself takes 1 s (close), 27 s (write) and 1 min
42 s (read).

### Sibling paths with equal outputs

A condition can select between two paths that compute the same result. A
zero-length `read` returns 0 whether the position is at or past the end of the
file or not, so `file_data.size` only picks one of two equal outcomes.

Each in-domain path records its outputs: `unchanged`, or a constant. A constant
is the output's KTest value, proven by one question to hold on the whole path.
It also records a content key per condition, from the canonical standalone
print. Two paths merge when:

- their outputs are equal;
- their conditions differ only in `c` on one and `(Eq false c)` on the other.

The merged region is their common prefix, and merging repeats to a fixpoint.
With complete exploration and no error or partial paths, the regions partition
the model domain. An input named by no remaining condition and no output then
cannot change the outcome, including whether the path faults. Such inputs are
reported as `control_without_effect`. Conditions that separate the domain from
model faults stay, because the fault paths never merge.

### Question size

Every field is copied into one flat context object. A read through its update
list therefore names nearly every input, and an unsliced question carries the
whole path: 20–45 KB, with the 884 stores of the context. Four reductions keep
questions small:

- **Slicing.** A question carries only the constraints connected to its claim
  through shared inputs. Inputs are the ones `dependencies` finds, so a read
  counts only the stores its index can hit. An observed output is a fresh
  array that only its own constraint defines. That constraint holds for any
  inputs, so it joins a question only if the claim names the output.
- **Pruned update lists.** A read prints only the stores it can return. With
  constant indices this is syntactic: the newest store of each byte. With
  symbolic indices it uses the reachable entries, which hold under the path
  constraints, so questions asked without the path prune syntactically only.
- **Canonical labels.** Labels are numbered in order of definition, so equal
  questions from different paths print the same text.
- **Answer cache.** Answers are cached by question text across all paths of a
  run. A question already in flight is not asked again.

Dropping constraints is always sound. A claim valid under a subset is valid
under the full path. Every caller reads a lost proof conservatively: a field
counts as changed, an index as reaching, a path as undecided. The exception is
feasibility, whose claim names no array, so it is asked under every
constraint. Reachability is decided first, under a slice that treats
symbolic-index reads as hitting nothing. The model-fault questions come after
it, under the refined slice. Asked before it, they lost the proof on four
write paths: the fault flag is in the context, and the file stores at
`f_pos + i` could not be ruled out from aliasing it.

A condition that reads no input with a declared domain is not asked whether
the domains imply it. It stays a control dependency.

Reanalysis of every published run gives identical results on every path,
with no undecided answers. The machine was shared, with load averages of
55–180 on 8 cores, so wall times vary up to 2× between identical runs. Solver
process counts are unaffected. On a 46-path sample of read with a symbolic
count, solver CPU fell from 298 s to 37 s and Python CPU from 18 s to 6 s.

| Run | Paths | Solver processes (before → after) | Analysis wall time (before → after) |
|-----|-------|-----------------------------------|--------------------------------------|
| close, fd split | 76 | 763 → 241 | 21 s → 17 s |
| write, fd split | 131 | 1170 → 472 | 54 s → 42 s |
| read, count 0–64 | 273 | 10271 → 1664 | 851 s → 150 s |
| write, count 0–16 split | 211 | 1678 → 1706 | 530 s → 370 s |
| read, count 0–16 split | 963 | 16554 → 3344 | 56 min → 131 s |

Write with a split count gains least on the flat context. Its store indices,
`f_pos + i`, are read through the earlier symbolic stores in the context, so
the confinement questions themselves carry long store histories. Its fault
flag is also in the context, so most of its 162 faulting paths need the
refined slice before `always` is proven. With `file_data` in its own object
(see [Separate objects](#separate-objects)), the stores stay out of the context
and its analysis takes 65 s of solver CPU instead of 454 s.

KLEE's own exploration spends about 99% of its time in the solver. On a
loaded machine, the same write-with-split-fd run took between 135 and 594 s
of solver time, so options were compared by KLEE's core solver-query count
(`SolverQueries` in `run.stats`), which load does not affect.

| Option | Core solver queries | Results |
|--------|---------------------|---------|
| default | 717–741 | — |
| `--cex-cache-superset` | 655–679 | same |
| `--simplify-sym-indices` | 709 | same |
| both | 679 | same |
| `--use-forked-solver=false` | 733 | same |
| `--optimize-array=all` | — | every input required |
| `--solver-backend=z3` | — | 79 of 80 paths partial at 20 min |

None of them changes the cost materially, so the defaults stay.
`--optimize-array=all` rewrites symbolic-index reads into selects over every
stored value. Every read then names every input, and the required set grows to
include the credentials and PIDs. `--klee-arg` passes such options through.

The tool asks the following per path. The questions that use input domains
assume every shaped input lies inside its domain:

- **Control dependence.** Inputs used by the path condition.
- **Data dependence.** For each output: is it provably equal to its own input
  under the path condition (unchanged)? If not, every input its expression
  reads is a dependency, including its own. For example, `open_fds & ~8`
  depends on `open_fds`.
- **Model domain.** `model_fault` is decided on each path: `never`, `always`
  or `undecided`. A KTest value is only one witness. `always` is tried first
  under the early slice; otherwise both are asked after reachability. Paths that always
  fault, or that end in a KLEE error, are not analyzed further (`analyzed:
  false`). Undecided paths count as inside the domain, so their dependencies
  are kept.

A path condition that the input domains alone imply is not a control
dependence. For example, `f_count != 0` holds whenever `f_count ≥ 1`. The
condition is printed standalone, with each label defined at its first use, and
asked without the path. `f_count` nevertheless stays required for read and
write: their condition is `f_count + 1 > 0`, which fails at `LONG_MAX`.

Required inputs are the union of control and data dependencies over the
non-faulting paths.

When KLEE stops at `--max-time` or the memory limit, it writes each unfinished
state as a test with a `.early` file. Such a KQuery is a path prefix: the call
has not returned, so no output is observed and the model fault is unknown.
These paths are `partial`. They add nothing to the required set, and their
prefix control dependencies are reported separately. The report then sets
`required_is_lower_bound` and lists `prefix_control_not_required`: inputs a
stopped prefix branches on that no complete path requires. An earlier version
analyzed stopped states as complete paths with no outputs. With 79 of 80
paths stopped, write with a symbolic count then lost the file and user bytes
from its required set. Without `kleaver`, every unbounded read is reported as
imprecise and no output is proven unchanged.

## Report

`report.json` records:

- KLEE completion (`exploration_complete` requires no halt, no kill and no
  partial paths) and `required_is_lower_bound`;
- path classes;
- required inputs, control and data dependencies;
- `control_without_effect`: inputs whose conditions only choose between paths
  with equal outputs;
- unchanged outputs;
- imprecise reads;
- solver calls and undecided answers per path;
- the comparison with the static footprint (`required_not_in_static`,
  `static_not_required`).

`klee/` holds the KTest and KQuery files. `--reanalyze OUT` recomputes the
dependencies from them. `--resume` publishes a run whose KLEE stage finished in
`OUT/work`. It first checks that the regenerated driver and symbolic names
match the files KLEE ran.

## Results on the captured `file-io` boundaries

Ramfs-kernel captures `read(4, buf, 8)`, `write(4, buf, 2)` and `close(3)` on
the rebuilt `file-io` slice, with the input domains described below
(`build/klee-state-{read,write,close}-20261027b`). Each exploration completed:
no halt and no partial paths. There were no imprecise reads and no undecided
solver answers.

| Call | Paths (in domain / model fault) | Symbolic inputs | Required |
|------|---------------------------------|-----------------|----------|
| read | 57 (28 / 29) | 31 | 6 |
| write | 13 (3 / 10) | 31 | 6 |
| close | 2 (2 / 0) | 30 | 4 |

Without those domains (`…-20261027`), read had 118 paths and write 30. Each
also required `file_pool[1].f_count`, but only at `LONG_MAX`.

Dependencies (`file_pool[1]` is the file behind the descriptor):

- **read**
  - Control: `file_data.size` and `file_pool[1].{f_mode, f_pos, object_id}`.
  - Data: user bytes ← file bytes, `f_mode`, `f_pos`; `f_pos` ← `f_mode`, `f_pos`.
  - Unchanged: `file_data`, `file_pool[1].f_count` and `file_pool[0]`.
- **write**
  - Control: same as read.
  - Data: file bytes ← file bytes, user bytes, `f_mode`, `f_pos`;
    `file_data.size` ← `f_mode`, `f_pos`; `f_pos` ← `f_mode`, `f_pos`.
  - Unchanged: `file_pool[1].f_count` (the reference is taken and released
    within the call), `file_pool[0]` and the user bytes.
- **close**
  - Control: `files.next_fd`.
  - Data: `open_fds[0]`, `full_fds_bits[0]` and `file_pool[1].f_count`, each
    from its own value (bit cleared, decremented).
  - Unchanged: `file_pool[0].f_count`.
  - Under the later graph invariants (see [More system calls](#more-system-calls)),
    `open_fds` and `full_fds_bits` are fixed by the observed slots. `close(3)`
    then needs only `f_count` and `next_fd`.

For every call, `required_not_in_static` is empty: the static footprint
contains every input that execution needed. The static-only fields are of two
kinds, and the run does not test either:

- fields the observed graph fixes: `current`, `task.files`, `files.fdt`,
  `fdtab.fd[]` and `max_fds`;
- binding transients that are 0 at every syscall boundary: `rcu_depth` and
  `files.file_lock`.

Credentials, PIDs, `umask`, `f_flags`, `f_version` and the descriptor bitmaps
(for read and write) are symbolic but unused.

Earlier versions of the analysis were wrong in two ways:

- They parsed chained update lists incorrectly.
- They treated an output that depends only on its own input as unchanged.

The first version reported 31 required inputs for write, including
credentials and PIDs. It also missed close's in-place updates.

## Validation by concrete replay

`tools/klee_state_validation.py` checks a discovery result against the
reduced slice:

```
python3 tools/klee_state_validation.py --discovery build/klee-state-read \
  --boundary build/linux-svc-unblocked-20261026/observe-read/boundary.json \
  --slice build/linux-transfer-guard-rebuild-20261026/file-io/kernel \
  --binding integrations/linux_aarch64/file-io/live-binding.json \
  --out build/klee-validation-read
```

All variants run in one freestanding AArch64 image under QEMU, with the
original slice bodies and the reviewed models. The context is restored and
rebound for every variant. The checks are:

- **Observed.** Variant 0 is the observation itself and must reproduce it.
- **Sufficiency.** By default 24 variants randomize every unused input at
  once, within the declared domains.
  - Outputs that may change must equal the full-machine observation.
  - Every other field must keep its variant's pre-state value.
- **KTest cross-check.** Each in-domain KLEE test is replayed with the driver's
  domain shaping applied. Its result, model fault and observed outputs must
  equal those KLEE computed. This checks KLEE's host-bitcode semantics against
  the compiled AArch64 code.
- **Necessity.** Each required input alone takes up to 12 values: the type
  extremes, values from in-domain KTests, and random values. The input is
  demonstrated when some variant diverges from the observation. If the
  observed call left the varied field itself unchanged, the variant is
  expected to keep its varied value. A field that only reappears in its own
  output is therefore not demonstrated: closing fd 3 never touches
  `file_pool[0].f_count`, even though other fd values do. A field the
  observed call wrote, such as `next_fd`, is still compared with the observed
  post value. A required
  input that is not demonstrated is reported, but the check does not fail on
  it. Requirements are a union over paths, and the observed path need not
  reach the others.

The status is `consistent` when the observed, sufficiency and KTest checks all
pass.

After an incomplete exploration (partial paths, `required_is_lower_bound`), no
input is proven unused and no output proven unchanged. Discovery then reports
no `unchanged_outputs`. Validation runs no sufficiency variants and predicts
the live post value for every observed output. The status is `partial` when the
observed and KTest checks pass; it says nothing about the inputs the
exploration never reached.

| Call | Randomized inputs | Sufficiency | KTest | Necessity demonstrated |
|------|-------------------|-------------|-------|------------------------|
| read | 25 | 24/24 equal | 28/28 equal | 6/6 |
| write | 25 | 24/24 equal | 3/3 equal | 6/6 |
| close | 26 | 24/24 equal | 2/2 equal | 4/4 |

Without the input domains, read and write also required `f_count`. There,
necessity diverged only at the type maximum, where the reviewed model's
overflow assertion fires. Each validation takes 6–19 s. These are concrete tests, not
proofs.

## Model-domain faults and input domains

`klee_state_validation.py --fault-sites` replays every always-faulting KTest
in one `-O0 -g` image. A breakpoint on `osrec_kernel_linux_assert` records the
call site of the first failing assertion for each variant. The tool
symbolizes that site to a slice source line and groups the paths by it
(`fault-sites.json`). Before input domains were added, 117 faulting paths fell
on three assertions:

| Assertion | read | write | Inputs reaching it |
|-----------|------|-------|--------------------|
| `regular_transfer`: `object_id != 2 \|\| *pos < 0` | 62 | 18 | `object_id` outside the binding's classes, or negative `f_pos` |
| `fput`: `f_count <= 0` | 28 | 3 | `f_count = LONG_MAX`, so `inc_not_zero` in `fget` overflows |
| `regular_transfer`: 64-byte write capacity | 0 | 6 | `f_pos` + count past the model's 64 bytes |

The first two are inputs that Linux does not produce. Input domains therefore
come from three sources, are recorded in `input_domains`, and are checked
against the observed pre- and post-states:

- **Contract `state_ranges`**, as before.
- **Binding class values.** `object_id` is the binding's classification of
  `f_inode->i_mode`, so it ranges over `[1, 2]`.
- **Declared `input_domains` in the analysis contracts.** Each entry has a
  reason. `pool[]` expands to every pool entry.
  - `f_pos` ≥ 0: regular files are never at a negative position.
  - `f_count` ≤ 2^32: references are bounded far below `LONG_MAX`.

The 64-byte capacity remains a model-domain fault. It is a deliberate bound of
the reviewed model, not a Linux property.

With these domains, read drops from 118 to 57 paths and write from 30 to 13.
`f_count` leaves the read and write required sets, and every remaining fault
is model scope:

| Assertion | read | write | Inputs reaching it |
|-----------|------|-------|--------------------|
| `regular_transfer`: `object_id != 2` | 29 | 7 | `object_id = 1`: the descriptor's file is a character device, and the reviewed transfer model covers regular files only |
| `regular_transfer`: 64-byte write capacity | 0 | 3 | `f_pos` + count past 64 bytes |

`object_id` stays required because the file's class selects the code.

## Symbolic arguments

`--symbolic-arg INDEX:LOW:HIGH` makes one syscall argument symbolic over a
domain. The required set then covers every argument value in that domain, not
only the captured call.

A split input (`:split`, or `--split-field`) reaches the code as a constant on
each path. The only conditions that name it are the driver's own value
comparisons, and no output depends on it as data, so the paths cannot show
whether the code needs it. Split inputs are therefore reported as
`split_inputs`, outside `required`, and the concrete necessity check decides
them. In the runs below, the fd and count were each demonstrated by 12 of 12
variants. The counts in the "Required" column include them. Results
(`build/klee-state-*-20261027`):

| Run | Exploration | Paths (in domain / fault / partial) | Required |
|-----|-------------|--------------------------------------|----------|
| close, fd 0–70 | halted at 20 min | 12 (1 / 0 / 11) | lower bound: fd |
| close, fd 0–70 split | complete, 36 s | 76 (76 / 0 / 0) | 6 |
| read, fd 0–70 | halted at 20 min | 17 (0 / 0 / 17) | none |
| read, fd 0–70 split | complete, 8 min 50 s | 295 (179 / 116 / 0) | 10 |
| write, fd 0–70 split | complete, 3 min 29 s | 131 (81 / 50 / 0) | 10 |
| read, count 0–64 | halted at 20 min | 273 (76 / 78 / 119) | lower bound: 7 |
| write, count 0–64 | halted at 20 min | 80 (0 / 1 / 79) | none |
| write, count 0–16 split | complete, 41 min 45 s | 211 (49 / 162 / 0) | 7 |
| read, count 0–16 split | halted at 60 min | 963 (238 / 255 / 470) | lower bound: 7 |
A symbolic fd indexes the descriptor table, and the table is part of the one
flat context object. Each table access is then a read or write at a symbolic
offset into that object, and every later read of the object has to consider
it. KLEE and the dependency queries both slow down sharply.

`INDEX:LOW:HIGH:split` avoids this. After shaping, the driver compares the
argument with each value in the domain and continues with the matching
constant. The comparisons stay in the path condition, so the argument is
still a control dependency. The call itself runs with a concrete descriptor,
so each fd costs about one concrete run. In the observed graph, fds 0–2 share
the console file (`file_pool[0]`) and fd 4 is the file (`file_pool[1]`). Read
and write therefore explore the transfer four times, and every other fd ends
in `EBADF`.

With the fd split, the required inputs are:

- **close:** fd, `f_count` of both pool files, `open_fds[0]`,
  `full_fds_bits[0]` and `next_fd`. Control: fd and `next_fd`. Each other
  field depends only on its own value.
- **read and write:** fd, file bytes, `file_data.size`, user bytes and
  `{f_mode, f_pos, object_id}` of both pool files. These are the concrete-call
  inputs, extended to every file that a descriptor can reach. `f_count` stays
  unused, as in the concrete runs.

Every set is inside the static footprint (`required_not_in_static` is empty).
Concrete replay is consistent for all three:

| Run | Sufficiency | KTest | Necessity demonstrated |
|-----|-------------|-------|------------------------|
| close, fd split | 24/24 equal | 76/76 equal | 5/6 |
| read, fd split | 24/24 equal | 179/179 equal | 7/10 |
| write, fd split | 24/24 equal | 81/81 equal | 7/10 |
| read, count 0–64 | 24/24 equal | 76/76 equal | 7/7 |
| write, count 0–16 split | 24/24 equal | 49/49 equal | 7/7 |
| read, count 0–16 split | 24/24 equal | 238/238 equal | 7/7 |
The inputs not demonstrated are `file_pool[0]` fields. Only fds 0–2 reach
them, and the observed call uses fd 3 (close) or 4 (read, write). The KTest
replays cover those paths.

A symbolic count makes the transfer loop length symbolic. Each iteration
forks, and each copy goes to a symbolic file offset. Without a split, write
with count 0–64 completed no in-domain path in 20 minutes. Read completed 76
in-domain paths in 20 minutes, and its stopped prefixes branch on no further
input.

Splitting the count over 0–16 costs about one concrete run per value.

- **Write** completes in 42 minutes. Its 162 faulting paths fall on the two
  model-scope assertions described below. In 114 paths the file is a
  character device. In 48 paths `f_pos` plus count passes the 64-byte
  capacity.
- **Read** completes every count from 0 to 10 within the hour, with no
  partial paths. Counts 11–16 remain partial: each extra byte adds about three
  paths. The complete counts already exceed the 8-byte file and the 8-byte
  user buffer.

For both calls the count adds itself to the concrete-call inputs and nothing
else. `f_count`, the credentials and the descriptor bitmaps stay unused.

## More system calls

The original checkpoint workload calls only `read`, `write`, `lseek` and
`close` after its checkpoint. `examples/linux-vm-checkpoint/init-more.c` also
calls `umask`, `getpid`, `getuid`, `getresuid`, `dup`, `dup3` and `close`
there. Each result is checked in the guest, and success appends ` more=ok` to
the original oracle (`build_linux_vm_checkpoint.py --workload
--success-suffix`). Its checkpoint
(`build/linux-svc-machine-checkpoint-more-20261028`) verified on unmodified
Linux 6.10.

| Call | Paths (in domain / fault) | Required | Validation |
|------|---------------------------|----------|------------|
| `lseek(4, 0, SEEK_CUR)` | 3 (2 / 1) | `f_mode`, `f_pos`, `object_id` | consistent |
| `lseek(4, 0, SEEK_SET)` | 5 (3 / 2) | `f_mode`, `f_pos`, `object_id` | consistent; `f_pos` not demonstrated |
| `read` on a closed fd | 1 (1 / 0) | none | consistent, 30 inputs randomized |
| `umask(077)` | 1 | `fs.umask` | consistent |
| `getpid()` | 1 | `task.tgid` | consistent |
| `getuid()` | 1 | `creds.uid` | consistent |
| `getresuid(&r, &e, &s)` | 1 | `uid`, `euid`, `suid`, user buffer | consistent |
| `dup(3)`, `next_fd` split | 12 (6 / 6) | `f_count`, `f_mode`, `close_on_exec`; `next_fd` split, not demonstrated | consistent |
| `dup3(3, 7, O_CLOEXEC)` | 1 | `f_count`, `close_on_exec` | consistent |
| `close(3)` | 2 | `f_count`, `next_fd` | consistent |
| `close(4)`, `close(7)` | 1 | `f_count` | consistent |
| `close(5)` | 2 | `f_count`, `next_fd` | consistent |

The descriptor-table rows use the graph invariants and the domain
`resize_in_progress = 0`. `expand_fdtable` sets and clears that flag within
one call, so it is 0 at every boundary of a task whose files table is not
shared. The other rows do not depend on either.

- **`getpid` reads `tgid`.** That is the Linux semantics: the thread-group
  leader's id.
- **`SEEK_SET` reads `f_pos`.** `vfs_setpos` resets `f_version` only when the
  offset differs from `f_pos`. Concrete replay cannot show it, because the
  observed `f_version` is already 0.
- **`close` of a descriptor above `next_fd`** does not need `next_fd`. The
  bound makes `fd < next_fd` false, as a domain-implied condition.
- **`dup`'s remaining faults** are `fd_install`'s warning for an
  `FMODE_BACKING` file, a bit flag that a range cannot express.

Fixes the new calls required:

- **`dup` blocked the static footprint.** The fd allocator scans bitmaps with
  an index the analyzer cannot bound. Discovery then observes every bound
  field. It finds `close_on_exec` as a dependency the static reads miss
  (`required_not_in_static`), and concrete replay agrees.
  - Without the graph invariants, the symbolic bitmap made
    `find_next_zero_bit` fork per bit: 2 of 284 paths finished in 20 minutes.
  - Without the `next_fd` split, the allocated slot was a symbolic index into
    the context.
  - With both, the run completes in 17 s.
- **`getresuid` admitted three overlapping user objects.** Its three pointers
  are 4 bytes apart. The replay then held three independent copies of one
  buffer and lost the aliasing. `svc_boundary.py` now merges overlapping
  objects of one class into a single object (`arguments` lists the pointers).
- **`put_user_u32` writes `target[i]`** through a resolved user pointer. The
  entry-state analyzer accepted `*p` through such external memory but not a
  subscript. It now treats both alike.
- **A released file** (after both `close` calls) has no file data in the
  observation. The validator fills in the restore's values for variants that
  vary those fields. It does not compare file fields that nothing observed,
  as in the reduced replay.

### Identity queries and error paths

`examples/linux-vm-checkpoint/init-ids.c` calls, after its checkpoint:

- the remaining identity queries;
- `umask` twice;
- error paths of the descriptor calls;
- zero-length `read` and `write`.

It appends ` ids=ok` to the oracle and verified on Linux 6.10
(`build/linux-svc-machine-checkpoint-ids-20261028`). The boundaries are in
`build/linux-svc-ids-20261028`, the runs in `build/klee-state-*-20261028e`, and
the reanalyses with sibling merging in `*-20261028e-m`.

| Call | Result | Required | Validation |
|------|--------|----------|------------|
| `getppid()` | 0 | `parent.tgid` | consistent |
| `geteuid()`, `getgid()`, `getegid()` | 0 | `creds.euid`, `creds.gid`, `creds.egid` | consistent |
| `gettid()` | 1 | `task.pid` | consistent |
| `getresgid(&r, &e, &s)` | 0 | `gid`, `egid`, `sgid`, user buffer | consistent |
| `umask(077)`, then `umask(022)` | 022, 077 | `fs.umask` | consistent |
| `dup(99)`, `close(99)`, `lseek(99, 0, 0)` | `-EBADF` | none | consistent |
| `lseek(3, 0, 99)` | `-EINVAL` | none | consistent |
| `dup3(3, 3, 0)`, `dup3(3, 9, 1)` | `-EINVAL` | none | consistent |
| `read(4, buf, 0)` | 0 | `f_mode`, `object_id` | consistent |
| `write(4, buf, 0)` | 0 | `f_mode`, `object_id` | consistent |

Every run has one in-domain path except zero-length `read` (2) and `write` (1),
whose other paths are model faults. All 16 were captured and replayed as
equivalent, except `dup(99)`. Its static footprint is blocked in the fd
allocator, as for `dup`; discovery observes every field and finds none
required.

- **`gettid` reads `pid`**, while `getpid` reads `tgid`.
- **The error paths read no state.** The descriptor number is out of range or
  the arguments are invalid. Both are decided from the arguments alone, before
  any table lookup.
- **Zero-length `read`** without sibling merging also required `file_data.size`
  and `f_pos`, and concrete replay could demonstrate neither. With merging, both
  drop and replay demonstrates the remaining two. `f_pos` drops because
  the domain already requires `f_pos >= 0`.

Reanalysis with sibling merging changed no other required set among the 35
current runs; all revalidate as consistent.

## State-changing calls

The `fd-control` slice adds `fcntl`, `pread64`, `pwrite64` and `ftruncate` to
`file-io`. Its binding binds each file's inode as related objects (see
[SVC boundaries](svc-boundary-replay.md#related-objects)). That makes
`inode_pool[i].i_mode` and `.append` symbolic inputs.

The 21 boundaries from `init-state.c` were discovered and validated in
`build/klee-state-*-20261029c`. Every run completed and validates as
consistent.

| Call | Required | Validation |
|------|----------|------------|
| `fcntl` `F_GETFD`, `F_SETFD` (fd and alias) | `close_on_exec[0]` | consistent |
| `fcntl` `F_GETFL` | `file_pool[1].f_flags` | consistent |
| `fcntl` `F_DUPFD` from 6 → 6; `F_DUPFD_CLOEXEC` from 0 → 5 | `f_count`, `f_mode`, `close_on_exec[0]` | consistent |
| `fcntl` `F_DUPFD` from 10, past the limit (`-EINVAL`); on fd 99 (`-EBADF`) | none | consistent |
| `pread64` (4 bytes at 2; all 10) | file bytes and size, `f_mode`, `object_id`, user buffer | consistent |
| `pwrite64` (at 6; extending at 9; restoring) | file bytes and size, `f_mode`, `object_id`, user buffer | consistent |
| `ftruncate` (shrink, grow, restore) | file bytes, `f_mode`, `object_id`, `i_mode`, `append` | consistent |
| `ftruncate` on the console | `i_mode`, plus `f_mode`, `object_id`, `append` from the regular-file paths | consistent |
| `pread64` negative offset; `ftruncate` negative length | none | consistent |

**Original `fcntl` entry and descriptor lookups.** The slice now runs Linux's own
`fcntl` entry, `do_fcntl` and `fdget`/`fdget_raw` with their `__fget_light`
fast path (`build/linux-fd-control-port-20261029p`). Rerun on the recaptured
boundaries (`build/klee-state-batch-fd-control-20261029p`), all 21 are still
complete and consistent, with two new inputs:

- `file_pool[1].f_mode` in every `fcntl` entry: the entry tests `FMODE_PATH`. For
  the commands observed, the O_PATH branch returns the same result, so the
  field is not demonstrated.
- `files.count.counter` in every call that looks up a descriptor: a table with
  one owner is borrowed from, and a shared one takes a reference that `fdput`
  drops again. Both paths return the same result, which doubles the path
  counts (for example `F_DUPFD_CLOEXEC`: 48 paths).

- **Positioned I/O doesn't read `f_pos`.** Unlike `read`/`write`, `pread64` and
  `pwrite64` never require it, and they leave it unchanged.
- **`ftruncate` doesn't read `file_data.size`.** The new size is the argument;
  the bytes are required because the tail is zeroed.
- **`F_DUPFD_CLOEXEC`** needs the same `--split-field files.next_fd:0:5` as
  `dup`. Without it, all eight paths were cut off at the 20-minute limit.

### A model constant: `RLIMIT_NOFILE`

A first workload ran at Linux's default limit. There, `fcntl(3, F_DUPFD, 10)`
returned 10. KLEE's only path, and the concrete replay of the observed state,
returned `-EINVAL`, and validation reported the run as inconsistent.

The reviewed models of 18 Linux profiles give `rlimit(RLIMIT_NOFILE)` as the
constant 8. `f_dupfd` and descriptor allocation bound new descriptors by it,
while PID 1's limit is 1024. Nothing checked that assumption, so the model's
answer for a start of 8 or more was wrong rather than outside its domain.

Now the `file-io` and `fd-control` bindings state it as a
[precondition](svc-boundary-replay.md#preconditions), so capture refuses such a
state. The workload sets the limit to 8 before its checkpoint, so Linux and the
model agree: `F_DUPFD` from 10 returns `-EINVAL` on both, and from 6 returns 6.
Binding the real limit instead would mean adding it to the slice state of each
profile, as `file-rlimit` does with `resource_limits`.

### Outputs another path writes

The validator now decides what may change from the in-domain paths that return
the observed result. Before, it used every in-domain path. On the console,
`ftruncate` returns `-EINVAL` and leaves the file alone. Other in-domain paths
truncate a regular file. Sufficiency randomizes `file_data`, which the
observed path never reads. The validator then predicted the observed bytes,
while the replay rightly kept the random ones.

Now an output that every in-domain path with the observed result leaves
unchanged keeps its variant value. A path whose result or outputs are
data-dependent counts as possibly changing everything.

### Original read, write and truncate path (2026-10-30)

The slice now runs the original `vfs_read`/`vfs_write` path through shmem, the
page cache, the xarray and the inode timestamps
(`build/linux-fd-control-port-20261030c`). The binding gained the inputs that
path reads (see [SVC boundaries](svc-boundary-replay.md)). The 21 boundaries were
recaptured into `build/linux-svc-state-20261030b` and rerun in
`build/klee-state-batch-fd-control-20261030d`.

| Call | Exploration | Required | Validation |
|------|-------------|----------|------------|
| `fcntl` (10 entries), `pread64` negative offset, `ftruncate` negative length | complete | unchanged | consistent |
| `ftruncate` shrink, grow, restore | complete | adds `i_flags`, `i_size`, seals, `alloced`, `swapped`, `fallocend` | consistent |
| `ftruncate` on the console | complete | `f_mode`, `i_mode`, `append` (no longer `object_id`) | consistent |
| `pread64` (4 bytes at 2; all) | halted at 20 min, `i_size` split 0–64: 956–1,001 paths, 308–316 in domain | lower bound: `f_flags`, `f_mode`, `i_flags`, `i_mode`, file bytes, `ioac.rchar`/`syscr`, user buffer | partial |
| `pwrite64` (at 6; extending; restoring) | halted at 20 min: 6,080–6,509 paths, 20–28 in domain | lower bound: `f_flags`, `f_iocb_flags`, `f_mode`, `i_flags`, `i_mode`, `i_size`, `ioac.syscw` | partial |

The truncate requirements are what `shmem_setattr` reads: the seals for
`F_SEAL_GROW` and `F_SEAL_SHRINK`, the size, and the block accounting that
`shmem_undo_range` and `shmem_recalc_inode` update. On the console,
`do_sys_ftruncate` now rejects the file by `S_ISREG` on `i_mode`, as Linux
does, instead of by the model's object class.

On `pread64` and `pwrite64` every observed state replays to the live
post-state. Every in-domain KTest (316, 308, 26, 20 and 28) gives the result
and outputs KLEE computed. But exploration does not finish. The write path
tests about 15 independent flag bits before it touches data:

- `f_mode`: `FMODE_WRITE`, `PWRITE`, `PATH`, `WRITER`, `CAN_WRITE`,
  `NONOTIFY`;
- `f_iocb_flags`: `IOCB_NOWAIT`, `IOCB_APPEND`, `IOCB_DIRECT`;
- `f_flags`: `O_LARGEFILE`;
- `i_flags`: `S_NOCMTIME`, `S_SWAPFILE`, `S_NOSEC`;
- the seals and the file type.

Most of these branches rejoin, so paths multiply. In the halted `pwrite64`
run, 99% of the 6,080 states were still on such prefixes, and 61% of the time
went to the solver. Longer limits did not help: a 2-hour `pread64` run with the
mount flags still symbolic ended with 1,823 of 3,756 paths partial.

The mount configuration first made this worse. The superblock flags,
`s_maxbytes`, the mount flags and the bdi capabilities were bound members, so
KLEE forked on each atime and read-only bit. These are mount options: they do
not change between calls on a mount. They are now
[preconditions](svc-boundary-replay.md#preconditions) that the binding checks
on every captured call, with the model's superblock and mount holding them.
With them pinned, `pread64` ends 20 minutes with 362 partial paths of 956;
with them symbolic, the 2-hour run above ended with 1,823 of 3,756.

The manifest records these halted results and puts the `pread64`, `pwrite64`
and truncate entries in the `long` tier. A halted run's paths depend on the
machine's speed, so on another machine their required sets may differ as lower
bounds.

Before validation learned about incomplete runs, these entries validated as
`inconsistent`. No completed path reached the successful write, so discovery
called the file bytes and `wchar` unchanged. The validator then expected the
pre-state, while the replay, correctly, produced the live post-state.

### Original identifiers, close, allocation, user copies and LSM hooks (2026-10-31)

The slice now also runs the original uid/gid map lookups, `filp_flush`, the
bit search and `expand_files`, the `iov_iter` user-copy chain and the LSM hook
walks (`build/linux-fd-control-port-20261030j`; 95.3% original code). The
binding gained the namespace maps and `task.flags`, so the 21 boundaries were
recaptured into `build/linux-svc-state-20261030k` and rerun in
`build/klee-state-batch-30k`. Every entry ran; 13 kept their recorded results.

| Call | Exploration | Required | Validation |
|------|-------------|----------|------------|
| `fcntl` (10 entries), `pread64` negative offset, `ftruncate` negative length and console | complete | unchanged | consistent |
| `ftruncate` shrink, grow, restore | complete | no longer `object_id` | consistent |
| `pread64` (4 bytes at 2; all) | halted at 20 min: 2,640 paths, 1,145 in domain, 1,219 partial | lower bound: adds `task.flags`, no longer `object_id` | partial |
| `pwrite64` (at 6; extending; restoring) | halted at 20 min: about 10,800 paths, 64 in domain | lower bound: adds `task.flags`, no longer `object_id`; the extending write adds `f_flags` and `i_size` | partial |

`object_id` was read only by the models the original code replaced: the
security-hook and flush models dispatched on the file's class. `task.flags` is
the `PF_KTHREAD` test in arm64's original `access_ok`, which decides whether to
untag the user address before every user copy.

## Batch reruns

`tools/klee_state_batch.py` reruns discovery and validation for every
boundary in a manifest. It compares each result with the one the manifest
expects. The manifests for the captured Linux boundaries are
`integrations/linux_aarch64/file-io/klee-state-batch.json` (35 entries) and
`integrations/linux_aarch64/fd-control/klee-state-batch.json` (21). Each entry holds:

- the boundary path and its SHA-256;
- the discovery arguments (symbolic or split arguments, split fields, time
  limit), after the shared slice, binding, contracts and default time limit;
- a tier: `quick` (KLEE takes seconds) or `long` (minutes);
- the expected result: exploration complete, `required`,
  `control_without_effect`, `split_inputs`, validation status, and the required
  inputs that validation did not demonstrate.

```sh
python3 tools/klee_state_batch.py \
  --manifest integrations/linux_aarch64/file-io/klee-state-batch.json \
  --work build/klee-state-batch --tier quick
```

Each entry is discovered into `WORK/NAME` and validated into
`WORK/NAME-validation`. The runner writes `WORK/summary.json` and exits
non-zero unless every selected entry matches. An entry matches only when every
expected item is equal; lists compare as sets.

Other outcomes are reported apart:

- `stale`: the boundary file no longer has the recorded hash;
- `missing`: the boundary file is absent;
- `failed`: a tool failed.

Two options support changes to the analysis:

- `--reuse` reanalyzes a finished run in `WORK/NAME` from its KQuery and KTest
  files instead of rerunning KLEE, when the run used the same boundary and
  arguments.
- `--record` writes the observed results into the manifest as the new
  expectations. Review the diff before keeping it.

With CMake, `-DOSREC_BUILD_KLEE_STATE_BATCH=ON` adds one test per manifest
and tier in `OSREC_KLEE_STATE_BATCH_TIERS` (default `quick`), for example
`klee_state_batch_fd-control_quick`. The tests need KLEE, QEMU and the captured inputs
under `build/`. `klee_state_batch_manifest` checks the runner's manifest
validation and comparison without KLEE.

A fresh run of the 30 `quick` entries took about 7 minutes with 4 jobs on a
loaded machine. 29 entries reproduced the recorded results.

`close-fdsplit` was recorded from a run made before the descriptor-table
invariants existed. Its fresh run no longer requires `open_fds[0]` or
`full_fds_bits[0]`: the invariants fix both fields by the object graph, so they
are not symbolic. The run keeps the same 76 complete paths and validates as
consistent, so the new result was recorded.

The `long` tier ran in parallel on the same machine: `read`, `write` and
`write-fdsplit` matched. `read-fdsplit` and `write-countsplit` reached KLEE's
one-hour limit with paths cut off; unloaded, they took 9 and 42 minutes.

An incomplete run gives a lower bound. It used to validate as inconsistent:
`read-fdsplit`'s partial paths never showed that the observed call changes
`f_pos`, so the validator predicted it unchanged. The manifest keeps the
complete results and gives these two entries a 7200-second limit. Incomplete
runs now validate as `partial` instead (see
[validation](#validation-by-concrete-replay)).

## Scope

Results hold only for the observed object graph and for the listed argument
domain. A run with partial paths gives a lower bound
(`required_is_lower_bound`). The fields that the graph fixes are reported as static-only: the
descriptor table pointers, `max_fds`, `current` and `task.files`. KLEE does not
test them.

An undecided solver answer is resolved conservatively: an index counts as
reaching the entry, and an output counts as changed.

Model-domain faults mark paths outside what the reviewed models describe. They
are not kernel errors.
