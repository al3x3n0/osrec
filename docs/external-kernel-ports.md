# External AArch64 kernel ports

Kernel construction can live in a separate directory selected with `--port path/to/port.json`. The shared builder snapshots pinned inputs before running the adapter, generates explicit contexts and checkpoint codecs, builds the archive, and verifies its proof on QEMU. The application importer, C frontend, windows and checkpoint chains reuse that archive.

The existing LiteOS-A file port keeps its repository module. The external fixture demonstrates a separate 64-bit port through the complete pipeline. It is a synthetic closure, not evidence of another real kernel capture or a native AArch64 OHOS capture. A real port still supplies its verified kernel/config/capture identity, original closure, dependency contracts, state policy and validation callbacks.

The [minimal Linux AArch64 port](linux-aarch64-slices.md) now supplies a real ARM64 Linux capture and reviewed original upstream syscall bodies through this same external bundle mechanism. Its explicit task/credential/mask projection uses the shared analyzer, gateway and checkpoint codec; kernel-specific dependency contracts remain port-owned.

## Descriptor

Keep the existing root recipes, scalar width and optional application register ABI. Replace `capture_adapter` with `bundle`; these construction mechanisms are mutually exclusive:

```json
{
  "format": "osrec-kernel-slice-port-v1",
  "name": "my-aarch64-kernel",
  "target_isa": "aarch64",
  "kernel_abi": "my-reviewed-kernel-abi",
  "argument_width": 64,
  "roots": [{"number": 81, "function": "SysExample", "arguments": ["unsigned", "buffer"]}],
  "bundle": {
    "format": "osrec-kernel-slice-bundle-v1",
    "adapter": "prepare.py",
    "proofs": {"session": {"source": "proof.c", "result_abi": 26}},
    "inputs": {
      "prepare.py": "<SHA-256 of prepare.py>",
      "proof.c": "<SHA-256 of proof.c>",
      "kernel.c": "<SHA-256 of kernel.c>",
      "checkpoint-policy.json": "<SHA-256 of checkpoint-policy.json>"
    }
  }
}
```

Digests are 64 lowercase hexadecimal characters. Declare every adapter, proof source, optional CPU application and auxiliary construction input. Names are normalized relative paths inside the descriptor's directory; absolute paths, traversal and references resolving outside it reject. Pin capture/model/type inputs read through the bundle too. Kernel/capture directories passed separately remain the adapter's identity-validation responsibility.

`session` proof is mandatory. Optional `frame` and `cpu` entries select `--application-frame` and `--cpu-gateway`, using existing result ABIs 19 and 20. A CPU entry also declares its pinned `application` assembly source. Missing selected proofs reject before adapter execution. ABI 18 remains available for ports implementing the existing file-profile proof contract.

## Construction and provenance

The adapter exports `prepare(args, sources)`. `args.port_root` and its `__file__` identify the private checked bundle copy. Read auxiliary inputs through those paths and write generated closure/model/adapter/data sources into `sources`. The adapter runs as trusted build-time Python; guest execution contains compiled code/data only.

Its result follows the existing contract:

- `sources`, `headers`: prepared original kernel closure for context transformation.
- `adapter_source`, `data_source`: returning session adapter and embedded capture data.
- `required_syscalls`: numbers covered by the descriptor roots.
- `checkpoint`, `identity`, `metadata`, `capture_manifest`: capture content and verified provenance. `metadata.kernel_image_sha256` is null when no kernel image exists, as in the fixture.
- `expected_result`: observations that must match the capture/port proof contract.
- Optional `checkpoint_policy`: generated-source-relative field-policy JSON. The adapter supplies `osrec_kernel_checkpoint_check(state, next)` for quiescent validation.
- For CPU mode, `cpu_breakpoints`: reviewed application label/immediate contracts.

Prepared sources can keep subdirectories. For example, `sources=['models/kernel.c', 'syscalls/kernel.c']`, `headers=['include/port_types.h', 'models/private.h', 'syscalls/private.h']`, `adapter_source='session/slice_driver.c'` and `data_source='data/capture.c'` are supported. The adapter creates those directories before writing or copying files. The generated-source root is an include directory; ordinary quoted includes still resolve relative to their original source/header location. All headers whose declarations or macros require transformation must be listed in `headers`.

Context analysis identifies each file by its full relative path, including `input_sha256` provenance keys. Distinct files may share source or header basenames. The builder assigns unique object/archive member names when compilation stems collide; both bodies remain in the callable archive. Proof objects are excluded by their full prepared paths, so a nested adapter named `slice_driver.c` is still included. Existing closures with unique compilation stems retain their object names. Prepared paths must be normalized relative regular files; traversal, absolute names, duplicate paths and symlink aliases reject.

Prepared source and header files use UTF-8. Context rewriting applies Clang's offsets and token lengths directly to the original bytes, preserving multibyte comments, string literals and identifiers accepted by the target compiler. LF, CRLF and CR input line endings retain their original bytes outside replaced ranges. An optional UTF-8 BOM stays first, ahead of the generated preamble. Generated helpers and preambles use UTF-8 and LF. The context plan declares `source_encoding: "utf-8"` and `source_offsets: "bytes"`; its input hashes cover the exact original bytes, including line endings and a BOM. Invalid UTF-8 rejects before any source mutation. See the [byte-preserving source workflow](#byte-preserving-source-workflow) for verification and retained images.

The existing runtime adapter, root signature checks, context restrictions and field coverage rules apply. Persistent integers/byte arrays, explicit self-references and [bounded context-owned object graphs](context-object-graphs.md) are supported. Struct-array policies and typed field-local reference IDs preserve changing links, aliases, cycles and pool slot reuse. [Owned buffer references](context-buffer-references.md) preserve typed cursors and reviewed end pointers as buffer IDs and byte offsets. External references and arbitrary heap graphs still need additional contracts.

Mutable file-scope scalars, structures, pointers and arrays can retain their C initializers through [automatic context restoration](initialized-context-state.md), including designated structure elements and pointers to owned objects. Source-local reconstruction helpers preserve private enums, constant macros and readonly constants and initialize each session independently.

[Mixed readonly and mutable declarations](initialized-context-state.md#mixed-readonly-and-mutable-declarations) preserve their readonly definitions while moving only mutable storage into context. Ports can rebuild canonical references to readonly image data using transient fields plus source-owned quiescent validation. Arbitrary changing image-data references still need a portable reference contract.

[Function-local mutable statics](local-static-context-state.md) are also owned automatically. The context plan maps each declaration to a distinct generated field, including shadowed names. Referenced readonly local seeds are lifted into private source storage so constructors and kernel bodies retain the same object identity. Ports classify mutable fields in their checkpoint policy so updates survive both subsequent calls and fresh checkpoint images; canonical references to lifted image data need a transient policy and source-owned boundary validation.

[Private objects in different source files](private-context-state.md) can share a C spelling. Colliding static definitions receive separate context fields; public declarations resolve to their public definition. The plan records each renamed field's source and original declaration so ports can classify it without renaming kernel code.

[Same-named private functions](private-context-functions.md) receive separate declaration identities and dependency keys. Context threading follows each file's direct calls independently, and public functions retain their existing root names. Shared header or macro spellings that require different per-file replacements still need source-local declarations or an adapter.

Libraries retain exact construction inputs in `port-inputs/`; composed images retain them in `kernel-port-inputs/`. Composition, four-mode verification and offline chain verification check these bytes against the descriptor. Changed input identities reject before adapter execution. Changed published inputs reject reuse, and adapter mutation of its private inputs rejects publication. The original external directory is unnecessary after publication.

## Generic proof result ABI 26

ABI 26 uses the existing 128-byte stopped-memory result area. Words 0–4 are magic `0x4f535243`, version 26, status, error and completed calls. Success is status 2/error 0. Words 5–18 are:

| Word | Observation | Required success value for N calls |
| --- | --- | --- |
| 5 | `call_count` | 1–65536 |
| 6 | `completed_sessions` | 3 |
| 7 | `verified_calls` | 3N |
| 8 | `isolation_checks` | 2N |
| 9 | `restart_checks` | 1 |
| 10 | `input_rejections` | Positive; exact port count in `expected_result` |
| 11 | `return_value_checks` | 3N |
| 12 | `application_memory_checks` | 3N |
| 13 | `scalar_width` | 32 or 64 |
| 14 | `context_functions` | Positive |
| 15 | `state_objects` | Positive |
| 16 | `slice_runtime_abi` | 1 |
| 17 | `recipe_checks` | 3N |
| 18 | `completion_checks` | 3 |

Word 4 must equal 3N. Execute two interleaved independent sessions, check the other session's unchanged state/application memory, restore one session and execute its sequence again. Verify every return, buffer and ordinal/progress contract. Rejected inputs must preserve state and application memory. Port-specific expected observations remain mandatory. This shared proof structure has no file descriptor, reference count or VFS assumptions. Functional verification still depends on the reviewed proof and adapter.

## Separate 64-bit fixture

```sh
python3 tools/export_syscall_slices.py \
  --capture tests/fixtures/portable-slice-port \
  --port tests/fixtures/portable-slice-port/port.json \
  --out build/my-external-port
python3 tools/verify_syscall_slices.py \
  --image build/my-external-port --out build/my-external-port-qemu
python3 tools/run_c_application_checkpoint_chain.py \
  --slices build/my-external-port \
  --source tests/fixtures/portable-slice-port/application.c \
  --spec tests/fixtures/portable-slice-port/spec.json \
  --pause-ordinals 2,4,5 --out build/my-external-port-chain
python3 tools/run_c_application_checkpoint_chain.py --verify build/my-external-port-chain
```

The fixture uses unsigned and negative signed 64-bit arguments, results and syscall numbers above 32 bits, macro helper calls, a context self-reference and guarded output memory. It uses x30 for the syscall number, x19–x24 for arguments and x25 for the result. The sequence ends at `0x30000000d`. Kernel state occupies 24 target bytes; its 80-byte portable record rebuilds the alias after relocation. The application uses distinct prefix/suffix SVC sites and nonzero SIMD/FP/TLS entry state.

The chain advances 0 → 2 → 4 → 5 → 6. Every image runs in all four QEMU ELF/raw × EL1/EL3 modes. Guest host services stay disabled; QMP reads stopped memory externally. The regression copies the bundle outside the repository, deletes that original directory after publication and verifies retained artifacts. It rejects changed identities, unsupported proofs, damaged published inputs, truncated scalar implementations and mismatched proof ABI declarations.

Retained artifacts are `build/external-port-kernel-final-v2`, its four-mode proof in `build/external-port-kernel-qemu-final-v2`, and the full chain in `build/external-port-chain-final-v2`. Offline verification of the retained chain passed.

Five affected CTest suites passed in 399.02 seconds: callable slices, application frames, CPU gateway, checkpoint chains and the external port. The retained report is `build/live-syscall-checks/qemu-external-port-results.xml`.

## Nested source layout

`tests/test_external_slice_port.py` also constructs a copied port with `models/kernel.c` and `syscalls/kernel.c`, same-named `private.h` headers in those directories, a nested model header, a nested adapter named `slice_driver.c`, generated capture data in `data/`, and a pinned proof in `verification/`. It checks both original source hashes and both archive bodies, then verifies the same six-call application/checkpoint chain. Changing either published `kernel.c` rejects verification. Removing the original port directory preserves replay and offline chain verification. Invalid prepared paths reject before context transformation writes files.

The retained copied bundle is `build/nested-source-port-final-v1`. Rebuild it into new output directories with:

```sh
python3 tools/export_syscall_slices.py \
  --capture build/nested-source-port-final-v1 \
  --port build/nested-source-port-final-v1/port.json \
  --out build/my-nested-source-kernel
python3 tools/verify_syscall_slices.py \
  --image build/my-nested-source-kernel --out build/my-nested-source-kernel-qemu
python3 tools/run_c_application_checkpoint_chain.py \
  --slices build/my-nested-source-kernel \
  --source build/nested-source-port-final-v1/application.c \
  --spec build/nested-source-port-final-v1/spec.json \
  --pause-ordinals 2,4,5 --out build/my-nested-source-chain
python3 tools/run_c_application_checkpoint_chain.py --verify build/my-nested-source-chain
```

Retained results are `build/nested-source-kernel-final-v1`, `build/nested-source-kernel-qemu-final-v1` and `build/nested-source-chain-final-v1`. The kernel matrix and four chain stages passed 20 QEMU executions across ELF/raw and EL1/EL3; offline chain verification passed. The context remains 24 bytes and its portable record 80 bytes. Saved `(ledger.value, ledger.calls)` pairs at ordinals 2, 4 and 5 are `(8589934601, 2)`, `(4294967313, 4)` and `(12884901908, 5)`. Construction hashes identify the tools used for that build, and guest host services remain disabled.

## Byte-preserving source workflow

Clang source offsets count bytes. Indexing decoded Python characters can move an edit into a different token after multibyte text; normalizing CRLF can change offsets and input hashes. The shared transformer now keeps source buffers, delimiter scans, initializer rewrites and edit ranges in byte coordinates. It decodes complete UTF-8 expressions only when composing generated C. Clang JSON and diagnostics are explicitly decoded as UTF-8, so an ASCII host locale cannot break AST name decoding. Unicode declaration names returned by the AST are encoded when inserted. Readonly declaration offsets in the plan refer to original input bytes, including a leading BOM.

The callable regression checks UTF-8 comments, typedef and private-function identifiers, mutable and readonly string seeds, owned pointers and local constant lifting. Each variant runs on QEMU with LF, CRLF, CR, or CRLF plus a BOM. The LF variant is transformed in a fresh Python interpreter under `LC_ALL=C`, with UTF-8 mode and locale coercion disabled, then compiled and verified on QEMU. It verifies encoded string bytes, interleaved cumulative updates, isolation and reset, exact source hashes, original byte offsets, untouched comments/line endings and BOM placement. Invalid UTF-8 rejects before changing source or header files.

`tests/test_source_bytes_checkpoint.py` creates a pinned portable port with UTF-8 comments in both kernel sources, the model header and the compiled C app. These inputs use CRLF and a BOM. Its kernel also contains a readonly local UTF-8 string and a mutable pointer to that string. The pointer is transient and has a source-owned canonical address/byte check at each boundary. The ordinary local seed pointer is reconstructed alongside it; saved ledger values and call counts remain persistent. The context is 40 bytes and its record 80 bytes. The base portable fixture remains 24/80 bytes.

The application advances through 0 → 2 → 4 → 5 → 6 in fresh images. Every resumed interval loads twice into different contexts, and each image runs as ELF/raw from EL1/EL3. The regression checks saved ledger pairs, exact prepared-source hashes, retained Unicode/BOM bytes and offline verification after deleting the original bundle. Changing a published comment fails the input pin check. Re-pinning a corrupted string seed fails the QEMU target proof before image publication, even when its pointer identity remains correct.

Reproduce the fixture and use the shared pipeline:

```sh
PYTHONPATH=tests python3 - <<'PY'
from pathlib import Path
from test_source_bytes_checkpoint import prepare_fixture
prepare_fixture(Path('build/my-source-bytes-port'))
PY
python3 tools/export_syscall_slices.py \
  --capture build/my-source-bytes-port \
  --port build/my-source-bytes-port/port.json --out build/my-source-bytes-kernel
python3 tools/verify_syscall_slices.py \
  --image build/my-source-bytes-kernel --out build/my-source-bytes-kernel-qemu
python3 tools/run_c_application_checkpoint_chain.py \
  --slices build/my-source-bytes-kernel \
  --source build/my-source-bytes-port/application.c \
  --spec build/my-source-bytes-port/spec.json \
  --pause-ordinals 2,4,5 --out build/my-source-bytes-chain
python3 tools/run_c_application_checkpoint_chain.py --verify build/my-source-bytes-chain
```

Retained inputs are `build/source-bytes-port-final-v1`; outputs are `build/source-bytes-kernel-final-v1`, `build/source-bytes-kernel-qemu-final-v1` and `build/source-bytes-chain-final-v1`. The kernel and four chain stages passed all four QEMU modes, for 20 retained matrix executions. Offline verification passed, construction hashes identify the tools used for that build and guest host services remain disabled. Saved ledger value/call pairs are `(8589934601, 2)`, `(4294967313, 4)` and `(12884901908, 5)`.

The compiler can fold away a readonly string's source symbol. Evidence therefore finds the exact 17 UTF-8/NUL bytes in readonly ELF load segments; the source-owned guest boundary check still verifies pointer identity and every byte. Their load addresses in the three producer images are `0x40407200`, `0x40607200` and `0x404071b0`; the final image uses `0x40607188`. This inspection uses the ELF segments and requires no retained string symbol.

Seven affected CTest suites passed across the serial run and final reruns: callable slices, OHOS application checkpoints, external ports, object graphs, buffer references, mixed declarations and the new source-byte checkpoint suite. The initial CTest report marked the buffer suite as timed out despite its captured Python output reporting success; the rerun passed in 12.51 seconds. After making Clang decoding explicitly UTF-8, the complete callable suite (12 tests) and the source-byte checkpoint suite passed again in 13.85 and 10.64 seconds. The three final suites completed in 37.00 seconds. Both attempts are retained in `build/live-syscall-checks/qemu-source-bytes-results.xml` and `qemu-source-bytes-final-results.xml`. `source-bytes-validation.json` records the seven final passing suites and report hashes; `source-bytes-retained-evidence.json` records construction hashes, exact input hashes, ledger pairs and readonly segment addresses. The focused ASCII-locale/encoding test passed in 1.60 seconds.

This fixes source-coordinate and encoding handling within the existing prepared C closure. Descriptor root names and checkpoint field/type policies retain their existing grammar and bounds; accepting a Unicode identifier in transformed C does not widen those contracts. [Ordinary function-local enum constants](local-static-context-state.md#local-enum-seed-checkpoint-workflow) can now seed mutable scalars, arrays and pointer offsets, with target values and shadowed scopes reconstructed automatically. Generated context parameters and helper temporaries avoid existing declaration and macro names. Function-local field types, lifted readonly seeds depending on local enums, indirect calls, volatile/TLS state, complex declarations and unsupported macro spellings still require preparation or an adapter. Macros whose values depend on source position also require explicit preparation. There is no session or checkpoint wire ABI change.

Seven regression suites passed: callable slices, external ports, object graphs, buffer references and application checkpoints in 118.52 seconds (`build/live-syscall-checks/qemu-nested-source-results.xml`), plus application frames and the CPU gateway in 31.53 seconds (`build/live-syscall-checks/qemu-nested-source-proof-results.xml`). The external-port suite now includes four tests, and the focused nested layout/path rejection pair passed in 35.36 seconds.

This support preserves a port's prepared directory layout. The adapter still supplies a reviewed C closure, model types, runtime boundary and checkpoint policy. It does not discover an arbitrary kernel's build configuration or dependency closure. Shared declaration/macro tokens that bind to different private definitions still require source-local declarations or preparation by the adapter.
