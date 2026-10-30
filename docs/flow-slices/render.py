"""Render focused OSREC data-format diagrams from implementation contracts."""
from pathlib import Path
import html
import json
import subprocess

ROOT = Path(__file__).resolve().parent


def card(title, subtitle, sections):
    rows = [f'<TR><TD COLSPAN="2" BGCOLOR="#dbeafe"><B>{html.escape(title)}</B></TD></TR>',
            f'<TR><TD COLSPAN="2"><FONT POINT-SIZE="10" COLOR="#1d4ed8">{html.escape(subtitle).replace(chr(10), "<BR/>")}</FONT></TD></TR>']
    for heading, fields in sections:
        rows.append(f'<TR><TD COLSPAN="2" BGCOLOR="#f1f5f9"><B>{html.escape(heading)}</B></TD></TR>')
        for key, value in fields:
            rows.append('<TR><TD ALIGN="LEFT"><FONT FACE="Courier" POINT-SIZE="11">'
                        + html.escape(key) + '</FONT></TD><TD ALIGN="LEFT"><FONT POINT-SIZE="11">'
                        + html.escape(value).replace('\n', '<BR ALIGN="LEFT"/>') + '</FONT></TD></TR>')
    return '<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="2" CELLPADDING="7">' + ''.join(rows) + '</TABLE>>'


def render(name, title, note, nodes, edges):
    graph = ['digraph flow {',
             'graph [rankdir=LR, bgcolor="#f8fafc", pad="0.3", nodesep="0.4", ranksep="0.6", fontname="Helvetica", fontsize=20, labelloc=t, label=' + json.dumps(title + '\n' + note, ensure_ascii=False) + '];',
             'node [shape=box, style="rounded,filled", fillcolor="white", color="#cbd5e1", fontname="Helvetica", margin="0.08"];',
             'edge [color="#2563eb", fontcolor="#334155", fontname="Helvetica", fontsize=11, arrowsize=0.7];']
    graph += [key + ' [label=' + card(*value) + '];' for key, value in nodes.items()]
    graph += [a + ' -> ' + b + ' [label=' + json.dumps(label, ensure_ascii=False) + '];' for a, b, label in edges]
    graph.append('}')
    path = ROOT / (name + '.dot')
    path.write_text('\n'.join(graph) + '\n')
    for fmt in ('svg', 'png'):
        subprocess.run(['dot', '-T' + fmt, '-Gdpi=150', str(path), '-o', str(ROOT / (name + '.' + fmt))], check=True)


render('01-capture-context', '01  Capture → reviewed port → session context',
       'Linux minimal-profile JSON fields shown; capture schemas and dependency models are port-specific.', {
    'capture': ('Native capture JSON', 'tools/capture_linux_aarch64.py', [
        ('capture.json • osrec-linux-aarch64-capture-v1', [
            ('initial', 'pid, tgid, ppid, uids[3], gids[3], umask'),
            ('calls[]', 'Ordered syscall observations'),
            ('number', 'Linux syscall number'),
            ('args[3]', 'Captured integers; output pointers normalized\nto app_words offsets / invalid-address sentinels'),
            ('raw_bits', 'Raw 64-bit syscall result bits'),
            ('words[8]', 'Observed uint32 user-buffer contents'),
            ('umask_after', 'Mask observed after each call')]),
        ('capture.manifest.json', [('identity', 'Kernel release + Image / config hashes'),
                                   ('capture_sha256', 'Exact capture JSON identity'),
                                   ('reviewed_source_identity', 'Selected upstream source identity')])]),
    'port': ('Prepared kernel port', 'tools/prepare_linux_aarch64_port.py\ntools/slice_port_bundle.py', [
        ('port.json • osrec-kernel-slice-port-v1', [('roots[]', 'number, function, arguments'),
            ('argument_width', 'Port-defined syscall scalar width'),
            ('bundle', 'Hash-bound adapter / proof / construction inputs')]),
        ('Prepared source closure', [('syscalls.c', 'Selected original syscall bodies'),
            ('models.c / model.h', 'Reviewed dependency and type definitions'),
            ('adapter.c / capture.c', 'Returning session adapter + embedded observations'),
            ('checkpoint-policy.json', 'Exact type + policy for every context field')])]),
    'context': ('Transformed per-session state', 'tools/contextify_slice.py', [
        ('slice_context.h • generated C, not wire data', [('struct osrec_kernel_context', 'Owns moved globals and supported local statics'),
            ('state access', 'global → ctx->field'),
            ('direct calls', 'callee(args) → callee(ctx, args)'),
            ('osrec_context_restore(ctx)', 'Zero storage; reconstruct original initializers\nOwned pointer seeds bind to this context')]),
        ('context-plan.json', [('fields', 'name + exact target C type'),
            ('context_functions', 'Functions requiring a context parameter'),
            ('function_dependencies', 'Direct-call dependency graph'),
            ('input_sha256', 'Exact prepared source / header hashes')]),
        ('Boundaries', [('adapter required', 'Indirect calls, mutable TLS / volatile state,\nexternal mutable state, unsupported declarations')])])
}, [('capture', 'port', 'Observed values\n+ provenance'), ('port', 'context', 'Prepared C closure\n+ owned headers')])

render('02-application-import', '02  Application checkpoint → route package → image',
       'JSON fields are schema projections. Hex strings encode bytes; ELF PT_LOAD segments define the initial image.', {
    'input': ('User-space input checkpoint', 'tools/compile_c_application.py or supplied ELF', [
        ('checkpoint.json • osrec-aarch64-application-checkpoint-v1', [
            ('elf_sha256', 'SHA-256 of exact application.elf'),
            ('frame', 'x[31], sp, pc, pstate, v[32] as [lo,hi],\nfpcr, fpsr, tpidr_el0, tpidrro_el0'),
            ('calls[]', '{pc}: ordered active syscall instruction addresses'),
            ('first_ordinal / completed_calls[]', 'Completed prefix count / {pc} history on resume'),
            ('exit', '{pc, original}: expected 4 original instruction bytes'),
            ('snapshots[]', '{address, data}: recorded non-code byte overlays'),
            ('extra_memory[]', '{address, bytes, permissions}: stack / heap ranges'),
            ('objects[]', '{address, bytes, id}: memory object identities'),
            ('assertions[]', '{address, data}: expected final memory bytes')])]),
    'routes': ('Validated route package', 'tools/import_application_checkpoint.py', [
        ('route-plan.json • osrec-aarch64-application-routes-v1', [
            ('frame', 'Normalized complete initial CPU frame'),
            ('loads[]', 'address, file_bytes, memory_bytes, flags,\nfile, sha256, plus file_offset for ELF segments'),
            ('sites[]', 'ordinal, svc_pc, continuation_pc = svc_pc + 4'),
            ('patches[]', 'address, original, replacement, kind'),
            ('regions[]', 'User-memory partitions with permissions / object IDs'),
            ('assertions / exit_pc', 'Final memory checks and explicit exit boundary')]),
        ('Retained files', [('original.elf / patched.elf', 'Original image / patched executable image'),
            ('memory payloads', 'ELF bytes + zero-filled BSS + snapshot overlays'),
            ('generated C / header', 'Loader data and ordered local route table')])]),
    'image': ('Self-contained replay image', 'tools/export_application_replay.py', [
        ('ELF / raw + manifest.json', [('slices.elf', 'ELF entry and PT_LOAD mapping are authoritative'),
            ('slices.bin', 'Raw load form of the replay image'),
            ('embedded inputs', 'Application RAM / frame, route table, slices.a,\ninitial context or saved joint kernel record'),
            ('manifest', 'Image / archive / source / application hashes,\nexpected result and target observations')]),
        ('Transformation', [('SVC patch', 'Declared SVC → BRK #0x5353'),
            ('exit patch', 'Declared exit → BRK #0x5354'),
            ('repeated PC', 'One physical patch; multiple ordered route entries')])])
}, [('input', 'routes', 'ELF + JSON\nValidate / patch / normalize'), ('routes', 'image', 'Payloads + routes + frame\nCombine with kernel archive')])

render('03-syscall-abi', '03  Local gateway → returning slice ABI → application',
       'These are in-memory C structures, not portable serialized records. Pointer and size_t layout follows the target ABI.', {
    'frame': ('Application frame and route', 'include/osrec/aarch64_frame.h\nruntime/aarch64_gateway.S / .c', [
        ('osrec_aarch64_frame • 808 bytes', [('x[31]', '31 × u64 general registers'),
            ('sp / pc / pstate', '3 × u64'),
            ('v[32]', '32 × {lo:u64, hi:u64}'),
            ('fpcr / fpsr', '2 × u32'),
            ('tpidr_el0 / tpidrro_el0', '2 × u64')]),
        ('osrec_aarch64_site', [('ordinal', 'u64: expected absolute call ordinal'),
            ('svc_pc / continuation_pc', 'u64 instruction addresses'),
            ('memory', 'osrec_user_memory view')]),
        ('Linux register mapping', [('x8', 'Syscall number'), ('x0–x5', 'Arguments'), ('x0 on return', 'Raw result')])]),
    'invoke': ('Slice invocation and memory', 'include/osrec/syscall_slice.h\nosrec_slice_execute(session, invocation, result)', [
        ('osrec_slice_invocation', [('ordinal / number', '2 × u64'),
            ('args[6]', '6 × u64'), ('memory', 'osrec_user_memory')]),
        ('osrec_user_memory', [('regions', 'const osrec_user_region *'), ('count', 'size_t')]),
        ('osrec_user_region', [('user_address', 'u64 application address'),
            ('image_address', 'unsigned char * to mapped replay bytes'),
            ('bytes', 'size_t range length'),
            ('permissions', 'u32: READ=1, WRITE=2 (RW=3)'),
            ('object_id', 'u32 logical memory identity')]),
        ('State supplied separately', [('session.state', 'Caller-owned kernel context pointer'),
            ('session.next', 'u64 expected invocation ordinal')])]),
    'result': ('Returning result and effects', 'runtime/syscall_slice.c\nruntime/aarch64_frame.c', [
        ('osrec_slice_result', [('raw', 'i64 raw syscall return'),
            ('status / diagnostic', '2 × u32'), ('ordinal', 'u64 invocation ordinal')]),
        ('Runtime status codes', [('0 / 1 / 2', 'OK / BAD_INPUT / BUSY'),
            ('3 / 4 / 5', 'DIVERGED / POISONED / COMPLETE')]),
        ('Successful return', [('frame.x[result_register]', 'Install raw result (Linux x0)'),
            ('frame.pc', 'svc_pc + 4'),
            ('user-memory effects', 'Writes retained in mapped application RAM'),
            ('kernel-context effects', 'Updates retained for the next syscall')])])
}, [('frame', 'invoke', 'Save live frame\nValidate route / extract registers'), ('invoke', 'result', 'Original body + reviewed models\nCompute return and effects')])

render('04-kernel-checkpoint', '04  Kernel checkpoint record • exact wire layout',
       'All header integers are little-endian. Payload is schema-bound AArch64 little-endian data; no raw context padding.', {
    'header': ('kernel.bin: fixed header', 'runtime/slice_checkpoint.c\nOSREC_SLICE_CHECKPOINT_ABI = 1', [
        ('Byte offset • type • meaning', [('0–7', 'u64 magic: 0x31504b434552534f\nASCII bytes: OSRECKP1'),
            ('8–11', 'u32 version = 1'), ('12–15', 'u32 total record bytes = 64 + payload_bytes'),
            ('16–47', '32 raw schema SHA-256 bytes'), ('48–55', 'u64 next absolute syscall ordinal'),
            ('56–63', 'u64 FNV-1a checksum\nRecord bytes excluding checksum field'),
            ('64 onward', 'Generated field payload')])]),
    'payload': ('Schema-defined payload', 'tools/slice_checkpoint_codec.py\nosrec-slice-checkpoint-schema-v1 policy', [
        ('Field policy → wire encoding', [('persist', 'Integer / byte-array bytes packed in field order'),
            ('context_reference', 'u64 field-local object ID; zero = null'),
            ('context_buffer_reference', 'u64 buffer ID + u64 byte offset\nCanonical null = (0,0)'),
            ('self_reference', 'No wire bytes; rebuild canonical owned link'),
            ('transient', 'No wire bytes; reconstruct initial / scratch state'),
            ('members / elements', 'Recursively classify struct / fixed-array fields')]),
        ('Codec manifest • osrec-slice-checkpoint-codec-v1', [('fields[]', 'type, policy, context offset / bytes,\nwire_offset and reference targets where applicable'),
            ('schema_sha256', 'Identity of layout, policy and construction'),
            ('payload_bytes / record_bytes', 'Generated size; payload ≤ 65,536 bytes')])]),
    'load': ('Validated restore into fresh context', 'osrec_slice_checkpoint_load()', [
        ('Validation before destination update', [('header', 'Magic / version / size / schema / checksum'),
            ('ordinal', 'Must not exceed selected call count'),
            ('references', 'IDs / offsets / nullability / alignment / bounds'),
            ('port callback', 'Validate temporary state at quiescent boundary')]),
        ('Successful reconstruction', [('1. restore', 'Recreate initial context seeds'),
            ('2. overlay', 'Install persisted scalar and array bytes'),
            ('3. rebind', 'IDs / offsets → destination context pointers'),
            ('4. resume', 'Install saved session.next ordinal')]),
        ('Failure contract', [('Rejected load', 'Session and destination state stay unchanged')])])
}, [('header', 'payload', 'Header binds payload\nto exact codec schema'), ('payload', 'load', 'Decode saved values\nRebind logical references')])

render('05-joint-resume', '05  Paused guest → joint package → fresh-image continuation',
       'Application CPU/RAM and kernel context are separate data formats, linked by ordinal and hash-bound identities.', {
    'dumps': ('Stopped-guest observations', 'tools/application_pause.py: observation_plan\nQMP memory reads outside guest execution', [
        ('pause-records/', [('frame.bin', '808 bytes: saved application CPU frame'),
            ('kernel.bin', '64-byte header + generated kernel payload'),
            ('memory-N.bin', 'Raw bytes for every imported memory load range')]),
        ('Pause contract', [('frame.pc', 'Next declared SVC; paused call has not executed'),
            ('kernel next ordinal', 'Absolute number of completed calls'),
            ('producer manifest', 'Dump hashes / addresses / sizes / proof status')])]),
    'joint': ('Portable joint checkpoint package', 'tools/application_pause.py: freeze / verify_joint', [
        ('Files', [('kernel.bin', 'Verified portable kernel record'),
            ('checkpoint.json', 'Updated user frame / writable RAM snapshots\nRemaining calls + completed_calls history'),
            ('application/', 'Original ELF + newly imported route package'),
            ('manifest.json', 'osrec-joint-application-kernel-checkpoint-v1')]),
        ('Joint manifest key fields', [('pause_ordinal / total_calls', 'Execution position and bounded sequence length'),
            ('generation', 'Checkpoint generation counter'),
            ('input_checkpoint_manifest_sha256', 'Parent identity, or null for first checkpoint'),
            ('kernel_schema_sha256', 'Codec identity'),
            ('kernel_archive_sha256', 'Kernel code identity'),
            ('application_manifest_sha256', 'User route / frame / memory identity'),
            ('artifact_hashes', 'Hashes for retained checkpoint package files')])]),
    'next': ('Fresh image and retained evidence', 'tools/application_checkpoint_chain.py\ntools/export_application_replay.py', [
        ('Composition', [('inputs', 'Matching slices.a + joint checkpoint package'),
            ('restoration', 'CPU / RAM restored; kernel references rebound'),
            ('active routes', 'Only remaining interval / final suffix'),
            ('execution', 'State persists between calls in this image')]),
        ('Published chain artifacts', [('stage-N/image', 'Self-contained ELF / raw + manifest'),
            ('stage-N/qemu', 'ELF / raw × EL1 / EL3 verification matrix'),
            ('stage-N/checkpoint', 'Next joint checkpoint if paused'),
            ('finish/', 'Final suffix image and verification evidence'),
            ('workflow.json', 'Intervals / generations / identities / hashes')])])
}, [('dumps', 'joint', 'Verify frame / RAM / record\nNormalize snapshot into package'), ('joint', 'next', 'Hash-bound saved state\nCompose and execute suffix')])

print('Rendered five PNG / SVG diagrams in', ROOT)
