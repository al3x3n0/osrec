import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { FileBlob, Presentation, PresentationFile } from '@oai/artifact-tool';
import JSZip from 'jszip';

const workspace = fileURLToPath(new URL('../../', import.meta.url));
const root = path.resolve(workspace, '../..');
const build = path.join(workspace, '.build/current-flow-macos');
const source = path.join(workspace, 'output/osrec-current-el0-flow-20261117.pptx');
const output = path.join(workspace, 'output/osrec-current-el0-flow-macos.pptx');
const home = process.env.HOME;
const skill = path.join(home, '.codex/plugins/cache/openai-primary-runtime/presentations/26.909.12148/skills/presentations');
const runtime = path.join(home, '.cache/codex-runtimes/codex-primary-runtime/dependencies');
const tools = path.join(skill, 'container_tools');
process.env.RUNTIME_NODE_MODULES = path.join(runtime, 'node/node_modules');
const { finalizePresentation, resolvePresentationFont } =
    await import(pathToFileURL(path.join(tools, 'artifact_tool_utils.mjs')));
const font = resolvePresentationFont({ fontFamily: 'Helvetica Neue' });
const codeFont = resolvePresentationFont({ fontFamily: 'Menlo' });

const color = {
    ink: '#142735', body: '#334155', muted: '#64748B', native: '#087F8C', kernel: '#2563EB',
    amber: '#B45309', pale: '#F1F5F9', blue: '#EFF6FF', teal: '#EDF9F8', cream: '#FFFBEB',
};
const caseDir = 'build/el0-ipc-whole-kernel-20261119a';
const userElf = 'build/el0-user-ipc-20261119a/ipc';
const evidence = 'build/el0-ipc-whole-hardened-20261119a/validation.json';
const manifest = `${caseDir}/program/manifest.json`;
const relocation = `${caseDir}/relocation.json`;
const reference = `${caseDir}/reference/calls.json`;
const baseline = `${caseDir}/linux-baseline/validation.json`;
const json = async relativePath => JSON.parse(await fs.readFile(path.join(root, relativePath), 'utf8'));
const [report, exported, linked, calls, linux] = await Promise.all(
    [evidence, manifest, relocation, reference, baseline].map(json),
);
const syscallCount = calls.calls.filter(event => event.number >= 0).length;
const faultCount = calls.calls.length - syscallCount;
const fault = calls.calls.find(event => event.event === 'exception');
const hex = value => `0x${value.toString(16)}`;
const format = value => value.toLocaleString('en-US');
const { user_entry: entry } = report;
const loader = 'runtime/el0_macos/loader.c';
const constructor = 'tools/linuxkernel_prepare_application.c';
const application = 'tools/el0_application.py';

const deck = await PresentationFile.importPptx(await FileBlob.load(source));
const archive = deck.slides.items.slice();
const originalLayout = deck.toProto().slides[0].useLayoutId;

function text(slide, value, x, y, width, height, options = {}) {
    const shape = slide.shapes.add({
        name: options.name ?? value.split('\n')[0].slice(0, 90),
        geometry: 'textbox',
        position: { left: x, top: y, width, height },
        fill: options.fill ?? 'none',
        line: { fill: 'none', width: 0 },
    });
    shape.text = value;
    shape.text.style = {
        typeface: options.mono ? codeFont : font,
        fontSize: options.size ?? 29,
        color: options.color ?? color.body,
        bold: options.bold ?? false,
        autoFit: 'none',
    };
    return shape;
}

function heading(slide, value, x, y, width, tint = color.ink) {
    return text(slide, value, x, y, width, 52, { size: 32, color: tint, bold: true });
}

function box(slide, x, y, width, height, stroke, fill) {
    return slide.shapes.add({
        geometry: 'rect',
        position: { left: x, top: y, width, height },
        fill,
        line: { fill: stroke, width: 1.7 },
    });
}

function node(slide, title, details, x, y, width, stroke, fill) {
    const shape = box(slide, x, y, width, 160, stroke, fill);
    text(slide, title, x + 18, y + 16, width - 36, 54, { size: 29, bold: true, color: color.ink });
    text(slide, details, x + 18, y + 80, width - 36, 75, { size: 25 });
    return shape;
}

function arrow(slide, from, to) {
    slide.shapes.connect(from, to, {
        kind: 'straight', fromSide: 'right', toSide: 'left',
        line: { fill: color.native, width: 2.5 }, tail: { type: 'arrow', width: 'med', length: 'med' },
    });
}

function code(slide, label, lines, x, y, width, { size = 26, tint = color.pale, lineHeight = 38 } = {}) {
    text(slide, label, x, y, width, 39, { size: 22, bold: true, color: color.muted });
    const height = lines.length * lineHeight + 24;
    box(slide, x, y + 44, width, height, '#CBD5E1', tint);
    lines.forEach((line, i) => {
        text(slide, line, x + 15, y + 53 + i * lineHeight, width - 30, lineHeight + 2, {
            size, mono: true, color: color.ink,
        });
    });
}

function note(slide, value, y = 775) {
    text(slide, value, 64, y, 1472, 59, { size: 27, color: color.body });
}

function footer(slide, label, number) {
    text(slide, label, 64, 854, 1350, 28, { size: 19, color: color.muted });
    text(slide, String(number).padStart(2, '0'), 1480, 850, 56, 32, { size: 21, color: color.muted });
}

function nativeTable(slide, values, widths, y, height, monospaceColumns = []) {
    const table = slide.tables.add({
        rows: values.length, columns: widths.length, left: 64, top: y,
        width: 1472, height, columnWidths: widths, values,
    });
    table.borders.assign({ style: 'solid', fill: '#CBD5E1', width: 0.6 });
    for (let row = 0; row < values.length; row++) {
        for (let column = 0; column < widths.length; column++) {
            const cell = table.getCell(row, column);
            const header = row === 0;
            cell.fill = header ? color.ink : row % 2 ? '#FFFFFF' : color.pale;
            cell.text.style = {
                typeface: !header && monospaceColumns.includes(column) ? codeFont : font,
                color: header ? '#FFFFFF' : color.body, fontSize: 26, bold: header,
            };
        }
    }
}

let added = 0;
function slide(title, subtitle, refs, notes) {
    const page = deck.slides.add({ width: 1600, height: 900, layoutId: originalLayout });
    page.background.fill = '#FFFFFF';
    text(page, title, 64, 43, 1472, 70, { size: 49, bold: true, color: color.ink });
    text(page, subtitle, 64, 132, 1472, 75);
    footer(page, 'OSREC  /  Apple Silicon EL0 replay', ++added);
    page.speakerNotes.textFrame.setText([...refs.map(ref => path.join(root, ref)), '', notes].join('\n'));
    return page;
}

{
    const page = slide(
        'User and kernel execution at EL0 on macOS',
        'A flat AArch64 checkpoint runs application code and relocated Linux kernel code on one Apple Silicon vCPU.',
        ['docs/el0-macos.md', 'docs/el0-user-binary.md', evidence, baseline],
        'The Apple Silicon run validates workload behavior through the completion breakpoint. The November 17 QEMU profile in the appendix describes a prior model setup and a different workload.',
    );
    const capture = node(page, 'Construct in Linux', 'Kernel capsule + user ELF\nCheckpoint at user entry', 64, 274, 400, color.muted, color.pale);
    const link = node(page, 'Link one replay ELF', 'User text, resident kernel text\nand initial RAM', 600, 274, 400, color.kernel, color.blue);
    const execute = node(page, 'Run on Apple Silicon', 'Load and validate the\ncombined EL0 execution', 1136, 274, 400, color.native, color.teal);
    arrow(page, capture, link);
    arrow(page, link, execute);
    heading(page, 'Verified IPC replay', 64, 547, 1472, color.kernel);
    const metrics = [
        [syscallCount, 'matched syscalls'],
        [faultCount, 'matched Linux translation fault'],
        [report.hardware_exceptions, 'hardware exceptions'],
    ];
    metrics.forEach(([value, label], i) => {
        const x = 64 + i * 500;
        text(page, String(value), x, 610, 170, 84, { size: 64, color: color.native, bold: true });
        text(page, label, x, 703, 480, 62, { size: 27 });
    });
}

{
    const page = slide(
        'What the flat loader sets up',
        'The Mach-O host loader reads the AArch64 ELF and starts an EL0t vCPU through Hypervisor.framework.',
        ['docs/el0-macos.md', loader, 'tools/el0_macos.py', `${caseDir}/program/pretranslated-elf.json`, evidence],
        'On macOS the harness supplies stage-2 RAM backing with hv_vm_map. Flat mode leaves both guest table roots at zero and disables guest SCTLR_EL1.M. Normal cacheable RAM holds the preloaded checkpoint. Linux page-table bytes in that RAM still participate in replay software checks. The ELF carries no guest model page tables.',
    );
    const load = node(page, 'ELF PT_LOAD segments', 'Copy file bytes into canonical RAM and zero-fill the rest', 64, 255, 400, color.muted, color.pale);
    const host = node(page, 'Hypervisor.framework', 'Map the backing RAM for one hardware vCPU', 600, 255, 400, color.kernel, color.blue);
    const el0 = node(page, 'Flat EL0t', 'User and kernel text share the same linked address space', 1136, 255, 400, color.native, color.teal);
    arrow(page, load, host);
    arrow(page, host, el0);
    code(page, 'vCPU state at user entry', [
        'SCTLR_EL1.M = 0',
        'TTBR0_EL1   = 0',
        'TTBR1_EL1   = 0',
    ], 64, 490, 538);
    heading(page, 'Captured Linux mappings', 660, 495, 875, color.kernel);
    text(page, 'The loader preloads RAM before execution. The replay reads the captured Linux PTEs when a user access needs a software check.', 660, 558, 875, 150);
    note(page, 'Guest stage-1 translation stays off. The harness provides stage-2 RAM backing.');
}

{
    const page = slide(
        'Resident kernel text links into the replay ELF',
        'The supplied-user builder includes all resident kernel instructions identified by the captured ELF.',
        ['docs/el0-user-binary.md', 'docs/el0-compact-relocation.md', application, 'runtime/el0_flat/whole-kernel.ld', relocation, manifest],
        'The exporter reads captured instruction bytes for persistent ELF-identified code. Init code and unidentified dynamic code are outside scope. The manifest lists two absent captured text ranges. Original PCs are dispatch keys. Data pointers and RAM aliases follow the runtime address-conversion paths.',
    );
    nativeTable(page, [
        ['Kernel entry', 'Original Linux PC', 'Linked EL0 PC', 'Taken in IPC'],
        ...linked.sample_functions.map(fn => [
            fn.function, fn.original_pc, fn.linked_pc, fn.function.endsWith('_chdir') ? 'No' : 'Yes',
        ]),
    ], [500, 380, 325, 267], 242, 280, [0, 1, 2]);
    heading(page, `${format(exported.source_instructions)} exported source instruction sites`, 64, 589, 1472, color.kernel);
    text(page, 'A user SVC transfers control through an EL0 gateway into captured kernel code. The guest can return to the application while staying in EL0.', 64, 652, 1472, 84);
    note(page, 'Use --kernel-slice to select a workload-specific link. In that mode, --extra-pc can seed additional original PCs.');
}

{
    const page = slide(
        'The captured user ELF determines the start PC',
        'Construction verifies that Linux reaches the supplied ELF entry before saving the application frame.',
        [constructor, 'runtime/el0_flat/start.S', 'runtime/el0_flat/program.c', 'runtime/el0_flat/gateway.inc', evidence],
        'The loader starts the replay ELF at its own e_entry. flat_main resolves flat_initial.cpu.pc in the original-PC index. The displayed resume sequence is the logical-stack form used in this IPC image. An already-running checkpoint resumes from its saved PC.',
    );
    nativeTable(page, [
        ['Address', 'IPC value', 'Role'],
        ['Replay ELF e_entry', report.entry, 'Bootstrap _start begins at EL0'],
        ['User ELF e_entry / saved PC', entry.original_pc, 'Original application instruction to resume'],
        ['Linked user entry', entry.linked_pc, 'First relocated application instruction'],
    ], [506, 302, 664], 227, 238, [1]);
    code(page, 'runtime/el0_flat/gateway.inc  /  flat_resume excerpt', [
        'ldp x16,x17,[sp,#128]',
        'add sp,sp,#800',
        'b \\target',
    ], 64, 521, 755);
    text(page, 'The resume thunk restores its scratch registers, releases the spill frame, then branches to the linked user instruction.', 875, 562, 661, 155);
}

{
    const page = slide(
        'The host verifies entry state and completion',
        'A hardware breakpoint stops execution before the first relocated user instruction.',
        [loader, 'tools/el0_macos.py', 'tests/test_el0_macos.py', evidence, reference],
        'The entry breakpoint is an intentional host debug exit. It is separate from hardware exceptions counted during execution. The match checks logical user mode, logical SP, the actual SP convention, X0–X30, NZCV, Q0–Q31, FPCR and FPSR. The loader resumes only on a match. An injected register mismatch reached the expected address and was rejected before workload execution.',
    );
    code(page, 'runtime/el0_macos/loader.c  /  entry capture excerpt', [
        'for (unsigned i = 0; i < 31; i++)',
        '    HV(hv_vcpu_get_reg(vcpu, HV_REG_X0 + i,',
        '                       &registers->x[i]));',
    ], 64, 233, 837, { size: 25 });
    heading(page, 'Before entry', 937, 236, 590, color.kernel);
    text(page, 'Bind the saved PC and code bytes to the user ELF. Check the observed integer and SIMD registers, flags and stack.', 937, 297, 590, 163);
    heading(page, 'At flat_completed', 64, 532, 1472, color.kernel);
    text(page, 'Stop before the terminal SVC. Compare the raw syscall and fault ledger, stop PC, counter inputs and UART against the reference.', 64, 594, 1320, 108);
    note(page, 'A negative test corrupted restored X0 and was rejected at the entry breakpoint.');
}

{
    const page = slide(
        'The IPC binary checks buffering and error paths',
        'The static AArch64 ELF issues raw Linux syscalls for a nonblocking pipe and an eventfd counter.',
        ['examples/el0-user/ipc.c', 'examples/el0-user/syscall.h', reference, baseline, evidence],
        'The pipe checks the payload PIPE42, a six-byte writev/readv transfer, EAGAIN while empty, and EOF after the writer closes and the buffer drains. The eventfd checks EINVAL for a 4-byte read, a full-width counter value of 7 after adding 5 to 2, and EAGAIN after draining. The AArch64 Linux baseline used the unmodified user ELF.',
    );
    code(page, 'examples/el0-user/ipc.c  /  selected checks', [
        'long fd = call(SYS_EVENTFD2, 2, NONBLOCK | CLOEXEC, 0);',
        'uint64_t increment = 5;',
        'uint64_t value;',
        '/* After checking fd, test the short read. */',
        'if (call(SYS_READ, fd, (long)&value, 4) != -INVALID)',
        '    return 21;',
    ], 64, 233, 965, { size: 25, lineHeight: 38 });
    heading(page, 'Pipe', 1074, 237, 462, color.kernel);
    text(page, 'Empty read → EAGAIN\nwritev / readv → 6 bytes\nClose, drain, then read → EOF', 1074, 295, 462, 146);
    heading(page, 'Eventfd', 1074, 483, 462, color.kernel);
    text(page, 'Short read → EINVAL\n2 + 5 → 7\nRead after drain → EAGAIN', 1074, 542, 462, 142);
    note(page, `Apple Silicon matched ${report.result.uart_bytes} UART bytes. AArch64 Linux printed OSREC_IPC_PASS and exited ${linux.exit_status}.`);
}

{
    const page = slide(
        'The remaining IPC fault is a .rodata read',
        'The checked replay logs one Linux translation fault. The Apple Silicon vCPU reports zero hardware exceptions.',
        [reference, evidence, constructor, 'runtime/el0_flat/program.c', userElf],
        'Disassembly of the original IPC ELF identifies the LDP at 0x20119c. Its first read of the page containing .rodata at FAR 0x200130 logs ESR 0x92000007. A software PTE check enters the captured Linux fault path in EL0. The PF_R proposal changes initial residency and needs a new reference. Deliberate COW, protection, and demand faults can still matter for other workloads.',
    );
    code(page, 'Original IPC instruction and recorded fault', [
        `${fault.pc}   ldp x9, x10, [x8]`,
        `FAR        ${hex(fault.arguments[1])}  (.rodata)`,
        `ESR        ${hex(fault.arguments[0])}`,
    ], 64, 231, 685, { tint: color.cream });
    code(page, 'Constructor today  /  segment filter', [
        'segments[i].p_type == PT_LOAD &&',
        'segments[i].p_flags & PF_X',
    ], 804, 231, 732);
    text(page, 'The live Linux PTE check routes this read into captured Linux fault code.', 64, 452, 685, 125);
    text(page, 'The constructor uses MADV_POPULATE_READ on executable segments before saving memory.', 804, 452, 732, 125);
    heading(page, 'Proposed construction change', 64, 587, 1472, color.amber);
    text(page, 'Also prefault nonempty readable PT_LOAD segments with PF_R. Record a fresh reference and check for zero logical faults with the same entry state and IPC results.', 64, 647, 1430, 120);
}

{
    const page = slide(
        'Reproduce the checked Mac run',
        'Run these commands from the repository root on Apple Silicon with the recorded IPC artifacts.',
        ['docs/el0-macos.md', 'runtime/el0_macos/Makefile', 'tools/el0_macos.py', evidence, reference],
        'Flat execution requires macOS 15 or later and Hypervisor support for EL2 configuration. Use the validation JSON and raw records in the output directory. The verified run consumed no counter inputs and produced 16 UART bytes. The breakpoints establish functional execution boundaries. Microarchitectural timing requires a separate measurement.',
    );
    const continuation = ' \\';
    code(page, 'Shell', [
        'make -C runtime/el0_macos loader',
        `replay=${caseDir}`,
        `python3 tools/el0_macos.py${continuation}`,
        '  --image "$replay/program/checkpoint"' + continuation,
        `  --user-elf ${userElf}${continuation}`,
        '  --reference "$replay/reference/calls.json"' + continuation,
        '  --out build/ipc-verification',
    ], 64, 222, 1472, { size: 27, lineHeight: 39 });
    heading(page, 'validation.json', 64, 610, 1310, color.kernel);
    text(page, 'Check user_entry.verified, host_events_verified and el0_interval_verified. The output also includes raw entry registers, terminal state, events and UART.', 64, 669, 1430, 95);
    note(page, 'The breakpoints establish functional execution boundaries for this run.');
}

{
    const page = slide(
        'The macOS checkpoint requires a segment loader',
        'Direct execution of this exact ELF failed with ENOEXEC on AArch64 Linux 6.10.14 with 4 KiB pages.',
        [`${caseDir}/program/checkpoint`, 'tools/pretranslate_el0_image.py', loader],
        'Checked with subprocess.run on AArch64 Linux 6.10.14-linuxkit, page size 4096, using the exact checkpoint SHA-256 in the Mac report. The 566 program headers occupy 31,696 bytes and exceed ELF_MIN_ALIGN on that host. Independently, the first packed RAM segment has a file offset of 0x1f0 and a page-aligned virtual address. Inspect with llvm-readelf -h -l. Android was assessed from its loader code and was not run on a device.\n\nLinux ELF loader: https://github.com/torvalds/linux/blob/v6.10/fs/binfmt_elf.c#L329-L365\nLinux program-header limit: https://github.com/torvalds/linux/blob/v6.10/fs/binfmt_elf.c#L474-L491\nAndroid common kernel loader: https://android.googlesource.com/kernel/common/+/refs/heads/android15-6.6/fs/binfmt_elf.c#352',
    );
    code(page, 'First packed RAM PT_LOAD  /  llvm-readelf', [
        'p_offset = 0x000001f0',
        'p_vaddr  = 0x5d92c000',
        'p_align  = 0x1',
    ], 64, 232, 694);
    heading(page, 'Why direct execution fails', 812, 237, 724, color.kernel);
    text(page, 'The 31,696-byte program-header table exceeds the tested Linux limit. Packed RAM offsets also fail the page-offset rule used by Linux and Android.', 812, 297, 724, 172);
    heading(page, 'Running the same bytes on another host', 64, 528, 1472, color.kernel);
    text(page, 'A compatible loader would copy the segments into RAM at the linked addresses, as the Mac loader does. Direct execve would need an ELF repacked for the host page size.', 64, 590, 1430, 112);
    note(page, 'The original IPC user ELF ran unchanged on AArch64 Linux. Android device testing is pending.');
}

function replaceText(slide, oldValue, newValue) {
    const shape = slide.shapes.items.find(item => item.text.toString() === oldValue);
    if (!shape) throw new Error(`Source slide text not found: ${oldValue}`);
    shape.text.replace(oldValue, newValue);
}

archive.forEach((page, index) => {
    replaceText(page, 'OSREC  /  Current EL0 checkpoint executor  /  17 November 2026',
        'OSREC  /  QEMU checkpoint profile  /  17 November 2026');
    replaceText(page, String(index + 1).padStart(2, '0'), String(index + added + 1).padStart(2, '0'));
});
replaceText(archive[0], 'Current EL0 checkpoint flow', 'Earlier QEMU checkpoint flow');
replaceText(archive[0], 'Captured application and kernel instructions continue together in one standalone executor.',
    'The November 17 random/fault workload used the QEMU model with guest page tables.');
replaceText(archive[0], 'Latest accepted run: 2,272 events match, with 2,381 gateway entries and zero hardware exceptions.',
    'This run matched 2,272 events, with 2,381 gateway entries and zero hardware exceptions.');

// Keep the imported chart, layouts, and other slide objects in the same document.
const combined = deck.toProto();
combined.slides = [...combined.slides.slice(archive.length), ...combined.slides.slice(0, archive.length)];
const presentation = Presentation.load(combined);

async function preserveSourceChart(candidate) {
    // The import retains cached values and range references but drops the workbook package.
    // Copy the original chart and its two dependencies so PowerPoint can edit the same data.
    const [from, to] = await Promise.all(
        [source, candidate].map(async file => JSZip.loadAsync(await fs.readFile(file))),
    );
    const chart = 'ppt/slides/charts/chart1.xml';
    if (!to.file(chart)) throw new Error('The exported slide lost its native chart.');
    for (const part of [
        chart,
        'ppt/slides/charts/_rels/chart1.xml.rels',
        'ppt/embeddings/chart-data-snapshot-001.xlsx',
    ]) {
        to.file(part, await from.file(part).async('nodebuffer'));
    }
    const types = '[Content_Types].xml';
    const workbookType = (await from.file(types).async('string')).match(/<Default\b[^>]*\bExtension="xlsx"[^>]*\/>/u)?.[0];
    if (!workbookType) throw new Error('Workbook content type is missing from the source.');
    const candidateTypes = await to.file(types).async('string');
    if (!candidateTypes.includes('Extension="xlsx"')) {
        to.file(types, candidateTypes.replace('</Types>', workbookType + '</Types>'));
    }
    await fs.writeFile(candidate, await to.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' }));
}

await fs.mkdir(build, { recursive: true });
const candidate = path.join(build, 'candidate.pptx');
await (await PresentationFile.exportPptx(presentation)).save(candidate);
await preserveSourceChart(candidate);
await finalizePresentation({
    workspaceDir: workspace, candidatePath: candidate, finalPath: output,
    pythonExecutable: path.join(runtime, 'python/bin/python3'),
    integrityValidatorPath: path.join(tools, 'inspect_presentation_package_integrity.py'),
    layoutValidatorPath: path.join(tools, 'inspect_presentation_layout_geometry.py'),
    explicitTotalSlideCount: added + archive.length,
    requiredNativeTableOwnerSlides: [3, 4, added + 10],
    requiredNativeChartOwnerSlides: [added + 11],
    requiredEmbeddedWorkbookChartOwnerSlides: [added + 11],
    layoutArgs: ['--expected-slide-size-emu', '15240000,8572500', '--validate-heading-fit',
        '--require-native-table-slide', '3', '--require-native-table-slide', '4',
        '--require-native-table-slide', String(added + 10)],
    fontPolicy: { basis: 'design', families: [font, codeFont] },
    verifyArtifactToolImport: true,
    receiptPath: path.join(build, 'validation-delivery.json'),
});

const delivered = await PresentationFile.importPptx(await FileBlob.load(output));
for (const [index, page] of delivered.slides.items.entries()) {
    const png = await delivered.export({ slide: page, format: 'png', scale: 1 });
    const name = `slide-${String(index + 1).padStart(2, '0')}`;
    await fs.writeFile(path.join(build, `${name}.png`), new Uint8Array(await png.arrayBuffer()));
    const layout = await page.export({ format: 'layout' });
    await fs.writeFile(path.join(build, `${name}.layout.json`), await layout.text());
    console.log(`Rendered ${name}`);
}
