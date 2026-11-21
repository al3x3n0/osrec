import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { FileBlob, Presentation, PresentationFile } from '@oai/artifact-tool';
import JSZip from 'jszip';

const workspace = fileURLToPath(new URL('../../', import.meta.url));
const root = path.resolve(workspace, '../..');
const build = path.join(workspace, '.build/current-flow-linux-android');
const source = path.join(workspace, 'output/osrec-current-el0-flow-20261117.pptx');
const output = path.join(workspace, 'output/osrec-current-el0-flow-linux-android.pptx');
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
const evidence = 'build/el0-ipc-merged-segments/linux-validation.json';
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
const packaging = await json('build/el0-ipc-merged-segments/program/pretranslated-elf.json');
if (!report.verified || packaging.image_sha256 !== report.image_sha256) throw new Error('Linux validation does not match the packaged ELF');
const packer = 'tools/pretranslate_el0_image.py';
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
    footer(page, 'OSREC  /  Linux and Android hosts', ++added);
    page.speakerNotes.textFrame.setText([...refs, '', notes].join('\n'));
    return page;
}

{
    const page = slide('EL0 checkpoint replay on Linux and Android',
        'The checkpoint ran as an AArch64 Linux process. Android is the next host target.',
        [application, evidence, baseline], 'The Linux result is for the clustered checkpoint ELF. The separate baseline runs the original IPC application.');
    const capture = node(page, 'Construct on Linux', 'Capture the user entry frame and kernel state', 64, 274, 400, color.muted, color.pale);
    const link = node(page, 'Package one ELF', 'Link the code and cluster the initial RAM segments', 600, 274, 400, color.kernel, color.blue);
    const execute = node(page, 'Execute at EL0', 'The host maps the ELF as an AArch64 process', 1136, 274, 400, color.native, color.teal);
    arrow(page, capture, link);
    arrow(page, link, execute);
    heading(page, 'Checked IPC replay on Linux', 64, 547, 1472, color.kernel);
    [[report.result.events, 'events against 16 expected'], [report.result.uart_bytes, 'UART bytes in replay RAM'], [report.result.exit_status, 'host process exit status']].forEach(([value,label], i) => {
        const x = 64 + i * 500;
        text(page, String(value), x, 610, 170, 84, { size: 64, color: color.native, bold: true });
        text(page, label, x, 703, 480, 62, { size: 27 });
    });
}

{
    const page = slide('How Linux loads the checkpoint',
        'The ELF program headers describe both the linked instructions and the initial contents of replay RAM.',
        [packer, evidence, 'build/el0-ipc-merged-segments/program/pretranslated-elf.json'], 'The report identifies the tested host as AArch64 Linux 6.10.14-linuxkit with 4096-byte pages.');
    const pack = node(page, 'Cluster RAM segments', 'Combine nearby ranges at page-aligned file offsets', 64, 255, 400, color.muted, color.pale);
    const load = node(page, 'Linux ELF loader', 'Map PT_LOAD ranges at their linked addresses', 600, 255, 400, color.kernel, color.blue);
    const run = node(page, 'Process entry', 'Bootstrap the captured application in user space', 1136, 255, 400, color.native, color.teal);
    arrow(page, pack, load);
    arrow(page, load, run);
    heading(page, 'Layout of the verified ELF', 64, 520, 1472, color.kernel);
    text(page, `The image has ${packaging.program_headers} program headers, including ${packaging.ram_load_segments} RAM load segments. Its header table fits the tested 4 KiB page size.`, 64, 590, 1380, 125);
    note(page, 'Clustering preserves the entry address and the virtual addresses used by the replay.');
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
        'The loader starts the replay ELF at its own e_entry. flat_main resolves flat_initial.cpu.pc in the original-PC index. The displayed resume sequence is the logical-stack form used in the IPC image. An already-running checkpoint resumes from its saved PC.',
    );
    nativeTable(page, [
        ['Entry point', 'Source', 'Role'],
        ['Replay ELF e_entry', 'ELF header', 'Bootstrap _start begins at EL0'],
        ['User ELF e_entry / saved PC', 'Saved CPU frame', 'Original application instruction to resume'],
        ['Linked user entry', 'Original-PC index', 'First relocated application instruction'],
    ], [506, 302, 664], 227, 238, [1]);
    code(page, 'runtime/el0_flat/gateway.inc  /  flat_resume excerpt', [
        'ldp x16,x17,[sp,#128]',
        'add sp,sp,#800',
        'b \\target',
    ], 64, 521, 755);
    text(page, 'The resume thunk restores its scratch registers, releases the spill frame, then branches to the linked user instruction.', 875, 562, 661, 155);
}

{
    const page = slide('What the Linux checks establish',
        'Two executions answer different questions about the same IPC workload.',
        [baseline, evidence, reference], 'The user baseline compares stdout after UART newline normalization. The checkpoint report records its completion state and event counts.');
    heading(page, 'Original application', 64, 280, 690, color.kernel);
    text(page, 'The unmodified IPC ELF used real Linux syscalls. It printed OSREC_IPC_PASS and exited with status 0.', 64, 355, 670, 220);
    heading(page, 'Checkpoint executable', 820, 280, 700, color.kernel);
    text(page, `The linked ELF ran captured kernel code at EL0. Its result recorded ${report.result.events} events and ${report.result.uart_bytes} UART bytes before the terminal exit syscall.`, 820, 355, 690, 220);
    note(page, 'The host exit status is visible to the shell. Event counts and UART bytes come from replay RAM.');
}

{
    const page = slide(
        'The IPC binary checks buffering and error paths',
        'The static AArch64 ELF issues raw Linux syscalls for a nonblocking pipe and an eventfd counter.',
        ['examples/el0-user/ipc.c', 'examples/el0-user/syscall.h', reference, baseline],
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
    note(page, `The original IPC application printed OSREC_IPC_PASS on AArch64 Linux and exited with status ${linux.exit_status}.`);
}

{
    const page = slide(
        'The remaining IPC fault is a .rodata read',
        'The captured reference contains one translation fault, triggered by a read from the application’s constant data.',
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
    const page = slide('Running the verified checkpoint on Linux',
        'Use the retained clustered ELF on an AArch64 Linux host with 4 KiB pages.',
        [evidence, packer], 'The digest in linux-validation.json identifies the tested executable. The shell checks process completion. The retained report also contains replay RAM observations.');
    code(page, 'Shell on the Linux host', [
        'run=build/el0-ipc-merged-segments',
        'getconf PAGESIZE',
        'sha256sum "$run/program/checkpoint"',
        '"$run/program/checkpoint"',
        'echo "$?"',
    ], 64, 222, 1472, { size: 27, lineHeight: 39 });
    heading(page, 'Recorded Linux result', 64, 560, 1472, color.kernel);
    text(page, 'The tested host reported a 4096-byte page and exit status 0. Compare the digest with image_sha256 in linux-validation.json to identify the same ELF.', 64, 632, 1430, 100);
}

{
    const page = slide('Android host validation',
        'Device execution is pending. The Linux run provides a reference for testing an arm64 Android device.',
        [evidence, packer, baseline], 'Use an authorized development device and a shell execution directory. Record the device page size and the ELF digest with any reported result.');
    code(page, 'Host shell with an attached development device', [
        'adb shell getconf PAGE_SIZE',
        'adb push build/el0-ipc-merged-segments/program/checkpoint /data/local/tmp/osrec',
        'adb shell chmod 700 /data/local/tmp/osrec',
        'adb shell /data/local/tmp/osrec',
        'echo "$?"',
    ], 64, 232, 1472, { size: 25, lineHeight: 39 });
    heading(page, 'Acceptance criteria', 64, 565, 1472, color.kernel);
    text(page, 'Check ELF alignment against the device page size before launch. Record the exit status. Full replay validation also requires reading the completion record and comparing the events and UART bytes.', 64, 633, 1430, 135);
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
