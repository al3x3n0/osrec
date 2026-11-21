import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { FileBlob, Presentation, PresentationFile } from '@oai/artifact-tool';

const workspace = fileURLToPath(new URL('../../', import.meta.url));
const build = path.join(workspace, '.build/customer-linux-android-readv-handoff');
const output = path.join(workspace, 'output/osrec-customer-linux-android-readv-handoff.pptx');
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
const deck = Presentation.create({ slideSize: { width: 1600, height: 900 } });
const report = 'build/el0-ipc-merged-segments/linux-validation.json';
const baseline = 'build/el0-ipc-whole-kernel-20261119a/linux-baseline/validation.json';
const calls = 'build/el0-ipc-whole-kernel-20261119a/reference/calls.json';
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
        alignment: options.alignment ?? 'left',
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

function block(page, label, x, y, w, h, stroke = color.kernel, fill = color.blue) {
    const shape = box(page, x, y, w, h, stroke, fill);
    shape.text = label;
    shape.text.style = {typeface: font, fontSize: 30, bold: true, color: color.ink,
        alignment: 'center', verticalAlignment: 'middle', autoFit: 'none'};
    return shape;
}

function connect(page, from, to, fromSide = 'right', toSide = 'left') {
    page.shapes.connect(from, to, {
        kind: 'straight', fromSide, toSide,
        line: {fill: color.native, width: 3}, tail: {type: 'arrow', width: 'lg', length: 'lg'},
    });
}

function sequence(page, actors, exchanges) {
    const centers = actors.map((_, i) => 265 + i * 535);
    actors.forEach((actor, i) => {
        const x = centers[i];
        box(page, x - 1, 298, 2, 432, '#CBD5E1', '#CBD5E1');
        block(page, actor, x - 191, 222, 382, 78);
    });
    exchanges.forEach(([from, to, label], i) => {
        const y = 380 + 82 * i;
        const point = x => box(page, x - 1, y - 1, 2, 2, color.native, color.native);
        const rightward = centers[from] < centers[to];
        connect(page, point(centers[from]), point(centers[to]), rightward ? 'right' : 'left', rightward ? 'left' : 'right');
        const left = Math.min(centers[from], centers[to]);
        const width = Math.abs(centers[from] - centers[to]);
        text(page, label, left + 4, y - 49, width - 8, 43, {size: 25, alignment: 'center'});
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

function flowRow(page, labels, y, height = 110) {
    const gap = 82;
    const width = (1472 - gap * (labels.length - 1)) / labels.length;
    const boxes = labels.map((label, i) => block(page, label, 64 + i * (width + gap), y, width, height));
    for (let i = 1; i < boxes.length; i++) connect(page, boxes[i - 1], boxes[i]);
}

let added = 0;
function slide(title, subtitle, refs, notes) {
    const page = deck.slides.add();
    page.background.fill = '#FFFFFF';
    text(page, title, 64, 43, 1472, 70, { size: 49, bold: true, color: color.ink });
    text(page, subtitle, 64, 132, 1472, 75);
    footer(page, 'OSREC  /  Linux and Android hosts', ++added);
    page.speakerNotes.textFrame.setText([...refs, '', notes].join('\n'));
    return page;
}

{
    const page = slide('Checkpoint replay on 64-bit Arm',
        'One executable carries the workload from the build host to the replay host.',
        ['docs/el0-user-binary.md', report], 'The Linux host trial used 4 KiB pages. Android device execution is pending. EL0 is Arm user privilege level.');
    heading(page, 'Linux build host', 68, 255, 430);
    heading(page, 'Delivery', 615, 255, 380);
    heading(page, 'Customer host', 1105, 255, 427);
    const input = block(page, 'Application ELF\n+ captured Linux state', 64, 345, 412, 146);
    const elf = block(page, 'program/checkpoint', 590, 345, 422, 146, color.native, color.teal);
    const process = block(page, 'One EL0 process\nApplication + kernel code', 1100, 345, 436, 146);
    connect(page, input, elf); connect(page, elf, process);
    const reportBox = block(page, 'Result in RAM\n16 events · 16 serial bytes', 1100, 618, 436, 105, color.muted, color.pale);
    connect(page, process, reportBox, 'bottom', 'top');
    note(page, 'Linux run verified on 4 KiB pages. Android device test pending.');
}

{
    const page = slide('Building the checkpoint',
        'The entry snapshot supplies the initial state. A separate run supplies the events and output used to check the replay.',
        ['docs/el0-user-binary.md', 'tools/el0_application.py', calls], 'The kernel loads the static ELF through execveat. The builder snapshots registers and memory at user entry. Reference results support checking at completion.');
    const load = block(page, 'execveat loads\nthe supplied ELF', 65, 355, 310, 126);
    const snap = block(page, 'Snapshot at entry\nRegisters + memory', 447, 355, 337, 126);
    const ref = block(page, 'Run from saved entry\nRecord events + output', 846, 570, 382, 119, color.native, color.teal);
    const link = block(page, 'Link code, gateways\nand initial memory', 862, 355, 345, 126);
    const elf = block(page, 'Checked\ncheckpoint ELF', 1280, 355, 255, 126, color.native, color.teal);
    connect(page, load, snap); connect(page, snap, link); connect(page, link, elf);
    connect(page, snap, ref, 'bottom', 'left'); connect(page, ref, link, 'top', 'bottom');
}

{
    const page = slide('Capturing Linux state in QEMU',
        'QEMU runs the Arm Linux guest during capture. The builder reuses its post-boot state for multiple application builds.',
        ['docs/source-image-flow.md', 'tools/kernel_state_dump.py', 'tools/el0_application.py'],
        'Restore the post-boot QEMU machine and stop at the selected system call in the arm64 synchronous exception vector. The GDB stub holds the virtual CPU stopped. Read the general-purpose, floating-point/SIMD and system registers, including the additional probed registers. QMP pmemsave writes the full guest RAM range to ram.bin. The capsule builder uses matching vmlinux symbols and DWARF type offsets to locate the task and its address space. Its manifest records asset hashes and the parent image identity.');
    heading(page, 'Stopped guest', 64, 234, 399);
    heading(page, 'Capture interface', 517, 234, 465);
    heading(page, 'Saved artifact', 1075, 234, 460);
    const stop = block(page, 'Selected syscall\nArm exception entry', 64, 419, 350, 118);
    const debug = block(page, 'GDB stub\nRead vCPU registers', 517, 339, 420, 100);
    const monitor = block(page, 'QMP pmemsave\nDump physical memory', 517, 541, 420, 100);
    const cpu = block(page, 'state.json\nPC, SP, SIMD and EL1 state', 1055, 339, 480, 100, color.native, color.teal);
    const ram = block(page, 'ram.bin\nFull guest RAM at this stop', 1055, 541, 480, 100, color.native, color.teal);
    connect(page, stop, debug); connect(page, stop, monitor);
    connect(page, debug, cpu); connect(page, monitor, ram);
    note(page, 'The vCPU stays paused across both reads. The builder combines this state with the matching kernel build.');
}

{
    const page = slide('Taking the application snapshot at ELF entry',
        'The captured kernel loads the new program. The constructor saves its entry registers before the first application instruction runs.',
        ['tools/linuxkernel_prepare_application.c', 'build/el0-ipc-whole-kernel-20261119a/prepare.stdout', 'docs/el0-user-binary.md'],
        'The helper closes inherited descriptors above stderr, writes the ELF into a memfd, then invokes execveat with the supplied arguments and an empty environment. It verifies that the resulting PC equals e_entry and keeps that register frame. It populates executable PT_LOAD pages with MADV_POPULATE_READ, clears the initial FP/SIMD state, locates the virtual memory area tree through the current task, and snapshots memory using the saved entry frame. The pipe and eventfd are created later by the application.');
    flowRow(page, ['Load ELF from memfd\nusing execveat', 'Verify entry PC\nand save registers', 'Populate executable pages\nand snapshot RAM'], 270, 130);
    heading(page, 'IPC example at capture', 64, 498, 900);
    code(page, 'Constructor output', ['entry PC       0x201160', 'stack pointer  0xffffc46569c0'], 64, 570, 719, {size: 28});
    text(page, 'At this point the stack holds argv and the auxiliary vector. Only executable segments are prefaulted, so a later data read can still fault.', 850, 591, 668, 140, {size: 30});
}

{
    const page = slide('What replay restores from the snapshot',
        'The prepared checkpoint pairs a register frame with the physical memory and address mappings that give those registers meaning.',
        ['runtime/linuxkernel_el0/native.c', 'tools/el0_application.py', 'build/el0-ipc-whole-kernel-20261119a/state/manifest.json'],
        'native.bin contains the entry context, initialized FP/SIMD state, architectural shadow, mapping records and code metadata. memory.bin has the full logical size of guest physical memory. The writer emits nonzero pages at their physical offsets and leaves zero pages as sparse holes. vma.bin identifies the virtual memory area tree and layout offsets. The manifest binds the native and memory image identity to the parent kernel image and identifies the user ELF. Expected syscall, fault and serial results are recorded in a subsequent run.');
    heading(page, 'Prepared artifact', 64, 225, 570);
    heading(page, 'How the builder or replay uses it', 836, 225, 700);
    const pairs = [
        ['native.bin', 'Restore the entry PC, stack pointer\nand saved register context'],
        ['memory.bin', 'Rebuild RAM at physical offsets,\nincluding the stack and page tables'],
        ['vma.bin', 'Locate the process memory-area tree\nand interpret mapped ranges'],
    ];
    pairs.forEach(([name, role], i) => {
        const y = 305 + 140 * i;
        const artifact = block(page, name, 64, y, 435, 98);
        const purpose = block(page, role, 817, y, 718, 98, color.native, color.teal);
        connect(page, artifact, purpose);
    });
    note(page, 'The manifest identifies the parent kernel image and user ELF. A digest binds native.bin and memory.bin to this snapshot.');
}

{
    const page = slide('Control flow inside the checkpoint',
        'After Linux maps the ELF, application and captured kernel code share one user-space process.',
        ['runtime/el0_flat/start.S', 'runtime/el0_flat/program.c', report], 'Startup restores the saved registers and branches to the linked entry. A gateway saves application context for a syscall. On return, replay restores application state. This repeats until the configured exit boundary.');
    sequence(page, ['Application', 'Replay runtime', 'Captured Linux kernel'], [
        [1, 0, 'Restore the application entry frame'],
        [0, 1, 'program_main+0x11c issues readv'],
        [1, 2, 'Enter Linux at vectors+0x400'],
        [2, 1, 'Linux returns 6 in the saved x0'],
        [1, 0, 'Resume at program_main+0x120'],
    ]);
    note(page, 'Repeat for each call. At exit, the runtime checks events and serial bytes, writes the result to RAM, then exits to the host.');
}

{
    const page = slide('Where runtime code hands control to Linux',
        'The first captured Linux instruction for this syscall is at vectors+0x400. In the checkpoint it executes at 0x51e06bd0.',
        ['build/linux-kernel-clang19-20261108/System.map', 'build/el0-ipc-merged-segments/program/checkpoint',
         'build/el0-ipc-merged-segments/profile-histogram/histogram.bin', 'runtime/el0/emulate.c',
         'runtime/el0_flat/program.c', 'runtime/el0_flat/gateway.S', calls],
        'The runtime entry is flat_capture_rest at 0x51dfcffc. flat_dispatch calls the step callback; step_syscall sets up logical exception state using the osrec_enter_syscall source helper. flat_restore branches to the selected resume thunk at 0x51e5e2e8, which branches into the translated vector slot at 0x51e06bd0. Its original Linux address is 0xffff800080010c00. The kernel path includes el0t_64_sync_handler, do_el0_svc, __arm64_sys_readv, do_readv and pipe_read. The arrows between kernel symbols summarize the path and skip intermediate calls. The histogram records one entry to __arm64_sys_readv. All execution takes place at physical EL0.');
    heading(page, 'OSREC runtime', 64, 221, 655);
    heading(page, 'Captured Linux', 849, 221, 687);
    const runtime = block(page, 'flat_capture_rest\nSave application registers', 64, 294, 590, 112);
    const dispatch = block(page, 'step_syscall / flat_restore\nSet exception state and resume', 64, 510, 590, 112);
    const vector = block(page, 'vectors+0x400  ·  0x51e06bd0\nFirst Linux instruction', 839, 510, 697, 112, color.native, color.teal);
    const handler = block(page, '__arm64_sys_readv  ·  0x53d0b788\nLinux handles fd 3 via pipe_read', 839, 294, 697, 112, color.native, color.teal);
    connect(page, runtime, dispatch, 'bottom', 'top'); connect(page, dispatch, vector);
    connect(page, vector, handler, 'top', 'bottom');
    note(page, 'Linux copies the bytes and computes the return value. OSREC restores the application context with x0 = 6.');
}
{
    const page = slide('A six-byte read through the gateway',
        'The writer queues “PIPE42” and closes. The reader then makes two calls.',
        ['examples/el0-user/ipc.c', calls], 'File descriptor 3 is the read end. The captured kernel copies the buffered payload into two user buffers. After draining the pipe, the next read returns EOF because the writer is closed.');
    heading(page, 'Pipe before readv', 64, 242, 545);
    heading(page, 'Destination buffers', 984, 242, 550);
    const pipe = block(page, 'fd 3  ·  writer closed\nP   I   P   E   4   2', 64, 401, 381, 130);
    const read = block(page, 'Captured readv\n2 destination buffers', 553, 401, 348, 130);
    const first = block(page, 'Buffer 1  ·  2 bytes\nP   I', 985, 302, 536, 103, color.native, color.teal);
    const second = block(page, 'Buffer 2  ·  4 bytes\nP   E   4   2', 985, 513, 536, 103, color.native, color.teal);
    connect(page, pipe, read); connect(page, read, first); connect(page, read, second);
    note(page, 'The call returns 6 in x0. The next read returns 0 because the pipe is empty and the writer has closed.');
}
{
    const page = slide('The six-byte read in AArch64 instructions',
        'At program_main+0x11c, w8 selects readv (65). OSREC saves the registers and hands control to captured Linux at vectors+0x400.',
        ['build/el0-user-ipc-20261119a/ipc', 'build/el0-ipc-whole-kernel-20261119a/program/program.S',
            'runtime/el0_flat/gateway.inc', 'build/el0-ipc-merged-segments/program/checkpoint', calls],
        'Disassemble the original IPC ELF with llvm-objdump -d. The ellipsis skips three instructions that clear unused syscall arguments. The generated source associates the next instruction with .Lp2012a0 and emits the original comparison word 0xf100181f. In the verified checkpoint, disassemble the return with llvm-objdump -d --start-address=0x51e01298 --stop-address=0x51e012a4 program/checkpoint. The branch at 0x51e012a0 lands on the comparison at 0x51e004d8.');
    code(page, 'Application  /  program_main', [
        '201284: 52800828  mov  w8, #0x41',
        '201288: 910003e1  mov  x1, sp',
        '20128c: 52800042  mov  w2, #2',
        '        ...',
        '20129c: d4000001  svc  #0',
        '2012a0: f100181f  cmp  x0, #6',
        '2012a4: 54000521  b.ne 0x201348',
    ], 64, 225, 730, {size: 26, lineHeight: 36});
    code(page, 'Linked checkpoint  /  return from readv', [
        '51e01298: a94847f0  ldp x16, x17, [sp, #0x80]',
        '51e0129c: 910c83ff  add sp, sp, #0x320',
        '51e012a0: 17fffc8e  b   0x51e004d8',
    ], 846, 225, 690, {size: 22, lineHeight: 39});
    code(page, 'Branch destination  /  linked program_main+0x120', [
        '51e004d8: f100181f  cmp x0, #0x6',
    ], 846, 445, 690, {size: 24});
    const runtime = block(page, 'OSREC runtime\nflat_capture_rest saves registers', 64, 609, 416, 118);
    const linux = block(page, 'Captured Linux entry\nvectors+0x400 at 0x51e06bd0', 564, 609, 471, 118, color.native, color.teal);
    const handler = block(page, 'Linux read handler\n__arm64_sys_readv', 1116, 609, 420, 118, color.native, color.teal);
    connect(page, runtime, linux); connect(page, linux, handler);
    note(page, 'Linux copies the bytes via pipe_read. OSREC resumes program_main+0x120 with x0 = 6.');
}

{
    const page = slide('Where the pipe read goes in the linked checkpoint',
        'The checkpoint maps the original syscall at 0x20129c to a gateway at 0x51e004bc. The addresses below are from the executable used in the Linux trial.',
        [report, 'build/el0-ipc-merged-segments/program/checkpoint', calls],
        'Reproduce from the trial directory: llvm-objdump -d --start-address=0x51e004bc --stop-address=0x51e004dc program/checkpoint. The flat_pcs table maps original PCs to resume thunks. Following their final branches maps 0x20129c to 0x51e004bc and 0x2012a0 to 0x51e004d8. The site descriptor is at 0x437f03f8.');
    code(page, 'Checkpoint executable  /  llvm-objdump -d', [
        '51e004bc: d10c83ff  sub  sp, sp, #0x320',
        '51e004c0: a90007e0  stp  x0, x1, [sp]',
        '51e004c4: 90f8cf80  adrp x0, 0x437f0000',
        '51e004c8: 910fe000  add  x0, x0, #0x3f8',
        '51e004cc: d503201f  nop',
        '51e004d0: 10fe5961  adr  x1, 0x51dfcffc',
        '51e004d4: d61f0020  br   x1',
        '51e004d8: f100181f  cmp  x0, #0x6',
    ], 64, 247, 790, {size: 26, lineHeight: 44});
    heading(page, 'Original PC', 884, 255, 310);
    heading(page, 'Linked PC', 1253, 255, 277);
    const svc = block(page, '0x20129c\nsvc', 884, 330, 265, 108);
    const gateway = block(page, '0x51e004bc\ngateway entry', 1230, 330, 305, 108);
    const cmp = block(page, '0x2012a0\ncmp', 884, 510, 265, 108);
    const resumed = block(page, '0x51e004d8\ncmp', 1230, 510, 305, 108);
    connect(page, svc, gateway); connect(page, cmp, resumed);
    note(page, 'br x1 enters flat_capture_rest (OSREC). The later handoff to Linux lands at vectors+0x400.');
}

{
    const page = slide('What the Linux test demonstrated',
        'The test exercised pipe data transfer, an empty pipe and a Linux event counter called eventfd.',
        [report, baseline, calls, 'examples/el0-user/ipc.c'], 'The original program also checks short reads and counter accumulation. The one expected page fault occurs on a read of constant data.');
    heading(page, 'Original application on Linux', 64, 229, 1400);
    flowRow(page, ['Run the IPC workload', 'Print OSREC_IPC_PASS', 'Exit status 0'], 311);
    heading(page, 'Checkpoint on Linux', 64, 477, 1400);
    flowRow(page, ['Run the saved workload', 'Match 16 events and\n16 serial bytes', 'Exit status 0'], 555);
    note(page, 'The expected events include 15 syscalls and one handled page fault.');
}

{
    const page = slide('What you need for the Linux trial',
        'The reference run used an AArch64 (64-bit Arm) host running Linux 6.10.14 with 4096-byte pages.',
        [report, 'build/el0-ipc-merged-segments/program/pretranslated-elf.json'], 'A checkpoint is packaged as an ELF, the executable file format used by Linux. The supplied image is aligned for the reference host.');
    const image = block(page, 'program/checkpoint', 64, 265, 450, 98);
    const reference = block(page, 'linux-validation.json', 64, 568, 450, 98);
    const match = block(page, 'Compare executable digest\nwith image_sha256', 623, 414, 420, 115);
    const host = block(page, 'Ready for trial\naarch64 · 4096-byte pages', 1120, 414, 415, 115);
    connect(page, image, match); connect(page, reference, match); connect(page, match, host);
    note(page, 'Run the commands from the trial directory containing both the executable and the validation report.');
}

{
    const page = slide('Running the Linux checkpoint',
        'Start with the same executable and host configuration as the reference run.',
        [report], 'The retained case directory in the repository is build/el0-ipc-merged-segments. The recorded kernel release was 6.10.14-linuxkit.');
    flowRow(page, ['Check host', 'Match image digest', 'Run checkpoint'], 241);
    code(page, 'Linux shell', ['uname -m', 'getconf PAGESIZE'], 64, 395, 434);
    code(page, 'Linux shell', ['sha256sum program/checkpoint'], 582, 395, 454, {size: 23});
    code(page, 'Linux shell', ['./program/checkpoint', 'echo "$?"'], 1098, 395, 437);
    text(page, 'Expected: aarch64 and 4096', 64, 577, 455, 100);
    text(page, 'Match image_sha256 in linux-validation.json.', 582, 577, 465, 100);
    text(page, 'Expected exit status: 0', 1098, 577, 437, 100);
    note(page, 'The checkpoint stores serial output in RAM. The shell reports process completion.');
}

{
    const page = slide('Testing on an Android development device',
        'Device execution is pending. Start with a 64-bit Arm device and check its page size against the Linux reference.',
        [report, 'tools/pretranslate_el0_image.py'], 'Use a connected development device with adb shell access. The reference ELF was verified on a 4096-byte page host. Record device identity, page size, executable digest and process status.');
    flowRow(page, ['Check device', 'Transfer and launch', 'Compare results'], 238);
    code(page, 'Workstation shell with adb', [
        'adb shell uname -m', 'adb shell getconf PAGE_SIZE',
        'adb push program/checkpoint /data/local/tmp/osrec',
        'adb shell chmod 700 /data/local/tmp/osrec',
        'adb shell /data/local/tmp/osrec', 'echo "$?"',
    ], 64, 412, 875, {size: 25, lineHeight: 39});
    heading(page, 'Device compatibility', 1000, 414, 535);
    text(page, 'Look for aarch64 and 4096. Other page sizes require an ELF alignment check before launch.', 1000, 480, 525, 150);
    text(page, 'Record exit status, events and serial bytes for comparison with Linux.', 1000, 652, 525, 119);
}
const presentation = deck;
await fs.mkdir(build, { recursive: true });
const candidate = path.join(build, 'candidate.pptx');
await (await PresentationFile.exportPptx(presentation)).save(candidate);

await finalizePresentation({
    workspaceDir: workspace, candidatePath: candidate, finalPath: output,
    pythonExecutable: path.join(runtime, 'python/bin/python3'),
    integrityValidatorPath: path.join(tools, 'inspect_presentation_package_integrity.py'),
    layoutValidatorPath: path.join(tools, 'inspect_presentation_layout_geometry.py'),
    explicitTotalSlideCount: added,
    layoutArgs: ['--expected-slide-size-emu', '15240000,8572500', '--validate-heading-fit'],
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
