import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {Presentation, PresentationFile} from '@oai/artifact-tool';

const root='/Users/al3x3n0/huawei/osrec';
const workspaceDir=path.join(root,'docs/slides');
const build=path.join(workspaceDir,'.build/solution-v2');
const out=path.join(workspaceDir,'output');
const skill='/Users/al3x3n0/.codex/plugins/cache/openai-primary-runtime/presentations/26.909.12148/skills/presentations';
await fs.mkdir(build,{recursive:true});
await fs.mkdir(out,{recursive:true});
const {resolvePresentationFont,finalizePresentation}=await import(pathToFileURL(path.join(skill,'container_tools/artifact_tool_utils.mjs')));
const font=resolvePresentationFont();
const p=Presentation.create({slideSize:{width:1600,height:900}});
const nativeTables=[];
const C={ink:'#142735',body:'#243447',muted:'#475569',blue:'#1D4F91',pale:'#EEF4FA',light:'#F8FAFC',white:'#FFFFFF'};

function txt(s,value,x,y,w,h,size=30,color=C.body,bold=false,typeface=font) {
 const z=s.shapes.add({geometry:'textbox',position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});
 z.text=value;z.text.style={typeface,fontSize:size,color,bold,autoFit:'none'};return z;
}
function slide(title,subtitle,sources,extra='') {
 const s=p.slides.add();s.background.fill=C.white;
 txt(s,title,64,36,1472,72,46,C.ink,true);
 if(subtitle)txt(s,subtitle,64,112,1472,58,28,C.muted);
 txt(s,'OSREC',64,850,120,28,20,C.muted);
 txt(s,String(p.slides.items.length).padStart(2,'0'),1490,850,46,28,20,C.muted);
 s.speakerNotes.textFrame.setText('Repository sources: '+sources.map(a=>path.join(root,a)).join('\n')+'\n\n'+extra);
 return s;
}
function note(s,value,y=805) {txt(s,value,64,y,1472,42,24,C.muted);}
function table(s,headers,rows,widths,opts={}) {
 const values=[headers,...rows],top=opts.top??200,height=opts.height??(values.length*82),size=opts.size??27;
 const t=s.tables.add({rows:values.length,columns:headers.length,left:64,top,width:1472,height,columnWidths:widths,values});
 t.styleOptions={headerRow:false,bandedRows:false};
 t.borders.assign({fill:'#D4DEE8',width:0.7,style:'solid'});
 t.cells.block({row:0,column:0,rowCount:values.length,columnCount:headers.length}).assign({margins:{left:17,right:17,top:8,bottom:8},anchor:'center',textStyle:{typeface:font,fontSize:size,color:C.body,autoFit:'none'}});
 for(let r=0;r<values.length;r++) {
   t.rows[r].height=height/values.length;
   for(let c=0;c<headers.length;c++) {
     const cell=t.getCell(r,c);cell.fill=r===0?C.ink:(r%2===0?C.light:C.white);
     cell.text.style={typeface:font,fontSize:size,color:r===0?C.white:(opts.blueLast&&c===headers.length-1?C.blue:C.body),bold:r===0||c===0,autoFit:'none'};
   }
 }
 nativeTables.push(p.slides.items.length);return t;
}
function section(s,title,body,x,y,w,h=155) {
 txt(s,title,x,y,w,44,33,C.ink,true);txt(s,body,x,y+55,w,h-55,28,C.body);
}
function box(s,title,body,x,y,w=300,h=190) {
 const b=s.shapes.add({geometry:'rect',position:{left:x,top:y,width:w,height:h},fill:C.pale,line:{fill:'#B8CADC',width:1}});
 txt(s,title,x+18,y+19,w-36,48,30,C.ink,true);
 txt(s,body,x+18,y+78,w-36,h-88,25,C.body);return b;
}
function connect(s,a,b) {s.shapes.connect(a,b,{kind:'straight',fromSide:'right',toSide:'left',line:{fill:C.blue,width:2},tail:{type:'arrow',width:'med',length:'med'}});}

// 01
{
 const s=slide('OSREC','Self-contained application and kernel replay',['README.md','docs/design.md']);
 txt(s,'Capture a selected execution.\nRe-execute it in an independent image.',64,258,1420,190,64,C.ink,true);
 txt(s,'Architecture, data contracts, implemented profiles\nand proposed development roadmap',64,510,1300,120,34,C.muted);
 note(s,'Current implementation: bounded functional replay in QEMU. RTL execution and timing validation remain pending.');
}
// 02
{
 const s=slide('Solution scope','A recorded scenario becomes executable code with restored state and checked behavior',['docs/design.md','docs/application-checkpoints.md']);
 section(s,'Capture', 'Observe selected syscalls on a native kernel and retain the state and external inputs required by the port.',64,215,1450,150);
 section(s,'Reconstruct', 'Package original selected code, application CPU/RAM, dependency models and portable kernel state.',64,410,1450,150);
 section(s,'Replay and verify', 'Run the image independently, recompute results and effects, and reject divergence from the declared contract.',64,605,1450,150);
}
// 03
{
 const s=slide('System architecture','Host tools construct the image. The freestanding guest executes the replay.',['docs/design.md','docs/elf-checkpoint-chains.md']);
 const a=box(s,'Native workload','Real kernel\nSelected syscalls\nRecorded observations',64,270,300,230);
 const b=box(s,'Construction','Reviewed closure\nContext and codec\nApplication routes',438,270,300,230);
 const c=box(s,'Replay image','Code and models\nEmbedded state\nValidation checks',812,270,300,230);
 const d=box(s,'Execution','EL0 application\nLocal kernel slices\nTarget-memory result',1186,270,350,230);
 connect(s,a,b);connect(s,b,c);connect(s,c,d);
 txt(s,'Construction data',64,575,700,45,32,C.ink,true);
 txt(s,'Capture files and source inputs remain on the host.',64,633,700,100,28);
 txt(s,'Runtime independence',812,575,724,45,32,C.ink,true);
 txt(s,'The guest requires no source kernel, host filesystem or semihosting.',812,633,724,100,28);
}
// 04
{
 const s=slide('The replay contract','Each port defines what the selected scenario must reproduce',['docs/design.md','docs/linux-aarch64-slices.md','docs/file-operations.md']);
 table(s,['Contract item','Embedded representation','Required check'],[
  ['Code','Selected original C and reviewed models','Pinned source and construction identity'],
  ['Initial state','Application frame/RAM and kernel context','Valid objects, layout and reference bindings'],
  ['External inputs','Recorded observations or boundary transcript','Expected call order, arguments and effects'],
  ['Completion','Expected return values and observable writes','Recomputed outputs and full required transcript'],
  ['Execution platform','Target ABI, load map and startup runtime','Independent image execution']
 ],[255,595,622],{height:530,size:27});
 note(s,'The contract bounds the claim. Output agreement alone does not prove that every dependency is represented.');
}
// 05
{
 const s=slide('Construction toolchain','Native capture feeds kernel export and application composition',['tools/run_linux_aarch64_checkpoint_pipeline.py','tools/export_syscall_slices.py','tools/import_application_checkpoint.py']);
 table(s,['Stage','Main tools','Output'],[
  ['Native capture','capture_linux_aarch64.py\nliteos_qemu_demo.py','capture.json and native provenance'],
  ['Prepare and transform','prepare_linux_aarch64_port.py\ncontextify_slice.py','Reviewed port and session-owned C state'],
  ['Export slices','slice_checkpoint_codec.py\nexport_syscall_slices.py','slices.a, proof ELF/raw and manifest'],
  ['Import application','compile_c_application.py\nimport_application_checkpoint.py','ELF, CPU/RAM payloads and route-plan.json'],
  ['Compose and verify','export_application_replay.py\nverify_syscall_slices.py','Self-contained image and QEMU evidence']
 ],[265,610,597],{height:560,size:26});
 note(s,'run_linux_aarch64_checkpoint_pipeline.py orchestrates native capture through the C application checkpoint chain.');
}
// 06
{
 const s=slide('Contextify: explicit session state','Move mutable static storage into a caller-owned context and thread it through direct calls',['tools/contextify_slice.py','docs/local-static-context-state.md','docs/initialized-context-state.md']);
 txt(s,'Original C',64,210,690,45,33,C.ink,true);
 txt(s,'static unsigned mask = 022;\n\nunsigned SetMask(unsigned next) {\n  unsigned old = mask;\n  mask = next & 0777;\n  return old;\n}',64,275,700,300,27,C.body,false,'Menlo');
 txt(s,'Transformed C',838,210,698,45,33,C.ink,true);
 txt(s,'struct Context { unsigned mask; };\n\nunsigned SetMask(struct Context *ctx,\n                 unsigned next) {\n  unsigned old = ctx->mask;\n  ctx->mask = next & 0777;\n  return old;\n}',838,275,698,330,27,C.body,false,'Menlo');
 txt(s,'Each session reconstructs its seeds once. Calls retain updates until an explicit restore.',64,645,1472,64,30,C.blue,true);
 txt(s,'CURRENT boundaries: direct calls, prepared C closure and supported declarations. TLS, volatile state and unknown ownership need adapters.',64,727,1472,92,26,C.muted);
}
// 07
{
 const s=slide('Kernel state and reference policies','Context storage and checkpoint wire encoding are separate contracts',['tools/slice_checkpoint_codec.py','docs/context-object-graphs.md','docs/context-buffer-references.md']);
 table(s,['Field policy','Checkpoint representation','Restoration'],[
  ['persist','Integer or byte-array values','Overlay saved values'],
  ['context_reference','Field-local object ID, null = 0','Bind to a declared destination object'],
  ['context_buffer_reference','Buffer ID and byte offset','Bind to an allowed array element or end'],
  ['self_reference','No pointer bytes','Rebuild a canonical owned link'],
  ['transient','No wire data','Reconstruct scratch or initial state'],
  ['members / elements','Recursive field classification','Apply leaf policies to structures/arrays']
 ],[390,510,572],{height:560,size:25});
 note(s,'Every field requires a reviewed policy. Arbitrary heap objects, physical addresses and raw pointers need additional contracts.');
}
// 08
{
 const s=slide('Application input and routing data','The ELF supplies executable bytes. Neutral metadata supplies saved state and ordered boundaries.',['docs/application-checkpoints.md','tools/import_application_checkpoint.py']);
 table(s,['Input data','Normalized route package'],[
  ['ELF entry and PT_LOAD segments','Initial memory payloads and validated executable spans'],
  ['frame: GPR, SIMD, SP, PC, FP and thread pointer','Complete loader-owned AArch64 frame'],
  ['calls[]: ordered syscall PCs','sites[]: ordinal, svc_pc and continuation_pc'],
  ['snapshots[], extra_memory[] and objects[]','RAM overlays and user-memory region identities'],
  ['exit and assertions[]','Explicit exit trap and final memory comparisons']
 ],[655,817],{height:520,size:28});
 note(s,'Declared SVCs become BRK #0x5353. Repeated PCs share one physical patch and retain multiple ordered route entries.');
}
// 09
{
 const s=slide('Returning syscall slices','The local EL1 gateway executes a selected kernel body and resumes the EL0 application',['include/osrec/aarch64_frame.h','include/osrec/syscall_slice.h','runtime/aarch64_gateway.c']);
 const a=box(s,'EL0 frame','Live registers\nExpected syscall PC\nSaved CPU state',64,250,330,220);
 const b=box(s,'Invocation','ordinal and number\nargs[6]\nUser-memory view',449,250,330,220);
 const c=box(s,'Kernel slice','Original body\nSession context\nReviewed models',834,250,330,220);
 const d=box(s,'Return','raw i64 result\nstatus and diagnostic\nUpdated context/RAM',1219,250,317,220);
 connect(s,a,b);connect(s,b,c);connect(s,c,d);
 section(s,'Linux register ABI','x8 selects the syscall. x0–x5 supply arguments. The raw result returns in x0.',64,565,720,160);
 section(s,'Continuation','Restore the application frame and resume at the original SVC PC plus four.',834,565,702,160);
 note(s,'Runtime C structures contain target pointers. They are distinct from portable checkpoint records.');
}
// 10
{
 const s=slide('Kernel checkpoint binary format','A 64-byte header binds the generated payload to its schema and execution position',['runtime/slice_checkpoint.c','include/osrec/slice_checkpoint.h','tools/slice_checkpoint_codec.py']);
 table(s,['Byte offsets','Encoding','Meaning'],[
  ['0–7','u64 magic','0x31504b434552534f, bytes OSRECKP1'],
  ['8–15','u32 version and u32 total bytes','Version 1 and complete record size'],
  ['16–47','32 raw bytes','Schema SHA-256 identity'],
  ['48–55','u64','Next absolute syscall ordinal'],
  ['56–63','u64 FNV-1a checksum','Record checksum excluding its own field'],
  ['64 onward','Schema-defined payload','Packed scalar values and logical references']
 ],[260,510,702],{height:540,size:27});
 note(s,'Little-endian target encoding. A rejected load leaves the destination state and session unchanged.');
}
// 11
{
 const s=slide('Joint checkpoints and fresh-image resume','Save application CPU/RAM together with the portable kernel record at a supported boundary',['docs/elf-checkpoint-chains.md','tools/application_pause.py','tools/application_checkpoint_chain.py']);
 const a=box(s,'Pause before next call','Live CPU frame\nApplication RAM\nKernel next ordinal',64,235,410,230);
 const b=box(s,'Export joint package','kernel.bin\ncheckpoint.json\napplication/ and manifest',595,235,410,230);
 const c=box(s,'Restore fresh image','Reconstruct seeds\nOverlay saved values\nRebind references',1126,235,410,230);
 connect(s,a,b);connect(s,b,c);
 txt(s,'Checkpoint identity',64,545,650,45,32,C.ink,true);
 txt(s,'Schema and archive hashes bind the kernel. Application hashes bind routes and memory. Generation and parent identity bind the chain.',64,605,670,145,28);
 txt(s,'Example Linux minimal chain',834,545,702,45,32,C.ink,true);
 txt(s,'0, 8, 15, 19, 20 completed calls\nEach resumed interval starts from its saved ordinal.\nThe final suffix checks completion.',834,605,702,145,28);
 note(s,'QMP observes stopped memory externally. The replay guest itself uses no host services.');
}
// 12
{
 const s=slide('Implemented kernel profiles','Current coverage is explicit and bounded by each reviewed port',['docs/linux-aarch64-slices.md','docs/file-operations.md'], 'Counts below come from documented profiles, not a new benchmark run. Linux upstream v6.10 bodies are behaviorally checked against LinuxKit 6.10.14-linuxkit. Exact native-source rebuild attestation is false. LiteOS native capture runs ARMv7 and selected C bodies are recompiled for AArch64.');
 table(s,['Profile','Native scenario','Portable replay state'],[
  ['Linux minimal','20 calls across 10 syscalls\nIdentity queries, umask and output faults','136-byte context\n112-byte kernel checkpoint record'],
  ['Linux credentials','42 calls including setresgid\nCredential changes, denial and group queries','216-byte context\n184-byte kernel checkpoint record'],
  ['LiteOS file lifecycle','32 calls across 9 syscall bodies\nCreate, write, alias, seek, read, stat and close','Shared descriptor/file models\n94 recorded dependency events']
 ],[300,620,552],{height:475,size:29});
 txt(s,'Native source identity caveat',64,720,1472,45,29,C.ink,true);
 txt(s,'Linux uses reviewed upstream bodies checked against LinuxKit. Exact native source-build attestation remains false. LiteOS capture is ARMv7 with selected C recompiled for AArch64.',64,770,1472,70,25,C.muted);
}
// 13
{
 const s=slide('Validation and retained evidence','A published package carries both executable inputs and checks of the declared behavior',['docs/elf-checkpoint-chains.md','tools/verify_syscall_slices.py','tools/run_linux_aarch64_checkpoint_pipeline.py']);
 table(s,['Layer','What it checks','Retained evidence'],[
  ['Capture review','Native results, buffer writes and state transitions','Capture and provenance manifests'],
  ['Construction','Source identities, policy coverage and image audits','Pinned inputs and generated manifests'],
  ['Target execution','Kernel completion and application assertions','128-byte target result block'],
  ['Four-mode matrix','ELF/raw loading and EL1/EL3 entry','verification-matrix.json'],
  ['Offline verification','Artifact hashes, routes and checkpoint lineage','workflow.json and stage packages']
 ],[270,650,552],{height:540,size:27});
 note(s,'These are functional checks under the port contract. RTL timing and general dependency completeness remain separate claims.');
}
// 14
{
 const s=slide('Analysis tools and proof boundaries','Analysis supports construction and observation reduction within declared models',['docs/entry-state-analysis.md','docs/el0-analysis.md','docs/trace-analysis.md','compiler/Planner.cpp']);
 table(s,['Tool','Implemented purpose','CURRENT boundary'],[
  ['Configured Clang AST','Discover field accesses and pointer edges\nFollow supported call closures','Explicit ownership and boundary policies\nConservative state footprint'],
  ['LLVM planner / EL0 analysis','Report dependencies and effects\nPropose slice/load-omission candidates','Candidates need separate validation\nAutomatic instrumentation remains future work'],
  ['KLEE trace analysis','Check trace sufficiency and reconstruction\nfor bounded SysRead','Bounded code and dependency models\nIncomplete exploration certifies no omission']
 ],[335,555,582],{height:460,size:26});
 txt(s,'Proof rule',64,720,1472,45,32,C.ink,true);
 txt(s,'Equal retained observations must imply equal declared outputs and effects. A separate reconstruction check reruns the code using those observations.',64,774,1472,64,27,C.blue);
}
// 15
{
 const s=slide('CURRENT limitations','Each current boundary has a proposed development direction',['docs/design.md','docs/application-checkpoints.md','tools/contextify_slice.py','docs/context-object-graphs.md'], 'Future solutions are proposals, not implemented capabilities or delivery commitments.');
 table(s,['Area','CURRENT limitation','Future solution (proposed)'],[
  ['Kernel coverage','Reviewed syscall roots only','Expand ports with dependency analysis'],
  ['State coverage','Explicit kernel-state projection','Extend discovery and synchronized capture'],
  ['Model fidelity','Reviewed dependency models','Expand original code and native comparison'],
  ['Object ownership','Declared objects and buffers only','Track lifetimes and relocate object graphs'],
  ['Concurrency','Sequential replay without general IRQ/SMP','Record scheduling and memory observations'],
  ['Application loading','Bounded static AArch64 images','Add relocation and address-space support'],
  ['Pause granularity','Supported syscall boundaries only','Add safe points and stack restoration'],
  ['Build compatibility','Exact construction identity required','Prove explicit schema migration compatibility'],
  ['Validation scope','QEMU functional checks only','Add RTL and cycle-level validation']
 ],[275,510,687],{top:185,height:610,size:24,blueLast:true});
 note(s,'Future solutions are development proposals. Each extension requires a defined replay contract and validation.',810);
}
// 16
{
 const s=slide('Proposed development roadmap','Sequence extensions by their dependency on reliable state and replay contracts',['docs/design.md','docs/entry-state-analysis.md'], 'This roadmap is a proposed prioritization. It adds no dates, effort estimates or measured performance targets. Explicit build identity remains the default even if migration is later introduced.');
 table(s,['Phase','Proposed work','Acceptance gate'],[
  ['1. Coverage and fidelity','Add reviewed roots and expand native comparison','Every added root has a state/effect contract'],
  ['2. State and loading','Extend lifetime tracking, relocation and safe points','Fresh-image restore preserves declared effects'],
  ['3. Async behavior','Capture blocking, IRQ effects and shared observations','Reproduce one bounded asynchronous scenario'],
  ['4. Delivery validation','Add RTL execution and qualified migration paths','Pass target checks and explicit compatibility tests']
 ],[340,615,517],{height:535,size:27,blueLast:true});
 note(s,'Near-term priority: broaden proven coverage and state fidelity before general concurrency or timing claims.');
}
// 17
{
 const s=slide('Acceptance criteria for extensions','Proposed gates preserve explicit scope as capabilities expand',['docs/design.md','docs/trace-analysis.md','docs/elf-checkpoint-chains.md']);
 table(s,['Gate','Evidence required'],[
  ['Native behavior','Match returns and declared state/memory effects against independent native observations'],
  ['Restoration','Resume at a different context address with correct aliases and object generations'],
  ['Failure handling','Reject incomplete captures, unsupported pointers and changed identities'],
  ['Execution independence','Run the delivery image without source checkout, capture files or host services'],
  ['Cost and timing','Measure capture overhead separately and validate any claimed target timing']
 ],[345,1127],{height:540,size:29});
 note(s,'There is no numeric performance promise yet. Define budgets after measuring the supported workload.');
}
// 18
{
 const s=slide('Operational handoff','Use the current pipeline to produce a complete, reviewable replay package',['docs/linux-aarch64-slices.md','docs/elf-checkpoint-chains.md','tools/run_application_checkpoint_chain.py']);
 txt(s,'Native Linux capture and full pipeline',64,205,1472,45,33,C.ink,true);
 txt(s,'python3 tools/run_linux_aarch64_checkpoint_pipeline.py \\\n  --kernel-image /path/to/arm64/Image --out build/my-pipeline',64,265,1472,105,27,C.body,false,'Menlo');
 txt(s,'Offline verification',64,420,1472,45,33,C.ink,true);
 txt(s,'python3 tools/run_linux_aarch64_checkpoint_pipeline.py \\\n  --verify build/my-pipeline',64,480,1472,105,27,C.body,false,'Menlo');
 txt(s,'Customer ELF or saved checkpoint',64,635,1472,45,33,C.ink,true);
 txt(s,'run_application_checkpoint_chain.py accepts --elf with --checkpoint,\nor --resume-checkpoint with matching --slices.',64,695,1472,80,29);
 note(s,'Handoff contains native evidence, pinned port inputs, replay images, joint checkpoints and verification reports.');
}

const candidatePath=path.join(build,'candidate.pptx');
await (await PresentationFile.exportPptx(p)).save(candidatePath);
console.log('Exported 18-slide draft');
await finalizePresentation({workspaceDir,candidatePath,finalPath:path.join(out,'osrec-solution-v2.pptx'),
 pythonExecutable:'/Users/al3x3n0/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3',
 integrityValidatorPath:path.join(skill,'container_tools/inspect_presentation_package_integrity.py'),
 layoutValidatorPath:path.join(skill,'container_tools/inspect_presentation_layout_geometry.py'),
 explicitTotalSlideCount:18,requiredNativeTableOwnerSlides:nativeTables,
 layoutArgs:['--expected-slide-size-emu','15240000,8572500','--validate-bullet-geometry','--validate-heading-fit',...nativeTables.flatMap(n=>['--require-native-table-slide',String(n)])],
 fontPolicy:{basis:'design',families:[font,'Menlo']},verifyArtifactToolImport:false,
 receiptPath:path.join(build,'validation.json')});
for(let i=0;i<p.slides.items.length;i++) {
 const preview=await p.export({slide:p.slides.items[i],format:'png',scale:1});
 await fs.writeFile(path.join(build,`slide-${String(i+1).padStart(2,'0')}.png`),new Uint8Array(await preview.arrayBuffer()));
 console.log('Rendered slide',i+1);
}
console.log('Saved',path.join(out,'osrec-solution-v2.pptx'));
