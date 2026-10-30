import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {Presentation, PresentationFile} from '@oai/artifact-tool';

const root='/Users/al3x3n0/huawei/osrec';
const workspaceDir=path.join(root,'docs/slides');
const build=path.join(workspaceDir,'.build/concise-v2');
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

function arrow(s,a,b,from='right',to='left',kind='straight') {
 s.shapes.connect(a,b,{kind,fromSide:from,toSide:to,line:{fill:C.blue,width:2},tail:{type:'arrow',width:'med',length:'med'}});
}

// 01: solution in one diagram, without a separate cover.
{
 const s=slide('OSREC solution','Capture selected application and kernel behavior, then replay it independently',['README.md','docs/design.md']);
 const a=box(s,'Native execution','Application syscalls\nReal kernel\nCaptured state and inputs',64,285,400,235);
 const b=box(s,'Replay package','Selected original code\nState and dependency models\nRuntime and checks',600,285,400,235);
 const c=box(s,'Standalone execution','EL0 application\nLocal kernel slices\nChecked results and effects',1136,285,400,235);
 connect(s,a,b);connect(s,b,c);
 txt(s,'The image embeds everything required by its declared scenario contract.',64,640,1472,60,36,C.ink,true);
 note(s,'CURRENT scope: bounded functional replay in QEMU. RTL execution and timing validation remain pending.');
}


// Main diagram: native inputs, image construction and fresh-image continuation.
{
 const s=slide('Main diagram: capture, build and replay','Original code, captured state and application checkpoints form one executable scenario',['docs/design.md','docs/application-checkpoints.md','docs/elf-checkpoint-chains.md'], 'Capture and source extraction are construction stages. Kernel dependencies outside the selected closure require reviewed models. The user ELF/checkpoint provides application code, CPU frame and memory overlays. Fresh-image continuation uses a matching joint kernel/application checkpoint. Runtime execution is sequential with local routing, no host services and explicit functional checks. The pause/checkpoint loop applies only at supported declared boundaries.');
 const a=box(s,'Record native behavior','Selected syscalls\nEntry state and external inputs',64,245,330,210);
 const b=box(s,'Prepare kernel replay','Keep selected original code\nOwn and encode session state',449,245,330,210);
 const c=box(s,'Build replay image','Embed code, models and state\nBind identities and checks',834,245,330,210);
 const d=box(s,'Execute and verify','Restore application and kernel\nRecompute results and effects',1219,245,317,210);
 connect(s,a,b);connect(s,b,c);connect(s,c,d);
 const e=box(s,'Application checkpoint','Executable code\nSaved CPU frame and RAM',64,595,330,170);
 const f=box(s,'Prepare application','Validate memory mappings\nRoute declared syscall sites',449,595,330,170);
 const g=box(s,'Save joint state','Supported pause boundary\nCPU/RAM and kernel record',1219,595,317,170);
 connect(s,e,f);arrow(s,f,c,'right','bottom','elbow');arrow(s,d,g,'bottom','top');arrow(s,g,c,'left','right','elbow');
 txt(s,'Resume in a fresh image',874,527,325,55,26,C.blue,true);
 note(s,'The guest uses embedded code and data. Host tools capture, construct and inspect the scenario.');
}

// 02: two input branches join at image composition.
{
 const s=slide('Construction flow','Kernel capture and application state meet in one self-contained image',['tools/export_syscall_slices.py','tools/import_application_checkpoint.py','tools/export_application_replay.py','tools/verify_syscall_slices.py']);
 const a=box(s,'Kernel capture','Original C and observations\nReviewed dependency policy',64,235,400,175);
 const b=box(s,'Make state portable','Own state per session\nEncode fields and references',600,235,400,175);
 const c=box(s,'Callable kernel code','Returning syscall bodies\nInitial state and identity',1136,235,400,175);
 connect(s,a,b);connect(s,b,c);
 const d=box(s,'Application input','Static AArch64 ELF\nCPU/RAM checkpoint',64,525,400,175);
 const e=box(s,'Application import','Validate memory and routes\nPatch declared SVC sites',600,525,400,175);
 const f=box(s,'Replay image','Compose ELF/raw image\nVerify against expected results',1136,525,400,175);
 connect(s,d,e);connect(s,e,f);arrow(s,c,f,'bottom','top');
 note(s,'Extract callable kernel code, restore application state, then link and verify the complete replay image.');
}

// 03: show state ownership instead of a full code listing.
{
 const s=slide('Independent session state','Mutable globals and supported local statics become explicit context fields',['tools/contextify_slice.py','docs/initialized-context-state.md','docs/context-object-graphs.md'], 'Contextify adds a context parameter to stateful functions and their direct callers. Original initializers reconstruct once per session or explicit reset. Unknown dependency ownership, indirect calls, mutable TLS and volatile state need adapters. Contextify does not prove whole-kernel state completeness.');
 const a=box(s,'Original shared state','static unsigned mask;\n\nSetMask(next)',64,335,380,245);
 const b=box(s,'Move state into contexts','mask becomes ctx->mask\nCallers pass ctx\nRestore original seeds',584,335,410,245);
 const c=box(s,'Session A','ctx_A.mask\nUpdates persist between calls',1134,235,402,190);
 const d=box(s,'Session B','ctx_B.mask\nUpdates persist between calls',1134,490,402,190);
 connect(s,a,b);arrow(s,b,c,'right','left','elbow');arrow(s,b,d,'right','left','elbow');
 note(s,'Separate contexts own separate mutable state. Portable checkpoint policies handle pointer rebinding.');
}

// 04: the execution cycle, including the application continuation.
{
 const s=slide('Syscall replay cycle','The application drives execution. The local gateway returns computed results.',['include/osrec/aarch64_frame.h','include/osrec/syscall_slice.h','runtime/aarch64_gateway.c'], 'Linux uses x8 for syscall number, x0–x5 for arguments and x0 for the raw result. The port declares the register ABI. The slice invocation carries ordinal, number, args[6] and a user-memory view. Results and modeled side effects must match the reviewed port contract. The current guest is sequential with MMU off and masked interrupts.');
 const a=box(s,'Application at EL0','Prepare arguments\nExecute patched syscall site',64,275,330,220);
 const b=box(s,'Local gateway','Save CPU frame\nValidate PC and ordinal',449,275,330,220);
 const c=box(s,'Kernel slice','Original syscall body\nContext and reviewed models',834,275,330,220);
 const d=box(s,'Return','Raw result and RAM effects\nResume at SVC PC + 4',1219,275,317,220);
 connect(s,a,b);connect(s,b,c);connect(s,c,d);
 const cont=box(s,'Next application instructions','Kernel context and application RAM retain preceding updates',420,645,760,145);
 arrow(s,d,cont,'bottom','right','elbow');arrow(s,cont,a,'left','bottom','elbow');
 note(s,'Linux ABI: x8 selects the syscall, x0–x5 supply arguments, and x0 receives the result.',812);
}

// 05: joint save/restore, with distinct application and kernel formats.
{
 const s=slide('Checkpoint and resume','Pause at a supported boundary and continue in a fresh image',['tools/application_pause.py','runtime/slice_checkpoint.c','docs/elf-checkpoint-chains.md'], 'Application state comprises the loader-owned CPU frame and mapped user-memory bytes. The kernel record is a 64-byte little-endian header plus a schema-defined payload. Header fields include magic/version, record size, schema hash, next ordinal and checksum. References use declared IDs and offsets. Joint manifests pin the code/archive, application routes, checkpoint generation and parent identity.');
 const a=box(s,'Paused state','Application CPU and RAM\nKernel context\nNext syscall ordinal',64,275,400,230);
 const b=box(s,'Joint checkpoint','Application code and saved RAM\nSaved CPU and kernel state\nIdentity and sequence metadata',600,275,400,230);
 const c=box(s,'Fresh image','Restore CPU and RAM\nOverlay kernel values\nRebind owned pointers',1136,275,400,230);
 connect(s,a,b);connect(s,b,c);
 txt(s,'Portable kernel record',64,590,680,48,33,C.ink,true);
 txt(s,'64-byte header and schema-defined values\nLogical reference IDs and byte offsets',64,650,680,100,30);
 txt(s,'Continuation contract',856,590,680,48,33,C.ink,true);
 txt(s,'Matching code and schema identity\nExecute only the remaining interval',856,650,680,100,30);
 note(s,'Host QMP reads stopped memory. The guest replay requires no host services.');
}

// 06: supported profiles above the functional proof chain.
{
 const s=slide('Current support and verification','Independent native observations anchor the replay checks',['docs/linux-aarch64-slices.md','docs/file-operations.md','tools/verify_syscall_slices.py'], 'Documented Linux minimal profile: 20 calls across 10 syscalls. Credentials profile: 42 calls including setresgid. LiteOS file workflow: 32 calls across 9 syscall bodies with 94 dependency events. Linux native source-build attestation remains false. LiteOS capture runs ARMv7 with selected original C recompiled for AArch64. Current guest execution is functional, not a timing proof.');
 section(s,'Linux minimal','20 calls\nIdentity, umask and output faults',64,205,450,170);
 section(s,'Linux credentials','42 calls\nCredential changes and group queries',575,205,450,170);
 section(s,'LiteOS files','32 calls\nShared file/descriptor lifecycle',1086,205,450,170);
 const a=box(s,'Native evidence','Returns and observable effects',64,485,400,190);
 const b=box(s,'Four-mode verification','ELF/raw loading\nEL1/EL3 entry',600,485,400,190);
 const c=box(s,'Verified package','Result bytes and assertions\nHashes and checkpoint lineage',1136,485,400,190);
 connect(s,a,b);connect(s,b,c);
 note(s,'These checks validate the declared functional contract. They do not establish RTL timing equivalence.');
}

// 07: group the nine limitations into five readable development themes.
{
 const s=slide('CURRENT limitations and future solutions','Proposed extensions retain explicit replay contracts',['docs/design.md','docs/application-checkpoints.md','docs/context-object-graphs.md','docs/trace-analysis.md'], 'Grouped CURRENT limitations: (1) selected kernel roots and reviewed dependency models, (2) projected state and bounded object ownership, (3) static application loading, syscall-only pause boundaries and exact build identity, (4) sequential execution without general IRQ/SMP reproduction, (5) functional QEMU validation without RTL timing evidence. Future directions are proposals, not implemented capabilities or delivery commitments. Extend supported coverage and native model comparison, state/lifetime discovery, relocation and safe points, proven schema migration, causal asynchronous observations and RTL execution with a separate timing contract.');
 txt(s,'CURRENT limitations',64,205,655,55,33,C.ink,true);
 txt(s,'Future solutions (proposed)',844,205,692,55,33,C.blue,true);
 const pairs=[
  ['Selected roots and reviewed models','Expand verified roots and native comparison'],
  ['Projected state and bounded objects','Extend discovery and lifetime tracking'],
  ['Static ELF, syscall pauses, exact build','Add loading, safe points and proven migration'],
  ['Sequential replay without general IRQ/SMP','Capture causal task, IRQ and memory effects'],
  ['Functional QEMU validation','Validate RTL execution and timing contracts']
 ];
 for(let i=0;i<pairs.length;i++) {
  const y=300+i*92;
  const a=txt(s,pairs[i][0],64,y,655,66,30,C.body);
  const b=txt(s,pairs[i][1],844,y,692,66,30,C.blue);
  arrow(s,a,b);
 }
 note(s,'Future capabilities remain proposals. Exact build identity stays the default until compatibility is proven.');
}

// 08: priorities and gates, without dates or unmeasured performance promises.
{
 const s=slide('Proposed roadmap','Expand proven coverage before general concurrency and timing claims',['docs/design.md','docs/entry-state-analysis.md'], 'Proposed sequence, not dates or committed estimates. Expand reviewed coverage and differential validation first. Then broaden object lifetimes, relocatable loading and safe points. Reproduce one bounded asynchronous scenario before general IRQ/SMP behavior. Add RTL loading/execution and independently define timing expectations. Quantify capture overhead on supported workloads before setting numerical budgets.');
 const a=box(s,'1. Coverage','Add reviewed roots\nValidate model effects',64,280,330,220);
 const b=box(s,'2. State','Track object lifetimes\nBroaden loading and restore',449,280,330,220);
 const c=box(s,'3. Async replay','Capture causal observations\nInclude task/IRQ effects',834,280,330,220);
 const d=box(s,'4. RTL validation','Run the target image\nDefine timing checks',1219,280,317,220);
 connect(s,a,b);connect(s,b,c);connect(s,c,d);
 const xs=[64,449,834,1219],ws=[330,330,330,317];
 const gates=['Native results match','Fresh-image state matches','Bounded async case matches','Target contract passes'];
 for(let i=0;i<4;i++) {
  txt(s,'Acceptance gate',xs[i],575,ws[i],45,27,C.ink,true);
  txt(s,gates[i],xs[i],633,ws[i],95,30,C.blue);
 }
 note(s,'Measure capture cost separately from replay performance. No dates or numeric performance targets are assumed.');
}

const candidatePath=path.join(build,'candidate.pptx');
await (await PresentationFile.exportPptx(p)).save(candidatePath);
console.log('Exported concise 9-slide draft');
await finalizePresentation({workspaceDir,candidatePath,finalPath:path.join(out,'osrec-solution-concise-v2.pptx'),
 pythonExecutable:'/Users/al3x3n0/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3',
 integrityValidatorPath:path.join(skill,'container_tools/inspect_presentation_package_integrity.py'),
 layoutValidatorPath:path.join(skill,'container_tools/inspect_presentation_layout_geometry.py'),
 explicitTotalSlideCount:9,requiredNativeTableOwnerSlides:[],
 layoutArgs:['--expected-slide-size-emu','15240000,8572500','--validate-bullet-geometry','--validate-heading-fit'],
 fontPolicy:{basis:'design',families:[font]},verifyArtifactToolImport:false,
 receiptPath:path.join(build,'validation.json')});
for(let i=0;i<p.slides.items.length;i++) {
 const preview=await p.export({slide:p.slides.items[i],format:'png',scale:1});
 await fs.writeFile(path.join(build,`slide-${String(i+1).padStart(2,'0')}.png`),new Uint8Array(await preview.arrayBuffer()));
 console.log('Rendered slide',i+1);
}

