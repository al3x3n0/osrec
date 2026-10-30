import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {Presentation,PresentationFile} from '@oai/artifact-tool';
const root='/Users/al3x3n0/huawei/osrec',workspaceDir=path.join(root,'docs/slides');
const build=path.join(workspaceDir,'.build/explained-stages');
const skill='/Users/al3x3n0/.codex/plugins/cache/openai-primary-runtime/presentations/26.909.12148/skills/presentations';
await fs.mkdir(build,{recursive:true});
const {resolvePresentationFont,finalizePresentation}=await import(pathToFileURL(path.join(skill,'container_tools/artifact_tool_utils.mjs')));
const font=resolvePresentationFont();
const p=Presentation.create({slideSize:{width:1600,height:900}});
const ink='#142735',body='#334155',muted='#64748B';
const colors=['#2563EB','#7C3AED','#15803D','#B45309'];
const pales=['#EFF6FF','#F5F3FF','#F0FDF4','#FFFBEB'];
function txt(s,value,x,y,w,h,size=28,color=body,bold=false){
 const z=s.shapes.add({geometry:'textbox',position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});
 z.text=value;z.text.style={typeface:font,fontSize:size,color,bold,autoFit:'none'};return z;
}
function rect(s,x,y,w,h,fill,line='none',width=0){return s.shapes.add({geometry:'rect',position:{left:x,top:y,width:w,height:h},fill,line:{fill:line,width}});}
function slide(title,subtitle,stage,sources,notes=''){
 const s=p.slides.add();s.background.fill='#FFFFFF';
 const color=stage?colors[stage-1]:ink;
 txt(s,title,64,40,1440,72,46,color,true);
 txt(s,subtitle,64,124,1472,72,28,body);
 rect(s,64,211,1472,3,stage?color:'#CBD5E1');
 txt(s,'OSREC',64,852,150,28,20,muted);txt(s,String(p.slides.items.length).padStart(2,'0'),1490,852,46,28,20,muted);
 s.speakerNotes.textFrame.setText(sources.map(v=>path.join(root,v)).join('\n')+'\n\n'+notes);
 return s;
}
function node(s,title,content,x,y,w,h,stage,size=25){
 const n=rect(s,x,y,w,h,pales[stage-1],colors[stage-1],1.4);
 txt(s,title,x+20,y+18,w-40,58,30,ink,true);
 txt(s,content,x+20,y+82,w-40,h-94,size,body);return n;
}
function link(s,a,b,from='right',to='left',stage=1,kind='straight'){
 s.shapes.connect(a,b,{kind,fromSide:from,toSide:to,line:{fill:colors[stage-1],width:2.3},tail:{type:'arrow',width:'med',length:'med'}});
}
function foot(s,value){txt(s,value,64,788,1472,50,25,body);}
function explain(s,label,value,y,stage){txt(s,label,64,y,410,40,29,colors[stage-1],true);txt(s,value,64,y+52,410,125,29,body);}

// 1. A deliberately simplified architecture map, with one handoff per stage.
{
 const s=slide('OSREC: four-stage replay flow','A bounded scenario becomes a self-contained image with explicit application and kernel state.',null,['docs/current-flow.dot','docs/design.md']);
 const titles=['1  Capture and slices','2  Import and compose','3  Execute replay','4  Checkpoint and verify'];
 const texts=['Observe native syscalls\nSelect kernel C\nMake state portable','Import application ELF\nEmbed code and state\nLink the replay image','Run application at EL0\nRoute traps to local slices\nReturn computed results','Verify each image\nExport joint state\nResume a fresh image'];
 const nodes=titles.map((title,i)=>node(s,title,texts[i],64+i*383,305,323,252,i+1));
 for(let i=0;i<3;i++)link(s,nodes[i],nodes[i+1],'right','left',i+1);
 const handoffs=['Kernel library + codec','Combined ELF / raw image','CPU / RAM + kernel state'];
 handoffs.forEach((v,i)=>txt(s,v,70+i*383,605,355,78,25,colors[i],true));
 txt(s,'Shared stage engine',64,716,345,42,29,ink,true);
 txt(s,'Host workflow that builds, verifies, saves and advances each interval.',425,716,1111,65,29,body);
 foot(s,'CURRENT scope: selected syscall behavior and functional QEMU validation.');
}

// 2. Capture evidence and source transformation are separate inputs to a kernel library.
{
 const s=slide('Stage 1: native capture and kernel slices','Turn selected kernel behavior into callable code with explicit session state.',1,['tools/export_syscall_slices.py','docs/linux-aarch64-slices.md','docs/file-operations.md']);
 explain(s,'Input','Native observations, selected kernel C and reviewed dependency models.',270,1);
 explain(s,'Output','Kernel slice library, portable state codec and a verified proof image.',507,1);
 const a=node(s,'Capture native calls','QEMU executes the real kernel\nRecord returns and RAM effects',570,270,430,178,1);
 const b=node(s,'Prepare reviewed closure','Selected syscall/helper C\nDependency models and policy',1100,270,430,178,1);
 const c=node(s,'Own and encode state','Clang AST and target layout\nGenerate context and codecs',570,535,430,185,1);
 const d=node(s,'Build and prove slices','Clang / LLVM / LLD build\nQEMU checks ELF and raw runs',1100,535,430,185,1);
 link(s,a,b,'right','left',1);link(s,b,c,'bottom','top',1,'elbow');link(s,c,d,'right','left',1);
 txt(s,'slices.a + codec + proof evidence',1040,741,490,36,24,colors[0],true);
 foot(s,'LiteOS-A is a testing fixture for kernel-port validation. Linux provides a separate capture path.');
}

// 3. Contextify is illustrated with source and state, rather than screenshots of the main graph.
{
 const s=slide('Contextify: state belongs to a session','Clang identifies declarations and references. OSREC rewrites supported mutable state.',1,['tools/contextify_slice.py','docs/initialized-context-state.md','docs/context-object-graphs.md'],'The code is illustrative. Mutable globals and supported local statics move into context fields. Direct callers pass the context. This does not prove whole-kernel state completeness. Indirect calls, TLS, volatile state and unknown dependency ownership need reviewed handling.');
 const a=node(s,'Original kernel C','static unsigned mask;\n\nSetMask(next);',64,331,370,240,1,29);
 const b=node(s,'Transformed kernel C','ctx->mask\n\nSetMask(ctx, next);',584,331,415,240,1,29);
 const c=node(s,'Session A context','mask and owned references\nUpdates stay with session A',1139,265,397,170,1);
 const d=node(s,'Session B context','mask and owned references\nUpdates stay with session B',1139,500,397,170,1);
 link(s,a,b,'right','left',1);link(s,b,c,'right','left',1,'elbow');link(s,b,d,'right','left',1,'elbow');
 txt(s,'Illustrative transformation',64,618,850,40,25,muted);
 txt(s,'Checkpoint restore',64,712,355,42,30,ink,true);
 txt(s,'Restore seed values, overlay saved fields, then rebind declared references.',440,712,1096,65,29);
 foot(s,'CURRENT limitation: reviewed state ownership and supported C constructs define the transformation boundary.');
}

// 4. Main application path plus the two construction inputs.
{
 const s=slide('Stage 2: application import and composition','Combine application code and state with the kernel slice library and replay runtime.',2,['tools/compile_c_application.py','tools/import_application_checkpoint.py','tools/export_application_replay.py']);
 const fixture=node(s,'C frontend: testing','TESTING PURPOSES\nClang / LLD build fixtures',64,259,410,168,2);
 const kernel=node(s,'Kernel inputs','slices.a and codec\nLoader / gateway / runtime C',1126,259,410,168,2);
 const app=node(s,'Application ELF + state','Static AArch64 user program\nCPU frame and RAM overlays',64,524,410,191,2);
 const importer=node(s,'Validate and import','Audit ELF and syscall routes\nPatch declared SVCs to BRKs',595,524,410,191,2);
 const image=node(s,'Compose replay image','App payload + kernel slices\nLink replay ELF and raw image',1126,524,410,191,2);
 link(s,fixture,app,'bottom','top',2);link(s,kernel,image,'bottom','top',2);link(s,app,importer,'right','left',2);link(s,importer,image,'right','left',2);
 txt(s,'Or supply application ELF\nwith saved user state',315,458,400,60,24,colors[1],true);
 foot(s,'Output: one combined replay ELF/raw image. Application ELF remains distinct from kernel proof ELF.');
}

// 5. Execution is a cycle, with an explicit user/kernel boundary.
{
 const s=slide('Stage 3: freestanding syscall replay','The application drives execution. Local kernel slices compute results and update state.',3,['runtime/aarch64_gateway.c','include/osrec/aarch64_frame.h','include/osrec/syscall_slice.h'],'Linux ABI uses x8 as syscall number, x0–x5 for arguments and x0 for the result. The port defines the ABI. Declared SVCs are patched to BRKs. The gateway validates the expected route and ordinal, invokes selected original syscall bodies with reviewed models and resumes at original SVC PC + 4.');
 const titles=['Application at EL0','Gateway at EL1','Kernel slice','Return to app'];
 const content=['Prepare arguments\nExecute patched BRK site','Save CPU frame\nCheck route and ordinal','Original syscall C\nContext + reviewed models','Raw result in x0\nRestore frame and RAM'];
 const nodes=titles.map((t,i)=>node(s,t,content[i],64+i*383,325,323,220,3));
 for(let i=0;i<3;i++)link(s,nodes[i],nodes[i+1],'right','left',3);
 const carry=node(s,'Continue from original SVC PC + 4','Application RAM and kernel state retain updates.',465,660,700,155,3,25);
 link(s,nodes[3],carry,'bottom','right',3,'elbow');link(s,carry,nodes[0],'left','bottom',3,'elbow');
 txt(s,'Linux ABI: x8 = syscall number, x0–x5 = arguments',64,257,1300,50,27,colors[2],true);
}

// 6. Verification occurs before exporting each intermediate checkpoint.
{
 const s=slide('Stage 4: verified checkpoint continuation','Verify each interval, export application and kernel state, then compose a fresh image.',4,['tools/application_checkpoint_chain.py','tools/application_pause.py','docs/elf-checkpoint-chains.md','runtime/slice_checkpoint.c']);
 const titles=['Compose interval','Verify image','Pause and export','Joint checkpoint'];
 const content=['Embed input state\nSet next pause ordinal','QEMU ELF / raw\nTest EL1 / EL3 starts','Pause at next boundary\nQMP reads guest memory','Application CPU and RAM\nPortable kernel record'];
 const nodes=titles.map((t,i)=>node(s,t,content[i],64+i*383,279,323,207,4));
 for(let i=0;i<3;i++)link(s,nodes[i],nodes[i+1],'right','left',4);
 const restore=node(s,'Fresh image: restore and resume','Restore saved values and rebind references.\nContinue the remaining interval.',470,585,730,155,4,25);
 link(s,nodes[3],restore,'bottom','right',4,'elbow');link(s,restore,nodes[0],'left','bottom',4,'elbow');
 txt(s,'Application state',64,744,380,40,28,ink,true);txt(s,'ELF identity, CPU frame and RAM bytes',64,792,700,44,25);
 txt(s,'Kernel state',846,744,380,40,28,ink,true);txt(s,'Schema-defined values, reference IDs and offsets',846,792,690,44,25);
}

// 7. Scope boundaries are paired with explicit future proposals.
{
 const s=slide('CURRENT limitations and future solutions','Future capabilities are proposals. Each extension needs a declared contract and validation.',null,['docs/design.md','docs/context-object-graphs.md','docs/application-checkpoints.md','docs/entry-state-analysis.md']);
 txt(s,'CURRENT limitations',64,263,640,47,32,ink,true);txt(s,'Future solutions (proposed)',861,263,675,47,32,colors[0],true);
 const rows=[['Selected kernel roots and reviewed models','Expand roots and compare model effects natively'],['Projected state and bounded ownership','Broaden discovery, lifetimes and reference handling'],['Static ELF and syscall pause boundaries','Add loading support and proven safe points'],['Sequential replay without general IRQ/SMP','Capture causal task, interrupt and memory effects'],['Functional QEMU validation','Add RTL execution and a separate timing contract']];
 for(const [i,[a,b]] of rows.entries()){
  const y=342+i*83;txt(s,a,64,y,655,69,28,body);txt(s,b,861,y,675,69,28,colors[0]);
  const left=rect(s,749,y+23,1,1,'none'),right=rect(s,823,y+23,1,1,'none');link(s,left,right,'right','left',1);
 }
 foot(s,'Exact code/schema identity remains the default until compatibility across versions is proven.');
}

// 8. Artifact roles resolve the repeated slices.elf basename.
{
 const s=slide('Artifact roles and key tools','C source ownership and ELF roles depend on the construction stage.',null,['tools/export_syscall_slices.py','tools/export_application_replay.py','docs/application-checkpoints.md']);
 const rows=[['Application C / ELF','User program. The C test frontend produces application.elf.'],['Kernel C / slices.a','Selected original syscall/helper C with reviewed dependency models.'],['Kernel proof ELF','slices.elf in the kernel export directory: slices, runtime and proof driver.'],['Combined replay ELF','slices.elf in the replay directory: app payload, kernel slices and runtime.'],['Generated runtime C','Context helpers, codec, loader and replay adapters.']];
 for(const [i,[label,value]] of rows.entries()){
  const y=265+i*86;txt(s,label,64,y,400,68,28,ink,true);txt(s,value,500,y,1036,68,27,body);
 }
 rect(s,64,710,1472,1,'#CBD5E1');
 txt(s,'Clang / AST',64,737,390,40,27,colors[0],true);txt(s,'Types and state references',64,784,390,44,24);
 txt(s,'QMP',565,737,410,40,27,colors[3],true);txt(s,'Host access to stopped guest memory',565,784,450,44,24);
 txt(s,'Shared stage engine',1070,737,466,40,27,colors[1],true);txt(s,'Build, verify, save and continue',1070,784,466,44,24);
}

const candidatePath=path.join(build,'candidate.pptx');
await (await PresentationFile.exportPptx(p)).save(candidatePath);
console.log('Exported 8-slide stage explanation with native diagrams');
await finalizePresentation({workspaceDir,candidatePath,finalPath:path.join(workspaceDir,'output/osrec-stages-explained-final.pptx'),pythonExecutable:'/Users/al3x3n0/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3',integrityValidatorPath:path.join(skill,'container_tools/inspect_presentation_package_integrity.py'),layoutValidatorPath:path.join(skill,'container_tools/inspect_presentation_layout_geometry.py'),explicitTotalSlideCount:8,requiredNativeTableOwnerSlides:[],layoutArgs:['--expected-slide-size-emu','15240000,8572500','--validate-heading-fit'],fontPolicy:{basis:'design',families:[font]},verifyArtifactToolImport:false,receiptPath:path.join(build,'validation-final.json')});
for(const [i,s] of p.slides.items.entries()){
 const preview=await p.export({slide:s,format:'png',scale:1});
 await fs.writeFile(path.join(build,`slide-${String(i+1).padStart(2,'0')}.png`),new Uint8Array(await preview.arrayBuffer()));
 console.log('Rendered',i+1);
}
