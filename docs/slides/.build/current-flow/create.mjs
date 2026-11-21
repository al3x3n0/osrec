import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {Presentation,PresentationFile,FileBlob} from '@oai/artifact-tool';

const root='/Users/al3x3n0/huawei/osrec';
const workspaceDir=path.join(root,'docs/slides');
const build=path.join(workspaceDir,'.build/current-flow');
const skill='/Users/al3x3n0/.codex/plugins/cache/openai-primary-runtime/presentations/26.909.12148/skills/presentations';
const runtime='/Users/al3x3n0/.cache/codex-runtimes/codex-primary-runtime/dependencies';
process.env.RUNTIME_NODE_MODULES=path.join(runtime,'node/node_modules');
const {resolvePresentationFont,applyPresentationChartFont,finalizePresentation}=await import(pathToFileURL(path.join(skill,'container_tools/artifact_tool_utils.mjs')));
const font=resolvePresentationFont();
const fontPolicy={basis:'design',families:[font]};
const p=Presentation.create({slideSize:{width:1600,height:900}});
const C={ink:'#142735',body:'#334155',muted:'#64748B',native:'#087F8C',kernel:'#2563EB',runtime:'#B45309',pale:'#F1F5F9',blue:'#EFF6FF',teal:'#EDF9F8',amber:'#FFFBEB'};
const report=JSON.parse(await fs.readFile(path.join(root,'build/el0-hardware-validation-20261113h/validation.json'),'utf8'));
const sources={doc:'docs/el0-hardware-memory.md',export:'tools/export_el0_program.py',program:'runtime/el0_flat/program.c',hardware:'tools/el0_hardware.py',user:'tools/el0_user_memory.py',svc:'tools/el0_syscall.py',uart:'tools/el0_uart.py',model:'tools/el0_hardware_model.py',core:'runtime/el0/emulate.c',result:'build/el0-hardware-validation-20261113h/validation.json'};

function text(s,t,x,y,w,h,size=30,color=C.body,bold=false){
 const n=s.shapes.add({geometry:'textbox',position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});
 n.text=t;n.text.style={typeface:font,fontSize:size,color,bold,autoFit:'none'};return n;
}
function box(s,x,y,w,h,stroke=C.native,fill=C.teal){return s.shapes.add({geometry:'rect',position:{left:x,top:y,width:w,height:h},fill,line:{fill:stroke,width:1.7}});}
function node(s,title,body,x,y,w=340,h=160,color=C.native,fill=C.teal){
 const n=box(s,x,y,w,h,color,fill);
 text(s,title,x+18,y+17,w-36,66,31,C.ink,true);
 if(body)text(s,body,x+18,y+83,w-36,h-91,26,C.body);
 return n;
}
function link(s,a,b,{from='right',to='left',color=C.native,kind='straight'}={}){
 s.shapes.connect(a,b,{kind,fromSide:from,toSide:to,line:{fill:color,width:2.5},tail:{type:'arrow',width:'med',length:'med'}});
}
function slide(title,subtitle,refs,notes=''){
 const s=p.slides.add();s.background.fill='#FFFFFF';
 text(s,title,64,43,1472,70,49,C.ink,true);
 text(s,subtitle,64,132,1472,74,29,C.body);
 text(s,'OSREC  /  Current EL0 checkpoint executor  /  13 November 2026',64,854,1350,28,19,C.muted);
 text(s,String(p.slides.items.length).padStart(2,'0'),1480,850,56,32,21,C.muted);
 s.speakerNotes.textFrame.setText(refs.map(k=>path.join(root,sources[k]??k)).join('\n')+'\n\n'+notes);
 return s;
}
function note(s,t,y=776){text(s,t,64,y,1472,62,27,C.body);}

// 1. A process overview rather than a decorative cover.
{
 const s=slide('Current EL0 checkpoint flow','Captured application and kernel instructions continue together in one standalone executor.',['doc','export','model','result'],
 'This deck describes the current captured-binary EL0 backend. The separate source-slice and portable-state workflows have different contracts. The latest local implementation includes uncommitted user-memory, SVC-entry and UART fast paths. Counts refer to the supplied random/fault workload.');
 const a=node(s,'Captured checkpoint','User CPU state and kernel RAM',64,264,400,168,C.muted,C.pale);
 const b=node(s,'Export and link','Native blocks and checked adapters',600,264,400,168,C.kernel,C.blue);
 const c=node(s,'Model setup','Hardware tables and EL0 entry',1136,264,400,168,C.muted,C.pale);
 const d=node(s,'EL0 computation','User code and captured kernel code',1136,556,400,168);
 const e=node(s,'Checked fallbacks','ERET, faults and unsupported cases',600,556,400,168,C.runtime,C.amber);
 const f=node(s,'Final validation','Events, counter inputs and UART',64,556,400,168,C.kernel,C.blue);
 link(s,a,b);link(s,b,c);link(s,c,d,{from:'bottom',to:'top'});
 link(s,d,e,{from:'left',to:'right',color:C.runtime});link(s,e,f,{from:'left',to:'right',color:C.kernel});
 note(s,'Latest accepted run: 2,272 events match, with 2,549 gateway entries and zero hardware exceptions.');
}
// 2. Construction inputs and the distinct use of expected evidence.
{
 const s=slide('Checkpoint construction','The exporter builds native execution blocks from the captured code and state.',['export','doc'],
 'The package supplies native.bin and sparse memory.bin, mappings, architecture shadow and admitted sites. vmlinux supports a conservative function closure. The user ELF identity must match the capture manifest. Coverage logs broaden code admission but never select branch outcomes. Counter values are ordered external inputs. Expected events and UART bytes are checked at completion.');
 const a=node(s,'Package and user ELF','Captured state and verified identity',64,260,420,156,C.muted,C.pale);
 const b=node(s,'vmlinux and code closure','Syscall roots and admitted code',64,510,420,156,C.muted,C.pale);
 const c=node(s,'AOT exporter','Decode, lower and link',635,385,360,170,C.kernel,C.blue);
 const d=node(s,'Standalone checkpoint ELF','Native blocks, adapters and RAM',1110,385,426,170);
 link(s,a,c,{from:'right',to:'top',kind:'elbow',color:C.kernel});
 link(s,b,c,{from:'right',to:'bottom',kind:'elbow',color:C.kernel});link(s,c,d,{color:C.kernel});
 text(s,'Ordered counter inputs accompany the image.',635,616,901,52,28,C.body);
 text(s,'Expected event and UART records serve the final checker.',635,683,901,60,28,C.body);
 note(s,'Recorded outcomes do not choose branches or supply computed syscall results.');
}
// 3. Actual and logical execution levels are separate concepts.
{
 const s=slide('Actual EL0 execution and logical privilege','Model initialization finishes before the delivered checkpoint begins.',['model','program','core'],
 'Setup installs actual hardware tables and starts at EL0. After entry the current QEMU fixture stops on unexpected hardware exceptions and does not service or resume them. Logical user/kernel mode lives in osrec_shadow. Actual SP stays on the private execution stack. Guest SP is in flat_active->guest_sp.');
 const setup=node(s,'Initialization fixture','Build tables and configure the CPU',64,255,430,165,C.muted,C.pale);
 const frame=box(s,590,246,946,444,C.kernel,'none');
 text(s,'ACTUAL EL0',620,266,840,52,32,C.kernel,true);
 const user=node(s,'Logical user mode','Application instruction blocks',635,350,374,180);
 const kernel=node(s,'Logical kernel mode','Captured kernel instruction blocks',1118,350,374,180,C.kernel,C.blue);
 link(s,setup,frame,{color:C.kernel,kind:'elbow'});link(s,user,kernel,{color:C.kernel});
 text(s,'Inline adapters and the shared emulator also execute inside this EL0 boundary.',635,573,837,90,29,C.body);
 text(s,'Private actual SP',64,555,450,45,31,C.ink,true);
 text(s,'Logical guest SP tracks the application or kernel stack.',64,615,450,102,29,C.body);
 note(s,'No runtime EL1 services. Unexpected hardware exceptions stop validation.');
}
// 4. The main decision tree.
{
 const s=slide('Instruction routing','Native execution handles the admitted case. Rejections retain their original diagnostic path.',['export','hardware','user','svc','program']);
 const a=node(s,'Original instruction','Decoded at export time',64,405,330,170,C.kernel,C.blue);
 const b=node(s,'Arithmetic and SIMD','Native instruction block',590,245,390,158);
 const c=node(s,'Memory access','Kernel alias or live user-PTE check',590,505,390,174);
 const d=node(s,'Native access and continuation','Restore scratch state and writeback',1146,245,390,158);
 const e=node(s,'Context gateway','Fault, ERET or unsupported case',1146,505,390,174,C.runtime,C.amber);
 link(s,a,b,{from:'right',to:'left',kind:'elbow'});link(s,a,c,{from:'right',to:'left',kind:'elbow'});
 link(s,b,d);link(s,c,d,{from:'right',to:'left',kind:'elbow'});link(s,c,e,{color:C.runtime});
 text(s,'pass',1030,274,110,42,25,C.native,true);
 text(s,'fallback',1008,602,125,42,25,C.runtime,true);
 note(s,'Shadow-register operations, indirect branches, SVC entry and result observation also have inline paths.');
}
// 5. Canonical RAM is the common physical store.
{
 const s=slide('Canonical RAM and virtual aliases','Kernel aliases and translated user accesses refer to the same captured physical bytes.',['hardware','user','model','export'],
 'Kernel static aliases map through the actual hardware MMU to linked flat_phys backing. User operations walk captured tables inline and replace the native instruction base with a canonical RAM pointer. They do not install an actual hardware mapping at the original user VA. Physical aliases of AOT text are excluded from writes.');
 const k=node(s,'Static kernel VA','Hardware alias and range checks',64,260,422,176,C.kernel,C.blue);
 const u=node(s,'User VA','Fresh captured TTBR0 walk',64,543,422,176);
 const pa=node(s,'Captured physical address','Permission and RAM admission',665,402,365,176);
 const ram=node(s,'Canonical RAM','flat_phys backing store',1200,402,336,176);
 link(s,k,pa,{from:'right',to:'top',kind:'elbow',color:C.kernel});
 link(s,u,pa,{from:'right',to:'bottom',kind:'elbow'});link(s,pa,ram);
 text(s,'Runtime pointer = flat_phys + captured PA − ram_base',568,658,968,60,31,C.ink,true);
 note(s,'PTE updates and data updates share this RAM. Every admitted physical alias of AOT text remains immutable.');
}
// 6. Live-PTE flow including the software-fault path.
{
 const s=slide('User-memory fast path and demand faults','Every access sees current captured PTEs. Successful accesses make no runtime call.',['user','program','core'],
 'The inline path supports 4 KiB granules, 25–48 VA bits, L1/L2 block leaves, AF, inherited AP restrictions, RAM bounds and immutable text protection. Cross-page accesses, permission failures and missing backing fall through before the original access executes. The existing handler computes the fault syndrome and enters captured kernel code. ERET still validates admitted user code mappings.');
 const a=node(s,'Effective user address','Includes logical SP and offsets',64,264,360,164);
 const b=node(s,'Live page-table walk','TTBR0, AF and inherited AP',620,264,360,164);
 const c=node(s,'Native load or store','Canonical RAM and writeback',1176,264,360,164);
 const d=node(s,'Checked fallback','Compute the architectural fault',620,574,360,164,C.runtime,C.amber);
 const e=node(s,'Captured fault handler','Update PTEs and return through ERET',1176,574,360,164,C.kernel,C.blue);
 link(s,a,b);link(s,b,c);
 link(s,b,d,{from:'bottom',to:'top',color:C.runtime});link(s,d,e,{color:C.kernel});
 text(s,'Checks include RAM bounds\nand immutable code.',64,484,490,86,29,C.body);
 const retryAnchor=s.shapes.add({geometry:'rect',position:{left:900,top:427,width:1,height:1},fill:'none',line:{fill:'none',width:0}});
 link(s,e,retryAnchor,{from:'top',to:'bottom',kind:'elbow',color:C.kernel});
 text(s,'return and retry',1100,457,300,42,25,C.kernel,true);
 text(s,'The resumed instruction reads the updated PTEs on retry.',64,631,440,98,29,C.body);
 note(s,'Software-detected faults enter the captured kernel. User/user-copy fallback entries: 185.');
}
// 7. Syscall entry and return.
{
 const s=slide('Syscall execution lifecycle','Logical SVC entry records evidence, then runs the captured kernel syscall implementation.',['svc','program','core','hardware']);
 const a=node(s,'Application SVC site','x8 number, x0–x5 arguments',64,265,400,165);
 const b=node(s,'Inline entry adapter','Record event and switch logical stack',600,265,400,165);
 const c=node(s,'Captured kernel vector','Entry code, dispatcher and syscall body',1136,265,400,165,C.kernel,C.blue);
 const d=node(s,'Inline result observation','Read result and complete the event',1136,565,400,165);
 const e=node(s,'Emulated ERET','Validate state and user-code mappings',600,565,400,165,C.runtime,C.amber);
 const f=node(s,'Application continuation','Computed result and updated RAM',64,565,400,165);
 link(s,a,b);link(s,b,c,{color:C.kernel});link(s,c,d,{from:'bottom',to:'top',color:C.kernel});
 link(s,d,e,{from:'left',to:'right',color:C.runtime});link(s,e,f,{from:'left',to:'right'});
 note(s,'SVC entry preserves FAR and all GPRs/NZCV. Expected results only participate in final validation.');
}
// 8. Intentional emulator work.
{
 const s=slide('ERET remains emulated','2,320 gateway entries preserve the logical exception-return contract.',['core','program','result']);
 const a=node(s,'Shadow SPSR and ELR','Saved mode, flags and return PC',64,350,350,174,C.runtime,C.amber);
 const b=node(s,'Validate return state','Supported PSTATE and EL0t or EL1h',610,350,380,174,C.runtime,C.amber);
 const c=node(s,'Apply logical return','DAIF, PAN, flags, mode and stack',1186,350,350,174,C.runtime,C.amber);
 link(s,a,b,{color:C.runtime});link(s,b,c,{color:C.runtime});
 text(s,'Return to user',64,598,440,48,32,C.ink,true);
 text(s,'Validate every admitted user-code page and resolve the original PC.',64,660,677,95,29,C.body);
 text(s,'Return to kernel',858,598,440,48,32,C.ink,true);
 text(s,'Keep the logical kernel stack and resolve the original PC.',858,660,678,95,29,C.body);
 note(s,'Unsupported state, changed code mappings and missing targets produce explicit stops.');
}
// 9. UART emulation is separate from actual MMIO.
{
 const s=slide('UART buffering and output evidence','Eligible kernel accesses preserve the existing register-buffer emulation inline.',['uart','program','export','result']);
 const a=node(s,'Kernel UART access','Check privilege, address and width',64,292,405,180,C.kernel,C.blue);
 const b=node(s,'Emulated register buffer','Read 0x18, write 0x00 or 0x38',603,292,405,180);
 const c=node(s,'UART output ledger','Append the low byte on a data write',1142,292,394,180);
 link(s,a,b);link(s,b,c);
 text(s,'Checks retained',64,579,420,48,32,C.ink,true);
 text(s,'Output capacity is 4,096 bytes. Invalid offsets, user accesses and unsupported widths retain the checked handler.',64,644,700,119,29,C.body);
 text(s,'Observed output',892,579,560,48,32,C.ink,true);
 text(s,'All 92 expected bytes match. The executor never accesses a physical UART.',892,644,644,111,29,C.body);
}
// 10. Editable count table with an explicit sum.
{
 const s=slide('Remaining context-gateway entries','The latest accepted workload uses 2,549 entries. ERET accounts for 2,320.',['result','program'],
 'Counts are gateway entries, not bytes, unique memory regions or processor cycles. Fault=201 is an overlapping diagnostic and is not an extra row to add. User/user-copy labels describe the remaining fallback entries without assuming every category is a distinct fault type.');
 const rows=[['Operation','Entries','Current handler role'],['ERET',2320,'Logical exception return'],['User loads and stores',136,'Checked fallback'],['Explicit user-copy accesses',49,'Checked fallback'],['Exclusive-window entry',5,'Checked exclusive path'],['Exclusive-window completion',5,'Restore the grouped access'],['Prefetch fallback',21,'Retain hint handling'],['Ordered counter reads',9,'Consume captured input in order'],['TPIDRRO writes',3,'Architecture platform hook'],['Completion boundary',1,'Stop and validate'],['Total',2549,'']];
 const table=s.tables.add({rows:rows.length,columns:3,left:64,top:224,width:1472,height:550,columnWidths:[550,180,742],values:rows});
 table.borders.assign({style:'solid',fill:'#CBD5E1',width:0.6});
 for(let r=0;r<rows.length;r++)for(let c=0;c<3;c++){
   const cell=table.getCell(r,c);cell.fill=r===0?C.ink:r===rows.length-1?C.teal:'#FFFFFF';
   cell.text.style={typeface:font,fontSize:26,color:r===0?'#FFFFFF':C.body,bold:r===0||r===rows.length-1};
 }
 note(s,'Kernel-RAM fast paths, successful user accesses, SVC entry and UART buffering use no context gateway.',792);
}
// 11. Native chart with the recent milestones, keeping the cycle caveat visible.
{
 const s=slide('Recent gateway-call reductions','The latest optimizations retain the same captured workload and result checks.',['result','doc'],
 'Milestones: before inline user translation 24,587, after user translation 4,986, after inline SVC entry 2,850, after UART register buffering 2,549. Original software backend approximately 2,261,577 entries. The overall reduction is computed against that original baseline. These are gateway counts and do not establish a timing speedup.');
 const chart=s.charts.add('bar',{position:{left:100,top:240,width:1400,height:438},categories:['Before user fast path','User memory','SVC entry','UART buffering'],series:[{name:'Gateway entries',values:[24587,4986,2850,2549],valuesFormatCode:'#,##0',fill:C.native}],barOptions:{direction:'column',grouping:'clustered'},hasLegend:false,dataLabels:{showValue:true,position:'outEnd'}});
 applyPresentationChartFont(chart,{fontFamily:font});
 for(const style of [chart.xAxis?.textStyle,chart.yAxis?.textStyle,chart.dataLabels?.textStyle])if(style)style.fontSize=24;
 text(s,'Original software backend: approximately 2,261,577 entries',64,721,1472,43,29,C.ink,true);
 note(s,'Overall reduction: 99.9%. Processor timing and RTL execution remain unverified.',784);
}
// 12. Evidence and explicit scope of the claims.
{
 const s=slide('Validation evidence and current scope','The latest profiled checkpoint passes the complete functional workload.',['result','model','doc','tests/test_el0_user_memory.py','tests/test_el0_syscall.py','tests/test_el0_uart.py'],
 `Artifact: build/el0-hardware-memory-20261113h/checkpoint\nSHA-256: ${report.image_sha256}\nModel: ${report.functional_model}\nThe isolated instruction fixtures use a QEMU EL1 harness. Complete-image validation checks actual EL0 at entry and completion and stops unexpected exceptions. Six optional native AArch64 Linux instruction tests are skipped on the local macOS host. Reported workload/rejection tests and cross-compiled instruction fixtures pass. Event equality does not prove equivalence for every possible workload or all memory bytes.`);
 text(s,'Observed evidence',64,257,625,48,34,C.kernel,true);
 const evidence=['2,272 events match','9 counter inputs consumed in order','92 UART bytes match','0 unexpected hardware exceptions','0 runtime EL1 services'];
 evidence.forEach((t,i)=>text(s,t,64,333+i*75,710,57,33,C.ink,i===0));
 text(s,'Scope and limits',898,257,638,48,34,C.runtime,true);
 text(s,'Captured random/fault workload\nFunctional QEMU Cortex-A53 model\nBounded admitted code closure',898,333,638,165,30,C.body);
 text(s,'Instruction fixtures and rejection checks cover the adapters. Unknown code and unsupported state stop explicitly.',898,552,638,143,30,C.body);
 note(s,'All computation stays at EL0 after setup. Cycle measurements and RTL validation remain future work.',780);
}

await fs.mkdir(build,{recursive:true});
const candidatePath=path.join(build,'candidate-final.pptx');
await (await PresentationFile.exportPptx(p)).save(candidatePath);
const finalPath=path.join(workspaceDir,'output/osrec-current-el0-flow-final.pptx');
await finalizePresentation({workspaceDir,candidatePath,finalPath,
 pythonExecutable:path.join(runtime,'python/bin/python3'),
 integrityValidatorPath:path.join(skill,'container_tools/inspect_presentation_package_integrity.py'),
 layoutValidatorPath:path.join(skill,'container_tools/inspect_presentation_layout_geometry.py'),
 explicitTotalSlideCount:12,requiredNativeTableOwnerSlides:[10],requiredNativeChartOwnerSlides:[11],
 materializeLiteralChartWorkbooks:true,
 layoutArgs:['--expected-slide-size-emu','15240000,8572500','--validate-bullet-geometry','--validate-heading-fit','--require-native-table-slide','10'],
 fontPolicy,verifyArtifactToolImport:true,receiptPath:path.join(build,'validation-delivery.json')});
console.log('Final:',finalPath,'Font:',font);
const delivered=await PresentationFile.importPptx(await FileBlob.load(finalPath));
for(const [i,s] of delivered.slides.items.entries()){
 const png=await delivered.export({slide:s,format:'png',scale:1});
 await fs.writeFile(path.join(build,`slide-${String(i+1).padStart(2,'0')}.png`),new Uint8Array(await png.arrayBuffer()));
 const layout=await s.export({format:'layout'});await fs.writeFile(path.join(build,`slide-${i+1}.layout.json`),await layout.text());
 console.log('Rendered',i+1);
}
