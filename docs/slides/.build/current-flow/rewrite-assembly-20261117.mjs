import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {Presentation,PresentationFile,FileBlob} from '@oai/artifact-tool';

const root='/Users/al3x3n0/huawei/osrec';
const workspaceDir=path.join(root,'docs/slides');
const build=path.join(workspaceDir,'.build/current-flow-assembly-20261117');
const skill='/Users/al3x3n0/.codex/plugins/cache/openai-primary-runtime/presentations/26.909.12148/skills/presentations';
const runtime='/Users/al3x3n0/.cache/codex-runtimes/codex-primary-runtime/dependencies';
process.env.RUNTIME_NODE_MODULES=path.join(runtime,'node/node_modules');
const {resolvePresentationFont,applyPresentationChartFont,finalizePresentation}=await import(pathToFileURL(path.join(skill,'container_tools/artifact_tool_utils.mjs')));
const font=resolvePresentationFont();
const mono=resolvePresentationFont({fontFamily:'Menlo'});
const fontPolicy={basis:'design',families:[font,mono]};
const p=Presentation.create({slideSize:{width:1600,height:900}});
const C={ink:'#142735',body:'#334155',muted:'#64748B',native:'#087F8C',kernel:'#2563EB',runtime:'#B45309',pale:'#F1F5F9',blue:'#EFF6FF',teal:'#EDF9F8',amber:'#FFFBEB'};
const report=JSON.parse(await fs.readFile(path.join(root,'build/el0-next-slices-measurement-20261117a/validation.json'),'utf8'));
const sources={optimization:'docs/el0-runtime-optimization.md',pretranslated:'docs/el0-pretranslated-memory.md',returns:'docs/el0-inline-return.md',counts:'build/el0-next-slices-profile-20261117a/counts.json',production:'build/el0-production-profile-20261117c/counts.json',doc:'docs/el0-hardware-memory.md',export:'tools/export_el0_program.py',program:'runtime/el0_flat/program.c',hardware:'tools/el0_hardware.py',user:'tools/el0_user_memory.py',svc:'tools/el0_syscall.py',uart:'tools/el0_uart.py',model:'tools/el0_hardware_model.py',core:'runtime/el0/emulate.c',result:'build/el0-next-slices-measurement-20261117a/validation.json'};

function text(s,t,x,y,w,h,size=30,color=C.body,bold=false){
 const n=s.shapes.add({geometry:'textbox',position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});
 n.text=t;n.text.style={typeface:font,fontSize:size,color,bold,autoFit:'none'};return n;
}
function box(s,x,y,w,h,stroke=C.native,fill=C.teal){return s.shapes.add({geometry:'rect',position:{left:x,top:y,width:w,height:h},fill,line:{fill:stroke,width:1.7}});}
function node(s,title,body,x,y,w=340,h=160,color=C.native,fill=C.teal){
 const n=box(s,x,y,w,h,color,fill);
 text(s,title,x+18,y+17,w-36,72,28,C.ink,true);
 if(body)text(s,body,x+18,y+91,w-36,h-96,24,C.body);
 return n;
}
function link(s,a,b,{from='right',to='left',color=C.native,kind='straight'}={}){
 s.shapes.connect(a,b,{kind,fromSide:from,toSide:to,line:{fill:color,width:2.5},tail:{type:'arrow',width:'med',length:'med'}});
}
function slide(title,subtitle,refs,notes=''){
 const s=p.slides.add();s.background.fill='#FFFFFF';
 text(s,title,64,43,1472,70,49,C.ink,true);
 text(s,subtitle,64,132,1472,74,29,C.body);
 text(s,'OSREC  /  Current EL0 checkpoint executor  /  17 November 2026',64,854,1350,28,19,C.muted);
 text(s,String(p.slides.items.length).padStart(2,'0'),1480,850,56,32,21,C.muted);
 s.speakerNotes.textFrame.setText([...refs,'optimization','pretranslated','returns'].map(k=>path.join(root,sources[k]??k)).join('\n')+'\n\n'+notes);
 return s;
}
function note(s,t,y=776){text(s,t,64,y,1472,62,27,C.body);}


function assemblySlide(title,subtitle,code,heading,explanation,caption,refs,notes=''){
 const s=slide(title,subtitle,refs,notes);
 const snippet=text(s,code,64,250,860,480,29,C.ink);
 snippet.text.style.typeface=mono;
 text(s,heading,1020,255,516,90,33,C.kernel,true);
 text(s,explanation,1020,370,516,340,29,C.body);
 note(s,caption,780);
 return s;
}

// 1. A process overview rather than a decorative cover.
{
 const s=slide('EL0 checkpoint executor','From a captured application and kernel to a standalone, measured AArch64 executor.',['doc','export','model','result'],
 'This deck describes the current captured-binary EL0 backend. The separate source-slice and portable-state workflows have different contracts. The current pretranslated backend uses native user/kernel stacks, syscall context gateways and generated user returns. Checked mode is the default; execution-only production is optional. Counts refer to the supplied random/fault workload.');
 const a=node(s,'Captured checkpoint','User CPU state and kernel RAM',64,264,400,168,C.muted,C.pale);
 const b=node(s,'Export and link','Native blocks and checked adapters',600,264,400,168,C.kernel,C.blue);
 const c=node(s,'Model setup','Hardware tables and EL0 entry',1136,264,400,168,C.muted,C.pale);
 const d=node(s,'EL0 computation','User code and captured kernel code',1136,556,400,168);
 const e=node(s,'Checked fallbacks','Syscalls, faults and residual ERET',600,556,400,168,C.runtime,C.amber);
 const f=node(s,'Final validation','Checked mode: events and UART',64,556,400,168,C.kernel,C.blue);
 link(s,a,b);link(s,b,c);link(s,c,d,{from:'bottom',to:'top'});
 link(s,d,e,{from:'left',to:'right',color:C.runtime});link(s,e,f,{from:'left',to:'right',color:C.kernel});
 note(s,'Latest accepted run: 2,272 events match, with 2,381 gateway entries and zero hardware exceptions.');
}
// 2. Construction inputs and the distinct use of expected evidence.
{
 const s=slide('Checkpoint construction and toolchain','Python export and AArch64 compilation turn captured state into an executable ELF.',['export','doc'],
 'The package supplies native.bin and sparse memory.bin, mappings, architecture shadow and admitted sites. vmlinux supports a conservative function closure. The user ELF identity must match the capture manifest. Coverage logs broaden code admission but never select branch outcomes. Counter values are ordered external inputs. Expected events and UART bytes are checked at completion.');
 const a=node(s,'Package and user ELF','Captured state and verified identity',64,260,420,156,C.muted,C.pale);
 const b=node(s,'vmlinux and code closure','Syscall roots and admitted code',64,510,420,156,C.muted,C.pale);
 const c=node(s,'AOT exporter','Decode, lower and link',635,385,360,170,C.kernel,C.blue);
 const d=node(s,'Standalone checkpoint ELF','Native blocks, adapters and RAM',1110,385,426,170);
 link(s,a,c,{from:'right',to:'top',kind:'elbow',color:C.kernel});
 link(s,b,c,{from:'right',to:'bottom',kind:'elbow',color:C.kernel});link(s,c,d,{color:C.kernel});
 text(s,'Ordered counter inputs accompany the image.',635,616,901,52,28,C.body);
 text(s,'Checked images embed expected outputs for the final checker.',635,683,901,60,28,C.body);
 note(s,'Recorded outcomes do not choose branches or supply computed syscall results.');
}
// Tools used for construction and measurement.
{
 const s=slide('Tools used to build and validate the executor','Each tool produces a distinct artifact or checks a distinct execution property.',
 ['tools/export_el0_program.py','runtime/el0_flat/Makefile','tools/el0_hardware_model.py','tools/gdb_remote.py','tools/qemu_plugins/instruction_profile.c','docs/el0-instruction-profile.md','docs/el0-runtime-optimization.md'],
 'Tool inventory verified from repository scripts and retained build reports. Runtime example uses LLVM 16 Clang targeting aarch64-none-elf and LLD; vmlinux input comes from the separate clang19 kernel build. QEMU 9.2.3 TCG models one Cortex-A53. Python clients speak GDB RSP to the simulator stub; a standalone GDB executable is not required by this runner. CTest/Python fixtures and linked-image audits supply regression evidence.');
 const rows=[
 ['Python exporter','Decode admitted code, lower architecture edges and emit assembly, RAM and proofs.'],
 ['Clang + LLD + Make','Cross-compile C/AArch64 assembly and link the freestanding ELF. Optional LTO.'],
 ['QEMU 9.2.3 TCG','Run one Cortex-A53 vCPU with MMU setup before entering the EL0 checkpoint.'],
 ['GDB remote interface','Python runner controls model stops and reads CPU state and the RAM result block.'],
 ['QEMU instruction plugin','Count executed guest instructions per PC. Python attributes payload and adapter cost.'],
 ['CTest + Python tests','Exercise context preservation, memory faults, negative cases and linked-image audits.']];
 rows.forEach(([name,body],i)=>{const y=242+i*86;text(s,name,64,y,425,72,29,C.ink,true);text(s,body,510,y,1026,72,28,C.body);});
 note(s,'QEMU provides functional and instruction-count evidence. Cycle timing and RTL execution remain unverified.',780);
}

// 3. Actual and logical execution levels are separate concepts.
{
 const s=slide('Actual EL0 execution and logical privilege','Model initialization finishes before the delivered checkpoint begins.',['model','program','core'],
 'Setup installs actual hardware tables and starts at EL0. After entry the current QEMU fixture stops on unexpected hardware exceptions and does not service or resume them. Logical user/kernel mode lives in osrec_shadow. User and kernel code use native SP in prepared aliases. Context gateways capture native state and switch to a private handler stack.');
 const setup=node(s,'Initialization fixture','Build tables and configure the CPU',64,255,430,165,C.muted,C.pale);
 const frame=box(s,590,246,946,444,C.kernel,'none');
 text(s,'ACTUAL EL0',620,266,840,52,32,C.kernel,true);
 const user=node(s,'Logical user mode','Application instruction blocks',635,350,374,180);
 const kernel=node(s,'Logical kernel mode','Captured kernel instruction blocks',1118,350,374,180,C.kernel,C.blue);
 link(s,setup,frame,{color:C.kernel,kind:'elbow'});link(s,user,kernel,{color:C.kernel});
 text(s,'Inline adapters and the shared emulator also execute inside this EL0 boundary.',635,573,837,90,29,C.body);
 text(s,'Native application/kernel SP',64,555,450,45,31,C.ink,true);
 text(s,'Prepared stack aliases serve native code. Handlers switch to a private stack.',64,615,450,102,29,C.body);
 note(s,'No runtime EL1 services. Unexpected hardware exceptions stop validation.');
}
// 4. The main decision tree.
{
 const s=slide('Native instructions and runtime adapters','The exporter retains native computation and inserts adapters at admitted architecture edges.',['export','hardware','user','svc','program']);
 const a=node(s,'Original instruction','Decoded at export time',64,405,330,170,C.kernel,C.blue);
 const b=node(s,'Arithmetic and SIMD','Native instruction block',590,245,390,158);
 const c=node(s,'Memory access','Kernel alias or live user-PTE check',590,505,390,174);
 const d=node(s,'Native access and continuation','Restore scratch state and writeback',1146,245,390,158);
 const e=node(s,'Context gateway','Fault, ERET or unsupported case',1146,505,390,174,C.runtime,C.amber);
 link(s,a,b,{from:'right',to:'left',kind:'elbow'});link(s,a,c,{from:'right',to:'left',kind:'elbow'});
 link(s,b,d);link(s,c,d,{from:'right',to:'left',kind:'elbow'});link(s,c,e,{color:C.runtime});
 text(s,'pass',1030,274,110,42,25,C.native,true);
 text(s,'fallback',1008,602,125,42,25,C.runtime,true);
 note(s,'Indexed dispatch, specialized returns and grouped system operations reduce adapter work.');
}
// 5. Prepared aliases and canonical RAM.
{
 const s=slide('Embedded RAM and prepared memory aliases','The ELF carries initial RAM and hardware page tables for the admitted mappings.',['pretranslated','model','export']);
 const k=node(s,'Kernel VA and native SP','Original loads and stores',64,260,422,176,C.kernel,C.blue);
 const u=node(s,'Proven resident user VA','43 direct memory sites',64,543,422,176);
 const pa=node(s,'Hardware translation','Prepared coherent aliases',665,402,365,176);
 const ram=node(s,'Canonical RAM','Shared captured physical bytes',1200,402,336,176);
 link(s,k,pa,{from:'right',to:'top',kind:'elbow',color:C.kernel});
 link(s,u,pa,{from:'right',to:'bottom',kind:'elbow'});link(s,pa,ram);
 text(s,'Other user accesses retain live software translation.',568,658,968,60,31,C.ink,true);
 note(s,'Prepared bindings are guarded at user return. Physical aliases of AOT text remain immutable.');
}

// 6. Live-PTE flow including the software-fault path.
{
 const s=slide('User-memory fast path and demand faults','Unresolved user accesses read live captured PTEs. Proven resident sites use native aliases.',['user','program','core'],
 'The inline path supports 4 KiB granules, 25–48 VA bits, L1/L2 block leaves, AF, inherited AP restrictions, RAM bounds and immutable text protection. Cross-page accesses, permission failures and missing backing fall through before the original access executes. The existing handler computes the fault syndrome and enters captured kernel code. ERET still validates admitted user code mappings.');
 const a=node(s,'Effective user address','Includes native SP and offsets',64,264,360,164);
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
 note(s,'Software-detected faults enter the captured kernel. Recorded faults: 185. Prepared bindings retain boundary checks.');
}
// 7. Syscall entry and return.
{
 const s=slide('Syscall execution lifecycle','A context gateway switches native stacks, then runs the captured kernel syscall implementation.',['svc','program','core','hardware']);
 const a=node(s,'Application SVC site','x8 number, x0–x5 arguments',64,265,400,165);
 const b=node(s,'Syscall gateway','Capture state and switch native stack',600,265,400,165);
 const c=node(s,'Captured kernel vector','Entry code, dispatcher and syscall body',1136,265,400,165,C.kernel,C.blue);
 const d=node(s,'Result observation','Checked mode records the result',1136,565,400,165);
 const e=node(s,'Generated user return','Check context, bindings and target',600,565,400,165,C.runtime,C.amber);
 const f=node(s,'Application continuation','Computed result and updated RAM',64,565,400,165);
 link(s,a,b);link(s,b,c,{color:C.kernel});link(s,c,d,{from:'bottom',to:'top',color:C.kernel});
 link(s,d,e,{from:'left',to:'right',color:C.runtime});link(s,e,f,{from:'left',to:'right'});
 note(s,'2,136 syscall gateways remain. Production removes event observation and final result comparisons.');
}
// Assembly evidence: exact prefix of native capture macro.
assemblySlide('Assembly: switch to the private runtime stack',
 'A syscall or fallback edge preserves scratch state before the C handler runs.',
 `stp x0,x1,[sp,#-32]!
stp x16,x17,[sp,#16]
mov x16,sp
adrp x17,flat_active
ldr x17,[x17,:lo12:flat_active]
ldr x17,[x17,#8]
mov sp,x17
sub sp,sp,#800`,
 'Two stack roles',
 'The first stores reserve 32 bytes on the native stack. X16 keeps that frame address.\n\nThe pointer at flat_active + 8 selects the private stack. The gateway then reserves an 800-byte context frame.',
 'Exact opening excerpt of flat_native_capture. Remaining instructions copy scratch state and dispatch the handler.',
 ['runtime/el0_flat/gateway.inc','runtime/el0_flat/gateway.S'],
 'runtime/el0_flat/gateway.inc, flat_native_capture macro. This is a contiguous excerpt, not the complete gateway. The handler later captures remaining GPRs, SIMD, flags and FP state.');

// 8. Generated user-return path.
{
 const s=slide('Generated user returns','2,271 returns use generated assembly. Only 49 residual ERET gateways remain.',['returns','core','result'],
 'Checked return checks SPSR, saved context, root/TCR, prepared descriptors, destination index and preserved registers/SP/PC before committing state. Rejection restores scratch state and enters the original gateway. Trusted production assumes the syscall/fault preservation ABI and retains stack admission and binding guards.');
 const a=node(s,'Saved return state','SPSR, ELR and entry context',64,350,350,174,C.runtime,C.amber);
 const b=node(s,'Checked inline return','Context, bindings and target',610,350,380,174);
 const c=node(s,'Native user resume','Restore flags, SP and original PC',1186,350,350,174);
 link(s,a,b);link(s,b,c);
 text(s,'Successful checked path',64,598,620,48,32,C.ink,true);
 text(s,'No C call or full context capture. ERET semantics remain emulated at EL0.',64,660,677,95,29,C.body);
 text(s,'Fallback and production',858,598,640,48,32,C.ink,true);
 text(s,'Rejected checks use the shared handler. Trusted production assumes return ABI preservation.',858,660,678,102,29,C.body);
 note(s,'Unknown targets, changed bindings and unsupported return state stop explicitly.');
}

// Assembly evidence: generated context comparison prefix.
assemblySlide('Assembly: register checks on user return',
 'Paired loads and conditional compares preserve one failure condition across the check chain.',
 `ldp x12,x14,[x13,#8]
cmp x1,x12
ccmp x2,x14,#0,eq
ldp x12,x14,[x13,#24]
ccmp x3,x12,#0,eq
ccmp x4,x14,#0,eq
ldp x12,x14,[x13,#40]
ccmp x5,x12,#0,eq
ccmp x6,x14,#0,eq`,
 'One rejection branch',
 'X13 points to the saved entry context. LDP loads expected register pairs.\n\nAfter a mismatch, CCMP with #0 keeps Z clear. The full chain checks X1–X30, then branches to fallback before committing state.',
 'Checked mode only. Trusted production removes these equivalence comparisons under its return ABI contract.',
 ['tools/el0_return.py','build/el0-next-slices-20261117a/program.S','returns'],
 'Exact contiguous excerpt from generated program.S at .Lur800080012058_skip_x0. Shows only X1-X6. Scratch aliases are recovered from saved slots later. The single b.ne occurs after the full X1-X30 chain. X0, SP, PC, root/TCR and prepared bindings have separate checks.');
// Assembly evidence: exact native resume body.
assemblySlide('Assembly: resume the native instruction stream',
 'The full-context resume thunk restores the native stack and branches to the generated destination.',
 `ldr x17,[sp,#248]
sub x17,x17,#16
ldr x16,[sp,#128]
str x16,[x17]
ldr x16,[sp,#136]
str x16,[x17,#8]
mov sp,x17
ldp x16,x17,[sp],#16
b \\target`,
 'Scratch registers survive',
 'The context holds the saved native SP at offset 248 and X16/X17 at 128/136.\n\nThe thunk stages both registers below that SP, restores them with a post-indexed load, then branches to the macro target.',
 'Exact flat_native_resume macro body. Generated direct thunks use smaller, dedicated frame conventions.',
 ['runtime/el0_flat/gateway.inc','runtime/el0_flat/gateway.S'],
 'Exact body of flat_native_resume excluding alignment, export directives and the macro label. Backslash target is an assembler macro parameter. This full-context thunk is distinct from the direct index thunks and the generated inline ERET path.');

// 9. UART emulation is separate from actual MMIO.
{
 const s=slide('UART buffering and output evidence','Eligible kernel accesses preserve the existing register-buffer emulation inline.',['uart','program','export','result']);
 const a=node(s,'Kernel UART access','Check privilege, address and width',64,292,405,180,C.kernel,C.blue);
 const b=node(s,'Emulated register buffer','Read 0x18, write 0x00 or 0x38',603,292,405,180);
 const c=node(s,'UART output ledger','Append the low byte on a data write',1142,292,394,180);
 link(s,a,b);link(s,b,c);
 text(s,'Checks retained',64,579,420,48,32,C.ink,true);
 text(s,'Output capacity is 4,096 bytes. Invalid offsets and unsupported accesses retain the checked handler.',64,644,700,119,29,C.body);
 text(s,'Observed output',892,579,560,48,32,C.ink,true);
 text(s,'Checked mode matches 92 bytes. Production retains actual output for host comparison.',892,644,644,111,29,C.body);
}
// 10. Editable gateway table.
{
 const s=slide('Remaining context-gateway entries','The checked workload uses 2,381 entries. Syscall entry now accounts for 2,136.',['result','program'],
 'Counts are gateway entries, not instructions or cycles. Memory categories sum to 195: 136 user + 49 explicit user-copy + 5 exclusive entry + 5 completion. Recorded faults=185 overlaps these categories. Inline ERET semantics do not imply a C gateway.');
 const rows=[['Operation','Entries','Current handler role'],['Syscall entry',2136,'Capture state and switch stack'],['Residual ERET',49,'General logical return handler'],['User loads and stores',136,'Checked fallback'],['Explicit user-copy accesses',49,'Checked fallback'],['Exclusive-window entry',5,'Checked grouped access'],['Exclusive-window completion',5,'Complete the grouped access'],['Completion boundary',1,'Stop and validate in checked mode'],['Total',2381,'']];
 const table=s.tables.add({rows:rows.length,columns:3,left:64,top:240,width:1472,height:510,columnWidths:[550,180,742],values:rows});
 table.borders.assign({style:'solid',fill:'#CBD5E1',width:0.6});
 for(let r=0;r<rows.length;r++)for(let c=0;c<3;c++){
 const cell=table.getCell(r,c);cell.fill=r===0?C.ink:r===rows.length-1?C.teal:'#FFFFFF';
 cell.text.style={typeface:font,fontSize:26,color:r===0?'#FFFFFF':C.body,bold:r===0||r===rows.length-1};
 }
 note(s,'Counter inputs, UART and successful generated user returns use inline paths.',792);
}

// 11. Measured instruction costs and distinct validation contracts.
{
 const s=slide('Checked and production instruction costs','Runtime/adaptation instructions inside the same captured execution interval.',['counts','production','optimization'],
 'Checked PROFILE=1 LTO=1: runtime 4465783, interval 7435760, whole ELF 7577710. Production --no-validation --trust-syscall-abi PROFILE=0 LTO=1: runtime 4116488, interval 7088600, whole ELF 7091246. Production live-translation PROFILE=0: runtime 5718553. The 7.82% reduction combines validation removal and disabled profiling. Denominator is 3041214 original kernel operation visits. Production verifies execution completion only.');
 const chart=s.charts.add('bar',{position:{left:100,top:240,width:1400,height:418},categories:['Checked + profiling','Production, live walks','Production, trusted ABI'],series:[{name:'Runtime instructions',values:[4465783,5718553,4116488],valuesFormatCode:'#,##0',fill:C.native}],barOptions:{direction:'column',grouping:'clustered'},hasLegend:false,dataLabels:{showValue:true,position:'outEnd'}});
 applyPresentationChartFont(chart,{fontFamily:font});
 for(const style of [chart.xAxis?.textStyle,chart.yAxis?.textStyle,chart.dataLabels?.textStyle])if(style)style.fontSize=24;
 text(s,'Runtime / original kernel operations: checked 1.4684:1, trusted production 1.3536:1',64,704,1472,48,29,C.ink,true);
 note(s,'Production combines validation removal with PROFILE=0. The 0.20:1 ceiling remains unmet.',780);
}

// 12. Evidence and verification scope.
{
 const s=slide('Validation evidence and production scope','Checked execution validates results. Production establishes execution completion.',['result','counts','production','optimization'],
 `Checked artifact: build/el0-next-slices-20261117a/checkpoint\nSHA-256: ${report.image_sha256}\nProduction artifact: build/el0-production-20261117c/checkpoint\nSHA-256: 18f92609af7457f32d67a45eefe7c4a9110e3f1e6ebfb89ebe1caf4c78399562\nProduction runtime_validation=false, verification_scope=execution-completion. Both consume nine counters and retain 92 actual UART bytes. Original-PC frequencies match 29917 PCs / 3182392 visits. QEMU 9.2.3 TCG Cortex-A53 one vCPU. Native kernel RAM fault recovery and arbitrary address-space replacement are outside admission. Evidence is workload-specific and does not prove all-memory equivalence.`);
 text(s,'Checked image',64,257,710,48,34,C.kernel,true);
 const evidence=['2,272 events match','9 ordered counter inputs','92 UART bytes match','2,381 gateways, 185 faults','0 hardware exceptions or EL1 services'];
 evidence.forEach((t,i)=>text(s,t,64,333+i*75,770,57,31,C.ink,i===0));
 text(s,'Execution-only production',898,257,638,48,34,C.runtime,true);
 text(s,'No event ledger or expected outputs.\nActual UART remains available.\nHost comparison matches checked output.',898,333,638,170,29,C.body);
 text(s,'Trusted ABI assumes register/SP/PC preservation. Live translation is available without that assumption.',898,552,638,143,29,C.body);
 note(s,'All computation remains at EL0 after setup. Instruction counts do not establish cycles or RTL performance.',780);
}


await fs.mkdir(build,{recursive:true});
const candidatePath=path.join(build,'candidate-final.pptx');
await (await PresentationFile.exportPptx(p)).save(candidatePath);
const finalPath=path.join(workspaceDir,'output/osrec-current-el0-flow-assembly-20261117.pptx');
await finalizePresentation({workspaceDir,candidatePath,finalPath,
 pythonExecutable:path.join(runtime,'python/bin/python3'),
 integrityValidatorPath:path.join(skill,'container_tools/inspect_presentation_package_integrity.py'),
 layoutValidatorPath:path.join(skill,'container_tools/inspect_presentation_layout_geometry.py'),
 explicitTotalSlideCount:16,requiredNativeTableOwnerSlides:[14],requiredNativeChartOwnerSlides:[15],
 materializeLiteralChartWorkbooks:true,
 layoutArgs:['--expected-slide-size-emu','15240000,8572500','--validate-bullet-geometry','--validate-heading-fit','--require-native-table-slide','14'],
 fontPolicy,verifyArtifactToolImport:true,receiptPath:path.join(build,'validation-delivery.json')});
console.log('Final:',finalPath,'Font:',font);
const delivered=await PresentationFile.importPptx(await FileBlob.load(finalPath));
for(const [i,s] of delivered.slides.items.entries()){
 const png=await delivered.export({slide:s,format:'png',scale:1});
 await fs.writeFile(path.join(build,`slide-${String(i+1).padStart(2,'0')}.png`),new Uint8Array(await png.arrayBuffer()));
 const layout=await s.export({format:'layout'});await fs.writeFile(path.join(build,`slide-${i+1}.layout.json`),await layout.text());
 console.log('Rendered',i+1);
}
