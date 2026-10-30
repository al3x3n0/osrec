import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { Presentation, PresentationFile } from '@oai/artifact-tool';

const skill = '/Users/al3x3n0/.codex/plugins/cache/openai-primary-runtime/presentations/26.909.12148/skills/presentations';
const workspaceDir = '/Users/al3x3n0/huawei/osrec/docs/slides';
const { resolvePresentationFont, finalizePresentation } = await import(pathToFileURL(path.join(skill, 'container_tools/artifact_tool_utils.mjs')));
const family = resolvePresentationFont();
const p = Presentation.create({ slideSize: { width: 1600, height: 900 } });
const s = p.slides.add();
s.background.fill = '#FFFFFF';
function text(value, left, top, width, height, size, color, bold=false) {
  const shape = s.shapes.add({geometry:'textbox',position:{left,top,width,height},fill:'none',line:{fill:'none',width:0}});
  shape.text=value;
  shape.text.style={typeface:family,fontSize:size,color,bold,autoFit:'none'};
  return shape;
}
text('OSREC: CURRENT limitations', 64, 35, 1472, 65, 46, '#142735', true);
text('Standalone replay of selected application and kernel behavior',64,106,1472,45,27,'#475569');
const rows = [
  ['Area', 'CURRENT limitation', 'Future solution (proposed)'],
  ['Kernel coverage', 'Reviewed syscall roots only', 'Expand ports with dependency-closure analysis'],
  ['State coverage', 'Explicit kernel-state projection', 'Generate state footprints and synchronized snapshots'],
  ['Model fidelity', 'Reviewed dependency models', 'Expand original code and compare models with native runs'],
  ['Object ownership', 'Declared objects and buffers only', 'Track object lifetimes and relocate object graphs'],
  ['Concurrency', 'Sequential replay without general IRQ/SMP', 'Record IRQ/scheduling effects and memory observations'],
  ['Application loading', 'Bounded static AArch64 images', 'Add relocation and process address-space support'],
  ['Pause granularity', 'Supported syscall boundaries only', 'Add compiler safe points and stack restoration'],
  ['Build compatibility', 'Exact construction identity required', 'Prove compatibility for explicit schema migrations'],
  ['Validation scope', 'QEMU functional checks only', 'Add RTL execution and cycle-level comparison']
];
const table = s.tables.add({rows:rows.length,columns:3,left:64,top:175,width:1472,height:600,columnWidths:[255,505,712],values:rows});
table.styleOptions={headerRow:false,bandedRows:false};
table.borders.assign({fill:'#E2E8F0',width:0.7,style:'solid'});
table.cells.block({row:0,column:0,rowCount:rows.length,columnCount:3}).assign({
  textStyle:{typeface:family,fontSize:24,color:'#243447',autoFit:'none'},
  margins:{left:16,right:16,top:9,bottom:9},anchor:'center'
});
for(let r=0;r<rows.length;r++) {
  table.rows[r].height=60;
  for(let c=0;c<3;c++) {
    const cell=table.getCell(r,c);
    cell.fill=r===0?'#142735':(r%2===0?'#F8FAFC':'#FFFFFF');
    cell.text.style={typeface:family,fontSize:24,color:r===0?'#FFFFFF':c===2?'#1D4F91':'#243447',bold:r===0||c===0,autoFit:'none'};
  }
}
text('Future solutions are development proposals. Each extension requires a defined replay contract and validation.',64,809,1472,52,24,'#475569');
s.speakerNotes.textFrame.setText(`Current limitations reflect the implemented bounded capture-and-replay scheme in this repository. Future solutions are proposed development directions, not implemented capabilities or committed delivery dates.\n\nSources: docs/design.md; docs/application-checkpoints.md (Current boundaries); docs/elf-checkpoint-chains.md; docs/entry-state-analysis.md; docs/context-object-graphs.md; docs/context-buffer-references.md; docs/initialized-context-state.md; tools/contextify_slice.py; tools/slice_checkpoint_codec.py.\n\nCoverage expands through reviewed roots and conservative dependency analysis. State discovery should retain blockers and explicit ownership/lifetime contracts. Model fidelity requires validating return values and observable effects, preferably against the same native build. Object relocation requires IDs, generations and supported lifetimes. Concurrency needs more than a schedule trace: shared-memory observations and included handler effects remain necessary. Additional pause boundaries need a supported stack and CPU-state restoration contract. Exact-build identity remains the default; migration needs an explicit proven compatibility relation. Functional QEMU checks do not establish timing equivalence.\n\nProposal order: first improve coverage, state discovery and native differential validation. Then extend object lifetimes, loading and safe points. General IRQ/SMP reproduction and cycle validation remain separate milestones.`);
const candidatePath=path.join(workspaceDir,'.build/candidate.pptx');
await (await PresentationFile.exportPptx(p)).save(candidatePath);
await finalizePresentation({workspaceDir,candidatePath,finalPath:path.join(workspaceDir,'output/osrec-current-limitations-v2.pptx'),
  pythonExecutable:'/Users/al3x3n0/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3',
  integrityValidatorPath:path.join(skill,'container_tools/inspect_presentation_package_integrity.py'),
  layoutValidatorPath:path.join(skill,'container_tools/inspect_presentation_layout_geometry.py'),
  explicitTotalSlideCount:1,requiredNativeTableOwnerSlides:[1],
  layoutArgs:['--expected-slide-size-emu','15240000,8572500','--validate-bullet-geometry','--validate-heading-fit','--require-native-table-slide','1'],
  fontPolicy:{basis:'design',families:[family]},verifyArtifactToolImport:false,
  receiptPath:path.join(workspaceDir,'.build/validation-v2.json')});
const preview=await p.export({slide:s,format:'png',scale:1.5});
await fs.writeFile(path.join(workspaceDir,'output/osrec-current-limitations-v2.png'),new Uint8Array(await preview.arrayBuffer()));
console.log('Created editable slide and PNG preview, font:',family);
