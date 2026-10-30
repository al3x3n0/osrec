import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {Presentation,PresentationFile} from '@oai/artifact-tool';
const root='/Users/al3x3n0/huawei/osrec';
const workspaceDir=path.join(root,'docs/slides');
const build=path.join(workspaceDir,'.build/image-slices');
const skill='/Users/al3x3n0/.codex/plugins/cache/openai-primary-runtime/presentations/26.909.12148/skills/presentations';
const {resolvePresentationFont,finalizePresentation}=await import(pathToFileURL(path.join(skill,'container_tools/artifact_tool_utils.mjs')));
const font=resolvePresentationFont();
const assets=JSON.parse(await fs.readFile(path.join(build,'assets.json'),'utf8'));
const p=Presentation.create({slideSize:{width:1920,height:1080}});
for(const [i,a] of assets.entries()) {
 const s=p.slides.add();s.background.fill='#F8FAFC';
 const heading=s.shapes.add({geometry:'textbox',position:{left:48,top:26,width:1760,height:78},fill:'none',line:{fill:'none',width:0}});
 heading.text=a.title;heading.text.style={typeface:font,fontSize:48,bold:true,color:'#142735',autoFit:'none'};
 const page=s.shapes.add({geometry:'textbox',position:{left:1830,top:45,width:48,height:38},fill:'none',line:{fill:'none',width:0}});
 page.text=String(i+1).padStart(2,'0');page.text.style={typeface:font,fontSize:25,color:'#475569',autoFit:'none'};
 s.images.add({blob:new Uint8Array(await fs.readFile(a.path)),contentType:'image/png',alt:a.title+' — exact source image crop',fit:'contain',position:{left:32,top:116,width:1856,height:932}});
 s.speakerNotes.textFrame.setText('Source: '+path.join(root,'docs/current-flow.png')+'\n'+a.title+'\nThis slide displays the original diagram or an unchanged crop. The overview retains complete cross-stage connections. Detail crops enlarge the original content without rewriting its labels.');
}
const candidatePath=path.join(build,'candidate.pptx');
await (await PresentationFile.exportPptx(p)).save(candidatePath);
console.log('Exported',assets.length,'slides based on the exact diagram');
await finalizePresentation({workspaceDir,candidatePath,finalPath:path.join(workspaceDir,'output/osrec-current-flow-image-slides-final.pptx'),pythonExecutable:'/Users/al3x3n0/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3',integrityValidatorPath:path.join(skill,'container_tools/inspect_presentation_package_integrity.py'),layoutValidatorPath:path.join(skill,'container_tools/inspect_presentation_layout_geometry.py'),explicitTotalSlideCount:assets.length,requiredNativeTableOwnerSlides:[],layoutArgs:['--expected-slide-size-emu','18288000,10287000','--validate-heading-fit'],fontPolicy:{basis:'design',families:[font]},verifyArtifactToolImport:false,receiptPath:path.join(build,'validation-final.json')});
for(const [i,s] of p.slides.items.entries()) {
 if(![3,5,11].includes(i)) continue;
 const blob=await p.export({slide:s,format:'png',scale:1});
 await fs.writeFile(path.join(build,`slide-${String(i+1).padStart(2,'0')}.png`),new Uint8Array(await blob.arrayBuffer()));
 console.log('Rendered',i+1);
}
