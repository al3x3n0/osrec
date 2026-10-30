import fs from 'node:fs/promises';
import {FileBlob, PresentationFile} from '@oai/artifact-tool';
const base='/Users/al3x3n0/huawei/osrec/docs/slides/output/osrec-current-limitations-v2';
const p=await PresentationFile.importPptx(await FileBlob.load(base+'.pptx'));
const image=await p.export({slide:p.slides.items[0],format:'png',scale:1.5});
await fs.writeFile(base+'.png',new Uint8Array(await image.arrayBuffer()));
console.log('Rendered final PPTX');
