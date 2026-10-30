"""Explicit-context kernel slices: native capture contract, app mappings and isolation."""
import hashlib,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from export_syscall_slices import export,validate_port,dispatch_header
from contextify_slice import transform
from freestanding_armv7 import run,audit
from freestanding_elf import prepare_target
from run_freestanding_armv7 import observe,require_success
from rtl_load_bundle import prepare
from rtl_boot_bundle import prepare as prepare_boot
from verify_qemu_bundle import verify
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');KERNEL=ROOT/'build/kernel_liteos_a';QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/files-native'

def options(stage,entry=0x40200000,result=0x40180000):
    return SimpleNamespace(arch='aarch64',capture=FIXTURE,kernel_root=KERNEL,out=stage/'image',port=ROOT/'integrations/liteos_a/files-slice-port.json',llvm_bin=LLVM,qemu=QEMU,entry_address=entry,result_address=result)

class CallableTests(unittest.TestCase):
    def test_returning_sessions_bundles_and_mutations(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);a=options(stage);report=export(a);r=report['target_observations']
            self.assertEqual(r['completed_calls'],96);self.assertEqual(r['divergences_returned'],1)
            self.assertGreater(report['state_layout']['OSREC_SLICE_STATE_BYTES'],0)
            self.assertTrue((a.out/'slices.a').is_file())
            members=run([LLVM/'llvm-ar','t',a.out/'slices.a']).stdout
            self.assertNotIn('slice_driver.o',members);self.assertIn('slice_adapter.o',members)
            symbols=run([LLVM/'llvm-nm','--defined-only',a.out/'slices.a']).stdout
            self.assertIn('osrec_kernel_SysRead',symbols);self.assertIn('osrec_slice_execute',symbols)
            plan=report['context_plan'];self.assertEqual(len(plan['owned_state']),28);self.assertEqual(len(plan['context_functions']),48)
            self.assertIn('memset',plan['pure_functions']);self.assertIn('GetPath',plan['context_functions'])
            text=(a.out/'sources/files_syscalls.c').read_text();self.assertIn('osrec_kernel_LOS_MuxAcquire(ctx, &',text)
            expected=(a.out/'target-result.bin').read_bytes()
            for raw in (False,True):
                replay=stage/('raw' if raw else 'elf');prepare(a.out/'slices.elf',[{'address':0x40000000,'bytes':64*1024*1024}],replay,a.out/'slices.bin' if raw else None)
                boot=stage/(replay.name+'-boot');prepare_boot(replay,boot,LLVM)
                for bundle,label in ((replay,'el1'),(boot,'el3')):
                    evidence=stage/(replay.name+'-'+label);self.assertEqual(verify(bundle,evidence,QEMU)['status'],'verified');self.assertEqual((evidence/'target-result.bin').read_bytes(),expected)
            sources=a.out/'sources';adapter=sources/'slice_adapter.c';original=adapter.read_text()
            mutations=[('ctx->invocation=(uint32_t)in->ordinal;ctx->error=0;','osrec_context_restore(ctx);ctx->invocation=(uint32_t)in->ordinal;ctx->error=0;'),
                ('ctx->witness=next_witness;','ctx->witness=next_witness;ctx->state[9]=99;'),
                ('if(value!=expected && value!=canonical)','if(value==expected || value==canonical)'),
                ('ctx->return_hash=(ctx->return_hash^','ctx->return_hash=(ctx->return_hash+'),
                ('ctx->state[0]=UINT32_MAX;','ctx->state[0]=0;')]
            compiled=[sources/n for n in ('files_models.c','files_syscalls.c','slice_adapter.c','slice_checkpoint.c','slice_runtime.c','slice_bytes.c','slice_guard.S','slice_driver.c')]
            for old,new in mutations:
                with self.subTest(old=old):
                    self.assertIn(old,original);adapter.write_text(original.replace(old,new,1));elf=stage/'bad.elf'
                    run([LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-std=c11','-O1','-ffreestanding','-fno-builtin','-I'+str(sources),'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',*compiled,'-o',elf]);audit(elf,LLVM)
                    observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],3)
                    with self.assertRaises(ValueError):require_success(observed)

    def test_kernel_independent_64bit_macro_and_alias_context(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);sources=stage/'sources';sources.mkdir();a=options(stage);flags=prepare_target(a,sources)
            (sources/'toy.h').write_text('#ifndef OSREC_TOY_H\n#define OSREC_TOY_H\n#include <stdint.h>\ntypedef struct {uint64_t value;} Object;\nuint64_t Provider(uint64_t);\nuint64_t Root(uint64_t);\n#define CALL_PROVIDER(n) Provider(n)\n#endif\n')
            (sources/'model.c').write_text('#include "toy.h"\nstatic uint64_t counter;\nstatic Object object;\nstatic Object *alias=&object;\nuint64_t Provider(uint64_t n){counter+=n;alias->value++;return counter ^ alias->value;}\n')
            (sources/'kernel.c').write_text('#include "toy.h"\nuint64_t Root(uint64_t n){return CALL_PROVIDER(n);}\n')
            plan=transform(sources,['model.c','kernel.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
            self.assertEqual(plan['context_functions'],['Provider','Root']);self.assertEqual({s['name'] for s in plan['owned_state']},{'counter','object','alias'})
            driver='''#include "slice_context.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static struct osrec_kernel_context a,b;
static void stop(void){for(;;)__asm__ volatile("wfe");}
void replay_fault(void){osrec_result[3]=99;osrec_result[2]=3;stop();}
void replay_main(void){osrec_result[0]=0x4f535243;osrec_result[1]=18;osrec_context_restore(&a);osrec_context_restore(&b);
 uint64_t x=osrec_kernel_Root(&a,UINT64_C(0x100000001)),y=osrec_kernel_Root(&b,7),z=osrec_kernel_Root(&a,3);
 if(x!=UINT64_C(0x100000000) || y!=6 || z!=UINT64_C(0x100000006) || a.alias!=&a.object || b.alias!=&b.object || b.counter!=7){osrec_result[3]=1;osrec_result[2]=3;stop();}
 osrec_context_restore(&a);if(a.counter || a.object.value || a.alias!=&a.object || b.counter!=7){osrec_result[3]=2;osrec_result[2]=3;stop();}
 osrec_result[4]=3;osrec_result[5]=(uint32_t)(x>>32);osrec_result[6]=(uint32_t)y;osrec_result[7]=(uint32_t)z;osrec_result[2]=2;stop();}
'''
            (sources/'driver.c').write_text(driver);elf=stage/'toy.elf'
            run([LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-I'+str(ROOT/'include'),'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'model.c',sources/'kernel.c',sources/'driver.c','-o',elf])
            audit(elf,LLVM);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],2);self.assertEqual(observed['completed_calls'],3);self.assertEqual(observed['call_count'],1);self.assertEqual(observed['verified_calls'],6);self.assertEqual(observed['interleaved_calls'],6)

    def test_unsupported_context_and_port_rejected(self):
        cases=['uint64_t Root(uint64_t n){static _Thread_local uint64_t state;return state+=n;}',
            'uint64_t Root(uint64_t n){static volatile uint64_t state;return state+=n;}',
            'uint64_t Root(uint64_t n){static uint64_t state __attribute__((aligned(64)));return state+=n;}',
            'uint64_t Root(uint64_t n){typedef uint64_t Local;static Local state;return state+=n;}',
            'uint64_t Root(uint64_t n){typedef uint64_t Local;static Local *state;return state!=0 ? n : 0;}',
            'uint64_t Root(uint64_t n){struct Local {uint64_t value;};static struct Local state;return state.value+=n;}',
            'uint64_t Root(uint64_t n){enum Local {SEED=7};static enum Local state=SEED;return state+=n;}',
            'static volatile uint64_t state;uint64_t Root(uint64_t n){return state+=n;}',
            'static _Thread_local uint64_t state;uint64_t Root(uint64_t n){return state+=n;}',
            'static uint64_t state;static uint64_t f(uint64_t n){return state+=n;}uint64_t Root(uint64_t n){uint64_t (*p)(uint64_t)=f;return p(n);}',
            'static uint64_t state;static uint64_t f(uint64_t n){return state+=n;}uint64_t Root(uint64_t n){uint64_t (*p)(uint64_t)=f;(void)p;return f(n);}']
        for text in cases:
            with self.subTest(text=text),tempfile.TemporaryDirectory() as name:
                s=Path(name);(s/'toy.h').write_text('#include <stdint.h>\nuint64_t Root(uint64_t);\n');(s/'kernel.c').write_text('#include "toy.h"\n'+text)
                with self.assertRaises(ValueError):transform(s,['kernel.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
        port=json.loads((ROOT/'integrations/liteos_a/files-slice-port.json').read_text())
        for key,value in (('argument_width',16),('target_isa','x86_64'),('capture_adapter','../module'),('name','../port')):
            bad=dict(port);bad[key]=value
            with self.assertRaises(ValueError):validate_port(bad)
        bad=dict(port);bad['roots']=[port['roots'][0],port['roots'][0]]
        with self.assertRaises(ValueError):validate_port(bad)

    def test_initialized_arrays_designators_cycles_and_private_constants(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(options(stage),sources)
            (sources/'toy.h').write_text('''#ifndef OSREC_SEEDED_H
#define OSREC_SEEDED_H
#include <stdint.h>
typedef struct Node {uint64_t value;struct Node *next;uint64_t *word;} Node;
uint64_t Provider(uint64_t);
uint64_t Root(uint64_t);
uint64_t Cross(uint64_t);
#define CALL_PROVIDER(n) Provider(n)
#endif
''')
            (sources/'model.c').write_text('''#include "toy.h"
enum {SEED=13};
#define BYTE_SEED 17
uint64_t values[4]={[2]=7,[3]=9};
static Node nodes[3]={[0]={.value=UINT64_C(0x100000001),.next=&nodes[2],.word=&values[2]},[2]={.value=5,.next=&nodes[0],.word=&values[3]}};
static uint64_t *links[3]={[2]=&nodes[2].value};
static char label[]="A;B";
static uint8_t matrix[2][3]={[1]={[2]=11}};
static uint32_t private_values[]={SEED,BYTE_SEED};
uint64_t Provider(uint64_t n){uint64_t *local[3]={[2]=links[2]};*local[2]+=n;*nodes[0].word+=n;++label[0];++matrix[1][2];++private_values[0];return *links[2]+values[2];}
''')
            (sources/'kernel.c').write_text('#include "toy.h"\nextern uint64_t values[];\nuint64_t Root(uint64_t n){return CALL_PROVIDER(n);}\nuint64_t Cross(uint64_t n){uint64_t *local[3]={[2]=&values[3]};return *local[2]+n;}\n')
            plan=transform(sources,['model.c','kernel.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
            self.assertEqual(plan['context_functions'],['Cross','Provider','Root'])
            self.assertEqual([f['name'] for f in plan['array_initializers']],['values','nodes','links','label','matrix','private_values'])
            driver='''#include "slice_context.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static struct osrec_kernel_context a,b;
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(unsigned n){osrec_result[3]=n;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
static void initial(const struct osrec_kernel_context *c){
if(c->values[0] || c->values[1] || c->values[2]!=7 || c->values[3]!=9 || c->nodes[0].value!=UINT64_C(0x100000001) || c->nodes[2].value!=5 || c->nodes[1].value || c->nodes[1].next || c->nodes[1].word)fail(1);
if(c->nodes[0].next!=&c->nodes[2] || c->nodes[2].next!=&c->nodes[0] || c->nodes[0].word!=&c->values[2] || c->nodes[2].word!=&c->values[3] || c->links[0] || c->links[1] || c->links[2]!=&c->nodes[2].value)fail(2);
if(c->label[0]!='A' || c->label[1]!=';' || c->label[2]!='B' || c->label[3] || c->private_values[0]!=13 || c->private_values[1]!=17)fail(3);
for(unsigned i=0;i<2;++i)for(unsigned j=0;j<3;++j)if(c->matrix[i][j]!=(i==1 && j==2 ? 11 : 0))fail(4);}
void replay_main(void){osrec_result[0]=0x4f535243;osrec_result[1]=18;
osrec_context_restore(&a);osrec_context_restore(&b);initial(&a);initial(&b);
if(osrec_kernel_Cross(&a,3)!=12 || osrec_kernel_Cross(&b,1)!=10)fail(9);
if(osrec_kernel_Root(&a,3)!=18)fail(5);initial(&b);
if(osrec_kernel_Root(&b,1)!=14 || osrec_kernel_Root(&a,4)!=26)fail(6);
if(a.values[2]!=14 || b.values[2]!=8 || a.label[0]!='C' || b.label[0]!='B' || a.matrix[1][2]!=13 || b.matrix[1][2]!=12 || a.private_values[0]!=15 || b.private_values[0]!=14)fail(7);
osrec_context_restore(&a);initial(&a);if(b.values[2]!=8 || b.nodes[2].value!=6 || b.nodes[0].next!=&b.nodes[2] || b.nodes[2].next!=&b.nodes[0])fail(8);
osrec_result[4]=3;osrec_result[2]=2;stop();}
'''
            (sources/'driver.c').write_text(driver);elf=stage/'seeded.elf'
            command=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-I'+str(ROOT/'include'),'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'model.c',sources/'kernel.c',sources/'driver.c','-o',elf]
            run(command);audit(elf,LLVM);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],2);self.assertEqual(observed['completed_calls'],3)
            # An omitted reconstruction helper must be visible to the target
            # proof, rather than silently falling back to zero-filled state.
            header=sources/'slice_context.h';text=header.read_text();header.write_text(text.replace('    osrec_kernel_restore_array_0(ctx);',''))
            run(command);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],3)

    def test_initialized_values_preserve_private_scope_and_complete_macros(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(options(stage),sources)
            (sources/'toy.h').write_text('''#ifndef OSREC_VALUE_SEEDS_H
#define OSREC_VALUE_SEEDS_H
#include <stdint.h>
typedef struct Node {uint64_t value;uint64_t *word;struct Node *next;uint32_t parts[3];} Node;
uint64_t Left(uint64_t);
uint64_t Right(uint64_t);
uint64_t Root(uint64_t);
#endif
''')
            (sources/'left').mkdir();(sources/'right').mkdir()
            (sources/'left/model.c').write_text('''#include "toy.h"
enum {SEED=13};
#define VALUE(a,b) (UINT64_C(0x100000000)+(a)+(b))
#define OTHER UINT64_C(0x200000003)
#define REFERENCE(n) (&(n))
static const uint64_t read_only_seed=5;
static uint64_t counter=VALUE(SEED, /* ;,)] */ 3), other=OTHER;
static Node node={.value=read_only_seed+SEED,.word=&counter,.next=&node,.parts={[2]=(uint32_t)VALUE(1,2)}};
static Node *current=REFERENCE(node);
static const uint64_t *salt=&read_only_seed;
static const char *text="A;,/*)*/B";
uint64_t Left(uint64_t n){*current->word+=n;current->value+=n;other^=n;return *current->word+current->value;}
''')
            # The same private enum/macro/object names have different values
            # in the other TU and must never leak into a shared header.
            (sources/'right/model.c').write_text('''#include "toy.h"
enum {SEED=23};
#define VALUE(a,b) (UINT64_C(0x200000000)+(a)+(b))
static uint64_t counter=VALUE(SEED,0);
uint64_t Right(uint64_t n){counter+=3*n;return counter;}
''')
            (sources/'entry.c').write_text('#include "toy.h"\nuint64_t Root(uint64_t n){return Left(n)+Right(n);}\n')
            names=['left/model.c','right/model.c','entry.c'];plan=transform(sources,names,['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
            self.assertEqual([f['name'] for f in plan['value_initializers']],['osrec_private_0_counter','other','node','current','salt','text','osrec_private_1_counter'])
            self.assertEqual([f['source'] for f in plan['value_initializers']],['left/model.c']*6+['right/model.c'])
            header=sources/'slice_context.h';original=header.read_text()
            for private in ('VALUE(', 'OTHER', 'SEED', 'read_only_seed'):self.assertNotIn(private,original)
            driver='''#include "slice_context.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static struct osrec_kernel_context a,b;
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(unsigned n){osrec_result[3]=n;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
static void initial(const struct osrec_kernel_context *c){
if(c->osrec_private_0_counter!=UINT64_C(4294967312) || c->osrec_private_1_counter!=UINT64_C(8589934615) || c->other!=UINT64_C(8589934595))fail(1);
if(c->node.value!=18 || c->node.word!=&c->osrec_private_0_counter || c->node.next!=&c->node || c->current!=&c->node || c->node.parts[0] || c->node.parts[1] || c->node.parts[2]!=3)fail(2);
if(!c->salt || *c->salt!=5 || !c->text || c->text[0]!='A' || c->text[1]!=';' || c->text[2]!=',' || c->text[8]!='B' || c->text[9])fail(3);}
void replay_main(void){osrec_result[0]=0x4f535243;osrec_result[1]=18;
osrec_context_restore(&a);osrec_context_restore(&b);initial(&a);initial(&b);
if(osrec_kernel_Root(&a,2)!=UINT64_C(12884901955))fail(4);initial(&b);
if(osrec_kernel_Root(&b,1)!=UINT64_C(12884901950) || osrec_kernel_Root(&a,3)!=UINT64_C(12884901970))fail(5);
if(a.node.word!=&a.osrec_private_0_counter || b.node.word!=&b.osrec_private_0_counter || a.node.value!=23 || b.node.value!=19)fail(6);
osrec_context_restore(&a);initial(&a);if(b.osrec_private_0_counter!=UINT64_C(4294967313) || b.node.value!=19 || b.node.next!=&b.node)fail(7);
osrec_result[4]=3;osrec_result[2]=2;stop();}
'''
            (sources/'driver.c').write_text(driver);elf=stage/'value-seeds.elf'
            command=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-I'+str(sources),'-I'+str(ROOT/'include'),'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',*[sources/n for n in names],sources/'driver.c','-o',elf]
            run(command);audit(elf,LLVM);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],2);self.assertEqual(observed['completed_calls'],3)
            for seed in ('osrec_private_0_counter','node'):
                helper=next(f['function'] for f in plan['value_initializers'] if f['name']==seed)
                with self.subTest(omitted=seed):
                    header.write_text(original.replace('    '+helper+'(ctx);',''));run(command);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],3)
            header.write_text(original)

    def test_mixed_readonly_and_owned_declarations_keep_constants(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(options(stage),sources)
            (sources/'toy.h').write_text('#include <stdint.h>\nuint64_t Root(uint64_t);\n')
            (sources/'kernel.c').write_text('''#include "toy.h"
static const uint64_t seed=13,bias=7,*alias=&seed,*bias_alias=&bias;
static const uint64_t zeros[2],*zero_alias=&zeros[1];
static uint64_t counter;
uint64_t Root(uint64_t n){
 static const uint64_t block_seed=5,*local_alias=&seed;
 if(*bias_alias!=7 || *zero_alias || *local_alias!=13)return UINT64_MAX;
 counter+=n;alias=(counter&1) ? &bias : &seed;
 return counter+*alias+block_seed;
}
''')
            plan=transform(sources,['kernel.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
            self.assertEqual([f['name'] for f in plan['owned_state']],['alias','bias_alias','zero_alias','counter','osrec_local_Root_local_alias_0'])
            retained=plan['retained_declarations'];self.assertEqual([f['declaration'] for f in retained],['seed','bias','zeros','block_seed'])
            self.assertEqual([f.get('function') for f in retained],[None,None,None,'Root'])
            self.assertTrue(all(f['source']=='kernel.c' and f['offset']>=0 for f in retained))
            driver='''#include "slice_context.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static struct osrec_kernel_context a,b;
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(unsigned n){osrec_result[3]=n;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
static void initial(const struct osrec_kernel_context *c){if(c->counter || !c->alias || *c->alias!=13 || *c->bias_alias!=7 || *c->zero_alias || *c->osrec_local_Root_local_alias_0!=13)fail(1);}
void replay_main(void){osrec_result[0]=0x4f535243;osrec_result[1]=18;
osrec_context_restore(&a);osrec_context_restore(&b);initial(&a);initial(&b);
if(osrec_kernel_Root(&a,2)!=20)fail(2);initial(&b);
if(osrec_kernel_Root(&b,1)!=13 || osrec_kernel_Root(&a,3)!=17)fail(3);
if(a.counter!=5 || b.counter!=1 || *a.alias!=7 || *b.alias!=7)fail(4);
osrec_context_restore(&a);initial(&a);if(b.counter!=1 || *b.alias!=7 || osrec_kernel_Root(&b,1)!=20)fail(5);
osrec_result[4]=4;osrec_result[2]=2;stop();}
'''
            (sources/'driver.c').write_text(driver);elf=stage/'mixed-declarations.elf'
            command=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-I'+str(ROOT/'include'),'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'kernel.c',sources/'driver.c','-o',elf]
            run(command);audit(elf,LLVM);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],2);self.assertEqual(observed['completed_calls'],4)
            source=sources/'kernel.c';text=source.read_text();self.assertIn('static const uint64_t seed = 13;',text)
            source.write_text(text.replace('static const uint64_t seed = 13;','static const uint64_t seed = 99;'))
            run(command);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],3)
        cases=[
            'static uint64_t counter;static const Record seed={.word=&counter},*alias=&seed;uint64_t Root(uint64_t n){return *alias->word+n;}',
            '_Alignas(32) static const uint64_t seed=13,*alias=&seed;uint64_t Root(uint64_t n){return *alias+n;}',
            'static const struct Local {uint64_t value;} seed={13},*alias=&seed;uint64_t Root(uint64_t n){return alias->value+n;}'
        ]
        for body in cases:
            with self.subTest(body=body),tempfile.TemporaryDirectory() as name:
                sources=Path(name);(sources/'toy.h').write_text('#include <stdint.h>\ntypedef struct {uint64_t *word;} Record;\nuint64_t Root(uint64_t);\n')
                (sources/'kernel.c').write_text('#include "toy.h"\n'+body)
                with self.assertRaises(ValueError):transform(sources,['kernel.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
                self.assertEqual((sources/'kernel.c').read_text(),'#include "toy.h"\n'+body);self.assertFalse((sources/'slice_context.h').exists())

    def test_local_readonly_seeds_preserve_identity_scope_and_reset(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(options(stage),sources)
            (sources/'toy.h').write_text('#include <stdint.h>\nuint64_t Root(uint64_t);\nuint64_t Other(uint64_t);\n')
            (sources/'kernel.c').write_text('''#include "toy.h"
#define VALUE(a,b) ((a)+(b))
#define ROOT_SEED seed
uint64_t Root(uint64_t n){
 static const uint64_t base=10;
 static const uint64_t seed=VALUE(base,3),unused=seed+1,*alias=&seed;
 static const uint64_t words[3]={[2]=7},*word=&words[2];
 static const uint64_t zeros[2],*zero=&zeros[1];
 static const char label[]="A;,/*)*/B";
 static const char *text=label;
 static uint64_t state=seed;
 uint64_t extra;
 {static const uint64_t seed=23,*alias=&seed;
  if(alias!=&seed || *alias!=23)return UINT64_MAX;extra=*alias;}
 if(alias!=&seed || ROOT_SEED!=13 || word!=&words[2] || zero!=&zeros[1] || *zero || text!=label || text[8]!='B' || unused!=14)return UINT64_MAX;
 state+=n;return state+*alias+*word+extra;
}
''')
            (sources/'other.c').write_text('''#include "toy.h"
uint64_t Other(uint64_t n){static const uint64_t seed=31,*alias=&seed;static uint64_t state=seed;
 if(alias!=&seed)return UINT64_MAX;state+=n;return state+*alias;}
''')
            plan=transform(sources,['kernel.c','other.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
            lifted=plan['lifted_constants'];self.assertEqual([(f['source'],f['declaration']) for f in lifted],[('kernel.c',n) for n in ('base','seed','words','zeros','label','seed')]+[('other.c','seed')])
            self.assertEqual(len({f['symbol'] for f in lifted}),7)
            self.assertEqual([f['declaration'] for f in plan['retained_declarations']],['unused'])
            self.assertFalse(any('local_constant_' in f['name'] for f in plan['owned_state']))
            driver='''#include "slice_context.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static struct osrec_kernel_context a,b;
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(unsigned n){osrec_result[3]=n;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
void replay_main(void){osrec_result[0]=0x4f535243;osrec_result[1]=18;
osrec_context_restore(&a);osrec_context_restore(&b);
if(osrec_kernel_Root(&a,2)!=58 || osrec_kernel_Other(&a,3)!=65)fail(1);
if(osrec_kernel_Root(&b,1)!=57 || osrec_kernel_Other(&b,1)!=63 || osrec_kernel_Root(&a,4)!=62)fail(2);
if(a.osrec_local_Root_alias_0!=b.osrec_local_Root_alias_0 || a.osrec_local_Root_state_4!=19 || b.osrec_local_Root_state_4!=14 || a.osrec_local_Other_state_1!=34 || b.osrec_local_Other_state_1!=32)fail(3);
osrec_context_restore(&a);
if(osrec_kernel_Root(&a,0)!=56 || osrec_kernel_Other(&a,0)!=62 || osrec_kernel_Root(&b,3)!=60 || osrec_kernel_Other(&b,2)!=65)fail(4);
osrec_result[4]=9;osrec_result[2]=2;stop();}
'''
            (sources/'driver.c').write_text(driver);elf=stage/'local-readonly.elf'
            command=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-I'+str(ROOT/'include'),'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'kernel.c',sources/'other.c',sources/'driver.c','-o',elf]
            run(command);audit(elf,LLVM);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],2);self.assertEqual(observed['completed_calls'],9)
            source=sources/'kernel.c';text=source.read_text();symbol=lifted[1]['symbol'];self.assertIn('&'+symbol,text)
            source.write_text(text.replace('ctx->osrec_local_Root_alias_0!=&'+symbol,'ctx->osrec_local_Root_alias_0!=&'+lifted[5]['symbol']))
            self.assertNotEqual(source.read_text(),text);run(command);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],3)
        cases=[
            'uint64_t Root(uint64_t n){typedef uint64_t Local;static const Local seed=13;static const Local *alias=&seed;return *alias+n;}',
            'uint64_t Root(uint64_t n){struct Local {uint64_t value;};static const struct Local seed={13},*alias=&seed;return alias->value+n;}',
            'uint64_t Root(uint64_t n){enum {BASE=13};static const uint64_t seed=BASE,*alias=&seed;return *alias+n;}',
            'uint64_t Root(uint64_t n){typedef uint64_t Local;static const uint64_t seed=(Local)13,*alias=&seed;return *alias+n;}',
            'uint64_t Root(uint64_t n){typedef uint64_t Local;static const uint64_t seed=sizeof(Local),*alias=&seed;return *alias+n;}',
            'uint64_t Root(uint64_t n){\n#define SEED 13\nstatic const uint64_t seed=SEED,*alias=&seed;return *alias+n;}',
            'uint64_t Root(uint64_t n){static const uint64_t seed __attribute__((aligned(32)))=13;static const uint64_t *alias=&seed;return *alias+n;}',
            'static uint64_t state;uint64_t Root(uint64_t n){static const Record seed={.word=&state},*alias=&seed;return *alias->word+n;}',
            'uint64_t Root(uint64_t n){static uint64_t state;static const Record seed={.word=&state},*alias=&seed;return *alias->word+n;}',
            '#define REF(x) (&x)\n#define BAD (&seed)\nuint64_t Root(uint64_t n){static const uint64_t seed=13;static const uint64_t *alias=BAD;return *alias+n;}',
            '#define GET seed\nuint64_t Root(uint64_t n){static const uint64_t seed=13,*alias=&seed;return *alias+GET+n;}uint64_t Other(uint64_t n){static const uint64_t seed=31;return GET+n;}',
            'static const uint64_t osrec_kernel_local_constant_Root_seed_0=1;uint64_t Root(uint64_t n){static const uint64_t seed=13,*alias=&seed;return *alias+n;}'
        ]
        for body in cases:
            with self.subTest(body=body),tempfile.TemporaryDirectory() as name:
                sources=Path(name);header='#include <stdint.h>\ntypedef struct {uint64_t *word;} Record;\nuint64_t Root(uint64_t);\n';(sources/'toy.h').write_text(header)
                original='#include "toy.h"\n'+body;(sources/'kernel.c').write_text(original)
                with self.assertRaises(ValueError):transform(sources,['kernel.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
                self.assertEqual((sources/'kernel.c').read_text(),original);self.assertEqual((sources/'toy.h').read_text(),header);self.assertFalse((sources/'slice_context.h').exists())

    def test_utf8_sources_byte_offsets_crlf_and_bom(self):
        header='''#ifndef BYTE_MODEL_H
#define BYTE_MODEL_H
/* 类型 é🙂 */
#include <stdint.h>
typedef uint64_t Число;
uint64_t Root(uint64_t);
uint64_t Other(void);
#define ADD(n) Шаг(n)
#endif
'''
        source='''/* 状态 é🙂 */
#include "toy.h"
static Число счёт=7;
static unsigned char words[]= // 初值 ; }
 "核;é🙂";
static const unsigned char fixed[]="源;,/*)*/🙂",*file_alias=fixed;
static Число *link=&счёт;
static Число Шаг(Число n){счёт+=n;++words[0];return счёт+words[1];}
uint64_t Root(uint64_t n){
 static const unsigned char 種[]="会;🙂",*alias=種;
 static Число calls;
 ++calls;if(file_alias!=fixed || alias!=種)return UINT64_MAX;
 return ADD(n)+calls;
}
uint64_t Other(void){return счёт+*link;}
/* End 路径 */
'''
        for newline,bom in (('\n',b''),('\r\n',b''),('\r',b''),('\r\n',b'\xef\xbb\xbf')):
            with self.subTest(newline=repr(newline),bom=bool(bom)),tempfile.TemporaryDirectory() as name:
                stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(options(stage),sources)
                original={n:bom+text.replace('\n',newline).encode('utf-8') for n,text in (('toy.h',header),('kernel.c',source))}
                for n,raw in original.items():(sources/n).write_bytes(raw)
                if newline=='\n':
                    # Clang emits UTF-8 AST names even on an ASCII host locale.
                    # Exercise a fresh interpreter with locale coercion and
                    # Python UTF-8 mode disabled, then verify the guest below.
                    script='import sys,codecs,locale;from pathlib import Path;sys.path.insert(0,sys.argv[2]);from contextify_slice import transform;assert codecs.lookup(locale.getencoding()).name=="ascii";transform(Path(sys.argv[1]),["kernel.c"],["toy.h"],Path(sys.argv[3]),include_dirs=[Path(sys.argv[4])])'
                    env=dict(os.environ,LC_ALL='C',PYTHONUTF8='0',PYTHONCOERCECLOCALE='0')
                    result=subprocess.run([sys.executable,'-X','utf8=0','-c',script,str(sources),str(ROOT/'tools'),str(LLVM/'clang'),str(ROOT/'include')],env=env,capture_output=True,timeout=60)
                    self.assertEqual(result.returncode,0,result.stderr.decode('utf-8',errors='replace'))
                    plan=json.loads((sources/'context-plan.json').read_bytes())
                else:plan=transform(sources,['kernel.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
                self.assertEqual(plan['input_sha256'],{n:hashlib.sha256(raw).hexdigest() for n,raw in original.items()})
                self.assertEqual((plan['source_encoding'],plan['source_offsets']),('utf-8','bytes'))
                self.assertEqual(plan['symbols']['Шаг'],'osrec_kernel_Шаг')
                self.assertIn({'name':'счёт','type':'Число'},plan['owned_state'])
                self.assertEqual(plan['retained_declarations'][0]['offset'],original['kernel.c'].index(b'fixed[]'))
                self.assertEqual(plan['lifted_constants'][0]['offset'],original['kernel.c'].index('種'.encode('utf-8')))
                rewritten=(sources/'kernel.c').read_bytes();self.assertTrue(rewritten.startswith(bom+b'#include "slice_context.h"\n'));self.assertTrue(rewritten.endswith(('/* End 路径 */'+newline).encode('utf-8')))
                self.assertTrue((sources/'toy.h').read_bytes().startswith(bom+b'struct osrec_kernel_context;\n'))
                self.assertIn(('/* 类型 é🙂 */'+newline).encode('utf-8'),(sources/'toy.h').read_bytes())
                rewritten.decode('utf-8')
                values=lambda text:','.join(str(n) for n in text.encode('utf-8')+b'\0')
                driver='''#include "slice_context.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static struct osrec_kernel_context a,b;
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(unsigned n){osrec_result[3]=n;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
static void initial(const struct osrec_kernel_context *c){
const unsigned char words[]={WORDS},fixed[]={FIXED},seed[]={SEED};
if(c->счёт!=7 || c->link!=&c->счёт || c->osrec_local_Root_calls_1)fail(1);
for(unsigned i=0;i<sizeof words;++i)if(c->words[i]!=words[i])fail(2);
for(unsigned i=0;i<sizeof fixed;++i)if(c->file_alias[i]!=fixed[i])fail(3);
for(unsigned i=0;i<sizeof seed;++i)if(c->osrec_local_Root_alias_0[i]!=seed[i])fail(4);}
void replay_main(void){osrec_result[0]=0x4f535243;osrec_result[1]=18;
osrec_context_restore(&a);osrec_context_restore(&b);initial(&a);initial(&b);
if(osrec_kernel_Root(&a,2)!=170 || osrec_kernel_Root(&b,1)!=169 || osrec_kernel_Root(&a,3)!=174)fail(5);
if(osrec_kernel_Other(&a)!=24 || osrec_kernel_Other(&b)!=16 || a.words[0]!=232 || b.words[0]!=231 || a.osrec_local_Root_calls_1!=2 || b.osrec_local_Root_calls_1!=1)fail(6);
osrec_context_restore(&a);initial(&a);if(osrec_kernel_Other(&b)!=16 || b.words[0]!=231 || a.file_alias!=b.file_alias || a.osrec_local_Root_alias_0!=b.osrec_local_Root_alias_0)fail(7);
osrec_result[4]=3;osrec_result[2]=2;stop();}
'''.replace('WORDS',values('核;é🙂')).replace('FIXED',values('源;,/*)*/🙂')).replace('SEED',values('会;🙂'))
                (sources/'driver.c').write_text(driver,encoding='utf-8');elf=stage/'source-bytes.elf'
                run([LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-I'+str(ROOT/'include'),'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'kernel.c',sources/'driver.c','-o',elf])
                audit(elf,LLVM);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],2);self.assertEqual(observed['completed_calls'],3)
        with tempfile.TemporaryDirectory() as name:
            sources=Path(name);raw=b'#include "toy.h"\n/* invalid UTF-8: \xff */\nuint64_t Root(uint64_t n){return n;}\n';header_bytes=header.encode('utf-8')
            (sources/'toy.h').write_bytes(header_bytes);(sources/'kernel.c').write_bytes(raw)
            with self.assertRaises(ValueError):transform(sources,['kernel.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
            self.assertEqual((sources/'kernel.c').read_bytes(),raw);self.assertEqual((sources/'toy.h').read_bytes(),header_bytes);self.assertFalse((sources/'slice_context.h').exists())

    def test_function_local_static_storage_isolation_aliases_and_reset(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(options(stage),sources)
            (sources/'toy.h').write_text('#include <stdint.h>\nuint64_t Root(uint64_t);\nuint64_t Provider(uint64_t);\n')
            (sources/'kernel.c').write_text('''#include "toy.h"
enum {SEED=7};
uint64_t Provider(uint64_t n){
 static uint64_t state=SEED,words[3]={[2]=9};
 static uint64_t *alias=&words[2];
 static const uint64_t increment=1;
 state+=n;*alias+=increment;return state+*alias;
}
uint64_t Root(uint64_t n){
 static uint64_t state;
 state+=n;uint64_t block;
 {static uint64_t state=3;state+=n;block=state;}
 return state+block+Provider(n);
}
''')
            # The same spelling in another function and a nested block denotes
            # different storage; every mutable declaration gets its own field.
            plan=transform(sources,['kernel.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
            self.assertEqual(plan['context_functions'],['Provider','Root'])
            self.assertEqual([(s['function'],s['declaration'],s['name']) for s in plan['local_state']],[(fn,var,'osrec_local_'+fn+'_'+var+'_'+str(i)) for fn,var,i in [('Provider','state',0),('Provider','words',1),('Provider','alias',2),('Root','state',0),('Root','state',1)]])
            driver='''#include "slice_context.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static struct osrec_kernel_context a,b;
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(unsigned n){osrec_result[3]=n;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
static void initial(const struct osrec_kernel_context *c){if(c->osrec_local_Provider_state_0!=7 || c->osrec_local_Provider_words_1[0] || c->osrec_local_Provider_words_1[1] || c->osrec_local_Provider_words_1[2]!=9 || c->osrec_local_Provider_alias_2!=&c->osrec_local_Provider_words_1[2] || c->osrec_local_Root_state_0 || c->osrec_local_Root_state_1!=3)fail(1);}
void replay_main(void){osrec_result[0]=0x4f535243;osrec_result[1]=18;
osrec_context_restore(&a);osrec_context_restore(&b);initial(&a);initial(&b);
if(osrec_kernel_Root(&a,2)!=26)fail(2);initial(&b);
if(osrec_kernel_Root(&b,1)!=23 || osrec_kernel_Root(&a,4)!=39)fail(3);
if(a.osrec_local_Provider_state_0!=13 || a.osrec_local_Provider_words_1[2]!=11 || a.osrec_local_Root_state_0!=6 || a.osrec_local_Root_state_1!=9 || b.osrec_local_Provider_state_0!=8 || b.osrec_local_Root_state_1!=4)fail(4);
osrec_context_restore(&a);initial(&a);if(b.osrec_local_Provider_alias_2!=&b.osrec_local_Provider_words_1[2] || osrec_kernel_Root(&b,3)!=33)fail(5);
osrec_result[4]=4;osrec_result[2]=2;stop();}
'''
            (sources/'driver.c').write_text(driver);elf=stage/'locals.elf'
            command=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-I'+str(ROOT/'include'),'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'kernel.c',sources/'driver.c','-o',elf]
            run(command);audit(elf,LLVM);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],2);self.assertEqual(observed['completed_calls'],4)
            # A reset per call destroys the retained static state and must fail.
            source=sources/'kernel.c';text=source.read_text();source.write_text(text.replace('ctx->osrec_local_Provider_state_0+=n;','ctx->osrec_local_Provider_state_0=7;ctx->osrec_local_Provider_state_0+=n;'))
            run(command);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],3)

    def test_private_objects_in_distinct_translation_units(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(options(stage),sources)
            (sources/'toy.h').write_text('#include <stdint.h>\nuint64_t Left(uint64_t);\nuint64_t Right(uint64_t);\nuint64_t Shared(uint64_t);\nuint64_t Root(uint64_t);\n')
            (sources/'left.c').write_text('#include "toy.h"\nstatic uint64_t counter=2,words[2]={[1]=10};\nstatic uint64_t *alias=&words[1];\nstatic const uint64_t immutable=7;\nuint64_t Left(uint64_t n){counter+=n;*alias+=n;return counter+*alias+immutable;}\n')
            (sources/'right.c').write_text('#include "toy.h"\nstatic uint64_t counter=5,words[2]={[1]=20};\nstatic uint64_t *alias=&words[1];\nstatic uint64_t immutable;\nuint64_t Right(uint64_t n){counter+=2*n;*alias+=3*n;immutable+=n;return counter+*alias+immutable;}\n')
            (sources/'public.c').write_text('#include "toy.h"\nuint64_t counter=100;\nuint64_t Shared(uint64_t n){counter+=n;return counter;}\n')
            (sources/'entry.c').write_text('#include "toy.h"\nuint64_t Root(uint64_t n){extern uint64_t counter;uint64_t left=Left(n),right=Right(n),shared=Shared(n);return left+right+shared+counter;}\n')
            names=['left.c','right.c','public.c','entry.c'];plan=transform(sources,names,['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
            self.assertEqual(plan['context_functions'],['Left','Right','Root','Shared'])
            self.assertEqual({s['name'] for s in plan['private_state']},{'osrec_private_'+str(i)+'_'+n for i in range(2) for n in ('counter','words','alias')})
            self.assertEqual(len(plan['owned_state']),8);self.assertIn('counter',{s['name'] for s in plan['owned_state']})
            driver='''#include "slice_context.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static struct osrec_kernel_context a,b;
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(unsigned n){osrec_result[3]=n;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
static void initial(const struct osrec_kernel_context *c){if(c->counter!=100 || c->immutable || c->osrec_private_0_counter!=2 || c->osrec_private_1_counter!=5 || c->osrec_private_0_words[0] || c->osrec_private_1_words[0] || c->osrec_private_0_words[1]!=10 || c->osrec_private_1_words[1]!=20 || c->osrec_private_0_alias!=&c->osrec_private_0_words[1] || c->osrec_private_1_alias!=&c->osrec_private_1_words[1])fail(1);}
void replay_main(void){osrec_result[0]=0x4f535243;osrec_result[1]=18;
osrec_context_restore(&a);osrec_context_restore(&b);initial(&a);initial(&b);
if(osrec_kernel_Root(&a,1)!=254)fail(2);initial(&b);
if(osrec_kernel_Root(&b,2)!=264 || osrec_kernel_Root(&a,3)!=284)fail(3);
if(a.counter!=104 || a.immutable!=4 || a.osrec_private_0_counter!=6 || a.osrec_private_1_counter!=13 || a.osrec_private_0_words[1]!=14 || a.osrec_private_1_words[1]!=32 || b.counter!=102 || b.immutable!=2 || b.osrec_private_0_counter!=4 || b.osrec_private_1_counter!=9)fail(4);
osrec_context_restore(&a);initial(&a);if(b.counter!=102 || b.osrec_private_0_alias!=&b.osrec_private_0_words[1] || b.osrec_private_1_alias!=&b.osrec_private_1_words[1])fail(5);
osrec_result[4]=3;osrec_result[2]=2;stop();}
'''
            (sources/'driver.c').write_text(driver);elf=stage/'private.elf'
            command=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-I'+str(ROOT/'include'),'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',*[sources/n for n in names],sources/'driver.c','-o',elf]
            run(command);audit(elf,LLVM);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],2);self.assertEqual(observed['completed_calls'],3)
            # Binding one file's counter to another file's storage must fail.
            source=sources/'left.c';source.write_text(source.read_text().replace('ctx->osrec_private_0_counter','ctx->osrec_private_1_counter'))
            run(command);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],3)
        for private in (False,True):
            with self.subTest(private=private),tempfile.TemporaryDirectory() as name:
                sources=Path(name);(sources/'toy.h').write_text('#include <stdint.h>\nuint64_t Root(uint64_t);\n')
                for n in ('left.c','right.c'):(sources/n).write_text('#include "toy.h"\n'+('static ' if private else '')+'uint64_t counter;\n')
                (sources/'entry.c').write_text('#include "toy.h"\nextern uint64_t counter;\nuint64_t Root(uint64_t n){return counter+=n;}\n')
                with self.assertRaisesRegex(ValueError,'private state' if private else 'ambiguous file-scope object'):transform(sources,['left.c','right.c','entry.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
        with tempfile.TemporaryDirectory() as name:
            sources=Path(name);(sources/'toy.h').write_text('#include <stdint.h>\nuint64_t Root(uint64_t);\n')
            (sources/'public.c').write_text('#include "toy.h"\nuint64_t counter;\n')
            (sources/'entry.c').write_text('#include "toy.h"\nuint64_t Root(uint64_t n){extern uint32_t counter;return counter+=n;}\n')
            with self.assertRaisesRegex(ValueError,'incompatible owned-state declaration'):transform(sources,['public.c','entry.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])

    def test_private_function_identity_context_dependencies_and_local_state(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(options(stage),sources)
            (sources/'toy.h').write_text('#include <stdint.h>\nuint64_t Left(uint64_t);\nuint64_t Right(uint64_t);\nuint64_t Shared(uint64_t);\nuint64_t Root(uint64_t);\n')
            (sources/'left.c').write_text('''#include "toy.h"
static uint64_t counter=2;
static uint64_t Step(uint64_t);
static uint64_t Tally(void);
#define CALL_STEP(n) Step(n)
static uint64_t Tally(void){return 5;}
static uint64_t Step(uint64_t n){static uint64_t calls;counter+=n;++calls;return counter+calls+Tally();}
uint64_t Left(uint64_t n){return CALL_STEP(n);}
''')
            (sources/'right.c').write_text('''#include "toy.h"
static uint64_t counter=10;
static uint64_t Step(uint64_t);
static uint64_t Tally(void);
#define CALL_STEP(n) Step(n)
static uint64_t Tally(void){static uint64_t calls;return ++calls;}
static uint64_t Step(uint64_t n){static uint64_t calls;counter+=3*n;++calls;return counter+calls+Tally();}
uint64_t Right(uint64_t n){return CALL_STEP(n);}
''')
            (sources/'public.c').write_text('#include "toy.h"\nuint64_t counter=100;\nuint64_t Step(uint64_t n){counter+=5*n;return counter;}\nuint64_t Shared(uint64_t n){return Step(n);}\n')
            (sources/'entry.c').write_text('#include "toy.h"\nuint64_t Root(uint64_t n){extern uint64_t Step(uint64_t);uint64_t left=Left(n),right=Right(n),shared=Shared(n);return left+right+shared+Step(0);}\n')
            names=['left.c','right.c','public.c','entry.c'];plan=transform(sources,names,['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
            self.assertEqual({f['name'] for f in plan['private_functions']},{'osrec_private_'+str(i)+'_'+n for i in range(2) for n in ('Step','Tally')})
            self.assertEqual(plan['pure_functions'],['osrec_private_0_Tally'])
            self.assertEqual(plan['function_dependencies']['Left'],['osrec_private_0_Step'])
            self.assertEqual(plan['function_dependencies']['Right'],['osrec_private_1_Step'])
            self.assertEqual(plan['function_dependencies']['osrec_private_0_Step'],['osrec_private_0_Tally'])
            self.assertEqual(plan['function_dependencies']['osrec_private_1_Step'],['osrec_private_1_Tally'])
            self.assertEqual(plan['function_dependencies']['Root'],['Left','Right','Shared','Step'])
            self.assertEqual({s['function'] for s in plan['local_state']},{'osrec_private_0_Step','osrec_private_1_Step','osrec_private_1_Tally'})
            driver='''#include "slice_context.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static struct osrec_kernel_context a,b;
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(unsigned n){osrec_result[3]=n;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
static void initial(const struct osrec_kernel_context *c){if(c->counter!=100 || c->osrec_private_0_counter!=2 || c->osrec_private_1_counter!=10 || c->osrec_local_osrec_private_0_Step_calls_0 || c->osrec_local_osrec_private_1_Step_calls_0 || c->osrec_local_osrec_private_1_Tally_calls_0)fail(1);}
void replay_main(void){osrec_result[0]=0x4f535243;osrec_result[1]=18;
osrec_context_restore(&a);osrec_context_restore(&b);initial(&a);initial(&b);
if(osrec_kernel_Root(&a,1)!=234)fail(2);initial(&b);
if(osrec_kernel_Root(&b,2)!=248 || osrec_kernel_Root(&a,3)!=279)fail(3);
if(a.counter!=120 || a.osrec_private_0_counter!=6 || a.osrec_private_1_counter!=22 || a.osrec_local_osrec_private_0_Step_calls_0!=2 || a.osrec_local_osrec_private_1_Step_calls_0!=2 || a.osrec_local_osrec_private_1_Tally_calls_0!=2 || b.counter!=110 || b.osrec_private_0_counter!=4 || b.osrec_private_1_counter!=16 || b.osrec_local_osrec_private_1_Tally_calls_0!=1)fail(4);
osrec_context_restore(&a);initial(&a);if(b.counter!=110 || b.osrec_local_osrec_private_0_Step_calls_0!=1)fail(5);
osrec_result[4]=3;osrec_result[2]=2;stop();}
'''
            (sources/'driver.c').write_text(driver);elf=stage/'private-functions.elf'
            command=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-I'+str(ROOT/'include'),'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',*[sources/n for n in names],sources/'driver.c','-o',elf]
            run(command);audit(elf,LLVM);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],2);self.assertEqual(observed['completed_calls'],3)
            # Calling the public implementation in place of a private helper
            # retains a valid signature but destroys its ownership semantics.
            source=sources/'left.c';text=source.read_text();source.write_text(text.replace('#define CALL_STEP(n) osrec_kernel_osrec_private_0_Step(ctx, n)','#define CALL_STEP(n) osrec_kernel_Step(ctx, n)'))
            (sources/'toy.h').write_text((sources/'toy.h').read_text()+'uint64_t osrec_kernel_Step(struct osrec_kernel_context *,uint64_t);\n')
            self.assertNotEqual(source.read_text(),text)
            run(command);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],3)
        for case in ('public','unresolved','escaped','shared-header','key-collision'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as name:
                sources=Path(name);header='#include <stdint.h>\nuint64_t Left(uint64_t);\nuint64_t Right(uint64_t);\n'
                if case=='shared-header':header+='static uint64_t Step(uint64_t);\n'
                (sources/'toy.h').write_text(header)
                for n,root in (('left.c','Left'),('right.c','Right')):
                    text='#include "toy.h"\n'+('' if case=='public' else 'static ')+'uint64_t Step(uint64_t n){static uint64_t calls;return n+(++calls);}\nuint64_t '+root+'(uint64_t n){'
                    if case=='escaped' and n=='left.c':text+='(void)Step;'
                    text+='return Step(n);}\n';(sources/n).write_text(text)
                names=['left.c','right.c']
                if case=='unresolved':
                    names.append('entry.c');(sources/'entry.c').write_text('#include "toy.h"\nextern uint64_t Step(uint64_t);\nuint64_t Root(uint64_t n){return Step(n);}\n')
                if case=='key-collision':(sources/'left.c').write_text((sources/'left.c').read_text()+'uint64_t osrec_private_0_Step(uint64_t n){return n;}\n')
                with self.assertRaises(ValueError):transform(sources,names,['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])

    def test_unsupported_initializer_references_rejected(self):
        cases=[
            'void osrec_kernel_restore_value_0(void);static uint64_t value=1;uint64_t Root(uint64_t n){return value+=n;}',
            'extern uint64_t outside;static uint64_t *link=&outside;uint64_t Root(uint64_t n){return *link+n;}',
            '#define OWNED value\nstatic uint64_t value;static uint64_t *link=&OWNED;uint64_t Root(uint64_t n){return *link+n;}',
            'extern uint64_t outside;static uint64_t *links[1]={&outside};uint64_t Root(uint64_t n){return *links[0]+n;}',
            'static uint64_t *links[1]={(uint64_t[]){7}};uint64_t Root(uint64_t n){return *links[0]+n;}',
            'typedef struct {uint64_t (*callback)(uint64_t);} Handler;static Handler handlers[1]={{Root}};uint64_t Root(uint64_t n){return handlers[0].callback!=0 ? n : 0;}',
            '#define OWNED values\nstatic uint64_t values[2];static uint64_t *links[1]={&OWNED[1]};uint64_t Root(uint64_t n){return *links[0]+n;}'
        ]
        for text in cases:
            with self.subTest(text=text),tempfile.TemporaryDirectory() as name:
                s=Path(name);(s/'toy.h').write_text('#include <stdint.h>\nuint64_t Root(uint64_t);\n');(s/'kernel.c').write_text('#include "toy.h"\n'+text)
                with self.assertRaises(ValueError):transform(s,['kernel.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
        with tempfile.TemporaryDirectory() as name:
            s=Path(name);(s/'toy.h').write_text('#include <stdint.h>\nuint64_t Root(uint64_t);\n')
            (s/'model.c').write_text('#include "toy.h"\nstatic uint64_t outside=7;\n')
            (s/'kernel.c').write_text('#include "toy.h"\nextern uint64_t outside;\nuint64_t Root(uint64_t n){return outside+n;}\n')
            with self.assertRaisesRegex(ValueError,'private state'):transform(s,['model.c','kernel.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])

if __name__=='__main__':
    if len(sys.argv)==4:KERNEL=Path(sys.argv[1]);LLVM=Path(sys.argv[2]);QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
