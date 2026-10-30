"""Local enum seeds retain target values, lexical scope and checkpoint state."""
import json
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from test_callable_slices import options
from contextify_slice import transform
from freestanding_armv7 import run,audit
from freestanding_elf import prepare_target
from run_freestanding_armv7 import observe
from export_syscall_slices import export
from verify_syscall_slices import verify_matrix
from run_c_application_checkpoint_chain import run_pipeline,verify_chain
from slice_port_bundle import digest,verify_published
from application_pause import verify_joint

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/portable-slice-port'


def prepare_fixture(destination):
    shutil.copytree(FIXTURE,destination)
    provider=destination/'provider.c';text=provider.read_text()
    original='    alias->value+=delta;++alias->calls;'
    if text.count(original)!=1:raise ValueError('local enum fixture provider changed')
    text=text.replace('uint64_t Provider(', '#define INITIAL_WORDS {[ctx]=SEED}\nuint64_t Provider(')
    text=text.replace(original,'''    enum {WIDTH=3,ctx=1,SEED=PRIVATE_HIGH+PRIVATE_LOW};
    static uint64_t words[WIDTH]=INITIAL_WORDS,*word=&words[ctx];
    static uint64_t calls;
    if(!output)return calls==alias->calls && words[ctx]==alias->value && word==&words[ctx] && !words[0] && !words[2];
    alias->value+=delta;++alias->calls;*word+=delta;++calls;
    if(calls!=alias->calls || *word!=alias->value)return UINT64_MAX;''')
    provider.write_bytes(b'\xef\xbb\xbf'+('/* 枚举状态 é🙂 */\n'+text).replace('\n','\r\n').encode('utf-8'))
    adapter=destination/'adapter.c';adapter.write_text(adapter.read_text().replace('ctx->alias==&ctx->ledger ?', 'ctx->alias==&ctx->ledger && osrec_kernel_Provider((struct osrec_kernel_context *)ctx,0,0) ?'))
    policy_file=destination/'checkpoint-policy.json';policy=json.loads(policy_file.read_text())
    policy['fields'].update({
        'osrec_local_Provider_words_0':{'type':'uint64_t[3]','policy':'persist'},
        'osrec_local_Provider_word_1':{'type':'uint64_t *','policy':'context_buffer_reference','targets':['osrec_local_Provider_words_0'],'nullable':False},
        'osrec_local_Provider_calls_2':{'type':'uint64_t','policy':'persist'}})
    policy_file.write_text(json.dumps(policy,indent=2)+'\n')
    port_file=destination/'port.json';port=json.loads(port_file.read_text())
    port['bundle']['inputs']={n:digest((destination/n).read_bytes()) for n in port['bundle']['inputs']}
    port_file.write_text(json.dumps(port,indent=2)+'\n')
    return port_file


class LocalEnumTests(unittest.TestCase):
    def test_generated_header_avoids_model_header_macros(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(options(stage),sources)
            (sources/'toy.h').write_text('''#ifndef TOY_H
#define TOY_H
#include <stdint.h>
#define ctx 37
#define osrec_initial 41
#define osrec_i 3
uint64_t Root(uint64_t);
#endif
''')
            (sources/'kernel.c').write_text('''#include "toy.h"
uint64_t Root(uint64_t n){static uint64_t local=ctx;local+=n;return local;}
''')
            plan=transform(sources,['kernel.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
            self.assertEqual(plan['context_parameters'],{'Root':'ctx_'})
            self.assertIn('osrec_context_restore(struct osrec_kernel_context *ctx_)',(sources/'slice_context.h').read_text())
            driver='''#include "slice_context.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static struct osrec_kernel_context a,b;
static void stop(void){for(;;)__asm__ volatile("wfe");}
void replay_fault(void){osrec_result[2]=3;stop();}
void replay_main(void){osrec_result[0]=0x4f535243;osrec_result[1]=18;
osrec_context_restore(&a);osrec_context_restore(&b);
if(osrec_kernel_Root(&a,2)!=39 || osrec_kernel_Root(&b,1)!=38 || osrec_kernel_Root(&a,3)!=42){replay_fault();}
osrec_context_restore(&a);
if(osrec_kernel_Root(&a,0)!=37 || osrec_kernel_Root(&b,2)!=40){replay_fault();}
osrec_result[4]=5;osrec_result[2]=2;stop();}
'''
            (sources/'driver.c').write_text(driver);elf=stage/'header-macros.elf'
            run([LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-I'+str(ROOT/'include'),'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'kernel.c',sources/'driver.c','-o',elf])
            audit(elf,LLVM);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],2);self.assertEqual(observed['completed_calls'],5)

    def test_context_names_preserve_parameters_constants_and_macros(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(options(stage),sources)
            (sources/'toy.h').write_text('#include <stdint.h>\nuint64_t Root(uint64_t ctx);\nuint64_t Reader(uint64_t);\nuint64_t Macros(uint64_t);\n')
            (sources/'entry.c').write_text('''#include "toy.h"
#define ctx__ 37
static const uint64_t ctx=3;
uint64_t Reader(uint64_t n){static uint64_t calls;calls+=n;return calls+ctx;}
uint64_t Root(uint64_t ctx){uint64_t ctx_=ctx+1;return Reader(ctx_)+ctx__;}
''')
            (sources/'macros.c').write_text('''#include "toy.h"
#define /* parameter */ ctx 37
#define osrec_initial 41
#define osrec_i 3
static uint64_t total=osrec_initial;
uint64_t Macros(uint64_t n){static uint64_t local=ctx;total+=n;local+=n;return total+local;}
'''.replace('\n','\r'))
            plan=transform(sources,['entry.c','macros.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
            self.assertEqual(plan['context_parameters'],{'Reader':'ctx_','Root':'ctx___','Macros':'ctx_'})
            driver='''#include "slice_context.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static struct osrec_kernel_context a,b;
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(unsigned n){osrec_result[3]=n;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
void replay_main(void){osrec_result[0]=0x4f535243;osrec_result[1]=18;
osrec_context_restore(&a);osrec_context_restore(&b);
if(osrec_kernel_Root(&a,2)!=43 || osrec_kernel_Root(&b,1)!=42 || osrec_kernel_Root(&a,3)!=47)fail(1);
if(osrec_kernel_Macros(&a,2)!=82 || osrec_kernel_Macros(&b,1)!=80 || osrec_kernel_Macros(&a,3)!=88)fail(2);
osrec_context_restore(&a);
if(osrec_kernel_Root(&a,0)!=41 || osrec_kernel_Macros(&a,0)!=78 || osrec_kernel_Root(&b,1)!=44 || osrec_kernel_Macros(&b,2)!=84)fail(3);
osrec_result[4]=10;osrec_result[2]=2;stop();}
'''
            (sources/'driver.c').write_text(driver);elf=stage/'context-names.elf'
            run([LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-I'+str(ROOT/'include'),'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry.c',sources/'macros.c',sources/'driver.c','-o',elf])
            audit(elf,LLVM);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],2);self.assertEqual(observed['completed_calls'],10)

    def test_enum_seed_state_survives_fresh_image_checkpoints(self):
        with tempfile.TemporaryDirectory(prefix='osrec-local-enums-') as name:
            stage=Path(name);port_root=stage/'port';port_file=prepare_fixture(port_root)
            args=SimpleNamespace(arch='aarch64',capture=port_root,kernel_root=stage/'unused',out=stage/'kernel',port=port_file,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000)
            kernel=export(args);plan=kernel['context_plan'];codec=kernel['checkpoint_codec']
            self.assertEqual(kernel['state_layout']['OSREC_SLICE_STATE_BYTES'],64);self.assertEqual(codec['record_bytes'],128)
            self.assertEqual(plan['context_parameters']['Provider'],'ctx_')
            self.assertEqual([e['name'] for e in plan['initializer_enums']],['osrec_local_Provider_words_0','osrec_local_Provider_word_1'])
            self.assertEqual(plan['input_sha256']['provider.c'],digest((port_root/'provider.c').read_bytes()))
            raw=(port_root/'provider.c').read_bytes()
            for entry in plan['initializer_enums']:
                group=entry['scopes'][0][0];self.assertEqual(raw[group['offset']:group['offset']+4],b'enum')
                seed=next(v for v in group['values'] if v['declaration']=='SEED');self.assertEqual(seed['initializer_value'],'4294967303')
            self.assertTrue((args.out/'sources/provider.c').read_bytes().startswith(b'\xef\xbb\xbf'))
            matrix=verify_matrix(args.out,stage/'kernel-qemu',qemu=QEMU,llvm_bin=LLVM);self.assertEqual(len(matrix['executions']),4)
            chain_args=SimpleNamespace(slices=args.out,source=[port_root/'application.c'],spec=port_root/'spec.json',pause_ordinals=[2,4,5],out=stage/'chain',llvm_bin=LLVM,qemu=QEMU)
            result=run_pipeline(chain_args);self.assertEqual(result['logical_calls'],6)
            offsets={f['path']:codec['header_bytes']+f['wire_offset'] for f in codec['fields'] if 'wire_offset' in f}
            for i,(value,ordinal) in enumerate(((8589934601,2),(4294967313,4),(12884901908,5))):
                joint=verify_joint(chain_args.out/('stage-'+str(i))/'checkpoint',kernel);record=joint['record'];self.assertEqual(len(record),128)
                self.assertEqual(struct.unpack_from('<QQ',record,64),(value,ordinal))
                self.assertEqual(struct.unpack_from('<QQQ',record,offsets['osrec_local_Provider_words_0']),(0,value,0))
                self.assertEqual(struct.unpack_from('<QQ',record,offsets['osrec_local_Provider_word_1']),(1,8))
                self.assertEqual(struct.unpack_from('<Q',record,offsets['osrec_local_Provider_calls_2'])[0],ordinal)
            for row in result['stages']:
                self.assertEqual(row['qemu_executions'],4);self.assertFalse(row['observations']['guest_host_services'])
            # A reviewed wrong enum seed must fail quiescent source validation
            # on target, before publishing a returning-slice image.
            provider=port_root/'provider.c';raw=provider.read_bytes();provider.write_bytes(raw.replace(b'SEED=PRIVATE_HIGH+PRIVATE_LOW',b'SEED=PRIVATE_HIGH+PRIVATE_LOW+1',1))
            port=json.loads(port_file.read_text());port['bundle']['inputs']['provider.c']=digest(provider.read_bytes());port_file.write_text(json.dumps(port))
            bad=SimpleNamespace(**dict(vars(args),out=stage/'bad-kernel'))
            with self.assertRaises(ValueError):export(bad)
            self.assertFalse(bad.out.exists())
            shutil.rmtree(port_root);verify_published(args.out/'port-inputs',kernel)
            self.assertEqual(verify_chain(chain_args.out)['status'],'verified')

    def test_scopes_designators_target_types_and_context_names(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(options(stage),sources)
            (sources/'toy.h').write_text('''#include <stdint.h>
uint64_t Left(uint64_t ctx);
uint64_t Right(uint64_t);
uint64_t Root(uint64_t);
uint64_t Wide(void);
''')
            (sources/'left.c').write_text('''#include "toy.h"
#define VALUE(a,b) ((a)+(b))
#define STRING(x) #x
static uint64_t Step(uint64_t n){
 enum E{BASE=13,NEXT,WIDTH=3};
 static uint64_t scalar=VALUE(BASE,0),words[WIDTH]={[WIDTH-1]=NEXT};
 static uint64_t *alias=&words[WIDTH-1];
 static char label[]=STRING(NEXT);
 uint64_t shadow;
 {enum E{BASE=23,NEXT,WIDTH=2};
  static uint64_t words[WIDTH]={[WIDTH-1]=NEXT},value=BASE;
  value+=n;words[WIDTH-1]+=n;shadow=value+words[WIDTH-1];}
 for(enum {BASE=41} i=0;i<1;++i){static uint64_t loop=BASE;loop+=n;shadow+=loop;}
 if(label[0]!='N' || label[1]!='E' || label[2]!='X' || label[3]!='T' || label[4])return UINT64_MAX;
 scalar+=n;*alias+=n;return scalar+*alias+shadow;
}
uint64_t Left(uint64_t n){return Step(n);}
''')
            (sources/'right.c').write_text('''#include "toy.h"
#define SEED_WORDS {[WIDTH-1]=BASE}
static uint64_t Step(uint64_t n){
 enum {BASE=31,WIDTH=3,ctx=2,osrec_initial=3,osrec_i=4,size_t=5};
 static uint64_t words[WIDTH]=SEED_WORDS;
 static uint64_t value=BASE+ctx+osrec_initial+osrec_i+size_t;
 static uint64_t *alias=&words[WIDTH-ctx];
 value+=n;*alias+=n;return value+*alias;
}
uint64_t Right(uint64_t n){return Step(n);}
uint64_t Wide(void){
 enum E{MIN=(-9223372036854775807LL-1LL),NEXT,HIGH=0x100000007UL,MAX=0xfffffffffffffffeUL};
 static uint64_t low=MIN,next=NEXT,high=HIGH,max=MAX;
 static uint64_t signature=_Generic(HIGH,long long:1,default:0);
 return low==(uint64_t)MIN && next==(uint64_t)NEXT && high==(uint64_t)HIGH && max==(uint64_t)MAX && signature==_Generic(HIGH,long long:1,default:0);
}
''')
            (sources/'entry.c').write_text('#include "toy.h"\nuint64_t Root(uint64_t n){return Left(n)+Right(n);}\n')
            names=['left.c','right.c','entry.c'];plan=transform(sources,names,['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
            self.assertEqual(plan['context_parameters']['Left'],'ctx_')
            self.assertEqual(plan['context_parameters']['osrec_private_1_Step'],'ctx_')
            entries=plan['initializer_enums'];self.assertTrue(any(len(e['scopes'])==2 for e in entries))
            self.assertFalse(any(e['name'].endswith('_label_3') for e in entries))
            values=[v for e in entries for scope in e['scopes'] for group in scope for v in group['values']]
            self.assertTrue(any(v['declaration']=='NEXT' and v['implicit'] for v in values))
            self.assertTrue(any(v.get('initializer_value')=='18446744073709551614' and v['initializer_type']=='unsigned long' for v in values))
            right=(sources/'right.c').read_text();self.assertIn('enum {BASE = ((int)31ULL)',right);self.assertIn(' *ctx_',right);self.assertIn('osrec_initial_',right);self.assertIn('__SIZE_TYPE__ osrec_i_',right)
            driver='''#include "slice_context.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static struct osrec_kernel_context a,b;
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(unsigned n){osrec_result[3]=n;osrec_result[2]=3;stop();}
void replay_fault(void){fail(99);}
void replay_main(void){osrec_result[0]=0x4f535243;osrec_result[1]=18;
osrec_context_restore(&a);osrec_context_restore(&b);
if(!osrec_kernel_Wide(&a) || !osrec_kernel_Wide(&b))fail(1);
if(osrec_kernel_Root(&a,2)!=174 || osrec_kernel_Root(&b,1)!=167 || osrec_kernel_Root(&a,3)!=195)fail(2);
if(a.osrec_local_osrec_private_1_Step_alias_2!=&a.osrec_local_osrec_private_1_Step_words_0[1] || b.osrec_local_osrec_private_1_Step_alias_2!=&b.osrec_local_osrec_private_1_Step_words_0[1] || b.osrec_local_osrec_private_1_Step_value_1!=46)fail(3);
osrec_context_restore(&a);if(!osrec_kernel_Wide(&a) || osrec_kernel_Root(&a,0)!=160 || osrec_kernel_Root(&b,3)!=188 || !osrec_kernel_Wide(&b))fail(4);
osrec_result[4]=5;osrec_result[2]=2;stop();}
'''
            (sources/'driver.c').write_text(driver);elf=stage/'local-enums.elf'
            command=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-I'+str(ROOT/'include'),'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',*[sources/n for n in names],sources/'driver.c','-o',elf]
            run(command);audit(elf,LLVM);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],2);self.assertEqual(observed['completed_calls'],5)
            source=sources/'left.c';text=source.read_text();source.write_text(text.replace('BASE = ((int)23ULL)','BASE = ((int)13ULL)',1))
            self.assertNotEqual(source.read_text(),text);run(command);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],3)
        cases=[
            'uint64_t Root(uint64_t n){enum __attribute__((packed)) E{SEED=13};static uint64_t value=SEED;return value+=n;}',
            'uint64_t Root(uint64_t n){enum {SEED=((unsigned __int128)1<<100)};static uint64_t value=(uint64_t)SEED;return value+=n;}',
            'uint64_t Root(uint64_t n){enum E{SEED=13};static uint64_t value=sizeof(enum E);return value+=n;}',
            'uint64_t Root(uint64_t n){enum {SEED=13};static const uint64_t seed=SEED,*alias=&seed;return *alias+n;}'
        ]
        for body in cases:
            with self.subTest(body=body),tempfile.TemporaryDirectory() as name:
                sources=Path(name);header='#include <stdint.h>\nuint64_t Root(uint64_t);\n';original='#include "toy.h"\n'+body
                (sources/'toy.h').write_text(header);(sources/'kernel.c').write_text(original)
                with self.assertRaises(ValueError):transform(sources,['kernel.c'],['toy.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
                self.assertEqual((sources/'kernel.c').read_text(),original);self.assertEqual((sources/'toy.h').read_text(),header);self.assertFalse((sources/'slice_context.h').exists())


if __name__=='__main__':unittest.main()
