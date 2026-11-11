"""Data-symbol derivation from a synthetic arm64 Image: agreement, rejection and live layout checks."""
import hashlib,json,struct,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import kernel_data_symbols as kds

BASE=0xffff800080000000;NOP=0xd503201f;RET=0xd65f03c0
def adrp(pc,target,rd):
    imm=((target&~0xfff)-(pc&~0xfff))>>12
    return 0x90000000|(imm&3)<<29|((imm>>2)&0x7ffff)<<5|rd
def add(rd,rn,imm):return 0x91000000|imm<<10|rn<<5|rd
def ldr(rt,rn,off):return 0xf9400000|(off//8)<<10|rn<<5|rt

class Fixture:
    """1200 two-word functions after _stext, then two functions forming DATA, init text, then data."""
    def __init__(self,tmp,data=BASE+0x40930,second=None,between=NOP,entry=NOP):
        size=0x50000;words=bytearray(size)
        struct.pack_into('<QQ',words,8,0,size);words[0x38:0x3c]=b'ARMd'
        rows=[(BASE+0x10000,'T','_stext')]
        for i in range(1200):
            at=0x10000+8*i;struct.pack_into('<II',words,at,entry,RET);rows.append((BASE+at,'T','f%d'%i))
        hash_at=BASE+0x20000;init_at=BASE+0x21000
        rows+=[(BASE+0x20000-0x100,'D','_etext'),(hash_at,'T','futex_hash'),(init_at,'t','futex_init'),(BASE+0x22000,'T','_einittext')]
        for i,w in enumerate([NOP,NOP,adrp(hash_at+8,data,1),add(5,1,data&0xfff),between,ldr(4,1,data&0xfff),RET]):struct.pack_into('<I',words,0x20000+4*i,w)
        other=second or data
        for i,w in enumerate([NOP,adrp(init_at+4,other,21),add(20,21,other&0xfff),RET]):struct.pack_into('<I',words,0x21000+4*i,w)
        self.image=tmp/'Image';self.image.write_bytes(bytes(words));digest=hashlib.sha256(bytes(words)).hexdigest()
        self.kallsyms=tmp/'kallsyms.txt';self.kallsyms.write_text('# kernel sha256 %s\n'%digest+''.join('%016x %s %s\n'%r for r in sorted(rows)))
        self.spec=tmp/'review.json'
        self.review=dict(format=kds.SPEC,kernel_image_sha256=digest,image_base='%#x'%BASE,symbols=dict(__futex_data=dict(source='test',
            layout=dict(size=16,align=16,fields=dict(queues=dict(offset=0,size=8),hashsize=dict(offset=8,size=8))),
            references=[dict(function='futex_hash',adrp=8,use=12,form='add'),dict(function='futex_hash',adrp=8,use=20,form='ldr'),dict(function='futex_init',adrp=4,use=8,form='add')],
            live_checks=[dict(check='power_of_two',field='hashsize',minimum=4),dict(check='linear_map',field='queues',align=64)])))
        self.write()
    def write(self):self.spec.write_text(json.dumps(self.review))
    def derive(self):return kds.derive(self.image,self.kallsyms,self.spec)

class Memory:
    def __init__(self,words):self.words=words
    def u(self,address,size=8):return self.words.get(address,0)&(1<<8*size)-1
    def read(self,address,size):
        out=bytearray(size)
        for at,value in self.words.items():
            for k in range(8):
                if 0<=at+k-address<size:out[at+k-address]=value>>8*k&255
        return bytes(out)

class Record:
    """Minimal type table: one 64-byte bucket record (waiters@0, lock@4, chain.node_list@8)."""
    def struct(self,name):return 'bucket'
    def sizeof(self,record):return 64
    def member(self,record,name):return {'waiters':(0,'atomic'),'counter':(0,None),'lock':(4,None),'chain':(8,'plist'),'node_list':(0,None)}[name]

class DataSymbolTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()

    def test_references_agree_on_the_address(self):
        f=Fixture(self.path);out=f.derive()['symbols']['__futex_data']
        self.assertEqual(out['address'],'%#x'%(BASE+0x40930))
        self.assertEqual([d['register'] for d in out['derivations']],['x1','x1','x21'])
        self.assertEqual(kds.listing(kds.Image(f.image,BASE),kds.symbols(f.kallsyms)[1],'futex_init'),[dict(adrp=4,use=8,form='add',address='%#x'%(BASE+0x40930))])

    def test_disagreeing_references_reject(self):
        with self.assertRaisesRegex(ValueError,'references disagree'):Fixture(self.path,second=BASE+0x40940).derive()

    def test_register_written_between_adrp_and_use_rejects(self):
        # mov x1, #0 between the ADRP and the LDR on x1.
        with self.assertRaisesRegex(ValueError,'redefine x1'):Fixture(self.path,between=0xd2800001).derive()

    def test_branch_between_adrp_and_use_rejects(self):
        with self.assertRaisesRegex(ValueError,'may branch'):Fixture(self.path,between=0x14000002).derive()

    def test_unconfirmed_base_rejects(self):
        with self.assertRaisesRegex(ValueError,'image base .* is not confirmed'):Fixture(self.path,entry=0x12345678).derive()

    def test_address_in_text_rejects(self):
        with self.assertRaisesRegex(ValueError,'not in image data'):Fixture(self.path,data=BASE+0x20930).derive()

    def test_wrong_use_form_and_kernel_reject(self):
        f=Fixture(self.path);f.review['symbols']['__futex_data']['references'][0]['form']='ldr';f.write()
        with self.assertRaisesRegex(ValueError,'is not ADRP then LDR'):f.derive()
        f.review['kernel_image_sha256']='0'*64;f.write()
        with self.assertRaisesRegex(ValueError,'different kernels'):f.derive()

    def test_a_reviewed_layout_must_agree_with_btf(self):
        from test_svc_boundary import btf_blob
        f=Fixture(self.path);words=bytearray(f.image.read_bytes())
        blob=btf_blob([(1,'int',4,None,0),(4,'pair',16,[('queues',1,0),('hashsize',1,64)],0)],['int','pair','queues','hashsize'])
        words[0x48000:0x48000+len(blob)]=blob;f.image.write_bytes(bytes(words))
        digest=hashlib.sha256(bytes(words)).hexdigest();f.review['kernel_image_sha256']=digest
        text=f.kallsyms.read_text().split('\n',1);f.kallsyms.write_text('# kernel sha256 %s\n'%digest+text[1])
        symbol=f.review['symbols']['__futex_data'];symbol['btf_record']='pair';symbol['layout']['fields']['queues']['size']=4;symbol['layout']['fields']['hashsize']=dict(offset=8,size=4)
        f.write();out=f.derive()['symbols']['__futex_data'];self.assertEqual(out['btf_record'],'pair')
        symbol['layout']['fields']['hashsize']['offset']=12;f.write()
        with self.assertRaisesRegex(ValueError,'differs from the review'):f.derive()
        symbol['layout']['fields']['hashsize']['offset']=8;symbol['layout']['size']=24;f.write()
        with self.assertRaisesRegex(ValueError,'review says 24'):f.derive()

    def test_live_layout_checks(self):
        symbol=Fixture(self.path).derive()['symbols']['__futex_data'];at=BASE+0x40930;queues=0xffff000002f68000
        symbol['live_checks'].append(dict(check='empty_lists',array='queues',count='hashsize',record='bucket',stride=64,counter='waiters.counter',list='chain.node_list',lock='lock'))
        words={at:queues,at+8:4,**{queues+64*i+8+k:queues+64*i+8 for i in range(4) for k in (0,8)}}
        evidence=kds.check_live(symbol,Record(),Memory(words),0xffff000000000000)
        self.assertEqual((evidence['hashsize'],evidence['empty_bucket']),(4,4))
        for change,message in (({at+8:6},'not a power of two'),({at:queues+8},'aligned linear-map'),({queues+64+4:1},'lock is held'),({queues+128+8:0},'non-empty list')):
            with self.subTest(message=message),self.assertRaisesRegex(ValueError,message):kds.check_live(symbol,Record(),Memory({**words,**change}),0xffff000000000000)
        # A bucket with waiters may have a non-empty list.
        self.assertEqual(kds.check_live(symbol,Record(),Memory({**words,queues+128:1,queues+128+8:0}),0xffff000000000000)['empty_bucket'],3)

if __name__=='__main__':unittest.main()
