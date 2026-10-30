"""Credential hook discovery keeps explicit models and rejects unknown footprints."""
import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import Analyzer,load_ast,capture_header
from credential_entry_state import capture_plan,COPY_MODEL
CLANG='/opt/homebrew/opt/llvm@16/bin/clang'
SOURCE='''typedef struct {unsigned userID,effUserID,gid,effGid,other;} User;
typedef struct {User *user;} LosProcessCB;
User *OsCurrUserGet(void);
LosProcessCB *OsCurrProcessGet(void);
void LOS_SpinLockSave(unsigned *);
void LOS_SpinUnlockRestore(unsigned);
unsigned LOS_ArchCopyToUser(void *,const void *,unsigned);
int SysGetRealEffSaveUserID(int *a,int *b,int *c) {
unsigned saved; LOS_SpinLockSave(&saved);
int x=OsCurrUserGet()->userID,y=OsCurrUserGet()->effUserID,z=OsCurrUserGet()->effUserID;
LOS_SpinUnlockRestore(saved);
if(LOS_ArchCopyToUser(a,&x,4))return -14;
if(LOS_ArchCopyToUser(b,&y,4))return -14;
if(LOS_ArchCopyToUser(c,&z,4))return -14;
return 0;
}
'''
USER={'function':'OsCurrUserGet','return_type':'User *','contract':{'kind':'object_provider','reason':'test user','implementation':'logical user','snapshot_safe':True}}
PROCESS={'function':'OsCurrProcessGet','return_type':'LosProcessCB *','contract':{'kind':'object_provider','reason':'test process','implementation':'logical process','snapshot_safe':True}}
POLICY={'OsCurrUserGet':USER['contract'],'LOS_SpinLockSave':{'kind':'ordering_model','reason':'test lock','implementation':'balanced lock'},'LOS_SpinUnlockRestore':{'kind':'ordering_model','reason':'test unlock','implementation':'balanced lock'}}

class CredentialEntryStateTests(unittest.TestCase):
    def parse(self,path,source):
        f=path/'input.c';f.write_text(source);db=path/'compile_commands.json';db.write_text(json.dumps([{'directory':str(path),'file':str(f),'arguments':[CLANG,'-std=c11','-c',str(f),'-o','input.o']}]))
        return load_ast(db,f)[0]

    def test_explicit_copy_model_and_generated_fields(self):
        with tempfile.TemporaryDirectory() as name:
            ast=self.parse(Path(name),SOURCE)
            blocked=Analyzer(ast,POLICY).analyze('SysGetRealEffSaveUserID')
            self.assertEqual(len(blocked['blockers']),3)
            with self.assertRaises(ValueError):capture_plan(blocked,PROCESS)
            plan=Analyzer(ast,{**POLICY,'LOS_ArchCopyToUser':COPY_MODEL}).analyze('SysGetRealEffSaveUserID')
            projected=capture_plan(plan,PROCESS);header=capture_header([projected])
            self.assertEqual(header.count('osrec_snapshot_scalar('),2);self.assertEqual(header.count('osrec_snapshot_edge('),1)
            self.assertIn('object_0->user->effUserID',header);self.assertIn('OsCurrProcessGet()',header)
            namespaced=copy.deepcopy(plan)
            for row in namespaced['call_sites']:
                if row['callee']!='LOS_ArchCopyToUser':row['callee']='tu0:'+row['callee']
            self.assertEqual(capture_header([capture_plan(namespaced,PROCESS)]),header)
            self.assertFalse(plan['completeness_proven']);self.assertEqual(projected['provider_bridge']['kind'],'reviewed_current_user_binding')
            for fault in ('extra_read','missing_read','write','unknown_dependency','provider','model'):
                bad=copy.deepcopy(plan)
                if fault=='extra_read':row=copy.deepcopy(bad['entry_reads'][0]);row['path']='OsCurrUserGet()->other';bad['entry_reads'].append(row)
                elif fault=='missing_read':bad['entry_reads'].pop()
                elif fault=='write':bad['state_writes']=[copy.deepcopy(bad['entry_reads'][0])]
                elif fault=='unknown_dependency':bad['call_sites'].append({'callee':'unknown','boundary':None})
                elif fault=='provider':bad['object_providers'][0]['return_type']='Other *'
                else:bad['call_sites'][0]['boundary']=None
                with self.subTest(fault=fault),self.assertRaises(ValueError):capture_plan(bad,PROCESS)
    def test_new_source_read_fails_closed(self):
        with tempfile.TemporaryDirectory() as name:
            ast=self.parse(Path(name),SOURCE.replace('return 0;','return OsCurrUserGet()->other;'))
            plan=Analyzer(ast,{**POLICY,'LOS_ArchCopyToUser':COPY_MODEL}).analyze('SysGetRealEffSaveUserID')
            with self.assertRaises(ValueError):capture_plan(plan,PROCESS)
if __name__=='__main__':unittest.main()
