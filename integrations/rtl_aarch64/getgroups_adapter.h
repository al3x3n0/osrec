/* Reviewed SysGetGroups adapter: one stable credential and shared output object. */
static void complete(uint32_t,uint32_t) __attribute__((noreturn));
extern int SysGetGroups(int,int *);
static union {User user;uint32_t words[8];} credential;
static uint32_t output[4],temporary[3],temporary_id,temporary_live,invocation,depth,locks,copies,usercopies;
static UINT8 pool_token;
UINT8 *m_aucSysMem1=&pool_token;
static LosProcessCB process;
VOID *LOS_MemAlloc(VOID *pool,UINT32 size)
{
 if(invocation!=2 || pool!=m_aucSysMem1 || size!=OSREC_GROUP_BYTES || depth!=1 || temporary_live || osrec_result[21]) complete(3,101);
 const struct getgroup_call *call=&checkpoint_getgroups[invocation];
 if(!call->allocation_attempted) complete(3,101);
 osrec_result[21]++;
 if(!call->allocation_id) {osrec_result[22]++;return 0;}
 temporary_id=call->allocation_id;temporary_live=1;
 osrec_result[27]++;osrec_result[30]=2;osrec_result[31]+=call->reuse;
 return temporary;
}
UINT32 LOS_MemFree(VOID *pool,VOID *address)
{
 if(invocation!=2 || pool!=m_aucSysMem1 || address!=temporary || !temporary_live || depth || usercopies!=1) complete(3,103);
 const struct getgroup_call *call=&checkpoint_getgroups[invocation];
 if(temporary_id!=call->allocation_id) complete(3,104);
 for(unsigned i=0;i<OSREC_GROUP_COUNT;++i) if(((volatile uint32_t *)temporary)[i]!=credential.words[5+i]) complete(3,107);
 temporary_live=0;osrec_result[28]++;osrec_result[30]=1;return LOS_OK;
}
int memcpy_s(void *out,size_t capacity,const void *in,size_t size)
{
 if(invocation!=2 || depth!=1 || !temporary_live || copies || out!=temporary || in!=&credential.user.groups[0] || size!=OSREC_GROUP_BYTES || capacity!=OSREC_GROUP_BYTES) complete(3,105);
 volatile unsigned char *destination=out;const volatile unsigned char *source=in;
 for(size_t i=0;i<size;++i) destination[i]=source[i];
 ++copies;osrec_result[29]++;return 0;
}
size_t LOS_ArchCopyToUser(void *out,const void *in,size_t size)
{
 if(invocation!=2 || depth || !temporary_live || copies!=1 || usercopies || out!=(unsigned char *)output+checkpoint_getgroups[invocation].output_offset || in!=temporary || size!=OSREC_GROUP_BYTES) complete(3,107);
 const struct getgroup_call *call=&checkpoint_getgroups[invocation];
 if(temporary_id!=call->allocation_id) complete(3,107);
 volatile unsigned char *destination=out;const volatile unsigned char *source=in;
 if(call->copy_result>size) complete(3,107);
 size_t copied=size-call->copy_result;
 for(size_t i=0;i<copied;++i) destination[i]=source[i];
 ++usercopies;osrec_result[23]++;osrec_result[19]+=(uint32_t)copied;osrec_result[20]+=call->copy_result!=0;return call->copy_result;
}
void OsrecSchedulerLock(UINT32 *saved)
{if(depth) complete(3,109);*saved=UINT32_C(0x13579bdf);depth=1;++locks;osrec_result[17]++;}
void OsrecSchedulerUnlock(UINT32 saved)
{if(depth!=1 || saved!=UINT32_C(0x13579bdf)) complete(3,110);depth=0;osrec_result[18]++;}
LosProcessCB *OsCurrProcessGet(void)
{if(depth!=1) complete(3,111);return &process;}
User *OsCurrUserGet(void)
{if(depth!=1) complete(3,112);return process.user;}
static int matches(const struct getgroup_call *call,int after)
{
 if(process.user!=&credential.user || temporary_live || osrec_result[30]!=1) return 0;
 for(unsigned i=0;i<5+OSREC_GROUP_COUNT;++i) if(((volatile uint32_t *)credential.words)[i]!=checkpoint_credential[i]) return 0;
 const uint32_t *expected=after ? call->after : call->before;
 for(unsigned i=0;i<4;++i) if(((volatile uint32_t *)output)[i]!=expected[i]) return 0;
 return 1;
}
static int osrec_restore(unsigned i)
{
 if(i || invocation || checkpoint_credential[4]!=OSREC_GROUP_COUNT) return 0;
 process.user=&credential.user;
 for(unsigned j=0;j<5+OSREC_GROUP_COUNT;++j) credential.words[j]=checkpoint_credential[j];
 for(unsigned j=0;j<4;++j) output[j]=checkpoint_getgroups[0].before[j];
 osrec_result[26]=OSREC_GROUP_COUNT<3 && checkpoint_getgroups[1].size==UINT32_MAX ? 20+OSREC_GROUP_COUNT : OSREC_GROUP_COUNT<3 && checkpoint_getgroups[2].list_is_null ? 18+OSREC_GROUP_COUNT : OSREC_GROUP_COUNT<3 && checkpoint_getgroups[1].list_is_null ? 16+OSREC_GROUP_COUNT : OSREC_COPY_PREFIX_PROFILE ? 13+OSREC_GROUP_COUNT : OSREC_GROUP_COUNT==1 ? 12 : OSREC_GROUP_COUNT==2 ? 13 : checkpoint_getgroups[1].size==UINT32_MAX ? 11 : checkpoint_getgroups[2].list_is_null ? 10 : checkpoint_getgroups[1].list_is_null ? 9 : 8;osrec_result[30]=1;return 1;
}
static int osrec_entry_matches(unsigned i)
{return i<3 && invocation==i && !depth && matches(&checkpoint_getgroups[i],0);}
static int osrec_state_matches(unsigned i)
{
 unsigned attempted=(i==2) && checkpoint_getgroups[2].allocation_attempted,expected=attempted && checkpoint_getgroups[2].allocation_id!=0;
 return i<3 && invocation==i+1 && !depth && locks==i+1 && osrec_result[18]==i+1 && copies==expected && usercopies==expected &&
  osrec_result[21]==attempted && osrec_result[22]==(attempted-expected) && osrec_result[27]==expected && osrec_result[28]==expected && osrec_result[19]==(OSREC_GROUP_BYTES-checkpoint_getgroups[2].copy_result)*expected && osrec_result[20]==(checkpoint_getgroups[2].copy_result!=0)*expected && matches(&checkpoint_getgroups[i],1);
}
uint32_t osrec_invoke(uint32_t number)
{
 if(number!=205 || invocation>=3) complete(3,113);
 const struct getgroup_call *call=&checkpoint_getgroups[invocation];
 uint32_t raw=(uint32_t)SysGetGroups((int)call->size,call->list_is_null ? 0 : (int *)((unsigned char *)output+call->output_offset));
 ++invocation;return raw;
}
