/* Reviewed three-copy credential query; no allocator or runtime host service. */
static void complete(uint32_t,uint32_t) __attribute__((noreturn));
extern int OSREC_QUERY_FUNCTION(int *,int *,int *);
static User user;
static LosProcessCB process;
static uint32_t output[4],invocation,depth,position;
void OsrecSchedulerLock(UINT32 *saved)
{if(depth || position) complete(3,101);*saved=0x13579bdf;depth=1;osrec_result[29]++;}
void OsrecSchedulerUnlock(UINT32 saved)
{if(depth!=1 || saved!=0x13579bdf) complete(3,102);depth=0;osrec_result[30]++;}
User *OsCurrUserGet(void)
{if(depth!=1 || process.user!=&user) complete(3,103);osrec_result[31]++;return process.user;}
size_t LOS_ArchCopyToUser(void *out,const void *in,size_t size)
{
 if(depth || invocation>=4 || position>=3 || size!=4) complete(3,104);
 unsigned j=position++;
 void *expected=invocation==j+1 ? 0 : (unsigned char *)output+checkpoint_offsets[j];
 if(out!=expected || *(const uint32_t *)in!=checkpoint_ids[j ? 1 : 0]) complete(3,105);
 osrec_result[27]++;
 if(!out) return 4;
 /* Byte stores support aliases, overlaps and unaligned user addresses. */
 for(unsigned k=0;k<4;++k) ((volatile unsigned char *)out)[k]=((const unsigned char *)in)[k];
 osrec_result[28]+=4;return 0;
}
static int matches(unsigned i,int after)
{
 if(process.user!=&user || user.OSREC_REAL_FIELD!=checkpoint_ids[0] || user.OSREC_EFFECTIVE_FIELD!=checkpoint_ids[1] || depth) return 0;
 const uint32_t *expected=after ? checkpoint_output[i].after : checkpoint_output[i].before;
 for(unsigned j=0;j<4;++j) if(((volatile uint32_t *)output)[j]!=expected[j]) return 0;
 return 1;
}
static int osrec_restore(unsigned i)
{
 if(i || invocation) return 0;
 process.user=&user;user.OSREC_REAL_FIELD=checkpoint_ids[0];user.OSREC_EFFECTIVE_FIELD=checkpoint_ids[1];
 for(unsigned j=0;j<4;++j) output[j]=checkpoint_output[0].before[j];
 osrec_result[26]=OSREC_QUERY_KIND;return 1;
}
static int osrec_entry_matches(unsigned i)
{return i<4 && invocation==i && position==0 && matches(i,0);}
static int osrec_state_matches(unsigned i)
{
 static const uint32_t attempts[4]={3,4,6,9},bytes[4]={12,12,16,24};
 return i<4 && invocation==i+1 && position==0 && matches(i,1) && osrec_result[27]==attempts[i] &&
  osrec_result[28]==bytes[i] && osrec_result[29]==i+1 && osrec_result[30]==i+1 && osrec_result[31]==3*(i+1);
}
uint32_t osrec_invoke(uint32_t number)
{
 if(number!=OSREC_QUERY_NUMBER || invocation>=4) complete(3,106);
 int *args[3];for(unsigned j=0;j<3;++j) args[j]=invocation==j+1 ? 0 : (int *)((unsigned char *)output+checkpoint_offsets[j]);
 uint32_t raw=(uint32_t)OSREC_QUERY_FUNCTION(args[0],args[1],args[2]);
 if(position!=(invocation ? invocation : 3)) complete(3,107);
 position=0;++invocation;return raw;
}
