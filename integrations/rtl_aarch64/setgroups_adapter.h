/* Reviewed bounded allocator, input regions and controlled prefix copy outcomes for three SysSetGroups calls.
 * Captured events constrain allocation/free; exit bytes are assertions only. */
static void complete(uint32_t,uint32_t) __attribute__((noreturn));
extern int SysSetGroups(int,const int *);
static union {User user;uint32_t words[8];} heap[8];
static uint32_t ids[8],live[8],sizes[8],depth,locks,unlocks,copies,permits,usercopies,invocation,event_index,allocation_index;
static int input_objects[3][2];
static unsigned char copy_before[3][8];
static LosProcessCB process;
static UINT8 pool_token;
UINT8 *m_aucSysMem1=&pool_token;
static unsigned slot(const void *address)
{
 for(unsigned i=0;i<8;++i) if(address==&heap[i].user && live[i]) return i;
 complete(3,100);
}
static unsigned live_count(void)
{
 unsigned count=0;for(unsigned i=0;i<8;++i) count+=live[i];return count;
}
static unsigned event_base(unsigned invocation_index)
{
 unsigned base=0;for(unsigned i=0;i<invocation_index && i<3;++i) base+=checkpoint_groups[i].event_count;return base;
}
static unsigned allocation_base(unsigned invocation_index)
{
 unsigned base=0;for(unsigned i=0;i<invocation_index && i<3;++i) base+=checkpoint_groups[i].allocation_count;return base;
}
static const struct group_event *next_event(unsigned kind)
{
 unsigned base=event_base(invocation);
 if(invocation>=3 || event_index<base || event_index-base>=checkpoint_groups[invocation].event_count) complete(3,101);
 const struct group_event *event=&checkpoint_groups[invocation].events[event_index-base];
 if(event->kind!=kind) complete(3,101);
 return event;
}
VOID *LOS_MemAlloc(VOID *pool,UINT32 size)
{
 unsigned base=allocation_base(invocation);
 if(invocation>=3 || allocation_index<base || allocation_index-base>=checkpoint_groups[invocation].allocation_count) complete(3,101);
 const struct group_allocation *attempt=&checkpoint_groups[invocation].allocations[allocation_index-base];
 if(pool!=m_aucSysMem1 || size!=attempt->size || !size || size>32 || depth) complete(3,101);
 ++allocation_index;osrec_result[21]++;
 if(!attempt->id) {osrec_result[22]++;return 0;}
 const struct group_event *event=next_event(1);
 if(size!=event->size || attempt->id!=event->id || attempt->reuse!=event->reuse) complete(3,101);
 for(unsigned i=0;i<8;++i) if(!live[i] && (ids[i]!=0)==event->reuse) {
  ids[i]=event->id;live[i]=1;sizes[i]=size;++event_index;
  osrec_result[27]++;osrec_result[30]=live_count();osrec_result[31]+=event->reuse;
  return &heap[i].user;
 }
 complete(3,102);
}
UINT32 LOS_MemFree(VOID *pool,VOID *address)
{
 const struct group_event *event=next_event(2);
 if(pool!=m_aucSysMem1 || depth) complete(3,103);
 unsigned i=slot(address);
 if(ids[i]!=event->id || process.user==address) complete(3,104);
 const struct group_call *call=&checkpoint_groups[invocation];
 if(call->size && ids[i]==call->allocations[0].id) {
  unsigned copied=4*call->size-call->copy_result;
  const volatile unsigned char *bytes=address,*expected=(const volatile unsigned char *)input_objects[invocation];
  for(unsigned j=0;j<copied;++j) if(bytes[j]!=expected[j]) complete(3,107);
  for(unsigned j=copied;j<4*call->size;++j) if(bytes[j]!=copy_before[invocation][j]) complete(3,107);
 }
 live[i]=0;++event_index;osrec_result[28]++;osrec_result[30]=live_count();return LOS_OK;
}
static unsigned range_slot(const void *address,size_t bytes,unsigned *offset)
{
 uintptr_t p=(uintptr_t)address;
 for(unsigned i=0;i<8;++i) if(live[i]) {
  uintptr_t base=(uintptr_t)&heap[i].user;
  if(p>=base && p-base<=sizes[i] && bytes<=sizes[i]-(p-base)) {*offset=(unsigned)(p-base);return i;}
 }
 complete(3,105);
}
int memcpy_s(void *destination,size_t capacity,const void *source,size_t size)
{
 if(depth!=1 || invocation>=3 || capacity<size) complete(3,105);
 const struct group_call *call=&checkpoint_groups[invocation];unsigned to_offset,from_offset;
 unsigned to=range_slot(destination,size,&to_offset),from=range_slot(source,size,&from_offset);
 if(to==from || ids[to]!=call->after.user || from_offset) complete(3,106);
 if(to_offset==0) {
  if(size!=sizeof(User) || capacity!=sizeof(User) || ids[from]!=call->before.user) complete(3,106);
 } else if(to_offset==20) {
  if(!call->size || size!=4*call->size || capacity!=size || ids[from]!=call->events[0].id) complete(3,106);
 } else complete(3,106);
 volatile unsigned char *out=destination;const volatile unsigned char *in=source;
 for(size_t i=0;i<size;++i) out[i]=in[i];
 ++copies;osrec_result[29]++;return 0;
}
int LOS_ArchCopyFromUser(void *out,const void *in,size_t size)
{
 if(invocation>=3 || depth) complete(3,107);
 const struct group_call *call=&checkpoint_groups[invocation];unsigned to=slot(out);
 if(!call->size || in!=input_objects[invocation] || size!=4*call->size || size!=sizes[to] || ids[to]!=call->events[0].id) complete(3,107);
 ++usercopies;osrec_result[23]++;
 volatile unsigned char *destination=out;const volatile unsigned char *source=in;
 if(call->copy_result>size) complete(3,107);
 for(size_t i=0;i<size;++i) copy_before[invocation][i]=destination[i];
 size_t copied=size-call->copy_result;
 for(size_t i=0;i<copied;++i) destination[i]=source[i];
 osrec_result[19]+=(uint32_t)copied;
 if(call->copy_result) {osrec_result[20]++;return (int)call->copy_result;}
 return 0;
}
int IsCapPermit(unsigned capability)
{ if(capability!=CAP_SETGID || depth || permits!=invocation) complete(3,108);++permits;return 1; }
void OsrecSchedulerLock(UINT32 *saved)
{ if(depth) complete(3,109);*saved=UINT32_C(0x13579bdf);depth=1;++locks; }
void OsrecSchedulerUnlock(UINT32 saved)
{ if(depth!=1 || saved!=UINT32_C(0x13579bdf)) complete(3,110);depth=0;++unlocks; }
LosProcessCB *OsCurrProcessGet(void)
{ if(depth!=1) complete(3,111);return &process; }
User *OsCurrUserGet(void)
{
 if(depth!=1 && (invocation>=3 || !checkpoint_groups[invocation].size || event_index!=event_base(invocation)+1)) complete(3,112);
 (void)slot(process.user);return process.user;
}
static int matches(const struct group_state *state)
{
 if(live_count()!=1 || state->values[4]<1 || state->values[4]>3) return 0;
 unsigned i=slot(process.user);User *user=&heap[i].user;
 if(ids[i]!=state->user || user->userID!=state->values[0] || user->effUserID!=state->values[1] ||
  user->gid!=state->values[2] || user->effGid!=state->values[3] || user->groupNumber!=state->values[4]) return 0;
 if(20+4*user->groupNumber>sizes[i]) return 0;
 for(unsigned group=0;group<user->groupNumber;++group) if(heap[i].words[5+group]!=state->values[5+group]) return 0;
 return 1;
}
static int inputs_match(void)
{
 for(unsigned i=0;i<3;++i) for(unsigned j=0;j<checkpoint_groups[i].size;++j)
  if(((volatile int *)input_objects[i])[j]!=(int)checkpoint_groups[i].input[j]) return 0;
 return 1;
}
static int osrec_restore(unsigned i)
{
 if(i || invocation) return 0;
 const struct group_state *state=&checkpoint_groups[0].before;
 if(state->values[4]<1 || state->values[4]>3) return 0;
 for(unsigned call=0;call<3;++call)
  if(checkpoint_groups[call].size>2 || checkpoint_groups[call].event_count>4 || checkpoint_groups[call].allocation_count<1 || checkpoint_groups[call].allocation_count>2) return 0;
 ids[0]=state->user;live[0]=1;process.user=&heap[0].user;sizes[0]=20+4*state->values[4];
 for(unsigned j=0;j<5+state->values[4];++j) heap[0].words[j]=state->values[j];
 for(unsigned call=0;call<3;++call) for(unsigned j=0;j<checkpoint_groups[call].size;++j) input_objects[call][j]=(int)checkpoint_groups[call].input[j];
 osrec_result[26]=5;osrec_result[30]=1;return 1;
}
static int osrec_entry_matches(unsigned i)
{ return i<3 && invocation==i && event_index==event_base(i) && allocation_index==allocation_base(i) && !depth && matches(&checkpoint_groups[i].before) && inputs_match(); }
static int osrec_state_matches(unsigned i)
{
 unsigned expected_copies=0,expected_usercopies=0,expected_locks=0,expected_copyfailures=0,expected_copybytes=0;
 for(unsigned j=0;j<=i && j<3;++j) {
  expected_copies+=(checkpoint_groups[j].raw==0)*(1+(checkpoint_groups[j].size!=0));
  expected_usercopies+=checkpoint_groups[j].size!=0 && checkpoint_groups[j].allocations[0].id!=0;
  if(checkpoint_groups[j].size && checkpoint_groups[j].allocations[0].id) expected_copybytes+=4*checkpoint_groups[j].size-checkpoint_groups[j].copy_result;
  expected_copyfailures+=checkpoint_groups[j].copy_result!=0;
  expected_locks+=checkpoint_groups[j].raw==0;
 }
 return i<3 && invocation==i+1 && event_index==event_base(i)+checkpoint_groups[i].event_count && allocation_index==allocation_base(i)+checkpoint_groups[i].allocation_count && !depth && locks==expected_locks && unlocks==expected_locks &&
  copies==expected_copies && usercopies==expected_usercopies && osrec_result[20]==expected_copyfailures && osrec_result[19]==expected_copybytes && permits==i+1 && matches(&checkpoint_groups[i].after) && inputs_match();
}
uint32_t osrec_invoke(uint32_t number)
{
 if(number!=206 || invocation>=3) complete(3,113);
 const struct group_call *call=&checkpoint_groups[invocation];
 uint32_t raw=(uint32_t)SysSetGroups((int)call->size,call->size ? input_objects[invocation] : 0);
 ++invocation;return raw;
}
