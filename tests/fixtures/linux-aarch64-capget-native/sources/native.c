#include "osrec_application.h"
extern uint32_t app_words[8];
extern uint64_t app_returns[];
void osrec_application_main(void);
static char output[65536];static size_t used;
#ifdef OSREC_LINUX_SETGROUPS_PROFILE
#ifdef OSREC_LINUX_SETGROUPS_DENIED_PROFILE
#define CAPTURE_EUID 1002
#else
#define CAPTURE_EUID 0
#endif
#if defined(OSREC_LINUX_SETGROUPS_DENIED_PROFILE) || defined(OSREC_LINUX_CAPABILITIES_PROFILE)
#include "linux-capability.h"
#endif
static const uint32_t *input_words;
#else
#define CAPTURE_EUID 1002
#endif
static void append(char c){if(used<sizeof(output))output[used++]=c;}
static void string(const char *p){while(*p)append(*p++);}
static void number(uint64_t n){char digits[20];unsigned i=0;do{digits[i++]=(char)('0'+n%10);n/=10;}while(n);while(i)append(digits[--i]);}
static void scalar(uint64_t n){number(n);append(',');}
static void flush(void)
{
    size_t sent=0;
    while(sent<used){int64_t n=osrec_app_syscall(64,1,(uintptr_t)output+sent,used-sent,0,0,0);if(n<=0)return;sent+=(size_t)n;}
    used=0;
}
static void halt(void){for(;;)__asm__ volatile("wfe");}
static void fail(void){string("OSREC_LINUX_CAPTURE_FAILED\n");flush();halt();}
#ifdef OSREC_LINUX_SETGROUPS_DENIED_PROFILE
static uint32_t effective_setgid(void)
{
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
    if(osrec_app_syscall(90,(uintptr_t)&header,(uintptr_t)data,0,0,0,0))fail();
    return (data[0].effective>>CAP_SETGID)&1u;
}
#endif
#ifdef OSREC_LINUX_CAPABILITIES_PROFILE
static void capability_sets(uint64_t sets[5])
{
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
    if(osrec_app_syscall(90,(uintptr_t)&header,(uintptr_t)data,0,0,0,0))fail();
    sets[0]=data[0].effective|((uint64_t)data[1].effective<<32);
    sets[1]=data[0].permitted|((uint64_t)data[1].permitted<<32);
    sets[2]=data[0].inheritable|((uint64_t)data[1].inheritable<<32);
    sets[3]=sets[4]=0;
    for(unsigned i=0;i<=40;++i){
        int64_t bounding=osrec_app_syscall(167,23,i,0,0,0,0);
        int64_t ambient=osrec_app_syscall(167,47,1,i,0,0,0);
        if(bounding<0 || bounding>1 || ambient<0 || ambient>1)fail();
        sets[3]|=(uint64_t)bounding<<i;sets[4]|=(uint64_t)ambient<<i;
    }
}
static void record_capabilities(void)
{
    uint64_t sets[5];capability_sets(sets);
    for(unsigned i=0;i<5;++i){if(i)append(',');number(sets[i]);}append(']');
}
#endif
void osrec_native_record(unsigned i,uint64_t syscall,const uint64_t *args)
{
    if(i)append(',');string("{\"number\":");number(syscall);string(",\"args\":[");
    for(unsigned j=0;j<3;++j){if(j)append(',');uint64_t value=args[j];if(syscall==148 || syscall==150 || ((syscall==158 || syscall==159) && j==1) || ((syscall==91 || syscall==90) && j<2))value=!value ? UINT64_MAX : value==1 ? UINT64_MAX-1 : value-(uintptr_t)app_words;number(value);}
    string("],\"raw_bits\":");number(app_returns[i]);string(",\"words\":[");
    for(unsigned j=0;j<8;++j){if(j)append(',');number(app_words[j]);}
#ifdef OSREC_LINUX_SETGROUPS_PROFILE
    string("],\"input_words\":[");for(unsigned j=0;j<8;++j){if(j)append(',');number(input_words[j]);}
#endif
    string("],\"umask_after\":");uint64_t mask=(uint64_t)osrec_app_syscall(166,022,0,0,0,0,0);number(mask);
    osrec_app_syscall(166,mask,0,0,0,0,0);
#ifdef OSREC_LINUX_CREDENTIAL_PROFILE
    uint32_t gids[3];
    if(osrec_app_syscall(150,(uintptr_t)&gids[0],(uintptr_t)&gids[1],(uintptr_t)&gids[2],0,0,0))fail();
    string(",\"gids_after\":[");scalar(gids[0]);scalar(gids[1]);number(gids[2]);
    string("],\"fsgid_after\":");number((uint64_t)osrec_app_syscall(152,UINT64_MAX,0,0,0,0,0));
#ifdef OSREC_LINUX_GETGROUPS_PROFILE
    uint32_t groups[4];int64_t count=osrec_app_syscall(158,4,(uintptr_t)groups,0,0,0,0);
    if(count<0 || count>4)fail();
    string(",\"groups_after\":[");for(int64_t j=0;j<count;++j){if(j)append(',');number(groups[j]);}append(']');
#endif
#endif
#ifdef OSREC_LINUX_SETGROUPS_DENIED_PROFILE
    string(",\"cap_setgid_after\":");number(effective_setgid());
#endif
#ifdef OSREC_LINUX_CAPABILITIES_PROFILE
    string(",\"capabilities_after\":[");record_capabilities();
#endif
    append('}');
}
#ifdef OSREC_LINUX_SETGROUPS_PROFILE
void osrec_native_record_input(unsigned i,uint64_t syscall,const uint64_t *args,const uint32_t *before)
{
    input_words=before;osrec_native_record(i,syscall,args);input_words=0;
}
#endif
void osrec_native_main(void)
{
#ifdef OSREC_LINUX_GETGROUPS_PROFILE
    uint32_t seed_groups[3]={4007,4001,4003};
    if(osrec_app_syscall(159,3,(uintptr_t)seed_groups,0,0,0,0))fail();
    if(osrec_app_syscall(226,(uintptr_t)&app_words[8],4096,0,0,0,0))fail();
#endif
    /* Prepare the profile's real/effective/saved identities. Saved UID zero
     * allows this PID-1 capture process to regain reboot rights. */
    if(osrec_app_syscall(149,2001,2002,2003,0,0,0) || osrec_app_syscall(147,1001,CAPTURE_EUID,0,0,0,0))fail();
#ifdef OSREC_LINUX_CAPABILITIES_PROFILE
    struct __user_cap_header_struct cap_header={_LINUX_CAPABILITY_VERSION_3,0};
    static const struct __user_cap_data_struct cap_data[2]={{(1u<<22)|(1u<<6),(1u<<22)|(1u<<6),0},{0,0,0}};
    if(osrec_app_syscall(91,(uintptr_t)&cap_header,(uintptr_t)cap_data,0,0,0,0))fail();
#endif
    osrec_app_syscall(166,022,0,0,0,0,0);
    string("OSREC_LINUX_CAPTURE {");
#ifdef OSREC_LINUX_CREDENTIAL_PROFILE
#ifdef OSREC_LINUX_CAPABILITIES_PROFILE
#ifdef OSREC_LINUX_CAPGET_PROFILE
    string("\"profile\":\"capget\",");
#else
    string("\"profile\":\"capabilities\",");
#endif
#elif defined(OSREC_LINUX_SETGROUPS_DENIED_PROFILE)
    string("\"profile\":\"setgroups-denied\",");
#elif defined(OSREC_LINUX_SETGROUPS_PROFILE)
    string("\"profile\":\"setgroups\",");
#elif defined(OSREC_LINUX_GETGROUPS_PROFILE)
    string("\"profile\":\"getgroups\",");
#elif defined(OSREC_LINUX_GROUP_SETTERS_PROFILE)
    string("\"profile\":\"group-setters\",");
#elif defined(OSREC_LINUX_FSGID_PROFILE)
    string("\"profile\":\"fsgid\",");
#else
    string("\"profile\":\"credentials\",");
#endif
#endif
    string("\"initial\":{\"pid\":");number((uint64_t)osrec_app_syscall(178,0,0,0,0,0,0));
    string(",\"tgid\":");number((uint64_t)osrec_app_syscall(172,0,0,0,0,0,0));
    string(",\"ppid\":");number((uint64_t)osrec_app_syscall(173,0,0,0,0,0,0));
    string(",\"uids\":[");scalar(1001);scalar(CAPTURE_EUID);number(0);
    string("],\"gids\":[");scalar(2001);scalar(2002);number(2003);
    append(']');
#ifdef OSREC_LINUX_GETGROUPS_PROFILE
    uint32_t initial_groups[4];int64_t count=osrec_app_syscall(158,4,(uintptr_t)initial_groups,0,0,0,0);
    if(count<0 || count>4)fail();
    string(",\"groups\":[");for(int64_t j=0;j<count;++j){if(j)append(',');number(initial_groups[j]);}append(']');
#endif
#ifdef OSREC_LINUX_SETGROUPS_DENIED_PROFILE
    string(",\"cap_setgid\":");number(effective_setgid());
#endif
#ifdef OSREC_LINUX_CAPABILITIES_PROFILE
    string(",\"capabilities\":[");record_capabilities();
#endif
    string(",\"umask\":18},\"calls\":[");
    osrec_application_main();string("]}\n");flush();
    if(osrec_app_syscall(147,UINT64_MAX,0,UINT64_MAX,0,0,0))fail();
    string("OSREC_LINUX_CAPTURE_DONE\n");flush();
    osrec_app_syscall(142,UINT64_C(0xfee1dead),UINT64_C(0x28121969),UINT64_C(0x4321fedc),0,0,0);
    halt();
}
