#include "osrec_application.h"
#include "linux-native-arguments.h"
#ifdef OSREC_LINUX_FILE_CAPABILITIES_PROFILE
#include "linux-capability.h"
#endif
extern uint32_t app_words[8];
extern uint64_t app_returns[];
void osrec_application_main(void);
#ifdef OSREC_LINUX_FSTAT_PROFILE
#ifdef OSREC_LINUX_FILE_LIMITS_PROFILE
static char output[4194304];
#elif defined(OSREC_LINUX_FILE_CREDENTIALS_PROFILE)
static char output[2097152];
#elif defined(OSREC_LINUX_FILE_GROUPS_PROFILE)
static char output[1048576];
#else
static char output[524288];
#endif
static const uint32_t *input_words;
extern uint32_t stat_words[32];
extern uint64_t stat_digest;
#elif defined(OSREC_LINUX_FILE_IO_PROFILE)
static char output[262144];
static const uint32_t *input_words;
#else
static char output[65536];
#endif
static size_t used;
#if defined(OSREC_LINUX_PRCTL_PROFILE) || defined(OSREC_LINUX_FILE_PRCTL_PROFILE)
#define CAPTURE_ARGUMENTS 5
#define CAPTURE_SETPCAP (1u<<8)
#else
#ifdef OSREC_LINUX_FILE_POSITIONED_PROFILE
#define CAPTURE_ARGUMENTS 4
#else
#define CAPTURE_ARGUMENTS 3
#endif
#define CAPTURE_SETPCAP 0
#endif
#ifdef OSREC_LINUX_FSUID_PROFILE
#define CAPTURE_FS_LOW ((1u<<0)|(1u<<1)|(1u<<2)|(1u<<3)|(1u<<4)|(1u<<7)|(1u<<9)|(1u<<27))
#define CAPTURE_FS_HIGH 1u
#else
#define CAPTURE_FS_LOW 0
#define CAPTURE_FS_HIGH 0
#endif
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
#ifdef OSREC_LINUX_FILE_IO_PROFILE
/* Private descriptor class probe: 2 for the memory file, 1 for the console.
 * Disk captures use F_GET_SEALS (shmem memfds carry F_SEAL_SEAL). Ramfs-rooted
 * kernels without SHMEM back memfds with ramfs, which has no seals, so the
 * probe reads the fstat file type instead. */
static int file_class(unsigned fd)
{
#ifdef OSREC_LINUX_RAMFS_ROOT
    unsigned char meta[128];
    if(osrec_app_syscall(80,fd,(uintptr_t)meta,0,0,0,0))return -1;
    uint32_t type=((uint32_t)meta[16]|(uint32_t)meta[17]<<8|(uint32_t)meta[18]<<16|(uint32_t)meta[19]<<24)&0170000;
    return type==0100000 ? 2 : type==0020000 ? 1 : -1;
#else
    int64_t seals=osrec_app_syscall(25,fd,1034,0,0,0,0);
    return seals==1 ? 2 : seals==-22 ? 1 : -1;
#endif
}
#endif
#ifdef OSREC_LINUX_FD_DUP_PROFILE
static void record_fds(void)
{
    append('[');
    for(unsigned fd=0;fd<8;++fd){
        int64_t flags=osrec_app_syscall(25,fd,1,0,0,0,0);
        int64_t status=osrec_app_syscall(25,fd,3,0,0,0,0);
        if(fd)append(',');append('[');
        if(flags==-9 && status==-9){scalar(0);number(0);}
        else{
#ifdef OSREC_LINUX_FILE_IO_PROFILE
            int class=file_class(fd);
            if(flags<0 || flags>1 || class<0)fail();
            scalar((uint64_t)class);number((uint64_t)flags);
#else
            if(flags<0 || flags>1 || (status!=0x20000 && status!=2))fail();
            scalar(status==2 ? 1 : 2);number((uint64_t)flags);
#endif
        }
        append(']');
    }
    append(']');
}
#endif
#ifdef OSREC_LINUX_FSTAT_PROFILE
static void native_stat(unsigned fd,unsigned char *out)
{
    if(osrec_app_syscall(80,fd,(uintptr_t)out,0,0,0,0))fail();
    for(unsigned j=72;j<120;++j)out[j]=0;
}
static void record_stat_metadata(void)
{
    append('[');
    for(unsigned i=0;i<2;++i){unsigned char buf[128];native_stat(i ? 3 : 1,buf);if(i)append(',');append('[');for(unsigned j=0;j<128;++j){if(j)append(',');number(buf[j]);}append(']');}
    append(']');
}
#endif
#ifdef OSREC_LINUX_FILE_IO_PROFILE
static void record_file(void)
{
    for(unsigned fd=0;fd<8;++fd)if(osrec_app_syscall(25,fd,1,0,0,0,0)>=0 && file_class(fd)==2){
        unsigned char bytes[64];
        int64_t size=osrec_app_syscall(67,fd,(uintptr_t)bytes,64,0,0,0);
        int64_t pos=osrec_app_syscall(62,fd,0,1,0,0,0);
        if(size<0 || size>64 || pos<0)fail();
        string("{\"size\":");number((uint64_t)size);string(",\"pos\":");number((uint64_t)pos);string(",\"bytes\":[");
        for(unsigned j=0;j<64;++j){if(j)append(',');number(j<(unsigned)size ? bytes[j] : 0);}string("]");
#ifdef OSREC_LINUX_FSTAT_PROFILE
        unsigned char meta[128];native_stat(fd,meta);uint64_t blocks=0;for(unsigned j=0;j<8;++j)blocks|=(uint64_t)meta[64+j]<<(8*j);string(",\"blocks\":");number(blocks);
#ifdef OSREC_LINUX_FCHMOD_PROFILE
        uint32_t mode=0;for(unsigned j=0;j<4;++j)mode|=(uint32_t)meta[16+j]<<(8*j);string(",\"mode\":");number(mode);
#ifdef OSREC_LINUX_FCHOWN_PROFILE
        uint32_t uid=0,gid=0;for(unsigned j=0;j<4;++j){uid|=(uint32_t)meta[24+j]<<(8*j);gid|=(uint32_t)meta[28+j]<<(8*j);}string(",\"uid\":");number(uid);string(",\"gid\":");number(gid);
#endif
#endif
#endif
        append('}');return;
    }
    string("null");
}
#endif
#ifdef OSREC_LINUX_SETGROUPS_DENIED_PROFILE
static uint32_t effective_setgid(void)
{
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
    if(osrec_app_syscall(90,(uintptr_t)&header,(uintptr_t)data,0,0,0,0))fail();
    return (data[0].effective>>CAP_SETGID)&1u;
}
#endif
#if defined(OSREC_LINUX_CAPABILITIES_PROFILE) || defined(OSREC_LINUX_FILE_CAPABILITIES_PROFILE)
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
#ifdef OSREC_LINUX_FILE_CAPABILITIES_PROFILE
static void record_file_caps(void)
{
    uint32_t header[2]={0x20080522,0},data[6];
    if(osrec_app_syscall(90,(uintptr_t)header,(uintptr_t)data,0,0,0,0))fail();
    append('[');for(unsigned j=0;j<3;++j){if(j)append(',');number(data[j]|((uint64_t)data[j+3]<<32));}append(']');
}
#endif
void osrec_native_record(unsigned i,uint64_t syscall,const uint64_t *args)
{
    if(i)append(',');string("{\"number\":");number(syscall);string(",\"args\":[");
    for(unsigned j=0;j<CAPTURE_ARGUMENTS;++j){if(j)append(',');uint64_t value=args[j];unsigned object=osrec_native_buffer_object(syscall,j);
        uintptr_t base=(uintptr_t)app_words;
#ifdef OSREC_LINUX_FSTAT_PROFILE
        if(object==2)base=(uintptr_t)stat_words;
#endif
        if(object)value=!value ? UINT64_MAX : value==1 ? UINT64_MAX-1 : value-base;
        number(value);}
    string("],\"raw_bits\":");number(app_returns[i]);string(",\"words\":[");
    for(unsigned j=0;j<8;++j){if(j)append(',');number(app_words[j]);}
#if defined(OSREC_LINUX_SETGROUPS_PROFILE) || defined(OSREC_LINUX_FILE_IO_PROFILE)
    string("],\"input_words\":[");for(unsigned j=0;j<8;++j){if(j)append(',');number(input_words[j]);}
#endif
    string("],\"umask_after\":");uint64_t mask=(uint64_t)osrec_app_syscall(166,022,0,0,0,0,0);number(mask);
    osrec_app_syscall(166,mask,0,0,0,0,0);
#ifdef OSREC_LINUX_FD_DUP_PROFILE
    string(",\"fds_after\":");record_fds();
#ifdef OSREC_LINUX_FILE_IO_PROFILE
    string(",\"file_after\":");record_file();
#endif
#endif
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
#ifdef OSREC_LINUX_PRCTL_PROFILE
    string(",\"securebits_after\":");number((uint64_t)osrec_app_syscall(167,27,0,0,0,0,0));
#endif
#ifdef OSREC_LINUX_FSUID_PROFILE
    string(",\"fsuid_after\":");number((uint64_t)osrec_app_syscall(151,UINT64_MAX,0,0,0,0,0));
#endif
#ifdef OSREC_LINUX_SETRESUID_PROFILE
    uint32_t uids[3];
    if(osrec_app_syscall(148,(uintptr_t)&uids[0],(uintptr_t)&uids[1],(uintptr_t)&uids[2],0,0,0))fail();
    string(",\"uids_after\":[");scalar(uids[0]);scalar(uids[1]);number(uids[2]);append(']');
#endif
#ifdef OSREC_LINUX_FSTAT_PROFILE
    string(",\"stat_words\":[");for(unsigned j=0;j<32;++j){if(j)append(',');number(stat_words[j]);}append(']');string(",\"stat_digest\":");number(stat_digest);
#endif
#ifdef OSREC_LINUX_FILE_CAPABILITIES_PROFILE
    string(",\"file_caps_after\":");record_file_caps();
#endif
#ifdef OSREC_LINUX_FILE_FSGID_PROFILE
    string(",\"file_fsgid_after\":");number((uint64_t)osrec_app_syscall(152,UINT64_MAX,0,0,0,0,0));
#endif
#ifdef OSREC_LINUX_FILE_FSUID_PROFILE
    string(",\"file_fsuid_after\":");number((uint64_t)osrec_app_syscall(151,UINT64_MAX,0,0,0,0,0));
#endif
#ifdef OSREC_LINUX_FILE_GROUPS_PROFILE
    uint32_t file_groups[4];int64_t file_group_count=osrec_app_syscall(158,4,(uintptr_t)file_groups,0,0,0,0);
    if(file_group_count<0 || file_group_count>4)fail();
    string(",\"file_groups_after\":[");for(int64_t j=0;j<file_group_count;++j){if(j)append(',');number(file_groups[j]);}append(']');
#endif
#ifdef OSREC_LINUX_FILE_GROUP_SETTERS_PROFILE
    uint32_t file_gids[3];if(osrec_app_syscall(150,(uintptr_t)&file_gids[0],(uintptr_t)&file_gids[1],(uintptr_t)&file_gids[2],0,0,0))fail();
    string(",\"file_gids_after\":[");scalar(file_gids[0]);scalar(file_gids[1]);number(file_gids[2]);append(']');
#endif
#ifdef OSREC_LINUX_FILE_STATUS_PROFILE
    string(",\"fd_status_after\":[");
    for(unsigned fd=0;fd<8;++fd){if(fd)append(',');int64_t flags=osrec_app_syscall(25,fd,3,0,0,0,0);if(flags==-9)string("null");else if(flags<0)fail();else number((uint64_t)flags);}append(']');
#endif
#ifdef OSREC_LINUX_FILE_PRCTL_PROFILE
    uint64_t sets[5];capability_sets(sets);
    string(",\"file_prctl_after\":[");number(sets[3]);append(',');number(sets[4]);append(',');number((uint64_t)osrec_app_syscall(167,27,0,0,0,0,0));append(']');
#endif
#ifdef OSREC_LINUX_FILE_CREDENTIALS_PROFILE
    uint32_t users[3];if(osrec_app_syscall(148,(uintptr_t)&users[0],(uintptr_t)&users[1],(uintptr_t)&users[2],0,0,0))fail();
    string(",\"file_uids_after\":[");scalar(users[0]);scalar(users[1]);number(users[2]);append(']');
#endif
#ifdef OSREC_LINUX_FILE_RLIMIT_PROFILE
    uint64_t limits[4];
    if(osrec_app_syscall(163,6,(uintptr_t)limits,0,0,0,0) || osrec_app_syscall(163,7,(uintptr_t)(limits+2),0,0,0,0))fail();
    string(",\"file_rlimits_after\":[[");scalar(limits[0]);number(limits[1]);string("],[");scalar(limits[2]);number(limits[3]);string("]]");
#endif
#ifdef OSREC_LINUX_FILE_LIMITS_PROFILE
    string(",\"file_all_rlimits_after\":[");
    for(unsigned resource=0;resource<16;++resource){
        uint64_t pair[2];if(osrec_app_syscall(163,resource,(uintptr_t)pair,0,0,0,0))fail();
        if(resource)append(',');append('[');scalar(pair[0]);number(pair[1]);append(']');
    }append(']');
#endif
    append('}');
}
#if defined(OSREC_LINUX_SETGROUPS_PROFILE) || defined(OSREC_LINUX_FILE_IO_PROFILE)
void osrec_native_record_input(unsigned i,uint64_t syscall,const uint64_t *args,const uint32_t *before)
{
    input_words=before;osrec_native_record(i,syscall,args);input_words=0;
}
#endif
void osrec_native_main(void)
{
#ifdef OSREC_LINUX_FD_DUP_PROFILE
    static const uint64_t nofile[2]={8,8};
    if(osrec_app_syscall(261,0,7,(uintptr_t)nofile,0,0,0))fail();
#ifdef OSREC_LINUX_FILE_IO_PROFILE
    static const unsigned char seed[16]={97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112};
    if(osrec_app_syscall(279,(uintptr_t)"osrec",1,0,0,0,0)!=3 || osrec_app_syscall(64,3,(uintptr_t)seed,16,0,0,0)!=16 || osrec_app_syscall(62,3,0,0,0,0,0))fail();
    if(osrec_app_syscall(226,(uintptr_t)&app_words[8],4096,0,0,0,0))fail();
#ifdef OSREC_LINUX_FCHMOD_PROFILE
    if(osrec_app_syscall(55,3,1002,UINT64_MAX,0,0,0))fail();
#ifdef OSREC_LINUX_FCHOWN_PROFILE
    static const uint32_t owner_seed_group=0;
    if(osrec_app_syscall(159,1,(uintptr_t)&owner_seed_group,0,0,0,0))fail();
#endif
#endif
#else
    if(osrec_app_syscall(56,(uint64_t)-100,(uintptr_t)"/init",0x80000,0,0,0)!=3)fail();
#endif
#endif
#if defined(OSREC_LINUX_SETRESUID_PROFILE) || defined(OSREC_LINUX_FILE_CREDENTIALS_PROFILE)
    static const uint64_t unlimited_nproc[2]={UINT64_MAX,UINT64_MAX};
    if(osrec_app_syscall(261,0,6,(uintptr_t)unlimited_nproc,0,0,0))fail();
#endif
#ifdef OSREC_LINUX_GETGROUPS_PROFILE
    uint32_t seed_groups[3]={4007,4001,4003};
    if(osrec_app_syscall(159,3,(uintptr_t)seed_groups,0,0,0,0))fail();
    if(osrec_app_syscall(226,(uintptr_t)&app_words[8],4096,0,0,0,0))fail();
#endif
#ifdef OSREC_LINUX_FSTAT_PROFILE
    if(osrec_app_syscall(226,(uintptr_t)&stat_words[32],4096,0,0,0,0))fail();
#endif
    /* Prepare the profile's real/effective/saved identities. Saved UID zero
     * allows this PID-1 capture process to regain reboot rights. */
    if(osrec_app_syscall(149,2001,2002,2003,0,0,0) || osrec_app_syscall(147,1001,CAPTURE_EUID,0,0,0,0))fail();
#ifdef OSREC_LINUX_FCHOWN_CAPABLE_PROFILE
    uint32_t ownership_header[2]={0x20080522,0};
    #ifdef OSREC_LINUX_FILE_CAPABILITIES_PROFILE
#ifdef OSREC_LINUX_FILE_CREDENTIALS_PROFILE
    static const uint32_t ownership_caps[6]={1,(1u<<22)|9u|64u|256u|128u,0,0,0,0};
#elif defined(OSREC_LINUX_FILE_PRCTL_PROFILE)
    static const uint32_t ownership_caps[6]={1,(1u<<22)|9u|64u|256u,0,0,0,0};
#elif defined(OSREC_LINUX_FILE_GROUPS_PROFILE)
    static const uint32_t ownership_caps[6]={1,(1u<<22)|9u|64u,0,0,0,0};
#else
    static const uint32_t ownership_caps[6]={1,(1u<<22)|9u,0,0,0,0};
#endif
#else
    static const uint32_t ownership_caps[6]={1,(1u<<22)|1u,0,0,0,0};
#endif
    if(osrec_app_syscall(91,(uintptr_t)ownership_header,(uintptr_t)ownership_caps,0,0,0,0))fail();
#endif
#ifdef OSREC_LINUX_CAPABILITIES_PROFILE
    struct __user_cap_header_struct cap_header={_LINUX_CAPABILITY_VERSION_3,0};
    static const struct __user_cap_data_struct cap_data[2]={{(1u<<22)|(1u<<6)|CAPTURE_SETPCAP|CAPTURE_FS_LOW,(1u<<22)|(1u<<6)|CAPTURE_SETPCAP|CAPTURE_FS_LOW,0},{CAPTURE_FS_HIGH,CAPTURE_FS_HIGH,0}};
    if(osrec_app_syscall(91,(uintptr_t)&cap_header,(uintptr_t)cap_data,0,0,0,0))fail();
#endif
    osrec_app_syscall(166,022,0,0,0,0,0);
    string("OSREC_LINUX_CAPTURE {");
#ifdef OSREC_LINUX_FILE_SETRLIMIT_PROFILE
    string("\"profile\":\"file-setrlimit\",");
#elif defined(OSREC_LINUX_FILE_LIMITS_PROFILE)
    string("\"profile\":\"file-limits\",");
#elif defined(OSREC_LINUX_FILE_RLIMIT_PROFILE)
    string("\"profile\":\"file-rlimit\",");
#elif defined(OSREC_LINUX_FILE_CREDENTIALS_PROFILE)
    string("\"profile\":\"file-credentials\",");
#elif defined(OSREC_LINUX_FILE_PRCTL_PROFILE)
    string("\"profile\":\"file-prctl\",");
#elif defined(OSREC_LINUX_FILE_CAPGET_PROFILE)
    string("\"profile\":\"file-capget\",");
#elif defined(OSREC_LINUX_FILE_STATUS_PROFILE)
    string("\"profile\":\"file-status\",");
#elif defined(OSREC_LINUX_FILE_GROUP_SETTERS_PROFILE)
    string("\"profile\":\"file-group-setters\",");
#elif defined(OSREC_LINUX_FILE_GROUPS_PROFILE)
    string("\"profile\":\"file-groups\",");
#elif defined(OSREC_LINUX_FILE_FSUID_PROFILE)
    string("\"profile\":\"file-fsuid\",");
#elif defined(OSREC_LINUX_FILE_FSGID_PROFILE)
    string("\"profile\":\"file-fsgid\",");
#elif defined(OSREC_LINUX_FILE_CAPABILITIES_PROFILE)
    string("\"profile\":\"file-capabilities\",");
#elif defined(OSREC_LINUX_FCHOWN_CAPABLE_PROFILE)
    string("\"profile\":\"fchown-capable\",");
#elif defined(OSREC_LINUX_FCHOWN_PROFILE)
    string("\"profile\":\"fchown\",");
#elif defined(OSREC_LINUX_FCHMOD_PROFILE)
    string("\"profile\":\"fchmod\",");
#elif defined(OSREC_LINUX_FSTAT_PROFILE)
    string("\"profile\":\"fstat\",");
#elif defined(OSREC_LINUX_CLOSE_RANGE_PROFILE)
    string("\"profile\":\"close-range\",");
#elif defined(OSREC_LINUX_FD_CONTROL_PROFILE)
    string("\"profile\":\"fd-control\",");
#elif defined(OSREC_LINUX_FILE_POSITIONED_PROFILE)
    string("\"profile\":\"file-positioned\",");
#elif defined(OSREC_LINUX_FILE_IO_PROFILE)
    string("\"profile\":\"file-io\",");
#elif defined(OSREC_LINUX_FD_DUP_PROFILE)
    string("\"profile\":\"fd-dup\",");
#endif
#ifdef OSREC_LINUX_CREDENTIAL_PROFILE
#ifdef OSREC_LINUX_CAPABILITIES_PROFILE
#ifdef OSREC_LINUX_CREDENTIAL_SETTERS_PROFILE
    string("\"profile\":\"credential-setters\",");
#elif defined(OSREC_LINUX_UID_SETTERS_PROFILE)
    string("\"profile\":\"uid-setters\",");
#elif defined(OSREC_LINUX_SETRESUID_PROFILE)
    string("\"profile\":\"setresuid\",");
#elif defined(OSREC_LINUX_FSUID_PROFILE)
    string("\"profile\":\"fsuid\",");
#elif defined(OSREC_LINUX_PRCTL_PROFILE)
    string("\"profile\":\"prctl\",");
#elif defined(OSREC_LINUX_CAPGET_PROFILE)
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
#ifdef OSREC_LINUX_FD_DUP_PROFILE
    uint64_t nofile_observed[2];
    if(osrec_app_syscall(163,7,(uintptr_t)nofile_observed,0,0,0,0) || nofile_observed[0]!=8 || nofile_observed[1]!=8)fail();
    string(",\"nofile_limit\":[8,8],\"file_flags\":[");
    scalar((uint64_t)osrec_app_syscall(25,0,3,0,0,0,0));number((uint64_t)osrec_app_syscall(25,3,3,0,0,0,0));
    string("],\"fds\":");record_fds();
#ifdef OSREC_LINUX_FILE_IO_PROFILE
    string(",\"file\":");record_file();
#ifdef OSREC_LINUX_FSTAT_PROFILE
    string(",\"stat_metadata\":");record_stat_metadata();
#endif
#endif
#endif
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
#ifdef OSREC_LINUX_PRCTL_PROFILE
    string(",\"securebits\":");number((uint64_t)osrec_app_syscall(167,27,0,0,0,0,0));
#endif
#ifdef OSREC_LINUX_FSUID_PROFILE
    string(",\"fsuid\":");number((uint64_t)osrec_app_syscall(151,UINT64_MAX,0,0,0,0,0));
#endif
#if defined(OSREC_LINUX_SETRESUID_PROFILE) || defined(OSREC_LINUX_FILE_CREDENTIALS_PROFILE)
#ifdef OSREC_LINUX_FILE_LIMITS_PROFILE
    string(",\"rlimits\":[");
    for(unsigned resource=0;resource<16;++resource){
        uint64_t pair[2];if(osrec_app_syscall(163,resource,(uintptr_t)pair,0,0,0,0))fail();
        if(resource)append(',');append('[');scalar(pair[0]);number(pair[1]);append(']');
    }append(']');
#endif
    uint64_t nproc[2];
    if(osrec_app_syscall(163,6,(uintptr_t)nproc,0,0,0,0) || nproc[0]!=UINT64_MAX || nproc[1]!=UINT64_MAX)fail();
    string(",\"nproc_limit\":[");scalar(nproc[0]);number(nproc[1]);append(']');
#endif
#ifdef OSREC_LINUX_FCHOWN_PROFILE
    uint32_t owner_groups[4];int64_t owner_count=osrec_app_syscall(158,4,(uintptr_t)owner_groups,0,0,0,0);
    if(owner_count!=1 || owner_groups[0]!=0)fail();
    string(",\"owner_groups\":[");number(owner_groups[0]);append(']');
    uint32_t owner_header[2]={0x20080522,0},owner_caps[6];
    if(osrec_app_syscall(90,(uintptr_t)owner_header,(uintptr_t)owner_caps,0,0,0,0))fail();
    uint64_t owner_effective=owner_caps[0]|((uint64_t)owner_caps[3]<<32);
    #ifdef OSREC_LINUX_FCHOWN_CAPABLE_PROFILE
    if(owner_effective!=1)fail();
#else
    if(owner_effective)fail();
#endif
    string(",\"ownership_effective_caps\":");number(owner_effective);
#endif
#ifdef OSREC_LINUX_FILE_CAPABILITIES_PROFILE
    string(",\"file_capabilities\":[");record_capabilities();
#endif
#ifdef OSREC_LINUX_FILE_FSGID_PROFILE
    string(",\"file_fsgid\":");number((uint64_t)osrec_app_syscall(152,UINT64_MAX,0,0,0,0,0));
#endif
#ifdef OSREC_LINUX_FILE_FSUID_PROFILE
    string(",\"file_fsuid\":");number((uint64_t)osrec_app_syscall(151,UINT64_MAX,0,0,0,0,0));
    string(",\"file_securebits\":");number((uint64_t)osrec_app_syscall(167,27,0,0,0,0,0));
#endif
    string(",\"umask\":18},\"calls\":[");
    osrec_application_main();string("]}\n");flush();
#ifndef OSREC_LINUX_SETRESUID_PROFILE
    if(osrec_app_syscall(147,UINT64_MAX,0,UINT64_MAX,0,0,0))fail();
#endif
    string("OSREC_LINUX_CAPTURE_DONE\n");flush();
    osrec_app_syscall(142,UINT64_C(0xfee1dead),UINT64_C(0x28121969),UINT64_C(0x4321fedc),0,0,0);
    halt();
}
