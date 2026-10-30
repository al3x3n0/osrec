#ifndef OSREC_FILES_MODEL_H
#define OSREC_FILES_MODEL_H
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include "files_checkpoint.h"
typedef int64_t ssize_t;
typedef int64_t off64_t;
typedef uint32_t mode_t;
typedef uintptr_t UINTPTR;
typedef uintptr_t VADDR_T;
typedef uintptr_t vaddr_t;
typedef void VOID;
#define EBADF 9
#define EFAULT 14
#define EMFILE 24
#define DEFAULT_FILE_MODE 0666
#define O_CLOEXEC 0x80000
#define O_DIRECTORY 0x10000
#define AT_FDCWD (-100)
#define CONFIG_NFILE_DESCRIPTORS ((int)FILE_SYSTEM_LIMIT)
#define LOSCFG_FILE_MODE 1
#define OK 0
struct stat {unsigned char bytes[FILE_STAT_SIZE];} __attribute__((aligned(8)));
#define stat64 stat
struct kstat {unsigned char bytes[FILE_KSTAT_SIZE];} __attribute__((aligned(8)));
_Static_assert(sizeof(struct stat)==152 && sizeof(struct kstat)==104,"captured OHOS metadata ABI");
typedef struct {int regionMux;} LosVmSpace;
typedef struct {LosVmSpace *vmSpace;} FileProcess;
extern unsigned char file_pool;
#define OS_SYS_MEM_ADDR (&file_pool)
FileProcess *OsCurrProcessGet(void);
int LOS_IsUserAddressRange(VADDR_T,size_t);
int LOS_MuxAcquire(int *);
int LOS_MuxRelease(int *);
int CheckRegion(const LosVmSpace *,VADDR_T,size_t);
void set_errno(int);
int get_errno(void);
int UserPathCopy(const char *,char **);
int AllocProcessFd(void);
void SetCloexecFlag(int);
int do_open(int,const char *,int,mode_t);
int do_opendir(const char *,int);
void AssociateSystemFd(int,int);
void FreeProcessFd(int);
uint32_t LOS_MemFree(void *,void *);
int GetAssociatedSystemFd(int);
int DisassociateProcessFd(int);
ssize_t write(int,const void *,size_t);
ssize_t read(int,void *,size_t);
off64_t _lseek64(int,int,int,off64_t *,int);
int fstat64(int,struct stat *);
int stat(const char *,struct stat *);
size_t LOS_ArchCopyToUser(void *,const void *,size_t);
int close(int);
int CheckProcessFd(int);
int AllocSpecifiedProcessFd(int);
void files_refer(int);
void ClearCloexecFlag(int);
int SysOpen(const char *,int,...);
int SysOpenat(int,const char *,int,...);
ssize_t SysWrite(int,const void *,size_t);
ssize_t SysRead(int,void *,size_t);
off64_t SysLseek64(int,int,int,off64_t *,int);
int SysFstat64(int,struct kstat *);
int SysStat(const char *,struct kstat *);
int SysDup2(int,int);
int SysClose(int);
void *memset(void *,int,size_t);
#endif
