/* Linux arm64 host edge for the single-threaded, libc-free executor.
 * Only compiler headers and Linux UAPI headers are used. Not a libc ABI. */
#ifndef LK_STANDALONE_H
#define LK_STANDALONE_H
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <asm/errno.h>
#include <linux/fcntl.h>
#include <linux/mman.h>
#include <asm/stat.h>
#include <asm/unistd.h>
#include <linux/memfd.h>
/* Keep the kernel's signal constants/types, with a typed handler union for C. */
#define sigaction lk_kernel_sigaction
#include <asm/signal.h>
#undef sigaction
#include <asm/siginfo.h>
#include <asm/sigcontext.h>
#include <asm/ucontext.h>
typedef struct ucontext ucontext_t;
typedef int sig_atomic_t;
typedef long ssize_t;
typedef long off_t;
struct sigaction {
    union { void (*sa_handler)(int); void (*sa_sigaction)(int,siginfo_t *,void *); };
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    sigset_t sa_mask;
};
#define MAP_FAILED ((void *)-1)
#define SEEK_SET 0
#define SEEK_DATA 3
#define SEEK_HOLE 4
#define _SC_PAGESIZE 30
#define SYS_tgkill __NR_tgkill
#define SYS_gettid __NR_gettid
extern int errno;
long lk_syscall6(long,long,long,long,long,long,long);
long syscall(long,...);
int getpid(void);
int sigaction(int,const struct sigaction *,struct sigaction *);
int sigaltstack(const stack_t *,stack_t *);
int sigprocmask(int,const sigset_t *,sigset_t *);
int sigfillset(sigset_t *);
int sigdelset(sigset_t *,int);
void *mmap(void *,size_t,int,int,int,off_t);
int munmap(void *,size_t);
int mprotect(void *,size_t,int);
int memfd_create(const char *,unsigned);
int ftruncate(int,off_t);
int fstat(int,struct stat *);
off_t lseek(int,off_t,int);
ssize_t read(int,void *,size_t);
ssize_t pwrite(int,const void *,size_t,off_t);
int close(int);
long sysconf(int);
void *calloc(size_t,size_t);
void free(void *);
void *memcpy(void *,const void *,size_t);
void *memset(void *,int,size_t);
int memcmp(const void *,const void *,size_t);
int strcmp(const char *,const char *);
size_t strlen(const char *);
/* x19..x30, SP, d8..d15, signal mask and save flag. */
typedef struct lk_jump { uint64_t state[21],mask,saved; } sigjmp_buf[1];
_Static_assert(offsetof(struct ucontext,uc_mcontext)==176,"Linux signal frame ABI");
_Static_assert(offsetof(siginfo_t,_sifields._sigfault._addr)==16,"Linux siginfo ABI");
_Static_assert(sizeof(struct sigaction)==32,"Linux sigaction ABI");
_Static_assert(sizeof(struct stat)==128,"Linux stat ABI");
_Static_assert(offsetof(struct lk_jump,mask)==168,"jump assembly ABI");
void lk_jump_prepare(sigjmp_buf,int);
int lk_setjmp(sigjmp_buf) __attribute__((returns_twice));
void siglongjmp(sigjmp_buf,int) __attribute__((noreturn));
#define sigsetjmp(env,save) (lk_jump_prepare((env),(save)),lk_setjmp(env))
/* Bounded buffered output and the small JSON formatter used by the launcher.
 * Supports only %s, %u, %lu, %lx and %% (no locale, heap or libc stdio). */
typedef struct { int fd,error,owned;size_t used;char bytes[4096]; } FILE;
extern FILE *stdout,*stderr;
#define PRIu64 "lu"
#define PRIx64 "lx"
FILE *fopen(const char *,const char *);
int fclose(FILE *);
int ferror(FILE *);
size_t fwrite(const void *,size_t,size_t,FILE *);
int fprintf(FILE *,const char *,...);
int printf(const char *,...);
int puts(const char *);
void lk_host_exit(int) __attribute__((noreturn));
void lk_host_start(uint64_t *) __attribute__((noreturn));
#endif
