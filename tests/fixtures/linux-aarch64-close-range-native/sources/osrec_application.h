#ifndef OSREC_APPLICATION_H
#define OSREC_APPLICATION_H
#include <stdint.h>
#include <stddef.h>
int64_t osrec_app_syscall(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
static inline int64_t osrec_app_linux_umask(uint64_t a0){return osrec_app_syscall(UINT64_C(166),a0,0,0,0,0,0);}
static inline int64_t osrec_app_linux_getresuid(uint64_t a0,uint64_t a1,uint64_t a2){return osrec_app_syscall(UINT64_C(148),a0,a1,a2,0,0,0);}
static inline int64_t osrec_app_linux_getresgid(uint64_t a0,uint64_t a1,uint64_t a2){return osrec_app_syscall(UINT64_C(150),a0,a1,a2,0,0,0);}
static inline int64_t osrec_app_linux_getpid(void){return osrec_app_syscall(UINT64_C(172),0,0,0,0,0,0);}
static inline int64_t osrec_app_linux_getppid(void){return osrec_app_syscall(UINT64_C(173),0,0,0,0,0,0);}
static inline int64_t osrec_app_linux_getuid(void){return osrec_app_syscall(UINT64_C(174),0,0,0,0,0,0);}
static inline int64_t osrec_app_linux_geteuid(void){return osrec_app_syscall(UINT64_C(175),0,0,0,0,0,0);}
static inline int64_t osrec_app_linux_getgid(void){return osrec_app_syscall(UINT64_C(176),0,0,0,0,0,0);}
static inline int64_t osrec_app_linux_getegid(void){return osrec_app_syscall(UINT64_C(177),0,0,0,0,0,0);}
static inline int64_t osrec_app_linux_gettid(void){return osrec_app_syscall(UINT64_C(178),0,0,0,0,0,0);}
static inline int64_t osrec_app_linux_dup(uint64_t a0){return osrec_app_syscall(UINT64_C(23),a0,0,0,0,0,0);}
static inline int64_t osrec_app_linux_dup3(uint64_t a0,uint64_t a1,uint64_t a2){return osrec_app_syscall(UINT64_C(24),a0,a1,a2,0,0,0);}
static inline int64_t osrec_app_linux_close(uint64_t a0){return osrec_app_syscall(UINT64_C(57),a0,0,0,0,0,0);}
static inline int64_t osrec_app_linux_lseek(uint64_t a0,uint64_t a1,uint64_t a2){return osrec_app_syscall(UINT64_C(62),a0,a1,a2,0,0,0);}
static inline int64_t osrec_app_linux_read(uint64_t a0,uint64_t a1,uint64_t a2){return osrec_app_syscall(UINT64_C(63),a0,a1,a2,0,0,0);}
static inline int64_t osrec_app_linux_write(uint64_t a0,uint64_t a1,uint64_t a2){return osrec_app_syscall(UINT64_C(64),a0,a1,a2,0,0,0);}
static inline int64_t osrec_app_linux_ftruncate(uint64_t a0,uint64_t a1){return osrec_app_syscall(UINT64_C(46),a0,a1,0,0,0,0);}
static inline int64_t osrec_app_linux_pread64(uint64_t a0,uint64_t a1,uint64_t a2,uint64_t a3){return osrec_app_syscall(UINT64_C(67),a0,a1,a2,a3,0,0);}
static inline int64_t osrec_app_linux_pwrite64(uint64_t a0,uint64_t a1,uint64_t a2,uint64_t a3){return osrec_app_syscall(UINT64_C(68),a0,a1,a2,a3,0,0);}
static inline int64_t osrec_app_linux_fcntl(uint64_t a0,uint64_t a1,uint64_t a2){return osrec_app_syscall(UINT64_C(25),a0,a1,a2,0,0,0);}
static inline int64_t osrec_app_linux_close_range(uint64_t a0,uint64_t a1,uint64_t a2){return osrec_app_syscall(UINT64_C(436),a0,a1,a2,0,0,0);}
int64_t osrec_app_syscall_prefix(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
#endif
