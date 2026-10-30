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
static inline int64_t osrec_app_linux_getgroups(uint64_t a0,uint64_t a1){return osrec_app_syscall(UINT64_C(158),a0,a1,0,0,0,0);}
static inline int64_t osrec_app_linux_setgroups(uint64_t a0,uint64_t a1){return osrec_app_syscall(UINT64_C(159),a0,a1,0,0,0,0);}
static inline int64_t osrec_app_linux_capset(uint64_t a0,uint64_t a1){return osrec_app_syscall(UINT64_C(91),a0,a1,0,0,0,0);}
int64_t osrec_app_syscall_prefix(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
#endif
