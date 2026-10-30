/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Selected definitions from Linux v6.10 include/uapi/asm-generic/unistd.h.
 * AArch64 uses these generic syscall numbers. This is a reviewed excerpt.
 */
#define __NR_write 64
#define __NR_reboot 142
#define __NR_setresuid 147
#define __NR_getresuid 148
#define __NR_setresgid 149
#define __NR_getresgid 150
#define __NR_umask 166
#define __NR_getpid 172
#define __NR_getppid 173
#define __NR_getuid 174
#define __NR_geteuid 175
#define __NR_getgid 176
#define __NR_getegid 177
#define __NR_gettid 178
#define __NR_setfsuid 151
#define __NR_setfsgid 152
#define __NR_setregid 143
#define __NR_setgid 144
#define __NR_getgroups 158
#define __NR_setgroups 159
#define __NR_mprotect 226
#define __NR_capget 90
#define __NR_capset 91
#define __NR_prctl 167

#define __NR_getrlimit 163
#define __NR_prlimit64 261

#define __NR_setreuid 145
#define __NR_setuid 146
