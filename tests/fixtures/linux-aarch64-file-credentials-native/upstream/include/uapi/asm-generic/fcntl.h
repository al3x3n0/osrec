/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Reviewed declaration excerpt from Linux v6.10 include/uapi/asm-generic/fcntl.h.
 * https://raw.githubusercontent.com/torvalds/linux/v6.10/include/uapi/asm-generic/fcntl.h */
#define O_ACCMODE 00000003
#define O_RDONLY 00000000
#define O_WRONLY 00000001
#define O_RDWR 00000002
#ifndef O_CREAT
#define O_CREAT 00000100
#endif
#ifndef O_TRUNC
#define O_TRUNC 00001000
#endif
#ifndef O_APPEND
#define O_APPEND 00002000
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 00004000
#endif
#ifndef FASYNC
#define FASYNC 00020000
#endif
#ifndef O_DIRECT
#define O_DIRECT 00040000
#endif
#ifndef O_NOATIME
#define O_NOATIME 01000000
#endif
#ifndef O_NDELAY
#define O_NDELAY O_NONBLOCK
#endif
#define F_GETFL 3
#define F_SETFL 4
