/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Selected declarations from Linux v6.10 include/uapi/linux/capability.h.
 * https://raw.githubusercontent.com/torvalds/linux/v6.10/include/uapi/linux/capability.h
 * __u32 and __user are supplied locally for the libc-free capture program. */
typedef uint32_t __u32;
#define __user
#define _LINUX_CAPABILITY_VERSION_1  0x19980330
#define _LINUX_CAPABILITY_U32S_1     1
#define _LINUX_CAPABILITY_VERSION_2  0x20071026
#define _LINUX_CAPABILITY_U32S_2     2
#define _LINUX_CAPABILITY_VERSION_3  0x20080522
#define _LINUX_CAPABILITY_U32S_3     2

typedef struct __user_cap_header_struct {
	__u32 version;
	int pid;
} __user *cap_user_header_t;

struct __user_cap_data_struct {
        __u32 effective;
        __u32 permitted;
        __u32 inheritable;
};
typedef struct __user_cap_data_struct __user *cap_user_data_t;
#define CAP_SETGID           6
#define CAP_CHOWN            0
#define CAP_DAC_OVERRIDE     1
#define CAP_DAC_READ_SEARCH  2
#define CAP_FOWNER           3
#define CAP_FSETID           4
#define CAP_SETUID           7
#define CAP_LINUX_IMMUTABLE  9
#define CAP_MKNOD            27
#define CAP_MAC_OVERRIDE     32
