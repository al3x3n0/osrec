/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Selected declarations from Linux v6.10 include/uapi/linux/capability.h.
 * https://raw.githubusercontent.com/torvalds/linux/v6.10/include/uapi/linux/capability.h
 * __u32 and __user are supplied locally for the libc-free capture program. */
typedef uint32_t __u32;
#define __user
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
