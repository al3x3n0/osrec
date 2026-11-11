/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Selected LP64 layout from Linux v6.11 asm-generic/stat.h; native ABI checked. */
#ifndef OSREC_UPSTREAM_STAT_H
#define OSREC_UPSTREAM_STAT_H
#define STAT_HAVE_NSEC 1
struct stat {
    unsigned long st_dev,st_ino;
    unsigned int st_mode,st_nlink,st_uid,st_gid;
    unsigned long st_rdev,__pad1;
    long st_size;
    int st_blksize,__pad2;
    long st_blocks,st_atime;
    unsigned long st_atime_nsec;
    long st_mtime;
    unsigned long st_mtime_nsec;
    long st_ctime;
    unsigned long st_ctime_nsec;
    unsigned int __unused4,__unused5;
};
#endif
