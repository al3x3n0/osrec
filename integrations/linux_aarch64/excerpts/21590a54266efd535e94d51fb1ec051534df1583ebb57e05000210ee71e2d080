/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Selected original macro definitions, Linux v6.10 include/uapi/linux/securebits.h. */
#ifndef OSREC_UPSTREAM_SECUREBITS_H
#define OSREC_UPSTREAM_SECUREBITS_H
#define issecure_mask(X) (1 << (X))
#define SECURE_NOROOT 0
#define SECURE_NOROOT_LOCKED 1
#define SECURE_NO_SETUID_FIXUP 2
#define SECURE_NO_SETUID_FIXUP_LOCKED 3
#define SECURE_KEEP_CAPS 4
#define SECURE_KEEP_CAPS_LOCKED 5
#define SECURE_NO_CAP_AMBIENT_RAISE 6
#define SECURE_NO_CAP_AMBIENT_RAISE_LOCKED 7
#define SECURE_ALL_BITS (issecure_mask(SECURE_NOROOT) | \
                         issecure_mask(SECURE_NO_SETUID_FIXUP) | \
                         issecure_mask(SECURE_KEEP_CAPS) | \
                         issecure_mask(SECURE_NO_CAP_AMBIENT_RAISE))
#define SECURE_ALL_LOCKS (SECURE_ALL_BITS << 1)
#endif
