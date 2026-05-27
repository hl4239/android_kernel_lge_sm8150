/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ANTI_FRIDA_H
#define _LINUX_ANTI_FRIDA_H

#include <linux/types.h>

struct vm_area_struct;
struct path;

#define ANTI_FRIDA_REPLACE_COMM "hidding"

/*
 * Per-hook feature bits exposed via the runtime sysctl. Each bit is set
 * to engage the corresponding /proc filter; the sysctl itself is named
 * inconspicuously (sched_compat_flags) so a userspace enumerator does
 * not see anti_frida in /proc/sys/kernel/.
 */
#define AF_FLAG_COMM         (1U << 0)   /* 0x01: hide comm in status/stat/comm */
#define AF_FLAG_TRACER_PID   (1U << 1)   /* 0x02: force TracerPid = 0 */
#define AF_FLAG_MAPS         (1U << 2)   /* 0x04: hide matching VMAs in maps/smaps */
#define AF_FLAG_FD_READDIR   (1U << 3)   /* 0x08: hide matching fds from fd readdir */
#define AF_FLAG_FD_READLINK  (1U << 4)   /* 0x10: -ENOENT on matching fd readlink */
#define AF_FLAG_ALL          0x1fU

#ifdef CONFIG_ANTI_FRIDA

bool anti_frida_match(const char *s);
void anti_frida_sanitize_comm(char *tcomm, size_t len);
bool anti_frida_path_should_hide(const struct path *p);
bool anti_frida_vma_should_hide(struct vm_area_struct *vma);
bool anti_frida_should_filter(unsigned int feature);

#else /* !CONFIG_ANTI_FRIDA */

static inline bool anti_frida_match(const char *s) { return false; }
static inline void anti_frida_sanitize_comm(char *tcomm, size_t len) { }
static inline bool anti_frida_path_should_hide(const struct path *p) { return false; }
static inline bool anti_frida_vma_should_hide(struct vm_area_struct *vma) { return false; }
static inline bool anti_frida_should_filter(unsigned int feature) { return false; }

#endif /* CONFIG_ANTI_FRIDA */

#endif /* _LINUX_ANTI_FRIDA_H */
