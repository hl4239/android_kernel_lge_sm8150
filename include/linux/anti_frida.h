/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ANTI_FRIDA_H
#define _LINUX_ANTI_FRIDA_H

#include <linux/types.h>

struct vm_area_struct;

#define ANTI_FRIDA_REPLACE_COMM "hidding"

#ifdef CONFIG_ANTI_FRIDA

bool anti_frida_match(const char *s);
void anti_frida_sanitize_comm(char *tcomm, size_t len);
bool anti_frida_vma_should_hide(struct vm_area_struct *vma);

#else /* !CONFIG_ANTI_FRIDA */

static inline bool anti_frida_match(const char *s) { return false; }
static inline void anti_frida_sanitize_comm(char *tcomm, size_t len) { }
static inline bool anti_frida_vma_should_hide(struct vm_area_struct *vma) { return false; }

#endif /* CONFIG_ANTI_FRIDA */

#endif /* _LINUX_ANTI_FRIDA_H */
