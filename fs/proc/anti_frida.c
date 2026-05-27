// SPDX-License-Identifier: GPL-2.0
/*
 * fs/proc/anti_frida.c
 *
 * Compile-time keyword filtering for /proc readers. When CONFIG_ANTI_FRIDA
 * is enabled, callers in fs/proc/{array,base,task_mmu,fd}.c consult these
 * helpers to sanitize task->comm strings, force TracerPid to zero, and
 * suppress VMA / fd entries whose backing file path matches a Frida
 * runtime artifact.
 *
 * Each hook is gated by a feature bit in the runtime sysctl
 * /proc/sys/kernel/sched_compat_flags. See AF_FLAG_* in
 * <linux/anti_frida.h>. The sysctl filename does not contain "frida" /
 * "anti" to avoid being noticed by detectors enumerating sysctls.
 */

#include <linux/anti_frida.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/mm_types.h>
#include <linux/string.h>
#include <linux/sysctl.h>

static const char * const anti_frida_keywords[] = {
	"frida",
	"frida-agent",
	"gum-js-loop",
	"gmain",
	"gum",
	"_AGENT_1.0",
	"/data/local/tmp",
};

bool anti_frida_match(const char *s)
{
	size_t i;

	if (!s)
		return false;

	for (i = 0; i < ARRAY_SIZE(anti_frida_keywords); i++) {
		if (strstr(s, anti_frida_keywords[i]))
			return true;
	}
	return false;
}

void anti_frida_sanitize_comm(char *tcomm, size_t len)
{
	if (!tcomm || len == 0)
		return;
	if (anti_frida_match(tcomm))
		strscpy(tcomm, ANTI_FRIDA_REPLACE_COMM, len);
}

bool anti_frida_path_should_hide(const struct path *p)
{
	char *buf;
	char *resolved;
	bool hide = false;

	if (!p || !p->dentry)
		return false;

	buf = (char *)__get_free_page(GFP_KERNEL);
	if (!buf)
		return false;

	resolved = d_path(p, buf, PAGE_SIZE);
	if (!IS_ERR(resolved))
		hide = anti_frida_match(resolved);

	free_page((unsigned long)buf);
	return hide;
}

bool anti_frida_vma_should_hide(struct vm_area_struct *vma)
{
	if (!vma || !vma->vm_file)
		return false;
	return anti_frida_path_should_hide(&vma->vm_file->f_path);
}

/*
 * Runtime feature bitmask. Default 0 so frida-server can attach and
 * inject its agent through /proc/self/fd/<N> without any filtering
 * interference. After the agent is in place, userspace sets the
 * relevant bits via
 *   echo <mask> > /proc/sys/kernel/sched_compat_flags
 * to engage one or more /proc filter hooks. Bit semantics are in
 * <linux/anti_frida.h> (AF_FLAG_*).
 *
 * The sysctl filename intentionally avoids "anti_frida" / "frida"
 * keywords so a userspace enumerator of /proc/sys/kernel/ does not
 * see an obviously bypass-related entry. The internal C identifier
 * still uses anti_frida_* because the kernel source is not exposed
 * to the detector.
 */
static int anti_frida_flags_int;

bool anti_frida_should_filter(unsigned int feature)
{
	return (READ_ONCE(anti_frida_flags_int) & feature) != 0;
}

static struct ctl_table anti_frida_sysctl_table[] = {
	{
		.procname     = "sched_compat_flags",
		.data         = &anti_frida_flags_int,
		.maxlen       = sizeof(int),
		.mode         = 0644,
		.proc_handler = proc_dointvec,
	},
	{ }
};

static int __init anti_frida_init(void)
{
	register_sysctl("kernel", anti_frida_sysctl_table);
	return 0;
}
fs_initcall(anti_frida_init);
