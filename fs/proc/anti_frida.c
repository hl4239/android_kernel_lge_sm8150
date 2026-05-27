// SPDX-License-Identifier: GPL-2.0
/*
 * fs/proc/anti_frida.c
 *
 * Compile-time keyword filtering for /proc readers. When CONFIG_ANTI_FRIDA is
 * enabled and the runtime sysctl /proc/sys/kernel/anti_frida_enabled is set
 * to 1, callers in fs/proc/{array,base,task_mmu,fd}.c consult these helpers
 * to sanitize task->comm strings and to suppress VMA / fd entries whose
 * backing file path matches a Frida runtime artifact.
 *
 * Filtering is unconditional once the sysctl is on: every reader sees the
 * scrubbed view, including Frida's own threads. The CTF workflow is to keep
 * the sysctl at 0 while frida-server attaches and injects, then flip it to 1
 * before letting the target app's detection code run.
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
 * Runtime toggle. Default 0 so frida-server can attach and inject its
 * agent through /proc/self/fd/<N> without any filtering interference.
 * After the agent is in place, userspace flips this to 1 via
 *   echo 1 > /proc/sys/kernel/anti_frida_enabled
 * to engage the full /proc filter (including the proc_fd_link readlink
 * hook). Setting it back to 0 immediately restores the pristine /proc.
 *
 * No reader-based bypass: once enabled, every reader (including Frida's
 * own threads and frida-server) sees the scrubbed view.
 */
static int anti_frida_enabled_int;

bool anti_frida_should_filter(void)
{
	return READ_ONCE(anti_frida_enabled_int) != 0;
}

static struct ctl_table anti_frida_sysctl_table[] = {
	{
		.procname     = "anti_frida_enabled",
		.data         = &anti_frida_enabled_int,
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
