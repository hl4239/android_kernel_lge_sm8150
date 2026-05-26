// SPDX-License-Identifier: GPL-2.0
/*
 * fs/proc/anti_frida.c
 *
 * Compile-time keyword filtering for /proc readers. When CONFIG_ANTI_FRIDA is
 * enabled, callers in fs/proc/{array,base,task_mmu}.c consult these helpers to
 * sanitize task->comm strings and to suppress VMA entries whose backing file
 * path matches a Frida runtime artifact.
 */

#include <linux/anti_frida.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/mm_types.h>
#include <linux/ptrace.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/string.h>

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
 * True when the current /proc reader is Frida itself: either the reading
 * thread carries a Frida-style name (e.g. gum-js-loop, gmain), or it is
 * currently ptraced by a process whose comm contains a Frida keyword
 * (e.g. frida-server during the dlopen("/proc/self/fd/<N>") injection
 * stub it pokes into the target). In both cases we must let the read
 * through unfiltered so Frida can self-introspect and complete injection.
 */
bool anti_frida_reader_is_frida_self(void)
{
	char comm[TASK_COMM_LEN];
	struct task_struct *tracer;
	bool result;

	get_task_comm(comm, current);
	if (anti_frida_match(comm))
		return true;

	rcu_read_lock();
	tracer = ptrace_parent(current);
	if (tracer) {
		get_task_comm(comm, tracer);
		result = anti_frida_match(comm);
	} else {
		result = false;
	}
	rcu_read_unlock();

	return result;
}
