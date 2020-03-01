#include <linux/kmod.h>
#include <linux/kallsyms.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/ctype.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
# include <linux/sched/mm.h>
#endif

#include "util.h"

asmlinkage int (*_access_process_vm)(struct task_struct *, unsigned long, void *, int, int);

int util_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    _access_process_vm = (void *) access_process_vm;
#else
	_access_process_vm = (void *) ksym_lookup_name("access_process_vm");
#endif
   
    if (!_access_process_vm)
		return -EFAULT;

    return 0;
}

/* stolen from mm/util.c */

int get_cmdline(struct task_struct *task, char *buffer, int buflen)
{
	int res = 0;
	unsigned int len;
	struct mm_struct *mm = get_task_mm(task);
	unsigned long arg_start, arg_end, env_start, env_end;
	if (!mm)
		goto out;
	if (!mm->arg_end)
		goto out_mm;

	down_read(&mm->mmap_sem);
	arg_start = mm->arg_start;
	arg_end = mm->arg_end;
	env_start = mm->env_start;
	env_end = mm->env_end;
	up_read(&mm->mmap_sem);

	len = arg_end - arg_start;

	if (len > buflen)
		len = buflen;

	res = _access_process_vm(task, arg_start, buffer, len, FOLL_FORCE);

	/*
	 * If the nul at the end of args has been overwritten, then
	 * assume application is using setproctitle(3).
	 */
	if (res > 0 && buffer[res-1] != '\0' && len < buflen) {
		len = strnlen(buffer, res);
		if (len < res) {
			res = len;
		} else {
			len = env_end - env_start;
			if (len > buflen - res)
				len = buflen - res;
			res += _access_process_vm(task, env_start, buffer+res, len, FOLL_FORCE);
			res = strnlen(buffer, res);
		}
	}
out_mm:
	mmput(mm);
out:
	return res;
}

/*
static int count_argc(const char *str)
{
	int count = 0;
	bool was_space;

	for (was_space = true; *str; str++) {
		if (isspace(*str)) {
			was_space = true;
		} else if (was_space) {
			was_space = false;
			count++;
		}
	}

	return count;
}

int run_cmd(const char *cmd)
{
	char **argv;
	int ret;
	int i;
	
	argv = argv_split(GFP_KERNEL, cmd, NULL);
	if (argv) {
		ret = exec(argv);
		argv_free(argv);
	} else {
		ret = -ENOMEM;
	}

	return ret;
}
*/