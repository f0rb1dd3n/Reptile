#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)

#include <linux/types.h>
#include <linux/sched.h>

char *kstrdup_quotable_cmdline(struct task_struct *task, gfp_t gfp);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
char *strreplace(char *s, char old, char new);
#endif

#else 
# include <linux/sched.h>
# include <linux/string.h>
# include <linux/string_helpers.h>
#endif