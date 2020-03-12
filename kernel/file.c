#include <linux/uaccess.h>
#include <linux/slab.h>

#include "file.h"

int file_check(void *arg, ssize_t size)
{
    int ret = 0;
	char *buf;

	if ((size <= 0) || (size >= SSIZE_MAX))
		return ret;

	buf = (char *)kmalloc(size + 1, GFP_KERNEL);
	if (!buf)
		return ret;

	if (copy_from_user((void *)buf, (void *)arg, size))
		goto out;

	buf[size] = 0;

	if ((strstr(buf, HIDETAGIN) != NULL) && (strstr(buf, HIDETAGOUT) != NULL))
		ret = 1;

out:
	kfree(buf);
	return ret;
}

int hide_content(void *arg, ssize_t size)
{
	char *buf, *p1, *p2;
	int i, newret;

	buf = (char *)kmalloc(size, GFP_KERNEL);
	if (!buf)
		return (-1);

	if (copy_from_user((void *)buf, (void *)arg, size)) {
		kfree(buf);
		return size;
	}

	p1 = strstr(buf, HIDETAGIN);
	p2 = strstr(buf, HIDETAGOUT);
	p2 += strlen(HIDETAGOUT);

	if (p1 >= p2 || !p1 || !p2) {
		kfree(buf);
		return size;
	}

	i = size - (p2 - buf);
	memmove((void *)p1, (void *)p2, i);
	newret = size - (p2 - p1);

	if (copy_to_user((void *)arg, (void *)buf, newret)) {
		kfree(buf);
		return size;
	}

	kfree(buf);
	return newret;
}