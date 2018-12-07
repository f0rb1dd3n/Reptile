#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define init_module(module_image, len, param_values) syscall(__NR_init_module, module_image, len, param_values)

int main(int argc, char **argv)
{
	int fd, ret = EXIT_FAILURE;
	struct stat st;
	size_t len;
	void *module_image;

	if (argc < 2)
		return ret;

	fd = open(argv[1], O_RDONLY);
	fstat(fd, &st);

	len = st.st_size;
	module_image = malloc(len);
	read(fd, module_image, len);

	init_module(module_image, len, "");

	if (errno == 37)
		ret = EXIT_SUCCESS;

	free(module_image);
	close(fd);
	return ret;
}
