#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "encrypt.h"

static long get_file_size(FILE *file)
{
	long size;
	fseek(file, 0, SEEK_END);
	size = ftell(file);
	rewind(file);
	return size;
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "USAGE: encrypt <file> <pass:hex(uint32)>\n");
		exit(-1);
	}

	FILE *file = fopen(argv[1], "rb");
	if (!file) {
		fprintf(stderr, "Can't open %s for reading\n", argv[1]);
		exit(-1);
	}

	long size = get_file_size(file);
	unsigned char *data = malloc(size);
	if (!data) {
		fprintf(stderr, "Can't allocate memory\n");
		exit(-1);
	}

	if (fread(data, size, 1, file) != 1) {
		fprintf(stderr, "Can't read data from file\n");
		exit(-1);
	}

	fclose(file);

	uint32_t key = strtol(argv[2], NULL, 16);
	do_encrypt(data, size, key);

	printf("#define DECRYPT_KEY 0x%08x\n", key);
	for (int i = 0; i < size; i++) {
		printf("0x%02x,", data[i]);
	}

	return 0;
}
