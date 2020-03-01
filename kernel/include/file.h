#include "config.h"

#define SSIZE_MAX 32767

extern int file_tampering_flag;

int file_check(void *arg, ssize_t size);
int hide_content(void *arg, ssize_t size);

static inline void file_tampering(void)
{
    if (file_tampering_flag)
        file_tampering_flag = 0;
    else
        file_tampering_flag = 1;
}