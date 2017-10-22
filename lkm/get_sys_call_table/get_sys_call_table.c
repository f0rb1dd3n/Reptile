#include <linux/module.h> 
#include <linux/syscalls.h>

static unsigned long *sc_table;

// util
void *memmem(const void *haystack, size_t haystack_size, const void *needle, size_t needle_size)
{
    char *p;

    for(p = (char *)haystack; p <= ((char *)haystack - needle_size + haystack_size); p++)
    {
        if(memcmp(p, needle, needle_size) == 0)
            return (void *)p;
    }
    return NULL;
}

// generic implementation of finding sys call table address
unsigned long *find_sys_call_table(void){
	unsigned long *syscall_table;
	unsigned long int i;

	for (i = PAGE_OFFSET; i < ULONG_MAX; i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
}

// x86_64 implementation
unsigned long *find_sct(void)
{
    unsigned long sct_off = 0;
    unsigned char code[512];
    char **p;

    rdmsrl(MSR_LSTAR, sct_off);
    memcpy(code, (void *)sct_off, sizeof(code));

    p = (char **)memmem(code, sizeof(code), "\xff\x14\xc5", 3);
  
    if(p)
    {
        unsigned long *table = *(unsigned long **)((char *)p + 3);
        table = (unsigned long *)(((unsigned long)table & 0xffffffff) | 0xffffffff00000000);
        return table;
    }
    return NULL;
}

static int __init getsyscalltable_module(void) { 

	printk("Loading module to getting sys_call_table...\n");

	sc_table = (unsigned long *)find_sys_call_table();
	
	if(sc_table) {
		printk("SYS_CALL_TABLE (method 1) found at: %lx\n", *sc_table); 
	}

	sc_table = (unsigned long *) find_sct();

	if(sc_table) {
		printk("SYS_CALL_TABLE (method 2) found at: %lx\n", *sc_table); 
	}

	if (!sc_table) {
		printk("sys_call_table not found\n");
		return -1;
	}
	return 0; 
} 

static void __exit bye_module(void) { 
	printk("Good bye kernel!\n"); 
}

module_init(getsyscalltable_module);
module_exit(bye_module);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("F0rb1dd3n - ighor@intruder-security.com");
MODULE_DESCRIPTION("An exemple of getting syscall table dinamically");
