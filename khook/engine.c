#include "internal.h"

static khook_stub_t *khook_stub_tbl = NULL;

////////////////////////////////////////////////////////////////////////////////

static int khook_lookup_cb(long data[], const char *name, void *module, long addr)
{
	int i = 0; while (!module && (((const char *)data[0]))[i] == name[i]) {
		if (!name[i++]) return !!(data[1] = addr);
	} return 0;
}

static void *khook_lookup_name(const char *name)
{
	long data[2] = { (long)name, 0 };
	kallsyms_on_each_symbol((void *)khook_lookup_cb, data);
	return (void *)data[1];
}

static void *khook_map_writable(void *addr, size_t len)
{
	struct page *pages[2] = { 0 }; // len << PAGE_SIZE
	long page_offset = offset_in_page(addr);
	int i, nb_pages = DIV_ROUND_UP(page_offset + len, PAGE_SIZE);

	addr = (void *)((long)addr & PAGE_MASK);
	for (i = 0; i < nb_pages; i++, addr += PAGE_SIZE) {
		if ((pages[i] = is_vmalloc_addr(addr) ?
		     vmalloc_to_page(addr) : virt_to_page(addr)) == NULL)
			return NULL;
	}

	addr = vmap(pages, nb_pages, VM_MAP, PAGE_KERNEL);
	return addr ? addr + page_offset : NULL;
}

////////////////////////////////////////////////////////////////////////////////

#ifdef CONFIG_X86
# include "x86/hook.c"
#else
# error Target CPU architecture is NOT supported !!!
#endif

////////////////////////////////////////////////////////////////////////////////

static void khook_wakeup(void)
{
	struct task_struct *p;
	rcu_read_lock();
	for_each_process(p) {
		wake_up_process(p);
	}
	rcu_read_unlock();
}

static int khook_sm_init_hooks(void *arg)
{
	khook_t *p;
	KHOOK_FOREACH_HOOK(p) {
		if (!p->target.addr_map) continue;
		khook_arch_sm_init_one(p);
	}
	return 0;
}

static int khook_sm_cleanup_hooks(void *arg)
{
	khook_t *p;
	KHOOK_FOREACH_HOOK(p) {
		if (!p->target.addr_map) continue;
		khook_arch_sm_cleanup_one(p);
	}
	return 0;
}

static void khook_resolve(void)
{
	khook_t *p;
	KHOOK_FOREACH_HOOK(p) {
		p->target.addr = khook_lookup_name(p->target.name);
	}
}

static void khook_map(void)
{
	khook_t *p;
	KHOOK_FOREACH_HOOK(p) {
		if (!p->target.addr) continue;
		p->target.addr_map = khook_map_writable(p->target.addr, 32);
		khook_debug("target %s@%p -> %p\n", p->target.name, p->target.addr, p->target.addr_map);
	}
}

static void khook_unmap(int wait)
{
	khook_t *p;
	KHOOK_FOREACH_HOOK(p) {
		khook_stub_t *stub = KHOOK_STUB(p);
		if (!p->target.addr_map) continue;
		while (wait && atomic_read(&stub->use_count) > 0) {
			khook_wakeup();
			msleep_interruptible(1000);
			khook_debug("waiting for %s...\n", p->target.name);
		}
		vunmap((void *)((long)p->target.addr_map & PAGE_MASK));
		p->target.addr_map = NULL;
	}
}

////////////////////////////////////////////////////////////////////////////////

int khook_init(void)
{
	void *(*malloc)(long size) = NULL;
	int   (*set_memory_x)(unsigned long, int) = NULL;

	malloc = khook_lookup_name("module_alloc");
	if (!malloc || KHOOK_ARCH_INIT()) return -EINVAL;

	khook_stub_tbl = malloc(KHOOK_STUB_TBL_SIZE);
	if (!khook_stub_tbl) return -ENOMEM;
	memset(khook_stub_tbl, 0, KHOOK_STUB_TBL_SIZE);

	//
	// Since some point memory allocated by module_alloc() doesn't
	// have eXecutable attributes. That's why we have to mark the
	// region executable explicitly.
	//

	set_memory_x = khook_lookup_name("set_memory_x");
	if (set_memory_x) {
		int numpages = round_up(KHOOK_STUB_TBL_SIZE, PAGE_SIZE) / PAGE_SIZE;
		set_memory_x((unsigned long)khook_stub_tbl, numpages);
	}

	khook_resolve();

	khook_map();
	stop_machine(khook_sm_init_hooks, NULL, NULL);
	khook_unmap(0);

	return 0;
}

void khook_cleanup(void)
{
	khook_map();
	stop_machine(khook_sm_cleanup_hooks, NULL, NULL);
	khook_unmap(1);
	vfree(khook_stub_tbl);
}
