#include "../internal.h"

////////////////////////////////////////////////////////////////////////////////
// IN-kernel length disassembler engine (x86 only, 2.6.33+)
////////////////////////////////////////////////////////////////////////////////

#include <asm/insn.h>

static struct {
	typeof(insn_init) *init;
	typeof(insn_get_length) *get_length;
} khook_arch_lde;

static inline int khook_arch_lde_init(void) {
	khook_arch_lde.init = khook_lookup_name("insn_init");
	if (!khook_arch_lde.init) return -EINVAL;
	khook_arch_lde.get_length = khook_lookup_name("insn_get_length");
	if (!khook_arch_lde.get_length) return -EINVAL;
	return 0;
}

static inline int khook_arch_lde_get_length(const void *p) {
	struct insn insn;
	int x86_64 = 0;
#ifdef CONFIG_X86_64
	x86_64 = 1;
#endif
#if defined MAX_INSN_SIZE && (MAX_INSN_SIZE == 15) /* 3.19.7+ */
	khook_arch_lde.init(&insn, p, MAX_INSN_SIZE, x86_64);
#else
	khook_arch_lde.init(&insn, p, x86_64);
#endif
	khook_arch_lde.get_length(&insn);
	return insn.length;
}

////////////////////////////////////////////////////////////////////////////////

// place a jump at addr @a from addr @f to addr @t
static inline void x86_put_jmp(void *a, void *f, void *t)
{
	*((char *)(a + 0)) = 0xE9;
	*(( int *)(a + 1)) = (long)(t - (f + 5));
}

static const char khook_stub_template[] = {
# include KHOOK_STUB_FILE_NAME
};

static inline void stub_fixup(void *stub, const void *value) {
	while (*(int *)stub != 0xcacacaca) stub++;
	*(long *)stub = (long)value;
}

static inline void khook_arch_sm_init_one(khook_t *hook) {
	khook_stub_t *stub = KHOOK_STUB(hook);
	if (hook->target.addr[0] == (char)0xE9 ||
	    hook->target.addr[0] == (char)0xCC) return;

	BUILD_BUG_ON(sizeof(khook_stub_template) > offsetof(khook_stub_t, nbytes));
	memcpy(stub, khook_stub_template, sizeof(khook_stub_template));
	stub_fixup(stub->hook, hook->fn);

	while (stub->nbytes < 5)
		stub->nbytes += khook_arch_lde_get_length(hook->target.addr + stub->nbytes);

	memcpy(stub->orig, hook->target.addr, stub->nbytes);
	x86_put_jmp(stub->orig + stub->nbytes, stub->orig + stub->nbytes, hook->target.addr + stub->nbytes);
	if (hook->flags & KHOOK_F_NOREF) {
		x86_put_jmp(hook->target.addr_map, hook->target.addr, hook->fn);
	} else {
		x86_put_jmp(hook->target.addr_map, hook->target.addr, stub->hook);
	}
	hook->orig = stub->orig; // the only link from hook to stub
}

static inline void khook_arch_sm_cleanup_one(khook_t *hook) {
	khook_stub_t *stub = KHOOK_STUB(hook);
	memcpy(hook->target.addr_map, stub->orig, stub->nbytes);
}

#define KHOOK_ARCH_INIT(...)					\
	(khook_arch_lde_init())
