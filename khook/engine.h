#pragma once

#include <linux/kernel.h>

typedef struct {
	void			*fn;		// handler fn address
	struct {
		const char	*name;		// target symbol name
		char		*addr;		// target symbol addr (see khook_lookup_name)
		char		*addr_map;	// writable mapping of target symbol
	} target;
	void			*orig;		// original fn call wrapper
} khook_t;

#define KHOOK_(t)							\
	static inline typeof(t) khook_##t; /* forward decl */		\
	khook_t								\
	__attribute__((unused))						\
	__attribute__((aligned(1)))					\
	__attribute__((section(".data.khook")))				\
	KHOOK_##t = {							\
		.fn = khook_##t,					\
		.target.name = #t,					\
	}

#define KHOOK(t)							\
	KHOOK_(t)
#define KHOOK_EXT(r, t, ...)						\
	extern r t(__VA_ARGS__);					\
	KHOOK_(t)

#define KHOOK_ORIGIN(t, ...)						\
	((typeof(t) *)KHOOK_##t.orig)(__VA_ARGS__)

extern int khook_init(void);
extern void khook_cleanup(void);
