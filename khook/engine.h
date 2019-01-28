#pragma once

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>
#include <linux/stop_machine.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/sched.h>

#ifndef for_each_process
# include <linux/sched/signal.h>
#endif

typedef struct {
	atomic_t	usage;

	unsigned char	*target;
	unsigned char	*target_map;
	unsigned char	*origin;
	unsigned char	*origin_map;
	unsigned char	*handlr;

	const char	*name;
	int		length;
} khook_t;

#define KHOOK_T_DEF(t)							\
	khook_t __attribute__((unused, section(".data.khook"), aligned(1))) KHOOK_##t

#define KHOOK_(t)							\
	static inline typeof(t) khook_##t; /* forward decl */		\
	static inline void notrace __khook_##t(void) {			\
		asm volatile (".rept 32; nop; .endr");			\
	}								\
	KHOOK_T_DEF(t) = {						\
		.name = #t,						\
		.origin = (void *)&__khook_##t,				\
		.handlr = (void *)&khook_##t,				\
		.usage = ATOMIC_INIT(0),				\
	}

#define KHOOK(t)							\
	KHOOK_(t)
#define KHOOK_EXT(r, t, ...)						\
	extern r t(__VA_ARGS__);					\
	KHOOK_(t)

#define KHOOK_GET(t)							\
	atomic_inc(&KHOOK_##t.usage)
#define KHOOK_PUT(t)							\
	atomic_dec(&KHOOK_##t.usage)
#define KHOOK_ORIGIN(t, ...)						\
	((typeof(t) *)KHOOK_##t.origin)(__VA_ARGS__)

extern int khook_init(void);
extern void khook_cleanup(void);
