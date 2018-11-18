#pragma once

#include <linux/delay.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/stop_machine.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>

typedef struct {
	atomic_t usage;

	unsigned char *target;
	unsigned char *target_map;
	unsigned char *origin;
	unsigned char *origin_map;
	unsigned char *handlr;

	const char *name;
	int length;
} khook_t;

#define KHOOK_T_DEF(t)                                                         \
	khook_t __attribute__((unused, section(".data.khook"), aligned(1)))    \
	    KHOOK_##t

#define KHOOK_(t)                                                              \
	void __attribute__((alias("khook_" #t))) khook_h_##t(void);            \
	void notrace khook_o_##t(void)                                         \
	{                                                                      \
		asm volatile(".rept 32; nop; .endr");                          \
	}                                                                      \
	KHOOK_T_DEF(t) = {                                                     \
	    .name = #t,                                                        \
	    .origin = (void *)&khook_o_##t,                                    \
	    .handlr = (void *)&khook_h_##t,                                    \
	    .usage = ATOMIC_INIT(0),                                           \
	}

#define KHOOK(t) KHOOK_(t)
#define KHOOK_EXT(r, t, ...)                                                   \
	extern r t(__VA_ARGS__);                                               \
	KHOOK_(t)

#define KHOOK_GET(t) atomic_inc(&KHOOK_##t.usage)
#define KHOOK_PUT(t) atomic_dec(&KHOOK_##t.usage)
#define KHOOK_ORIGIN(t, ...) ((typeof(t) *)KHOOK_##t.origin)(__VA_ARGS__)

extern int khook_init(void);
extern void khook_cleanup(void);
