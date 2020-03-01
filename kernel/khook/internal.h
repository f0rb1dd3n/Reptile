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

#include "engine.h"

extern khook_t KHOOK_tbl[];
extern khook_t KHOOK_tbl_end[];

#define KHOOK_FOREACH_HOOK(p)		\
	for (p = KHOOK_tbl; p < KHOOK_tbl_end; p++)

typedef struct {
#pragma pack(push, 1)
	union {
		unsigned char _0x00_[ 0x10 ];
		atomic_t use_count;
	};
	union {
		unsigned char _0x10_[ 0x20 ];
		unsigned char orig[0];
	};
	union {
		unsigned char _0x30_[ 0x80 ];
		unsigned char hook[0];
	};
#pragma pack(pop)
	unsigned nbytes;
} __attribute__((aligned(32))) khook_stub_t;

static khook_stub_t *khook_stub_tbl;

#define KHOOK_STUB(h)							\
	(khook_stub_tbl + ((h) - KHOOK_tbl))

#define KHOOK_STUB_TBL_SIZE						\
	(sizeof(khook_stub_t) * (KHOOK_tbl_end - KHOOK_tbl + 1))

#if BITS_PER_LONG == 64
# define KHOOK_STUB_FILE_NAME "stub.inc"
#else
# define KHOOK_STUB_FILE_NAME "stub32.inc"
#endif

#ifdef DEBUG
# define khook_debug(fmt, ...)		\
	pr_debug("[khook] " fmt, ##__VA_ARGS__)
#else
# define khook_debug(fmt, ...)
#endif
