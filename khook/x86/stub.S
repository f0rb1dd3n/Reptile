#
# KHOOK STUB layout
# -----------------
#    0x00: atomic_t = (0)
#    0x10: orig function call wrapper
#    0x30: hook function call wrapper
#

KHOOK_STUB_atomic_use_count:
	.rept 16
	.byte 0x00
	.endr

KHOOK_STUB_orig:
	.rept 32
	.byte 0x00
	.endr

#
# Hooking of function with more than N arguments requires us to
# make a local copy of all arguments starting from N as they are
# passed through the stack as per the ABI.
#
# TODO: x86-32 implementation of CALL_COPY_N_ARGS macro
#

#ifdef __x86_64__
.macro CALL_COPY_N_ARGS n
	sub $(\n * 8), %rsp
	.set i, 0
	.rept \n
		mov ((\n + i + 1) * 8)(%rsp), %rax
		mov %rax, (i * 8)(%rsp)
		.set i, i + 1
	.endr
	movabs $0xcacacacacacacaca, %rax
	call *%rax
	add $(\n * 8), %rsp
.endm
KHOOK_STUB_hook:
	lock incl KHOOK_STUB_atomic_use_count(%rip)
	CALL_COPY_N_ARGS 8
	lock decl KHOOK_STUB_atomic_use_count(%rip)
	ret
#else
KHOOK_STUB_hook:
	call 1f
1:	pop %eax
	lock incl -(1b - KHOOK_STUB_atomic_use_count)(%eax)
	mov $0xcacacaca, %eax
	call *%eax
	call 1f
1:	pop %ecx
	lock decl -(1b - KHOOK_STUB_atomic_use_count)(%ecx)
	ret
#endif
