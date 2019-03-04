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

#ifdef __x86_64__
KHOOK_STUB_hook:
	lock incl KHOOK_STUB_atomic_use_count(%rip)
	movabs $0xcacacacacacacaca, %rax
	call *%rax
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
