MODNAME		?= reptile

obj-m		+= $(MODNAME).o
$(MODNAME)-y	+= rep_mod.o

ccflags-y	+= -Werror -fno-stack-protector -fomit-frame-pointer
ldflags-y	+= -T$(src)/khook/engine.lds

KBUILD_CFLAGS	:= $(filter-out -pg,$(KBUILD_CFLAGS))
KBUILD_CFLAGS	:= $(filter-out -mfentry,$(KBUILD_CFLAGS))
