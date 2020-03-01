#
# Default stand alone makefile for kconfig.
#
# The Makefile and Makefile.br in this directory should
# not be called directly for standalone build.
# Actually they are included by this makefile.
#

##
# Makefile parameters.
#
# The parameters are configured as for kernel build
# by default. Override them for your application
# setting.
#

# TOP srcdir and this srcdir (relative to TOPDIR)
TOPDIR=.
SRCDIR=.

# O: output directory (objs/exes), default to src dir
O=$(TOPDIR)/$(SRCDIR)

# Build configuration
KBUILD_KCONFIG=Kconfig
KBUILD_CONFIG_DIR=configs
KBUILD_DEFCONFIG=defconfig

# Product information (exported)
export PRODUCT_ENV=KCONFIG
export PRODUCT=Kernel
export PRODUCT_VERSION=<undefined version>
export PRODUCT_DOMAIN=kernel.org

# Kconfig configuration (exported)
export $(PRODUCT_ENV)_CONFIG=.config


# End of Makefile parameters.
##

##
# Makefile adaptation/inclusion.

# Buid vars
HOSTCC=$(CC)
HOSTCXX=$(CXX)
HOSTCFLAGS=-O2 -g
HOSTCXXFLAGS=-O2 -g
srctree=$(TOPDIR)
src=$(TOPDIR)/$(SRCDIR)
obj=$(O)

# Enable execution from Makefile *conf programs
export PATH:=$(PATH):$(obj)

include $(TOPDIR)/$(SRCDIR)/Makefile.br

# End of Makefile adaptation/inclusion.
##
