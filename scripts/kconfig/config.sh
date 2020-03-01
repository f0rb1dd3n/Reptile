#!/bin/sh
#
# usage: kconfig/config.sh <make args>
#
# Runs the requested configuration from
# the directory to be configured.
#
# For instance:
# cd myproject/
# kconfig/config.sh menuconfig
#
# Will generated a 'config' file in
# myproject/ from the 'Kconfig' file
# in myproject/
#

set -e
dir=`dirname $0`
topdir=`dirname $dir`
srcdir=`basename $dir`
kconfig_targets="${1-config}"
set +x
exec make -f $dir/GNUmakefile \
    TOPDIR=$topdir \
    SRCDIR=$srcdir \
    $kconfig_targets
