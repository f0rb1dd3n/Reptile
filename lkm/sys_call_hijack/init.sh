#!/bin/bash

echo -e "\n\e[00;31m################################### \e[01;36mCompiling...\e[00;31m ###################################\e[00m\n"
make
echo
gcc l33t.c -o l33t
echo -e "\n\e[00;31m####################################################################################\e[00m\n"

echo -e "Loading module..."
insmod sys_call_hijack.ko
echo -e "LOADED!"
echo -e "\nTo Remove the module run: rmmod sys_call_hijack"

echo -e "\n\e[00;31m################################### \e[01;36mCleanning...\e[00;31m ###################################\e[00m\n" 
make clean
echo
