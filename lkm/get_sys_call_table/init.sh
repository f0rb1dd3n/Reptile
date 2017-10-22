#!/bin/bash

echo -e "\n\e[00;31m################################### \e[01;36mCompiling...\e[00;31m ###################################\e[00m\n"
make
echo -e "\n\e[00;31m####################################################################################\e[00m\n"

echo -e "Loading module..."
insmod get_sys_call_table.ko
echo -e "LOADED!"

echo -e "\nRemoving module..."
rmmod get_sys_call_table
echo -e "DONE!"

#echo -e "\nOriginal address of sys_call_table at System.map"
#grep sys_call_table /boot/System.map-$(uname -r)

echo -e "\n\e[00;31m################################### \e[01;36mCleanning...\e[00;31m ###################################\e[00m\n" 
make clean
echo
