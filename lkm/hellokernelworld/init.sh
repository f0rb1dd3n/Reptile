#!/bin/bash

echo -e "\n\e[00;31m################################### \e[01;36mCompiling...\e[00;31m ###################################\e[00m\n"
make
echo -e "\n\e[00;31m####################################################################################\e[00m\n"

echo -e "Loading module..."
insmod hellokernelworld.ko
echo -e "LOADED!"

echo -e "\nRemoving module..."
rmmod hellokernelworld
echo -e "DONE!"

echo -e "\n\e[00;31m################################### \e[01;36mCleanning...\e[00;31m ###################################\e[00m\n" 
make clean
echo
