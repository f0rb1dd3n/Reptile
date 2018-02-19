#!/bin/bash
#
# You can customize it!

/reptile/reptile_heavens_door
kill -49 `ps -ef | grep reptile_heavens_door | grep -v grep | awk '{print $2}'`
kill -50 0
