#!/bin/bash

kill -48 0
kill -49 `ps -ef | grep heavens_door | grep -v grep | awk '{print $2}'`
kill -50 0
