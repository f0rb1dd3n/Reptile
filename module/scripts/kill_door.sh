#!/bin/bash

kill -9 `ps -ef | grep heavens_door | grep -v grep | awk '{print $2}'`
