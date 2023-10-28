#!/bin/bash

# 1. Start run.sh in the background
./.build/dvm --no-ephemeral -c 1 > /dev/null 2>&1 &
sleep 0.25

# 2. Curl the / endpoint
./measure

# 3. Kill run.sh
RUN_SH_PID=$(pidof dvm)
kill -n 9 $RUN_SH_PID
wait $RUN_SH_PID > /dev/null 2>&1
