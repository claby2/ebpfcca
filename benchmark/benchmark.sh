#!/bin/bash

# on server side:
# sudo apt install iperf3
# iperf3 -s -p {TARGET_PORT}

TARGET_SERVER=$1
TARGET_PORT=$2
TOTAL_SECONDS=$3
REPORT_INTERVAL=$4
CCA=$5
TRIALS=$6

# loop for trials
for i in $(seq 1 $TRIALS)
do
    echo "Trial $i for $CCA Starting..."
    touch $CCA_$i.json
    sudo sysctl --write net.ipv4.tcp_congestion_control=$CCA
    iperf3 -c $TARGET_SERVER -p $TARGET_PORT \
    --json --verbose --timestamps --interval $REPORT_INTERVAL \
    --time $TOTAL_SECONDS --logfile $CCA_$i.json

    echo "Trial $i for $CCA done, sleeping for 5 seconds"
    sleep 5
done
