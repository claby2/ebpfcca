#!/bin/bash

# on server side:
# sudo apt install iperf3
# iperf3 -s -p {TARGET_PORT}

TARGET_SERVER=bokaibi.com
TARGET_PORT=5142
TOTAL_SECONDS=30
REPORT_INTERVAL=0.1

# native cubic
touch cubic.json
sudo sysctl --write net.ipv4.tcp_congestion_control=cubic
iperf3 -c $TARGET_SERVER -p $TARGET_PORT \
--json --verbose --timestamps --interval $REPORT_INTERVAL \
--time $TOTAL_SECONDS --logfile cubic.json

sleep 5

# bpf cubic
touch bpf_cubic.json
sudo sysctl --write net.ipv4.tcp_congestion_control=bpf_cubic
iperf3 -c $TARGET_SERVER -p $TARGET_PORT \
--json --verbose --timestamps --interval $REPORT_INTERVAL \
--time $TOTAL_SECONDS --logfile bpf_cubic.json
