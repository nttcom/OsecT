#!/bin/bash

OLDEST=$(pgrep -fo $0)
if [ $$ != $OLDEST ] && [ $PPID != $OLDEST ]; then
    echo "already running"
    exit
fi

/usr/local/bin/yaf --mac --live pcap --in $1 --rotate 60 --out /var/log/yaf/flow
