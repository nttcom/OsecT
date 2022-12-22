#!/bin/bash

OLDEST=$(pgrep -fo $0)
if [ $$ != $OLDEST ] && [ $PPID != $OLDEST ]; then
    echo "already running"
    exit
fi

/opt/p0f/bin/p0f-k -f /opt/p0f/etc/p0f-k.fp -i $1 -O /var/log/p0f-k.log -R 60 > /dev/null 2>&1
