#!/bin/bash

OLDEST=$(pgrep -fo $0)
if [ $$ != $OLDEST ] && [ $PPID != $OLDEST ]; then
    echo "already running"
    exit
fi

/usr/bin/suricata -c /opt/ot_tools/suricata.yaml -i $1 > /dev/null 2>&1
