#!/bin/bash

OLDEST=$(pgrep -fo $0)
if [ $$ != $OLDEST ] && [ $PPID != $OLDEST ]; then
    echo "already running"
    exit
fi

cd /opt/edge_cron/
python3 /opt/edge_cron/manage.py complete_to_archives
