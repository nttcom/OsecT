#!/bin/bash

OLDEST=$(pgrep -fo $0)
if [ $$ != $OLDEST ] && [ $PPID != $OLDEST ]; then
    echo "already running"
    exit
fi

cd /opt/edge_cron/
# pypy3 /opt/edge_cron/manage.py complete_to_archives
python3.8 /opt/edge_cron/manage.py complete_to_archives
