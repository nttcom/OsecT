#!/bin/bash

OLDEST=$(pgrep -fo $0)
if [ $$ != $OLDEST ] && [ $PPID != $OLDEST ]; then
    echo "already running"
    exit
fi

source /opt/ot_tools/proxy_env.txt

cd /opt/edge_cron/ || exit
python3.8 /opt/edge_cron/manage.py tunnel_batch
