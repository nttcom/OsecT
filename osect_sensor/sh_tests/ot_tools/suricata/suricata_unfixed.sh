#!/bin/bash

# ログファイルの欠損が生じる可能性があるスクリプト
# Commit ID: 2e79e9232b00e1d81477b1436b8c86cdb18b7652

# suricata -c $1 -r $2$3 -l $4

cat /var/log/suricata/eve?*.json > $4/eve.json
rm /var/log/suricata/eve?*.json

# rm $4/fast.log
# rm $4/stats.log