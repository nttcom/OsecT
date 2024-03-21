#!/bin/bash

# ログファイルの欠損が生じる可能性があるスクリプト
# Commit ID: e373faa93b1b2d49e670675f17af0a44099d7831

cd $1/$2
cat $(ls /var/log/p0f-k.log.*) > p0f-k.log
chmod 644 p0f-k.log
rm -f $(ls /var/log/p0f-k.log.*)
