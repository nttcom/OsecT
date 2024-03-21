#!/bin/bash

# ログファイルの欠損が生じる可能性があるスクリプト
# Commit ID: 8d5a01080f3fae323ae83505f44e3cbb221ca489

merge_log () {
    cat $1 > $2
    sed -i '/^#/d' $2
    sed -i '1i #ts     start-time      end-time        duration        rtt     proto   sip     sp      dip     dp srcMacAddress    destMacAddress  iflags  uflags  riflags ruflags isn     risn    tag     rtag    pktoct      rpkt    roct    end-reason' $2
}

cd $1/$2 || exit

flow=$(find "/var/log/yaf" -name "flow*.yaf")
for flowfile in $flow; do
    /usr/local/bin/yafscii --tabular --print-header --mac --in $flowfile --out flow.csv
    cat flow.csv | /opt/ot_tools/yaf.awk > "$flowfile".log
    rm "$flowfile" flow.csv
done

merge_log "/var/log/yaf/flow*.log" "yaf_flow.log"
rm /var/log/yaf/flow*.log