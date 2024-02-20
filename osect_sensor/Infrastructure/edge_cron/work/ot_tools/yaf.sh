#!/bin/bash

merge_and_remove_log () {
    files=$(ls $1)
    cat ${files} > $2
    sed -i '/^#/d' $2
    sed -i '1i #ts     start-time      end-time        duration        rtt     proto   sip     sp      dip     dp srcMacAddress    destMacAddress  iflags  uflags  riflags ruflags isn     risn    tag     rtag    pktoct      rpkt    roct    end-reason' $2
    rm ${files}
}

cd $1/$2 || exit

flow=$(find "/var/log/yaf" -name "flow*.yaf")
for flowfile in $flow; do
    /usr/local/bin/yafscii --tabular --print-header --mac --in $flowfile --out flow.csv
    cat flow.csv | /opt/ot_tools/yaf.awk > "$flowfile".log
    rm "$flowfile" flow.csv
done

merge_and_remove_log "/var/log/yaf/flow*.log" "yaf_flow.log"
