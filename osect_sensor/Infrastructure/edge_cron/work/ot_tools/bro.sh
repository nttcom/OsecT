#!/bin/bash

merge_log () {
    cat $1 > $2
    sed -i '/^#/d' $2
    sed -i '1i #\n#\n#\n#\n#\n#\n#\n#' $2
    sed -i '$a #close' $2
}

cd $1/$2
DATE=$(date "+%Y-%m-%d")
merge_log "/opt/zeek/logs/${DATE}/conn.*.log" "conn.log"
merge_log "/opt/zeek/logs/${DATE}/arp.*.log" "arp.log"
merge_log "/opt/zeek/logs/${DATE}/ns.*.log" "ns.log"
merge_log "/opt/zeek/logs/${DATE}/dns.*.log" "dns.log"
merge_log "/opt/zeek/logs/${DATE}/http.*.log" "http.log"
merge_log "/opt/zeek/logs/${DATE}/cifs.*.log" "mswin-browser.log"
rm /opt/zeek/logs/${DATE}/*.log
