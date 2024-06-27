#!/bin/bash

merge_and_remove_log () {
    files=$(find /usr/local/zeek/logs -name "$1")
    cat ${files} > $2
    sed -i '/^#/d' $2
    sed -i '1i #\n#\n#\n#\n#\n#\n#\n#' $2
    sed -i '$a #close' $2
    rm ${files}
}

reformat_log () {
    sed -i '/^#/d' $1
    sed -i '1i #' $1
}

cd $1/$2
# conn_long.logと重複するためconn.logに出力されるduration>60を除外
tmp_files=$(find /usr/local/zeek/logs -name "conn.*.log")
awk '$9<60{print}' ${tmp_files} > "/usr/local/zeek/logs/conn_replace.log"
rm ${tmp_files}
# conn.logとconn_long.logの両方を回収
merge_and_remove_log "conn*.log" "conn.log"
merge_and_remove_log "arp.*.log" "arp.log"
merge_and_remove_log "ns.*.log" "ns.log"
merge_and_remove_log "dns.*.log" "dns.log"
merge_and_remove_log "http.*.log" "http.log"
merge_and_remove_log "cifs.*.log" "mswin-browser.log"
reformat_log "mswin-browser.log"
merge_and_remove_log "mydhcp.*.log" "dhcp2.log"
reformat_log "dhcp2.log"
merge_and_remove_log "dhcpv6.*.log" "dhcpv6.log"
reformat_log "dhcpv6.log"
merge_and_remove_log "nbns.*.log" "netbios-ns.log"
reformat_log "netbios-ns.log"
merge_and_remove_log "ssdp.*.log" "ssdp.log"
reformat_log "ssdp.log"
# OTプロトコル: Bacnet/IP
merge_and_remove_log "bacnet.*.log" "bacnet.log"
# OTプロトコル: CC-Link
merge_and_remove_log "cclink-ief-basic.*.log" "cclink-ief-basic.log"
merge_and_remove_log "cclink-ie.*.log" "cclink-ie.log"
merge_and_remove_log "cclink-ie-tsn.*.log" "cclink-ie-tsn.log"
merge_and_remove_log "cclink-ie-tsn-slmp.*.log" "cclink-ie-tsn-slmp.log"
merge_and_remove_log "cclink-ie-tsn-ptp.*.log" "cclink-ie-tsn-ptp.log"

if [ $4 = "True" ]; then
    # tsharkでの出力と同じにするため
    merge_and_remove_log "bacnet.*.log" "bacnet.log"
fi

if [ $5 = "True" ]; then
    merge_and_remove_log "modbus_detailed.*.log" "modbus_detailed.log"
fi
