#!/bin/bash

merge_log () {
    cat $(find /usr/local/zeek/logs -name ${1}) > $2
    sed -i '/^#/d' $2
    sed -i '1i #\n#\n#\n#\n#\n#\n#\n#' $2
    sed -i '$a #close' $2
}

reformat_log () {
    sed -i '/^#/d' $1
    sed -i '1i #' $1
}

cd $1/$2
# conn_long.logと重複するためconn.logに出力されるduration>60を除外
awk '$9<60{print}' $(find /usr/local/zeek/logs -name "conn.*.log") > "/usr/local/zeek/logs/conn_replace.log"
rm $(find /usr/local/zeek/logs -name "conn.*.log")
# conn.logとconn_long.logの両方を回収
merge_log "conn*.log" "conn.log"
merge_log "arp.*.log" "arp.log"
merge_log "ns.*.log" "ns.log"
merge_log "dns.*.log" "dns.log"
merge_log "http.*.log" "http.log"
merge_log "cifs.*.log" "mswin-browser.log"
reformat_log "mswin-browser.log"
merge_log "mydhcp.*.log" "dhcp2.log"
reformat_log "dhcp2.log"
merge_log "dhcpv6.*.log" "dhcpv6.log"
reformat_log "dhcpv6.log"
merge_log "nbns.*.log" "netbios-ns.log"
reformat_log "netbios-ns.log"
merge_log "ssdp.*.log" "ssdp.log"
reformat_log "ssdp.log"
# OTプロトコル: CC-Link
merge_log "cclink-ief-basic.*.log" "cclink-ief-basic.log"
merge_log "cclink-ie.*.log" "cclink-ie.log"

if [ $4 = "True" ]; then
    # tsharkでの出力と同じにするため
    merge_log "bacnet_service.*.log" "bacnet_service.log"
    sed -i '/^#/d' bacnet_service.log
    sed -i '1i #' bacnet_service.log
fi

if [ $5 = "True" ]; then
    merge_log "modbus_detailed.*.log" "modbus_detailed.log"
fi

rm $(find /usr/local/zeek/logs -name "*.log")
