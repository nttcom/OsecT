#!/bin/bash

merge_log () {
    cat $1 > $2
    sed -i '/^#/d' $2
    sed -i '1i #\n#\n#\n#\n#\n#\n#\n#' $2
    sed -i '$a #close' $2
}

reformat_log () {
    sed -i '/^#/d' $1
    sed -i '1i #' $1
}

cd $1/$2
DATE=$(date -u "+%Y-%m-%d")
merge_log "/opt/zeek/logs/${DATE}/conn.*.log" "conn.log"
merge_log "/opt/zeek/logs/${DATE}/arp.*.log" "arp.log"
merge_log "/opt/zeek/logs/${DATE}/ns.*.log" "ns.log"
merge_log "/opt/zeek/logs/${DATE}/dns.*.log" "dns.log"
merge_log "/opt/zeek/logs/${DATE}/http.*.log" "http.log"
merge_log "/opt/zeek/logs/${DATE}/cifs.*.log" "mswin-browser.log"
reformat_log "mswin-browser.log"
merge_log "/opt/zeek/logs/${DATE}/mydhcp.*.log" "dhcp2.log"
reformat_log "dhcp2.log"
merge_log "/opt/zeek/logs/${DATE}/dhcpv6.*.log" "dhcpv6.log"
reformat_log "dhcpv6.log"
merge_log "/opt/zeek/logs/${DATE}/nbns.*.log" "netbios-ns.log"
reformat_log "netbios-ns.log"
merge_log "/opt/zeek/logs/${DATE}/ssdp.*.log" "ssdp.log"
reformat_log "ssdp.log"
merge_log "/opt/zeek/logs/${DATE}/cclink-ief-basic.*.log" "cclink-ief-basic.log"
merge_log "/opt/zeek/logs/${DATE}/cclink-ie.*.log" "cclink-ie.log"

if [ $4 = "True" ]; then
    # tsharkでの出力と同じにするため
    merge_log "/opt/zeek/logs/${DATE}/bacnet_service.*.log" "bacnet_service.log"
    sed -i '/^#/d' bacnet_service.log
    sed -i '1i #' bacnet_service.log
fi

if [ $5 = "True" ]; then
    merge_log "/opt/zeek/logs/${DATE}/modbus_detailed.*.log" "modbus_detailed.log"
fi

rm /opt/zeek/logs/${DATE}/*.log
