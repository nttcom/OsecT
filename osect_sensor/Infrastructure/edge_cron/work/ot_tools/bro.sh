#!/bin/bash

merge_log () {
    cat $1 > $2
    sed -i '/^#/d' $2
    sed -i '1i #\n#\n#\n#\n#\n#\n#\n#' $2
    sed -i '$a #close' $2
}

#mkdir tmp
#cd tmp || exit
#
#/opt/zeek/bin/zeek -r $1/$3 \
#		   /opt/zeek/share/zeek/base/protocols/arp.zeek \
#		   /opt/zeek/share/zeek/base/protocols/ns.zeek \
#		   /opt/zeek/share/zeek/base/protocols/consts_bacnet.zeek \
#		   /opt/zeek/share/zeek/base/protocols/main_bacnet.zeek
#mv {conn,arp,ns,dns,http}.log ../
#
#if [ $4 = "True" ]; then
#    # tsharkでの出力と同じにするため
#    sed -i '/^#/d' bacnet_service.log
#    sed -i '1i #' bacnet_service.log
#    mv bacnet_service.log ../
#fi
#if [ $5 = "True" ]; then
#    mv modbus_detailed.log ../
#fi
#
#cd $1/$2 || exit
#rm -rf tmp

cd $1/$2
DATE=$(date "+%Y-%m-%d")
merge_log "/opt/zeek/logs/${DATE}/conn.*.log" "conn.log"
merge_log "/opt/zeek/logs/${DATE}/arp.*.log" "arp.log"
merge_log "/opt/zeek/logs/${DATE}/ns.*.log" "ns.log"
merge_log "/opt/zeek/logs/${DATE}/dns.*.log" "dns.log"
merge_log "/opt/zeek/logs/${DATE}/http.*.log" "http.log"
rm /opt/zeek/logs/${DATE}/*.log
