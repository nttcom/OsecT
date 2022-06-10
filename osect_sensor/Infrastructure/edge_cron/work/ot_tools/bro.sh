#!/bin/bash

cd $1/$2 || exit
mkdir tmp
cd tmp || exit
/opt/zeek/bin/zeek -r $1/$3 \
		   /opt/zeek/share/zeek/base/protocols/arp.zeek \
		   /opt/zeek/share/zeek/base/protocols/ns.zeek \
		   /opt/zeek/share/zeek/base/protocols/consts_bacnet.zeek \
		   /opt/zeek/share/zeek/base/protocols/main_bacnet.zeek \
		   zeek-plugin-enip \
		   zeek-plugin-profinet \
		   zeek-plugin-s7comm \
		   icsnpp-ethercat \
		   icsnpp-opcua-binary \
		   icsnpp-modbus
# 新しいOTプロトコルに対応する場合は、以下にログを追記
mv {conn,arp,ns,dns,http}.log ../
cd $1/$2 || exit
rm -rf tmp
# rm packet_filter.log weird.log ssl.log
