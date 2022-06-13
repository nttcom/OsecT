#!/bin/bash

cd $1/$2 || exit
mkdir tmp
cd tmp || exit
/opt/zeek/bin/zeek /opt/zeek/share/zeek/base/protocols/arp.zeek /opt/zeek/share/zeek/base/protocols/ns.zeek /opt/zeek/share/zeek/base/protocols/consts_bacnet.zeek /opt/zeek/share/zeek/base/protocols/main_bacnet.zeek /opt/zeek/share/zeek/site/icsnpp-modbus/main.zeek -r $1/$3
mv {conn,arp,ns,dns,http}.log ../
if [ $4 = "True" ]; then
    mv modbus_detailed.log ../
fi
cd $1/$2 || exit
rm -rf tmp
# rm packet_filter.log weird.log ssl.log
