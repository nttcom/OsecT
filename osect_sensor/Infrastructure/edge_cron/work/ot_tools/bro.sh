#!/bin/bash

cd $1/$2 || exit
mkdir tmp
cd tmp || exit
/opt/zeek/bin/zeek -r $1/$3 \
		   /opt/zeek/share/zeek/base/protocols/arp.zeek \
		   /opt/zeek/share/zeek/base/protocols/ns.zeek \
		   /opt/zeek/share/zeek/base/protocols/consts_bacnet.zeek \
		   /opt/zeek/share/zeek/base/protocols/main_bacnet.zeek
mv {conn,arp,ns,dns,http}.log ../
if [ $4 = "True" ]; then
    # tsharkでの出力と同じにするため
    sed -i '/^#/d' bacnet_service.log
    sed -i '1i #' bacnet_service.log
    mv bacnet_service.log ../
fi
cd $1/$2 || exit
rm -rf tmp
