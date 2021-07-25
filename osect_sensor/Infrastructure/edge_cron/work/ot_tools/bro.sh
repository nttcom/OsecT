#!/bin/bash

cd $1/$2
mkdir tmp
cd tmp
/opt/zeek/bin/zeek /opt/zeek/share/zeek/base/protocols/arp.zeek /opt/zeek/share/zeek/base/protocols/ns.zeek -r $1/$3
mv {conn,arp,ns,dns,http}.log ../
cd $1/$2
rm -rf tmp
# rm packet_filter.log weird.log ssl.log
