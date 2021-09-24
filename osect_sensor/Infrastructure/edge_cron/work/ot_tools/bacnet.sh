#!/bin/bash

cd $1/$2
mkdir tmp
cd tmp
/opt/zeek/bin/zeek /opt/zeek/share/zeek/base/protocols/consts_bacnet.zeek /opt/zeek/share/zeek/base/protocols/main_bacnet.zeek -r $1/$3
mv bacnet.log bacnet_service.log
mv bacnet_service.log ../
cd $1/$2
rm -rf tmp
