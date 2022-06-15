#!/bin/bash

cd $1/$2 || exit
/usr/bin/tshark -l -n -T fields  -e frame.time_epoch -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e udp.dstport -e bacapp.type -e bacapp.confirmed_service -e bacapp.unconfirmed_service -e bacapp.objectType -Y 'bacapp and udp and not icmp and not icmpv6' -r ../$3 | /opt/ot_tools/tsharkfields2bacnetservicelog_dict.awk > ./bacnet_service.log
