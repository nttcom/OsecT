#!/bin/sh

# tcpdump -w realtime-%F-%T.pcap -G 60 -ni enp0s3 -s 0 -z ./capture.sh
/usr/bin/python3.7 /opt/edge_tcpdump/manage.py tcpdump_control
