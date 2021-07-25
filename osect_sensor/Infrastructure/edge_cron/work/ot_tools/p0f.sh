#!/bin/bash

cd $1/$2
/opt/p0f/bin/p0f-k -f /opt/p0f/etc/p0f-k.fp -r ../$3 -O p0f-k.log > /dev/null
#/opt/p0f-3.09b/p0f -f /opt/p0f-3.09b/p0f.fp -r ../$3 -o p0f.log > /dev/null
chmod 644 p0f-k.log

