#!/bin/bash

cd $1/$2
cat /var/log/p0f-k.log.* > p0f-k.log
chmod 644 p0f-k.log
rm /var/log/p0f-k.log.*

