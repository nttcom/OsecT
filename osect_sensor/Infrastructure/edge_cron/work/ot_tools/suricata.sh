#!/bin/bash
suricata -c $1 -r $2$3 -l $4
rm $4/fast.log
rm $4/stats.log
